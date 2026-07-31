//! Live client sessions.
//!
//! Two things need a list of who is currently connected, and neither could be
//! built without one.
//!
//! **Disabling a user has to mean something.** The authenticator already
//! refuses a disabled user at the next handshake, but a session established a
//! second earlier keeps running indefinitely. An operator revoking access
//! during an incident does not mean "starting from the next reconnect".
//!
//! **A per-user connection cap has to be counted somewhere.** The limit is
//! stored per user, so the count has to be per user too.
//!
//! ## Why a kick is graceful
//!
//! The obvious implementation — keep the session's `JoinHandle` and `abort()`
//! it — is wrong, and wrong in a way that outlives the session it kills.
//! Aborting drops the relay future wherever it happens to be, which may be
//! halfway through forwarding a backend's response. The `Checkout` is then
//! dropped too, and since nothing marked it broken it goes straight back into
//! the pool with unread bytes in its socket. The next client to borrow it
//! receives the tail of someone else's result set.
//!
//! So a kick sets a flag, and the relay loops read it at the one point where
//! the backend is provably at a message boundary: between statements. An idle
//! client goes immediately; a client with a query in flight goes when that
//! query finishes. The alternative is a corrupted pool.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::watch;

/// A live session, as the admin API sees it.
#[derive(Debug, Clone, Serialize)]
pub struct LiveSession {
    pub id: u64,
    pub user: String,
    pub pool: String,
    pub application: Option<String>,
    pub client_addr: String,
    pub since_ms: i64,
    pub elapsed_us: u64,
}

struct Entry {
    public: LiveSession,
    since: Instant,
    /// Flipped to end the session. Every relay loop watches this.
    kick: watch::Sender<bool>,
}

/// A user already holds as many sessions as it is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooManySessions {
    pub user: String,
    pub limit: u32,
}

/// Every client session currently attached to this process.
#[derive(Default)]
pub struct SessionRegistry {
    next_id: AtomicU64,
    entries: RwLock<BTreeMap<u64, Entry>>,
}

impl SessionRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { next_id: AtomicU64::new(1), entries: RwLock::new(BTreeMap::new()) })
    }

    /// Admit a session, or refuse it because the user is at its limit.
    ///
    /// `limit` of `0` means "no personal cap". The check and the insert happen
    /// under one write lock so that two simultaneous connections cannot both
    /// see room for one.
    pub fn register(
        self: &Arc<Self>,
        user: &str,
        pool: &str,
        application: Option<&str>,
        client_addr: &str,
        limit: u32,
    ) -> Result<SessionHandle, TooManySessions> {
        let mut entries = self.entries.write().expect("session registry poisoned");

        if limit > 0 {
            let held = entries.values().filter(|entry| entry.public.user == user).count();
            if held >= limit as usize {
                return Err(TooManySessions { user: user.to_string(), limit });
            }
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (kick, receiver) = watch::channel(false);
        entries.insert(
            id,
            Entry {
                public: LiveSession {
                    id,
                    user: user.to_string(),
                    pool: pool.to_string(),
                    application: application.map(str::to_string),
                    client_addr: client_addr.to_string(),
                    since_ms: now_ms(),
                    elapsed_us: 0,
                },
                since: Instant::now(),
                kick,
            },
        );

        Ok(SessionHandle { registry: self.clone(), id, signal: KickSignal(Some(receiver)) })
    }

    /// End every session belonging to `user`. Returns how many were signalled.
    pub fn kick_user(&self, user: &str) -> usize {
        self.signal(|entry| entry.public.user == user)
    }

    /// End every session attached to `pool`.
    pub fn kick_pool(&self, pool: &str) -> usize {
        self.signal(|entry| entry.public.pool == pool)
    }

    /// End one session by id. False means it had already gone.
    pub fn kick_session(&self, id: u64) -> bool {
        self.signal(|entry| entry.public.id == id) > 0
    }

    fn signal(&self, matches: impl Fn(&Entry) -> bool) -> usize {
        let entries = self.entries.read().expect("session registry poisoned");
        entries
            .values()
            .filter(|entry| matches(entry))
            // `send` fails only when every receiver is gone, which means the
            // session is already unwinding. Not a kick we performed.
            .filter(|entry| entry.kick.send(true).is_ok())
            .count()
    }

    /// Sessions currently attached, longest-lived first.
    pub fn snapshot(&self) -> Vec<LiveSession> {
        let mut sessions: Vec<_> = self
            .entries
            .read()
            .expect("session registry poisoned")
            .values()
            .map(|entry| {
                let mut session = entry.public.clone();
                session.elapsed_us = entry.since.elapsed().as_micros() as u64;
                session
            })
            .collect();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.elapsed_us));
        sessions
    }

    /// How many sessions each user holds. Drives the Users page.
    pub fn counts_by_user(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::new();
        for entry in self.entries.read().expect("session registry poisoned").values() {
            *counts.entry(entry.public.user.clone()).or_insert(0) += 1;
        }
        counts
    }

    pub fn len(&self) -> usize {
        self.entries.read().expect("session registry poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn deregister(&self, id: u64) {
        self.entries.write().expect("session registry poisoned").remove(&id);
    }
}

/// Keeps a session in the registry for as long as it is alive.
pub struct SessionHandle {
    registry: Arc<SessionRegistry>,
    id: u64,
    signal: KickSignal,
}

impl SessionHandle {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// A cheap, cloneable handle the relay loops can await on.
    pub fn signal(&self) -> KickSignal {
        self.signal.clone()
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.registry.deregister(self.id);
    }
}

/// The receiving end of a kick.
///
/// [`KickSignal::never`] exists so that code paths without a registry — tests,
/// and the untraced relay entry points — do not have to invent a channel whose
/// sender they must then keep alive.
#[derive(Clone)]
pub struct KickSignal(Option<watch::Receiver<bool>>);

impl KickSignal {
    /// A signal that never fires.
    pub fn never() -> Self {
        Self(None)
    }

    /// Has this session already been kicked?
    pub fn is_kicked(&self) -> bool {
        self.0.as_ref().is_some_and(|receiver| *receiver.borrow())
    }

    /// Resolve once this session has been kicked, and never otherwise.
    ///
    /// Cancel-safe: `watch::Receiver::changed` is, and the flag it reports is
    /// latched, so losing a `select!` race cannot drop a kick.
    pub async fn kicked(&mut self) {
        let Some(receiver) = self.0.as_mut() else {
            // Nothing can ever kick this session, so this branch of a `select!`
            // must simply never complete.
            return std::future::pending().await;
        };
        loop {
            if *receiver.borrow_and_update() {
                return;
            }
            if receiver.changed().await.is_err() {
                // The registry dropped the sender, so no kick can arrive. The
                // session ends on its own terms.
                return std::future::pending().await;
            }
        }
    }
}

impl std::fmt::Debug for KickSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KickSignal").field("kicked", &self.is_kicked()).finish()
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Arc<SessionRegistry> {
        SessionRegistry::new()
    }

    fn open(registry: &Arc<SessionRegistry>, user: &str) -> SessionHandle {
        registry.register(user, "app_main", Some("orders-api"), "127.0.0.1:5000", 0).expect("no limit")
    }

    #[test]
    fn a_session_is_listed_while_it_lives_and_gone_the_moment_it_ends() {
        let registry = registry();
        {
            let _session = open(&registry, "svc_orders");
            let live = registry.snapshot();
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].user, "svc_orders");
            assert_eq!(live[0].pool, "app_main");
        }
        assert!(registry.snapshot().is_empty(), "a dropped session must not linger as a phantom");
    }

    #[test]
    fn a_per_user_cap_is_enforced_and_freed_again() {
        let registry = registry();
        let first = registry.register("svc_orders", "app_main", None, "a", 2).unwrap();
        let second = registry.register("svc_orders", "app_main", None, "b", 2).unwrap();

        assert_eq!(
            registry.register("svc_orders", "app_main", None, "c", 2).err(),
            Some(TooManySessions { user: "svc_orders".into(), limit: 2 })
        );

        // Another user has its own budget.
        assert!(registry.register("svc_reports", "app_main", None, "d", 2).is_ok());

        drop(second);
        assert!(registry.register("svc_orders", "app_main", None, "e", 2).is_ok(), "a closed session frees its slot");
        drop(first);
    }

    #[test]
    fn a_cap_of_zero_means_no_personal_limit() {
        let registry = registry();
        let mut held = Vec::new();
        for i in 0..50 {
            held.push(registry.register("svc_orders", "app_main", None, &i.to_string(), 0).expect("uncapped"));
        }
        assert_eq!(registry.len(), 50);
    }

    #[tokio::test]
    async fn kicking_a_user_signals_every_session_it_owns_and_nobody_elses() {
        let registry = registry();
        let mine = open(&registry, "svc_orders");
        let also_mine = open(&registry, "svc_orders");
        let theirs = open(&registry, "svc_reports");

        assert_eq!(registry.kick_user("svc_orders"), 2);

        assert!(mine.signal().is_kicked());
        assert!(also_mine.signal().is_kicked());
        assert!(!theirs.signal().is_kicked(), "kicking one user must not disturb another");

        // And the signal actually resolves, rather than merely being readable.
        tokio::time::timeout(std::time::Duration::from_secs(1), mine.signal().kicked())
            .await
            .expect("a kicked session must wake up");
    }

    #[tokio::test]
    async fn a_kick_that_arrives_before_anyone_waits_is_not_lost() {
        // The flag is latched precisely so a session that was busy running a
        // query still sees the kick when it comes back to wait for input.
        let registry = registry();
        let session = open(&registry, "svc_orders");
        registry.kick_user("svc_orders");

        tokio::time::timeout(std::time::Duration::from_secs(1), session.signal().kicked())
            .await
            .expect("a latched kick must still resolve");
    }

    #[tokio::test]
    async fn a_signal_that_can_never_fire_never_resolves() {
        // Otherwise every relay loop without a registry would exit instantly.
        let mut signal = KickSignal::never();
        assert!(!signal.is_kicked());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), signal.kicked()).await.is_err(),
            "KickSignal::never must park forever"
        );
    }

    #[tokio::test]
    async fn an_unkicked_session_keeps_waiting() {
        let registry = registry();
        let session = open(&registry, "svc_orders");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), session.signal().kicked()).await.is_err(),
            "nothing has kicked this session"
        );
    }

    #[test]
    fn kicking_by_pool_and_by_id_select_the_right_sessions() {
        let registry = registry();
        let a = registry.register("svc_orders", "app_main", None, "a", 0).unwrap();
        let b = registry.register("svc_reports", "reporting", None, "b", 0).unwrap();

        assert_eq!(registry.kick_pool("reporting"), 1);
        assert!(b.signal().is_kicked());
        assert!(!a.signal().is_kicked());

        assert!(registry.kick_session(a.id()));
        assert!(a.signal().is_kicked());
        assert!(!registry.kick_session(9999), "an unknown id kicks nothing");
    }

    #[test]
    fn counts_by_user_drives_the_users_page() {
        let registry = registry();
        let _a = open(&registry, "svc_orders");
        let _b = open(&registry, "svc_orders");
        let _c = open(&registry, "svc_reports");

        let counts = registry.counts_by_user();
        assert_eq!(counts.get("svc_orders"), Some(&2));
        assert_eq!(counts.get("svc_reports"), Some(&1));
        assert_eq!(counts.get("nobody"), None);
    }
}
