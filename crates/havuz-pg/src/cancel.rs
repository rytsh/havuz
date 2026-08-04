//! Query cancellation.
//!
//! Cancellation in Postgres does not travel on the connection being cancelled.
//! The client opens a *second* connection and sends a `CancelRequest` carrying
//! the `(process_id, secret_key)` pair it was handed at startup.
//!
//! For a pooler this is genuinely awkward, and getting it wrong is one of the
//! quieter ways to break a deployment: `Ctrl-C` in `psql` stops working,
//! statement timeouts on the client side stop taking effect, and runaway
//! queries keep burning database CPU. Nobody notices until production.
//!
//! havuz issues its own key pair to each client and keeps a mapping to the real
//! backend. The client's key must be ours, because by the time a cancellation
//! arrives the backend it refers to may already belong to somebody else — in
//! which case the right answer is to do nothing rather than cancel an innocent
//! third party's query.
//!
//! ## Why the mapping moves
//!
//! In session mode a client owns one backend for its whole life and the mapping
//! could be written once. In transaction mode it owns one only while a
//! statement is in flight, and between statements it owns none at all. A fixed
//! mapping would therefore be wrong in exactly the case cancellation matters
//! most: `Ctrl-C` would be delivered to whichever client borrowed that backend
//! next.
//!
//! So a [`CancelScope`] is retargeted as its session borrows and returns
//! backends, and points at nothing while the client is idle. A cancellation
//! that arrives then is dropped, which is correct — there is no query to stop.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use havuz_control::CancelHook;
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::protocol::StartupPacket;

/// How long a cancellation may spend reaching a backend before it is given up
/// on. Short by design: a cancellation nobody is waiting for is worthless, and
/// an operator pressing a button must not be left hanging by a sick server.
pub const CANCEL_TIMEOUT: Duration = Duration::from_secs(3);

/// Where a cancellation should actually be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelTarget {
    pub host: String,
    pub port: u16,
    pub backend_pid: i32,
    pub backend_secret: i32,
}

/// The key pair havuz hands to a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CancelKey {
    pub process_id: i32,
    pub secret_key: i32,
}

/// Maps havuz-issued keys to backend keys.
///
/// The value is an `Option` because a transaction-mode client spends most of
/// its life holding no backend at all. `None` means "connected, but nothing to
/// cancel"; a missing entry means "we never issued this key, or the session is
/// gone".
#[derive(Debug, Default)]
pub struct CancelRegistry {
    entries: RwLock<HashMap<CancelKey, Option<CancelTarget>>>,
    next_id: Mutex<i32>,
}

impl CancelRegistry {
    pub fn new() -> Self {
        Self { entries: RwLock::new(HashMap::new()), next_id: Mutex::new(1) }
    }

    /// Issue a fresh key for a client session, pointing at nothing yet.
    ///
    /// The process id is a counter so it stays readable in logs; the secret is
    /// random, because it is the only thing standing between an attacker and
    /// the ability to cancel other people's queries.
    ///
    /// The returned scope owns the entry: dropping it unregisters the key, so
    /// no relay path can leak one by returning early.
    pub fn scope(self: &Arc<Self>) -> CancelScope {
        let process_id = {
            let mut next = self.next_id.lock().expect("cancel id counter poisoned");
            let id = *next;
            *next = next.wrapping_add(1).max(1);
            id
        };
        let key = CancelKey { process_id, secret_key: rand::thread_rng().gen() };
        self.entries.write().expect("cancel registry poisoned").insert(key, None);
        CancelScope(Arc::new(ScopeInner { registry: self.clone(), key }))
    }

    fn retarget(&self, key: CancelKey, target: Option<CancelTarget>) {
        if let Some(slot) = self.entries.write().expect("cancel registry poisoned").get_mut(&key) {
            *slot = target;
        }
    }

    fn unregister(&self, key: CancelKey) {
        self.entries.write().expect("cancel registry poisoned").remove(&key);
    }

    /// The backend a key currently points at, if any.
    pub fn lookup(&self, key: CancelKey) -> Option<CancelTarget> {
        self.entries.read().expect("cancel registry poisoned").get(&key).cloned().flatten()
    }

    pub fn len(&self) -> usize {
        self.entries.read().expect("cancel registry poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One client session's place in the registry.
///
/// Cloneable so the same slot can be handed to a query trace as something an
/// operator may cancel; the entry lives until the last clone is dropped, which
/// is the end of the session.
#[derive(Debug, Clone)]
pub struct CancelScope(Arc<ScopeInner>);

#[derive(Debug)]
struct ScopeInner {
    registry: Arc<CancelRegistry>,
    key: CancelKey,
}

impl Drop for ScopeInner {
    fn drop(&mut self) {
        self.registry.unregister(self.key);
    }
}

impl CancelScope {
    /// The key pair handed to the client during startup.
    pub fn key(&self) -> CancelKey {
        self.0.key
    }

    /// Point at the backend this session is borrowing, or at nothing once it
    /// gives the backend back.
    pub fn retarget(&self, target: Option<CancelTarget>) {
        self.0.registry.retarget(self.0.key, target);
    }

    /// The backend currently borrowed, if any.
    pub fn target(&self) -> Option<CancelTarget> {
        self.0.registry.lookup(self.0.key)
    }
}

/// Lets an operator cancel through the same slot the client uses.
///
/// Going through the scope rather than recording a target when the query
/// started is what makes an admin cancellation safe: by the time the button is
/// pressed the query may have finished and the backend moved on, and the scope
/// will have stopped pointing at it.
#[async_trait]
impl CancelHook for CancelScope {
    async fn cancel(&self) -> Result<(), String> {
        let Some(target) = self.target() else {
            return Err("this session is not running a query right now".into());
        };
        deliver(&target, CANCEL_TIMEOUT).await.map_err(|e| e.to_string())
    }
}

/// Deliver a cancellation to the backend.
///
/// Postgres never answers a `CancelRequest`; it closes the socket whether or
/// not anything was cancelled. So this is best-effort by construction, and a
/// timeout is applied so a hung backend cannot tie up the caller.
pub async fn deliver(target: &CancelTarget, timeout: Duration) -> std::io::Result<()> {
    let connect = TcpStream::connect((target.host.as_str(), target.port));
    let mut socket = tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "cancel connect timed out"))??;

    let packet = StartupPacket::CancelRequest { process_id: target.backend_pid, secret_key: target.backend_secret };
    socket.write_all(&packet.encode()).await?;
    socket.flush().await?;
    let _ = socket.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn target() -> CancelTarget {
        CancelTarget { host: "pg".into(), port: 5432, backend_pid: 9001, backend_secret: -42 }
    }

    #[test]
    fn a_retargeted_scope_resolves_to_its_backend() {
        let registry = Arc::new(CancelRegistry::new());
        let scope = registry.scope();
        assert_eq!(registry.lookup(scope.key()), None, "a fresh session holds no backend");

        scope.retarget(Some(target()));
        assert_eq!(registry.lookup(scope.key()), Some(target()));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn releasing_a_backend_stops_the_key_pointing_at_it() {
        // The transaction-mode hazard: between statements the client owns
        // nothing, and the backend it just used may already be serving someone
        // else. Cancelling then would hit a stranger's query.
        let registry = Arc::new(CancelRegistry::new());
        let scope = registry.scope();
        scope.retarget(Some(target()));
        scope.retarget(None);
        assert_eq!(scope.target(), None, "an idle client must have nothing to cancel");
        assert_eq!(registry.len(), 1, "but the session is still connected");
    }

    #[test]
    fn the_key_handed_to_the_client_is_never_the_backend_key() {
        // If we passed the backend's key through, any client could cancel any
        // query on that backend, including one belonging to another tenant.
        let registry = Arc::new(CancelRegistry::new());
        let scope = registry.scope();
        scope.retarget(Some(target()));
        assert_ne!(scope.key().secret_key, -42, "the secret must be ours, not the backend's");
        assert_ne!(scope.key().process_id, 9001);
    }

    #[test]
    fn secrets_are_unpredictable_and_keys_are_unique() {
        let registry = Arc::new(CancelRegistry::new());
        let mut secrets = std::collections::HashSet::new();
        let mut pids = std::collections::HashSet::new();
        let scopes: Vec<_> = (0..500).map(|_| registry.scope()).collect();
        for scope in &scopes {
            secrets.insert(scope.key().secret_key);
            pids.insert(scope.key().process_id);
        }
        assert_eq!(pids.len(), 500, "process ids must not collide");
        assert!(secrets.len() > 495, "secrets must be random, got {} distinct", secrets.len());
    }

    #[test]
    fn an_unknown_key_resolves_to_nothing_rather_than_a_guess() {
        let registry = Arc::new(CancelRegistry::new());
        let scope = registry.scope();
        scope.retarget(Some(target()));
        // A stale or forged key must cancel nothing at all.
        assert_eq!(registry.lookup(CancelKey { process_id: 12345, secret_key: 678 }), None);
    }

    #[test]
    fn a_finished_session_takes_its_key_with_it() {
        let registry = Arc::new(CancelRegistry::new());
        let scope = registry.scope();
        let key = scope.key();
        scope.retarget(Some(target()));

        let clone = scope.clone();
        drop(scope);
        assert_eq!(registry.lookup(key), Some(target()), "a live trace still holds the slot");

        drop(clone);
        assert_eq!(registry.lookup(key), None, "a finished session must not remain cancellable");
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn cancelling_an_idle_session_reports_why_rather_than_dialling_nothing() {
        let registry = Arc::new(CancelRegistry::new());
        let scope = registry.scope();
        let error = scope.cancel().await.expect_err("there is no query to cancel");
        assert!(error.contains("not running a query"), "got {error}");
    }

    #[tokio::test]
    async fn delivery_sends_the_backend_key_pair_verbatim() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            socket.read_exact(&mut buf).await.unwrap();
            buf
        });

        let target =
            CancelTarget { host: addr.ip().to_string(), port: addr.port(), backend_pid: 9001, backend_secret: -42 };
        deliver(&target, Duration::from_secs(2)).await.unwrap();

        let buf = server.await.unwrap();
        assert_eq!(i32::from_be_bytes(buf[0..4].try_into().unwrap()), 16);
        assert_eq!(i32::from_be_bytes(buf[4..8].try_into().unwrap()), 80_877_102);
        assert_eq!(i32::from_be_bytes(buf[8..12].try_into().unwrap()), 9001);
        assert_eq!(i32::from_be_bytes(buf[12..16].try_into().unwrap()), -42, "negative secrets must survive");
    }

    #[tokio::test]
    async fn delivery_to_a_dead_backend_fails_quickly_instead_of_hanging() {
        let target = CancelTarget { host: "127.0.0.1".into(), port: 1, backend_pid: 1, backend_secret: 2 };
        assert!(deliver(&target, Duration::from_millis(500)).await.is_err());
    }
}
