//! Identities havuz learned from the wire rather than from its user list.
//!
//! A pool with `backend_auth = passthrough` admits clients that have no
//! [`UserConfig`](havuz_core::state::UserConfig). There is nothing local to
//! check their password against the first time they appear, so havuz asks the
//! database: it opens one connection with those credentials, and only sends
//! `AuthenticationOk` if that worked.
//!
//! Doing that on *every* connection would make the pool a free brute-force
//! channel pointed at PostgreSQL, and would put a full backend handshake in
//! front of every client. So the answer is remembered — as a verifier, derived
//! here with havuz's own salt, never the password itself. From the second
//! connection on, the identity takes exactly the same locally-checked path a
//! configured user takes, and a wrong password is refused by havuz.
//!
//! ## Why this is not in the state file
//!
//! These are not havuz users. They carry no grants, no `read_only`, no
//! `disabled`; they are a cache of "the database said yes to this password",
//! and the database is free to change its mind. Persisting them would create a
//! second, stale user directory that nobody administers and that outlives the
//! credential it was derived from.
//!
//! So this type has no `Serialize`, deliberately, in the same way
//! [`BackendCredential`](crate::session::BackendCredential) has none. It lives
//! for as long as the identity has connections and goes when
//! [`forget`](EphemeralIdentities::forget) is called from the idle sweeper —
//! which is the same moment the plaintext itself is dropped.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::scram::ScramVerifier;

/// Verifiers for identities the database vouched for, held in memory only.
#[derive(Debug, Default)]
pub struct EphemeralIdentities {
    /// Keyed by pool as well as user: the same name on two pools may be two
    /// different database roles with two different passwords, and one pool
    /// vouching for a password must not admit that name to another.
    known: RwLock<HashMap<(String, String), ScramVerifier>>,
}

impl EphemeralIdentities {
    pub fn new() -> Self {
        Self::default()
    }

    /// What to check this identity's password against, if anything.
    ///
    /// `None` means havuz has never admitted it and only the database can say.
    pub fn verifier(&self, pool: &str, user: &str) -> Option<ScramVerifier> {
        self.known.read().expect("ephemeral identity map poisoned").get(&key(pool, user)).cloned()
    }

    /// Record that the database accepted this password.
    ///
    /// The verifier is derived with a fresh salt rather than reusing anything
    /// the backend sent, so what is held here is not usable against the
    /// database even if the process memory is read.
    pub fn learn(&self, pool: &str, user: &str, password: &str) {
        let verifier = ScramVerifier::from_password(password);
        self.known.write().expect("ephemeral identity map poisoned").insert(key(pool, user), verifier);
    }

    /// Keep only the identities of `pool` that `keep` still says yes to.
    ///
    /// Called from the idle sweeper with "has a live session, or connections
    /// still open". Keeping a verifier past that would let a credential the
    /// database has since revoked go on opening sessions for as long as the
    /// process lived.
    ///
    /// Phrased as a sweep over what is held rather than as a `forget` at each
    /// disconnect, because an identity can be vouched for and then never get a
    /// connection at all — the client goes away between the two. Anything keyed
    /// on the disconnect would leak exactly those.
    pub fn retain(&self, pool: &str, keep: impl Fn(&str) -> bool) {
        self.known.write().expect("ephemeral identity map poisoned").retain(|(p, user), _| p != pool || keep(user));
    }

    /// Drop every identity belonging to a pool, for when the pool itself is
    /// removed or reconfigured.
    pub fn forget_pool(&self, pool: &str) {
        self.known.write().expect("ephemeral identity map poisoned").retain(|(p, _), _| p != pool);
    }

    /// How many identities are currently vouched for. For the dashboard and for
    /// tests; there is no way to get a password back out of this type.
    pub fn len(&self) -> usize {
        self.known.read().expect("ephemeral identity map poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn key(pool: &str, user: &str) -> (String, String) {
    (pool.to_string(), user.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(verifier: &ScramVerifier, password: &str) -> bool {
        let candidate = ScramVerifier::from_password_with(password, verifier.salt(), verifier.iterations());
        candidate.stored_key() == verifier.stored_key()
    }

    #[test]
    fn an_identity_is_unknown_until_the_database_has_vouched_for_it() {
        // The first connection has to reach the backend; anything else would
        // mean havuz decided a password it has never seen was correct.
        let ids = EphemeralIdentities::new();
        assert!(ids.verifier("app_main", "alice").is_none());

        ids.learn("app_main", "alice", "hunter2");
        assert!(matches(&ids.verifier("app_main", "alice").unwrap(), "hunter2"));
    }

    #[test]
    fn a_learned_verifier_refuses_the_wrong_password_without_asking_the_database() {
        // This is the whole point of remembering: the second attempt with a bad
        // password stops at havuz instead of becoming a database login.
        let ids = EphemeralIdentities::new();
        ids.learn("app_main", "alice", "hunter2");
        assert!(!matches(&ids.verifier("app_main", "alice").unwrap(), "hunter3"));
    }

    #[test]
    fn the_verifier_is_salted_here_and_not_taken_from_the_backend() {
        // Two pools that learned the same password must not produce the same
        // stored key, or the map becomes a rainbow table of live credentials.
        let ids = EphemeralIdentities::new();
        ids.learn("orders", "alice", "hunter2");
        ids.learn("reports", "alice", "hunter2");
        let a = ids.verifier("orders", "alice").unwrap();
        let b = ids.verifier("reports", "alice").unwrap();
        assert_ne!(a.salt(), b.salt(), "a shared salt would leak that two identities share a password");
    }

    #[test]
    fn one_pool_vouching_for_a_name_does_not_admit_it_to_another() {
        // Same name, different database roles. Postgres would refuse; havuz
        // must not pre-empt that with a cached yes.
        let ids = EphemeralIdentities::new();
        ids.learn("orders", "alice", "hunter2");
        assert!(ids.verifier("reports", "alice").is_none());
    }

    #[test]
    fn an_identity_that_is_no_longer_connected_goes_back_to_the_database() {
        // A revoked password that stayed cached would keep working for the life
        // of the process.
        let ids = EphemeralIdentities::new();
        ids.learn("app_main", "alice", "hunter2");
        ids.learn("app_main", "bob", "hunter2");
        ids.retain("app_main", |user| user == "bob");
        assert!(ids.verifier("app_main", "alice").is_none());
        assert!(ids.verifier("app_main", "bob").is_some(), "bob is still connected");
    }

    #[test]
    fn sweeping_one_pool_leaves_the_others_alone() {
        // The sweeper works pool by pool and knows nothing about who is
        // connected elsewhere, so it must not be able to answer for them.
        let ids = EphemeralIdentities::new();
        ids.learn("orders", "alice", "hunter2");
        ids.learn("reports", "alice", "hunter2");
        ids.retain("orders", |_| false);
        assert!(ids.verifier("orders", "alice").is_none());
        assert!(ids.verifier("reports", "alice").is_some());
    }

    #[test]
    fn a_removed_pool_takes_its_identities_with_it() {
        let ids = EphemeralIdentities::new();
        ids.learn("orders", "alice", "hunter2");
        ids.learn("orders", "bob", "hunter2");
        ids.learn("reports", "alice", "hunter2");
        ids.forget_pool("orders");
        assert_eq!(ids.len(), 1);
        assert!(ids.verifier("reports", "alice").is_some());
    }
}
