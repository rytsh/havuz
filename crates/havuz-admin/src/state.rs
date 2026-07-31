//! Shared state for admin handlers.

use std::sync::Arc;
use std::time::Instant;

use havuz_core::{AdminAuth, StateStore};
use havuz_pg::PgFamily;
use havuz_secrets::MasterKey;

#[derive(Clone)]
pub struct AdminState {
    pub store: Arc<StateStore>,
    pub master_key: Arc<MasterKey>,
    pub family: Arc<PgFamily>,
    /// Expected bearer token, resolved once at startup. `None` means the
    /// listener is on loopback and unauthenticated, which the bootstrap
    /// validation already enforced.
    pub token: Option<Arc<str>>,
    pub started_at: Instant,
    pub serve_ui: bool,
}

impl AdminState {
    pub fn new(
        store: Arc<StateStore>,
        master_key: Arc<MasterKey>,
        family: Arc<PgFamily>,
        auth: &AdminAuth,
        serve_ui: bool,
    ) -> Self {
        let token = match auth {
            AdminAuth::None => None,
            AdminAuth::Bearer { token_env } => {
                std::env::var(token_env).ok().filter(|t| !t.is_empty()).map(|t| Arc::from(t.as_str()))
            }
        };

        Self { store, master_key, family, token, started_at: Instant::now(), serve_ui }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_core::State;

    fn state(auth: &AdminAuth) -> AdminState {
        let key = Arc::new(MasterKey::generate());
        let store = Arc::new(StateStore::ephemeral(State::default()));
        let family = PgFamily::new(store.clone(), key.clone());
        AdminState::new(store, key, family, auth, false)
    }

    #[test]
    fn no_auth_means_no_expected_token() {
        assert!(state(&AdminAuth::None).token.is_none());
    }

    #[test]
    fn a_bearer_token_is_read_from_the_environment() {
        std::env::set_var("HAVUZ_TEST_ADMIN_TOKEN", "s3cret");
        let s = state(&AdminAuth::Bearer { token_env: "HAVUZ_TEST_ADMIN_TOKEN".into() });
        assert_eq!(s.token.as_deref(), Some("s3cret"));
        std::env::remove_var("HAVUZ_TEST_ADMIN_TOKEN");
    }

    #[test]
    fn an_empty_token_is_treated_as_absent() {
        std::env::set_var("HAVUZ_TEST_EMPTY_TOKEN", "");
        let s = state(&AdminAuth::Bearer { token_env: "HAVUZ_TEST_EMPTY_TOKEN".into() });
        assert!(s.token.is_none(), "an empty variable must not authenticate everyone");
        std::env::remove_var("HAVUZ_TEST_EMPTY_TOKEN");
    }
}
