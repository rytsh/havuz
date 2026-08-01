//! Shared state for admin handlers.

use std::sync::Arc;
use std::time::Instant;

use havuz_control::{FamilySet, Registries};
use havuz_core::{AdminAuth, StateStore};
use havuz_secrets::MasterKey;

#[derive(Clone)]
pub struct AdminState {
    pub store: Arc<StateStore>,
    pub master_key: Arc<MasterKey>,
    /// Every family in this process, behind the control-plane seam.
    ///
    /// Handlers route by the family a pool names. None of them mentions a wire
    /// protocol, which is what used to force this crate to depend on
    /// `havuz-pg` and with it the whole Postgres codec.
    pub families: FamilySet,
    /// Sessions, pins, holders and traces, shared by every family so the
    /// dashboard shows one list rather than one per protocol.
    pub registries: Registries,
    /// A port a pool may not claim, because this process already holds it.
    ///
    /// `None` when the admin listener cannot collide with pool ports at all —
    /// a different interface, for instance.
    pub reserved_port: Option<u16>,
    /// Whether the client-facing listeners can offer TLS.
    ///
    /// Pools that ask clients for a password require it, and refusing them at
    /// creation is far kinder than refusing every connection afterwards.
    pub client_tls: bool,
    /// Expected bearer token, resolved once at startup. `None` means the
    /// listener is on loopback and unauthenticated, which the bootstrap
    /// validation already enforced.
    pub token: Option<Arc<str>>,
    pub started_at: Instant,
    pub serve_ui: bool,
}

impl AdminState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<StateStore>,
        master_key: Arc<MasterKey>,
        families: FamilySet,
        registries: Registries,
        reserved_port: Option<u16>,
        client_tls: bool,
        auth: &AdminAuth,
        serve_ui: bool,
    ) -> Self {
        let token = match auth {
            AdminAuth::None => None,
            AdminAuth::Bearer { token_env } => {
                std::env::var(token_env).ok().filter(|t| !t.is_empty()).map(|t| Arc::from(t.as_str()))
            }
        };

        Self {
            store,
            master_key,
            families,
            registries,
            reserved_port,
            client_tls,
            token,
            started_at: Instant::now(),
            serve_ui,
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_control::testing::FakeFamily;
    use havuz_core::State;

    fn state(auth: &AdminAuth) -> AdminState {
        let key = Arc::new(MasterKey::generate());
        let store = Arc::new(StateStore::ephemeral(State::default()));
        let registries = Registries::ephemeral();
        let families = FamilySet::new(vec![FakeFamily::new(store.clone())]);
        AdminState::new(store, key, families, registries, None, true, auth, false)
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
