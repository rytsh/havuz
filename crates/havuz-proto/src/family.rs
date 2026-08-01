//! The object-safe entry point a listener holds.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use havuz_registry::FamilyDescriptor;
use tokio::net::TcpStream;

use crate::error::ProtoResult;
use crate::flow::PinReason;

/// The pools reachable through the listener a connection arrived on.
///
/// Routing is decided by configuration, not by the protocol: a pool declares
/// its port, and pools that declare the same port share one socket. That leaves
/// the family two cases and no guessing.
///
/// * One pool on the port — the client's database field is not routing
///   information at all, and is ignored. This is what lets a connection string
///   omit the database entirely.
/// * Several pools — the client names one. A name that is not on this listener
///   is refused with the list of names that are, rather than with "database
///   does not exist", which sends an operator looking in the wrong place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRoute {
    pools: Arc<[String]>,
}

impl PoolRoute {
    /// Panics if `pools` is empty: a listener with no pools should have been
    /// closed rather than bound.
    pub fn new(pools: impl Into<Arc<[String]>>) -> Self {
        let pools = pools.into();
        assert!(!pools.is_empty(), "a listener must serve at least one pool");
        Self { pools }
    }

    /// The pool a client reaches without naming one, if there is no ambiguity.
    pub fn sole(&self) -> Option<&str> {
        match &*self.pools {
            [only] => Some(only),
            _ => None,
        }
    }

    pub fn contains(&self, pool: &str) -> bool {
        self.pools.iter().any(|candidate| candidate == pool)
    }

    /// For the error message a client sees when it names the wrong pool.
    pub fn names(&self) -> &[String] {
        &self.pools
    }
}

/// Who connected, resolved during the family's handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// havuz user, not the backend service account.
    pub user: String,
    /// Pool this connection landed on, already resolved against the listener's
    /// [`PoolRoute`].
    pub pool: String,
    /// Client-supplied application name, when the protocol carries one. Echoed
    /// into the backend so `pg_stat_activity` can still attribute work to a
    /// real client even though every backend connection shares one account.
    pub application_name: Option<String>,
    pub peer: SocketAddr,
}

/// How a client session ended. Feeds the statistics layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeOutcome {
    /// Whether the connection ever got past authentication.
    pub authenticated: bool,
    /// Set if the session lost its ability to multiplex.
    pub pinned: Option<PinReason>,
    /// Transactions (or statements, in statement mode) relayed.
    pub exchanges: u64,
    pub bytes_to_client: u64,
    pub bytes_to_backend: u64,
}

impl ServeOutcome {
    pub fn rejected() -> Self {
        Self { authenticated: false, pinned: None, exchanges: 0, bytes_to_client: 0, bytes_to_backend: 0 }
    }
}

/// One wire-protocol family.
///
/// Object-safe on purpose: `havuz-server` binds every listener and stores
/// `Arc<dyn ProtocolFamily>` without knowing which family it got. Families do
/// not own sockets — that is what let one family monopolise the process before
/// per-pool ports existed.
#[async_trait]
pub trait ProtocolFamily: Send + Sync + 'static {
    /// Static metadata, used by the admin API and to validate configuration.
    fn descriptor(&self) -> &'static FamilyDescriptor;

    /// Take ownership of an accepted socket and run the session to completion.
    ///
    /// The family performs its own handshake, resolves the [`ClientIdentity`]
    /// within `route`, checks a backend out of the pool and relays until either
    /// side hangs up.
    async fn serve(&self, io: TcpStream, peer: SocketAddr, route: &PoolRoute) -> ProtoResult<ServeOutcome>;

    /// Best-effort probe used by "Test Connection" in the UI and by the
    /// background health checker.
    ///
    /// Runs on the control plane, never on the hot path, so families are free
    /// to use a high-level client library here.
    async fn probe(&self, pool: &str) -> ProtoResult<Probe>;
}

/// Result of a control-plane probe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Probe {
    /// Server version string as reported by the backend.
    pub version: String,
    /// Round-trip latency of the probe.
    pub latency_ms: u64,
    /// Whether the target accepts writes. Distinguishes a primary from a
    /// replica without the operator having to label it by hand.
    pub read_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_outcome_records_nothing_but_the_rejection() {
        let outcome = ServeOutcome::rejected();
        assert!(!outcome.authenticated);
        assert_eq!(outcome.exchanges, 0);
        assert_eq!(outcome.pinned, None);
        assert_eq!(outcome.bytes_to_client, 0);
        assert_eq!(outcome.bytes_to_backend, 0);
    }

    #[test]
    fn a_listener_with_one_pool_needs_no_database_name() {
        let route = PoolRoute::new(vec!["app_main".to_string()]);
        assert_eq!(route.sole(), Some("app_main"));
        assert!(route.contains("app_main"));
    }

    #[test]
    fn a_shared_listener_refuses_to_guess() {
        let route = PoolRoute::new(vec!["orders".to_string(), "reports".to_string()]);
        assert_eq!(route.sole(), None, "picking one would silently connect the client to the wrong database");
        assert!(route.contains("reports"));
        assert!(!route.contains("payroll"));
        assert_eq!(route.names(), ["orders", "reports"]);
    }

    #[test]
    #[should_panic(expected = "at least one pool")]
    fn a_listener_with_no_pools_is_a_bug_not_a_state() {
        let _ = PoolRoute::new(Vec::<String>::new());
    }

    #[test]
    fn client_identity_separates_havuz_user_from_pool() {
        let id = ClientIdentity {
            user: "svc_orders".into(),
            pool: "app_main".into(),
            application_name: Some("orders-api".into()),
            peer: "10.0.0.7:52344".parse().unwrap(),
        };
        // The backend service account is deliberately not part of the client
        // identity: clients never learn it.
        assert_eq!(id.user, "svc_orders");
        assert_eq!(id.pool, "app_main");
        assert_eq!(id.application_name.as_deref(), Some("orders-api"));
    }

    #[test]
    fn probe_serialises_for_the_test_connection_button() {
        let probe = Probe { version: "PostgreSQL 16.2".into(), latency_ms: 3, read_only: false };
        let json = serde_json::to_value(&probe).unwrap();
        assert_eq!(json["version"], "PostgreSQL 16.2");
        assert_eq!(json["latency_ms"], 3);
        assert_eq!(json["read_only"], false);
    }

    #[test]
    fn family_trait_is_object_safe() {
        // If this stops compiling, listeners can no longer be family-agnostic
        // and the whole extensibility story collapses.
        fn _accepts_dyn(_: &dyn ProtocolFamily) {}
    }
}
