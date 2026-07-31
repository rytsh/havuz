//! The object-safe entry point a listener holds.

use std::net::SocketAddr;

use async_trait::async_trait;
use havuz_registry::FamilyDescriptor;
use tokio::net::TcpStream;

use crate::error::ProtoResult;
use crate::flow::PinReason;

/// Who connected, resolved during the family's handshake.
///
/// The pool name comes from the protocol's own routing information — for
/// Postgres that is the `database` field of the startup packet — so a single
/// listener serves every pool of that family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// havuz user, not the backend service account.
    pub user: String,
    /// Pool the client asked for.
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
/// Object-safe on purpose: `havuz-server` binds a listener and stores
/// `Arc<dyn ProtocolFamily>` without knowing which family it got. Adding MySQL
/// later means implementing this trait and registering a descriptor — no
/// changes to the listener, the pool engine, the admin API or the UI.
#[async_trait]
pub trait ProtocolFamily: Send + Sync + 'static {
    /// Static metadata, used by the admin API and to validate configuration.
    fn descriptor(&self) -> &'static FamilyDescriptor;

    /// Take ownership of an accepted socket and run the session to completion.
    ///
    /// The family performs its own handshake, resolves the [`ClientIdentity`],
    /// checks it out of the pool and relays until either side hangs up.
    async fn serve(&self, io: TcpStream, peer: SocketAddr) -> ProtoResult<ServeOutcome>;

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
