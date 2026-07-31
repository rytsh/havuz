//! PostgreSQL wire protocol, protocol version 3.
//!
//! Two rules shape this crate.
//!
//! **The data path owns its own codec.** We do not build on `tokio-postgres`
//! here. A pooler relays frames; a client library parses, buffers and
//! reinterprets them. Putting a high-level client in the middle would add
//! allocation and semantics we then have to undo. `tokio-postgres` is used, but
//! only on the control plane — health probes and "Test Connection" — where a
//! round trip more or less is irrelevant.
//!
//! **Client credentials never reach the backend.** havuz authenticates clients
//! against its own user list and opens backend connections with a single
//! service account. This is not a shortcut: sharing one backend identity is
//! precisely what makes a backend connection reusable by any client, and it is
//! also forced on us because SCRAM cannot be proxied (channel binding ties the
//! exchange to the TLS session).

pub mod backend;
pub mod cancel;
pub mod classify;
pub mod family;
pub mod group;
pub mod health;
pub mod prepared;
pub mod protocol;
pub mod relay;
pub mod routing;
pub mod scram;
pub mod session;
pub mod stream;
pub mod trace;
pub mod txn;

pub use backend::{BackendConfig, PgBackend, PgConnector};
pub use cancel::{CancelKey, CancelRegistry, CancelTarget};
pub use classify::{classify, route_intent, ClientIntent, RouteIntent};
pub use family::PgFamily;
pub use group::{GroupSnapshot, PoolGroup};
pub use prepared::{BackendStatements, ClientStatements, PreparedError, Rewrite};
pub use protocol::{ErrorField, Message, ProtocolError, StartupPacket, TransactionStatus, PROTOCOL_VERSION_3};
pub use relay::{session_relay, session_relay_traced, RelayStats};
pub use routing::{PrimaryReason, ReplicaState, Route, Router, RoutingSnapshot, SessionRouting};
pub use scram::{ScramClient, ScramError, ScramServer, ScramVerifier};
pub use session::{Authenticator, ClientHandshake, HandshakeOutcome};
pub use stream::MaybeTls;
pub use trace::{
    ActiveTrace, QueryResult, ResultSet, TraceContext, TraceDetail, TraceError, TraceFilter, TraceStore, TraceSummary,
};
pub use txn::{transaction_relay, TxnOutcome};
