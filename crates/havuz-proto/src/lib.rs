//! The seam every protocol family plugs into.
//!
//! A pooler's central question is not "how do I run this query" — it is **"when
//! may I take this backend away from this client?"**. Everything in this crate
//! exists to answer that question in a way the generic pool engine can consume
//! without knowing anything about Postgres, MySQL or RESP.
//!
//! Getting this boundary right is what makes adding a second family a matter of
//! weeks instead of a rewrite. Concretely:
//!
//! * [`FlowEvent`] is the only vocabulary the pool understands.
//! * [`SessionState`] turns a stream of those events into a release decision.
//! * [`BackendConn`] / [`BackendConnector`] are what the pool actually stores.
//! * [`ProtocolFamily`] is object-safe so listeners can hold `Arc<dyn ..>`.

mod conn;
mod error;
mod family;
mod flow;
mod pins;

pub use conn::{BackendConn, BackendConnector, ResetOutcome};
pub use error::{ProtoError, ProtoResult};
pub use family::{ClientIdentity, PoolRoute, Probe, ProtocolFamily, ServeOutcome};
pub use flow::{FlowEvent, PinReason, SessionState};
pub use pins::{PinOffender, PinRegistry, PinReport, ReasonCount};

pub use havuz_registry::PoolMode;
