//! A PostgreSQL frontend for databases that have no Rust driver.
//!
//! Oracle, DB2, Informix, Teradata, Snowflake and the rest of the long tail all
//! have exactly one thing in common: a JDBC driver. This crate lets a client
//! reach them by speaking the PostgreSQL wire protocol to the client and JDBC,
//! through a JVM sidecar, to the database.
//!
//! ## What makes this different from every other family
//!
//! havuz relays. A pooler reads a frame from a client, writes it to a backend,
//! and copies the answer back without understanding it — `havuz-pg` says so in
//! its first paragraph and the whole performance story follows from it.
//!
//! **There is nothing to relay here.** JDBC is a Java API, not a wire protocol;
//! no bytes come back that a PostgreSQL client could read. So this crate parses
//! the client's statements, executes them through the sidecar, and *composes*
//! `RowDescription`, `DataRow` and `CommandComplete` itself. It is a PostgreSQL
//! server, and that is a different job from the rest of havuz.
//!
//! Two consequences worth stating plainly:
//!
//! * **A JVM is required.** havuz reports that clearly at startup rather than
//!   failing on the first connection.
//! * **The performance figures in the README do not apply.** They measure a
//!   relay. This path parses, converts and re-encodes every value.
//!
//! ## What it reuses
//!
//! Everything client-facing: the PostgreSQL codec, the startup handshake,
//! SCRAM, TLS, per-user authentication, the session registry and query tracing
//! all come from `havuz-pg` unchanged. The bridge is a frontend for that
//! protocol, so depending on its implementation is not a layering accident.

pub mod agent;
pub mod conn;
pub mod family;
pub mod rewrite;
pub mod session;
pub mod types;

pub use agent::{Agent, AgentCommand, AgentError};
pub use conn::{agent_command, JdbcBackend, JdbcConfig, JdbcConnector};
pub use family::{JdbcFamily, FAMILY_ID};
pub use rewrite::{to_jdbc, Rewritten};
pub use session::{startup_parameters, Session, SessionStats};
pub use types::{command_tag, pg_type, Encoding, PgType};
