//! Admin HTTP API and dashboard.
//!
//! Two constraints shape this crate.
//!
//! **The hot path must not pay for the dashboard.** Handlers only ever read an
//! `ArcSwap` snapshot of the configuration and lock-free pool counters. No
//! handler takes a lock the pooler also takes, so a slow HTTP client cannot
//! slow down a query.
//!
//! **Secrets are write-only.** A password can be submitted, never read back.
//! `GET /api/v1/pools` reports whether a backend password is *set*, never what
//! it is.

mod auth;
mod error;
mod metrics;
mod routes;
mod state;
mod ui;

pub use error::ApiError;
pub use routes::router;
pub use state::AdminState;
