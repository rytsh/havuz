//! Protocol-agnostic connection pool.
//!
//! This is a *server-side* pool and that distinction matters. Client-side pools
//! such as `deadpool` or `bb8` assume one process with one credential and a
//! cooperative caller. A pooler needs things they do not offer:
//!
//! * a bounded wait queue with an explicit timeout, so an exhausted pool
//!   rejects clients instead of growing an unbounded backlog;
//! * per-checkout accounting that feeds a live dashboard;
//! * pause / drain, so configuration changes and shutdowns are graceful;
//! * lifetime and idle reaping driven by the operator's limits.
//!
//! One idea *is* borrowed from client-side pools: no validation query on
//! checkout. Round-tripping `SELECT 1` before every hand-off is pure latency.
//! A connection that died unobserved is detected on first use and the client
//! sees a normal backend error, which is what would have happened anyway.

mod breaker;
mod counters;
mod pool;

pub use breaker::{BreakerConfig, BreakerSnapshot, BreakerState, CircuitBreaker};
pub use counters::{PoolSnapshot, WaitStats};
pub use pool::{Checkout, Pool, PoolError, PoolStatus};
