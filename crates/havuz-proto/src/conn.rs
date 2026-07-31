//! What the pool actually stores.
//!
//! The pool engine is generic over these two traits and knows nothing else
//! about a family. Note what is deliberately *absent*: there is no `query`
//! method. A pooler relays bytes; it does not execute statements.

use std::time::Instant;

use async_trait::async_trait;

use crate::error::ProtoResult;

/// Result of preparing a backend for reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetOutcome {
    /// Nothing to undo; the connection was already clean.
    AlreadyClean,
    /// Session state was cleared and the connection may be reused.
    Cleaned,
    /// The connection cannot be made clean and must be closed.
    Discard,
}

/// A live connection to a database, owned by the pool.
#[async_trait]
pub trait BackendConn: Send + Sync + 'static {
    /// Non-blocking liveness check.
    ///
    /// Must not perform a round trip. Following dbx's `RecyclingMethod::Fast`,
    /// we accept that a stale connection is discovered on first use rather than
    /// paying a `SELECT 1` on every checkout — that round trip is pure overhead
    /// on the hot path and buys very little.
    fn is_broken(&self) -> bool;

    /// When the connection was established. Drives `max_lifetime`.
    fn opened_at(&self) -> Instant;

    /// Backend process identifier, when the protocol exposes one. Purely for
    /// diagnostics; lets the dashboard line up with `pg_stat_activity`.
    fn backend_pid(&self) -> Option<u32> {
        None
    }

    /// Clear any session state left by the previous client.
    ///
    /// Only called when the connection is actually being recycled between
    /// clients, never on the per-transaction path.
    async fn reset(&mut self) -> ProtoResult<ResetOutcome>;

    /// Close politely, sending whatever termination message the protocol wants.
    async fn close(&mut self);
}

/// Opens new backend connections for one pool.
#[async_trait]
pub trait BackendConnector: Send + Sync + 'static {
    type Conn: BackendConn;

    /// Establish and authenticate a connection, ready for a client to use.
    async fn connect(&self) -> ProtoResult<Self::Conn>;

    /// Label used in logs and metrics, e.g. `pg-primary.internal:5432`.
    fn target_label(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct FakeConn {
        opened_at: Instant,
        broken: bool,
        closed: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BackendConn for FakeConn {
        fn is_broken(&self) -> bool {
            self.broken
        }

        fn opened_at(&self) -> Instant {
            self.opened_at
        }

        async fn reset(&mut self) -> ProtoResult<ResetOutcome> {
            if self.broken {
                Ok(ResetOutcome::Discard)
            } else {
                Ok(ResetOutcome::Cleaned)
            }
        }

        async fn close(&mut self) {
            self.closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct FakeConnector {
        opened: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BackendConnector for FakeConnector {
        type Conn = FakeConn;

        async fn connect(&self) -> ProtoResult<FakeConn> {
            self.opened.fetch_add(1, Ordering::Relaxed);
            Ok(FakeConn { opened_at: Instant::now(), broken: false, closed: self.closed.clone() })
        }

        fn target_label(&self) -> String {
            "fake:5432".into()
        }
    }

    #[tokio::test]
    async fn the_trait_pair_is_enough_to_manage_a_connection_lifecycle() {
        let opened = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let connector = FakeConnector { opened: opened.clone(), closed: closed.clone() };

        let mut conn = connector.connect().await.unwrap();
        assert_eq!(opened.load(Ordering::Relaxed), 1);
        assert!(!conn.is_broken());
        assert_eq!(conn.reset().await.unwrap(), ResetOutcome::Cleaned);
        assert_eq!(conn.backend_pid(), None, "pid is optional and defaults to unknown");

        conn.close().await;
        assert_eq!(closed.load(Ordering::Relaxed), 1);
        assert_eq!(connector.target_label(), "fake:5432");
    }

    #[tokio::test]
    async fn a_broken_connection_asks_to_be_discarded_instead_of_recycled() {
        let mut conn = FakeConn { opened_at: Instant::now(), broken: true, closed: Arc::new(AtomicUsize::new(0)) };
        assert!(conn.is_broken());
        assert_eq!(conn.reset().await.unwrap(), ResetOutcome::Discard);
    }

    #[test]
    fn connector_is_object_safe_enough_for_dynamic_pools() {
        // The pool is generic over the connector, but the family layer above it
        // holds trait objects; make sure the connection type at least can be.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FakeConn>();
        assert_send_sync::<FakeConnector>();
    }
}
