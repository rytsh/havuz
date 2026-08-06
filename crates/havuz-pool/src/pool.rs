//! The pool engine.

use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use havuz_core::PoolLimits;
use havuz_proto::{BackendConn, BackendConnector, ProtoError};
use tokio::sync::{mpsc, Semaphore};

use crate::counters::{Counters, PoolSnapshot};

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("pool '{pool}' exhausted: waited {waited_ms}ms for a backend")]
    Timeout { pool: String, waited_ms: u64 },
    #[error("pool '{pool}' is {status}")]
    Unavailable { pool: String, status: &'static str },
    #[error("pool '{pool}': cannot open backend connection: {source}")]
    Connect {
        pool: String,
        #[source]
        source: ProtoError,
    },
}

impl PoolError {
    pub fn kind(&self) -> &'static str {
        match self {
            PoolError::Timeout { .. } => "timeout",
            PoolError::Unavailable { .. } => "unavailable",
            PoolError::Connect { .. } => "connect",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolStatus {
    Active,
    /// Existing checkouts continue; new ones are refused. Used while a pool is
    /// being reconfigured.
    Paused,
    /// Like paused, but idle connections are closed as they come back.
    Draining,
    Closed,
}

impl PoolStatus {
    fn as_str(self) -> &'static str {
        match self {
            PoolStatus::Active => "active",
            PoolStatus::Paused => "paused",
            PoolStatus::Draining => "draining",
            PoolStatus::Closed => "closed",
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => PoolStatus::Active,
            1 => PoolStatus::Paused,
            2 => PoolStatus::Draining,
            _ => PoolStatus::Closed,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            PoolStatus::Active => 0,
            PoolStatus::Paused => 1,
            PoolStatus::Draining => 2,
            PoolStatus::Closed => 3,
        }
    }
}

struct Slot<T> {
    conn: T,
    idle_since: Instant,
}

struct Inner<C: BackendConnector> {
    name: String,
    connector: Arc<C>,
    limits: PoolLimits,
    /// One permit per backend connection we are allowed to have checked out.
    /// Idle connections do not hold permits, which is what keeps
    /// `active + idle <= max_size` true without a second counter.
    permits: Arc<Semaphore>,
    idle: Mutex<VecDeque<Slot<C::Conn>>>,
    counters: Counters,
    status: AtomicU8,
    /// Closing is async but `Drop` is not, so retired connections are handed to
    /// a background task that says goodbye properly.
    closer: mpsc::UnboundedSender<C::Conn>,
}

impl<C: BackendConnector> Inner<C> {
    fn status(&self) -> PoolStatus {
        PoolStatus::from_u8(self.status.load(Ordering::Acquire))
    }

    fn retire(&self, conn: C::Conn) {
        self.counters.closed_total.fetch_add(1, Ordering::Relaxed);
        // If the closer task is gone we are shutting down; dropping the
        // connection still closes the socket.
        let _ = self.closer.send(conn);
    }

    fn is_expired(&self, conn: &C::Conn) -> bool {
        !self.limits.max_lifetime.is_zero() && conn.opened_at().elapsed() >= self.limits.max_lifetime
    }
}

/// A pool of backend connections for one configured pool.
pub struct Pool<C: BackendConnector> {
    inner: Arc<Inner<C>>,
}

impl<C: BackendConnector> Clone for Pool<C> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<C: BackendConnector> Pool<C> {
    /// Build a pool and start its background tasks.
    ///
    /// Must be called from within a Tokio runtime.
    pub fn new(name: impl Into<String>, connector: Arc<C>, limits: PoolLimits) -> Self {
        let (closer_tx, mut closer_rx) = mpsc::unbounded_channel::<C::Conn>();

        let inner = Arc::new(Inner {
            name: name.into(),
            connector,
            permits: Arc::new(Semaphore::new(limits.max_size as usize)),
            limits,
            idle: Mutex::new(VecDeque::new()),
            counters: Counters::default(),
            status: AtomicU8::new(PoolStatus::Active.as_u8()),
            closer: closer_tx,
        });

        tokio::spawn(async move {
            while let Some(mut conn) = closer_rx.recv().await {
                conn.close().await;
            }
        });

        let pool = Self { inner };
        pool.spawn_reaper();
        pool
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn status(&self) -> PoolStatus {
        self.inner.status()
    }

    pub fn snapshot(&self) -> PoolSnapshot {
        self.inner.counters.snapshot(
            &self.inner.name,
            self.inner.limits.max_size,
            self.inner.limits.max_client_connections,
            self.inner.status().as_str(),
        )
    }

    /// Take a backend out of the pool, waiting up to `queue_timeout`.
    pub async fn acquire(&self) -> Result<Checkout<C>, PoolError> {
        let status = self.inner.status();
        if status != PoolStatus::Active {
            return Err(PoolError::Unavailable { pool: self.inner.name.clone(), status: status.as_str() });
        }

        let started = Instant::now();
        self.inner.counters.waiting.fetch_add(1, Ordering::Relaxed);
        let waiting = WaitingGuard(&self.inner.counters.waiting);
        let permit =
            tokio::time::timeout(self.inner.limits.queue_timeout, self.inner.permits.clone().acquire_owned()).await;
        drop(waiting);

        let permit = match permit {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(PoolError::Unavailable { pool: self.inner.name.clone(), status: "closed" });
            }
            Err(_) => {
                self.inner.counters.timeout_total.fetch_add(1, Ordering::Relaxed);
                let waited_ms = started.elapsed().as_millis() as u64;
                self.inner.counters.record_wait(started.elapsed().as_micros() as u64);
                return Err(PoolError::Timeout { pool: self.inner.name.clone(), waited_ms });
            }
        };

        self.inner.counters.record_wait(started.elapsed().as_micros() as u64);

        // Reuse an idle connection if one is still fit for service. No
        // validation round trip here on purpose; a connection that died
        // unobserved surfaces on first use.
        loop {
            let slot = {
                let mut idle = self.inner.idle.lock().expect("idle queue poisoned");
                idle.pop_front()
            };
            let Some(slot) = slot else { break };
            self.inner.counters.idle.fetch_sub(1, Ordering::Relaxed);

            if slot.conn.is_broken() || self.inner.is_expired(&slot.conn) {
                self.inner.counters.discarded_total.fetch_add(1, Ordering::Relaxed);
                self.inner.retire(slot.conn);
                continue;
            }

            self.inner.counters.active.fetch_add(1, Ordering::Relaxed);
            self.inner.counters.checkout_total.fetch_add(1, Ordering::Relaxed);
            return Ok(Checkout { conn: Some(slot.conn), inner: self.inner.clone(), permit, discard: false });
        }

        // Nothing reusable: open a new one. The permit is already held, so this
        // cannot overshoot max_size.
        let conn = match tokio::time::timeout(self.inner.limits.connect_timeout, self.inner.connector.connect()).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(source)) => {
                self.inner.counters.connect_error_total.fetch_add(1, Ordering::Relaxed);
                return Err(PoolError::Connect { pool: self.inner.name.clone(), source });
            }
            Err(_) => {
                self.inner.counters.connect_error_total.fetch_add(1, Ordering::Relaxed);
                let ms = self.inner.limits.connect_timeout.as_millis() as u64;
                return Err(PoolError::Connect { pool: self.inner.name.clone(), source: ProtoError::Timeout(ms) });
            }
        };

        self.inner.counters.created_total.fetch_add(1, Ordering::Relaxed);
        self.inner.counters.active.fetch_add(1, Ordering::Relaxed);
        self.inner.counters.checkout_total.fetch_add(1, Ordering::Relaxed);
        Ok(Checkout { conn: Some(conn), inner: self.inner.clone(), permit, discard: false })
    }

    /// Open connections up to `min_idle` so the first client does not pay for a
    /// handshake.
    pub async fn warmup(&self) -> Result<usize, PoolError> {
        let target = self.inner.limits.min_idle as usize;
        // The checkouts must be held simultaneously. Acquiring and releasing in
        // a loop would just hand the same connection back each time and warm
        // exactly one slot.
        let mut held = Vec::with_capacity(target);
        for _ in 0..target {
            held.push(self.acquire().await?);
        }
        let opened = held.len();
        drop(held);
        Ok(opened)
    }

    /// Refuse new checkouts. In-flight ones are untouched.
    pub fn pause(&self) {
        self.inner.status.store(PoolStatus::Paused.as_u8(), Ordering::Release);
    }

    pub fn resume(&self) {
        self.inner.status.store(PoolStatus::Active.as_u8(), Ordering::Release);
    }

    /// Refuse new checkouts and close idle connections now; the rest are closed
    /// as they are returned.
    pub fn drain(&self) -> usize {
        self.inner.status.store(PoolStatus::Draining.as_u8(), Ordering::Release);
        self.close_idle(0)
    }

    /// Permanently close the pool.
    pub fn close(&self) {
        self.inner.status.store(PoolStatus::Closed.as_u8(), Ordering::Release);
        self.inner.permits.close();
        self.close_idle(0);
    }

    /// Close idle connections down to `keep`. Returns how many were closed.
    fn close_idle(&self, keep: usize) -> usize {
        let mut retired = Vec::new();
        {
            let mut idle = self.inner.idle.lock().expect("idle queue poisoned");
            while idle.len() > keep {
                let Some(slot) = idle.pop_back() else { break };
                retired.push(slot.conn);
            }
        }
        let count = retired.len();
        self.inner.counters.idle.fetch_sub(count as u64, Ordering::Relaxed);
        for conn in retired {
            self.inner.retire(conn);
        }
        count
    }

    /// Close idle connections that exceeded `idle_timeout` or `max_lifetime`,
    /// never dropping below `min_idle`.
    pub fn reap(&self) -> usize {
        let limits = &self.inner.limits;
        let min_idle = limits.min_idle as usize;
        let mut retired = Vec::new();

        {
            let mut idle = self.inner.idle.lock().expect("idle queue poisoned");
            let mut kept = VecDeque::with_capacity(idle.len());
            // How many healthy connections we may retire for being idle before
            // dropping below the warm floor.
            let mut budget = idle.len().saturating_sub(min_idle);

            while let Some(slot) = idle.pop_front() {
                // Unusable connections go regardless of min_idle; keeping a
                // dead connection warm serves nobody.
                if slot.conn.is_broken() || self.inner.is_expired(&slot.conn) {
                    retired.push(slot.conn);
                    continue;
                }

                let too_idle = !limits.idle_timeout.is_zero() && slot.idle_since.elapsed() >= limits.idle_timeout;
                if too_idle && budget > 0 {
                    budget -= 1;
                    retired.push(slot.conn);
                } else {
                    kept.push_back(slot);
                }
            }
            *idle = kept;
        }

        let count = retired.len();
        if count > 0 {
            self.inner.counters.idle.fetch_sub(count as u64, Ordering::Relaxed);
            self.inner.counters.discarded_total.fetch_add(count as u64, Ordering::Relaxed);
            for conn in retired {
                self.inner.retire(conn);
            }
        }
        count
    }

    fn spawn_reaper(&self) {
        let weak = Arc::downgrade(&self.inner);
        // A short fixed tick keeps the implementation simple; the work is O(idle)
        // and idle lists are tiny.
        let interval = Duration::from_secs(1);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let Some(inner) = weak.upgrade() else { return };
                if inner.status() == PoolStatus::Closed {
                    return;
                }
                let pool = Pool { inner };
                pool.reap();
            }
        });
    }
}

struct WaitingGuard<'a>(&'a AtomicU64);

impl Drop for WaitingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A backend connection borrowed from the pool.
///
/// Returned automatically on drop. Call [`Checkout::discard`] when the protocol
/// layer knows the connection is no longer clean — for example after a fatal
/// backend error or a session that ended mid-transaction.
pub struct Checkout<C: BackendConnector> {
    conn: Option<C::Conn>,
    inner: Arc<Inner<C>>,
    #[allow(dead_code)]
    permit: tokio::sync::OwnedSemaphorePermit,
    discard: bool,
}

impl<C: BackendConnector> Checkout<C> {
    /// Mark the connection as unfit for reuse; it is closed instead of pooled.
    pub fn discard(&mut self) {
        self.discard = true;
    }

    pub fn pool_name(&self) -> &str {
        &self.inner.name
    }
}

impl<C: BackendConnector> std::fmt::Debug for Checkout<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checkout")
            .field("pool", &self.inner.name)
            .field("backend_pid", &self.conn.as_ref().and_then(|c| c.backend_pid()))
            .field("discard", &self.discard)
            .finish()
    }
}

impl<C: BackendConnector> Deref for Checkout<C> {
    type Target = C::Conn;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("checkout is only empty after drop")
    }
}

impl<C: BackendConnector> DerefMut for Checkout<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().expect("checkout is only empty after drop")
    }
}

impl<C: BackendConnector> Drop for Checkout<C> {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else { return };
        self.inner.counters.active.fetch_sub(1, Ordering::Relaxed);

        let unfit = self.discard || conn.is_broken() || self.inner.is_expired(&conn);
        let draining = matches!(self.inner.status(), PoolStatus::Draining | PoolStatus::Closed);

        if unfit || draining {
            if unfit {
                self.inner.counters.discarded_total.fetch_add(1, Ordering::Relaxed);
            }
            self.inner.retire(conn);
            return;
        }

        self.inner.counters.idle.fetch_add(1, Ordering::Relaxed);
        self.inner.idle.lock().expect("idle queue poisoned").push_back(Slot { conn, idle_since: Instant::now() });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use havuz_proto::{ProtoResult, ResetOutcome};
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct TestConn {
        id: usize,
        opened_at: Instant,
        broken: Arc<std::sync::atomic::AtomicBool>,
        closed: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BackendConn for TestConn {
        fn is_broken(&self) -> bool {
            self.broken.load(Ordering::Relaxed)
        }

        fn opened_at(&self) -> Instant {
            self.opened_at
        }

        fn backend_pid(&self) -> Option<u32> {
            Some(self.id as u32)
        }

        async fn reset(&mut self) -> ProtoResult<ResetOutcome> {
            Ok(ResetOutcome::Cleaned)
        }

        async fn close(&mut self) {
            self.closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct TestConnector {
        next_id: AtomicUsize,
        opened: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
        fail: Arc<std::sync::atomic::AtomicBool>,
        broken: Arc<std::sync::atomic::AtomicBool>,
        delay: Duration,
    }

    impl TestConnector {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                next_id: AtomicUsize::new(1),
                opened: Arc::new(AtomicUsize::new(0)),
                closed: Arc::new(AtomicUsize::new(0)),
                fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                broken: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                delay: Duration::ZERO,
            })
        }
    }

    #[async_trait]
    impl BackendConnector for TestConnector {
        type Conn = TestConn;

        async fn connect(&self) -> ProtoResult<TestConn> {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.fail.load(Ordering::Relaxed) {
                return Err(ProtoError::backend("refused"));
            }
            self.opened.fetch_add(1, Ordering::Relaxed);
            Ok(TestConn {
                id: self.next_id.fetch_add(1, Ordering::Relaxed),
                opened_at: Instant::now(),
                broken: self.broken.clone(),
                closed: self.closed.clone(),
            })
        }

        fn target_label(&self) -> String {
            "test:5432".into()
        }
    }

    fn limits(max_size: u32) -> PoolLimits {
        PoolLimits {
            max_size,
            min_idle: 0,
            max_client_connections: 100,
            queue_timeout: Duration::from_millis(100),
            connect_timeout: Duration::from_millis(100),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
            idle_in_transaction_timeout: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn a_connection_is_reused_instead_of_reopened() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector.clone(), limits(3));

        for _ in 0..5 {
            let conn = pool.acquire().await.unwrap();
            assert_eq!(conn.backend_pid(), Some(1), "the same backend keeps coming back");
        }

        assert_eq!(connector.opened.load(Ordering::Relaxed), 1, "5 checkouts must not open 5 connections");
        let s = pool.snapshot();
        assert_eq!(s.checkout_total, 5);
        assert_eq!(s.created_total, 1);
        assert_eq!(s.open, 1);
        assert_eq!(s.idle, 1);
        assert_eq!(s.active, 0);
    }

    #[tokio::test]
    async fn max_size_is_never_exceeded() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector.clone(), limits(3));

        let a = pool.acquire().await.unwrap();
        let b = pool.acquire().await.unwrap();
        let c = pool.acquire().await.unwrap();

        assert_eq!(pool.snapshot().active, 3);
        assert_eq!(connector.opened.load(Ordering::Relaxed), 3);

        // The fourth client waits and then times out rather than opening a
        // fourth backend connection.
        let err = pool.acquire().await.unwrap_err();
        assert!(matches!(err, PoolError::Timeout { .. }), "got {err:?}");
        assert_eq!(connector.opened.load(Ordering::Relaxed), 3, "the database is protected");

        drop((a, b, c));
    }

    #[tokio::test]
    async fn this_is_the_whole_point_many_clients_few_backends() {
        // 100 sequential clients served by at most 3 backend connections.
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector.clone(), limits(3));

        for _ in 0..100 {
            let conn = pool.acquire().await.unwrap();
            drop(conn);
        }

        assert_eq!(pool.snapshot().checkout_total, 100);
        assert_eq!(connector.opened.load(Ordering::Relaxed), 1, "sequential clients need exactly one backend");
        assert!(pool.snapshot().open <= 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_clients_queue_instead_of_flooding_the_database() {
        let connector = TestConnector::new();
        let mut lim = limits(3);
        lim.queue_timeout = Duration::from_secs(5);
        let pool = Pool::new("app_main", connector.clone(), lim);

        let mut tasks = Vec::new();
        for _ in 0..50 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                let conn = pool.acquire().await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
                drop(conn);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        let opened = connector.opened.load(Ordering::Relaxed);
        assert!(opened <= 3, "50 concurrent clients opened {opened} backends, must be <= 3");
        assert_eq!(pool.snapshot().checkout_total, 50);
    }

    #[tokio::test]
    async fn a_waiting_client_is_served_as_soon_as_one_is_returned() {
        let connector = TestConnector::new();
        let mut lim = limits(1);
        lim.queue_timeout = Duration::from_secs(5);
        let pool = Pool::new("app_main", connector.clone(), lim);

        let held = pool.acquire().await.unwrap();

        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire().await.map(|c| c.backend_pid()) })
        };

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.snapshot().waiting, 1, "the second client is queued, not rejected");

        drop(held);
        assert_eq!(waiter.await.unwrap().unwrap(), Some(1), "the freed backend is handed straight over");
        assert_eq!(connector.opened.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancelling_a_checkout_removes_it_from_the_waiting_count() {
        let connector = TestConnector::new();
        let mut lim = limits(1);
        lim.queue_timeout = Duration::from_secs(5);
        let pool = Pool::new("app_main", connector, lim);
        let _held = pool.acquire().await.unwrap();

        assert!(tokio::time::timeout(Duration::from_millis(20), pool.acquire()).await.is_err());
        assert_eq!(pool.snapshot().waiting, 0);
        assert_eq!(pool.snapshot().timeout_total, 0, "caller cancellation is not a pool timeout");
    }

    #[tokio::test]
    async fn exhaustion_reports_the_pool_and_the_wait() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector, limits(1));
        let _held = pool.acquire().await.unwrap();

        let err = pool.acquire().await.unwrap_err();
        let PoolError::Timeout { pool: name, waited_ms } = &err else {
            panic!("expected a timeout, got {err:?}");
        };
        assert_eq!(name, "app_main");
        assert!(*waited_ms >= 90, "should have waited out queue_timeout, waited {waited_ms}ms");
        assert_eq!(pool.snapshot().timeout_total, 1);
    }

    #[tokio::test]
    async fn broken_connections_are_discarded_not_recycled() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector.clone(), limits(3));

        let conn = pool.acquire().await.unwrap();
        connector.broken.store(true, Ordering::Relaxed);
        drop(conn);

        assert_eq!(pool.snapshot().idle, 0, "a broken connection must not go back on the shelf");
        assert_eq!(pool.snapshot().discarded_total, 1);

        // Give the background closer a chance to run.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(connector.closed.load(Ordering::Relaxed), 1, "it is closed politely");
    }

    #[tokio::test]
    async fn explicit_discard_retires_the_connection() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector.clone(), limits(3));

        let mut conn = pool.acquire().await.unwrap();
        conn.discard();
        drop(conn);

        assert_eq!(pool.snapshot().idle, 0);
        assert_eq!(pool.snapshot().discarded_total, 1);

        let next = pool.acquire().await.unwrap();
        assert_eq!(next.backend_pid(), Some(2), "a fresh connection is opened");
    }

    #[tokio::test]
    async fn connections_past_max_lifetime_are_retired_on_checkout() {
        let connector = TestConnector::new();
        let mut lim = limits(3);
        lim.max_lifetime = Duration::from_millis(30);
        let pool = Pool::new("app_main", connector.clone(), lim);

        drop(pool.acquire().await.unwrap());
        assert_eq!(pool.snapshot().idle, 1);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let conn = pool.acquire().await.unwrap();
        assert_eq!(conn.backend_pid(), Some(2), "the aged connection is replaced");
        assert_eq!(connector.opened.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn reap_closes_idle_connections_past_their_timeout() {
        let connector = TestConnector::new();
        let mut lim = limits(3);
        lim.idle_timeout = Duration::from_millis(20);
        let pool = Pool::new("app_main", connector.clone(), lim);

        drop(pool.acquire().await.unwrap());
        assert_eq!(pool.snapshot().idle, 1);
        assert_eq!(pool.reap(), 0, "not idle long enough yet");

        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(pool.reap(), 1);
        assert_eq!(pool.snapshot().idle, 0);
    }

    #[tokio::test]
    async fn reap_keeps_min_idle_warm() {
        let connector = TestConnector::new();
        let mut lim = limits(3);
        lim.min_idle = 2;
        lim.idle_timeout = Duration::from_millis(10);
        let pool = Pool::new("app_main", connector.clone(), lim);

        assert_eq!(pool.warmup().await.unwrap(), 2);
        assert_eq!(pool.snapshot().idle, 2);

        tokio::time::sleep(Duration::from_millis(30)).await;
        pool.reap();
        assert_eq!(pool.snapshot().idle, 2, "min_idle connections stay warm even when idle");
    }

    #[tokio::test]
    async fn connect_failures_are_reported_and_do_not_leak_permits() {
        let connector = TestConnector::new();
        connector.fail.store(true, Ordering::Relaxed);
        let pool = Pool::new("app_main", connector.clone(), limits(1));

        let err = pool.acquire().await.unwrap_err();
        assert!(matches!(err, PoolError::Connect { .. }), "got {err:?}");
        assert_eq!(pool.snapshot().connect_error_total, 1);

        // The permit must have been released, otherwise the pool would be
        // permanently stuck after a backend outage.
        connector.fail.store(false, Ordering::Relaxed);
        let conn = pool.acquire().await.unwrap();
        assert_eq!(conn.backend_pid(), Some(1), "the pool recovers once the backend is back");
    }

    #[tokio::test]
    async fn pause_refuses_new_checkouts_but_keeps_existing_ones() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector, limits(3));
        let held = pool.acquire().await.unwrap();

        pool.pause();
        assert_eq!(pool.status(), PoolStatus::Paused);
        let err = pool.acquire().await.unwrap_err();
        assert!(matches!(err, PoolError::Unavailable { status: "paused", .. }));

        // The in-flight checkout is untouched.
        assert_eq!(held.backend_pid(), Some(1));
        drop(held);

        pool.resume();
        assert!(pool.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn drain_closes_idle_now_and_returned_connections_later() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector.clone(), limits(3));

        let held = pool.acquire().await.unwrap();
        drop(pool.acquire().await.unwrap()); // one idle
        assert_eq!(pool.snapshot().idle, 1);

        assert_eq!(pool.drain(), 1, "idle connections go immediately");
        assert_eq!(pool.snapshot().idle, 0);

        drop(held);
        assert_eq!(pool.snapshot().idle, 0, "a connection returned during drain is closed, not pooled");

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(connector.closed.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn a_closed_pool_refuses_everything() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector, limits(3));
        drop(pool.acquire().await.unwrap());

        pool.close();
        assert_eq!(pool.status(), PoolStatus::Closed);
        assert!(matches!(pool.acquire().await.unwrap_err(), PoolError::Unavailable { .. }));
        assert_eq!(pool.snapshot().idle, 0);
    }

    #[tokio::test]
    async fn connect_timeout_is_enforced() {
        let connector = Arc::new(TestConnector {
            next_id: AtomicUsize::new(1),
            opened: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicUsize::new(0)),
            fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            broken: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            delay: Duration::from_millis(500),
        });
        let mut lim = limits(3);
        lim.connect_timeout = Duration::from_millis(30);
        let pool = Pool::new("app_main", connector, lim);

        let started = Instant::now();
        let err = pool.acquire().await.unwrap_err();
        assert!(matches!(err, PoolError::Connect { .. }));
        assert!(started.elapsed() < Duration::from_millis(300), "must give up at connect_timeout");
    }

    #[tokio::test]
    async fn snapshot_tracks_the_live_fan_in() {
        let connector = TestConnector::new();
        let pool = Pool::new("app_main", connector, limits(3));

        let _a = pool.acquire().await.unwrap();
        let _b = pool.acquire().await.unwrap();
        let s = pool.snapshot();
        assert_eq!(s.active, 2);
        assert_eq!(s.open, 2);
        assert_eq!(s.fan_in(), Some(1.0), "without queued clients the ratio is 1:1");
        assert_eq!(s.name, "app_main");
        assert_eq!(s.status, "active");
    }
}
