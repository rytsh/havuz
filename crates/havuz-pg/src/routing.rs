//! Choosing a target.
//!
//! Read/write split is the feature most likely to break an application
//! silently. A misrouted write fails loudly and gets fixed in minutes. A
//! misrouted *read* returns data from a replica that has not caught up, and the
//! application sees a row it just inserted simply not being there. No error, no
//! log line, and a bug report that says "sometimes it doesn't save".
//!
//! Three rules keep that from happening:
//!
//! 1. **Anything not provably read-only goes to the primary** (see
//!    [`crate::classify::route_intent`]).
//! 2. **After a session writes, its reads stay on the primary** for a
//!    configured window. This is what makes insert-then-select keep working.
//! 3. **A transaction never changes target midway.** The first statement
//!    decides, and a plain `BEGIN` decides "primary", because the client has
//!    not told us what is coming.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use havuz_control::PrimaryReason;

use havuz_control::{PrimaryReasonCount, ReplicaRouting, RoutingReport};
use havuz_core::RoutingConfig;
use havuz_pool::{BreakerConfig, CircuitBreaker};

use crate::classify::RouteIntent;

/// Lag value meaning "we have not measured this yet".
pub const LAG_UNKNOWN: u64 = u64::MAX;

/// Where a statement was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Primary(PrimaryReason),
    /// Index into the replica list.
    Replica(usize),
}

/// Health and position of one replica.
#[derive(Debug)]
pub struct ReplicaState {
    pub label: String,
    pub weight: u32,
    pub breaker: CircuitBreaker,
    /// Replication delay in milliseconds, or [`LAG_UNKNOWN`].
    lag_millis: AtomicU64,
}

impl ReplicaState {
    pub fn new(label: impl Into<String>, weight: u32, breaker: BreakerConfig) -> Self {
        Self {
            label: label.into(),
            weight: weight.max(1),
            breaker: CircuitBreaker::new(breaker),
            lag_millis: AtomicU64::new(LAG_UNKNOWN),
        }
    }

    pub fn set_lag(&self, lag: Option<Duration>) {
        self.lag_millis.store(lag.map(|d| d.as_millis() as u64).unwrap_or(LAG_UNKNOWN), Ordering::Relaxed);
    }

    pub fn lag(&self) -> Option<Duration> {
        match self.lag_millis.load(Ordering::Relaxed) {
            LAG_UNKNOWN => None,
            millis => Some(Duration::from_millis(millis)),
        }
    }

    /// Is this replica fit to serve a read?
    fn is_eligible(&self, max_lag: Option<Duration>) -> bool {
        if let Some(limit) = max_lag {
            match self.lag() {
                Some(lag) if lag > limit => return false,
                // An unmeasured replica is not a healthy replica. Serving reads
                // from one whose lag we have never seen is exactly the silent
                // staleness this whole module exists to avoid.
                None => return false,
                Some(_) => {}
            }
        }
        self.breaker.allows()
    }

    pub fn snapshot(&self) -> ReplicaRouting {
        ReplicaRouting {
            label: self.label.clone(),
            weight: self.weight,
            lag_millis: self.lag(),
            breaker: self.breaker.snapshot(),
        }
    }
}

/// Per-client-session routing state.
///
/// Small and cheap: one of these lives per connected client.
#[derive(Debug, Default)]
pub struct SessionRouting {
    last_write: Option<Instant>,
    /// Target chosen for the transaction currently in progress.
    transaction_route: Option<Route>,
}

impl SessionRouting {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that this session wrote, starting the sticky window.
    pub fn note_write(&mut self) {
        self.last_write = Some(Instant::now());
    }

    /// Would a read from this session still be served by the primary?
    pub fn is_sticky(&self, window: Duration) -> bool {
        if window.is_zero() {
            return false;
        }
        self.last_write.is_some_and(|at| at.elapsed() < window)
    }

    /// Pin the session to a target for the duration of a transaction.
    pub fn begin_transaction(&mut self, route: Route) {
        self.transaction_route = Some(route);
    }

    pub fn end_transaction(&mut self) {
        self.transaction_route = None;
    }

    pub fn transaction_route(&self) -> Option<Route> {
        self.transaction_route
    }
}

/// Counts of routing decisions, for the dashboard and `/metrics`.
#[derive(Debug, Default)]
pub struct RoutingStats {
    to_primary: AtomicU64,
    to_replica: AtomicU64,
    primary_reasons: [AtomicU64; 5],
}

impl RoutingStats {
    fn record(&self, route: Route) {
        match route {
            Route::Primary(reason) => {
                self.to_primary.fetch_add(1, Ordering::Relaxed);
                self.primary_reasons[reason.index()].fetch_add(1, Ordering::Relaxed);
            }
            Route::Replica(_) => {
                self.to_replica.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn snapshot(&self) -> RoutingReport {
        let to_primary = self.to_primary.load(Ordering::Relaxed);
        let to_replica = self.to_replica.load(Ordering::Relaxed);
        let total = to_primary + to_replica;

        RoutingReport {
            to_primary,
            to_replica,
            replica_share: (total > 0).then(|| to_replica as f32 / total as f32),
            primary_reasons: PrimaryReason::ALL
                .iter()
                .map(|reason| PrimaryReasonCount {
                    reason: *reason,
                    count: self.primary_reasons[reason.index()].load(Ordering::Relaxed),
                })
                .collect(),
        }
    }
}

/// Picks targets.
#[derive(Debug)]
pub struct Router {
    config: RoutingConfig,
    replicas: Vec<Arc<ReplicaState>>,
    /// Cursor for weighted round-robin.
    cursor: AtomicU64,
    stats: RoutingStats,
}

impl Router {
    pub fn new(config: RoutingConfig, replicas: Vec<Arc<ReplicaState>>) -> Self {
        Self { config, replicas, cursor: AtomicU64::new(0), stats: RoutingStats::default() }
    }

    pub fn replicas(&self) -> &[Arc<ReplicaState>] {
        &self.replicas
    }

    pub fn stats(&self) -> &RoutingStats {
        &self.stats
    }

    pub fn config(&self) -> &RoutingConfig {
        &self.config
    }

    /// Choose a target for the next statement.
    pub fn choose(&self, intent: RouteIntent, session: &mut SessionRouting) -> Route {
        let route = self.decide(intent, session);
        self.stats.record(route);
        route
    }

    fn decide(&self, intent: RouteIntent, session: &mut SessionRouting) -> Route {
        // A transaction never changes target midway. Splitting one across a
        // primary and a replica would give it two different snapshots.
        if let Some(existing) = session.transaction_route() {
            if intent == RouteIntent::Write {
                session.note_write();
            }
            return match existing {
                Route::Primary(_) => Route::Primary(PrimaryReason::TransactionPinned),
                replica => replica,
            };
        }

        if !self.config.read_write_split || self.replicas.is_empty() {
            if intent == RouteIntent::Write {
                session.note_write();
            }
            return Route::Primary(PrimaryReason::SplitDisabled);
        }

        if intent == RouteIntent::Write {
            session.note_write();
            return Route::Primary(PrimaryReason::Write);
        }

        // The rule that makes this safe for ordinary applications: a read that
        // follows this session's own write goes where the write went.
        if session.is_sticky(self.config.sticky_after_write) {
            return Route::Primary(PrimaryReason::ReadAfterWrite);
        }

        match self.pick_replica() {
            Some(index) => Route::Replica(index),
            None => Route::Primary(PrimaryReason::NoReplicaAvailable),
        }
    }

    /// Weighted round-robin over eligible replicas.
    fn pick_replica(&self) -> Option<usize> {
        let eligible: Vec<(usize, u32)> = self
            .replicas
            .iter()
            .enumerate()
            .filter(|(_, r)| r.is_eligible(self.config.max_replica_lag))
            .map(|(i, r)| (i, r.weight))
            .collect();

        if eligible.is_empty() {
            return None;
        }

        let total: u64 = eligible.iter().map(|(_, w)| *w as u64).sum();
        let position = self.cursor.fetch_add(1, Ordering::Relaxed) % total;

        let mut accumulated = 0u64;
        for (index, weight) in eligible {
            accumulated += weight as u64;
            if position < accumulated {
                return Some(index);
            }
        }
        None
    }

    /// Record the outcome of using a replica, so the breaker can react.
    pub fn record_result(&self, route: Route, success: bool) {
        if let Route::Replica(index) = route {
            if let Some(replica) = self.replicas.get(index) {
                if success {
                    replica.breaker.record_success();
                } else {
                    replica.breaker.record_failure();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(split: bool) -> RoutingConfig {
        RoutingConfig {
            read_write_split: split,
            sticky_after_write: Duration::from_millis(100),
            max_replica_lag: Some(Duration::from_secs(5)),
            ..RoutingConfig::default()
        }
    }

    /// Replicas start with unknown lag, which makes them ineligible. A health
    /// probe would normally set this.
    fn healthy_replica(label: &str, weight: u32) -> ReplicaState {
        let state = ReplicaState::new(label, weight, BreakerConfig::default());
        state.set_lag(Some(Duration::ZERO));
        state
    }

    fn router(split: bool, replicas: Vec<ReplicaState>) -> Router {
        Router::new(config(split), replicas.into_iter().map(Arc::new).collect())
    }

    #[test]
    fn with_split_disabled_everything_goes_to_the_primary() {
        let r = router(false, vec![healthy_replica("r1", 1)]);
        let mut session = SessionRouting::new();

        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Primary(PrimaryReason::SplitDisabled));
        assert_eq!(r.choose(RouteIntent::Write, &mut session), Route::Primary(PrimaryReason::SplitDisabled));
    }

    #[test]
    fn a_pool_without_replicas_never_claims_to_split() {
        let r = router(true, vec![]);
        let mut session = SessionRouting::new();
        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Primary(PrimaryReason::SplitDisabled));
    }

    #[test]
    fn reads_reach_a_replica_and_writes_do_not() {
        let r = router(true, vec![healthy_replica("r1", 1)]);
        let mut session = SessionRouting::new();

        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Replica(0));
        assert_eq!(r.choose(RouteIntent::Write, &mut session), Route::Primary(PrimaryReason::Write));
    }

    #[test]
    fn a_read_after_a_write_stays_on_the_primary() {
        // The scenario that breaks applications: insert a row, then read it
        // back. Serving that read from a lagging replica returns nothing, with
        // no error anywhere.
        let r = router(true, vec![healthy_replica("r1", 1)]);
        let mut session = SessionRouting::new();

        assert_eq!(r.choose(RouteIntent::Write, &mut session), Route::Primary(PrimaryReason::Write));
        assert_eq!(
            r.choose(RouteIntent::Read, &mut session),
            Route::Primary(PrimaryReason::ReadAfterWrite),
            "the read must follow the write"
        );
    }

    #[test]
    fn the_sticky_window_expires() {
        let r = router(true, vec![healthy_replica("r1", 1)]);
        let mut session = SessionRouting::new();

        r.choose(RouteIntent::Write, &mut session);
        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Primary(PrimaryReason::ReadAfterWrite));

        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Replica(0), "traffic returns to replicas");
    }

    #[test]
    fn a_zero_sticky_window_disables_the_protection() {
        let mut cfg = config(true);
        cfg.sticky_after_write = Duration::ZERO;
        let r = Router::new(cfg, vec![Arc::new(healthy_replica("r1", 1))]);
        let mut session = SessionRouting::new();

        r.choose(RouteIntent::Write, &mut session);
        assert_eq!(
            r.choose(RouteIntent::Read, &mut session),
            Route::Replica(0),
            "the operator opted out, so we honour it — the config warns about this"
        );
    }

    #[test]
    fn a_transaction_never_switches_target_midway() {
        let r = router(true, vec![healthy_replica("r1", 1)]);
        let mut session = SessionRouting::new();

        // A plain BEGIN is classified as a write, so the transaction lands on
        // the primary and stays there.
        let first = r.choose(RouteIntent::Write, &mut session);
        session.begin_transaction(first);

        assert_eq!(
            r.choose(RouteIntent::Read, &mut session),
            Route::Primary(PrimaryReason::TransactionPinned),
            "a read inside a write transaction must see that transaction's snapshot"
        );

        session.end_transaction();
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Replica(0));
    }

    #[test]
    fn a_read_only_transaction_stays_on_its_replica() {
        let r = router(true, vec![healthy_replica("r1", 1), healthy_replica("r2", 1)]);
        let mut session = SessionRouting::new();

        let first = r.choose(RouteIntent::Read, &mut session);
        session.begin_transaction(first);

        for _ in 0..5 {
            assert_eq!(r.choose(RouteIntent::Read, &mut session), first, "round-robin must not move it");
        }
    }

    #[test]
    fn a_replica_with_unmeasured_lag_is_not_used() {
        // Never measured is not the same as caught up. Using it would be the
        // silent staleness this module exists to prevent.
        let unmeasured = ReplicaState::new("r1", 1, BreakerConfig::default());
        let r = router(true, vec![unmeasured]);
        let mut session = SessionRouting::new();

        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Primary(PrimaryReason::NoReplicaAvailable));
    }

    #[test]
    fn a_lagging_replica_is_skipped() {
        let fresh = healthy_replica("fresh", 1);
        let stale = healthy_replica("stale", 1);
        stale.set_lag(Some(Duration::from_secs(60)));

        let r = router(true, vec![stale, fresh]);
        let mut session = SessionRouting::new();

        for _ in 0..10 {
            assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Replica(1), "only the fresh one");
        }
    }

    #[test]
    fn disabling_the_lag_check_admits_unmeasured_replicas() {
        let mut cfg = config(true);
        cfg.max_replica_lag = None;
        let r = Router::new(cfg, vec![Arc::new(ReplicaState::new("r1", 1, BreakerConfig::default()))]);
        let mut session = SessionRouting::new();

        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Replica(0));
    }

    #[test]
    fn a_failing_replica_is_taken_out_and_traffic_falls_back() {
        let r = router(true, vec![healthy_replica("r1", 1)]);
        let mut session = SessionRouting::new();

        assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Replica(0));

        for _ in 0..3 {
            r.record_result(Route::Replica(0), false);
        }

        assert_eq!(
            r.choose(RouteIntent::Read, &mut session),
            Route::Primary(PrimaryReason::NoReplicaAvailable),
            "with its only replica down the pool must keep serving from the primary"
        );
    }

    #[test]
    fn one_failing_replica_does_not_take_the_others_with_it() {
        let r = router(true, vec![healthy_replica("bad", 1), healthy_replica("good", 1)]);
        let mut session = SessionRouting::new();

        for _ in 0..3 {
            r.record_result(Route::Replica(0), false);
        }

        for _ in 0..10 {
            assert_eq!(r.choose(RouteIntent::Read, &mut session), Route::Replica(1));
        }
    }

    #[test]
    fn round_robin_respects_weights() {
        let r = router(true, vec![healthy_replica("small", 1), healthy_replica("big", 3)]);
        let mut session = SessionRouting::new();

        let mut counts = [0usize; 2];
        for _ in 0..400 {
            match r.choose(RouteIntent::Read, &mut session) {
                Route::Replica(i) => counts[i] += 1,
                other => panic!("expected a replica, got {other:?}"),
            }
        }

        assert_eq!(counts[0], 100, "weight 1 of 4");
        assert_eq!(counts[1], 300, "weight 3 of 4");
    }

    #[test]
    fn routing_stats_show_whether_the_split_is_doing_anything() {
        let r = router(true, vec![healthy_replica("r1", 1)]);
        let mut session = SessionRouting::new();

        r.choose(RouteIntent::Read, &mut session);
        r.choose(RouteIntent::Read, &mut session);
        r.choose(RouteIntent::Write, &mut session);
        r.choose(RouteIntent::Read, &mut session); // sticky

        let s = r.stats().snapshot();
        assert_eq!(s.to_replica, 2);
        assert_eq!(s.to_primary, 2);
        assert!((s.replica_share.unwrap() - 0.5).abs() < 1e-6);

        let reasons: std::collections::HashMap<_, _> = s.primary_reasons.iter().map(|r| (r.reason, r.count)).collect();
        assert_eq!(reasons[&PrimaryReason::Write], 1);
        assert_eq!(reasons[&PrimaryReason::ReadAfterWrite], 1, "and why the replica was skipped");
    }

    #[test]
    fn stats_start_empty_rather_than_claiming_a_share() {
        let r = router(true, vec![healthy_replica("r1", 1)]);
        assert_eq!(r.stats().snapshot().replica_share, None);
    }

    #[test]
    fn snapshots_serialise_for_the_dashboard() {
        let replica = healthy_replica("r1", 2);
        replica.set_lag(Some(Duration::from_millis(250)));

        let json = serde_json::to_value(replica.snapshot()).unwrap();
        assert_eq!(json["label"], "r1");
        assert_eq!(json["weight"], 2);
        assert_eq!(json["lag_millis"], 250);
        assert_eq!(json["breaker"]["state"], "closed");

        let unmeasured = ReplicaState::new("r2", 1, BreakerConfig::default());
        let json = serde_json::to_value(unmeasured.snapshot()).unwrap();
        assert!(json["lag_millis"].is_null(), "unknown lag must not read as zero");
    }
}
