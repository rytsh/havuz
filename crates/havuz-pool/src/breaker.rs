//! Circuit breaker.
//!
//! When a replica goes down, the naive behaviour is to keep sending it traffic
//! and keep failing. Each attempt costs a TCP connect and a timeout, so a dead
//! replica does not just stop helping — it actively makes the pool slower than
//! having no replica at all.
//!
//! A breaker sits in front of each target and stops the bleeding:
//!
//! ```text
//! closed ──(N consecutive failures)──> open
//!   ^                                    │
//!   │                             (cooldown elapses)
//!   │                                    v
//!   └──(M consecutive successes)── half-open ──(any failure)──> open
//! ```
//!
//! The half-open state is what makes recovery automatic without stampeding: one
//! probe at a time is admitted, and the target has to prove itself before full
//! traffic returns.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    /// Healthy; traffic flows.
    Closed,
    /// Failing; traffic is refused without an attempt.
    Open,
    /// Cooldown elapsed; a limited number of probes are allowed through.
    HalfOpen,
}

impl BreakerState {
    pub fn as_str(self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Consecutive failures that trip the breaker.
    pub failure_threshold: u32,
    /// Consecutive successes in half-open that close it again.
    pub success_threshold: u32,
    /// How long to stay open before admitting a probe.
    pub cooldown: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            // One failure is too twitchy: a single dropped packet would remove
            // a healthy replica from rotation.
            failure_threshold: 3,
            success_threshold: 2,
            cooldown: Duration::from_secs(10),
        }
    }
}

/// Tracks the health of one target.
///
/// All operations are lock-free; this is consulted on every routing decision.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    /// 0 = closed, 1 = open, 2 = half-open.
    state: AtomicU32,
    consecutive_failures: AtomicU32,
    consecutive_successes: AtomicU32,
    /// Microseconds since `epoch` when the breaker opened.
    opened_at_micros: AtomicU64,
    /// Set while a half-open probe is in flight, so only one gets through.
    probe_in_flight: AtomicBool,
    epoch: Instant,

    failures_total: AtomicU64,
    trips_total: AtomicU64,
    rejected_total: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            state: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            opened_at_micros: AtomicU64::new(0),
            probe_in_flight: AtomicBool::new(false),
            epoch: Instant::now(),
            failures_total: AtomicU64::new(0),
            trips_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> BreakerState {
        match self.state.load(Ordering::Acquire) {
            0 => BreakerState::Closed,
            1 => BreakerState::Open,
            _ => BreakerState::HalfOpen,
        }
    }

    /// May traffic be sent to this target right now?
    ///
    /// Has a side effect in the open state: once the cooldown has elapsed the
    /// breaker moves to half-open and admits a single probe.
    pub fn allows(&self) -> bool {
        match self.state() {
            BreakerState::Closed => true,
            BreakerState::HalfOpen => {
                // Exactly one probe at a time, or recovery turns into a
                // thundering herd against a target that is still fragile.
                self.probe_in_flight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
            }
            BreakerState::Open => {
                if self.cooldown_elapsed() {
                    // Move to half-open and take the probe slot in one step.
                    if self.state.compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                        self.consecutive_successes.store(0, Ordering::Relaxed);
                        self.probe_in_flight.store(true, Ordering::Release);
                        return true;
                    }
                }
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.probe_in_flight.store(false, Ordering::Release);

        if self.state() == BreakerState::HalfOpen {
            let successes = self.consecutive_successes.fetch_add(1, Ordering::AcqRel) + 1;
            if successes >= self.config.success_threshold {
                self.state.store(0, Ordering::Release);
                self.consecutive_successes.store(0, Ordering::Relaxed);
            }
        }
    }

    pub fn record_failure(&self) {
        self.failures_total.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.probe_in_flight.store(false, Ordering::Release);

        // A failure during recovery means the target is not ready; go straight
        // back to open rather than burning the remaining probes.
        if self.state() == BreakerState::HalfOpen {
            self.trip();
            return;
        }

        let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if failures >= self.config.failure_threshold {
            self.trip();
        }
    }

    fn trip(&self) {
        let was_closed = self.state.swap(1, Ordering::AcqRel) != 1;
        self.opened_at_micros.store(self.epoch.elapsed().as_micros() as u64, Ordering::Release);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if was_closed {
            self.trips_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Force the breaker closed, e.g. after an operator fixes the target.
    pub fn reset(&self) {
        self.state.store(0, Ordering::Release);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.probe_in_flight.store(false, Ordering::Release);
    }

    fn cooldown_elapsed(&self) -> bool {
        let opened = Duration::from_micros(self.opened_at_micros.load(Ordering::Acquire));
        self.epoch.elapsed().saturating_sub(opened) >= self.config.cooldown
    }

    pub fn snapshot(&self) -> BreakerSnapshot {
        BreakerSnapshot {
            state: self.state(),
            failures_total: self.failures_total.load(Ordering::Relaxed),
            trips_total: self.trips_total.load(Ordering::Relaxed),
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(BreakerConfig::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BreakerSnapshot {
    pub state: BreakerState,
    pub failures_total: u64,
    pub trips_total: u64,
    /// Requests refused without an attempt. This is the number that shows the
    /// breaker earning its keep.
    pub rejected_total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(BreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            cooldown: Duration::from_millis(50),
        })
    }

    #[test]
    fn a_healthy_target_is_always_allowed() {
        let b = breaker();
        assert_eq!(b.state(), BreakerState::Closed);
        for _ in 0..100 {
            assert!(b.allows());
            b.record_success();
        }
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn isolated_failures_do_not_remove_a_replica_from_rotation() {
        // A single dropped packet must not cost us a replica.
        let b = breaker();
        for _ in 0..10 {
            b.record_failure();
            b.record_success();
        }
        assert_eq!(b.state(), BreakerState::Closed, "failures must be consecutive to count");
    }

    #[test]
    fn consecutive_failures_trip_the_breaker() {
        let b = breaker();
        b.record_failure();
        b.record_failure();
        assert_eq!(b.state(), BreakerState::Closed, "not yet at the threshold");

        b.record_failure();
        assert_eq!(b.state(), BreakerState::Open);
        assert_eq!(b.snapshot().trips_total, 1);
    }

    #[test]
    fn an_open_breaker_refuses_without_trying() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure();
        }
        for _ in 0..5 {
            assert!(!b.allows(), "a dead target must not cost a connect attempt");
        }
        assert_eq!(b.snapshot().rejected_total, 5);
    }

    #[test]
    fn after_the_cooldown_exactly_one_probe_is_admitted() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure();
        }
        assert!(!b.allows());

        std::thread::sleep(Duration::from_millis(60));

        assert!(b.allows(), "the first caller after the cooldown probes");
        assert_eq!(b.state(), BreakerState::HalfOpen);
        assert!(!b.allows(), "concurrent callers must not stampede a fragile target");
    }

    #[test]
    fn recovery_needs_repeated_success() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure();
        }
        std::thread::sleep(Duration::from_millis(60));

        assert!(b.allows());
        b.record_success();
        assert_eq!(b.state(), BreakerState::HalfOpen, "one success is not proof");

        assert!(b.allows());
        b.record_success();
        assert_eq!(b.state(), BreakerState::Closed, "two consecutive successes close it");
        assert!(b.allows());
    }

    #[test]
    fn a_failure_during_recovery_reopens_immediately() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure();
        }
        std::thread::sleep(Duration::from_millis(60));

        assert!(b.allows());
        b.record_success();
        assert_eq!(b.state(), BreakerState::HalfOpen);

        assert!(b.allows());
        b.record_failure();
        assert_eq!(b.state(), BreakerState::Open, "a half-recovered target goes straight back out");
        assert!(!b.allows(), "and the cooldown starts again");
    }

    #[test]
    fn tripping_twice_without_recovering_counts_once() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure();
        }
        assert_eq!(b.snapshot().trips_total, 1);
        for _ in 0..3 {
            b.record_failure();
        }
        assert_eq!(b.snapshot().trips_total, 1, "still the same outage");
    }

    #[test]
    fn reset_restores_a_target_immediately() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure();
        }
        assert!(!b.allows());

        b.reset();
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allows(), "an operator who fixed the target should not have to wait");
    }

    #[test]
    fn the_snapshot_counts_what_an_operator_needs() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure();
        }
        b.allows();
        b.allows();

        let s = b.snapshot();
        assert_eq!(s.state, BreakerState::Open);
        assert_eq!(s.failures_total, 3);
        assert_eq!(s.trips_total, 1);
        assert_eq!(s.rejected_total, 2);
    }

    #[test]
    fn concurrent_probing_admits_exactly_one() {
        use std::sync::Arc;
        let b = Arc::new(breaker());
        for _ in 0..3 {
            b.record_failure();
        }
        std::thread::sleep(Duration::from_millis(60));

        let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let (b, admitted) = (b.clone(), admitted.clone());
            handles.push(std::thread::spawn(move || {
                if b.allows() {
                    admitted.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(admitted.load(Ordering::Relaxed), 1, "16 threads raced for the probe slot; only one may take it");
    }

    #[test]
    fn serialises_for_the_dashboard() {
        let b = breaker();
        let json = serde_json::to_value(b.snapshot()).unwrap();
        assert_eq!(json["state"], "closed");
    }
}
