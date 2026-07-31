//! Pin analytics.
//!
//! Transaction-mode pooling degrades silently. A pool configured for 100
//! clients over 3 backends will happily run as 100-over-100 if the application
//! issues `SET application_name` on connect, and every dashboard in existence
//! will show a healthy pool the entire time.
//!
//! This registry answers the question nobody else answers: **which user, from
//! which application, using which construct, is costing you the multiplexing
//! you configured?** That is a sentence an operator can act on.
//!
//! Written from the session teardown path, read by the admin API. Cardinality
//! is capped because `application_name` is attacker-controlled in the sense
//! that any client can set it to anything.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;

use serde::Serialize;

use crate::flow::PinReason;

/// Distinct (user, application, reason) combinations tracked before we stop
/// adding new ones. Well past what a real deployment produces, far below what
/// would threaten memory.
const MAX_ENTRIES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PinKey {
    user: String,
    application: String,
    reason: PinReason,
}

#[derive(Debug)]
struct PinEntry {
    count: u64,
    first_seen: Instant,
    last_seen: Instant,
}

/// Records why sessions stopped being shareable.
#[derive(Debug)]
pub struct PinRegistry {
    entries: RwLock<BTreeMap<PinKey, PinEntry>>,
    /// Per-reason totals, kept separately so `/metrics` never has to walk the
    /// map or care whether it was capped.
    totals: [AtomicU64; PinReason::ALL.len()],
    /// Sessions that finished without being pinned. The denominator for the
    /// only ratio that matters here.
    unpinned: AtomicU64,
    dropped: AtomicU64,
}

impl Default for PinRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PinRegistry {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            totals: std::array::from_fn(|_| AtomicU64::new(0)),
            unpinned: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Record a pinned session.
    pub fn record(&self, user: &str, application: Option<&str>, reason: PinReason) {
        self.totals[reason_index(reason)].fetch_add(1, Ordering::Relaxed);

        let key = PinKey { user: user.to_string(), application: application.unwrap_or("-").to_string(), reason };

        let mut entries = self.entries.write().expect("pin registry poisoned");
        let now = Instant::now();

        match entries.get_mut(&key) {
            Some(entry) => {
                entry.count += 1;
                entry.last_seen = now;
            }
            None => {
                // Refuse to grow without bound. The per-reason totals stay
                // accurate, so the breakdown remains trustworthy even when the
                // detail is capped.
                if entries.len() >= MAX_ENTRIES {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                entries.insert(key, PinEntry { count: 1, first_seen: now, last_seen: now });
            }
        }
    }

    /// Record a session that stayed shareable.
    pub fn record_clean(&self) {
        self.unpinned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_for(&self, reason: PinReason) -> u64 {
        self.totals[reason_index(reason)].load(Ordering::Relaxed)
    }

    pub fn pinned_total(&self) -> u64 {
        self.totals.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    pub fn unpinned_total(&self) -> u64 {
        self.unpinned.load(Ordering::Relaxed)
    }

    /// Share of sessions that lost their ability to multiplex.
    ///
    /// This is the number to put in front of an operator. Above a few percent
    /// in transaction mode means the configured fan-in is fiction.
    pub fn pin_rate(&self) -> Option<f32> {
        let pinned = self.pinned_total();
        let total = pinned + self.unpinned_total();
        (total > 0).then(|| pinned as f32 / total as f32)
    }

    /// Full report, ordered by impact.
    pub fn report(&self) -> PinReport {
        let entries = self.entries.read().expect("pin registry poisoned");
        let now = Instant::now();

        let mut offenders: Vec<PinOffender> = entries
            .iter()
            .map(|(key, entry)| PinOffender {
                user: key.user.clone(),
                application: key.application.clone(),
                reason: key.reason,
                actionable: key.reason.is_actionable(),
                count: entry.count,
                first_seen_secs_ago: now.duration_since(entry.first_seen).as_secs(),
                last_seen_secs_ago: now.duration_since(entry.last_seen).as_secs(),
            })
            .collect();

        // Loudest first: an operator should not have to sort this by hand.
        offenders.sort_by(|a, b| b.count.cmp(&a.count).then(a.user.cmp(&b.user)));

        // Every reason appears, including the ones at zero, so the breakdown is
        // a complete picture rather than a list of what happened to fire.
        let by_reason = PinReason::ALL
            .iter()
            .map(|reason| ReasonCount { reason: *reason, count: self.total_for(*reason) })
            .collect();

        PinReport {
            pinned_sessions: self.pinned_total(),
            clean_sessions: self.unpinned_total(),
            pin_rate: self.pin_rate(),
            by_reason,
            offenders,
            truncated: self.dropped.load(Ordering::Relaxed) > 0,
        }
    }

    pub fn reset(&self) {
        self.entries.write().expect("pin registry poisoned").clear();
        for counter in &self.totals {
            counter.store(0, Ordering::Relaxed);
        }
        self.unpinned.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
    }
}

fn reason_index(reason: PinReason) -> usize {
    PinReason::ALL.iter().position(|r| *r == reason).expect("PinReason::ALL is exhaustive")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonCount {
    pub reason: PinReason,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PinOffender {
    pub user: String,
    pub application: String,
    pub reason: PinReason,
    /// Whether changing the application can plausibly fix this.
    pub actionable: bool,
    pub count: u64,
    pub first_seen_secs_ago: u64,
    pub last_seen_secs_ago: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PinReport {
    pub pinned_sessions: u64,
    pub clean_sessions: u64,
    pub pin_rate: Option<f32>,
    pub by_reason: Vec<ReasonCount>,
    pub offenders: Vec<PinOffender>,
    /// Detail was capped; `by_reason` is still exact.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_registry_claims_nothing() {
        let registry = PinRegistry::new();
        let report = registry.report();

        assert_eq!(report.pinned_sessions, 0);
        assert_eq!(report.pin_rate, None, "a rate over zero sessions would be meaningless");
        assert!(report.offenders.is_empty());
        assert_eq!(report.by_reason.len(), PinReason::ALL.len(), "every reason is listed, even at zero");
    }

    #[test]
    fn the_report_names_the_offender() {
        let registry = PinRegistry::new();
        for _ in 0..5 {
            registry.record("svc_orders", Some("orders-api"), PinReason::SessionParameter);
        }
        registry.record("svc_reports", Some("reporting"), PinReason::TempTable);

        let report = registry.report();
        assert_eq!(report.offenders.len(), 2);

        let top = &report.offenders[0];
        assert_eq!(top.user, "svc_orders");
        assert_eq!(top.application, "orders-api");
        assert_eq!(top.reason, PinReason::SessionParameter);
        assert_eq!(top.count, 5);
        assert!(top.actionable, "a SET can be removed from the application");
    }

    #[test]
    fn offenders_are_sorted_by_impact() {
        let registry = PinRegistry::new();
        registry.record("quiet", None, PinReason::Listen);
        for _ in 0..10 {
            registry.record("loud", None, PinReason::SessionParameter);
        }

        let report = registry.report();
        assert_eq!(report.offenders[0].user, "loud", "the biggest problem goes first");
        assert_eq!(report.offenders[0].count, 10);
    }

    #[test]
    fn the_pin_rate_is_the_number_that_matters() {
        let registry = PinRegistry::new();
        for _ in 0..9 {
            registry.record_clean();
        }
        registry.record("svc", None, PinReason::SessionParameter);

        let rate = registry.pin_rate().unwrap();
        assert!((rate - 0.1).abs() < 1e-6, "1 pinned out of 10 sessions is 10%, got {rate}");
    }

    #[test]
    fn a_missing_application_name_is_recorded_not_dropped() {
        let registry = PinRegistry::new();
        registry.record("svc", None, PinReason::Listen);

        let report = registry.report();
        assert_eq!(report.offenders[0].application, "-");
    }

    #[test]
    fn the_same_offender_from_two_applications_is_two_rows() {
        // Same user, different deployments: the operator needs to know which
        // service to fix.
        let registry = PinRegistry::new();
        registry.record("svc", Some("api-v1"), PinReason::SessionParameter);
        registry.record("svc", Some("api-v2"), PinReason::SessionParameter);

        assert_eq!(registry.report().offenders.len(), 2);
        assert_eq!(registry.total_for(PinReason::SessionParameter), 2);
    }

    #[test]
    fn unactionable_reasons_are_flagged_so_they_can_be_filtered_out() {
        let registry = PinRegistry::new();
        registry.record("replicator", Some("wal-reader"), PinReason::Replication);

        let report = registry.report();
        assert!(!report.offenders[0].actionable, "nobody can make replication stop pinning");
    }

    #[test]
    fn cardinality_is_capped_but_totals_stay_exact() {
        let registry = PinRegistry::new();
        // A client can put anything in application_name, so this is a real
        // memory exhaustion vector rather than a theoretical one.
        for i in 0..MAX_ENTRIES + 500 {
            registry.record("svc", Some(&format!("app-{i}")), PinReason::SessionParameter);
        }

        let report = registry.report();
        assert_eq!(report.offenders.len(), MAX_ENTRIES, "detail is bounded");
        assert!(report.truncated, "and the report says so");
        assert_eq!(
            report.pinned_sessions,
            (MAX_ENTRIES + 500) as u64,
            "the totals must remain exact even when detail is dropped"
        );
    }

    #[test]
    fn counts_accumulate_across_reasons() {
        let registry = PinRegistry::new();
        registry.record("a", None, PinReason::SessionParameter);
        registry.record("b", None, PinReason::TempTable);
        registry.record("c", None, PinReason::TempTable);

        assert_eq!(registry.total_for(PinReason::SessionParameter), 1);
        assert_eq!(registry.total_for(PinReason::TempTable), 2);
        assert_eq!(registry.total_for(PinReason::Listen), 0);
        assert_eq!(registry.pinned_total(), 3);
    }

    #[test]
    fn reset_clears_everything() {
        let registry = PinRegistry::new();
        registry.record("svc", None, PinReason::Listen);
        registry.record_clean();
        registry.reset();

        let report = registry.report();
        assert_eq!(report.pinned_sessions, 0);
        assert_eq!(report.clean_sessions, 0);
        assert!(report.offenders.is_empty());
    }

    #[test]
    fn the_report_serialises_for_the_dashboard() {
        let registry = PinRegistry::new();
        registry.record("svc_orders", Some("orders-api"), PinReason::SessionParameter);

        let json = serde_json::to_value(registry.report()).unwrap();
        assert_eq!(json["offenders"][0]["user"], "svc_orders");
        assert_eq!(json["offenders"][0]["reason"], "session_parameter");
        assert_eq!(json["by_reason"][0]["reason"], "session_parameter");
    }

    #[test]
    fn concurrent_recording_does_not_lose_counts() {
        use std::sync::Arc;
        let registry = Arc::new(PinRegistry::new());
        let mut handles = Vec::new();

        for _ in 0..8 {
            let registry = registry.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    registry.record("svc", Some("app"), PinReason::SessionParameter);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(registry.pinned_total(), 800);
        assert_eq!(registry.report().offenders[0].count, 800);
    }
}
