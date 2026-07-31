//! Pool statistics.
//!
//! Everything here is atomic and written from the hot path, so the rules are:
//! no locks, no allocation, `Relaxed` ordering. Counters are monotonic where
//! possible because gauges derived from deltas survive restarts and scrape
//! gaps better than gauges maintained by hand.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

#[derive(Debug, Default)]
pub(crate) struct Counters {
    /// Backends currently checked out by a client.
    pub active: AtomicU64,
    /// Backends open and available.
    pub idle: AtomicU64,
    /// Clients blocked waiting for a backend right now.
    pub waiting: AtomicU64,

    pub created_total: AtomicU64,
    pub closed_total: AtomicU64,
    pub checkout_total: AtomicU64,
    pub timeout_total: AtomicU64,
    pub connect_error_total: AtomicU64,
    /// Backends discarded because they were broken or too old.
    pub discarded_total: AtomicU64,

    /// Sum and count let us derive a mean without keeping a histogram on the
    /// hot path; `max` catches the tail that a mean hides.
    wait_micros_total: AtomicU64,
    wait_samples: AtomicU64,
    wait_micros_max: AtomicU64,
}

impl Counters {
    pub fn record_wait(&self, micros: u64) {
        self.wait_micros_total.fetch_add(micros, Ordering::Relaxed);
        self.wait_samples.fetch_add(1, Ordering::Relaxed);
        self.wait_micros_max.fetch_max(micros, Ordering::Relaxed);
    }

    pub fn snapshot(&self, name: &str, max_size: u32, max_clients: u32, status: &str) -> PoolSnapshot {
        let samples = self.wait_samples.load(Ordering::Relaxed);
        let total = self.wait_micros_total.load(Ordering::Relaxed);
        let active = self.active.load(Ordering::Relaxed);
        let idle = self.idle.load(Ordering::Relaxed);

        PoolSnapshot {
            name: name.to_string(),
            status: status.to_string(),
            active,
            idle,
            open: active + idle,
            waiting: self.waiting.load(Ordering::Relaxed),
            max_size,
            max_client_connections: max_clients,
            created_total: self.created_total.load(Ordering::Relaxed),
            closed_total: self.closed_total.load(Ordering::Relaxed),
            checkout_total: self.checkout_total.load(Ordering::Relaxed),
            timeout_total: self.timeout_total.load(Ordering::Relaxed),
            connect_error_total: self.connect_error_total.load(Ordering::Relaxed),
            discarded_total: self.discarded_total.load(Ordering::Relaxed),
            wait: WaitStats {
                samples,
                mean_micros: if samples == 0 { 0 } else { total / samples },
                max_micros: self.wait_micros_max.load(Ordering::Relaxed),
            },
        }
    }
}

/// Point-in-time view of one pool, as served to the dashboard and `/metrics`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PoolSnapshot {
    pub name: String,
    pub status: String,

    pub active: u64,
    pub idle: u64,
    /// `active + idle`: connections this pool is holding against the database.
    pub open: u64,
    pub waiting: u64,

    pub max_size: u32,
    pub max_client_connections: u32,

    pub created_total: u64,
    pub closed_total: u64,
    pub checkout_total: u64,
    pub timeout_total: u64,
    pub connect_error_total: u64,
    pub discarded_total: u64,

    pub wait: WaitStats,
}

impl PoolSnapshot {
    /// Realised client-to-backend ratio.
    ///
    /// The headline number: with 100 clients served by 3 backends this reads
    /// 33.3. Deliberately computed from observed values rather than configured
    /// limits, so it reflects what is actually happening.
    pub fn fan_in(&self) -> Option<f32> {
        let clients = self.active + self.waiting;
        if self.open == 0 || clients == 0 {
            return None;
        }
        Some(clients as f32 / self.open as f32)
    }

    /// Fraction of the backend budget in use. Above ~0.9 sustained means
    /// `max_size` is the bottleneck.
    pub fn saturation(&self) -> f32 {
        if self.max_size == 0 {
            return 0.0;
        }
        self.active as f32 / self.max_size as f32
    }

    pub fn is_exhausted(&self) -> bool {
        self.waiting > 0 && self.active >= self.max_size as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WaitStats {
    pub samples: u64,
    pub mean_micros: u64,
    pub max_micros: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> PoolSnapshot {
        Counters::default().snapshot("app_main", 3, 100, "active")
    }

    #[test]
    fn empty_pool_reports_no_fan_in() {
        let s = snapshot();
        assert_eq!(s.fan_in(), None, "a ratio over zero backends is meaningless");
        assert_eq!(s.saturation(), 0.0);
        assert!(!s.is_exhausted());
    }

    #[test]
    fn fan_in_is_the_headline_number() {
        let counters = Counters::default();
        counters.active.store(3, Ordering::Relaxed);
        counters.waiting.store(97, Ordering::Relaxed);

        let s = counters.snapshot("app_main", 3, 100, "active");
        assert_eq!(s.open, 3);
        let fan_in = s.fan_in().unwrap();
        assert!((fan_in - 33.333).abs() < 0.01, "100 clients over 3 backends is 33x, got {fan_in}");
        assert!(s.is_exhausted(), "clients are queued at max_size");
        assert_eq!(s.saturation(), 1.0);
    }

    #[test]
    fn idle_backends_count_towards_open_but_not_saturation() {
        let counters = Counters::default();
        counters.active.store(1, Ordering::Relaxed);
        counters.idle.store(4, Ordering::Relaxed);

        let s = counters.snapshot("app_main", 10, 100, "active");
        assert_eq!(s.open, 5);
        assert_eq!(s.active, 1);
        assert!((s.saturation() - 0.1).abs() < f32::EPSILON);
        assert!(!s.is_exhausted(), "nobody is waiting");
    }

    #[test]
    fn wait_stats_track_mean_and_tail() {
        let counters = Counters::default();
        counters.record_wait(100);
        counters.record_wait(300);
        counters.record_wait(50_000);

        let s = counters.snapshot("app_main", 3, 100, "active");
        assert_eq!(s.wait.samples, 3);
        assert_eq!(s.wait.mean_micros, (100 + 300 + 50_000) / 3);
        assert_eq!(s.wait.max_micros, 50_000, "the tail is what operators feel");
    }

    #[test]
    fn wait_stats_are_zero_not_nan_without_samples() {
        let s = snapshot();
        assert_eq!(s.wait.samples, 0);
        assert_eq!(s.wait.mean_micros, 0);
        assert_eq!(s.wait.max_micros, 0);
    }

    #[test]
    fn snapshot_serialises_flat_for_the_dashboard() {
        let json = serde_json::to_value(snapshot()).unwrap();
        assert_eq!(json["name"], "app_main");
        assert_eq!(json["max_size"], 3);
        assert_eq!(json["open"], 0);
        assert!(json["wait"].is_object());
    }
}
