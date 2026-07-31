//! Target health probing.
//!
//! Two questions, asked of every target on a timer.
//!
//! **How far behind is this replica?** Naively that is
//! `now() - pg_last_xact_replay_timestamp()`, and it is wrong in a way that
//! matters: when the primary is idle, the last replayed timestamp stops moving
//! and the computed lag grows without bound even though the replica is
//! perfectly caught up. Under [`LAG_QUERY`] the LSNs are compared first, so a
//! caught-up replica reports zero regardless of write traffic.
//!
//! **Is the primary still the primary?** A promoted replica keeps accepting
//! connections and keeps rejecting writes, so a pooler that never checks will
//! route writes into an error loop after a failover. Asking
//! `pg_is_in_recovery()` turns that into a log line and a metric.
//!
//! Probes run through the pool itself rather than a side connection. That costs
//! nothing extra and has a useful property: the probe exercises the same path
//! real traffic takes, so it cannot report healthy while clients cannot connect.

use std::sync::Arc;
use std::time::Duration;

use havuz_pool::Pool;

use crate::backend::PgConnector;
use crate::routing::ReplicaState;

/// Replication delay in seconds.
///
/// The LSN comparison is a *distance*, not an equality, and the difference is
/// not cosmetic. `pg_last_wal_receive_lsn()` reports what streaming
/// replication has received; after a standby restarts it first replays WAL it
/// already had on disk and only then reconnects, so replay is legitimately
/// **ahead** of receive for a while. Measured on a real standby moments after a
/// restart:
///
/// ```text
/// receive_lsn   0/3000000
/// replay_lsn    0/3065BE8
/// byte_distance -416744      <- replay is ahead
/// timestamp_lag 352.9        <- and the timestamp is meaningless
/// ```
///
/// An equality test fails there, falls through to the timestamp branch, and
/// reports six minutes of lag on a standby that is perfectly caught up. The
/// replica would then be pulled out of rotation until the next write happened
/// to arrive. Treating any non-positive distance as caught up fixes it.
pub const LAG_QUERY: &str = "\
SELECT CASE \
WHEN NOT pg_is_in_recovery() THEN 0 \
WHEN pg_last_wal_receive_lsn() IS NULL THEN NULL \
WHEN pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()) <= 0 THEN 0 \
ELSE COALESCE(EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())), 0) \
END";

/// Whether this server is a standby.
pub const RECOVERY_QUERY: &str = "SELECT pg_is_in_recovery()";

/// Outcome of probing one target.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeResult {
    Healthy { in_recovery: bool, lag: Option<Duration> },
    Failed { error: String },
}

/// Probe a target through its pool.
pub async fn probe(pool: &Pool<PgConnector>) -> ProbeResult {
    let mut checkout = match pool.acquire().await {
        Ok(checkout) => checkout,
        Err(e) => return ProbeResult::Failed { error: e.to_string() },
    };

    let in_recovery = match checkout.query_scalar(RECOVERY_QUERY).await {
        Ok(Some(value)) => value == "t" || value.eq_ignore_ascii_case("true"),
        Ok(None) => false,
        Err(e) => {
            checkout.discard();
            return ProbeResult::Failed { error: e.to_string() };
        }
    };

    if !in_recovery {
        // A primary has no lag to report.
        return ProbeResult::Healthy { in_recovery, lag: Some(Duration::ZERO) };
    }

    match checkout.query_scalar(LAG_QUERY).await {
        Ok(Some(value)) => {
            let seconds: f64 = value.parse().unwrap_or(f64::MAX);
            // A negative reading means clock skew between the servers, not a
            // replica ahead of its primary. Clamp rather than wrap.
            let lag = Duration::from_secs_f64(seconds.clamp(0.0, 86_400.0));
            ProbeResult::Healthy { in_recovery, lag: Some(lag) }
        }
        // NULL means the standby has not replayed anything yet. Reporting zero
        // would let a brand new replica take reads it cannot serve.
        Ok(None) => ProbeResult::Healthy { in_recovery, lag: None },
        Err(e) => {
            checkout.discard();
            ProbeResult::Failed { error: e.to_string() }
        }
    }
}

/// Apply a probe result to a replica's routing state.
pub fn apply_to_replica(state: &ReplicaState, result: &ProbeResult) {
    match result {
        ProbeResult::Healthy { in_recovery, lag } => {
            if !*in_recovery {
                // This target was configured as a replica but is accepting
                // writes. Almost always a failover nobody told us about.
                tracing::warn!(
                    replica = %state.label,
                    "target is configured as a replica but is not in recovery; it may have been promoted"
                );
            }
            state.set_lag(*lag);
            state.breaker.record_success();
        }
        ProbeResult::Failed { error } => {
            tracing::debug!(replica = %state.label, %error, "replica probe failed");
            // Lag is now unknown, and unknown lag means ineligible. Without
            // this, a replica that stops responding keeps its last good lag
            // reading and stays in rotation until the breaker trips.
            state.set_lag(None);
            state.breaker.record_failure();
        }
    }
}

/// Run health probes for one pool group until cancelled.
pub fn spawn(
    pool_name: String,
    primary: Arc<Pool<PgConnector>>,
    replicas: Vec<(Arc<Pool<PgConnector>>, Arc<ReplicaState>)>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Stagger the first probe so restarting havuz does not hit every
        // database in the fleet at the same instant.
        tokio::time::sleep(Duration::from_millis(250)).await;

        loop {
            match probe(&primary).await {
                ProbeResult::Healthy { in_recovery: true, .. } => {
                    // The write target is a standby. Every write will fail
                    // until this is fixed, so it must be loud.
                    tracing::error!(
                        pool = %pool_name,
                        "primary is in recovery; writes will fail until a primary is configured"
                    );
                }
                ProbeResult::Failed { error } => {
                    tracing::warn!(pool = %pool_name, %error, "primary probe failed");
                }
                ProbeResult::Healthy { .. } => {}
            }

            for (pool, state) in &replicas {
                let result = probe(pool).await;
                apply_to_replica(state, &result);
            }

            tokio::time::sleep(interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_pool::BreakerConfig;

    fn replica() -> ReplicaState {
        ReplicaState::new("r1", 1, BreakerConfig { failure_threshold: 2, ..BreakerConfig::default() })
    }

    #[test]
    fn the_lag_query_compares_lsn_distance_not_equality() {
        // Two distinct traps this guards against, both observed on a real
        // standby:
        //
        //   * a timestamp-only formula reports growing lag whenever the primary
        //     is idle, draining traffic off a healthy replica;
        //   * an equality test misses the case where replay is *ahead* of
        //     receive, which happens for a while after every standby restart.
        assert!(LAG_QUERY.contains("pg_wal_lsn_diff"), "distance, not equality");
        assert!(LAG_QUERY.contains("<= 0"), "replay ahead of receive still means caught up");
        assert!(
            LAG_QUERY.contains("pg_last_wal_receive_lsn() IS NULL THEN NULL"),
            "a standby that has never received anything has unknown lag, not zero"
        );
    }

    #[test]
    fn a_successful_probe_records_lag_and_health() {
        let state = replica();
        apply_to_replica(&state, &ProbeResult::Healthy { in_recovery: true, lag: Some(Duration::from_millis(120)) });

        assert_eq!(state.lag(), Some(Duration::from_millis(120)));
        assert_eq!(state.breaker.state(), havuz_pool::BreakerState::Closed);
    }

    #[test]
    fn a_failed_probe_clears_the_lag_reading() {
        // Keeping the last good reading would leave a dead replica looking
        // fresh until the breaker happened to trip.
        let state = replica();
        apply_to_replica(&state, &ProbeResult::Healthy { in_recovery: true, lag: Some(Duration::ZERO) });
        assert_eq!(state.lag(), Some(Duration::ZERO));

        apply_to_replica(&state, &ProbeResult::Failed { error: "connection refused".into() });
        assert_eq!(state.lag(), None, "unknown lag means ineligible");
    }

    #[test]
    fn repeated_failures_trip_the_breaker() {
        let state = replica();
        apply_to_replica(&state, &ProbeResult::Failed { error: "x".into() });
        assert_eq!(state.breaker.state(), havuz_pool::BreakerState::Closed);

        apply_to_replica(&state, &ProbeResult::Failed { error: "x".into() });
        assert_eq!(state.breaker.state(), havuz_pool::BreakerState::Open);
    }

    #[test]
    fn a_standby_that_has_replayed_nothing_reports_unknown_lag() {
        let state = replica();
        apply_to_replica(&state, &ProbeResult::Healthy { in_recovery: true, lag: None });
        assert_eq!(state.lag(), None, "a fresh standby must not be treated as caught up");
    }

    #[test]
    fn a_promoted_replica_still_reports_healthy_but_is_flagged() {
        // It answers queries, so the breaker must not trip; the warning is what
        // tells an operator the topology changed underneath them.
        let state = replica();
        apply_to_replica(&state, &ProbeResult::Healthy { in_recovery: false, lag: Some(Duration::ZERO) });
        assert_eq!(state.breaker.state(), havuz_pool::BreakerState::Closed);
    }
}
