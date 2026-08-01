//! What a family tells the dashboard about its targets.
//!
//! These types deliberately live above the families rather than inside one.
//! `/metrics` and the Targets screen would otherwise have to know the shape of
//! every family's internal snapshot struct, which is the same coupling that
//! forced `havuz-admin` to depend on `havuz-pg` in the first place.
//!
//! The vocabulary is "one primary, zero or more replicas, and a router that
//! chose between them". A family without replicas — a JDBC bridge, a Redis
//! proxy — reports an empty replica list and a routing report where every
//! statement went to the primary. Nothing here assumes PostgreSQL.

use std::time::Duration;

use havuz_pool::{BreakerSnapshot, PoolSnapshot};
use serde::Serialize;

/// Everything the control plane knows about one configured pool's targets.
///
/// Field names are part of the admin API contract; the dashboard reads them
/// directly.
#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub name: String,
    pub mode: String,
    pub read_write_split: bool,
    pub primary: TargetPool,
    pub replicas: Vec<ReplicaReport>,
    pub routing: RoutingReport,
}

/// One user running as its own database role.
///
/// Reported separately from [`TargetReport`] and never as a metric label: a
/// series per user is unbounded cardinality, and the question this answers —
/// "who is holding connections of their own, and how many" — is one an operator
/// asks on a page, not on a dashboard refresh.
#[derive(Debug, Clone, Serialize)]
pub struct BackendIdentity {
    pub pool: String,
    /// havuz user, which under per-user authentication is also the database
    /// role these connections were opened as.
    pub user: String,
    pub pool_snapshot: PoolSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetPool {
    pub label: String,
    pub pool: PoolSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplicaReport {
    #[serde(flatten)]
    pub routing: ReplicaRouting,
    pub pool: PoolSnapshot,
}

/// Health and position of one replica.
#[derive(Debug, Clone, Serialize)]
pub struct ReplicaRouting {
    pub label: String,
    pub weight: u32,
    /// `None` means never measured, which is *not* the same as caught up. The
    /// exposition renders it as `-1` for exactly that reason.
    #[serde(serialize_with = "serialize_lag")]
    pub lag_millis: Option<Duration>,
    pub breaker: BreakerSnapshot,
}

fn serialize_lag<S: serde::Serializer>(value: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(d) => s.serialize_some(&(d.as_millis() as u64)),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RoutingReport {
    pub to_primary: u64,
    pub to_replica: u64,
    /// Fraction of statements a replica actually handled. The number that says
    /// whether read/write split is doing anything.
    pub replica_share: Option<f32>,
    pub primary_reasons: Vec<PrimaryReasonCount>,
}

/// Why a statement went to the primary. Surfaced in the dashboard, because
/// "why is my replica idle?" is otherwise unanswerable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryReason {
    /// Read/write split is not enabled for this pool.
    SplitDisabled,
    /// The statement writes, or could not be proven not to.
    Write,
    /// The session wrote recently, so its reads follow it to the primary.
    ReadAfterWrite,
    /// A transaction is open and was already routed.
    TransactionPinned,
    /// Every replica is unhealthy, lagging, or absent.
    NoReplicaAvailable,
}

impl PrimaryReason {
    /// Bounded label set, safe to use as a Prometheus label value.
    pub fn as_str(self) -> &'static str {
        match self {
            PrimaryReason::SplitDisabled => "split_disabled",
            PrimaryReason::Write => "write",
            PrimaryReason::ReadAfterWrite => "read_after_write",
            PrimaryReason::TransactionPinned => "transaction_pinned",
            PrimaryReason::NoReplicaAvailable => "no_replica_available",
        }
    }

    pub const ALL: [PrimaryReason; 5] = [
        PrimaryReason::SplitDisabled,
        PrimaryReason::Write,
        PrimaryReason::ReadAfterWrite,
        PrimaryReason::TransactionPinned,
        PrimaryReason::NoReplicaAvailable,
    ];

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|r| *r == self).expect("PrimaryReason::ALL is exhaustive")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PrimaryReasonCount {
    pub reason: PrimaryReason,
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_has_a_distinct_stable_label() {
        let mut seen = std::collections::BTreeSet::new();
        for reason in PrimaryReason::ALL {
            assert!(seen.insert(reason.as_str()), "duplicate label {}", reason.as_str());
            assert_eq!(PrimaryReason::ALL[reason.index()], reason);
        }
    }

    #[test]
    fn an_unmeasured_lag_serialises_as_null_rather_than_zero() {
        // Zero means caught up. A scrape must never confuse the two.
        let routing = ReplicaRouting {
            label: "replica-1".into(),
            weight: 1,
            lag_millis: None,
            breaker: havuz_pool::CircuitBreaker::new(havuz_pool::BreakerConfig::default()).snapshot(),
        };
        let json = serde_json::to_value(&routing).unwrap();
        assert!(json["lag_millis"].is_null());
    }
}
