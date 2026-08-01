//! What the control plane needs from any protocol family.
//!
//! [`havuz_proto::ProtocolFamily`] answers the data-plane question: given a
//! socket and the pools behind it, serve the client. That is enough for an
//! accept loop and nothing else. The admin API, the dashboard and `/metrics`
//! need a second surface — rebuild this pool, what is open, who is connected,
//! what got pinned — and until this crate existed that surface was a pile of
//! inherent methods on `PgFamily`, which is why `havuz-admin` had to depend on
//! `havuz-pg`.
//!
//! Two things keep [`ControlPlane`] small.
//!
//! **Sockets are not the family's.** `havuz-server` binds every port and hands
//! over accepted connections. A family owning listeners is what made the shared
//! client port single-family in the first place.
//!
//! **Observability is process-wide.** Live sessions, pin analytics, backend
//! holders and query traces are shared through [`Registries`], not duplicated
//! per family. Two families in one process are still one dashboard, and a
//! second trace database would be a second file to protect for no gain.
//!
//! What is left is four methods about pools.

pub mod holders;
pub mod report;
pub mod sessions;
#[cfg(feature = "testing")]
pub mod testing;
pub mod trace;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use havuz_core::State;
use havuz_pool::PoolSnapshot;
use havuz_proto::{PinRegistry, ProtoError, ProtoResult, ProtocolFamily};

pub use holders::{BackendHolder, HolderHandle, HolderRegistry};
pub use report::{
    BackendIdentity, PrimaryReason, PrimaryReasonCount, ReplicaReport, ReplicaRouting, RoutingReport, TargetPool,
    TargetReport,
};
pub use sessions::{KickSignal, LiveSession, SessionHandle, SessionRegistry, TooManySessions};
pub use trace::{
    ActiveTrace, QueryResult, ResultSet, TraceContext, TraceDetail, TraceError, TraceFilter, TraceSpan, TraceStore,
    TraceSummary, MAX_RESULT_BYTES, MAX_RESULT_ROWS, RETENTION_DAYS,
};

/// The observability every family shares.
///
/// Constructed once and handed to each family, so the dashboard shows one list
/// of sessions and one pin rate no matter how many protocols are running.
#[derive(Clone)]
pub struct Registries {
    pub sessions: Arc<SessionRegistry>,
    pub pins: Arc<PinRegistry>,
    pub holders: Arc<HolderRegistry>,
    pub traces: Arc<TraceStore>,
}

impl std::fmt::Debug for Registries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registries").field("sessions", &self.sessions.len()).finish_non_exhaustive()
    }
}

impl Registries {
    /// Traces persisted to `path`, which is created with mode 0600.
    pub fn persistent(path: impl AsRef<std::path::Path>) -> Result<Self, TraceError> {
        Ok(Self::with_traces(TraceStore::open(path)?))
    }

    /// Traces kept in memory. For tests and for `--dry-run`.
    pub fn ephemeral() -> Self {
        Self::with_traces(TraceStore::memory())
    }

    fn with_traces(traces: Arc<TraceStore>) -> Self {
        Self {
            sessions: SessionRegistry::new(),
            pins: Arc::new(PinRegistry::new()),
            holders: HolderRegistry::new(),
            traces,
        }
    }
}

/// The control-plane surface of one protocol family.
///
/// Object-safe, and used as `Arc<dyn ControlPlane>`: the server builds families
/// it does not name and the admin API serves them without knowing which one it
/// got.
///
/// Every method takes `&self`. A family that needs an owned handle to itself
/// holds its own `Weak`, because `self: &Arc<Self>` is not a legal receiver on
/// a trait object and making every caller clone an `Arc` for a read would leak
/// that detail into the admin handlers.
pub trait ControlPlane: ProtocolFamily {
    /// Bring the live pool set in line with the stored configuration.
    ///
    /// Must be idempotent and must ignore pools belonging to another family:
    /// the admin API calls it on every family after every mutation.
    fn sync_pools(&self) -> ProtoResult<()>;

    /// Rebuild one pool after its runtime settings change.
    ///
    /// A no-op for a pool this family does not own.
    fn reload_pool(&self, name: &str) -> ProtoResult<()>;

    /// Flat per-pool view, combined across targets. Drives the pool list, the
    /// summary and most of `/metrics`.
    fn pool_snapshots(&self) -> Vec<PoolSnapshot>;

    /// Per-target detail: replica health, lag and routing distribution.
    /// Families without replicas report an empty replica list.
    fn target_reports(&self) -> Vec<TargetReport>;

    /// Users currently running as their own database role.
    ///
    /// Empty for families and pools that share one service account, which is
    /// the default and will stay the common case.
    fn backend_identities(&self) -> Vec<BackendIdentity> {
        Vec::new()
    }
}

/// Every family compiled into this process.
///
/// Pools name their family, so routing a control-plane request is a lookup
/// rather than a match arm that has to be updated in four files.
#[derive(Clone, Default)]
pub struct FamilySet {
    families: Vec<Arc<dyn ControlPlane>>,
}

impl std::fmt::Debug for FamilySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.families.iter().map(|family| family.descriptor().id)).finish()
    }
}

impl FamilySet {
    pub fn new(families: Vec<Arc<dyn ControlPlane>>) -> Self {
        Self { families }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn ControlPlane>> {
        self.families.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }

    pub fn get(&self, family_id: &str) -> Option<&Arc<dyn ControlPlane>> {
        self.families.iter().find(|family| family.descriptor().id == family_id)
    }

    /// The family that owns a pool, according to the configuration.
    pub fn for_pool(&self, state: &State, pool: &str) -> Option<&Arc<dyn ControlPlane>> {
        self.get(&state.pools.get(pool)?.family)
    }

    /// Rebuild every family's pools.
    ///
    /// Stops at the first failure, so a bad pool is reported rather than
    /// leaving half the process reconfigured and half not.
    pub fn sync_all(&self) -> ProtoResult<()> {
        for family in &self.families {
            family
                .sync_pools()
                .map_err(|e| ProtoError::backend(format!("family '{}': {e}", family.descriptor().id)))?;
        }
        Ok(())
    }

    /// Every pool in the process, sorted by name so the dashboard does not
    /// reorder rows as families are added.
    pub fn pool_snapshots(&self) -> Vec<PoolSnapshot> {
        let mut out: Vec<_> = self.families.iter().flat_map(|family| family.pool_snapshots()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn target_reports(&self) -> Vec<TargetReport> {
        let mut out: Vec<_> = self.families.iter().flat_map(|family| family.target_reports()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn backend_identities(&self) -> Vec<BackendIdentity> {
        let mut out: Vec<_> = self.families.iter().flat_map(|family| family.backend_identities()).collect();
        out.sort_by(|a, b| (&a.pool, &a.user).cmp(&(&b.pool, &b.user)));
        out
    }
}

/// The process-wide client ceiling.
///
/// Enforced at accept time rather than after the handshake: a connection storm
/// must not be able to exhaust file descriptors while every one of those
/// sockets waits for a startup packet that per-pool limits would eventually
/// have rejected. Process-wide because file descriptors are, and because the
/// listeners now belong to the server rather than to any one family.
#[derive(Debug)]
pub struct ClientGate {
    live: Arc<AtomicU64>,
    max: AtomicU64,
}

impl Default for ClientGate {
    fn default() -> Self {
        Self::new(u32::MAX)
    }
}

impl ClientGate {
    pub fn new(max: u32) -> Self {
        Self { live: Arc::new(AtomicU64::new(0)), max: AtomicU64::new(max as u64) }
    }

    /// Claim a slot, or `None` if the process is already at its ceiling.
    ///
    /// The check and the increment are one `fetch_update`, so two simultaneous
    /// accepts cannot both see room for one.
    pub fn try_acquire(&self) -> Option<ClientPermit> {
        let max = self.max.load(Ordering::Relaxed);
        self.live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| (live < max).then_some(live + 1))
            .ok()
            .map(|_| ClientPermit { live: self.live.clone() })
    }

    pub fn live(&self) -> u64 {
        self.live.load(Ordering::Relaxed)
    }
}

/// Holds one client slot for as long as the session lives.
#[derive(Debug)]
pub struct ClientPermit {
    live: Arc<AtomicU64>,
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_admits_up_to_the_ceiling_and_frees_slots_on_drop() {
        let gate = ClientGate::new(2);

        let first = gate.try_acquire().expect("first slot");
        let second = gate.try_acquire().expect("second slot");
        assert_eq!(gate.live(), 2);
        assert!(gate.try_acquire().is_none(), "the ceiling must be enforced at accept time");

        drop(second);
        assert_eq!(gate.live(), 1);
        assert!(gate.try_acquire().is_some(), "a closed session frees its slot");
        drop(first);
    }

    #[test]
    fn registries_are_shared_by_cloning_the_handles_not_the_state() {
        let registries = Registries::ephemeral();
        let copy = registries.clone();
        let _session = registries.sessions.register("svc", "app_main", None, "127.0.0.1:1", 0).unwrap();
        assert_eq!(copy.sessions.len(), 1, "two families must see one session list");
    }

    #[test]
    fn an_empty_family_set_reports_nothing_rather_than_panicking() {
        let set = FamilySet::default();
        assert!(set.is_empty());
        assert!(set.pool_snapshots().is_empty());
        assert!(set.get("postgres").is_none());
        set.sync_all().expect("nothing to sync");
    }
}
