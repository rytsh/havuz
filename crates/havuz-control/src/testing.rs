//! A family with no protocol behind it.
//!
//! Enabled by the `testing` feature. It exists so that crates above the seam —
//! `havuz-admin` in particular — can be tested without linking a wire codec.
//! That is not tidiness: if the admin API can only be exercised against
//! `havuz-pg`, then "the admin API does not depend on Postgres" is an assertion
//! nobody is checking, and it quietly stops being true.
//!
//! [`FakeFamily`] tracks pools exactly the way a real family does — it builds
//! the ones configured for its id, drains the ones that disappear — and refuses
//! to serve a connection, because there is nothing to serve it with.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use havuz_core::state::TargetRole;
use havuz_core::StateStore;
use havuz_pool::{BreakerConfig, CircuitBreaker, PoolSnapshot, WaitStats};
use havuz_proto::{PoolRoute, Probe, ProtoError, ProtoResult, ProtocolFamily, ServeOutcome};
use havuz_registry::FamilyDescriptor;
use tokio::net::TcpStream;

use crate::{ControlPlane, ReplicaReport, ReplicaRouting, RoutingReport, TargetPool, TargetReport};

/// A family that keeps a pool list and nothing else.
pub struct FakeFamily {
    family_id: &'static str,
    store: Arc<StateStore>,
    pools: Mutex<BTreeMap<String, PoolSnapshot>>,
    /// How many times the control plane asked for a rebuild. Lets a test assert
    /// that a mutation actually reached the family rather than only the store.
    syncs: Mutex<u32>,
}

impl FakeFamily {
    /// Pretends to be `postgres`, which is the only usable registry entry, so
    /// pools created through the admin API land here.
    pub fn new(store: Arc<StateStore>) -> Arc<Self> {
        Self::for_family("postgres", store)
    }

    pub fn for_family(family_id: &'static str, store: Arc<StateStore>) -> Arc<Self> {
        Arc::new(Self { family_id, store, pools: Mutex::new(BTreeMap::new()), syncs: Mutex::new(0) })
    }

    pub fn syncs(&self) -> u32 {
        *self.syncs.lock().expect("sync counter poisoned")
    }
}

impl ControlPlane for FakeFamily {
    fn sync_pools(&self) -> ProtoResult<()> {
        *self.syncs.lock().expect("sync counter poisoned") += 1;
        let state = self.store.load();
        let mut pools = self.pools.lock().expect("pool map poisoned");
        pools.retain(|name, _| state.pools.get(name).is_some_and(|c| c.family == self.family_id && !c.disabled));
        for (name, config) in &state.pools {
            if config.family != self.family_id || config.disabled {
                continue;
            }
            pools.entry(name.clone()).or_insert_with(|| PoolSnapshot {
                name: name.clone(),
                status: "active".into(),
                active: 0,
                idle: 0,
                open: 0,
                waiting: 0,
                max_size: config.limits.max_size,
                max_client_connections: config.limits.max_client_connections,
                created_total: 0,
                closed_total: 0,
                checkout_total: 0,
                timeout_total: 0,
                connect_error_total: 0,
                discarded_total: 0,
                wait: WaitStats { samples: 0, mean_micros: 0, max_micros: 0 },
            });
        }
        Ok(())
    }

    fn reload_pool(&self, name: &str) -> ProtoResult<()> {
        self.pools.lock().expect("pool map poisoned").remove(name);
        self.sync_pools()
    }

    fn pool_snapshots(&self) -> Vec<PoolSnapshot> {
        self.pools.lock().expect("pool map poisoned").values().cloned().collect()
    }

    /// Derived from the configuration rather than from a live connection, so a
    /// test can assert how the admin API renders a report without a database.
    /// Everything measured is reported as never measured, which is the state a
    /// freshly built pool is actually in.
    fn target_reports(&self) -> Vec<TargetReport> {
        let state = self.store.load();
        self.pools
            .lock()
            .expect("pool map poisoned")
            .values()
            .filter_map(|snapshot| {
                let config = state.pools.get(&snapshot.name)?;
                let label = |target: &havuz_core::Target| format!("{}:{}", target.host, target.port);
                Some(TargetReport {
                    name: snapshot.name.clone(),
                    mode: config.mode.as_str().to_string(),
                    read_write_split: config.routing.read_write_split,
                    primary: TargetPool {
                        label: config.primary().map(label).unwrap_or_default(),
                        pool: snapshot.clone(),
                    },
                    replicas: config
                        .targets
                        .iter()
                        .filter(|target| target.role == TargetRole::Replica)
                        .map(|target| ReplicaReport {
                            routing: ReplicaRouting {
                                label: label(target),
                                weight: target.weight,
                                lag_millis: None,
                                breaker: CircuitBreaker::new(BreakerConfig::default()).snapshot(),
                            },
                            pool: snapshot.clone(),
                        })
                        .collect(),
                    routing: RoutingReport::default(),
                })
            })
            .collect()
    }
}

#[async_trait]
impl ProtocolFamily for FakeFamily {
    fn descriptor(&self) -> &'static FamilyDescriptor {
        havuz_registry::family(self.family_id).expect("FakeFamily must name a registered family")
    }

    async fn serve(&self, _io: TcpStream, _peer: SocketAddr, _route: &PoolRoute) -> ProtoResult<ServeOutcome> {
        Err(ProtoError::Unsupported("FakeFamily speaks no protocol"))
    }

    /// Always fails, honestly: there is no driver to reach a database with.
    /// A failed probe is information the UI shows, not a server fault, and that
    /// is the path worth covering here.
    async fn probe(&self, pool: &str) -> ProtoResult<Probe> {
        if !self.pools.lock().expect("pool map poisoned").contains_key(pool) {
            return Err(ProtoError::NoRoute(pool.to_string()));
        }
        Err(ProtoError::backend("FakeFamily cannot connect to anything"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_core::state::{PoolConfig, PoolLimits, State, Target};
    use havuz_core::PoolMode;

    fn pool(family: &str) -> PoolConfig {
        PoolConfig {
            family: family.into(),
            profile: None,
            mode: PoolMode::Session,
            targets: vec![Target::new("127.0.0.1", 1)],
            backend_user: "app".into(),
            database: "appdb".into(),
            listen_port: 6432,
            limits: PoolLimits::default(),
            settings: Default::default(),
            routing: Default::default(),
            backend_auth: Default::default(),
            trace: Default::default(),
            disabled: false,
            description: None,
        }
    }

    #[test]
    fn it_builds_only_the_pools_that_name_its_family() {
        let mut state = State::default();
        state.pools.insert("mine".into(), pool("postgres"));
        state.pools.insert("theirs".into(), pool("mysql"));

        let family = FakeFamily::new(Arc::new(StateStore::ephemeral(state)));
        family.sync_pools().unwrap();

        let names: Vec<_> = family.pool_snapshots().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["mine"], "a family must ignore another family's pools");
    }

    #[tokio::test]
    async fn a_removed_pool_stops_being_reported_and_probed() {
        let mut state = State::default();
        state.pools.insert("mine".into(), pool("postgres"));
        let store = Arc::new(StateStore::ephemeral(state));

        let family = FakeFamily::new(store.clone());
        family.sync_pools().unwrap();
        assert!(matches!(family.probe("mine").await.unwrap_err(), ProtoError::Backend(_)));

        store.update(|state| state.pools.clear()).await.unwrap();
        family.sync_pools().unwrap();
        assert!(family.pool_snapshots().is_empty());
        assert!(matches!(family.probe("mine").await.unwrap_err(), ProtoError::NoRoute(_)));
        assert_eq!(family.syncs(), 2);
    }
}
