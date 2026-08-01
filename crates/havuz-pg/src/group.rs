//! A pool and its replicas.
//!
//! Each target gets its own [`Pool`], because a connection to a replica is not
//! interchangeable with one to the primary. The [`Router`] sits above them and
//! decides which one a given statement may use.

use std::sync::Arc;
use std::time::Duration;

use havuz_control::{ReplicaReport, TargetPool, TargetReport};
use havuz_core::state::{PoolConfig, TargetRole};
use havuz_pool::{BreakerConfig, Pool, PoolSnapshot};
use havuz_proto::{PoolMode, ProtoError};

use crate::backend::PgConnector;
use crate::routing::{ReplicaState, Route, Router};

/// A configured pool: one primary, zero or more replicas, and a router.
pub struct PoolGroup {
    name: String,
    mode: PoolMode,
    primary: Arc<Pool<PgConnector>>,
    primary_label: String,
    replica_pools: Vec<Arc<Pool<PgConnector>>>,
    router: Router,
    health: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for PoolGroup {
    fn drop(&mut self) {
        if let Some(handle) = &self.health {
            handle.abort();
        }
    }
}

impl std::fmt::Debug for PoolGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolGroup")
            .field("name", &self.name)
            .field("mode", &self.mode.as_str())
            .field("replicas", &self.replica_pools.len())
            .finish()
    }
}

impl PoolGroup {
    /// Build a group from configuration.
    ///
    /// `build_connector` is supplied by the caller so this stays testable
    /// without a database and without reaching into the secret store.
    pub fn build<F>(name: &str, config: &PoolConfig, mut build_connector: F) -> Result<Arc<Self>, ProtoError>
    where
        F: FnMut(&havuz_core::Target) -> Result<PgConnector, ProtoError>,
    {
        let primary_target =
            config.primary().ok_or_else(|| ProtoError::backend(format!("pool '{name}' has no target")))?;

        let primary = Arc::new(Pool::new(
            format!("{name}/primary"),
            Arc::new(build_connector(primary_target)?),
            config.limits.clone(),
        ));

        let breaker = BreakerConfig {
            failure_threshold: config.routing.failure_threshold.max(1),
            success_threshold: 2,
            cooldown: config.routing.recovery_cooldown,
        };

        let mut replica_pools = Vec::new();
        let mut replica_states = Vec::new();

        for target in config.targets.iter().filter(|t| t.role == TargetRole::Replica) {
            let label = target.address();
            replica_pools.push(Arc::new(Pool::new(
                format!("{name}/{label}"),
                Arc::new(build_connector(target)?),
                config.limits.clone(),
            )));
            replica_states.push(Arc::new(ReplicaState::new(label, target.weight, breaker)));
        }

        let router = Router::new(config.routing.clone(), replica_states.clone());

        let health = if config.routing.read_write_split && !replica_states.is_empty() {
            let pairs: Vec<_> = replica_pools.iter().cloned().zip(replica_states.iter().cloned()).collect();
            Some(crate::health::spawn(
                name.to_string(),
                primary.clone(),
                pairs,
                config.routing.health_interval.max(Duration::from_secs(1)),
            ))
        } else {
            None
        };

        Ok(Arc::new(Self {
            name: name.to_string(),
            mode: config.mode,
            primary,
            primary_label: primary_target.address(),
            replica_pools,
            router,
            health,
        }))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mode(&self) -> PoolMode {
        self.mode
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    pub fn primary(&self) -> &Arc<Pool<PgConnector>> {
        &self.primary
    }

    /// The pool a route points at.
    ///
    /// A route referring to a replica that no longer exists falls back to the
    /// primary rather than failing: correctness first, performance second.
    pub fn pool_for(&self, route: Route) -> &Arc<Pool<PgConnector>> {
        match route {
            Route::Primary(_) => &self.primary,
            Route::Replica(index) => self.replica_pools.get(index).unwrap_or(&self.primary),
        }
    }

    pub fn target_label(&self, route: Route) -> String {
        match route {
            Route::Primary(_) => format!("primary/{}", self.primary_label),
            Route::Replica(index) => self
                .router
                .replicas()
                .get(index)
                .map(|replica| format!("replica/{}", replica.label))
                .unwrap_or_else(|| format!("primary/{}", self.primary_label)),
        }
    }

    /// Stop accepting new work and close idle connections everywhere.
    pub fn drain(&self) {
        self.primary.drain();
        for pool in &self.replica_pools {
            pool.drain();
        }
        if let Some(handle) = &self.health {
            handle.abort();
        }
    }

    pub fn snapshot(&self) -> TargetReport {
        TargetReport {
            name: self.name.clone(),
            mode: self.mode.as_str().to_string(),
            read_write_split: self.router.config().read_write_split,
            primary: TargetPool { label: self.primary_label.clone(), pool: self.primary.snapshot() },
            replicas: self
                .replica_pools
                .iter()
                .zip(self.router.replicas())
                .map(|(pool, state)| ReplicaReport { routing: state.snapshot(), pool: pool.snapshot() })
                .collect(),
            routing: self.router.stats().snapshot(),
        }
    }

    /// Combined view across every target, for the flat pool list.
    pub fn combined_pool_snapshot(&self) -> PoolSnapshot {
        let mut combined = self.primary.snapshot();
        combined.name = self.name.clone();
        for pool in &self.replica_pools {
            combined.merge(&pool.snapshot());
        }
        combined
    }

    /// Per-target snapshots in report order: primary, then each replica.
    pub fn target_snapshots(&self) -> Vec<PoolSnapshot> {
        std::iter::once(self.primary.snapshot()).chain(self.replica_pools.iter().map(|p| p.snapshot())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendConfig;
    use havuz_core::state::{PoolLimits, RoutingConfig, Target};
    use havuz_core::SslMode;

    fn connector(target: &havuz_core::Target) -> Result<PgConnector, ProtoError> {
        Ok(PgConnector::new(BackendConfig {
            host: target.host.clone(),
            port: target.port,
            database: "appdb".into(),
            user: "app".into(),
            password: String::new(),
            ssl_mode: SslMode::Disable,
            tls: None,
            application_name: "havuz/test".into(),
            supports_discard_all: true,
        }))
    }

    fn config(split: bool, replicas: usize) -> PoolConfig {
        let mut targets = vec![Target::new("primary.internal", 5432)];
        for i in 0..replicas {
            targets.push(Target {
                host: format!("replica{i}.internal"),
                port: 5432,
                role: TargetRole::Replica,
                weight: 1,
            });
        }
        PoolConfig {
            family: "postgres".into(),
            profile: None,
            mode: PoolMode::Transaction,
            targets,
            backend_user: "app".into(),
            database: "appdb".into(),
            listen_port: 6432,
            limits: PoolLimits { max_size: 3, ..PoolLimits::default() },
            settings: Default::default(),
            routing: RoutingConfig { read_write_split: split, ..RoutingConfig::default() },
            backend_auth: Default::default(),
            disabled: false,
            description: None,
        }
    }

    #[tokio::test]
    async fn a_group_builds_one_pool_per_target() {
        let group = PoolGroup::build("app_main", &config(true, 2), connector).unwrap();
        assert_eq!(group.router().replicas().len(), 2);
        assert_eq!(group.snapshot().replicas.len(), 2);
        assert_eq!(group.snapshot().primary.label, "primary.internal:5432");
    }

    #[tokio::test]
    async fn a_pool_without_replicas_is_just_a_primary() {
        let group = PoolGroup::build("app_main", &config(false, 0), connector).unwrap();
        assert!(group.router().replicas().is_empty());
        assert!(std::ptr::eq(Arc::as_ptr(group.pool_for(Route::Replica(0))), Arc::as_ptr(group.primary())));
    }

    #[tokio::test]
    async fn routes_resolve_to_the_right_pool() {
        let group = PoolGroup::build("app_main", &config(true, 2), connector).unwrap();

        let primary = group.pool_for(Route::Primary(crate::routing::PrimaryReason::Write));
        assert_eq!(primary.name(), "app_main/primary");
        assert_eq!(group.pool_for(Route::Replica(0)).name(), "app_main/replica0.internal:5432");
        assert_eq!(group.pool_for(Route::Replica(1)).name(), "app_main/replica1.internal:5432");
    }

    #[tokio::test]
    async fn an_out_of_range_replica_index_falls_back_to_the_primary() {
        // Would only happen if configuration changed under a live session, but
        // failing the query would be a worse answer than using the primary.
        let group = PoolGroup::build("app_main", &config(true, 1), connector).unwrap();
        assert!(std::ptr::eq(Arc::as_ptr(group.pool_for(Route::Replica(99))), Arc::as_ptr(group.primary())));
    }

    #[tokio::test]
    async fn health_probing_only_runs_when_it_can_matter() {
        let with_split = PoolGroup::build("a", &config(true, 1), connector).unwrap();
        assert!(with_split.health.is_some());

        let no_split = PoolGroup::build("b", &config(false, 1), connector).unwrap();
        assert!(no_split.health.is_none(), "no point probing replicas nothing will be routed to");

        let no_replicas = PoolGroup::build("c", &config(true, 0), connector).unwrap();
        assert!(no_replicas.health.is_none());
    }

    #[tokio::test]
    async fn the_combined_snapshot_sums_the_group() {
        let group = PoolGroup::build("app_main", &config(true, 2), connector).unwrap();
        let combined = group.combined_pool_snapshot();

        assert_eq!(combined.name, "app_main");
        assert_eq!(combined.max_size, 9, "3 per target across 3 targets");
        assert_eq!(combined.open, 0);
    }

    #[tokio::test]
    async fn a_pool_with_no_targets_is_refused() {
        let mut cfg = config(false, 0);
        cfg.targets.clear();
        assert!(PoolGroup::build("app_main", &cfg, connector).is_err());
    }
}
