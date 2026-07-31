//! Runtime state: pools, users, secrets.
//!
//! This is the plane the admin UI owns. It is persisted as one atomically
//! rewritten JSON document (see [`crate::store`]) and is the source of truth
//! once havuz has started at least once.

use std::collections::BTreeMap;
use std::time::Duration;

use havuz_registry::{Maturity, PoolMode};
use havuz_secrets::SecretStore;
use serde::{Deserialize, Serialize};

/// Bumped when the on-disk shape changes in a way that needs migration.
pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    #[serde(default)]
    pub pools: BTreeMap<String, PoolConfig>,
    #[serde(default)]
    pub users: BTreeMap<String, UserConfig>,
    #[serde(default)]
    pub secrets: SecretStore,
}

impl Default for State {
    fn default() -> Self {
        Self { version: STATE_VERSION, pools: BTreeMap::new(), users: BTreeMap::new(), secrets: SecretStore::new() }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateError {
    #[error("state file version {found} is newer than this build understands ({expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("pool '{0}' is not a valid name; use letters, digits, '_' and '-'")]
    BadPoolName(String),
    #[error("user '{0}' is not a valid name; use letters, digits, '_' and '-'")]
    BadUserName(String),
    #[error("pool '{pool}' references unknown database family '{family}'")]
    UnknownFamily { pool: String, family: String },
    #[error("pool '{pool}' references unknown driver profile '{profile}' of family '{family}'")]
    UnknownProfile { pool: String, family: String, profile: String },
    #[error("pool '{pool}' uses family '{family}' which has no driver yet")]
    FamilyNotImplemented { pool: String, family: String },
    #[error("pool '{pool}' requests {mode} mode, but profile '{profile}' only supports up to {max}")]
    PoolModeTooAggressive { pool: String, profile: String, mode: &'static str, max: &'static str },
    #[error("pool '{0}' has no targets")]
    NoTargets(String),
    #[error("pool '{pool}': min_idle ({min_idle}) cannot exceed max_size ({max_size})")]
    MinIdleAboveMax { pool: String, min_idle: u32, max_size: u32 },
    #[error("pool '{0}': max_size must be at least 1")]
    ZeroMaxSize(String),
    #[error("pool '{0}': listen_port must be between 1 and 65535")]
    ZeroListenPort(String),
    #[error("pools '{first}' and '{second}' both request listen port {port}")]
    DuplicateListenPort { first: String, second: String, port: u16 },
    #[error("user '{user}' is granted unknown pool '{pool}'")]
    UnknownPoolGrant { user: String, pool: String },
    #[error("user '{0}' has no pool grants and could never connect")]
    NoGrants(String),
}

impl State {
    /// Check every invariant the pooler relies on at runtime.
    ///
    /// Called on load and before every write, so an invalid state can never be
    /// persisted or served.
    pub fn validate(&self) -> Result<(), StateError> {
        if self.version > STATE_VERSION {
            return Err(StateError::UnsupportedVersion { found: self.version, expected: STATE_VERSION });
        }

        let mut listen_ports = BTreeMap::new();
        for (name, pool) in &self.pools {
            if !is_valid_name(name) {
                return Err(StateError::BadPoolName(name.clone()));
            }
            pool.validate(name)?;
            if let Some(port) = pool.listen_port {
                if port == 0 {
                    return Err(StateError::ZeroListenPort(name.clone()));
                }
                if let Some(first) = listen_ports.insert(port, name.clone()) {
                    return Err(StateError::DuplicateListenPort { first, second: name.clone(), port });
                }
            }
        }

        for (name, user) in &self.users {
            if !is_valid_name(name) {
                return Err(StateError::BadUserName(name.clone()));
            }
            if user.pools.is_empty() {
                return Err(StateError::NoGrants(name.clone()));
            }
            for granted in &user.pools {
                if !self.pools.contains_key(granted) {
                    return Err(StateError::UnknownPoolGrant { user: name.clone(), pool: granted.clone() });
                }
            }
        }

        Ok(())
    }

    /// Non-fatal observations worth showing in the UI.
    ///
    /// The most important one by far: a small `max_size` on a session-mode pool
    /// does not save backend connections, it just queues clients. This is the
    /// single most common misconfiguration in every pooler.
    pub fn warnings(&self) -> Vec<Warning> {
        let mut out = Vec::new();
        for (name, pool) in &self.pools {
            if !pool.mode.multiplexes() && pool.limits.max_client_connections > pool.limits.max_size {
                out.push(Warning::SessionModeQueues {
                    pool: name.clone(),
                    max_client_connections: pool.limits.max_client_connections,
                    max_size: pool.limits.max_size,
                });
            }
            if pool.limits.max_client_connections < pool.limits.max_size {
                out.push(Warning::BackendsExceedClients {
                    pool: name.clone(),
                    max_client_connections: pool.limits.max_client_connections,
                    max_size: pool.limits.max_size,
                });
            }
            if !self.users.values().any(|u| u.pools.iter().any(|p| p == name)) {
                out.push(Warning::PoolWithoutUsers { pool: name.clone() });
            }
            if pool.routing.read_write_split && pool.replicas().count() == 0 {
                out.push(Warning::SplitWithoutReplicas { pool: name.clone() });
            }
            if pool.routing.read_write_split && pool.routing.sticky_after_write.is_zero() {
                out.push(Warning::NoStickyWindow { pool: name.clone() });
            }
        }
        out
    }

    /// Pools a user may connect to, honouring the disabled flags on both sides.
    pub fn pools_for_user(&self, user: &str) -> Vec<&str> {
        let Some(user) = self.users.get(user).filter(|u| !u.disabled) else {
            return Vec::new();
        };
        user.pools
            .iter()
            .filter(|p| self.pools.get(*p).is_some_and(|pool| !pool.disabled))
            .map(String::as_str)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Warning {
    /// `max_size` cannot reduce backend connections in session mode.
    SessionModeQueues {
        pool: String,
        max_client_connections: u32,
        max_size: u32,
    },
    /// More backends than clients can ever use them.
    BackendsExceedClients {
        pool: String,
        max_client_connections: u32,
        max_size: u32,
    },
    PoolWithoutUsers {
        pool: String,
    },
    /// Read/write split is on but there is nothing to split onto.
    SplitWithoutReplicas {
        pool: String,
    },
    /// Read/write split with no sticky window: a read issued straight after a
    /// write can be served stale.
    NoStickyWindow {
        pool: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoolConfig {
    /// Registry family id, e.g. `postgres`.
    pub family: String,
    /// Registry driver profile id, e.g. `cockroachdb`. `None` uses the family default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub mode: PoolMode,
    pub targets: Vec<Target>,
    /// Backend service account. The password lives in the secret store, keyed
    /// by `havuz_secrets::pool_backend_password(pool_name)`.
    pub backend_user: String,
    /// Database opened on the backend.
    pub database: String,
    /// Optional client-facing port dedicated to this pool. When absent, clients
    /// use the shared listener and select the pool by database name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    pub limits: PoolLimits,
    /// Family-specific settings validated against the registry's config fields.
    #[serde(default)]
    pub settings: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl PoolConfig {
    fn validate(&self, name: &str) -> Result<(), StateError> {
        let family = havuz_registry::family(&self.family)
            .ok_or_else(|| StateError::UnknownFamily { pool: name.into(), family: self.family.clone() })?;

        if family.maturity == Maturity::Planned {
            return Err(StateError::FamilyNotImplemented { pool: name.into(), family: self.family.clone() });
        }

        let profile = match &self.profile {
            Some(id) => family.profile(id).ok_or_else(|| StateError::UnknownProfile {
                pool: name.into(),
                family: self.family.clone(),
                profile: id.clone(),
            })?,
            None => family.default_profile(),
        };

        // A profile may cap the pooling mode below what the family supports:
        // Redshift cannot be driven as hard as upstream Postgres.
        if rank(self.mode) > rank(profile.quirks.max_pool_mode) {
            return Err(StateError::PoolModeTooAggressive {
                pool: name.into(),
                profile: profile.id.into(),
                mode: self.mode.as_str(),
                max: profile.quirks.max_pool_mode.as_str(),
            });
        }

        if self.targets.is_empty() {
            return Err(StateError::NoTargets(name.into()));
        }
        if self.limits.max_size == 0 {
            return Err(StateError::ZeroMaxSize(name.into()));
        }
        if self.limits.min_idle > self.limits.max_size {
            return Err(StateError::MinIdleAboveMax {
                pool: name.into(),
                min_idle: self.limits.min_idle,
                max_size: self.limits.max_size,
            });
        }
        Ok(())
    }

    /// Best-case client-to-backend ratio this pool can deliver.
    ///
    /// Returns `None` in session mode, where multiplexing is impossible and any
    /// ratio we printed would be a lie.
    pub fn fan_in(&self) -> Option<f32> {
        if !self.mode.multiplexes() || self.limits.max_size == 0 {
            return None;
        }
        Some(self.limits.max_client_connections as f32 / self.limits.max_size as f32)
    }

    /// Primary target, i.e. the one that accepts writes.
    pub fn primary(&self) -> Option<&Target> {
        self.targets.iter().find(|t| t.role == TargetRole::Primary).or_else(|| self.targets.first())
    }

    pub fn replicas(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter().filter(|t| t.role == TargetRole::Replica)
    }
}

/// Ordering used to compare how aggressive a pooling mode is.
fn rank(mode: PoolMode) -> u8 {
    match mode {
        PoolMode::Session => 0,
        PoolMode::Transaction => 1,
        PoolMode::Statement => 2,
    }
}

/// How traffic is spread across a pool's targets.
///
/// Read/write split is **off by default**, and that is a deliberate product
/// decision rather than caution. Turning it on changes the consistency
/// guarantees an application sees: a read that follows a write can land on a
/// replica that has not caught up yet, and the symptom is missing data rather
/// than an error. It should be an explicit choice, made once, by someone who
/// knows the application.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RoutingConfig {
    /// Route read-only statements to replicas.
    pub read_write_split: bool,

    /// After a session writes, keep its reads on the primary for this long.
    ///
    /// This is what makes read/write split safe for ordinary applications:
    /// the classic "insert then select it back" pattern keeps working because
    /// the read follows the write to the primary. Set it comfortably above
    /// your replication lag.
    #[serde(with = "humantime_serde")]
    pub sticky_after_write: Duration,

    /// Refuse replicas lagging further behind than this. `None` disables the
    /// check, which means stale reads are bounded only by hope.
    #[serde(with = "humantime_serde")]
    pub max_replica_lag: Option<Duration>,

    /// How often each target is probed.
    #[serde(with = "humantime_serde")]
    pub health_interval: Duration,

    /// Consecutive probe failures that take a target out of rotation.
    pub failure_threshold: u32,

    /// How long a failed target waits before it is probed again.
    #[serde(with = "humantime_serde")]
    pub recovery_cooldown: Duration,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            read_write_split: false,
            sticky_after_write: Duration::from_secs(10),
            max_replica_lag: Some(Duration::from_secs(5)),
            health_interval: Duration::from_secs(5),
            failure_threshold: 3,
            recovery_cooldown: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub role: TargetRole,
    /// Relative weight for load balancing across same-role targets.
    #[serde(default = "one")]
    pub weight: u32,
}

fn one() -> u32 {
    1
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port, role: TargetRole::Primary, weight: 1 }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetRole {
    #[default]
    Primary,
    Replica,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PoolLimits {
    /// Maximum backend connections havuz will open. This is the number that
    /// protects the database.
    pub max_size: u32,
    /// Connections kept warm so the first client does not pay for a handshake.
    pub min_idle: u32,
    /// Maximum clients accepted into this pool.
    pub max_client_connections: u32,
    /// How long a client waits for a backend before being rejected.
    #[serde(with = "humantime_serde")]
    pub queue_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Idle backends older than this are closed down to `min_idle`.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Backends are retired at this age even while healthy, so failovers and
    /// credential rotations converge.
    #[serde(with = "humantime_serde")]
    pub max_lifetime: Duration,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_size: 10,
            min_idle: 0,
            max_client_connections: 100,
            queue_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserConfig {
    /// Pools this user may reach. Empty is rejected at validation time.
    pub pools: Vec<String>,
    /// Per-user share of the pool's client budget. `0` means "no personal cap".
    #[serde(default)]
    pub max_client_connections: u32,
    /// Reject anything the protocol layer classifies as a write.
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl UserConfig {
    pub fn new(pools: Vec<String>) -> Self {
        Self { pools, max_client_connections: 0, read_only: false, disabled: false, description: None }
    }
}

/// Names end up in URLs, log lines and metric labels, so keep them boring.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> PoolConfig {
        PoolConfig {
            family: "postgres".into(),
            profile: None,
            mode: PoolMode::Session,
            targets: vec![Target::new("pg-primary.internal", 5432)],
            backend_user: "app".into(),
            database: "appdb".into(),
            listen_port: None,
            limits: PoolLimits::default(),
            settings: Default::default(),
            routing: Default::default(),
            disabled: false,
            description: None,
        }
    }

    fn state_with_pool(name: &str, pool: PoolConfig) -> State {
        let mut state = State::default();
        state.pools.insert(name.into(), pool);
        state.users.insert("svc".into(), UserConfig::new(vec![name.into()]));
        state
    }

    #[test]
    fn default_state_is_valid() {
        State::default().validate().unwrap();
    }

    #[test]
    fn a_realistic_pool_validates() {
        state_with_pool("app_main", pool()).validate().unwrap();
    }

    #[test]
    fn unknown_family_is_rejected() {
        let mut p = pool();
        p.family = "cassandra".into();
        let err = state_with_pool("app_main", p).validate().unwrap_err();
        assert_eq!(err, StateError::UnknownFamily { pool: "app_main".into(), family: "cassandra".into() });
    }

    #[test]
    fn planned_family_cannot_be_configured_yet() {
        let mut p = pool();
        p.family = "mysql".into();
        let err = state_with_pool("app_main", p).validate().unwrap_err();
        assert_eq!(err, StateError::FamilyNotImplemented { pool: "app_main".into(), family: "mysql".into() });
    }

    #[test]
    fn profile_caps_the_pool_mode() {
        // openGauss is capped at session mode by its quirk table.
        let mut p = pool();
        p.profile = Some("opengauss".into());
        p.mode = PoolMode::Transaction;
        let err = state_with_pool("app_main", p).validate().unwrap_err();
        assert_eq!(
            err,
            StateError::PoolModeTooAggressive {
                pool: "app_main".into(),
                profile: "opengauss".into(),
                mode: "transaction",
                max: "session",
            }
        );
    }

    #[test]
    fn profile_that_allows_transaction_mode_passes() {
        let mut p = pool();
        p.profile = Some("cockroachdb".into());
        p.mode = PoolMode::Transaction;
        state_with_pool("app_main", p).validate().unwrap();
    }

    #[test]
    fn limits_are_sanity_checked() {
        let mut p = pool();
        p.limits.max_size = 0;
        assert_eq!(state_with_pool("x", p).validate().unwrap_err(), StateError::ZeroMaxSize("x".into()));

        let mut p = pool();
        p.limits.min_idle = 20;
        p.limits.max_size = 10;
        assert_eq!(
            state_with_pool("x", p).validate().unwrap_err(),
            StateError::MinIdleAboveMax { pool: "x".into(), min_idle: 20, max_size: 10 }
        );

        let mut p = pool();
        p.targets.clear();
        assert_eq!(state_with_pool("x", p).validate().unwrap_err(), StateError::NoTargets("x".into()));
    }

    #[test]
    fn dedicated_listen_ports_must_be_nonzero_and_unique() {
        let mut zero = pool();
        zero.listen_port = Some(0);
        assert_eq!(state_with_pool("zero", zero).validate().unwrap_err(), StateError::ZeroListenPort("zero".into()));

        let mut state = state_with_pool("first", pool());
        state.pools.get_mut("first").unwrap().listen_port = Some(5544);
        let mut second = pool();
        second.listen_port = Some(5544);
        state.pools.insert("second".into(), second);
        assert_eq!(
            state.validate().unwrap_err(),
            StateError::DuplicateListenPort { first: "first".into(), second: "second".into(), port: 5544 }
        );
    }

    #[test]
    fn user_grants_must_point_at_real_pools() {
        let mut state = state_with_pool("app_main", pool());
        state.users.insert("ghost".into(), UserConfig::new(vec!["missing".into()]));
        assert_eq!(
            state.validate().unwrap_err(),
            StateError::UnknownPoolGrant { user: "ghost".into(), pool: "missing".into() }
        );
    }

    #[test]
    fn a_user_without_grants_is_a_configuration_error_not_a_silent_noop() {
        let mut state = state_with_pool("app_main", pool());
        state.users.insert("ghost".into(), UserConfig::new(vec![]));
        assert_eq!(state.validate().unwrap_err(), StateError::NoGrants("ghost".into()));
    }

    #[test]
    fn names_are_restricted() {
        let mut state = State::default();
        state.pools.insert("bad name!".into(), pool());
        assert!(matches!(state.validate().unwrap_err(), StateError::BadPoolName(_)));

        assert!(is_valid_name("app_main"));
        assert!(is_valid_name("app-main-2"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("_leading"));
        assert!(!is_valid_name("has space"));
        assert!(!is_valid_name(&"x".repeat(64)));
    }

    #[test]
    fn future_state_version_is_refused_rather_than_misread() {
        let state = State { version: STATE_VERSION + 1, ..Default::default() };
        assert_eq!(
            state.validate().unwrap_err(),
            StateError::UnsupportedVersion { found: STATE_VERSION + 1, expected: STATE_VERSION }
        );
    }

    #[test]
    fn fan_in_is_only_reported_where_it_is_real() {
        let mut p = pool();
        p.limits.max_client_connections = 100;
        p.limits.max_size = 3;

        p.mode = PoolMode::Session;
        assert_eq!(p.fan_in(), None, "session mode cannot multiplex, so no ratio is honest");

        p.mode = PoolMode::Transaction;
        let fan_in = p.fan_in().unwrap();
        assert!((fan_in - 33.333).abs() < 0.01, "got {fan_in}");
    }

    #[test]
    fn session_mode_with_a_small_max_size_produces_a_warning() {
        let mut p = pool();
        p.mode = PoolMode::Session;
        p.limits.max_client_connections = 100;
        p.limits.max_size = 3;

        let warnings = state_with_pool("app_main", p).warnings();
        assert!(
            warnings.iter().any(|w| matches!(
                w,
                Warning::SessionModeQueues { pool, max_client_connections: 100, max_size: 3 } if pool == "app_main"
            )),
            "operators must be told that 97 clients will queue: {warnings:?}"
        );
    }

    #[test]
    fn transaction_mode_with_the_same_numbers_does_not_warn() {
        let mut p = pool();
        p.mode = PoolMode::Transaction;
        p.limits.max_client_connections = 100;
        p.limits.max_size = 3;

        let warnings = state_with_pool("app_main", p).warnings();
        assert!(!warnings.iter().any(|w| matches!(w, Warning::SessionModeQueues { .. })));
    }

    #[test]
    fn pool_without_users_is_flagged() {
        let mut state = State::default();
        state.pools.insert("orphan".into(), pool());
        assert!(state.warnings().iter().any(|w| matches!(w, Warning::PoolWithoutUsers { pool } if pool == "orphan")));
    }

    #[test]
    fn disabled_pools_and_users_drop_out_of_routing() {
        let mut state = state_with_pool("app_main", pool());
        assert_eq!(state.pools_for_user("svc"), vec!["app_main"]);

        state.pools.get_mut("app_main").unwrap().disabled = true;
        assert!(state.pools_for_user("svc").is_empty(), "disabled pool must not be routable");

        state.pools.get_mut("app_main").unwrap().disabled = false;
        state.users.get_mut("svc").unwrap().disabled = true;
        assert!(state.pools_for_user("svc").is_empty(), "disabled user must not connect");

        assert!(state.pools_for_user("nobody").is_empty());
    }

    #[test]
    fn primary_and_replica_selection() {
        let mut p = pool();
        p.targets = vec![
            Target { host: "r1".into(), port: 5432, role: TargetRole::Replica, weight: 1 },
            Target { host: "p1".into(), port: 5432, role: TargetRole::Primary, weight: 1 },
        ];
        assert_eq!(p.primary().unwrap().host, "p1", "primary is picked by role, not order");
        assert_eq!(p.replicas().count(), 1);

        // With no explicit primary we fall back to the first target rather than
        // refusing to serve.
        p.targets = vec![Target { host: "only".into(), port: 5432, role: TargetRole::Replica, weight: 1 }];
        assert_eq!(p.primary().unwrap().host, "only");
    }

    #[test]
    fn serde_roundtrip_keeps_durations_human_readable() {
        let state = state_with_pool("app_main", pool());
        let json = serde_json::to_string_pretty(&state).unwrap();
        assert!(json.contains("\"queue_timeout\": \"5s\""), "durations must stay readable:\n{json}");

        let restored: State = serde_json::from_str(&json).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.pools["app_main"], state.pools["app_main"]);
    }
}
