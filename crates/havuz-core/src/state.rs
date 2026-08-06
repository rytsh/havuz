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
    #[error(
        "pools '{first}' ({first_family}) and '{second}' ({second_family}) share listen port {port}, \
         but a listener can only speak one protocol"
    )]
    MixedFamiliesOnPort { first: String, first_family: String, second: String, second_family: String, port: u16 },
    #[error("pool '{pool}': alias '{alias}' is not a valid name; use letters, digits, '_' and '-'")]
    BadAliasName { pool: String, alias: String },
    #[error("pool '{pool}' lists its own name '{alias}' as an alias; a pool is always reachable by its name")]
    AliasIsOwnPool { pool: String, alias: String },
    #[error(
        "pools '{first}' and '{second}' share listen port {port} and both answer to '{name}'; \
         a client sends one database name and must reach one pool"
    )]
    RoutableNameCollides { name: String, port: u16, first: String, second: String },
    #[error(
        "pool '{0}' authenticates per user, so min_idle must be 0: havuz cannot warm a connection \
         for a user whose password it does not hold"
    )]
    PerUserWarmup(String),
    #[error(
        "pool '{0}' authenticates per user and enables read/write split, which needs a service \
         account to measure replica lag with; set a backend user and password"
    )]
    PerUserSplitWithoutProbe(String),
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

        // Routing first, then the pools themselves. A port shared by two
        // families is a mistake about the port, and saying so is more useful
        // than the driver complaint one of those pools would also produce.
        self.validate_listeners()?;

        for (name, pool) in &self.pools {
            if !is_valid_name(name) {
                return Err(StateError::BadPoolName(name.clone()));
            }
            pool.validate(name)?;
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
    /// Every port is real and every port speaks one protocol.
    ///
    /// Pools sharing a port is the normal case — that is how a client picks
    /// between them by database name — but they must all belong to one family,
    /// because the listener has to decide which handshake to run before it has
    /// read a single byte.
    fn validate_listeners(&self) -> Result<(), StateError> {
        let mut ports: BTreeMap<u16, (&String, &String)> = BTreeMap::new();
        // Every string a client may put in its database field, per port. Pool
        // names go in first and aliases second, so a pool is never made
        // unreachable by somebody else's alias — the alias is what gets
        // refused, and the operator is told which pool it collided with.
        let mut routable: BTreeMap<(u16, &str), &String> = BTreeMap::new();

        for (name, pool) in &self.pools {
            if pool.listen_port == 0 {
                return Err(StateError::ZeroListenPort(name.clone()));
            }
            let (first, first_family) = *ports.entry(pool.listen_port).or_insert((name, &pool.family));
            if first_family != &pool.family {
                return Err(StateError::MixedFamiliesOnPort {
                    first: first.clone(),
                    first_family: first_family.clone(),
                    second: name.clone(),
                    second_family: pool.family.clone(),
                    port: pool.listen_port,
                });
            }
            // Pool names cannot collide with each other: they are map keys.
            routable.insert((pool.listen_port, name.as_str()), name);
        }

        for (name, pool) in &self.pools {
            for alias in &pool.aliases {
                if !is_valid_name(alias) {
                    return Err(StateError::BadAliasName { pool: name.clone(), alias: alias.clone() });
                }
                if alias == name {
                    return Err(StateError::AliasIsOwnPool { pool: name.clone(), alias: alias.clone() });
                }
                if let Some(other) = routable.insert((pool.listen_port, alias.as_str()), name) {
                    return Err(StateError::RoutableNameCollides {
                        name: alias.clone(),
                        port: pool.listen_port,
                        first: other.clone(),
                        second: name.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// The listeners this configuration asks for, keyed by port.
    ///
    /// This is the whole routing table. There is no shared listener and no
    /// process-wide client port: a pool declares the port clients reach it on,
    /// and pools that declare the same port share one socket.
    ///
    /// Disabled pools are excluded, so disabling the last pool on a port closes
    /// it rather than leaving a socket that accepts and then refuses.
    pub fn listeners(&self) -> BTreeMap<u16, Listener> {
        let mut out: BTreeMap<u16, Listener> = BTreeMap::new();
        for (name, pool) in self.pools.iter().filter(|(_, pool)| !pool.disabled) {
            let listener = out.entry(pool.listen_port).or_insert_with(|| Listener {
                port: pool.listen_port,
                family: pool.family.clone(),
                pools: Vec::new(),
                aliases: Vec::new(),
            });
            listener.pools.push(name.clone());
            listener.aliases.extend(pool.aliases.iter().map(|alias| (alias.clone(), name.clone())));
        }
        // `pools` is already sorted because it came from a `BTreeMap`; the
        // aliases were gathered per pool and have to be sorted here, so that
        // two runs over the same configuration produce the same listener and
        // the reconciler does not see a change that is not one.
        for listener in out.values_mut() {
            listener.aliases.sort();
        }
        out
    }

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
            // A passthrough pool with no configured users is not a mistake, it
            // is the mode working as asked. Warning about it would train
            // operators to ignore the banner that matters.
            if !pool.backend_auth.is_passthrough() && !self.users.values().any(|u| u.pools.iter().any(|p| p == name)) {
                out.push(Warning::PoolWithoutUsers { pool: name.clone() });
            }
            if pool.routing.read_write_split && pool.replicas().count() == 0 {
                out.push(Warning::SplitWithoutReplicas { pool: name.clone() });
            }
            if pool.routing.read_write_split && pool.routing.sticky_after_write.is_zero() {
                out.push(Warning::NoStickyWindow { pool: name.clone() });
            }
            // Not a misconfiguration — it was asked for explicitly — but it is
            // the one setting in havuz that can hand a working database
            // credential to whoever is on the wire, so it stays visible for as
            // long as it is on.
            if pool.backend_auth.is_per_user() && pool.allow_password_without_tls {
                out.push(Warning::PasswordWithoutTls { pool: name.clone() });
            }
            // Also asked for explicitly, and also permanent. havuz cannot
            // refuse a password it has never seen before, so every first
            // attempt on this pool becomes a database login attempt. That is
            // the deal the mode offers and it should stay on the screen.
            if pool.backend_auth.is_passthrough() {
                out.push(Warning::PassthroughPool { pool: name.clone() });
            }
            // Per-user auth without a service account removes the fallback the
            // migration path relies on. The users left on it are refused when
            // they connect, which is far too late to find out.
            if pool.backend_auth.is_per_user() && pool.backend_user.is_empty() {
                let mut stranded: Vec<String> = self
                    .users
                    .iter()
                    .filter(|(_, user)| !user.own_backend_role && user.pools.iter().any(|p| p == name))
                    .map(|(user, _)| user.clone())
                    .collect();
                stranded.sort();
                if !stranded.is_empty() {
                    out.push(Warning::UsersWithoutBackendRole { pool: name.clone(), users: stranded });
                }
            }
            // An idle-in-transaction limit is about reclaiming a pool slot, and
            // in session mode there is no slot to reclaim: the client holds its
            // backend until it disconnects either way. Ending it early would
            // only shorten the lock wait, which is not what the setting says it
            // does, so it does nothing here and that has to be visible.
            if !pool.mode.multiplexes() && !pool.limits.idle_in_transaction_timeout.is_zero() {
                out.push(Warning::IdleTimeoutInSessionMode { pool: name.clone() });
            }
            // Read-only is enforced by refusing the statements that would turn
            // `default_transaction_read_only` back off, which means reading
            // every statement. Session mode is a byte shovel and does not, so
            // the guarantee silently weakens to "on by default".
            //
            // A read-only *pool* in session mode is the worse of the two: the
            // operator marked the route, not a person, so the expectation is
            // that nothing coming through the port can write. Say so without
            // naming users, because the flag applies to all of them and to
            // every user added later.
            if !pool.mode.multiplexes() {
                if pool.read_only {
                    out.push(Warning::ReadOnlyNotEnforced { pool: name.clone(), pool_wide: true, users: Vec::new() });
                } else {
                    let mut readers: Vec<String> = self
                        .users
                        .iter()
                        .filter(|(_, user)| user.read_only && user.pools.iter().any(|p| p == name))
                        .map(|(user, _)| user.clone())
                        .collect();
                    readers.sort();
                    if !readers.is_empty() {
                        out.push(Warning::ReadOnlyNotEnforced { pool: name.clone(), pool_wide: false, users: readers });
                    }
                }
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
    /// An idle-in-transaction limit is set on a session-mode pool, where it is
    /// not enforced. The client owns its backend for the whole session there,
    /// so ending it early would free nothing that disconnecting would not.
    IdleTimeoutInSessionMode {
        pool: String,
    },
    /// A read-only guarantee is claimed on a session-mode pool, where it
    /// cannot be held: havuz inspects no statements there, so the client can
    /// simply turn the setting off again.
    ///
    /// `pool_wide` distinguishes the two sources. Set, the pool itself is
    /// marked read-only and `users` is empty because every client is affected;
    /// clear, `users` are the read-only users that can reach a writable pool.
    ReadOnlyNotEnforced {
        pool: String,
        pool_wide: bool,
        users: Vec<String>,
    },
    /// Read/write split with no sticky window: a read issued straight after a
    /// write can be served stale.
    NoStickyWindow {
        pool: String,
    },
    /// A per-user pool with no service account still has users who have not
    /// been moved onto a database role of their own. There is nothing left for
    /// them to fall back to, so they are locked out at connect time.
    UsersWithoutBackendRole {
        pool: String,
        users: Vec<String>,
    },
    /// A per-user pool has been allowed to ask for passwords over an
    /// unencrypted socket. What travels there is a database credential, so
    /// anyone on the path can reach the database without going through havuz.
    PasswordWithoutTls {
        pool: String,
    },
    /// A pool admits clients havuz has no user record for, by trying their
    /// credentials against the database. Nothing local can refuse a password
    /// that has never been seen, so a first attempt from anyone who can reach
    /// the port reaches PostgreSQL's authentication.
    PassthroughPool {
        pool: String,
    },
}

/// One client-facing socket and the pools reachable through it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listener {
    pub port: u16,
    /// Every pool on a listener speaks the same protocol; [`State::validate`]
    /// refuses anything else.
    pub family: String,
    /// Sorted, because `pools` is a `BTreeMap`.
    pub pools: Vec<String>,
    /// Extra names clients may use here, as `(alias, pool)`, sorted by alias.
    ///
    /// Flattened out of the pools rather than left on them, because this is the
    /// listener's routing table and nothing above it should have to walk the
    /// pool list to rebuild one.
    pub aliases: Vec<(String, String)>,
}

impl Listener {
    /// The pool a client reaches when it names none.
    ///
    /// `Some` only when this listener has exactly one pool: with several, the
    /// client has to say which, and guessing would silently connect it to the
    /// wrong database.
    pub fn sole_pool(&self) -> Option<&str> {
        match self.pools.as_slice() {
            [only] => Some(only),
            _ => None,
        }
    }
}

/// Which identity havuz opens backend connections as.
///
/// The default is what every pooler does, and it is what makes a backend
/// connection reusable by any client: one service account, shared. The
/// alternative buys things no amount of pooler cleverness can otherwise
/// provide — `pg_stat_activity.usename`, row-level security, real `GRANT`
/// enforcement, database-side audit — and costs fan-in, which becomes per-user
/// rather than per-pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendAuth {
    /// One service account for the whole pool.
    #[default]
    Shared,
    /// Each client's own database role, using the password it supplied.
    ///
    /// havuz never stores that password: it asks the client for it, checks it
    /// against the stored verifier, and forwards it to the backend. The
    /// consequences are real and are enforced at validation time — the client
    /// leg must be encrypted, and connections cannot be opened for a user who
    /// is not currently connected.
    PerUser,
    /// The same, with havuz's own user list out of the way.
    ///
    /// [`PerUser`](Self::PerUser) still requires a havuz user: the password is
    /// checked against a stored verifier before it is forwarded, and the grant
    /// list, `disabled` and `read_only` all hang off that record. Passthrough
    /// keeps every one of those rules for users that *are* configured, and adds
    /// one case they do not cover — a client havuz has never heard of. Its
    /// password can only be checked by the database, so havuz asks the database:
    /// it opens one connection with those credentials before admitting the
    /// client, and remembers the answer in memory for as long as that client has
    /// connections.
    ///
    /// The point is that an operator no longer has to store a backend
    /// credential anywhere. The cost is that the pool will attempt a database
    /// login on behalf of anyone who can reach the port, which is why
    /// [`Warning::PassthroughPool`] is raised for as long as it is on.
    Passthrough,
}

impl BackendAuth {
    /// Backend connections are opened as the connecting client rather than as
    /// the pool's service account.
    ///
    /// True for both client-authenticated modes. Everything that follows from
    /// opening connections as the client — a connection set per identity, no
    /// warm connections, no honest single `max_size` ceiling, a cleartext ask
    /// that needs TLS — follows for passthrough exactly as it does for
    /// [`BackendAuth::PerUser`], so those rules are written against this and
    /// not against the variant.
    pub fn is_per_user(self) -> bool {
        matches!(self, BackendAuth::PerUser | BackendAuth::Passthrough)
    }

    /// Clients with no havuz user record may still be admitted, by asking the
    /// database whether their password works.
    pub fn is_passthrough(self) -> bool {
        matches!(self, BackendAuth::Passthrough)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BackendAuth::Shared => "shared",
            BackendAuth::PerUser => "per_user",
            BackendAuth::Passthrough => "passthrough",
        }
    }
}

/// How much of a pool's traffic is written to the query trace store.
///
/// Tracing is the feature that makes a pooler explicable — which statement
/// waited, on which backend, and what it returned — and it is also the feature
/// that turns the pooler into a copy of your data. Those are not the same
/// decision, so this is not a boolean: keeping *what ran* is cheap and rarely
/// sensitive, while keeping *what came back* is a sample of production rows
/// sitting in a second file with a second lifetime.
///
/// Picked per pool, because the answer differs per pool: a queue table and a
/// table of patient records do not deserve the same treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceLevel {
    /// Nothing is recorded. The pool disappears from the query trace screen
    /// entirely — no history, and no entry under "running now" either.
    Off,
    /// Statement text, timings, target, backend PID and outcome. Enough to
    /// answer why something was slow and where it ran; no row values, so a
    /// trace cannot leak what the query returned.
    #[default]
    Statements,
    /// Everything [`TraceLevel::Statements`] keeps, plus a bounded sample of
    /// the rows the backend sent back. The sample is capped, but it is real
    /// production data and outlives the connection that produced it.
    Full,
}

impl TraceLevel {
    pub fn is_off(self) -> bool {
        matches!(self, TraceLevel::Off)
    }

    /// Whether result rows are kept alongside the statement.
    pub fn captures_results(self) -> bool {
        matches!(self, TraceLevel::Full)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TraceLevel::Off => "off",
            TraceLevel::Statements => "statements",
            TraceLevel::Full => "full",
        }
    }
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
    ///
    /// Required under [`BackendAuth::Shared`], which has no other way in.
    /// Optional under [`BackendAuth::PerUser`], where it stops being the account
    /// clients run as and becomes the account health probes and "Test
    /// Connection" use — those have no client, so they have no credential to
    /// borrow — plus the fallback for users who have no database role of their
    /// own. Empty means there is no service account: only users connecting as
    /// themselves get in, and probing is unavailable, which is why
    /// [`RoutingConfig::read_write_split`] then has to be off.
    pub backend_user: String,
    /// Database opened on the backend.
    pub database: String,
    /// Client-facing port. Required: a pool nobody can reach is not a pool.
    ///
    /// Pools may share a port. With one pool on a port the client's database
    /// field is ignored; with several, it names which one — by this pool's name
    /// or by one of its [`aliases`](Self::aliases). See [`State::listeners`].
    pub listen_port: u16,
    /// Extra names clients may put in their database field to reach this pool.
    ///
    /// The startup packet carries exactly one routing field, so a port shared
    /// by several pools makes the client name one of them. Without aliases that
    /// name has to be the pool's own, which drags two unrelated decisions
    /// together: a pool ends up having to be called after its database, and two
    /// pools over *one* database — a read-write one and a reporting one, say —
    /// cannot both be reachable under the database's real name.
    ///
    /// An alias separates them. `orders_rw` and `orders_ro` can share a port
    /// and a database while clients keep writing `dbname=orders` and
    /// `dbname=orders_bi`.
    ///
    /// Aliases and pool names share one namespace per port, because a client
    /// cannot tell them apart: it sends one string and expects one pool. A pool
    /// alone on its port has no use for them — its clients' database field is
    /// ignored entirely — but they are still worth declaring before a second
    /// pool arrives on that port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub limits: PoolLimits,
    /// Family-specific settings validated against the registry's config fields.
    #[serde(default)]
    pub settings: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub routing: RoutingConfig,
    /// Whose credentials backend connections are opened with.
    #[serde(default)]
    pub backend_auth: BackendAuth,
    /// Ask clients for their password even on an unencrypted socket.
    ///
    /// Only meaningful under [`BackendAuth::PerUser`], which is the one mode
    /// that has to hold the plaintext. Off by default, and the default is the
    /// one to keep: the password such a pool asks for is not a pooler password,
    /// it is a working *database* credential. Handing it to anyone on the path
    /// does not merely let them impersonate a client against havuz, it lets
    /// them connect to the database directly and leave havuz out of it.
    ///
    /// It exists because "TLS everywhere" is not always the operator's to
    /// decide — a unix-socket-like private link, a service mesh that already
    /// encrypts, a legacy client that cannot speak TLS at all. Turning it on
    /// raises [`Warning::PasswordWithoutTls`] and logs on every connection that
    /// actually takes the unencrypted path.
    #[serde(default)]
    pub allow_password_without_tls: bool,
    /// Every session on this pool is opened read-only, whoever connects.
    ///
    /// [`UserConfig::read_only`] says a *person* may not write; this says a
    /// *route* may not be written through. They are different questions and the
    /// second one is the one an operator usually has: a reporting pool, a BI
    /// tool's port, a replica-backed alias next to the read-write one. Answering
    /// it per user means remembering the flag on every user ever granted the
    /// pool, and the one that gets forgotten is silently allowed to write.
    ///
    /// Enforced exactly as the user flag is — `default_transaction_read_only`
    /// set on the backend, with the statements that would turn it off refused —
    /// so it is PostgreSQL that rejects the write, not a classifier guessing at
    /// one. The two combine by OR: a read-only user stays read-only on a
    /// writable pool, and a writable user becomes read-only here.
    ///
    /// Carries the same caveat as the user flag, and [`Warning::ReadOnlyNotEnforced`]
    /// says so: in session mode havuz inspects no statements, so a client can
    /// set the parameter back itself.
    #[serde(default)]
    pub read_only: bool,
    /// How much of this pool's traffic reaches the query trace store.
    #[serde(default)]
    pub trace: TraceLevel,
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

        if self.backend_auth.is_per_user() {
            // A warm connection has to be opened before anyone asks for one,
            // and under per-user auth the credential arrives with the client.
            if self.limits.min_idle > 0 {
                return Err(StateError::PerUserWarmup(name.into()));
            }
            // Health probing runs on a timer with no client attached, so it
            // has nothing to authenticate as unless a service account exists.
            if self.routing.read_write_split && self.backend_user.is_empty() {
                return Err(StateError::PerUserSplitWithoutProbe(name.into()));
            }
        }
        Ok(())
    }

    /// Backend connections this pool may open in total.
    ///
    /// Under per-user auth `max_size` is a *per-user* budget, so the ceiling
    /// scales with however many distinct users are connected at once. There is
    /// no honest single number, which is exactly what an operator needs to be
    /// told rather than shown a comforting one.
    pub fn backend_ceiling(&self) -> Option<u32> {
        (!self.backend_auth.is_per_user()).then_some(self.limits.max_size)
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
    /// How long a client may sit inside an open transaction without sending
    /// anything before its session is ended. Zero, the default, means no limit.
    ///
    /// Transaction mode's whole premise is that an idle client holds nothing.
    /// A client that runs `BEGIN` and then stops talking — a debugger on a
    /// breakpoint, a request that threw between the transaction and the commit
    /// — breaks that premise: it holds a backend, and its locks, until it
    /// disconnects. One such client can take a pool slot for hours.
    ///
    /// Off by default because ending someone's transaction is destructive and
    /// the operator is the one who knows whether their longest legitimate
    /// think-time is a second or a minute. Set it comfortably above that.
    ///
    /// Only enforced where it means something. In session mode the client owns
    /// its backend for the whole session anyway, so ending it early would free
    /// nothing that disconnecting would not — see
    /// [`Warning::IdleTimeoutInSessionMode`].
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub idle_in_transaction_timeout: Duration,
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
            idle_in_transaction_timeout: Duration::ZERO,
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
    /// Connect to the database as this user rather than as the pool's service
    /// account.
    ///
    /// Only meaningful on a pool with `backend_auth = per_user`, and off by
    /// default so that flipping a pool into that mode changes nothing until
    /// each user is moved deliberately. That is the whole migration path: one
    /// user at a time, with the rest still pooling normally behind the service
    /// account.
    ///
    /// A user with this set must exist as a database role with the same name
    /// and the same password it uses to reach havuz.
    #[serde(default)]
    pub own_backend_role: bool,
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
        Self {
            pools,
            max_client_connections: 0,
            own_backend_role: false,
            read_only: false,
            disabled: false,
            description: None,
        }
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
            listen_port: 6432,
            aliases: Vec::new(),
            limits: PoolLimits::default(),
            settings: Default::default(),
            routing: Default::default(),
            backend_auth: Default::default(),
            allow_password_without_tls: false,
            read_only: false,
            trace: Default::default(),
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
    fn a_per_user_pool_cannot_keep_connections_warm() {
        // There is no credential to open one with until a client shows up.
        let mut p = pool();
        p.backend_auth = BackendAuth::PerUser;
        p.limits.min_idle = 2;
        assert_eq!(
            state_with_pool("app_main", p).validate().unwrap_err(),
            StateError::PerUserWarmup("app_main".into())
        );
    }

    #[test]
    fn a_per_user_pool_may_split_reads_only_if_it_can_probe() {
        let mut p = pool();
        p.backend_auth = BackendAuth::PerUser;
        p.routing.read_write_split = true;
        p.backend_user = String::new();
        assert_eq!(
            state_with_pool("app_main", p.clone()).validate().unwrap_err(),
            StateError::PerUserSplitWithoutProbe("app_main".into())
        );

        p.backend_user = "havuz_probe".into();
        state_with_pool("app_main", p).validate().expect("a service account makes probing possible again");
    }

    #[test]
    fn per_user_pools_have_no_single_backend_ceiling() {
        // max_size becomes a per-user budget, so any total we printed would be
        // a guess about how many users connect at once.
        let mut p = pool();
        assert_eq!(p.backend_ceiling(), Some(p.limits.max_size));
        p.backend_auth = BackendAuth::PerUser;
        assert_eq!(p.backend_ceiling(), None);
    }

    #[test]
    fn passthrough_carries_every_rule_per_user_auth_carries() {
        // It is per-user authentication with the user list stepped over for
        // names it has never seen, not a separate kind of pool. Anything that
        // follows from opening backends as the client has to follow here too,
        // or the second mode quietly reintroduces what the first ruled out.
        let mut p = pool();
        p.backend_auth = BackendAuth::Passthrough;
        assert!(p.backend_auth.is_per_user(), "the rules are written against this, not against the variant");
        assert_eq!(p.backend_ceiling(), None);

        let mut warm = p.clone();
        warm.limits.min_idle = 2;
        assert_eq!(
            state_with_pool("app_main", warm).validate().unwrap_err(),
            StateError::PerUserWarmup("app_main".into())
        );

        let mut split = p.clone();
        split.routing.read_write_split = true;
        split.backend_user = String::new();
        assert_eq!(
            state_with_pool("app_main", split).validate().unwrap_err(),
            StateError::PerUserSplitWithoutProbe("app_main".into())
        );
    }

    #[test]
    fn only_passthrough_admits_names_that_are_not_configured() {
        // The distinction the resolver hangs off. Shared and per-user pools
        // both refuse an unknown name outright.
        assert!(!BackendAuth::Shared.is_passthrough());
        assert!(!BackendAuth::PerUser.is_passthrough());
        assert!(BackendAuth::Passthrough.is_passthrough());
    }

    #[test]
    fn a_passthrough_pool_says_so_for_as_long_as_it_is_on() {
        // Not a misconfiguration and not dismissible: this is the one pool
        // where a credential havuz has never seen becomes a database login.
        let mut p = pool();
        p.backend_auth = BackendAuth::Passthrough;
        let warnings = state_with_pool("app_main", p).warnings();
        assert!(
            warnings.contains(&Warning::PassthroughPool { pool: "app_main".into() }),
            "the operator has to be able to see this from the dashboard: {warnings:?}"
        );
    }

    #[test]
    fn a_passthrough_pool_with_no_configured_users_is_not_a_complaint() {
        // Having no users is the mode working as asked. Warning about it
        // teaches operators to ignore the banner that does matter.
        let ungranted = |auth| {
            let mut p = pool();
            p.backend_auth = auth;
            let mut state = State::default();
            state.pools.insert("app_main".into(), p);
            state.warnings()
        };

        let warnings = ungranted(BackendAuth::Passthrough);
        assert!(!warnings.contains(&Warning::PoolWithoutUsers { pool: "app_main".into() }), "{warnings:?}");

        let warnings = ungranted(BackendAuth::Shared);
        assert!(
            warnings.contains(&Warning::PoolWithoutUsers { pool: "app_main".into() }),
            "a shared pool with no users really is unreachable: {warnings:?}"
        );
    }

    #[test]
    fn backend_auth_survives_a_round_trip_under_its_wire_name() {
        // The name in the state file and the name in the API payload are the
        // same string, and both are what an operator types.
        for (mode, wire) in [
            (BackendAuth::Shared, "shared"),
            (BackendAuth::PerUser, "per_user"),
            (BackendAuth::Passthrough, "passthrough"),
        ] {
            assert_eq!(mode.as_str(), wire);
            assert_eq!(serde_json::to_value(mode).unwrap(), serde_json::json!(wire));
            assert_eq!(serde_json::from_value::<BackendAuth>(serde_json::json!(wire)).unwrap(), mode);
        }
    }

    #[test]
    fn backend_auth_defaults_to_shared_so_existing_state_files_load_unchanged() {
        let json = serde_json::to_value(pool()).unwrap();
        let mut without = json.as_object().unwrap().clone();
        without.remove("backend_auth");
        let parsed: PoolConfig = serde_json::from_value(serde_json::Value::Object(without)).unwrap();
        assert_eq!(parsed.backend_auth, BackendAuth::Shared);
    }

    #[test]
    fn a_pool_written_before_the_trace_setting_existed_records_statements_only() {
        // Upgrading tightens rather than loosens: a pool that has never been
        // asked stops keeping result rows, and keeps everything an operator
        // actually diagnoses with. The other direction — silently continuing to
        // sample production data because the file predates the question — is
        // not a default anyone consented to.
        let json = serde_json::to_value(pool()).unwrap();
        let mut without = json.as_object().unwrap().clone();
        without.remove("trace");
        let parsed: PoolConfig = serde_json::from_value(serde_json::Value::Object(without)).unwrap();
        assert_eq!(parsed.trace, TraceLevel::Statements);
        assert!(!parsed.trace.captures_results());
        assert!(!parsed.trace.is_off());
    }

    #[test]
    fn trace_levels_serialise_as_the_names_the_api_uses() {
        for (level, name) in
            [(TraceLevel::Off, "off"), (TraceLevel::Statements, "statements"), (TraceLevel::Full, "full")]
        {
            assert_eq!(serde_json::to_value(level).unwrap(), serde_json::json!(name));
            assert_eq!(level.as_str(), name);
        }
    }

    #[test]
    fn a_listen_port_of_zero_is_rejected() {
        let mut zero = pool();
        zero.listen_port = 0;
        assert_eq!(state_with_pool("zero", zero).validate().unwrap_err(), StateError::ZeroListenPort("zero".into()));
    }

    #[test]
    fn pools_may_share_a_port_and_are_then_selected_by_name() {
        let mut state = state_with_pool("orders", pool());
        state.pools.insert("reports".into(), pool());
        state.validate().expect("sharing a port is the normal case, not an error");

        let listeners = state.listeners();
        assert_eq!(listeners.len(), 1);
        let listener = &listeners[&6432];
        assert_eq!(listener.pools, ["orders", "reports"]);
        assert_eq!(listener.sole_pool(), None, "with two pools the client has to say which");
    }

    #[test]
    fn a_port_with_one_pool_needs_no_database_name() {
        let state = state_with_pool("orders", pool());
        assert_eq!(state.listeners()[&6432].sole_pool(), Some("orders"));
    }

    #[test]
    fn a_disabled_pool_does_not_hold_its_port_open() {
        let mut state = state_with_pool("orders", pool());
        state.pools.get_mut("orders").unwrap().disabled = true;
        assert!(state.listeners().is_empty(), "the socket must close, not accept and then refuse");
    }

    #[test]
    fn an_alias_lets_two_pools_share_one_database_on_one_port() {
        // The reason aliases exist. Without them `orders` is a name only one of
        // these can have, so the other is unreachable under the name its
        // clients already write.
        let mut rw = pool();
        rw.aliases = vec!["orders".into()];
        let mut state = state_with_pool("orders_rw", rw);

        let mut ro = pool();
        ro.aliases = vec!["orders_bi".into()];
        state.pools.insert("orders_ro".into(), ro);
        state.validate().expect("distinct aliases on one port are fine");

        let listener = &state.listeners()[&6432];
        assert_eq!(listener.pools, ["orders_ro", "orders_rw"]);
        assert_eq!(
            listener.aliases,
            [("orders".to_string(), "orders_rw".to_string()), ("orders_bi".to_string(), "orders_ro".to_string())],
            "sorted by alias, so the same configuration always produces the same listener"
        );
    }

    #[test]
    fn two_pools_on_a_port_cannot_answer_to_the_same_name() {
        let mut first = pool();
        first.aliases = vec!["orders".into()];
        let mut state = state_with_pool("orders_rw", first);

        let mut second = pool();
        second.aliases = vec!["orders".into()];
        state.pools.insert("orders_ro".into(), second);

        assert!(
            matches!(state.validate().unwrap_err(), StateError::RoutableNameCollides { ref name, port: 6432, .. } if name == "orders"),
            "a client sends one name and must reach one pool"
        );
    }

    #[test]
    fn an_alias_cannot_shadow_another_pool_on_the_same_port() {
        // Accepting this would make `reports` unreachable while the dashboard
        // went on showing it, which is the worst of both outcomes.
        let mut state = state_with_pool("reports", pool());
        let mut squatter = pool();
        squatter.aliases = vec!["reports".into()];
        state.pools.insert("orders".into(), squatter);

        assert!(
            matches!(state.validate().unwrap_err(), StateError::RoutableNameCollides { ref name, .. } if name == "reports")
        );
    }

    #[test]
    fn the_same_alias_on_two_different_ports_is_fine() {
        // Routing is per listener, so there is nothing to be ambiguous about.
        let mut first = pool();
        first.aliases = vec!["orders".into()];
        let mut state = state_with_pool("orders_rw", first);

        let mut second = pool();
        second.listen_port = 6433;
        second.aliases = vec!["orders".into()];
        state.pools.insert("orders_staging".into(), second);

        state.validate().expect("two ports, two routing tables");
        assert_eq!(state.listeners().len(), 2);
    }

    #[test]
    fn a_pool_cannot_alias_its_own_name() {
        // Harmless to honour, but it is almost always a half-finished edit, and
        // silently accepting it hides the typo it usually is.
        let mut redundant = pool();
        redundant.aliases = vec!["orders".into()];
        assert_eq!(
            state_with_pool("orders", redundant).validate().unwrap_err(),
            StateError::AliasIsOwnPool { pool: "orders".into(), alias: "orders".into() }
        );
    }

    #[test]
    fn an_alias_obeys_the_same_naming_rules_as_a_pool() {
        let mut bad = pool();
        bad.aliases = vec!["orders prod".into()];
        assert_eq!(
            state_with_pool("orders_rw", bad).validate().unwrap_err(),
            StateError::BadAliasName { pool: "orders_rw".into(), alias: "orders prod".into() }
        );
    }

    #[test]
    fn a_pool_without_aliases_keeps_them_out_of_the_state_document() {
        // The field is additive: a configuration that never mentions aliases
        // must round-trip byte for byte through the state file.
        let state = state_with_pool("orders", pool());
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("aliases"), "an unused field must not appear in state.json");

        let reloaded: State = serde_json::from_str(&json).unwrap();
        assert!(reloaded.pools["orders"].aliases.is_empty());
        reloaded.validate().unwrap();
    }

    #[test]
    fn two_families_cannot_share_one_socket() {
        // Nothing could decide which handshake to run before reading a byte.
        let mut state = state_with_pool("orders", pool());
        let mut other = pool();
        other.family = "mysql".into();
        state.pools.insert("analytics".into(), other);
        assert!(matches!(state.validate().unwrap_err(), StateError::MixedFamiliesOnPort { port: 6432, .. }));
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
    fn a_per_user_pool_without_a_service_account_flags_the_users_it_locks_out() {
        // The fallback these users rely on does not exist, and they find out
        // when they connect unless something says so first.
        let mut p = pool();
        p.backend_auth = BackendAuth::PerUser;
        p.backend_user = String::new();
        let mut state = state_with_pool("app_main", p);

        let stranded = state.warnings().into_iter().find_map(|w| match w {
            Warning::UsersWithoutBackendRole { pool, users } if pool == "app_main" => Some(users),
            _ => None,
        });
        assert_eq!(stranded, Some(vec!["svc".to_string()]));

        state.users.get_mut("svc").unwrap().own_backend_role = true;
        assert!(
            !state.warnings().iter().any(|w| matches!(w, Warning::UsersWithoutBackendRole { .. })),
            "a user on its own database role needs no service account"
        );
    }

    #[test]
    fn a_per_user_pool_with_a_service_account_strands_nobody() {
        let mut p = pool();
        p.backend_auth = BackendAuth::PerUser;
        let state = state_with_pool("app_main", p);
        assert!(!state.warnings().iter().any(|w| matches!(w, Warning::UsersWithoutBackendRole { .. })));
    }

    #[test]
    fn allowing_a_password_on_an_unencrypted_socket_is_flagged_for_as_long_as_it_is_on() {
        let mut p = pool();
        p.backend_auth = BackendAuth::PerUser;
        p.allow_password_without_tls = true;
        let state = state_with_pool("app_main", p);
        assert!(
            state.warnings().iter().any(|w| matches!(w, Warning::PasswordWithoutTls { pool } if pool == "app_main")),
            "what travels on that socket opens the database directly; it does not get to be quiet"
        );
    }

    #[test]
    fn the_flag_is_inert_on_a_pool_that_never_asks_for_a_password() {
        // A shared pool runs SCRAM and never learns a password, so there is
        // nothing for this setting to expose and nothing to warn about.
        let mut p = pool();
        p.allow_password_without_tls = true;
        let state = state_with_pool("app_main", p);
        assert!(!state.warnings().iter().any(|w| matches!(w, Warning::PasswordWithoutTls { .. })));
    }

    #[test]
    fn a_read_only_pool_in_session_mode_says_so_without_naming_users() {
        // The flag was put on the route, so listing the users who happen to
        // hold a grant today would be answering a different question — and
        // would go stale the moment another one is added.
        let mut p = pool();
        p.mode = PoolMode::Session;
        p.read_only = true;
        let state = state_with_pool("app_main", p);

        let warning = state.warnings().into_iter().find_map(|w| match w {
            Warning::ReadOnlyNotEnforced { pool, pool_wide, users } if pool == "app_main" => Some((pool_wide, users)),
            _ => None,
        });
        assert_eq!(warning, Some((true, Vec::new())));
    }

    #[test]
    fn a_read_only_pool_that_multiplexes_is_enforceable_and_quiet() {
        let mut p = pool();
        p.mode = PoolMode::Transaction;
        p.read_only = true;
        let state = state_with_pool("app_main", p);
        assert!(
            !state.warnings().iter().any(|w| matches!(w, Warning::ReadOnlyNotEnforced { .. })),
            "havuz reads every statement here, so the guarantee holds"
        );
    }

    #[test]
    fn a_read_only_user_on_a_writable_session_pool_is_still_named() {
        let mut p = pool();
        p.mode = PoolMode::Session;
        let mut state = state_with_pool("app_main", p);
        state.users.get_mut("svc").unwrap().read_only = true;

        let warning = state.warnings().into_iter().find_map(|w| match w {
            Warning::ReadOnlyNotEnforced { pool, pool_wide, users } if pool == "app_main" => Some((pool_wide, users)),
            _ => None,
        });
        assert_eq!(warning, Some((false, vec!["svc".to_string()])));
    }

    #[test]
    fn a_read_only_pool_does_not_warn_twice_about_its_read_only_users() {
        // Both sources are present, and there is still one thing wrong: the
        // pool cannot enforce read-only. Saying it twice trains operators to
        // stop reading the banner.
        let mut p = pool();
        p.mode = PoolMode::Session;
        p.read_only = true;
        let mut state = state_with_pool("app_main", p);
        state.users.get_mut("svc").unwrap().read_only = true;

        assert_eq!(state.warnings().iter().filter(|w| matches!(w, Warning::ReadOnlyNotEnforced { .. })).count(), 1);
    }

    #[test]
    fn read_only_defaults_off_and_survives_a_round_trip() {
        // `#[serde(default)]` means a state.json written before this field
        // existed still loads, and loads as writable — the only answer that
        // cannot surprise an operator who never asked for the feature.
        let stored = serde_json::to_value(pool()).unwrap();
        assert_eq!(stored["read_only"], serde_json::json!(false));

        let mut p = pool();
        p.read_only = true;
        let decoded: PoolConfig = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        assert_eq!(decoded, p);

        let mut legacy = stored.as_object().unwrap().clone();
        legacy.remove("read_only");
        let decoded: PoolConfig = serde_json::from_value(serde_json::Value::Object(legacy)).unwrap();
        assert!(!decoded.read_only);
    }

    #[test]
    fn an_idle_in_transaction_limit_on_a_session_pool_is_flagged_as_inert() {
        // It is not wrong, it just does nothing: the client owns its backend
        // until it disconnects either way, so there is no slot to reclaim.
        let mut p = pool();
        p.mode = PoolMode::Session;
        p.limits.idle_in_transaction_timeout = Duration::from_secs(30);
        let state = state_with_pool("app_main", p);
        assert!(
            state
                .warnings()
                .iter()
                .any(|w| matches!(w, Warning::IdleTimeoutInSessionMode { pool } if pool == "app_main")),
            "a setting that silently does nothing is worse than one that is refused"
        );
    }

    #[test]
    fn an_idle_in_transaction_limit_is_quiet_where_it_is_enforced() {
        let mut p = pool();
        p.mode = PoolMode::Transaction;
        p.limits.idle_in_transaction_timeout = Duration::from_secs(30);
        let state = state_with_pool("app_main", p);
        assert!(!state.warnings().iter().any(|w| matches!(w, Warning::IdleTimeoutInSessionMode { .. })));

        // And off is off, in either mode.
        let mut p = pool();
        p.mode = PoolMode::Session;
        let state = state_with_pool("app_main", p);
        assert!(!state.warnings().iter().any(|w| matches!(w, Warning::IdleTimeoutInSessionMode { .. })));
    }

    #[test]
    fn an_idle_in_transaction_limit_defaults_off_and_survives_a_round_trip() {
        // The field arrived after pools existed, so a `state.json` written
        // before it must still load — and must load as "no limit", because
        // inventing one would start ending sessions nobody asked to end.
        let limits = PoolLimits::default();
        assert_eq!(limits.idle_in_transaction_timeout, Duration::ZERO);

        let mut stored = serde_json::to_value(&limits).unwrap();
        assert_eq!(stored["idle_in_transaction_timeout"], serde_json::json!("0s"));

        stored.as_object_mut().unwrap().remove("idle_in_transaction_timeout");
        let decoded: PoolLimits = serde_json::from_value(stored).unwrap();
        assert_eq!(decoded.idle_in_transaction_timeout, Duration::ZERO);

        let set = PoolLimits { idle_in_transaction_timeout: Duration::from_secs(90), ..Default::default() };
        let decoded: PoolLimits = serde_json::from_value(serde_json::to_value(&set).unwrap()).unwrap();
        assert_eq!(decoded, set);
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
