//! Wiring: state -> agents -> pools -> sessions.
//!
//! One JVM per pool, and one JDBC connection per pooled session on it. The
//! agent is started when the pool is built rather than on first use, so a
//! missing runtime or an unloadable driver is a startup error an operator sees
//! rather than a failure the first client discovers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use havuz_control::{ControlPlane, Registries, RoutingReport, TargetPool, TargetReport, TraceContext};
use havuz_core::state::{PoolConfig, State, TraceLevel};
use havuz_core::StateStore;
use havuz_pg::protocol::sqlstate;
use havuz_pg::{complete_startup, ClientHandshake, HandshakeOutcome, Message, StateAuthenticator};
use havuz_pool::{Pool, PoolSnapshot};
use havuz_proto::{PoolRoute, Probe, ProtoError, ProtoResult, ProtocolFamily, ServeOutcome};
use havuz_registry::{FamilyDescriptor, PoolMode, SessionRules};
use havuz_secrets::MasterKey;
use tokio::net::TcpStream;

use crate::agent::Agent;
use crate::conn::{agent_command, JdbcConfig, JdbcConnector};
use crate::session::{startup_parameters, Session, SessionPolicy};

/// The registry id this family serves.
pub const FAMILY_ID: &str = "jdbc";

/// Pools reached over JDBC.
pub struct JdbcFamily {
    state: Arc<StateStore>,
    master_key: Arc<MasterKey>,
    pools: RwLock<HashMap<String, Arc<JdbcPool>>>,
    registries: Registries,
    handshake: ClientHandshake<StateAuthenticator>,
}

struct JdbcPool {
    name: String,
    agent: Arc<Agent>,
    pool: Arc<Pool<JdbcConnector>>,
    label: String,
    server_version: String,
    /// How aggressively a backend may be taken back from a client. Captured
    /// when the pool is built, because changing it under a live session would
    /// move the release points mid-flight.
    mode: PoolMode,
    /// What the profile says its statements do to session state. In session
    /// mode this is never consulted; in transaction mode it is what makes a
    /// release safe.
    rules: SessionRules,
    idle_in_transaction: Duration,
    trace: TraceLevel,
}

impl JdbcFamily {
    pub fn new(state: Arc<StateStore>, master_key: Arc<MasterKey>, registries: Registries) -> Arc<Self> {
        let authenticator = Arc::new(StateAuthenticator::new(state.clone(), master_key.clone()));
        Arc::new(Self {
            state,
            master_key,
            pools: RwLock::new(HashMap::new()),
            registries,
            handshake: ClientHandshake::new(authenticator),
        })
    }

    fn pool(&self, name: &str) -> Option<Arc<JdbcPool>> {
        self.pools.read().expect("pool map poisoned").get(name).cloned()
    }

    /// Turn a stored pool into everything needed to open connections for it.
    fn config_for(&self, name: &str, config: &PoolConfig, state: &State) -> Result<JdbcConfig, ProtoError> {
        let family = havuz_registry::family(FAMILY_ID).expect("jdbc is always registered");
        let connection = family.connection(&config.settings);

        let password =
            state.secrets.get(&self.master_key, &havuz_secrets::pool_backend_password(name)).unwrap_or_default();

        let setting = |key: &str| config.settings.get(key).and_then(|value| value.as_str()).map(str::to_string);

        // Comma separated rather than a list, because the registry's form model
        // has no list field and one is not worth adding for this.
        let driver_paths: Vec<String> = setting("driver_paths")
            .unwrap_or_default()
            .split(',')
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
            .collect();

        if driver_paths.is_empty() {
            return Err(ProtoError::backend(format!(
                "pool '{name}' has no JDBC driver JARs; vendor drivers are rarely redistributable and must be supplied"
            )));
        }
        for path in &driver_paths {
            if !std::path::Path::new(path).exists() {
                return Err(ProtoError::backend(format!("pool '{name}': driver JAR {path} does not exist")));
            }
        }

        let url = if connection.host.is_empty() {
            // The URL takes the host role, so an empty one means the form was
            // not filled in rather than that a default would do.
            return Err(ProtoError::backend(format!("pool '{name}' has no JDBC URL")));
        } else {
            connection.host.clone()
        };

        Ok(JdbcConfig {
            label: redact(&url),
            url,
            user: connection.user,
            password: connection.password.unwrap_or(password),
            driver_class: setting("driver_class").filter(|value| !value.is_empty()),
            driver_paths,
            connect_timeout_ms: config.limits.connect_timeout.as_millis() as u64,
            // The pool's own setting first, then the profile's. An operator who
            // picked "Oracle" should not also have to know the statement that
            // resets an Oracle session, and one who does know better must be
            // able to say so.
            reset_query: config.reset_query(),
        })
    }

    fn rebuild_pools(&self) -> Result<(), ProtoError> {
        let state = self.state.load();
        let mut pools = self.pools.write().expect("pool map poisoned");

        for (name, config) in &state.pools {
            if config.family != FAMILY_ID || config.disabled || pools.contains_key(name) {
                continue;
            }
            // Building is async because starting a JVM is; the pool map is
            // filled by `sync_pools` on a runtime, so this defers the work.
            let built = futures_lite_block(self.build(name, config, &state))?;
            tracing::info!(
                pool = %name,
                target = %built.label,
                server = %built.server_version,
                java = %built.agent.info().java,
                "jdbc pool ready"
            );
            pools.insert(name.clone(), Arc::new(built));
        }

        pools.retain(|name, pool| {
            let live = state.pools.get(name).is_some_and(|c| c.family == FAMILY_ID && !c.disabled);
            if !live {
                tracing::info!(pool = %name, "jdbc pool removed from configuration, draining");
                pool.pool.drain();
                let agent = pool.agent.clone();
                tokio::spawn(async move { agent.shutdown().await });
            }
            live
        });

        Ok(())
    }

    async fn build(&self, name: &str, config: &PoolConfig, state: &State) -> Result<JdbcPool, ProtoError> {
        let jdbc = self.config_for(name, config, state)?;
        let setting = |key: &str| config.settings.get(key).and_then(|value| value.as_str());

        let command = agent_command(setting("agent_jar"), setting("java")).map_err(ProtoError::backend)?;
        let agent = Agent::start(&command).await.map_err(ProtoError::from)?;

        // One connection now, to turn "the driver class is wrong" from
        // something the first client finds into something the operator does.
        let server_version = JdbcConnector::probe(&agent, &jdbc).await.inspect_err(|_| {
            let agent = agent.clone();
            tokio::spawn(async move { agent.shutdown().await });
        })?;

        let pool = Arc::new(Pool::new(
            format!("{name}/jdbc"),
            Arc::new(JdbcConnector::new(agent.clone(), jdbc.clone())),
            config.limits.clone(),
        ));

        // `PoolConfig::validate` has already refused a mode this profile cannot
        // hold, so reading both here is reading two facts that agree.
        let profile = config.profile().expect("the family and profile are validated before a pool is built");

        Ok(JdbcPool {
            name: name.to_string(),
            agent,
            pool,
            label: jdbc.label,
            server_version,
            mode: config.mode,
            rules: profile.quirks.session,
            idle_in_transaction: config.limits.idle_in_transaction_timeout,
            trace: config.trace,
        })
    }
}

/// Run a future to completion from a synchronous caller on a Tokio runtime.
///
/// `sync_pools` is synchronous because every other family's is, and starting a
/// JVM is not. Blocking here is acceptable precisely once — at pool build time,
/// on the admin path, never while serving a client.
fn futures_lite_block<T>(future: impl std::future::Future<Output = Result<T, ProtoError>>) -> Result<T, ProtoError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => Err(ProtoError::backend("building a JDBC pool requires a Tokio runtime")),
    }
}

/// Strip anything credential-shaped out of a URL before it reaches a log.
fn redact(url: &str) -> String {
    match url.split_once('?') {
        Some((head, _)) => format!("{head}?…"),
        None => url.to_string(),
    }
}

impl ControlPlane for JdbcFamily {
    fn sync_pools(&self) -> ProtoResult<()> {
        self.rebuild_pools()
    }

    fn reload_pool(&self, name: &str) -> ProtoResult<()> {
        if let Some(retired) = self.pools.write().expect("pool map poisoned").remove(name) {
            retired.pool.drain();
            let agent = retired.agent.clone();
            tokio::spawn(async move { agent.shutdown().await });
        }
        self.rebuild_pools()
    }

    fn pool_snapshots(&self) -> Vec<PoolSnapshot> {
        let pools = self.pools.read().expect("pool map poisoned");
        let mut out: Vec<_> = pools
            .values()
            .map(|pool| {
                let mut snapshot = pool.pool.snapshot();
                snapshot.name = pool.name.clone();
                snapshot
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// One target and never a replica: read/write split needs a way to tell a
    /// standby from a primary, and JDBC offers none that is portable.
    fn target_reports(&self) -> Vec<TargetReport> {
        let pools = self.pools.read().expect("pool map poisoned");
        let mut out: Vec<_> = pools
            .values()
            .map(|pool| TargetReport {
                name: pool.name.clone(),
                mode: pool.mode.as_str().into(),
                read_write_split: false,
                primary: TargetPool { label: pool.label.clone(), pool: pool.pool.snapshot() },
                replicas: Vec::new(),
                routing: RoutingReport::default(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

#[async_trait]
impl ProtocolFamily for JdbcFamily {
    fn descriptor(&self) -> &'static FamilyDescriptor {
        havuz_registry::family(FAMILY_ID).expect("jdbc is always registered")
    }

    async fn serve(&self, io: TcpStream, peer: SocketAddr, route: &PoolRoute) -> ProtoResult<ServeOutcome> {
        let (mut client, outcome) = self.handshake.run_for_pool(io, peer, route).await?;

        let HandshakeOutcome::Established { identity, .. } = outcome else {
            // Cancellation carries no credentials and there is nothing to
            // cancel: JDBC exposes no portable way to interrupt a statement on
            // another connection.
            return Ok(ServeOutcome::rejected());
        };

        let Some(pool) = self.pool(&identity.pool) else {
            let text = format!("pool \"{}\" is not available", identity.pool);
            let _ = Message::fatal(sqlstate::UNDEFINED_DATABASE, &text).write(&mut client).await;
            return Err(ProtoError::NoRoute(identity.pool));
        };

        let session_limit =
            self.state.load().users.get(&identity.user).map(|user| user.max_client_connections).unwrap_or(0);
        let registered = match self.registries.sessions.register(
            &identity.user,
            &identity.pool,
            identity.application_name.as_deref(),
            &identity.peer.to_string(),
            session_limit,
        ) {
            Ok(session) => session,
            Err(limit) => {
                let text = format!("too many connections for user \"{}\" (limit {})", limit.user, limit.limit);
                let _ = Message::fatal(sqlstate::TOO_MANY_CONNECTIONS, &text).write(&mut client).await;
                return Err(ProtoError::backend(text));
            }
        };

        let holder = self.registries.holders.session(
            TraceContext {
                pool: identity.pool.clone(),
                user: identity.user.clone(),
                application: identity.application_name.clone(),
                client_addr: identity.peer.to_string(),
                level: pool.trace,
            },
            pool.mode,
        );
        holder.waiting_for_startup();

        // Acquired before the handshake completes in both modes, so an
        // exhausted pool is something the client is told at connect time rather
        // than something it discovers on its first query. In a multiplexing
        // mode `Session::new` hands it straight back.
        let checkout = match pool.pool.acquire().await {
            Ok(checkout) => checkout,
            Err(e) => {
                let _ = Message::fatal(sqlstate::TOO_MANY_CONNECTIONS, &e.to_string()).write(&mut client).await;
                return Err(ProtoError::backend(e.to_string()));
            }
        };

        // havuz issues no cancellation key it could honour, so it sends a pair
        // that resolves to nothing rather than one that looks usable.
        complete_startup(&mut client, &startup_parameters(&pool.server_version), 0, 0).await?;

        let policy = SessionPolicy {
            // Only carried into a multiplexing mode. In session mode the client
            // owns its backend either way, so ending it early would free
            // nothing that disconnecting would not.
            idle_in_transaction: if pool.mode.multiplexes() {
                pool.idle_in_transaction
            } else {
                std::time::Duration::ZERO
            },
            kick: registered.signal(),
        };

        let mut session =
            Session::new(&pool.agent, &pool.pool, checkout, pool.mode, pool.rules, policy, &holder, pool.label.clone());
        let result = session.run(&mut client).await;
        let exchanges = session.stats().exchanges;
        let pinned = session.pin();
        let failed = result.is_err();

        // Whatever the session was still holding when it ended. In transaction
        // mode this is usually nothing: the backend went back at the last
        // `ReadyForQuery`.
        if let Some(mut checkout) = session.into_checkout() {
            if failed {
                // The client went away mid-statement, so what the driver is
                // doing is unknown. Retiring beats handing the next client a
                // connection with a half-finished transaction on it.
                checkout.poison();
            }
            checkout.recycle().await;
        }
        holder.clear();

        // In session mode nothing was ever shared, so counting every session as
        // clean would flatter the pin rate into uselessness.
        if pool.mode.multiplexes() {
            match pinned {
                Some(reason) => {
                    self.registries.pins.record(&identity.user, identity.application_name.as_deref(), reason);
                    tracing::info!(
                        user = %identity.user,
                        pool = %identity.pool,
                        application = identity.application_name.as_deref().unwrap_or("-"),
                        reason = %reason,
                        "jdbc session was pinned and could not be multiplexed"
                    );
                }
                None => self.registries.pins.record_clean(),
            }
        }

        result?;
        Ok(ServeOutcome { authenticated: true, pinned, exchanges, bytes_to_client: 0, bytes_to_backend: 0 })
    }

    async fn probe(&self, pool_name: &str) -> ProtoResult<Probe> {
        let pool = self.pool(pool_name).ok_or_else(|| ProtoError::NoRoute(pool_name.to_string()))?;
        let started = std::time::Instant::now();
        let checkout = pool.pool.acquire().await.map_err(|e| ProtoError::backend(e.to_string()))?;
        drop(checkout);
        Ok(Probe {
            version: pool.server_version.clone(),
            latency_ms: started.elapsed().as_millis() as u64,
            // JDBC has no portable way to ask; claiming read-write would be a
            // guess that could route a write at a standby.
            read_only: false,
        })
    }
}

/// How long a drained agent is given to exit before it is killed.
#[allow(dead_code)]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_core::state::{PoolLimits, Target, UserConfig};
    use havuz_core::PoolMode;
    use serde_json::json;

    fn pool_config(settings: serde_json::Map<String, serde_json::Value>) -> PoolConfig {
        PoolConfig {
            family: FAMILY_ID.into(),
            profile: None,
            mode: PoolMode::Session,
            targets: vec![Target::new("unused", 0)],
            backend_user: "app".into(),
            database: String::new(),
            listen_port: 6543,
            aliases: Vec::new(),
            limits: PoolLimits::default(),
            settings,
            routing: Default::default(),
            backend_auth: Default::default(),
            allow_password_without_tls: false,
            read_only: false,
            trace: Default::default(),
            disabled: false,
            description: None,
        }
    }

    fn family_with(settings: serde_json::Map<String, serde_json::Value>) -> (Arc<JdbcFamily>, Arc<StateStore>) {
        let mut state = State::default();
        state.pools.insert("app_main".into(), pool_config(settings));
        state.users.insert("svc".into(), UserConfig::new(vec!["app_main".into()]));
        let store = Arc::new(StateStore::ephemeral(state));
        let family = JdbcFamily::new(store.clone(), Arc::new(MasterKey::generate()), Registries::ephemeral());
        (family, store)
    }

    fn settings(pairs: &[(&str, &str)]) -> serde_json::Map<String, serde_json::Value> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), json!(v))).collect()
    }

    #[test]
    fn the_descriptor_is_the_registry_entry() {
        let (family, _) = family_with(settings(&[]));
        assert_eq!(family.descriptor().id, "jdbc");
        assert!(family.descriptor().capabilities.reports_transaction_status);
    }

    #[test]
    fn a_pool_without_driver_jars_is_refused_with_the_reason() {
        // The single most common way to misconfigure this, and a bare "cannot
        // connect" would send an operator to the network team.
        let (family, store) =
            family_with(settings(&[("url", "jdbc:oracle:thin:@//db:1521/ORCL"), ("username", "app")]));
        let state = store.load();
        let error = family.config_for("app_main", &state.pools["app_main"], &state).unwrap_err();
        assert!(error.to_string().contains("driver"), "got: {error}");
    }

    #[test]
    fn a_driver_jar_that_does_not_exist_is_caught_before_the_jvm_starts() {
        let (family, store) = family_with(settings(&[
            ("url", "jdbc:oracle:thin:@//db:1521/ORCL"),
            ("username", "app"),
            ("driver_paths", "/nonexistent/ojdbc11.jar"),
        ]));
        let state = store.load();
        let error = family.config_for("app_main", &state.pools["app_main"], &state).unwrap_err();
        assert!(error.to_string().contains("does not exist"), "got: {error}");
    }

    #[test]
    fn a_pool_without_a_url_is_refused() {
        let (family, store) = family_with(settings(&[("username", "app"), ("driver_paths", "/tmp")]));
        let state = store.load();
        let error = family.config_for("app_main", &state.pools["app_main"], &state).unwrap_err();
        assert!(error.to_string().contains("URL"), "got: {error}");
    }

    #[test]
    fn several_driver_jars_may_be_given_at_once() {
        // Some drivers need a companion JAR for authentication or i18n.
        let dir = std::env::temp_dir();
        let one = dir.join("havuz-jdbc-a.jar");
        let two = dir.join("havuz-jdbc-b.jar");
        std::fs::write(&one, b"x").unwrap();
        std::fs::write(&two, b"x").unwrap();

        let paths = format!("{}, {}", one.display(), two.display());
        let (family, store) = family_with(settings(&[
            ("url", "jdbc:db2://db:50000/SAMPLE"),
            ("username", "app"),
            ("driver_paths", &paths),
        ]));
        let state = store.load();
        let config = family.config_for("app_main", &state.pools["app_main"], &state).unwrap();
        assert_eq!(config.driver_paths.len(), 2);

        std::fs::remove_file(one).ok();
        std::fs::remove_file(two).ok();
    }

    #[test]
    fn the_profile_supplies_a_reset_query_and_the_setting_overrides_it() {
        // Without one, every connection is closed when its client leaves and
        // the pool saves no handshakes at all. An operator who picked their
        // database from a list should not also have to know the statement.
        let dir = std::env::temp_dir();
        let jar = dir.join("havuz-jdbc-reset.jar");
        std::fs::write(&jar, b"x").unwrap();
        let paths = jar.display().to_string();

        let mut settings =
            settings(&[("url", "jdbc:postgresql://db:5432/appdb"), ("username", "app"), ("driver_paths", &paths)]);
        let mut config = pool_config(settings.clone());
        config.profile = Some("postgresql".into());

        let mut state = State::default();
        state.pools.insert("app_main".into(), config);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = JdbcFamily::new(store.clone(), Arc::new(MasterKey::generate()), Registries::ephemeral());

        let state = store.load();
        let jdbc = family.config_for("app_main", &state.pools["app_main"], &state).unwrap();
        assert_eq!(jdbc.reset_query.as_deref(), Some("DISCARD ALL"));

        // And an operator who knows better than the profile can say so.
        settings.insert("reset_query".into(), json!("RESET ALL"));
        let mut config = pool_config(settings);
        config.profile = Some("postgresql".into());
        let mut state = State::default();
        state.pools.insert("app_main".into(), config);
        let store = Arc::new(StateStore::ephemeral(state));
        let state = store.load();
        let jdbc = family.config_for("app_main", &state.pools["app_main"], &state).unwrap();
        assert_eq!(jdbc.reset_query.as_deref(), Some("RESET ALL"));

        std::fs::remove_file(jar).ok();
    }

    #[test]
    fn the_generic_profile_closes_connections_rather_than_guessing_how_to_clean_them() {
        let dir = std::env::temp_dir();
        let jar = dir.join("havuz-jdbc-noreset.jar");
        std::fs::write(&jar, b"x").unwrap();
        let paths = jar.display().to_string();

        let (family, store) = family_with(settings(&[
            ("url", "jdbc:informix-sqli://db:9088/app"),
            ("username", "app"),
            ("driver_paths", &paths),
        ]));
        let state = store.load();
        let jdbc = family.config_for("app_main", &state.pools["app_main"], &state).unwrap();
        assert_eq!(jdbc.reset_query, None, "a database nobody named gets no invented reset statement");

        std::fs::remove_file(jar).ok();
    }

    #[test]
    fn a_url_with_credentials_in_its_query_is_not_logged_whole() {
        assert_eq!(redact("jdbc:pg://db/app?password=hunter2"), "jdbc:pg://db/app?…");
        assert_eq!(redact("jdbc:oracle:thin:@//db:1521/ORCL"), "jdbc:oracle:thin:@//db:1521/ORCL");
    }

    #[test]
    fn the_url_field_carries_the_host_role() {
        // There is no separate host or port: a JDBC URL names its own, and two
        // places to write the same host is two places to get it wrong.
        let family = havuz_registry::family(FAMILY_ID).unwrap();
        assert_eq!(family.field_for(havuz_registry::FieldRole::Host).map(|f| f.name), Some("url"));
    }

    #[tokio::test]
    async fn probing_an_unconfigured_pool_reports_no_route() {
        let (family, _) = family_with(settings(&[]));
        assert!(matches!(family.probe("nope").await.unwrap_err(), ProtoError::NoRoute(_)));
    }
}
