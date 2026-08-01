//! Wiring: state -> pools -> sessions.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use havuz_control::{BackendIdentity as BackendIdentityReport, ControlPlane, Registries, TargetReport, TraceContext};
use havuz_core::state::{PoolConfig, State};
use havuz_core::{SslMode, StateStore, TraceLevel};
use havuz_pool::PoolSnapshot;
use havuz_proto::{
    BackendConn, PoolMode, PoolRoute, Probe, ProtoError, ProtoResult, ProtocolFamily, ResetOutcome, ServeOutcome,
    SessionState,
};
use havuz_registry::FamilyDescriptor;
use havuz_secrets::MasterKey;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::backend::{BackendConfig, PgConnector};
use crate::cancel::{CancelKey, CancelRegistry, CancelTarget};
use crate::group::PoolGroup;
use crate::protocol::{sqlstate, Message};
use crate::scram::ScramVerifier;
use crate::session::{
    complete_startup, AuthDenial, Authenticator, BackendCredential, ClientAuth, ClientHandshake, HandshakeOutcome,
};

const CANCEL_TIMEOUT: Duration = Duration::from_secs(3);

/// The registry id this family serves. Pools configured for anything else are
/// not ours, and are skipped rather than mishandled.
pub const FAMILY_ID: &str = "postgres";

/// How often idle per-user pools are swept away.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Postgres pools.
///
/// Owns no sockets: `havuz-server` binds every pool port and calls
/// [`ProtocolFamily::serve`] with the pools behind it. What is left here is the
/// handshake, the pool map and the relay.
pub struct PgFamily {
    /// A handle to ourselves for the idle sweeper, which outlives any one call.
    me: Weak<Self>,
    state: Arc<StateStore>,
    master_key: Arc<MasterKey>,
    pools: RwLock<HashMap<String, Arc<PoolEntry>>>,
    cancels: Arc<CancelRegistry>,
    registries: Registries,
    handshake: ClientHandshake<StateAuthenticator>,
    /// Started the first time a per-user pool is actually used, so a
    /// conventional deployment never pays for it.
    sweeper: Mutex<Option<JoinHandle<()>>>,
}

/// One configured pool: the service account's connections, plus a set per user
/// that runs as itself.
struct PoolEntry {
    config: PoolConfig,
    /// Used by every client under `BackendAuth::Shared`, by users that have not
    /// been moved onto their own role, and always by health probes and "Test
    /// Connection" — those run on a timer with no client attached, so they have
    /// no credential to borrow.
    shared: Arc<PoolGroup>,
    per_user: RwLock<HashMap<String, Arc<UserGroup>>>,
}

/// One user's own connections to a pool.
struct UserGroup {
    group: Arc<PoolGroup>,
    /// Which password these connections were opened with.
    ///
    /// A client arriving with a different one means the password was rotated
    /// between two connections, and the existing backends are now authenticated
    /// as a credential the operator has revoked. They have to go.
    fingerprint: [u8; 32],
}

impl PoolEntry {
    /// One row for the flat pool list, summed across every identity.
    ///
    /// Deliberately collapsed to the pool name. A per-user breakdown belongs on
    /// the pool page, not in `/metrics`: thirteen series multiplied by every
    /// user who has ever connected is how a monitoring bill becomes a incident.
    fn combined_snapshot(&self) -> PoolSnapshot {
        let mut combined = self.shared.combined_pool_snapshot();
        for user in self.per_user.read().expect("per-user pool map poisoned").values() {
            combined.merge(&user.group.combined_pool_snapshot());
        }
        combined
    }

    /// Per-target detail, with each target's counters summed across identities.
    ///
    /// The structure — which replica, how far behind, is its breaker open —
    /// comes from the service account's group, because routing and health are
    /// properties of the target rather than of whoever is connected to it.
    fn report(&self) -> TargetReport {
        let mut report = self.shared.snapshot();
        let per_user: Vec<Vec<PoolSnapshot>> = self
            .per_user
            .read()
            .expect("per-user pool map poisoned")
            .values()
            .map(|user| user.group.target_snapshots())
            .collect();

        for targets in &per_user {
            if let Some(primary) = targets.first() {
                report.primary.pool.merge(primary);
            }
            for (replica, snapshot) in report.replicas.iter_mut().zip(targets.iter().skip(1)) {
                replica.pool.merge(snapshot);
            }
        }
        report
    }

    /// Users currently running as themselves, with what each is holding.
    fn identities(&self) -> Vec<(String, PoolSnapshot)> {
        let mut out: Vec<_> = self
            .per_user
            .read()
            .expect("per-user pool map poisoned")
            .iter()
            .map(|(user, held)| (user.clone(), held.group.combined_pool_snapshot()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn drain(&self) {
        self.shared.drain();
        for user in self.per_user.read().expect("per-user pool map poisoned").values() {
            user.group.drain();
        }
    }
}

/// How clients reach havuz: plaintext, or TLS with these settings.
#[derive(Clone, Default)]
pub struct ClientTls {
    pub acceptor: Option<TlsAcceptor>,
    /// Refuse clients that decline TLS. Meaningless without an acceptor.
    pub require: bool,
}

impl std::fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTls").field("enabled", &self.acceptor.is_some()).field("require", &self.require).finish()
    }
}

impl PgFamily {
    pub fn new(state: Arc<StateStore>, master_key: Arc<MasterKey>, registries: Registries) -> Arc<Self> {
        Self::with_tls(state, master_key, registries, ClientTls::default())
    }

    pub fn with_tls(
        state: Arc<StateStore>,
        master_key: Arc<MasterKey>,
        registries: Registries,
        tls: ClientTls,
    ) -> Arc<Self> {
        let authenticator = Arc::new(StateAuthenticator { state: state.clone(), master_key: master_key.clone() });
        let mut handshake = ClientHandshake::new(authenticator);
        if let Some(acceptor) = tls.acceptor {
            handshake = handshake.with_tls(acceptor, tls.require);
        }
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            state,
            master_key,
            pools: RwLock::new(HashMap::new()),
            cancels: Arc::new(CancelRegistry::new()),
            registries,
            handshake,
            sweeper: Mutex::new(None),
        })
    }

    pub fn cancels(&self) -> &Arc<CancelRegistry> {
        &self.cancels
    }

    /// Configured pooling mode for a pool, defaulting to the safest option if
    /// the pool vanished between routing and lookup.
    fn pool_mode(&self, name: &str) -> PoolMode {
        self.state.load().pools.get(name).map(|p| p.mode).unwrap_or(PoolMode::Session)
    }

    /// Read at connect time rather than baked into the pool, so turning tracing
    /// up during an incident takes effect on the next session instead of
    /// requiring the pool to be rebuilt underneath its clients.
    fn trace_level(&self, name: &str) -> TraceLevel {
        self.state.load().pools.get(name).map(|p| p.trace).unwrap_or_default()
    }

    /// Bring the live pool set in line with the configuration.
    ///
    /// Pools that disappeared are drained rather than dropped, so in-flight
    /// clients finish their work instead of getting a reset connection.
    fn rebuild_pools(&self) -> Result<(), ProtoError> {
        let state = self.state.load();
        let mut pools = self.pools.write().expect("pool map poisoned");

        for (name, config) in &state.pools {
            if config.family != FAMILY_ID || config.disabled {
                continue;
            }
            if pools.contains_key(name) {
                continue;
            }
            let shared = PoolGroup::build(name, config, |target| {
                self.connector_for(name, config, &state, target, BackendIdentity::Service)
            })?;
            let replicas = shared.router().replicas().len();
            pools.insert(
                name.clone(),
                Arc::new(PoolEntry { config: config.clone(), shared, per_user: RwLock::new(HashMap::new()) }),
            );
            tracing::info!(
                pool = %name,
                mode = config.mode.as_str(),
                replicas,
                read_write_split = config.routing.read_write_split,
                backend_auth = config.backend_auth.as_str(),
                "pool ready"
            );
        }

        pools.retain(|name, entry| {
            let live = state.pools.get(name).is_some_and(|c| c.family == FAMILY_ID && !c.disabled);
            if !live {
                tracing::info!(pool = %name, "pool removed from configuration, draining");
                entry.drain();
            }
            live
        });

        Ok(())
    }

    /// Whose credentials a set of backend connections is opened with.
    fn connector_for(
        &self,
        name: &str,
        config: &PoolConfig,
        state: &State,
        target: &havuz_core::Target,
        identity: BackendIdentity<'_>,
    ) -> Result<PgConnector, ProtoError> {
        let (user, password, application_name) = match identity {
            BackendIdentity::Service => (
                config.backend_user.clone(),
                state.secrets.get(&self.master_key, &havuz_secrets::pool_backend_password(name)).unwrap_or_default(),
                format!("havuz/{name}"),
            ),
            // Carrying the havuz user into `application_name` as well as into
            // the role means `pg_stat_activity` finally attributes work to a
            // real caller, which the shared service account never could.
            BackendIdentity::User { name: user, password } => {
                (user.to_string(), password.to_string(), format!("havuz/{name}/{user}"))
            }
        };

        let ssl_mode = config
            .settings
            .get("sslmode")
            .and_then(|v| v.as_str())
            .map(SslMode::parse)
            .transpose()
            .map_err(|e| ProtoError::Tls(e.to_string()))?
            .unwrap_or(SslMode::Prefer);

        let ca_path = config.settings.get("ssl_root_cert").and_then(|v| v.as_str()).map(std::path::PathBuf::from);
        let tls =
            havuz_core::tls::client_config(ssl_mode, ca_path.as_deref()).map_err(|e| ProtoError::Tls(e.to_string()))?;

        let profile = havuz_registry::family("postgres")
            .and_then(|f| match &config.profile {
                Some(id) => f.profile(id),
                None => Some(f.default_profile()),
            })
            .ok_or_else(|| ProtoError::backend(format!("pool '{name}' has an unknown driver profile")))?;

        Ok(PgConnector::new(BackendConfig {
            host: target.host.clone(),
            port: target.port,
            database: config.database.clone(),
            user,
            password,
            ssl_mode,
            tls,
            application_name,
            supports_discard_all: profile.quirks.supports_discard_all,
        }))
    }

    fn entry(&self, name: &str) -> Option<Arc<PoolEntry>> {
        self.pools.read().expect("pool map poisoned").get(name).cloned()
    }

    /// The connections this client should borrow from.
    ///
    /// Without a credential — a shared pool, or a user still on the service
    /// account — this is the pool's own group and nothing else happens. With
    /// one, the user gets a group of its own, built on first use.
    fn group_for(
        &self,
        entry: &Arc<PoolEntry>,
        pool: &str,
        user: &str,
        credential: Option<&BackendCredential>,
    ) -> Result<Arc<PoolGroup>, ProtoError> {
        let Some(credential) = credential else {
            // A per-user pool may be created without a service account at all,
            // in which case the fallback these clients rely on does not exist.
            // Saying so beats letting the backend reject a connection opened as
            // nobody, which reads like a database misconfiguration.
            if entry.config.backend_auth.is_per_user() && entry.config.backend_user.is_empty() {
                return Err(ProtoError::auth(format!(
                    "pool '{pool}' has no service account: give user '{user}' a database role of its own, \
                     or add a backend user to the pool"
                )));
            }
            return Ok(entry.shared.clone());
        };
        let fingerprint = credential.fingerprint();

        if let Some(existing) = entry.per_user.read().expect("per-user pool map poisoned").get(user) {
            if existing.fingerprint == fingerprint {
                return Ok(existing.group.clone());
            }
        }

        let state = self.state.load();
        let mut groups = entry.per_user.write().expect("per-user pool map poisoned");

        // Re-check: another connection for the same user may have built it
        // while we were not holding the lock.
        if let Some(existing) = groups.get(user) {
            if existing.fingerprint == fingerprint {
                return Ok(existing.group.clone());
            }
            // Established sessions keep an `Arc` and finish against the old
            // group; nothing new is handed out from it.
            tracing::info!(%pool, %user, "backend password changed, replacing this user's connections");
            existing.group.drain();
        }

        let group = PoolGroup::build(pool, &entry.config, |target| {
            self.connector_for(
                pool,
                &entry.config,
                &state,
                target,
                BackendIdentity::User { name: user, password: credential.expose() },
            )
        })?;
        groups.insert(user.to_string(), Arc::new(UserGroup { group: group.clone(), fingerprint }));
        tracing::info!(%pool, %user, held = groups.len(), "opened a backend identity for this user");
        drop(groups);

        self.ensure_sweeper();
        Ok(group)
    }

    /// Start the idle sweeper once, lazily.
    ///
    /// Lazily because a deployment that never uses per-user authentication
    /// should not pay for a timer, and because this is the first point at which
    /// we are guaranteed to be inside a Tokio runtime.
    fn ensure_sweeper(&self) {
        let mut slot = self.sweeper.lock().expect("sweeper slot poisoned");
        if slot.is_some() {
            return;
        }
        let weak = self.me.clone();
        *slot = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(family) = weak.upgrade() else { return };
                family.sweep_idle_users();
            }
        }));
    }

    /// Drop the connection sets of users who have gone.
    ///
    /// Two conditions, both required: no live session on that pool, and no open
    /// backend connection left. The second is what the pool's own reaper
    /// produces after `idle_timeout`, so this does not close anything early —
    /// it only reclaims the empty shell, and with it the client's password.
    fn sweep_idle_users(&self) {
        let entries: Vec<(String, Arc<PoolEntry>)> =
            self.pools.read().expect("pool map poisoned").iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        for (pool, entry) in entries {
            let live = self.registries.sessions.users_in_pool(&pool);
            let mut groups = entry.per_user.write().expect("per-user pool map poisoned");
            groups.retain(|user, held| {
                let keep = live.contains(user) || held.group.combined_pool_snapshot().open > 0;
                if !keep {
                    tracing::debug!(%pool, %user, "releasing an idle backend identity");
                    held.group.drain();
                }
                keep
            });
        }
    }
}

/// Whose credentials a backend connection is opened with.
enum BackendIdentity<'a> {
    Service,
    User { name: &'a str, password: &'a str },
}

impl ControlPlane for PgFamily {
    fn sync_pools(&self) -> ProtoResult<()> {
        self.rebuild_pools()
    }

    /// Rebuild one pool after its runtime settings change.
    ///
    /// Existing sessions keep an `Arc` to the retired group and can finish;
    /// subsequent lookups use the freshly configured group. The old group must
    /// stay active because an idle transaction-mode client may need to borrow
    /// another backend before it disconnects.
    fn reload_pool(&self, name: &str) -> ProtoResult<()> {
        self.pools.write().expect("pool map poisoned").remove(name);
        self.rebuild_pools()
    }

    fn pool_snapshots(&self) -> Vec<PoolSnapshot> {
        let pools = self.pools.read().expect("pool map poisoned");
        let mut out: Vec<_> = pools.values().map(|entry| entry.combined_snapshot()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    fn target_reports(&self) -> Vec<TargetReport> {
        let pools = self.pools.read().expect("pool map poisoned");
        let mut out: Vec<_> = pools.values().map(|entry| entry.report()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    fn backend_identities(&self) -> Vec<BackendIdentityReport> {
        let pools = self.pools.read().expect("pool map poisoned");
        let mut out: Vec<_> = pools
            .iter()
            .flat_map(|(pool, entry)| {
                entry.identities().into_iter().map(move |(user, pool_snapshot)| BackendIdentityReport {
                    pool: pool.clone(),
                    user,
                    pool_snapshot,
                })
            })
            .collect();
        out.sort_by(|a, b| (&a.pool, &a.user).cmp(&(&b.pool, &b.user)));
        out
    }
}

#[async_trait]
impl ProtocolFamily for PgFamily {
    fn descriptor(&self) -> &'static FamilyDescriptor {
        havuz_registry::family("postgres").expect("postgres is always registered")
    }

    async fn serve(&self, io: TcpStream, peer: SocketAddr, route: &PoolRoute) -> ProtoResult<ServeOutcome> {
        let (mut client, outcome) = self.handshake.run_for_pool(io, peer, route).await?;

        let (identity, startup_params, credential) = match outcome {
            HandshakeOutcome::Cancel { process_id, secret_key } => {
                // Unauthenticated by design: the key pair is the credential.
                // An unknown key cancels nothing, which is the whole point of
                // issuing our own.
                let key = CancelKey { process_id, secret_key };
                match self.cancels.lookup(key) {
                    Some(target) => {
                        if let Err(e) = crate::cancel::deliver(&target, CANCEL_TIMEOUT).await {
                            tracing::debug!(error = %e, "cancel delivery failed");
                        }
                    }
                    None => tracing::debug!(process_id, "cancel request for an unknown key, ignoring"),
                }
                return Ok(ServeOutcome::rejected());
            }
            HandshakeOutcome::Established { identity, startup_params, credential } => {
                (identity, startup_params, credential)
            }
        };

        let Some(entry) = self.entry(&identity.pool) else {
            let _ =
                Message::fatal(sqlstate::UNDEFINED_DATABASE, &format!("pool \"{}\" is not available", identity.pool))
                    .write(&mut client)
                    .await;
            return Err(ProtoError::NoRoute(identity.pool));
        };

        // Under per-user authentication this is where the client's own database
        // role gets its connections; otherwise it is the pool's service account
        // and nothing new happens.
        let group = match self.group_for(&entry, &identity.pool, &identity.user, credential.as_ref()) {
            Ok(group) => group,
            Err(e) => {
                let text = format!("cannot prepare backend connections for \"{}\": {e}", identity.user);
                let _ = Message::fatal(sqlstate::CANNOT_CONNECT_NOW, &text).write(&mut client).await;
                return Err(ProtoError::backend(text));
            }
        };

        // What this user is allowed to do, read once at connect time. Changing
        // it later takes effect on the next connection — and, for anything
        // urgent, on a kick.
        let (read_only, session_limit) = self
            .state
            .load()
            .users
            .get(&identity.user)
            .map(|user| (user.read_only, user.max_client_connections))
            .unwrap_or((false, 0));

        // The per-user connection budget. Counted here rather than at accept
        // time because that is the first point the user is known.
        let session = match self.registries.sessions.register(
            &identity.user,
            &identity.pool,
            identity.application_name.as_deref(),
            &identity.peer.to_string(),
            session_limit,
        ) {
            Ok(session) => session,
            Err(havuz_pg_too_many) => {
                let text = format!(
                    "too many connections for user \"{}\" (limit {})",
                    havuz_pg_too_many.user, havuz_pg_too_many.limit
                );
                let _ = Message::fatal(sqlstate::TOO_MANY_CONNECTIONS, &text).write(&mut client).await;
                return Err(ProtoError::backend(text));
            }
        };

        let mode = self.pool_mode(&identity.pool);
        let trace_context = TraceContext {
            pool: identity.pool.clone(),
            user: identity.user.clone(),
            application: identity.application_name.clone(),
            client_addr: identity.peer.to_string(),
            level: self.trace_level(&identity.pool),
        };
        let holder = self.registries.holders.session(trace_context.clone(), mode);
        holder.waiting_for_startup();

        // The startup checkout always comes from the primary: the client needs
        // a real backend's parameters, and the primary is the one target every
        // pool is guaranteed to have.
        let checkout_started = Instant::now();
        let acquire = group.primary().acquire();
        tokio::pin!(acquire);
        let mut startup_kick = session.signal();
        let checkout_result = tokio::select! {
            result = &mut acquire => result,
            disconnected = client.wait_for_disconnect() => {
                return Err(ProtoError::Io(disconnected.err().unwrap_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "client disconnected while waiting for a backend")
                })));
            }
            // A client queued behind an exhausted pool holds no backend, so it
            // is the cheapest possible thing to kick.
            _ = startup_kick.kicked() => {
                let text = "terminating connection due to administrator command";
                let _ = Message::fatal(sqlstate::ADMIN_SHUTDOWN, text).write(&mut client).await;
                return Err(ProtoError::backend(text));
            }
        };
        let mut checkout = match checkout_result {
            Ok(checkout) => checkout,
            Err(e) => {
                let (code, text) = match &e {
                    havuz_pool::PoolError::Timeout { .. } => (
                        sqlstate::TOO_MANY_CONNECTIONS,
                        format!("{e}; {}", self.registries.holders.timeout_hint(&identity.pool)),
                    ),
                    havuz_pool::PoolError::Unavailable { .. } => (sqlstate::CANNOT_CONNECT_NOW, e.to_string()),
                    havuz_pool::PoolError::Connect { .. } => (sqlstate::CANNOT_CONNECT_NOW, e.to_string()),
                };
                self.registries.traces.record_failure(
                    &trace_context,
                    "connection checkout",
                    checkout_started.elapsed(),
                    code,
                    &text,
                );
                let _ = Message::fatal(code, &text).write(&mut client).await;
                return Err(ProtoError::backend(text));
            }
        };

        let cancel_key = self.cancels.register(CancelTarget {
            host: group.name().to_string(),
            port: 0,
            backend_pid: checkout.backend_pid().unwrap_or(0) as i32,
            backend_secret: checkout.secret_key().unwrap_or(0),
        });

        complete_startup(&mut client, checkout.parameters(), cancel_key.process_id, cancel_key.secret_key).await?;

        // The client's own startup parameters. They never reached a backend
        // before this: the handshake read them, used `application_name` for
        // logging and dropped the rest, so a connection string carrying
        // `?options=-c search_path%3Dapp` silently did nothing.
        let mut params = crate::params::ClientParams::from_startup(&startup_params);

        // Enforced by PostgreSQL, not by guessing which statements are writes:
        // no classifier can see the INSERT inside a SELECT that calls a
        // function, and `default_transaction_read_only` does not have to.
        if read_only {
            params.enforce_read_only();
        }

        let policy = crate::txn::SessionPolicy { read_only, kick: session.signal() };

        let outcome = if mode.multiplexes() {
            // Transaction mode: the startup checkout has done its job (the
            // client needed a real backend's parameters), so give it straight
            // back. From here the client holds nothing while it is idle, which
            // is the entire source of the fan-in.
            drop(checkout);
            holder.clear();

            let mut state = SessionState::new(mode);
            let result = crate::txn::transaction_relay_traced(
                &mut client,
                &group,
                &mut state,
                &mut params,
                policy,
                &self.registries.traces,
                &trace_context,
                &holder,
            )
            .await;
            self.cancels.unregister(cancel_key);

            match result {
                Ok(txn) => ServeOutcome {
                    authenticated: true,
                    pinned: txn.pinned,
                    exchanges: txn.exchanges,
                    bytes_to_client: txn.stats.to_client,
                    bytes_to_backend: txn.stats.to_backend,
                },
                Err(e) => {
                    tracing::debug!(error = %e, user = %identity.user, "transaction relay ended with an error");
                    return Err(e);
                }
            }
        } else {
            // Session mode: bytes are shovelled in both directions, with just
            // enough framing awareness to stop the client's Terminate from
            // reaching — and killing — a backend we want to reuse.
            //
            // The backend is exclusive here, so there is nothing to multiplex,
            // but the client's startup parameters still have to be applied:
            // this connection came out of a pool and carries whoever used it
            // last.
            match crate::txn::sync_params(&mut checkout, &params).await {
                Ok(crate::txn::ParamSync::Unchanged | crate::txn::ParamSync::Applied) => {}
                Ok(crate::txn::ParamSync::Refused(detail)) => {
                    let text = format!("cannot apply session parameters: {detail}");
                    let _ = Message::fatal(sqlstate::INVALID_PARAMETER_VALUE, &text).write(&mut client).await;
                    return Err(ProtoError::backend(text));
                }
                Err(e) => {
                    checkout.discard();
                    let _ = Message::fatal(sqlstate::CANNOT_CONNECT_NOW, &e.to_string()).write(&mut client).await;
                    return Err(e);
                }
            }

            let backend_pid = checkout.backend_pid();
            let target =
                group.target_label(crate::routing::Route::Primary(crate::routing::PrimaryReason::SplitDisabled));
            holder.session_reserved(target.clone(), backend_pid);
            let relay = crate::relay::session_relay_traced(
                &mut client,
                checkout.stream_mut(),
                &self.registries.traces,
                &trace_context,
                target,
                backend_pid,
                session.signal(),
            )
            .await;
            self.cancels.unregister(cancel_key);

            let (to_backend, to_client) = match relay {
                Ok(stats) => {
                    // A kicked byte shovel stops wherever it was, so the
                    // backend's framing position is unknown. Resetting it would
                    // mean reading replies to a statement that may still be
                    // interleaved with the last response.
                    if stats.backend_closed || stats.kicked {
                        checkout.discard();
                    }
                    (stats.to_backend, stats.to_client)
                }
                Err(e) => {
                    // The framing position is unknown after a mid-message
                    // failure, so the backend cannot be trusted for reuse.
                    tracing::debug!(error = %e, user = %identity.user, "relay ended with an error");
                    checkout.discard();
                    (0, 0)
                }
            };

            // Clean before it goes back on the shelf. Without this, one
            // client's temp tables and session variables become the next
            // client's problem.
            if matches!(checkout.reset().await, Ok(ResetOutcome::Discard) | Err(_)) {
                checkout.discard();
            }
            drop(checkout);

            ServeOutcome {
                authenticated: true,
                pinned: None,
                exchanges: 0,
                bytes_to_client: to_client,
                bytes_to_backend: to_backend,
            }
        };

        // Only transaction-mode sessions carry a meaningful verdict: in session
        // mode nothing is ever shared, so counting every session as "clean"
        // would flatter the pin rate into uselessness.
        if mode.multiplexes() {
            match outcome.pinned {
                Some(reason) => {
                    // The product's most valuable signal: this session stopped
                    // being shareable, and here is exactly who did it and why.
                    self.registries.pins.record(&identity.user, identity.application_name.as_deref(), reason);
                    tracing::info!(
                        user = %identity.user,
                        pool = %identity.pool,
                        application = identity.application_name.as_deref().unwrap_or("-"),
                        reason = %reason,
                        "session was pinned and could not be multiplexed"
                    );
                }
                None => self.registries.pins.record_clean(),
            }
        }

        Ok(outcome)
    }

    async fn probe(&self, pool_name: &str) -> ProtoResult<Probe> {
        // Probing runs on the service account: there is no client here, so
        // there is no credential to borrow.
        let entry = self.entry(pool_name).ok_or_else(|| ProtoError::NoRoute(pool_name.to_string()))?;
        if entry.config.backend_user.is_empty() {
            return Err(ProtoError::auth(
                "this pool has no service account, so there is no identity to probe with: \
                 every backend connection is opened as the client that asked for it",
            ));
        }
        let group = entry.shared.clone();
        let started = std::time::Instant::now();
        let checkout = group.primary().acquire().await.map_err(|e| ProtoError::backend(e.to_string()))?;

        let version = checkout
            .parameters()
            .iter()
            .find(|(k, _)| k == "server_version")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "unknown".into());

        // `default_transaction_read_only` distinguishes a hot standby from a
        // primary without the operator having to label targets by hand.
        let read_only = checkout.parameters().iter().any(|(k, v)| k == "default_transaction_read_only" && v == "on");

        Ok(Probe { version, latency_ms: started.elapsed().as_millis() as u64, read_only })
    }
}

/// Authenticates clients against the state store.
///
/// Public because the JDBC bridge authenticates its clients the same way: they
/// are havuz users reaching a havuz pool, and which protocol lives behind that
/// pool is not the authenticator's business. A second copy of this would be a
/// second place for the rules about `disabled` and pool grants to drift.
pub struct StateAuthenticator {
    state: Arc<StateStore>,
    master_key: Arc<MasterKey>,
}

impl StateAuthenticator {
    pub fn new(state: Arc<StateStore>, master_key: Arc<MasterKey>) -> Self {
        Self { state, master_key }
    }
}

impl Authenticator for StateAuthenticator {
    fn resolve(&self, user: &str, pool: &str) -> Result<ClientAuth, AuthDenial> {
        let state = self.state.load();

        let Some(pool_config) = state.pools.get(pool) else {
            return Err(AuthDenial::UnknownPool { pool: pool.into() });
        };
        if pool_config.disabled {
            return Err(AuthDenial::UnknownPool { pool: pool.into() });
        }

        let Some(user_config) = state.users.get(user) else {
            return Err(AuthDenial::UnknownUser);
        };
        if user_config.disabled {
            return Err(AuthDenial::Disabled);
        }
        if !user_config.pools.iter().any(|p| p == pool) {
            return Err(AuthDenial::NotGranted { user: user.into(), pool: pool.into() });
        }

        let stored = state
            .secrets
            .get(&self.master_key, &havuz_secrets::user_verifier(user))
            .map_err(|_| AuthDenial::UnknownUser)?;

        let verifier = ScramVerifier::parse(&stored).map_err(|e| {
            tracing::error!(%user, error = %e, "stored verifier is unusable");
            AuthDenial::UnknownUser
        })?;

        // Both sides have to opt in: the pool must be in per-user mode, and the
        // user must have been moved onto its own database role. Anything else
        // keeps the SCRAM path and the service account, which is what makes the
        // migration incremental.
        let needs_plaintext = pool_config.backend_auth.is_per_user() && user_config.own_backend_role;
        Ok(ClientAuth { verifier, needs_plaintext })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_core::state::{BackendAuth, PoolLimits, Target, UserConfig};
    use havuz_registry::PoolMode;

    fn family_for(store: Arc<StateStore>, key: MasterKey) -> Arc<PgFamily> {
        PgFamily::new(store, Arc::new(key), Registries::ephemeral())
    }

    fn pool_config() -> PoolConfig {
        PoolConfig {
            family: "postgres".into(),
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

    fn state_with_user(password: &str, key: &MasterKey) -> State {
        let mut state = State::default();
        state.pools.insert("app_main".into(), pool_config());
        state.users.insert("svc_orders".into(), UserConfig::new(vec!["app_main".into()]));
        state
            .secrets
            .put(key, havuz_secrets::user_verifier("svc_orders"), &ScramVerifier::from_password(password).encode())
            .unwrap();
        state
    }

    #[tokio::test]
    async fn the_trace_level_is_read_from_the_pool_at_connect_time() {
        // Read per session rather than captured when the pool is built, so
        // raising capture during an incident does not mean rebuilding the pool
        // underneath the clients it is meant to diagnose.
        let key = MasterKey::generate();
        let mut state = state_with_user("hunter2", &key);
        state.pools.get_mut("app_main").unwrap().trace = TraceLevel::Off;
        let store = Arc::new(StateStore::ephemeral(state));
        let family = family_for(store.clone(), key);

        assert_eq!(family.trace_level("app_main"), TraceLevel::Off);
        assert_eq!(family.trace_level("no_such_pool"), TraceLevel::Statements, "the default, not a panic");

        store
            .update(|s| {
                s.pools.get_mut("app_main").unwrap().trace = TraceLevel::Full;
                true
            })
            .await
            .unwrap();
        assert_eq!(family.trace_level("app_main"), TraceLevel::Full, "without a pool rebuild");
    }

    #[tokio::test]
    async fn sync_creates_a_pool_per_configured_postgres_pool() {
        let key = MasterKey::generate();
        let state = state_with_user("hunter2", &key);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = family_for(store, key);

        family.sync_pools().unwrap();
        let snapshots = family.pool_snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "app_main");
        assert_eq!(snapshots[0].open, 0, "pools start empty; connections are opened on demand");
    }

    #[tokio::test]
    async fn disabled_pools_are_not_served() {
        let key = MasterKey::generate();
        let mut state = state_with_user("hunter2", &key);
        state.pools.get_mut("app_main").unwrap().disabled = true;

        let store = Arc::new(StateStore::ephemeral(state));
        let family = family_for(store, key);
        family.sync_pools().unwrap();
        assert!(family.pool_snapshots().is_empty());
    }

    #[tokio::test]
    async fn sync_is_idempotent_and_does_not_recreate_live_pools() {
        let key = MasterKey::generate();
        let state = state_with_user("hunter2", &key);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = family_for(store, key);

        family.sync_pools().unwrap();
        let first = Arc::as_ptr(&family.entry("app_main").unwrap().shared.clone());
        family.sync_pools().unwrap();
        let second = Arc::as_ptr(&family.entry("app_main").unwrap().shared.clone());

        assert_eq!(first, second, "resyncing must not tear down a working pool");
    }

    #[tokio::test]
    async fn reload_replaces_lookups_without_draining_existing_sessions() {
        let key = MasterKey::generate();
        let state = state_with_user("hunter2", &key);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = family_for(store.clone(), key);
        family.sync_pools().unwrap();
        let old = family.entry("app_main").unwrap().shared.clone();

        store
            .update(|s| {
                s.pools.get_mut("app_main").unwrap().mode = PoolMode::Transaction;
            })
            .await
            .unwrap();
        family.reload_pool("app_main").unwrap();

        let new = family.entry("app_main").unwrap().shared.clone();
        assert!(!Arc::ptr_eq(&old, &new), "new connections must use the replacement");
        assert_eq!(new.mode(), PoolMode::Transaction);
        assert_eq!(
            old.primary().status(),
            havuz_pool::PoolStatus::Active,
            "established clients must be able to finish against the old group"
        );
    }

    fn credential(password: &str) -> BackendCredential {
        BackendCredential::for_test(password)
    }

    /// A pool whose clients authenticate against the database as themselves.
    async fn per_user_family() -> (Arc<PgFamily>, Registries) {
        let key = MasterKey::generate();
        let mut state = state_with_user("hunter2", &key);
        state.pools.get_mut("app_main").unwrap().backend_auth = BackendAuth::PerUser;
        state.users.get_mut("svc_orders").unwrap().own_backend_role = true;

        let registries = Registries::ephemeral();
        let family = PgFamily::new(Arc::new(StateStore::ephemeral(state)), Arc::new(key), registries.clone());
        family.sync_pools().unwrap();
        (family, registries)
    }

    #[tokio::test]
    async fn each_user_gets_its_own_connections_and_the_service_account_stays_put() {
        let (family, _) = per_user_family().await;
        let entry = family.entry("app_main").unwrap();

        let orders = family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter2"))).unwrap();
        let reports = family.group_for(&entry, "app_main", "svc_reports", Some(&credential("other"))).unwrap();

        assert!(!Arc::ptr_eq(&orders, &reports), "two users must not share a set of backend connections");
        assert!(!Arc::ptr_eq(&orders, &entry.shared), "and neither may borrow the service account's");
        assert_eq!(family.backend_identities().len(), 2);
    }

    #[tokio::test]
    async fn the_same_user_reconnecting_reuses_its_connections() {
        // Otherwise per-user auth would cost a fresh pool on every connection
        // and there would be no pooling left at all.
        let (family, _) = per_user_family().await;
        let entry = family.entry("app_main").unwrap();

        let first = family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter2"))).unwrap();
        let second = family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter2"))).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn a_rotated_password_replaces_the_connections_opened_with_the_old_one() {
        // Those backends are authenticated as a credential the operator has
        // just revoked. Keeping them would quietly defeat the rotation.
        let (family, _) = per_user_family().await;
        let entry = family.entry("app_main").unwrap();

        let before = family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter2"))).unwrap();
        let after = family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter3"))).unwrap();

        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(before.primary().status(), havuz_pool::PoolStatus::Draining);
        assert_eq!(family.backend_identities().len(), 1, "the old set is replaced, not accumulated");
    }

    #[tokio::test]
    async fn a_client_without_a_credential_falls_back_to_the_service_account() {
        // The migration path: a pool can be in per-user mode while users move
        // onto their own database roles one at a time.
        let (family, _) = per_user_family().await;
        let entry = family.entry("app_main").unwrap();

        let group = family.group_for(&entry, "app_main", "svc_legacy", None).unwrap();
        assert!(Arc::ptr_eq(&group, &entry.shared));
        assert!(family.backend_identities().is_empty());
    }

    #[tokio::test]
    async fn without_a_service_account_a_client_that_is_not_its_own_role_is_told_why() {
        // A per-user pool may be created with no service account at all. The
        // fallback then does not exist, and saying so beats opening a backend
        // connection as nobody and relaying whatever the database makes of it.
        let key = MasterKey::generate();
        let mut state = state_with_user("hunter2", &key);
        let pool = state.pools.get_mut("app_main").unwrap();
        pool.backend_auth = BackendAuth::PerUser;
        pool.backend_user = String::new();

        let family = PgFamily::new(Arc::new(StateStore::ephemeral(state)), Arc::new(key), Registries::ephemeral());
        family.sync_pools().unwrap();
        let entry = family.entry("app_main").unwrap();

        let err = family.group_for(&entry, "app_main", "svc_legacy", None).unwrap_err();
        assert_eq!(err.kind(), "auth");
        assert!(err.to_string().contains("svc_legacy"), "the message must name the user to fix: {err}");

        // A user that does bring a credential is unaffected.
        assert!(family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter2"))).is_ok());
    }

    #[tokio::test]
    async fn a_pool_without_a_service_account_cannot_be_probed() {
        let key = MasterKey::generate();
        let mut state = state_with_user("hunter2", &key);
        let pool = state.pools.get_mut("app_main").unwrap();
        pool.backend_auth = BackendAuth::PerUser;
        pool.backend_user = String::new();

        let family = PgFamily::new(Arc::new(StateStore::ephemeral(state)), Arc::new(key), Registries::ephemeral());
        family.sync_pools().unwrap();

        let err = family.probe("app_main").await.unwrap_err();
        assert_eq!(err.kind(), "auth");
        assert!(err.to_string().contains("service account"), "{err}");
    }

    #[tokio::test]
    async fn a_user_that_has_gone_gives_its_connections_and_its_password_back() {
        let (family, registries) = per_user_family().await;
        let entry = family.entry("app_main").unwrap();

        let session = registries.sessions.register("svc_orders", "app_main", None, "127.0.0.1:1", 0).unwrap();
        family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter2"))).unwrap();

        family.sweep_idle_users();
        assert_eq!(family.backend_identities().len(), 1, "a connected user keeps its connections");

        drop(session);
        family.sweep_idle_users();
        assert!(family.backend_identities().is_empty(), "and loses them, and its password, once it is gone");
    }

    #[tokio::test]
    async fn a_session_on_another_pool_does_not_keep_these_connections_alive() {
        let (family, registries) = per_user_family().await;
        let entry = family.entry("app_main").unwrap();

        let _elsewhere = registries.sessions.register("svc_orders", "reporting", None, "127.0.0.1:1", 0).unwrap();
        family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter2"))).unwrap();

        family.sweep_idle_users();
        assert!(family.backend_identities().is_empty());
    }

    #[tokio::test]
    async fn the_flat_pool_list_stays_one_row_per_pool() {
        // Thirteen metric series multiplied by every user who has ever
        // connected is how a monitoring bill becomes an incident.
        let (family, _) = per_user_family().await;
        let entry = family.entry("app_main").unwrap();
        family.group_for(&entry, "app_main", "svc_orders", Some(&credential("hunter2"))).unwrap();
        family.group_for(&entry, "app_main", "svc_reports", Some(&credential("other"))).unwrap();

        let snapshots = family.pool_snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "app_main");
        assert_eq!(family.target_reports().len(), 1);
    }

    #[tokio::test]
    async fn removing_a_pool_from_config_drains_it() {
        let key = MasterKey::generate();
        let state = state_with_user("hunter2", &key);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = family_for(store.clone(), key);
        family.sync_pools().unwrap();

        // Pools and users must go together: a user granted a missing pool is a
        // validation error, so a half-update would be rejected.
        store
            .update(|s| {
                s.pools.clear();
                s.users.clear();
            })
            .await
            .unwrap();

        family.sync_pools().unwrap();
        assert!(family.pool_snapshots().is_empty());
    }

    #[tokio::test]
    async fn authentication_resolves_a_granted_user() {
        let key = Arc::new(MasterKey::generate());
        let state = state_with_user("hunter2", &key);
        let auth = StateAuthenticator { state: Arc::new(StateStore::ephemeral(state)), master_key: key };

        assert!(auth.resolve("svc_orders", "app_main").is_ok());
    }

    #[tokio::test]
    async fn authentication_rejects_every_way_a_client_can_be_wrong() {
        let key = Arc::new(MasterKey::generate());
        let mut state = state_with_user("hunter2", &key);
        state.pools.insert("other".into(), pool_config());
        state.users.insert("blocked".into(), {
            let mut u = UserConfig::new(vec!["app_main".into()]);
            u.disabled = true;
            u
        });
        state
            .secrets
            .put(&key, havuz_secrets::user_verifier("blocked"), &ScramVerifier::from_password("x").encode())
            .unwrap();

        let auth = StateAuthenticator { state: Arc::new(StateStore::ephemeral(state)), master_key: key };

        assert_eq!(auth.resolve("ghost", "app_main").unwrap_err(), AuthDenial::UnknownUser);
        assert_eq!(
            auth.resolve("svc_orders", "missing").unwrap_err(),
            AuthDenial::UnknownPool { pool: "missing".into() }
        );
        assert_eq!(
            auth.resolve("svc_orders", "other").unwrap_err(),
            AuthDenial::NotGranted { user: "svc_orders".into(), pool: "other".into() }
        );
        assert_eq!(auth.resolve("blocked", "app_main").unwrap_err(), AuthDenial::Disabled);
    }

    #[tokio::test]
    async fn a_user_without_a_stored_verifier_cannot_authenticate() {
        let key = Arc::new(MasterKey::generate());
        let mut state = State::default();
        state.pools.insert("app_main".into(), pool_config());
        state.users.insert("svc_orders".into(), UserConfig::new(vec!["app_main".into()]));
        // No secret stored for this user.

        let auth = StateAuthenticator { state: Arc::new(StateStore::ephemeral(state)), master_key: key };
        assert_eq!(auth.resolve("svc_orders", "app_main").unwrap_err(), AuthDenial::UnknownUser);
    }

    #[tokio::test]
    async fn the_descriptor_is_the_registry_entry() {
        let family = family_for(Arc::new(StateStore::ephemeral(State::default())), MasterKey::generate());
        assert_eq!(family.descriptor().id, "postgres");
        assert!(family.descriptor().capabilities.scram_sha256);
    }

    #[tokio::test]
    async fn probing_an_unconfigured_pool_reports_no_route() {
        let family = family_for(Arc::new(StateStore::ephemeral(State::default())), MasterKey::generate());
        assert!(matches!(family.probe("nope").await.unwrap_err(), ProtoError::NoRoute(_)));
    }
}
