//! Wiring: state -> pools -> sessions.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use havuz_core::state::{PoolConfig, State};
use havuz_core::{SslMode, StateStore};
use havuz_proto::{
    BackendConn, PinRegistry, PoolMode, Probe, ProtoError, ProtoResult, ProtocolFamily, ResetOutcome, ServeOutcome,
    SessionState,
};
use havuz_registry::FamilyDescriptor;
use havuz_secrets::MasterKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::backend::{BackendConfig, PgConnector};
use crate::cancel::{CancelKey, CancelRegistry, CancelTarget};
use crate::group::{GroupSnapshot, PoolGroup};
use crate::holder::HolderRegistry;
use crate::protocol::{sqlstate, Message};
use crate::scram::ScramVerifier;
use crate::session::{complete_startup, AuthDenial, Authenticator, ClientHandshake, HandshakeOutcome};
use crate::sessions::SessionRegistry;
use crate::trace::{TraceContext, TraceError, TraceStore};

const CANCEL_TIMEOUT: Duration = Duration::from_secs(3);

/// Postgres family: one listener, many pools.
pub struct PgFamily {
    state: Arc<StateStore>,
    master_key: Arc<MasterKey>,
    pools: RwLock<HashMap<String, Arc<PoolGroup>>>,
    cancels: Arc<CancelRegistry>,
    pins: Arc<PinRegistry>,
    traces: Arc<TraceStore>,
    holders: Arc<HolderRegistry>,
    listener_base: RwLock<Option<ListenerBase>>,
    dedicated_listeners: Mutex<HashMap<String, DedicatedListener>>,
    listener_routes: RwLock<HashMap<u16, String>>,
    live_clients: Arc<AtomicU64>,
    max_clients: AtomicU64,
    sessions: Arc<SessionRegistry>,
    handshake: ClientHandshake<StateAuthenticator>,
}

#[derive(Debug, Clone, Copy)]
struct ListenerBase {
    ip: IpAddr,
    shared_port: u16,
}

struct DedicatedListener {
    port: u16,
    handle: JoinHandle<()>,
}

pub struct ClientPermit {
    live: Arc<AtomicU64>,
}

impl Drop for PgFamily {
    fn drop(&mut self) {
        if let Ok(listeners) = self.dedicated_listeners.get_mut() {
            for listener in listeners.values() {
                listener.handle.abort();
            }
        }
    }
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

impl PgFamily {
    pub fn new(state: Arc<StateStore>, master_key: Arc<MasterKey>) -> Arc<Self> {
        Self::with_traces(state, master_key, TraceStore::memory())
    }

    pub fn persistent(
        state: Arc<StateStore>,
        master_key: Arc<MasterKey>,
        trace_path: impl AsRef<std::path::Path>,
    ) -> Result<Arc<Self>, TraceError> {
        Ok(Self::with_traces(state, master_key, TraceStore::open(trace_path)?))
    }

    fn with_traces(state: Arc<StateStore>, master_key: Arc<MasterKey>, traces: Arc<TraceStore>) -> Arc<Self> {
        let authenticator = Arc::new(StateAuthenticator { state: state.clone(), master_key: master_key.clone() });
        Arc::new(Self {
            state,
            master_key,
            pools: RwLock::new(HashMap::new()),
            cancels: Arc::new(CancelRegistry::new()),
            pins: Arc::new(PinRegistry::new()),
            traces,
            holders: HolderRegistry::new(),
            listener_base: RwLock::new(None),
            dedicated_listeners: Mutex::new(HashMap::new()),
            listener_routes: RwLock::new(HashMap::new()),
            live_clients: Arc::new(AtomicU64::new(0)),
            max_clients: AtomicU64::new(u64::MAX),
            sessions: SessionRegistry::new(),
            handshake: ClientHandshake::new(authenticator),
        })
    }

    /// Who is connected right now, and the only way to disconnect them.
    pub fn sessions(&self) -> &Arc<SessionRegistry> {
        &self.sessions
    }

    pub fn cancels(&self) -> &Arc<CancelRegistry> {
        &self.cancels
    }

    /// Why sessions stopped being shareable. Served by the admin API.
    pub fn pins(&self) -> &Arc<PinRegistry> {
        &self.pins
    }

    pub fn traces(&self) -> &Arc<TraceStore> {
        &self.traces
    }

    pub fn holders(&self) -> &Arc<HolderRegistry> {
        &self.holders
    }

    pub fn configure_listeners(&self, shared: SocketAddr, max_clients: u32) {
        *self.listener_base.write().expect("listener base poisoned") =
            Some(ListenerBase { ip: shared.ip(), shared_port: shared.port() });
        self.max_clients.store(max_clients as u64, Ordering::Relaxed);
    }

    pub fn try_acquire_client(&self) -> Option<ClientPermit> {
        let max = self.max_clients.load(Ordering::Relaxed);
        self.live_clients
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| (live < max).then_some(live + 1))
            .ok()
            .map(|_| ClientPermit { live: self.live_clients.clone() })
    }

    pub fn live_clients(&self) -> u64 {
        self.live_clients.load(Ordering::Relaxed)
    }

    pub fn validate_listen_port(&self, pool: &str, port: Option<u16>) -> Result<(), ProtoError> {
        let Some(port) = port else { return Ok(()) };
        if port == 0 {
            return Err(ProtoError::backend("dedicated listen port must be between 1 and 65535"));
        }
        let Some(base) = *self.listener_base.read().expect("listener base poisoned") else {
            return Ok(());
        };
        if port == base.shared_port {
            return Err(ProtoError::backend(format!(
                "dedicated listen port {port} conflicts with the shared listener"
            )));
        }
        let listeners = self.dedicated_listeners.lock().expect("dedicated listener map poisoned");
        if listeners.get(pool).is_some_and(|listener| listener.port == port) {
            return Ok(());
        }
        if let Some((owner, _)) = listeners.iter().find(|(_, listener)| listener.port == port) {
            return Err(ProtoError::backend(format!("dedicated listen port {port} is already used by pool '{owner}'")));
        }
        drop(listeners);
        std::net::TcpListener::bind(SocketAddr::new(base.ip, port))
            .map(drop)
            .map_err(|error| ProtoError::backend(format!("cannot bind dedicated listen port {port}: {error}")))
    }

    /// Configured pooling mode for a pool, defaulting to the safest option if
    /// the pool vanished between routing and lookup.
    fn pool_mode(&self, name: &str) -> PoolMode {
        self.state.load().pools.get(name).map(|p| p.mode).unwrap_or(PoolMode::Session)
    }

    /// Bring the live pool set in line with the configuration.
    ///
    /// Pools that disappeared are drained rather than dropped, so in-flight
    /// clients finish their work instead of getting a reset connection.
    pub fn sync_pools(self: &Arc<Self>) -> Result<(), ProtoError> {
        let state = self.state.load();
        let mut pools = self.pools.write().expect("pool map poisoned");

        for (name, config) in &state.pools {
            if config.family != "postgres" || config.disabled {
                continue;
            }
            if pools.contains_key(name) {
                continue;
            }
            let group = PoolGroup::build(name, config, |target| self.connector_for(name, config, &state, target))?;
            let replicas = group.router().replicas().len();
            pools.insert(name.clone(), group);
            tracing::info!(
                pool = %name,
                mode = config.mode.as_str(),
                replicas,
                read_write_split = config.routing.read_write_split,
                "pool ready"
            );
        }

        pools.retain(|name, group| {
            let live = state.pools.get(name).is_some_and(|c| c.family == "postgres" && !c.disabled);
            if !live {
                tracing::info!(pool = %name, "pool removed from configuration, draining");
                group.drain();
            }
            live
        });

        drop(pools);
        self.sync_dedicated_listeners(&state)
    }

    /// Rebuild one pool after its runtime settings change.
    ///
    /// Existing sessions keep an `Arc` to the retired group and can finish;
    /// subsequent lookups use the freshly configured group. The old group must
    /// stay active because an idle transaction-mode client may need to borrow
    /// another backend before it disconnects.
    pub fn reload_pool(self: &Arc<Self>, name: &str) -> Result<(), ProtoError> {
        self.pools.write().expect("pool map poisoned").remove(name);
        self.sync_pools()
    }

    pub fn stop_dedicated_listeners(&self) {
        let mut listeners = self.dedicated_listeners.lock().expect("dedicated listener map poisoned");
        for (_, listener) in listeners.drain() {
            listener.handle.abort();
        }
        self.listener_routes.write().expect("listener routes poisoned").clear();
    }

    fn sync_dedicated_listeners(self: &Arc<Self>, state: &State) -> Result<(), ProtoError> {
        let Some(base) = *self.listener_base.read().expect("listener base poisoned") else {
            return Ok(());
        };
        let desired: HashMap<String, u16> = state
            .pools
            .iter()
            .filter(|(_, config)| config.family == "postgres" && !config.disabled)
            .filter_map(|(name, config)| config.listen_port.map(|port| (name.clone(), port)))
            .collect();

        let mut listeners = self.dedicated_listeners.lock().expect("dedicated listener map poisoned");
        let retired: Vec<_> = listeners
            .iter()
            .filter(|(name, listener)| desired.get(*name) != Some(&listener.port))
            .map(|(name, _)| name.clone())
            .collect();
        for name in retired {
            if let Some(listener) = listeners.remove(&name) {
                listener.handle.abort();
                self.listener_routes.write().expect("listener routes poisoned").remove(&listener.port);
                tracing::info!(pool = %name, port = listener.port, "dedicated pool listener stopped");
            }
        }

        for (name, port) in desired {
            if listeners.contains_key(&name) {
                continue;
            }
            if port == base.shared_port {
                return Err(ProtoError::backend(format!(
                    "pool '{name}' dedicated listen port {port} conflicts with the shared listener"
                )));
            }
            let addr = SocketAddr::new(base.ip, port);
            let std_listener = std::net::TcpListener::bind(addr)
                .map_err(|error| ProtoError::backend(format!("pool '{name}' cannot listen on {addr}: {error}")))?;
            std_listener
                .set_nonblocking(true)
                .map_err(|error| ProtoError::backend(format!("pool '{name}' cannot configure {addr}: {error}")))?;
            let listener = TcpListener::from_std(std_listener)
                .map_err(|error| ProtoError::backend(format!("pool '{name}' cannot use {addr}: {error}")))?;
            self.listener_routes.write().expect("listener routes poisoned").insert(port, name.clone());
            let weak = Arc::downgrade(self);
            let listener_pool = name.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let (socket, peer) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::warn!(pool = %listener_pool, %addr, %error, "dedicated listener accept failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let Some(family) = weak.upgrade() else { return };
                    let Some(permit) = family.try_acquire_client() else {
                        tracing::warn!(pool = %listener_pool, %peer, "refusing dedicated connection, global client limit reached");
                        drop(socket);
                        continue;
                    };
                    tokio::spawn(async move {
                        if let Err(error) = family.serve(socket, peer).await {
                            tracing::debug!(%peer, error = %error, kind = error.kind(), "dedicated session failed");
                        }
                        drop(permit);
                    });
                }
            });
            listeners.insert(name.clone(), DedicatedListener { port, handle });
            tracing::info!(pool = %name, %addr, "dedicated pool listener ready");
        }
        Ok(())
    }

    fn connector_for(
        &self,
        name: &str,
        config: &PoolConfig,
        state: &State,
        target: &havuz_core::Target,
    ) -> Result<PgConnector, ProtoError> {
        let password =
            state.secrets.get(&self.master_key, &havuz_secrets::pool_backend_password(name)).unwrap_or_default();

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
            user: config.backend_user.clone(),
            password,
            ssl_mode,
            tls,
            application_name: format!("havuz/{name}"),
            supports_discard_all: profile.quirks.supports_discard_all,
        }))
    }

    fn pool(&self, name: &str) -> Option<Arc<PoolGroup>> {
        self.pools.read().expect("pool map poisoned").get(name).cloned()
    }

    pub fn snapshots(&self) -> Vec<havuz_pool::PoolSnapshot> {
        let pools = self.pools.read().expect("pool map poisoned");
        let mut out: Vec<_> = pools.values().map(|g| g.combined_pool_snapshot()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Per-target detail: replica health, lag and routing distribution.
    pub fn group_snapshots(&self) -> Vec<GroupSnapshot> {
        let pools = self.pools.read().expect("pool map poisoned");
        let mut out: Vec<_> = pools.values().map(|g| g.snapshot()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

#[async_trait]
impl ProtocolFamily for PgFamily {
    fn descriptor(&self) -> &'static FamilyDescriptor {
        havuz_registry::family("postgres").expect("postgres is always registered")
    }

    async fn serve(&self, io: TcpStream, peer: SocketAddr) -> ProtoResult<ServeOutcome> {
        let local_port = io.local_addr().map_err(ProtoError::Io)?.port();
        let forced_pool = self.listener_routes.read().expect("listener routes poisoned").get(&local_port).cloned();
        let (mut client, outcome) = self.handshake.run_for_pool(io, peer, forced_pool.as_deref()).await?;

        let (identity, startup_params) = match outcome {
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
            HandshakeOutcome::Established { identity, startup_params } => (identity, startup_params),
        };

        let Some(group) = self.pool(&identity.pool) else {
            let _ =
                Message::fatal(sqlstate::UNDEFINED_DATABASE, &format!("pool \"{}\" is not available", identity.pool))
                    .write(&mut client)
                    .await;
            return Err(ProtoError::NoRoute(identity.pool));
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
        let session = match self.sessions.register(
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
        };
        let holder = self.holders.session(trace_context.clone(), mode);
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
                    havuz_pool::PoolError::Timeout { .. } => {
                        (sqlstate::TOO_MANY_CONNECTIONS, format!("{e}; {}", self.holders.timeout_hint(&identity.pool)))
                    }
                    havuz_pool::PoolError::Unavailable { .. } => (sqlstate::CANNOT_CONNECT_NOW, e.to_string()),
                    havuz_pool::PoolError::Connect { .. } => (sqlstate::CANNOT_CONNECT_NOW, e.to_string()),
                };
                self.traces.record_failure(
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
                &self.traces,
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
                &self.traces,
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
                    self.pins.record(&identity.user, identity.application_name.as_deref(), reason);
                    tracing::info!(
                        user = %identity.user,
                        pool = %identity.pool,
                        application = identity.application_name.as_deref().unwrap_or("-"),
                        reason = %reason,
                        "session was pinned and could not be multiplexed"
                    );
                }
                None => self.pins.record_clean(),
            }
        }

        Ok(outcome)
    }

    async fn probe(&self, pool_name: &str) -> ProtoResult<Probe> {
        let group = self.pool(pool_name).ok_or_else(|| ProtoError::NoRoute(pool_name.to_string()))?;
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
struct StateAuthenticator {
    state: Arc<StateStore>,
    master_key: Arc<MasterKey>,
}

impl Authenticator for StateAuthenticator {
    fn verifier(&self, user: &str, pool: &str) -> Result<ScramVerifier, AuthDenial> {
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

        ScramVerifier::parse(&stored).map_err(|e| {
            tracing::error!(%user, error = %e, "stored verifier is unusable");
            AuthDenial::UnknownUser
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_core::state::{PoolLimits, Target, UserConfig};
    use havuz_registry::PoolMode;

    async fn family_with(state: State) -> (Arc<PgFamily>, Arc<MasterKey>) {
        let key = Arc::new(MasterKey::generate());
        let store = Arc::new(StateStore::ephemeral(state));
        (PgFamily::new(store, key.clone()), key)
    }

    fn pool_config() -> PoolConfig {
        PoolConfig {
            family: "postgres".into(),
            profile: None,
            mode: PoolMode::Session,
            targets: vec![Target::new("127.0.0.1", 1)],
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
    async fn sync_creates_a_pool_per_configured_postgres_pool() {
        let key = MasterKey::generate();
        let state = state_with_user("hunter2", &key);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = PgFamily::new(store, Arc::new(key));

        family.sync_pools().unwrap();
        let snapshots = family.snapshots();
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
        let family = PgFamily::new(store, Arc::new(key));
        family.sync_pools().unwrap();
        assert!(family.snapshots().is_empty());
    }

    #[tokio::test]
    async fn sync_is_idempotent_and_does_not_recreate_live_pools() {
        let key = MasterKey::generate();
        let state = state_with_user("hunter2", &key);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = PgFamily::new(store, Arc::new(key));

        family.sync_pools().unwrap();
        let first = Arc::as_ptr(&family.pool("app_main").unwrap());
        family.sync_pools().unwrap();
        let second = Arc::as_ptr(&family.pool("app_main").unwrap());

        assert_eq!(first, second, "resyncing must not tear down a working pool");
    }

    #[tokio::test]
    async fn reload_replaces_lookups_without_draining_existing_sessions() {
        let key = MasterKey::generate();
        let state = state_with_user("hunter2", &key);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = PgFamily::new(store.clone(), Arc::new(key));
        family.sync_pools().unwrap();
        let old = family.pool("app_main").unwrap();

        store
            .update(|s| {
                s.pools.get_mut("app_main").unwrap().mode = PoolMode::Transaction;
            })
            .await
            .unwrap();
        family.reload_pool("app_main").unwrap();

        let new = family.pool("app_main").unwrap();
        assert!(!Arc::ptr_eq(&old, &new), "new connections must use the replacement");
        assert_eq!(new.mode(), PoolMode::Transaction);
        assert_eq!(
            old.primary().status(),
            havuz_pool::PoolStatus::Active,
            "established clients must be able to finish against the old group"
        );
    }

    #[tokio::test]
    async fn dedicated_listener_follows_pool_configuration() {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dedicated_port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let shared = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();

        let key = MasterKey::generate();
        let mut state = state_with_user("hunter2", &key);
        state.pools.get_mut("app_main").unwrap().listen_port = Some(dedicated_port);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = PgFamily::new(store.clone(), Arc::new(key));
        family.configure_listeners(shared, 100);
        family.sync_pools().unwrap();

        let socket = TcpStream::connect(("127.0.0.1", dedicated_port)).await.expect("dedicated port must open");
        drop(socket);

        store.update(|state| state.pools.get_mut("app_main").unwrap().listen_port = None).await.unwrap();
        family.sync_pools().unwrap();
        assert!(TcpStream::connect(("127.0.0.1", dedicated_port)).await.is_err(), "removed port must close");
    }

    #[tokio::test]
    async fn occupied_or_shared_dedicated_ports_are_rejected_before_state_changes() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let shared = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let key = MasterKey::generate();
        let family = PgFamily::new(Arc::new(StateStore::ephemeral(state_with_user("hunter2", &key))), Arc::new(key));
        family.configure_listeners(shared, 100);

        assert!(family.validate_listen_port("app_main", Some(occupied_port)).is_err());
        assert!(family.validate_listen_port("app_main", Some(shared.port())).is_err());
    }

    #[tokio::test]
    async fn removing_a_pool_from_config_drains_it() {
        let key = MasterKey::generate();
        let state = state_with_user("hunter2", &key);
        let store = Arc::new(StateStore::ephemeral(state));
        let family = PgFamily::new(store.clone(), Arc::new(key));
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
        assert!(family.snapshots().is_empty());
    }

    #[tokio::test]
    async fn authentication_resolves_a_granted_user() {
        let key = Arc::new(MasterKey::generate());
        let state = state_with_user("hunter2", &key);
        let auth = StateAuthenticator { state: Arc::new(StateStore::ephemeral(state)), master_key: key };

        assert!(auth.verifier("svc_orders", "app_main").is_ok());
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

        assert_eq!(auth.verifier("ghost", "app_main").unwrap_err(), AuthDenial::UnknownUser);
        assert_eq!(
            auth.verifier("svc_orders", "missing").unwrap_err(),
            AuthDenial::UnknownPool { pool: "missing".into() }
        );
        assert_eq!(
            auth.verifier("svc_orders", "other").unwrap_err(),
            AuthDenial::NotGranted { user: "svc_orders".into(), pool: "other".into() }
        );
        assert_eq!(auth.verifier("blocked", "app_main").unwrap_err(), AuthDenial::Disabled);
    }

    #[tokio::test]
    async fn a_user_without_a_stored_verifier_cannot_authenticate() {
        let key = Arc::new(MasterKey::generate());
        let mut state = State::default();
        state.pools.insert("app_main".into(), pool_config());
        state.users.insert("svc_orders".into(), UserConfig::new(vec!["app_main".into()]));
        // No secret stored for this user.

        let auth = StateAuthenticator { state: Arc::new(StateStore::ephemeral(state)), master_key: key };
        assert_eq!(auth.verifier("svc_orders", "app_main").unwrap_err(), AuthDenial::UnknownUser);
    }

    #[tokio::test]
    async fn the_descriptor_is_the_registry_entry() {
        let (family, _) = family_with(State::default()).await;
        assert_eq!(family.descriptor().id, "postgres");
        assert!(family.descriptor().capabilities.scram_sha256);
    }

    #[tokio::test]
    async fn probing_an_unconfigured_pool_reports_no_route() {
        let (family, _) = family_with(State::default()).await;
        assert!(matches!(family.probe("nope").await.unwrap_err(), ProtoError::NoRoute(_)));
    }
}
