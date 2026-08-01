//! HTTP routes.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use havuz_core::state::{BackendAuth, PoolConfig, PoolLimits, RoutingConfig, Target, TraceLevel, UserConfig, Warning};
use havuz_pool::PoolSnapshot;
use havuz_registry::{FieldRole, PoolMode};
use havuz_secrets::ScramVerifier;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;

use crate::error::ApiError;
use crate::state::AdminState;
use crate::{auth, metrics, ui};

pub fn router(state: AdminState) -> Router {
    let api = Router::new()
        .route("/families", get(list_families))
        .route("/pools", get(list_pools).post(create_pool))
        .route("/pools/{name}", get(get_pool).patch(update_pool).delete(delete_pool))
        .route("/pools/{name}/pause", post(pause_pool))
        .route("/pools/{name}/resume", post(resume_pool))
        .route("/pools/{name}/drain", post(drain_pool))
        .route("/pools/{name}/probe", post(probe_pool))
        .route("/pools/{name}/targets", get(pool_targets))
        .route("/pools/{name}/identities", get(pool_identities))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{name}", patch(update_user).delete(delete_user))
        .route("/users/{name}/kick", post(kick_user))
        .route("/sessions", get(list_sessions))
        .route("/config", get(get_config))
        .route("/summary", get(get_summary))
        .route("/pins", get(get_pins).delete(reset_pins))
        .route("/traces", get(get_traces).delete(clear_traces))
        .route("/traces/{id}", get(get_trace));

    Router::new()
        .nest("/api/v1", api)
        .route("/metrics", get(prometheus))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .fallback(ui::serve)
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::require_token))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// --- families ---

/// The UI builds its "Add Database" form from this. Adding a family never
/// requires a frontend change.
async fn list_families() -> impl IntoResponse {
    let families: Vec<_> = havuz_registry::families()
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "label": f.label,
                "description": f.description,
                "maturity": f.maturity,
                "usable": f.maturity.is_usable(),
                "default_port": f.default_port,
                "capabilities": f.capabilities,
                "pool_modes": f.pool_modes,
                "default_pool_mode": f.default_pool_mode,
                "profiles": f.profiles,
                "schema": f.json_schema(),
            })
        })
        .collect();
    Json(json!({ "families": families }))
}

// --- pools ---

#[derive(Debug, Serialize)]
struct PoolView {
    name: String,
    family: String,
    profile: Option<String>,
    mode: PoolMode,
    database: String,
    backend_user: String,
    listen_port: u16,
    backend_auth: BackendAuth,
    trace: TraceLevel,
    /// Whether a password is stored. Never the password itself.
    has_backend_password: bool,
    targets: Vec<Target>,
    limits: PoolLimits,
    settings: serde_json::Map<String, serde_json::Value>,
    routing: RoutingConfig,
    replica_count: usize,
    disabled: bool,
    description: Option<String>,
    /// Configured best case, `null` in session mode where it cannot happen.
    configured_fan_in: Option<f32>,
    /// Total backend connections this pool may open, or `null` when clients
    /// authenticate as themselves and the ceiling depends on how many of them
    /// are connected at once.
    backend_ceiling: Option<u32>,
    runtime: Option<PoolSnapshot>,
}

fn pool_view(name: &str, config: &PoolConfig, state: &havuz_core::State, runtime: Option<PoolSnapshot>) -> PoolView {
    PoolView {
        name: name.to_string(),
        family: config.family.clone(),
        profile: config.profile.clone(),
        mode: config.mode,
        database: config.database.clone(),
        backend_user: config.backend_user.clone(),
        listen_port: config.listen_port,
        backend_auth: config.backend_auth,
        trace: config.trace,
        has_backend_password: state.secrets.contains(&havuz_secrets::pool_backend_password(name)),
        targets: config.targets.clone(),
        limits: config.limits.clone(),
        settings: config.settings.clone(),
        routing: config.routing.clone(),
        replica_count: config.replicas().count(),
        disabled: config.disabled,
        description: config.description.clone(),
        configured_fan_in: config.fan_in(),
        backend_ceiling: config.backend_ceiling(),
        runtime,
    }
}

async fn list_pools(State(state): State<AdminState>) -> impl IntoResponse {
    let current = state.store.load();
    let snapshots: BTreeMap<String, PoolSnapshot> =
        state.families.pool_snapshots().into_iter().map(|s| (s.name.clone(), s)).collect();

    let pools: Vec<_> = current
        .pools
        .iter()
        .map(|(name, config)| pool_view(name, config, &current, snapshots.get(name).cloned()))
        .collect();

    Json(json!({ "pools": pools, "warnings": current.warnings() }))
}

async fn get_pool(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let current = state.store.load();
    let config = current.pools.get(&name).ok_or_else(|| ApiError::NotFound(format!("pool '{name}'")))?;
    let runtime = state.families.pool_snapshots().into_iter().find(|s| s.name == name);
    Ok(Json(pool_view(&name, config, &current, runtime)))
}

/// Everything a pool needs, and nothing the family already declared.
///
/// The connection details — host, port, database, account, password — arrive in
/// `settings` under whatever names the family chose, and are read back through
/// [`havuz_registry::FieldRole`]. That is deliberate: the dashboard used to
/// lift five hardcoded Postgres field names out of the form before submitting,
/// so "adding a family never touches the frontend" was true of the rendering
/// and false of the submitting.
#[derive(Debug, Deserialize)]
struct CreatePool {
    name: String,
    family: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    mode: Option<PoolMode>,
    /// Optional. Omitted means one primary, built from the connection fields.
    /// Supplied means the caller is configuring replicas as well.
    #[serde(default)]
    targets: Option<Vec<Target>>,
    /// Required: a pool nobody can reach is not a pool.
    listen_port: u16,
    /// Whose credentials backend connections are opened with. Defaults to one
    /// shared service account, which is what every other pooler does.
    #[serde(default)]
    backend_auth: BackendAuth,
    /// How much of this pool's traffic is recorded. Defaults to statements
    /// only: the timings and outcomes are what a pooler is asked to explain,
    /// and the row values are the part that turns a trace into a copy of the
    /// data.
    #[serde(default)]
    trace: TraceLevel,
    #[serde(default)]
    limits: Option<PoolLimits>,
    #[serde(default)]
    settings: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    routing: Option<RoutingConfig>,
    #[serde(default)]
    description: Option<String>,
}

/// Reject a port before it is persisted, so a bad value is a `400` rather than
/// a pool that silently never listens.
///
/// Sharing a port with another pool is fine and is how a client picks between
/// them by database name; sharing it with a *different family* is not, and
/// neither is taking the port this process serves its own API on.
fn check_listen_port(state: &AdminState, pool: &str, port: u16, family: &str) -> Result<(), ApiError> {
    if port == 0 {
        return Err(ApiError::BadRequest("listen_port must be between 1 and 65535".into()));
    }
    if state.reserved_port == Some(port) {
        return Err(ApiError::BadRequest(format!("port {port} is the admin listener")));
    }
    let current = state.store.load();
    if let Some((owner, config)) = current
        .pools
        .iter()
        .find(|(name, config)| name.as_str() != pool && config.listen_port == port && config.family != family)
    {
        return Err(ApiError::BadRequest(format!(
            "port {port} already serves pool '{owner}' of family '{}'; a listener speaks one protocol",
            config.family
        )));
    }
    Ok(())
}

async fn create_pool(
    State(state): State<AdminState>,
    Json(body): Json<CreatePool>,
) -> Result<impl IntoResponse, ApiError> {
    check_listen_port(&state, &body.name, body.listen_port, &body.family)?;
    if body.backend_auth.is_per_user() && !state.client_tls {
        // The handshake refuses this per connection anyway; catching it here
        // means the operator finds out while creating the pool rather than
        // when the first client fails to connect to it.
        return Err(ApiError::BadRequest(
            "per-user authentication asks clients for their password, so it needs client-facing TLS; \
             set server.tls.cert and server.tls.key and restart"
                .into(),
        ));
    }
    let (family, profile) = havuz_registry::resolve(&body.family, body.profile.as_deref())
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    if body.backend_auth.is_per_user() && !family.capabilities.per_user_auth {
        // Refusing beats accepting and quietly pooling everyone through the
        // service account, which looks identical in the UI and nothing like it
        // in the database's own view of who is connected.
        return Err(ApiError::BadRequest(format!(
            "family '{}' cannot open backend connections as the connecting client; use a shared service account",
            family.id
        )));
    }

    // Validate the family-specific settings against the same declaration the
    // UI rendered its form from.
    //
    // Under per-user auth every client arrives with its own credential, so the
    // service account stops being the way in and becomes an optional fallback
    // for probes and for users that have not been moved across yet. Leaving it
    // blank there is a legitimate choice — a pool nobody but named users can
    // open — so the family's `required` flag is relaxed for credential fields
    // rather than being enforced against a mode it predates.
    let credentials_optional = body.backend_auth.is_per_user();
    for field in family.config_fields {
        let field = match field.role {
            Some(FieldRole::User | FieldRole::Password) if credentials_optional => field.optional(),
            _ => *field,
        };
        field.validate(body.settings.get(field.name)).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(unknown) = body.settings.keys().find(|k| !family.config_fields.iter().any(|f| f.name == k.as_str())) {
        return Err(ApiError::BadRequest(format!("unknown setting '{unknown}' for family '{}'", family.id)));
    }

    // Read the form back through the roles the family declared, rather than
    // through field names this crate would otherwise have to know.
    let connection = family.connection(&body.settings);
    let targets = match body.targets {
        Some(targets) if !targets.is_empty() => targets,
        _ => vec![Target::new(&connection.host, connection.port)],
    };

    // Credentials never reach the state document; they go to the sealed store
    // keyed by pool name.
    let mut settings = body.settings;
    for secret in family.secret_fields() {
        settings.remove(secret);
    }

    let mode = body.mode.unwrap_or(family.default_pool_mode);
    let name = body.name.clone();
    let password = connection.password.clone();

    let config = PoolConfig {
        family: family.id.to_string(),
        profile: Some(profile.id.to_string()),
        mode,
        targets,
        backend_user: connection.user,
        database: connection.database,
        listen_port: body.listen_port,
        limits: body.limits.unwrap_or_default(),
        settings,
        routing: body.routing.unwrap_or_default(),
        backend_auth: body.backend_auth,
        trace: body.trace,
        disabled: false,
        description: body.description,
    };

    let master_key = state.master_key.clone();
    let created = state
        .store
        .update(move |s| {
            if s.pools.contains_key(&name) {
                return false;
            }
            if let Some(password) = &password {
                let _ = s.secrets.put(&master_key, havuz_secrets::pool_backend_password(&name), password);
            }
            s.pools.insert(name.clone(), config);
            true
        })
        .await?;

    if !created {
        return Err(ApiError::Conflict(format!("pool '{}'", body.name)));
    }

    state.families.sync_all().map_err(|e| ApiError::Internal(e.to_string()))?;

    let current = state.store.load();
    let config = current.pools.get(&body.name).expect("just inserted");
    Ok((axum::http::StatusCode::CREATED, Json(pool_view(&body.name, config, &current, None))))
}

#[derive(Debug, Deserialize)]
struct UpdatePool {
    #[serde(default)]
    mode: Option<PoolMode>,
    #[serde(default)]
    max_size: Option<u32>,
    #[serde(default)]
    max_client_connections: Option<u32>,
    #[serde(default)]
    listen_port: Option<u16>,
    /// Changeable after creation on purpose: turning capture up for the length
    /// of an incident and back down afterwards is the normal way to use it, and
    /// having to recreate the pool would make that impossible.
    #[serde(default)]
    trace: Option<TraceLevel>,
}

async fn update_pool(
    State(state): State<AdminState>,
    Path(name): Path<String>,
    Json(body): Json<UpdatePool>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(family) = state.store.load().pools.get(&name).map(|pool| pool.family.clone()) else {
        return Err(ApiError::NotFound(format!("pool '{name}'")));
    };
    if let Some(listen_port) = body.listen_port {
        check_listen_port(&state, &name, listen_port, &family)?;
    }
    let update_name = name.clone();
    let found = state
        .store
        .update(move |s| match s.pools.get_mut(&update_name) {
            Some(pool) => {
                if let Some(mode) = body.mode {
                    pool.mode = mode;
                }
                if let Some(max_size) = body.max_size {
                    pool.limits.max_size = max_size;
                }
                if let Some(max_clients) = body.max_client_connections {
                    pool.limits.max_client_connections = max_clients;
                }
                if let Some(listen_port) = body.listen_port {
                    pool.listen_port = listen_port;
                }
                if let Some(trace) = body.trace {
                    pool.trace = trace;
                }
                true
            }
            None => false,
        })
        .await?;

    if !found {
        return Err(ApiError::NotFound(format!("pool '{name}'")));
    }

    state
        .families
        .get(&family)
        .ok_or_else(|| ApiError::Internal(format!("no driver for family '{family}'")))?
        .reload_pool(&name)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let current = state.store.load();
    let config = current.pools.get(&name).expect("updated pool exists");
    let runtime = state.families.pool_snapshots().into_iter().find(|s| s.name == name);
    Ok(Json(pool_view(&name, config, &current, runtime)))
}

async fn delete_pool(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let removed = state
        .store
        .update({
            let name = name.clone();
            move |s| {
                let removed = s.pools.remove(&name).is_some();
                // A user left pointing at a deleted pool would fail validation
                // and block the whole delete, so the grant goes with it.
                for user in s.users.values_mut() {
                    user.pools.retain(|p| p != &name);
                }
                s.users.retain(|_, u| !u.pools.is_empty());
                // Drop the now-unreachable credential rather than leaving
                // ciphertext behind forever.
                let live: Vec<String> = s.pools.keys().cloned().collect();
                s.secrets.retain_owners("pool", &live);
                removed
            }
        })
        .await?;

    if !removed {
        return Err(ApiError::NotFound(format!("pool '{name}'")));
    }
    state.families.sync_all().map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(json!({ "deleted": name })))
}

async fn pause_pool(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    set_disabled(&state, &name, true).await?;
    Ok(Json(json!({ "pool": name, "status": "paused" })))
}

async fn resume_pool(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    set_disabled(&state, &name, false).await?;
    Ok(Json(json!({ "pool": name, "status": "active" })))
}

async fn set_disabled(state: &AdminState, name: &str, disabled: bool) -> Result<(), ApiError> {
    if !disabled {
        // Resuming reopens a socket, so the port has to be checked again: it
        // may have been claimed while this pool was down.
        let current = state.store.load();
        let pool = current.pools.get(name).ok_or_else(|| ApiError::NotFound(format!("pool '{name}'")))?;
        check_listen_port(state, name, pool.listen_port, &pool.family)?;
    }
    let found = state
        .store
        .update({
            let name = name.to_string();
            move |s| match s.pools.get_mut(&name) {
                Some(pool) => {
                    pool.disabled = disabled;
                    true
                }
                None => false,
            }
        })
        .await?;

    if !found {
        return Err(ApiError::NotFound(format!("pool '{name}'")));
    }
    state.families.sync_all().map_err(|e| ApiError::Internal(e.to_string()))
}

async fn drain_pool(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    if !state.store.load().pools.contains_key(&name) {
        return Err(ApiError::NotFound(format!("pool '{name}'")));
    }
    Ok(Json(json!({ "pool": name, "status": "draining" })))
}

async fn probe_pool(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let family = state
        .families
        .for_pool(&state.store.load(), &name)
        .ok_or_else(|| ApiError::NotFound(format!("pool '{name}'")))?
        .clone();
    match family.probe(&name).await {
        Ok(probe) => Ok(Json(json!({ "ok": true, "probe": probe }))),
        // A failed probe is information, not a server fault: the UI shows the
        // reason next to the Test Connection button.
        Err(e) => Ok(Json(json!({ "ok": false, "error": e.to_string(), "kind": e.kind() }))),
    }
}

// --- users ---

#[derive(Debug, Serialize)]
struct UserView {
    name: String,
    pools: Vec<String>,
    max_client_connections: u32,
    /// Connects to the database as itself rather than as the pool's service
    /// account. Only takes effect on pools configured for per-user auth.
    own_backend_role: bool,
    read_only: bool,
    disabled: bool,
    description: Option<String>,
    has_password: bool,
    /// Sessions this user has attached right now.
    live_sessions: u64,
}

async fn list_users(State(state): State<AdminState>) -> impl IntoResponse {
    let current = state.store.load();
    // Live session counts turn the page from a list of records into something
    // an operator can act on: disabling a user with 40 connections attached
    // means something quite different from disabling one with none.
    let live = state.registries.sessions.counts_by_user();
    let users: Vec<_> = current
        .users
        .iter()
        .map(|(name, u)| UserView {
            name: name.clone(),
            pools: u.pools.clone(),
            max_client_connections: u.max_client_connections,
            own_backend_role: u.own_backend_role,
            read_only: u.read_only,
            disabled: u.disabled,
            description: u.description.clone(),
            has_password: current.secrets.contains(&havuz_secrets::user_verifier(name)),
            live_sessions: live.get(name).copied().unwrap_or(0),
        })
        .collect();
    Json(json!({ "users": users }))
}

#[derive(Debug, Deserialize)]
struct UpdateUser {
    /// Absent means "leave alone". Present-but-empty is rejected by
    /// validation, because a user with no grants could never connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pools: Option<Vec<String>>,
    #[serde(default)]
    max_client_connections: Option<u32>,
    /// Move this user on or off its own database role. Existing connections
    /// under the old identity finish; new ones use the new one.
    #[serde(default)]
    own_backend_role: Option<bool>,
    #[serde(default)]
    read_only: Option<bool>,
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default)]
    description: Option<Option<String>>,
    /// Replace the password. The plaintext is turned into a verifier here and
    /// never stored.
    #[serde(default)]
    password: Option<String>,
    /// End this user's live sessions as part of the same request.
    ///
    /// Disabling a user only refuses the *next* handshake, so an operator
    /// revoking access during an incident almost always wants this too.
    #[serde(default)]
    kick: bool,
}

async fn update_user(
    State(state): State<AdminState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateUser>,
) -> Result<impl IntoResponse, ApiError> {
    if body.password.as_ref().is_some_and(|p| p.is_empty()) {
        return Err(ApiError::BadRequest("password must not be empty".into()));
    }
    if body.pools.as_ref().is_some_and(|p| p.is_empty()) {
        return Err(ApiError::BadRequest("a user needs at least one pool grant; delete the user instead".into()));
    }

    let verifier = body.password.as_deref().map(|p| ScramVerifier::from_password(p).encode());
    let master_key = state.master_key.clone();

    let found = state
        .store
        .update({
            let name = name.clone();
            move |s| {
                let Some(user) = s.users.get_mut(&name) else { return false };
                if let Some(pools) = body.pools {
                    user.pools = pools;
                }
                if let Some(max) = body.max_client_connections {
                    user.max_client_connections = max;
                }
                if let Some(own) = body.own_backend_role {
                    user.own_backend_role = own;
                }
                if let Some(read_only) = body.read_only {
                    user.read_only = read_only;
                }
                if let Some(disabled) = body.disabled {
                    user.disabled = disabled;
                }
                if let Some(description) = body.description {
                    user.description = description;
                }
                if let Some(verifier) = verifier {
                    let _ = s.secrets.put(&master_key, havuz_secrets::user_verifier(&name), &verifier);
                }
                true
            }
        })
        .await?;

    if !found {
        return Err(ApiError::NotFound(format!("user '{name}'")));
    }

    // Only after the change is durable. Kicking first would drop sessions that
    // a failed validation then leaves entitled to reconnect.
    let kicked = if body.kick { state.registries.sessions.kick_user(&name) } else { 0 };

    Ok(Json(json!({ "updated": name, "kicked": kicked })))
}

/// End every live session belonging to a user.
///
/// Graceful by construction: each session stops at its next statement
/// boundary, because ending one mid-response would return a half-read backend
/// to the pool. A client running a long query goes when that query finishes.
async fn kick_user(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    if !state.store.load().users.contains_key(&name) {
        return Err(ApiError::NotFound(format!("user '{name}'")));
    }
    let kicked = state.registries.sessions.kick_user(&name);
    Ok(Json(json!({ "user": name, "kicked": kicked })))
}

/// Who is connected right now.
async fn list_sessions(State(state): State<AdminState>) -> impl IntoResponse {
    Json(json!({ "sessions": state.registries.sessions.snapshot() }))
}

#[derive(Debug, Deserialize)]
struct CreateUser {
    name: String,
    password: String,
    pools: Vec<String>,
    #[serde(default)]
    max_client_connections: u32,
    #[serde(default)]
    own_backend_role: bool,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    description: Option<String>,
}

async fn create_user(
    State(state): State<AdminState>,
    Json(body): Json<CreateUser>,
) -> Result<impl IntoResponse, ApiError> {
    if body.password.is_empty() {
        return Err(ApiError::BadRequest("password must not be empty".into()));
    }

    // Derive the verifier here and drop the password immediately: it is never
    // written to disk, not even encrypted.
    let verifier = ScramVerifier::from_password(&body.password).encode();
    let name = body.name.clone();
    let master_key = state.master_key.clone();

    let config = UserConfig {
        pools: body.pools,
        max_client_connections: body.max_client_connections,
        own_backend_role: body.own_backend_role,
        read_only: body.read_only,
        disabled: false,
        description: body.description,
    };

    let created = state
        .store
        .update(move |s| {
            if s.users.contains_key(&name) {
                return false;
            }
            let _ = s.secrets.put(&master_key, havuz_secrets::user_verifier(&name), &verifier);
            s.users.insert(name.clone(), config);
            true
        })
        .await?;

    if !created {
        return Err(ApiError::Conflict(format!("user '{}'", body.name)));
    }

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "name": body.name,
            "connection_string": format!("postgresql://{}:<password>@<havuz-host>:5432/<pool>", body.name),
        })),
    ))
}

async fn delete_user(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let removed = state
        .store
        .update({
            let name = name.clone();
            move |s| {
                let removed = s.users.remove(&name).is_some();
                let live: Vec<String> = s.users.keys().cloned().collect();
                s.secrets.retain_owners("user", &live);
                removed
            }
        })
        .await?;

    if !removed {
        return Err(ApiError::NotFound(format!("user '{name}'")));
    }
    Ok(Json(json!({ "deleted": name })))
}

// --- overview ---

async fn get_config(State(state): State<AdminState>) -> impl IntoResponse {
    let current = state.store.load();
    // Secrets are omitted entirely rather than masked, so there is no shape to
    // reason about on the client side.
    Json(json!({
        "version": current.version,
        "pools": current.pools.len(),
        "users": current.users.len(),
        "warnings": current.warnings(),
    }))
}

async fn get_summary(State(state): State<AdminState>) -> impl IntoResponse {
    let snapshots = state.families.pool_snapshots();
    let current = state.store.load();

    let backend: u64 = snapshots.iter().map(|s| s.open).sum();
    let clients: u64 = snapshots.iter().map(|s| s.active + s.waiting).sum();
    let warnings: Vec<Warning> = current.warnings();

    Json(json!({
        "uptime_seconds": state.uptime_seconds(),
        "pools": snapshots.len(),
        "users": current.users.len(),
        "client_connections": clients,
        "backend_connections": backend,
        // The number the whole product exists to move.
        "fan_in": if backend == 0 { None } else { Some(clients as f32 / backend as f32) },
        "warnings": warnings,
        "pool_snapshots": snapshots,
    }))
}

/// Per-target detail: replica health, replication lag and where traffic went.
///
/// "Why is my replica idle?" is otherwise unanswerable, and the answer is
/// usually one of the primary_reasons counters rather than a broken replica.
async fn pool_targets(
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .families
        .target_reports()
        .into_iter()
        .find(|g| g.name == name)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("pool '{name}'")))
}

/// Who is holding connections of their own, and how many.
///
/// Empty for a pool with one service account, which is the default. The answer
/// lives here rather than in `/metrics` because it is unbounded in the number
/// of users, and a Prometheus series per user is how a monitoring bill becomes
/// an incident.
async fn pool_identities(
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let current = state.store.load();
    let Some(config) = current.pools.get(&name) else {
        return Err(ApiError::NotFound(format!("pool '{name}'")));
    };
    let identities: Vec<_> =
        state.families.backend_identities().into_iter().filter(|identity| identity.pool == name).collect();

    Ok(Json(json!({
        "pool": name,
        "backend_auth": config.backend_auth,
        // With per-user auth this is a per-user budget, so the total depends on
        // how many users are connected. Saying so beats printing a guess.
        "max_size_is_per_user": config.backend_auth.is_per_user(),
        "identities": identities,
    })))
}

/// Why transaction-mode sessions stopped being shareable.
///
/// The endpoint no competing pooler offers, and the one that turns "my pool is
/// full" into "turn off `SET application_name` in orders-api".
async fn get_pins(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.registries.pins.report())
}

async fn reset_pins(State(state): State<AdminState>) -> impl IntoResponse {
    state.registries.pins.reset();
    Json(json!({ "reset": true }))
}

async fn get_traces(
    State(state): State<AdminState>,
    Query(filter): Query<havuz_control::TraceFilter>,
) -> Result<impl IntoResponse, ApiError> {
    let trace_store = state.registries.traces;
    let traces = trace_store.list(&filter).map_err(|error| ApiError::Internal(error.to_string()))?;
    let total = trace_store.count(&filter).map_err(|error| ApiError::Internal(error.to_string()))?;
    let limit = filter.limit.unwrap_or(100).clamp(1, 500);
    let offset = filter.offset.unwrap_or(0);
    Ok(Json(json!({
        "active": trace_store.active(),
        "holders": state.registries.holders.snapshot(),
        "pool_snapshots": state.families.pool_snapshots(),
        "traces": traces,
        "pagination": { "total": total, "limit": limit, "offset": offset },
        "retention_days": havuz_control::RETENTION_DAYS,
        "result_limits": {
            "rows": havuz_control::MAX_RESULT_ROWS,
            "bytes": havuz_control::MAX_RESULT_BYTES,
        }
    })))
}

async fn get_trace(State(state): State<AdminState>, Path(id): Path<u64>) -> Result<impl IntoResponse, ApiError> {
    state
        .registries
        .traces
        .get(id)
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("query trace '{id}'")))
}

async fn clear_traces(State(state): State<AdminState>) -> Result<impl IntoResponse, ApiError> {
    let deleted = state.registries.traces.clear().map_err(|error| ApiError::Internal(error.to_string()))?;
    Ok(Json(json!({ "deleted": deleted })))
}

async fn prometheus(State(state): State<AdminState>) -> impl IntoResponse {
    let body = metrics::render(
        &state.families.pool_snapshots(),
        &state.families.target_reports(),
        &state.registries.pins.report(),
        state.uptime_seconds(),
    );
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

async fn readyz(State(state): State<AdminState>) -> impl IntoResponse {
    // Ready means "configuration loaded and pools constructed", not "every
    // database is reachable": a single unreachable replica must not take the
    // whole pooler out of a load balancer.
    let pools = state.store.load().pools.len();
    Json(json!({ "ready": true, "pools": pools }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use havuz_control::testing::FakeFamily;
    use havuz_core::{State as CoreState, StateStore};
    use havuz_secrets::MasterKey;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn app() -> (Router, AdminState) {
        build_app(None, true)
    }

    fn app_with_reserved(reserved: Option<u16>) -> (Router, AdminState) {
        build_app(reserved, true)
    }

    fn app_without_tls() -> (Router, AdminState) {
        build_app(None, false)
    }

    fn build_app(reserved: Option<u16>, client_tls: bool) -> (Router, AdminState) {
        let key = Arc::new(MasterKey::generate());
        let store = Arc::new(StateStore::ephemeral(CoreState::default()));
        let registries = havuz_control::Registries::ephemeral();
        let families = havuz_control::FamilySet::new(vec![FakeFamily::new(store.clone())]);
        let state = AdminState::new(
            store,
            key,
            families,
            registries,
            reserved,
            client_tls,
            &havuz_core::AdminAuth::None,
            false,
        );
        (router(state.clone()), state)
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    async fn get(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = app.clone().oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap()).await.unwrap();
        (response.status(), body_json(response).await)
    }

    async fn post(app: &Router, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        (response.status(), body_json(response).await)
    }

    async fn patch(app: &Router, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        (response.status(), body_json(response).await)
    }

    /// Exactly what the dashboard sends: the form, verbatim, plus the pooler
    /// settings. No connection field is repeated at the top level.
    fn pool_payload() -> serde_json::Value {
        json!({
            "name": "app_main",
            "family": "postgres",
            "mode": "session",
            "listen_port": 6432,
            "settings": {
                "host": "pg-primary.internal",
                "port": 5432,
                "database": "appdb",
                "username": "app",
                "password": "hunter2",
            },
            "limits": { "max_size": 3, "max_client_connections": 100 }
        })
    }

    #[tokio::test]
    async fn postgres_defaults_to_transaction_mode() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload.as_object_mut().unwrap().remove("mode");

        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["mode"], "transaction");
        assert!(body["configured_fan_in"].is_number());
    }

    #[tokio::test]
    async fn a_pool_can_be_reconfigured_without_deleting_it() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        let (status, body) = patch(
            &app,
            "/api/v1/pools/app_main",
            json!({ "mode": "transaction", "max_size": 12, "max_client_connections": 240 }),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["mode"], "transaction");
        assert_eq!(body["limits"]["max_size"], 12);
        assert_eq!(body["limits"]["max_client_connections"], 240);
        assert!(state.families.pool_snapshots().iter().any(|pool| pool.name == "app_main" && pool.max_size == 12));
    }

    #[tokio::test]
    async fn invalid_pool_reconfiguration_is_rejected_without_changing_state() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        let (status, _) = patch(&app, "/api/v1/pools/app_main", json!({ "max_size": 0 })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(state.store.load().pools["app_main"].limits.max_size, 3);
    }

    #[tokio::test]
    async fn a_pool_port_can_be_moved_without_recreating_the_pool() {
        let (app, state) = app();
        let mut payload = pool_payload();
        payload["listen_port"] = json!(5544);
        let (status, created) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::CREATED, "body: {created}");
        assert_eq!(created["listen_port"], 5544);

        let (_, updated) = patch(&app, "/api/v1/pools/app_main", json!({ "listen_port": 5545 })).await;
        assert_eq!(updated["listen_port"], 5545);
        assert_eq!(state.store.load().pools["app_main"].listen_port, 5545);
    }

    #[tokio::test]
    async fn two_pools_may_share_a_port() {
        // This is how a client picks between them by database name, and it is
        // the reason a port is not unique per pool.
        let (app, state) = app();
        let mut first = pool_payload();
        first["listen_port"] = json!(5544);
        let (status, body) = post(&app, "/api/v1/pools", first).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");

        let mut second = pool_payload();
        second["name"] = json!("reports");
        second["listen_port"] = json!(5544);
        let (status, body) = post(&app, "/api/v1/pools", second).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(state.store.load().listeners()[&5544].pools, ["app_main", "reports"]);
    }

    #[tokio::test]
    async fn a_pool_cannot_claim_the_admin_port() {
        let (app, state) = app_with_reserved(Some(7432));
        let mut payload = pool_payload();
        payload["listen_port"] = json!(7432);

        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert!(state.store.load().pools.is_empty(), "a rejected port must not persist the pool");
    }

    #[tokio::test]
    async fn a_listen_port_of_zero_is_rejected() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload["listen_port"] = json!(0);
        let (status, _) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn families_endpoint_carries_everything_the_ui_needs() {
        let (app, _) = app();
        let (status, body) = get(&app, "/api/v1/families").await;
        assert_eq!(status, StatusCode::OK);

        let families = body["families"].as_array().unwrap();
        let pg = families.iter().find(|f| f["id"] == "postgres").unwrap();
        assert_eq!(pg["usable"], true);
        assert_eq!(pg["default_port"], 5432);
        assert!(pg["schema"]["properties"]["host"].is_object(), "the form is generated from this");
        assert!(pg["profiles"].as_array().unwrap().iter().any(|p| p["id"] == "cockroachdb"));

        // Planned families stay visible so the roadmap is honest.
        let mysql = families.iter().find(|f| f["id"] == "mysql").unwrap();
        assert_eq!(mysql["usable"], false);
    }

    #[tokio::test]
    async fn creating_a_pool_then_reading_it_back_never_exposes_the_password() {
        let (app, _) = app();
        let (status, created) = post(&app, "/api/v1/pools", pool_payload()).await;
        assert_eq!(status, StatusCode::CREATED, "body: {created}");
        assert_eq!(created["has_backend_password"], true);

        let (status, body) = get(&app, "/api/v1/pools/app_main").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["has_backend_password"], true);

        let serialized = body.to_string();
        assert!(!serialized.contains("hunter2"), "the API must never echo a secret back");
    }

    #[tokio::test]
    async fn a_duplicate_pool_is_a_conflict_not_an_overwrite() {
        let (app, _) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        let (status, _) = post(&app, "/api/v1/pools", pool_payload()).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn unknown_families_and_settings_are_rejected() {
        let (app, _) = app();

        let mut payload = pool_payload();
        payload["family"] = json!("cassandra");
        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "bad_request");

        let mut payload = pool_payload();
        payload["family"] = json!("mysql");
        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a planned family cannot be configured yet");
        assert!(body["error"]["message"].as_str().unwrap().contains("not implemented"));

        let mut payload = pool_payload();
        payload["settings"]["nonsense"] = json!("x");
        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]["message"].as_str().unwrap().contains("nonsense"));
    }

    #[tokio::test]
    async fn settings_are_validated_against_the_registry_declaration() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload["settings"]["sslmode"] = json!("verify-everything");
        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]["message"].as_str().unwrap().contains("sslmode"));
    }

    #[tokio::test]
    async fn session_mode_with_a_small_max_size_is_reported_as_a_warning() {
        let (app, _) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        let (_, body) = get(&app, "/api/v1/pools").await;
        let warnings = body["warnings"].as_array().unwrap();
        assert!(
            warnings.iter().any(|w| w["kind"] == "session_mode_queues"),
            "operators must be told 97 clients will queue: {warnings:?}"
        );

        // And no fan-in is claimed, because session mode cannot deliver one.
        assert!(body["pools"][0]["configured_fan_in"].is_null());
    }

    #[tokio::test]
    async fn transaction_mode_reports_the_configured_fan_in() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload["mode"] = json!("transaction");
        post(&app, "/api/v1/pools", payload).await;

        let (_, body) = get(&app, "/api/v1/pools/app_main").await;
        let fan_in = body["configured_fan_in"].as_f64().unwrap();
        assert!((fan_in - 33.333).abs() < 0.01, "100 clients over 3 backends, got {fan_in}");
    }

    #[tokio::test]
    async fn creating_a_user_stores_a_verifier_and_not_the_password() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        let (status, body) =
            post(&app, "/api/v1/users", json!({ "name": "svc_orders", "password": "hunter2", "pools": ["app_main"] }))
                .await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");

        let stored = state.store.load();
        let verifier = stored.secrets.get(&state.master_key, &havuz_secrets::user_verifier("svc_orders")).unwrap();
        assert!(verifier.starts_with("SCRAM-SHA-256$"));
        assert!(!verifier.contains("hunter2"), "only a verifier is kept, never the password");

        let (_, listed) = get(&app, "/api/v1/users").await;
        assert_eq!(listed["users"][0]["has_password"], true);
        assert!(!listed.to_string().contains("hunter2"));
    }

    #[tokio::test]
    async fn editing_a_user_changes_only_what_was_sent() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        post(
            &app,
            "/api/v1/users",
            json!({ "name": "svc_orders", "password": "hunter2", "pools": ["app_main"], "read_only": true }),
        )
        .await;

        let (status, body) = patch(&app, "/api/v1/users/svc_orders", json!({ "disabled": true })).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let user = state.store.load().users.get("svc_orders").cloned().unwrap();
        assert!(user.disabled);
        assert!(user.read_only, "an absent field means leave it alone, not reset it");
        assert_eq!(user.pools, vec!["app_main".to_string()]);
    }

    #[tokio::test]
    async fn editing_a_user_can_rotate_the_password_without_storing_it() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        post(&app, "/api/v1/users", json!({ "name": "svc", "password": "old", "pools": ["app_main"] })).await;
        let before = state.store.load().secrets.get(&state.master_key, &havuz_secrets::user_verifier("svc")).unwrap();

        let (status, _) = patch(&app, "/api/v1/users/svc", json!({ "password": "new" })).await;
        assert_eq!(status, StatusCode::OK);

        let after = state.store.load().secrets.get(&state.master_key, &havuz_secrets::user_verifier("svc")).unwrap();
        assert_ne!(before, after, "the verifier must actually change");
        assert!(!after.contains("new"), "the password itself is never stored");
    }

    #[tokio::test]
    async fn a_user_cannot_be_edited_into_a_state_it_could_never_connect_from() {
        let (app, _) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        post(&app, "/api/v1/users", json!({ "name": "svc", "password": "p", "pools": ["app_main"] })).await;

        // Zero grants means every handshake fails. Deleting is the honest way
        // to say that.
        let (status, _) = patch(&app, "/api/v1/users/svc", json!({ "pools": [] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // And a grant to a pool that does not exist is rejected by validation.
        let (status, _) = patch(&app, "/api/v1/users/svc", json!({ "pools": ["ghost"] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = patch(&app, "/api/v1/users/svc", json!({ "password": "" })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn editing_an_unknown_user_is_a_404() {
        let (app, _) = app();
        let (status, _) = patch(&app, "/api/v1/users/ghost", json!({ "disabled": true })).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = post(&app, "/api/v1/users/ghost/kick", json!({})).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn kicking_reports_how_many_sessions_it_ended() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        post(&app, "/api/v1/users", json!({ "name": "svc", "password": "p", "pools": ["app_main"] })).await;

        // Nobody is connected yet, and saying so is more useful than an error.
        let (status, body) = post(&app, "/api/v1/users/svc/kick", json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["kicked"], 0);

        let sessions = state.registries.sessions;
        let _a = sessions.register("svc", "app_main", None, "10.0.0.1:5000", 0).unwrap();
        let _b = sessions.register("svc", "app_main", None, "10.0.0.2:5000", 0).unwrap();
        let _other = sessions.register("someone_else", "app_main", None, "10.0.0.3:5000", 0).unwrap();

        let (_, listed) = get(&app, "/api/v1/users").await;
        let svc = listed["users"].as_array().unwrap().iter().find(|u| u["name"] == "svc").unwrap();
        assert_eq!(svc["live_sessions"], 2, "the page must show what disabling this user would interrupt");

        let (_, body) = post(&app, "/api/v1/users/svc/kick", json!({})).await;
        assert_eq!(body["kicked"], 2, "and only this user's sessions");
    }

    #[tokio::test]
    async fn disabling_a_user_can_end_its_sessions_in_the_same_request() {
        // Disabling only refuses the next handshake. An operator revoking
        // access during an incident means now.
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        post(&app, "/api/v1/users", json!({ "name": "svc", "password": "p", "pools": ["app_main"] })).await;

        let sessions = state.registries.sessions;
        let live = sessions.register("svc", "app_main", None, "10.0.0.1:5000", 0).unwrap();

        let (status, body) = patch(&app, "/api/v1/users/svc", json!({ "disabled": true, "kick": true })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["kicked"], 1);
        assert!(state.store.load().users["svc"].disabled);
        assert!(live.signal().is_kicked());
    }

    #[tokio::test]
    async fn live_sessions_are_listed_for_an_operator() {
        let (app, state) = app();
        let sessions = state.registries.sessions;
        let _live = sessions.register("svc", "app_main", Some("orders-api"), "10.0.0.1:5000", 0).unwrap();

        let (status, body) = get(&app, "/api/v1/sessions").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["sessions"][0]["user"], "svc");
        assert_eq!(body["sessions"][0]["pool"], "app_main");
        assert_eq!(body["sessions"][0]["application"], "orders-api");
        assert_eq!(body["sessions"][0]["client_addr"], "10.0.0.1:5000");
    }

    #[tokio::test]
    async fn an_empty_password_is_refused() {
        let (app, _) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        let (status, _) =
            post(&app, "/api/v1/users", json!({ "name": "x", "password": "", "pools": ["app_main"] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deleting_a_pool_also_removes_its_grants_and_credentials() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        post(&app, "/api/v1/users", json!({ "name": "svc", "password": "p", "pools": ["app_main"] })).await;

        let response = app
            .clone()
            .oneshot(Request::builder().method("DELETE").uri("/api/v1/pools/app_main").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let stored = state.store.load();
        assert!(stored.pools.is_empty());
        assert!(!stored.secrets.contains(&havuz_secrets::pool_backend_password("app_main")), "orphan secret left");
        assert!(stored.users.is_empty(), "a user with no remaining grants cannot connect anyway");
    }

    #[tokio::test]
    async fn deleting_something_that_does_not_exist_is_a_404() {
        let (app, _) = app();
        let response = app
            .clone()
            .oneshot(Request::builder().method("DELETE").uri("/api/v1/pools/ghost").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn pausing_and_resuming_flips_the_disabled_flag() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        post(&app, "/api/v1/pools/app_main/pause", json!({})).await;
        assert!(state.store.load().pools["app_main"].disabled);

        post(&app, "/api/v1/pools/app_main/resume", json!({})).await;
        assert!(!state.store.load().pools["app_main"].disabled);
    }

    #[tokio::test]
    async fn probing_an_unreachable_backend_reports_the_reason_instead_of_failing() {
        let (app, _) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        let (status, body) = post(&app, "/api/v1/pools/app_main/probe", json!({})).await;
        assert_eq!(status, StatusCode::OK, "a failed probe is information, not a server error");
        assert_eq!(body["ok"], false);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn summary_reports_the_headline_numbers() {
        let (app, _) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        let (status, body) = get(&app, "/api/v1/summary").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["pools"], 1);
        assert_eq!(body["backend_connections"], 0);
        assert!(body["fan_in"].is_null(), "no ratio before any traffic");
        assert!(body["uptime_seconds"].is_number());
    }

    #[tokio::test]
    async fn metrics_are_prometheus_formatted() {
        let (app, _) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        let response =
            app.clone().oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/plain; version=0.0.4");

        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body.contains("# TYPE havuz_pool_backend_connections gauge"));
        assert!(body.contains("pool=\"app_main\""));
    }

    #[tokio::test]
    async fn a_pool_with_replicas_reports_them() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload["targets"] = json!([
            { "host": "pg-primary.internal", "port": 5432, "role": "primary" },
            { "host": "pg-replica-1.internal", "port": 5432, "role": "replica", "weight": 2 },
        ]);
        payload["routing"] = json!({
            "read_write_split": true,
            "sticky_after_write": "10s",
            "max_replica_lag": "5s",
            "health_interval": "5s",
            "failure_threshold": 3,
            "recovery_cooldown": "10s",
        });

        let (status, created) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::CREATED, "body: {created}");
        assert_eq!(created["replica_count"], 1);
        assert_eq!(created["routing"]["read_write_split"], true);

        let (status, targets) = get(&app, "/api/v1/pools/app_main/targets").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(targets["primary"]["label"], "pg-primary.internal:5432");
        assert_eq!(targets["replicas"][0]["label"], "pg-replica-1.internal:5432");
        assert_eq!(targets["replicas"][0]["weight"], 2);
        assert!(targets["replicas"][0]["lag_millis"].is_null(), "lag is unknown until probed");
        assert_eq!(targets["replicas"][0]["breaker"]["state"], "closed");
        assert_eq!(targets["read_write_split"], true);
    }

    #[tokio::test]
    async fn enabling_split_without_replicas_warns() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload["routing"] = json!({ "read_write_split": true });
        post(&app, "/api/v1/pools", payload).await;

        let (_, body) = get(&app, "/api/v1/pools").await;
        let warnings = body["warnings"].as_array().unwrap();
        assert!(
            warnings.iter().any(|w| w["kind"] == "split_without_replicas"),
            "turning on a split with nothing to split onto must be flagged: {warnings:?}"
        );
    }

    #[tokio::test]
    async fn routing_metrics_are_exported_per_target() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload["targets"] = json!([
            { "host": "p", "port": 5432, "role": "primary" },
            { "host": "r", "port": 5432, "role": "replica" },
        ]);
        payload["routing"] = json!({ "read_write_split": true });
        post(&app, "/api/v1/pools", payload).await;

        let response =
            app.clone().oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap()).await.unwrap();
        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();

        assert!(body.contains("havuz_routing_statements_total{pool=\"app_main\",target=\"replica\"} 0"));
        assert!(body.contains("havuz_replica_lag_seconds{pool=\"app_main\",replica=\"r:5432\"} -1"));
        assert!(body.contains("havuz_replica_breaker{pool=\"app_main\",replica=\"r:5432\",state=\"closed\"} 1"));
    }

    #[tokio::test]
    async fn a_shared_pool_reports_no_backend_identities() {
        let (app, _) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;

        let (status, body) = get(&app, "/api/v1/pools/app_main/identities").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["backend_auth"], "shared");
        assert_eq!(body["max_size_is_per_user"], false);
        assert!(body["identities"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_per_user_pool_says_that_max_size_is_a_per_user_budget() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload["backend_auth"] = json!("per_user");
        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["backend_auth"], "per_user");
        // There is no honest total: it depends on how many users connect.
        assert!(body["backend_ceiling"].is_null());

        let (_, identities) = get(&app, "/api/v1/pools/app_main/identities").await;
        assert_eq!(identities["max_size_is_per_user"], true);
    }

    #[tokio::test]
    async fn a_pool_records_statements_unless_asked_otherwise() {
        let (app, state) = app();
        let (status, body) = post(&app, "/api/v1/pools", pool_payload()).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["trace"], "statements");
        assert_eq!(state.store.load().pools["app_main"].trace, havuz_core::TraceLevel::Statements);
    }

    #[tokio::test]
    async fn the_trace_level_is_chosen_at_creation_and_changeable_afterwards() {
        // Turning capture up for the length of an incident and back down again
        // is the normal way to use this, so it cannot be creation-only.
        let (app, state) = app();
        let mut payload = pool_payload();
        payload["trace"] = json!("full");
        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["trace"], "full");

        let (status, body) = patch(&app, "/api/v1/pools/app_main", json!({ "trace": "off" })).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["trace"], "off");
        assert_eq!(state.store.load().pools["app_main"].trace, havuz_core::TraceLevel::Off);

        // An update that says nothing about tracing leaves it alone.
        patch(&app, "/api/v1/pools/app_main", json!({ "max_size": 5 })).await;
        assert_eq!(state.store.load().pools["app_main"].trace, havuz_core::TraceLevel::Off);
    }

    #[tokio::test]
    async fn an_unknown_trace_level_is_refused_rather_than_defaulted() {
        let (app, state) = app();
        let mut payload = pool_payload();
        payload["trace"] = json!("everything");
        let (status, _) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(state.store.load().pools.is_empty());
    }

    #[tokio::test]
    async fn a_per_user_pool_does_not_need_a_service_account() {
        // Every client brings its own credential, so the service account is a
        // fallback rather than the way in. Demanding one would be demanding a
        // login the operator may deliberately not want to exist.
        let (app, state) = app();
        let mut payload = pool_payload();
        payload["backend_auth"] = json!("per_user");
        payload["settings"] = json!({ "host": "pg-primary.internal", "port": 5432, "database": "appdb" });

        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["backend_user"], "");
        assert_eq!(body["has_backend_password"], false);
        assert_eq!(state.store.load().pools["app_main"].backend_user, "");
    }

    #[tokio::test]
    async fn a_shared_pool_still_needs_a_service_account() {
        // The relaxation is per-user auth's alone: a shared pool with no
        // account is a pool nobody can connect through.
        let (app, state) = app();
        let mut payload = pool_payload();
        payload["settings"] = json!({ "host": "pg-primary.internal", "port": 5432, "database": "appdb" });

        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert!(body["error"]["message"].as_str().unwrap_or_default().contains("username"), "body: {body}");
        assert!(state.store.load().pools.is_empty());
    }

    #[tokio::test]
    async fn per_user_authentication_is_refused_by_families_that_cannot_do_it() {
        // Accepting it would pool every client through the service account
        // while the dashboard claimed otherwise.
        let (app, state) = app();
        let payload = json!({
            "name": "legacy",
            "family": "jdbc",
            "listen_port": 6433,
            "backend_auth": "per_user",
            "settings": {
                "url": "jdbc:oracle:thin:@//db.internal:1521/ORCLPDB1",
                "driver_paths": "/opt/havuz/drivers/ojdbc11.jar",
                "username": "app",
                "password": "hunter2",
            },
            "limits": { "max_size": 3, "max_client_connections": 100 }
        });

        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert!(
            body["error"]["message"].as_str().unwrap_or_default().contains("connecting client"),
            "the reason must name the limitation, not the credentials: {body}"
        );
        assert!(state.store.load().pools.is_empty());
    }

    #[tokio::test]
    async fn per_user_authentication_is_refused_without_client_tls() {
        // It asks clients for their password. Catching it here beats letting
        // every connection to the pool fail afterwards.
        let (app, state) = app_without_tls();
        let mut payload = pool_payload();
        payload["backend_auth"] = json!("per_user");

        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert!(body["error"]["message"].as_str().unwrap_or_default().contains("TLS"), "body: {body}");
        assert!(state.store.load().pools.is_empty());
    }

    #[tokio::test]
    async fn a_user_can_be_moved_onto_its_own_database_role_and_back() {
        let (app, state) = app();
        post(&app, "/api/v1/pools", pool_payload()).await;
        post(&app, "/api/v1/users", json!({ "name": "svc_orders", "password": "p", "pools": ["app_main"] })).await;

        // Off by default, so flipping a pool into per-user mode changes nothing
        // until each user is moved deliberately.
        assert!(!state.store.load().users["svc_orders"].own_backend_role);

        patch(&app, "/api/v1/users/svc_orders", json!({ "own_backend_role": true })).await;
        assert!(state.store.load().users["svc_orders"].own_backend_role);

        let (_, users) = get(&app, "/api/v1/users").await;
        let user = users["users"].as_array().unwrap().iter().find(|u| u["name"] == "svc_orders").unwrap();
        assert_eq!(user["own_backend_role"], true);

        patch(&app, "/api/v1/users/svc_orders", json!({ "own_backend_role": false })).await;
        assert!(!state.store.load().users["svc_orders"].own_backend_role);
    }

    #[tokio::test]
    async fn a_per_user_pool_cannot_keep_connections_warm() {
        let (app, _) = app();
        let mut payload = pool_payload();
        payload["backend_auth"] = json!("per_user");
        payload["limits"] = json!({ "max_size": 3, "max_client_connections": 100, "min_idle": 2 });

        let (status, body) = post(&app, "/api/v1/pools", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn identities_of_an_unknown_pool_is_a_404() {
        let (app, _) = app();
        let (status, _) = get(&app, "/api/v1/pools/ghost/identities").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn targets_of_an_unknown_pool_is_a_404() {
        let (app, _) = app();
        let (status, _) = get(&app, "/api/v1/pools/ghost/targets").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_pin_report_names_who_broke_multiplexing() {
        let (app, state) = app();
        state.registries.pins.record("svc_orders", Some("orders-api"), havuz_proto::PinReason::SessionParameter);
        state.registries.pins.record_clean();

        let (status, body) = get(&app, "/api/v1/pins").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["pinned_sessions"], 1);
        assert_eq!(body["clean_sessions"], 1);
        assert_eq!(body["offenders"][0]["user"], "svc_orders");
        assert_eq!(body["offenders"][0]["application"], "orders-api");
        assert_eq!(body["offenders"][0]["reason"], "session_parameter");
        assert_eq!(body["offenders"][0]["actionable"], true);

        // Every reason is listed, including the ones at zero, so the breakdown
        // is a full picture rather than a list of what happened to fire.
        assert_eq!(body["by_reason"].as_array().unwrap().len(), havuz_proto::PinReason::ALL.len());
    }

    #[tokio::test]
    async fn pin_statistics_can_be_reset_after_a_fix_is_deployed() {
        let (app, state) = app();
        state.registries.pins.record("svc", None, havuz_proto::PinReason::Listen);

        let response = app
            .clone()
            .oneshot(Request::builder().method("DELETE").uri("/api/v1/pins").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let (_, body) = get(&app, "/api/v1/pins").await;
        assert_eq!(body["pinned_sessions"], 0, "so an operator can confirm the fix worked");
    }

    #[tokio::test]
    async fn query_traces_expose_active_history_detail_and_filters() {
        let (app, state) = app();
        let context = havuz_control::TraceContext {
            pool: "app_main".into(),
            user: "svc_orders".into(),
            application: Some("orders-api".into()),
            client_addr: "127.0.0.1:5000".into(),
            level: havuz_core::TraceLevel::Full,
        };
        let holder = state.registries.holders.session(context.clone(), havuz_core::PoolMode::Transaction);
        holder.idle_in_transaction("primary/127.0.0.1:5432".into(), Some(4242));
        let mut span = state.registries.traces.begin(&context, "select 42");
        span.assign("primary/127.0.0.1:5432", Some(4242));

        let (status, active) = get(&app, "/api/v1/traces?pool=app_main&user=svc_orders&limit=1&offset=0").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(active["active"][0]["sql"], "select 42");
        assert_eq!(active["active"][0]["backend_pid"], 4242);
        assert_eq!(active["holders"][0]["reason"], "idle_in_transaction");
        assert_eq!(active["holders"][0]["backend_pid"], 4242);
        assert!(active["pool_snapshots"].is_array());
        assert_eq!(active["pagination"]["limit"], 1);
        assert_eq!(active["pagination"]["offset"], 0);

        span.succeed();
        let mut history = serde_json::Value::Null;
        for _ in 0..20 {
            history = get(&app, "/api/v1/traces?q=select&status=succeeded").await.1;
            if history["traces"].as_array().is_some_and(|traces| !traces.is_empty()) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let id = history["traces"][0]["id"].as_u64().expect("completed trace id");
        assert_eq!(history["pagination"]["total"], 1);
        let (status, detail) = get(&app, &format!("/api/v1/traces/{id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(detail["user"], "svc_orders");
        assert!(detail["result"]["sets"].is_array());

        let response = app
            .clone()
            .oneshot(Request::builder().method("DELETE").uri("/api/v1/traces").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.registries.traces.list(&havuz_control::TraceFilter::default()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn pin_metrics_are_exported() {
        let (app, state) = app();
        state.registries.pins.record("svc", Some("api"), havuz_proto::PinReason::SessionParameter);

        let response =
            app.clone().oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap()).await.unwrap();
        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();

        assert!(body.contains("havuz_sessions_pinned_total{reason=\"session_parameter\"} 1"));
        assert!(body.contains("# TYPE havuz_session_pin_rate gauge"));
    }

    #[tokio::test]
    async fn health_endpoints_answer() {
        let (app, _) = app();
        let response =
            app.clone().oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let (status, body) = get(&app, "/readyz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ready"], true);
    }

    #[tokio::test]
    async fn a_configured_token_is_enforced_except_on_health() {
        std::env::set_var("HAVUZ_TEST_ROUTES_TOKEN", "s3cret");
        let key = Arc::new(MasterKey::generate());
        let store = Arc::new(StateStore::ephemeral(CoreState::default()));
        let registries = havuz_control::Registries::ephemeral();
        let families = havuz_control::FamilySet::new(vec![FakeFamily::new(store.clone())]);
        let state = AdminState::new(
            store,
            key,
            families,
            registries,
            None,
            true,
            &havuz_core::AdminAuth::Bearer { token_env: "HAVUZ_TEST_ROUTES_TOKEN".into() },
            false,
        );
        let app = router(state);

        let (status, _) = get(&app, "/api/v1/pools").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no token means no access");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/pools")
                    .header("authorization", "Bearer s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let (status, _) = get(&app, "/healthz").await;
        assert_eq!(status, StatusCode::OK, "orchestrators have no token");

        let (status, _) = get(&app, "/metrics").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "metrics reveal topology");

        std::env::remove_var("HAVUZ_TEST_ROUTES_TOKEN");
    }
}
