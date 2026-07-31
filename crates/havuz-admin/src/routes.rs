//! HTTP routes.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use havuz_core::state::{PoolConfig, PoolLimits, RoutingConfig, Target, UserConfig, Warning};
use havuz_pg::ScramVerifier;
use havuz_pool::PoolSnapshot;
use havuz_registry::PoolMode;
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
        .route("/pools/{name}", get(get_pool).delete(delete_pool))
        .route("/pools/{name}/pause", post(pause_pool))
        .route("/pools/{name}/resume", post(resume_pool))
        .route("/pools/{name}/drain", post(drain_pool))
        .route("/pools/{name}/probe", post(probe_pool))
        .route("/pools/{name}/targets", get(pool_targets))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{name}", delete(delete_user))
        .route("/config", get(get_config))
        .route("/summary", get(get_summary))
        .route("/pins", get(get_pins).delete(reset_pins));

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
        has_backend_password: state.secrets.contains(&havuz_secrets::pool_backend_password(name)),
        targets: config.targets.clone(),
        limits: config.limits.clone(),
        settings: config.settings.clone(),
        routing: config.routing.clone(),
        replica_count: config.replicas().count(),
        disabled: config.disabled,
        description: config.description.clone(),
        configured_fan_in: config.fan_in(),
        runtime,
    }
}

async fn list_pools(State(state): State<AdminState>) -> impl IntoResponse {
    let current = state.store.load();
    let snapshots: BTreeMap<String, PoolSnapshot> =
        state.family.snapshots().into_iter().map(|s| (s.name.clone(), s)).collect();

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
    let runtime = state.family.snapshots().into_iter().find(|s| s.name == name);
    Ok(Json(pool_view(&name, config, &current, runtime)))
}

#[derive(Debug, Deserialize)]
struct CreatePool {
    name: String,
    family: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    mode: Option<PoolMode>,
    targets: Vec<Target>,
    database: String,
    backend_user: String,
    #[serde(default)]
    backend_password: Option<String>,
    #[serde(default)]
    limits: Option<PoolLimits>,
    #[serde(default)]
    settings: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    routing: Option<RoutingConfig>,
    #[serde(default)]
    description: Option<String>,
}

async fn create_pool(
    State(state): State<AdminState>,
    Json(body): Json<CreatePool>,
) -> Result<impl IntoResponse, ApiError> {
    let (family, profile) = havuz_registry::resolve(&body.family, body.profile.as_deref())
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Validate the family-specific settings against the same declaration the
    // UI rendered its form from.
    for field in family.config_fields {
        field.validate(body.settings.get(field.name)).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(unknown) = body.settings.keys().find(|k| !family.config_fields.iter().any(|f| f.name == k.as_str())) {
        return Err(ApiError::BadRequest(format!("unknown setting '{unknown}' for family '{}'", family.id)));
    }

    let mode = body.mode.unwrap_or(family.default_pool_mode);
    let name = body.name.clone();
    let password = body.backend_password.clone();

    let config = PoolConfig {
        family: family.id.to_string(),
        profile: Some(profile.id.to_string()),
        mode,
        targets: body.targets,
        backend_user: body.backend_user,
        database: body.database,
        limits: body.limits.unwrap_or_default(),
        settings: body.settings,
        routing: body.routing.unwrap_or_default(),
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

    state.family.sync_pools().map_err(|e| ApiError::Internal(e.to_string()))?;

    let current = state.store.load();
    let config = current.pools.get(&body.name).expect("just inserted");
    Ok((axum::http::StatusCode::CREATED, Json(pool_view(&body.name, config, &current, None))))
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
    state.family.sync_pools().map_err(|e| ApiError::Internal(e.to_string()))?;
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
    state.family.sync_pools().map_err(|e| ApiError::Internal(e.to_string()))
}

async fn drain_pool(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    if !state.store.load().pools.contains_key(&name) {
        return Err(ApiError::NotFound(format!("pool '{name}'")));
    }
    Ok(Json(json!({ "pool": name, "status": "draining" })))
}

async fn probe_pool(State(state): State<AdminState>, Path(name): Path<String>) -> Result<impl IntoResponse, ApiError> {
    use havuz_proto::ProtocolFamily;
    match state.family.probe(&name).await {
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
    read_only: bool,
    disabled: bool,
    description: Option<String>,
    has_password: bool,
}

async fn list_users(State(state): State<AdminState>) -> impl IntoResponse {
    let current = state.store.load();
    let users: Vec<_> = current
        .users
        .iter()
        .map(|(name, u)| UserView {
            name: name.clone(),
            pools: u.pools.clone(),
            max_client_connections: u.max_client_connections,
            read_only: u.read_only,
            disabled: u.disabled,
            description: u.description.clone(),
            has_password: current.secrets.contains(&havuz_secrets::user_verifier(name)),
        })
        .collect();
    Json(json!({ "users": users }))
}

#[derive(Debug, Deserialize)]
struct CreateUser {
    name: String,
    password: String,
    pools: Vec<String>,
    #[serde(default)]
    max_client_connections: u32,
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
    let snapshots = state.family.snapshots();
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
        .family
        .group_snapshots()
        .into_iter()
        .find(|g| g.name == name)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("pool '{name}'")))
}

/// Why transaction-mode sessions stopped being shareable.
///
/// The endpoint no competing pooler offers, and the one that turns "my pool is
/// full" into "turn off `SET application_name` in orders-api".
async fn get_pins(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.family.pins().report())
}

async fn reset_pins(State(state): State<AdminState>) -> impl IntoResponse {
    state.family.pins().reset();
    Json(json!({ "reset": true }))
}

async fn prometheus(State(state): State<AdminState>) -> impl IntoResponse {
    let body = metrics::render(
        &state.family.snapshots(),
        &state.family.group_snapshots(),
        &state.family.pins().report(),
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
    use havuz_core::{State as CoreState, StateStore};
    use havuz_pg::PgFamily;
    use havuz_secrets::MasterKey;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn app() -> (Router, AdminState) {
        let key = Arc::new(MasterKey::generate());
        let store = Arc::new(StateStore::ephemeral(CoreState::default()));
        let family = PgFamily::new(store.clone(), key.clone());
        let state = AdminState::new(store, key, family, &havuz_core::AdminAuth::None, false);
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

    fn pool_payload() -> serde_json::Value {
        json!({
            "name": "app_main",
            "family": "postgres",
            "targets": [{ "host": "pg-primary.internal", "port": 5432 }],
            "database": "appdb",
            "backend_user": "app",
            "backend_password": "hunter2",
            "settings": { "host": "pg-primary.internal", "database": "appdb", "username": "app" },
            "limits": { "max_size": 3, "max_client_connections": 100 }
        })
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
        let mut payload = pool_payload();
        payload["targets"] = json!([{ "host": "127.0.0.1", "port": 1 }]);
        post(&app, "/api/v1/pools", payload).await;

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
    async fn targets_of_an_unknown_pool_is_a_404() {
        let (app, _) = app();
        let (status, _) = get(&app, "/api/v1/pools/ghost/targets").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_pin_report_names_who_broke_multiplexing() {
        let (app, state) = app();
        state.family.pins().record("svc_orders", Some("orders-api"), havuz_proto::PinReason::SessionParameter);
        state.family.pins().record_clean();

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
        state.family.pins().record("svc", None, havuz_proto::PinReason::Listen);

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
    async fn pin_metrics_are_exported() {
        let (app, state) = app();
        state.family.pins().record("svc", Some("api"), havuz_proto::PinReason::SessionParameter);

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
        let family = PgFamily::new(store.clone(), key.clone());
        let state = AdminState::new(
            store,
            key,
            family,
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
