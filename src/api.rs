//! GHOST NAS HTTP API Server
//!
//! Axum-based REST API for TrueNAS SCALE middleware integration.
//! Provides endpoints for health, sessions, vault, TrueNAS, handshake.

use axum::{
    extract::{Path, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::info;

use crate::session::{SessionManager, SessionMeta};
use crate::vault::Vault;
use crate::truenas::TrueNASBridge;
use crate::config::GhostConfig;

// ---------- Shared State ----------

#[derive(Clone)]
pub struct AppState {
    pub config: GhostConfig,
    pub session_manager: Arc<SessionManager>,
    pub vault: Arc<Vault>,
    pub truenas: Arc<TrueNASBridge>,
    pub node_fingerprint: String,
}

// ---------- Response Types ----------

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    version: String,
    node_fingerprint: String,
    sessions_active: usize,
    vault_groups: usize,
    truenas_connected: bool,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct QuotaUpdate {
    quota: String,
}

#[derive(Deserialize)]
struct HandshakeRequest {
    target: String,
}

// ---------- Router ----------

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/metrics/ws", get(metrics_ws))
        .route("/api/v1/sessions", get(list_sessions))
        .route("/api/v1/sessions/{fingerprint}", get(get_session))
        .route("/api/v1/sessions/{fingerprint}/wipe", post(wipe_session))
        .route("/api/v1/vault/status", get(vault_status))
        .route("/api/v1/vault/groups", get(list_groups))
        .route("/api/v1/vault/groups/{group_id}", get(get_group))
        .route("/api/v1/vault/groups/{group_id}", delete(delete_group))
        .route("/api/v1/vault/quota", put(update_quota))
        .route("/api/v1/vault/gc", post(trigger_gc))
        .route("/api/v1/truenas/health", get(truenas_health))
        .route("/api/v1/truenas/dataset", get(dataset_info))
        .route("/api/v1/truenas/provision", post(provision_dataset))
        .route("/api/v1/handshake/status", get(handshake_status))
        .route("/api/v1/handshake/initiate", post(initiate_handshake))
        .nest_service("/", ServeDir::new("/usr/share/ghost-nas/webui"))
        .layer(cors)
        .with_state(state)
}

// ---------- Handlers ----------

async fn health_check() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        node_fingerprint: String::new(),
        sessions_active: 0,
        vault_groups: 0,
        truenas_connected: false,
        uptime_secs: 0,
    })
}

async fn get_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let sessions = state.session_manager.count().await;
    let vault_meta = state.vault.group_count().await;

    Json(StatusResponse {
        status: "running".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        node_fingerprint: state.node_fingerprint.clone(),
        sessions_active: sessions,
        vault_groups: vault_meta,
        truenas_connected: state.truenas.cached_dataset().await.is_some(),
        uptime_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

async fn metrics_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_metrics_socket(socket, state))
}

async fn handle_metrics_socket(mut socket: WebSocket, state: AppState) {
    info!("WebSocket metrics client connected");
    loop {
        let status = StatusResponse {
            status: "running".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            node_fingerprint: state.node_fingerprint.clone(),
            sessions_active: state.session_manager.count().await,
            vault_groups: state.vault.group_count().await,
            truenas_connected: state.truenas.cached_dataset().await.is_some(),
            uptime_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        let json = serde_json::to_string(&status).unwrap_or_default();
        if socket.send(Message::Text(json)).await.is_err() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

// ---------- Session Handlers ----------

async fn list_sessions(State(state): State<AppState>) -> Json<Vec<SessionMeta>> {
    Json(state.session_manager.all_meta().await)
}

async fn get_session(
    State(state): State<AppState>,
    Path(fp): Path<String>,
) -> Response {
    match state.session_manager.find(&fp).await {
        Some(session) => {
            match session.to_meta() {
                Some(meta) => Json(meta).into_response(),
                None => (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Session has no active key".into(),
                    }),
                )
                    .into_response(),
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Session {} not found", fp),
            }),
        )
            .into_response(),
    }
}

async fn wipe_session(
    State(state): State<AppState>,
    Path(fp): Path<String>,
) -> Response {
    state.session_manager.remove(&fp).await;
    Json(serde_json::json!({"status": "wiped", "fingerprint": fp})).into_response()
}

// ---------- Vault Handlers ----------

async fn vault_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let ds = state.truenas.cached_dataset().await;
    let groups = state.vault.group_count().await;
    Json(serde_json::json!({
        "mount_path": state.config.vault.mount_path,
        "groups": groups,
        "zfs": ds,
    }))
}

async fn list_groups(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.vault.all_group_ids().await)
}

async fn get_group(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
) -> Response {
    match state.vault.get_meta(&group_id).await {
        Some(meta) => {
            let shards = state.vault.list_shards(&group_id).await.unwrap_or_default();
            Json(serde_json::json!({
                "group_id": group_id,
                "meta": meta,
                "shard_count": shards.len(),
                "shard_indices": shards,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Group {} not found", group_id),
            }),
        )
            .into_response(),
    }
}

async fn delete_group(
    State(_state): State<AppState>,
    Path(group_id): Path<String>,
) -> Response {
    match _state.vault.secure_wipe_group(&group_id).await {
        Ok(_) => Json(serde_json::json!({"status": "wiped", "group": group_id})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn update_quota(
    State(state): State<AppState>,
    Json(req): Json<QuotaUpdate>,
) -> Response {
    match state.truenas.set_vault_quota(&req.quota).await {
        Ok(_) => Json(serde_json::json!({"status": "updated", "quota": req.quota})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn trigger_gc(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.vault.garbage_collect().await {
        Ok(collected) => Json(serde_json::json!({"status": "gc_complete", "collected": collected})),
        Err(e) => Json(serde_json::json!({"status": "gc_error", "error": e.to_string()})),
    }
}

// ---------- TrueNAS Handlers ----------

async fn truenas_health(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.truenas.health_check().await {
        Ok(health) => Json(serde_json::json!(health)),
        Err(e) => Json(serde_json::json!({"error": e.to_string(), "healthy": false})),
    }
}

async fn dataset_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.truenas.get_dataset_info().await {
        Ok(info) => Json(serde_json::json!(info)),
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn provision_dataset(State(state): State<AppState>) -> Response {
    match state.truenas.provision_vault_dataset().await {
        Ok(_) => Json(serde_json::json!({"status": "provisioned"})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

// ---------- Handshake Handlers ----------

async fn handshake_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let sessions = state.session_manager.all_meta().await;
    Json(serde_json::json!({
        "sessions": sessions,
        "fingerprint": state.node_fingerprint,
    }))
}

async fn initiate_handshake(
    State(_state): State<AppState>,
    Json(req): Json<HandshakeRequest>,
) -> Json<serde_json::Value> {
    info!("Handshake initiation requested to {}", req.target);
    Json(serde_json::json!({
        "status": "initiated",
        "target": req.target,
    }))
}