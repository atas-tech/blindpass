// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::admin_session::{session_response, valid_origin};
use crate::routes::auth::hash_api_key;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use blindpass_core::custody::sha256;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapBody {
    username: String,
    display_name: String,
    password: String,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/api/v3/admin/bootstrap", post(bootstrap))
}

async fn bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BootstrapBody>,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"not_ready","message":"controller is not ready"})),
        )
            .into_response();
    };
    if !valid_origin(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"origin_denied","message":"origin is not allowed"})),
        )
            .into_response();
    }
    let username = body.username.trim();
    let display_name = body.display_name.trim();
    let Some(bootstrap_token) = headers
        .get("x-blindpass-bootstrap-token")
        .and_then(|value| value.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                json!({"error":"bootstrap_required","message":"bootstrap capability is required"}),
            ),
        )
            .into_response();
    };
    if bootstrap_token.len() < 32
        || !valid_account_name(username)
        || display_name.is_empty()
        || display_name.len() > 160
        || body.password.len() < 12
        || body.password.len() > 1_024
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_request","message":"bootstrap fields are invalid"})),
        )
            .into_response();
    }
    let password_hash = match hash_api_key(&body.password) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"bootstrap_failed","message":"administrator setup failed"})),
            )
                .into_response();
        }
    };
    let operator_id = random_uuid();
    let token_hash = match token_hash(bootstrap_token) {
        Some(hash) => hash,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"bootstrap_failed","message":"administrator setup failed"})),
            )
                .into_response();
        }
    };
    match store.bootstrap_operator_with_token(&token_hash, &operator_id, username, display_name, &password_hash).await {
        Ok(true) => {
            let refresh_token = random_token();
            let Some(refresh_hash) = crate::routes::auth::hash_refresh_token(&refresh_token) else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error":"bootstrap_failed","message":"administrator setup failed"})),
                )
                    .into_response();
            };
            match store
                .create_browser_session(
                    &operator_id,
                    &refresh_hash,
                    state.refresh_token_ttl_seconds,
                )
                .await
            {
                Ok(Some(session)) => session_response(
                    StatusCode::CREATED,
                    &state,
                    session,
                    Some(&refresh_token),
                ),
                Ok(None) | Err(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error":"bootstrap_failed","message":"administrator setup failed"})),
                )
                    .into_response(),
            }
        }
        Ok(false) => (StatusCode::CONFLICT, Json(json!({"error":"bootstrap_unavailable","message":"bootstrap is expired, used, or setup is already complete"}))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":"bootstrap_failed","message":"administrator setup failed"}))).into_response(),
    }
}

fn valid_account_name(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@-".contains(&byte))
}

fn token_hash(token: &str) -> Option<String> {
    sha256(token.as_bytes())
        .ok()
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn random_token() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_uuid() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let raw = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..]
    )
}
