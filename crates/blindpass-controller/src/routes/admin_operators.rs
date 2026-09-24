// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::admin_session::{
    authenticated_session, operator_body, valid_origin, valid_session_csrf,
};
use crate::routes::auth::hash_api_key;
use crate::store::LocalSession;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v3/admin/operators",
            get(list_operators).post(create_operator),
        )
        .route(
            "/api/v3/admin/operators/{id}",
            patch(update_operator).delete(delete_operator),
        )
        .route(
            "/api/v3/admin/operators/{id}/reset-password",
            post(reset_password),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateOperatorInput {
    username: String,
    display_name: String,
    role: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateOperatorInput {
    display_name: Option<String>,
    role: Option<String>,
}

async fn list_operators(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    if let Err(response) = require_admin(&state, &headers, false).await {
        return *response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.list_local_operators().await {
        Ok(operators) => Json(json!({
            "items": operators.iter().map(operator_body).collect::<Vec<_>>(),
            "next_cursor": Value::Null
        }))
        .into_response(),
        Err(_) => unavailable(),
    }
}

async fn create_operator(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateOperatorInput>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, true).await {
        return *response;
    }
    let username = body.username.trim();
    let display_name = body.display_name.trim();
    if !valid_username(username)
        || display_name.is_empty()
        || display_name.len() > 160
        || !valid_role(&body.role)
        || body.password.len() < 12
        || body.password.len() > 1_024
    {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_operator",
            "operator fields are invalid",
        );
    }
    let password_hash = match hash_api_key(&body.password) {
        Ok(hash) => hash,
        Err(_) => return unavailable(),
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store
        .create_local_operator(
            &random_uuid(),
            username,
            display_name,
            &body.role,
            &password_hash,
        )
        .await
    {
        Ok(()) => match store.operator_by_username(username).await {
            Ok(Some(operator)) => {
                (StatusCode::CREATED, Json(operator_body(&operator))).into_response()
            }
            Ok(None) | Err(_) => unavailable(),
        },
        Err(_) => admin_error(
            StatusCode::CONFLICT,
            "username_unavailable",
            "an operator with that username already exists",
        ),
    }
}

async fn update_operator(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UpdateOperatorInput>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, true).await {
        return *response;
    }
    if body.display_name.is_none() && body.role.is_none() {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_operator",
            "at least one operator field is required",
        );
    }
    if body
        .display_name
        .as_ref()
        .is_some_and(|value| value.trim().is_empty() || value.trim().len() > 160)
        || body.role.as_ref().is_some_and(|role| !valid_role(role))
    {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_operator",
            "operator fields are invalid",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let current = match store.operator_by_id(&id).await {
        Ok(Some(operator)) if operator.disabled_at_ms.is_none() => operator,
        Ok(_) => {
            return admin_error(
                StatusCode::NOT_FOUND,
                "operator_not_found",
                "operator was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    let display_name = body
        .display_name
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current.display_name);
    let role = body.role.as_deref().unwrap_or(&current.role);
    match store.update_local_operator(&id, display_name, role).await {
        Ok(Some(true)) => match store.operator_by_id(&id).await {
            Ok(Some(operator)) => (StatusCode::OK, Json(operator_body(&operator))).into_response(),
            Ok(None) | Err(_) => unavailable(),
        },
        Ok(Some(false)) => admin_error(
            StatusCode::CONFLICT,
            "last_admin_required",
            "the instance must retain an active administrator",
        ),
        Ok(None) => admin_error(
            StatusCode::NOT_FOUND,
            "operator_not_found",
            "operator was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn delete_operator(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, true).await {
        return *response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.delete_local_operator(&id).await {
        Ok(Some(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Some(false)) => admin_error(
            StatusCode::CONFLICT,
            "last_admin_required",
            "the instance must retain an active administrator",
        ),
        Ok(None) => admin_error(
            StatusCode::NOT_FOUND,
            "operator_not_found",
            "operator was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn reset_password(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, true).await {
        return *response;
    }
    let temporary_password = random_token();
    let password_hash = match hash_api_key(&temporary_password) {
        Ok(hash) => hash,
        Err(_) => return unavailable(),
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store
        .reset_local_operator_password(&id, &password_hash)
        .await
    {
        Ok(true) => Json(json!({"temporary_password":temporary_password})).into_response(),
        Ok(false) => admin_error(
            StatusCode::NOT_FOUND,
            "operator_not_found",
            "operator was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn require_admin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    unsafe_method: bool,
) -> Result<LocalSession, Box<Response>> {
    let session = authenticated_session(state.store.as_ref(), headers)
        .await
        .ok_or_else(|| {
            Box::new(admin_error(
                StatusCode::UNAUTHORIZED,
                "session_required",
                "an active local session is required",
            ))
        })?;
    if session.operator.role != "admin" {
        return Err(Box::new(admin_error(
            StatusCode::FORBIDDEN,
            "role_denied",
            "administrator role is required",
        )));
    }
    if unsafe_method && (!valid_origin(state, headers) || !valid_session_csrf(headers, &session)) {
        return Err(Box::new(admin_error(
            StatusCode::FORBIDDEN,
            "csrf_or_origin_denied",
            "origin or CSRF validation failed",
        )));
    }
    Ok(session)
}

fn valid_username(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@-".contains(&byte))
}

fn valid_role(value: &str) -> bool {
    matches!(value, "admin" | "operator" | "viewer")
}

fn random_token() -> String {
    let mut bytes = [0_u8; 24];
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

fn admin_error(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({"error":error,"message":message}))).into_response()
}

fn unavailable() -> Response {
    admin_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "not_ready",
        "controller is not ready",
    )
}
