// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::admin_session::{authenticated_session, valid_origin, valid_session_csrf};
use crate::routes::auth::{hash_api_key, new_api_key};
use crate::store::{AdminAgentRecord, LocalSession, Store};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::json;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v3/admin/agents", get(list_agents).post(create_agent))
        .route("/api/v3/admin/agents/{id}/rotate-key", post(rotate_key))
        .route("/api/v3/admin/agents/{id}", delete(revoke_agent))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAgentInput {
    agent_id: String,
    display_name: String,
}

async fn list_agents(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    if let Err(response) = require_admin(&state, &headers, false).await {
        return *response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.list_admin_agents().await {
        Ok(agents) => Json(json!({
            "items": agents.iter().map(|agent| agent_body(agent, store.tenant_id())).collect::<Vec<_>>(),
            "next_cursor": null
        }))
        .into_response(),
        Err(_) => unavailable(),
    }
}

async fn create_agent(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateAgentInput>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, true).await {
        return *response;
    }
    let agent_id = body.agent_id.trim();
    let display_name = body.display_name.trim();
    if !valid_agent_id(agent_id) || display_name.is_empty() || display_name.len() > 160 {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_agent",
            "agent fields are invalid",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let row_id = random_uuid();
    let bootstrap_api_key = new_api_key(&row_id);
    let key_hash = match hash_api_key(&bootstrap_api_key) {
        Ok(hash) => hash,
        Err(_) => return unavailable(),
    };
    match store
        .create_agent_with_id(
            &row_id,
            agent_id,
            display_name,
            ring_from_id(agent_id).as_deref(),
            &key_hash,
        )
        .await
    {
        Ok(_) => match find_admin_agent(store, &row_id).await {
            Ok(Some(agent)) => (
                StatusCode::CREATED,
                Json(json!({
                    "agent":agent_body(&agent, store.tenant_id()),
                    "bootstrap_api_key":bootstrap_api_key
                })),
            )
                .into_response(),
            Ok(None) | Err(_) => unavailable(),
        },
        Err(_) => admin_error(
            StatusCode::CONFLICT,
            "agent_id_unavailable",
            "an agent with that id already exists",
        ),
    }
}

async fn rotate_key(
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
    let existing = match store.agent_by_key_id(&id).await {
        Ok(Some(agent)) if agent.status == "active" => agent,
        Ok(_) => {
            return admin_error(
                StatusCode::NOT_FOUND,
                "agent_not_found",
                "agent was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    let bootstrap_api_key = new_api_key(&existing.id);
    let key_hash = match hash_api_key(&bootstrap_api_key) {
        Ok(hash) => hash,
        Err(_) => return unavailable(),
    };
    match store
        .replace_agent_api_key_hash(&existing.agent_id, existing.key_version, &key_hash)
        .await
    {
        Ok(Some(_)) => match find_admin_agent(store, &id).await {
            Ok(Some(agent)) => (
                StatusCode::OK,
                Json(json!({
                    "agent":agent_body(&agent, store.tenant_id()),
                    "bootstrap_api_key":bootstrap_api_key
                })),
            )
                .into_response(),
            Ok(None) | Err(_) => unavailable(),
        },
        Ok(None) => admin_error(
            StatusCode::CONFLICT,
            "agent_changed",
            "agent key changed concurrently",
        ),
        Err(_) => unavailable(),
    }
}

async fn revoke_agent(
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
    let existing = match store.agent_by_key_id(&id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return admin_error(
                StatusCode::NOT_FOUND,
                "agent_not_found",
                "agent was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    if existing.status == "active" && store.revoke_agent(&existing.agent_id).await.is_err() {
        return unavailable();
    }
    match find_admin_agent(store, &id).await {
        Ok(Some(agent)) => {
            (StatusCode::OK, Json(agent_body(&agent, store.tenant_id()))).into_response()
        }
        Ok(None) | Err(_) => unavailable(),
    }
}

async fn find_admin_agent(
    store: &Store,
    id: &str,
) -> Result<Option<AdminAgentRecord>, crate::store::StoreError> {
    Ok(store
        .list_admin_agents()
        .await?
        .into_iter()
        .find(|agent| agent.id == id))
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

pub(crate) fn agent_body(agent: &AdminAgentRecord, workspace_id: &str) -> serde_json::Value {
    json!({
        "id": agent.id,
        "agent_id": agent.agent_id,
        "workspace_id": workspace_id,
        "display_name": agent.name,
        "status": agent.status,
        "created_at": rfc3339_millis(agent.created_at_ms),
        "revoked_at": agent.revoked_at_ms.map(rfc3339_millis)
    })
}

pub(crate) fn rfc3339_millis(timestamp_ms: i64) -> String {
    let seconds = timestamp_ms.div_euclid(1_000);
    let milliseconds = timestamp_ms.rem_euclid(1_000);
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z")
}

fn valid_agent_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
}

fn ring_from_id(agent_id: &str) -> Option<String> {
    agent_id
        .split_once("/ring/")
        .map(|(_, ring)| ring.to_owned())
        .filter(|ring| !ring.is_empty())
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
