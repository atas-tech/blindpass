// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::admin_agents::{agent_body, rfc3339_millis};
use crate::routes::auth::{
    AuthError, authenticate_api_key, authenticate_user, hash_api_key, mint_agent_token, new_api_key,
};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v2/agents/token", post(mint_token))
        .route("/api/v2/agents/{aid}/rotate-key", post(rotate_key))
        .route("/api/v2/agents/{aid}", delete(revoke_agent))
}

#[derive(Serialize)]
struct AgentView {
    id: String,
    workspace_id: String,
    agent_id: String,
    display_name: String,
    status: String,
    created_at: String,
    revoked_at: Option<String>,
}

#[derive(Serialize)]
struct AgentTokenResponse {
    access_token: String,
    access_token_expires_at: u64,
    agent: AgentView,
}

async fn mint_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"service_unavailable"})),
        )
            .into_response();
    };
    let client_ip = client_ip(&headers, peer, &state);
    let rate = match store
        .consume_rate_limit(
            &format!("agent-token:{client_ip}"),
            state.agent_token_rate_limit,
            state.agent_token_rate_window_ms,
        )
        .await
    {
        Ok(rate) => rate,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"service_unavailable"})),
            )
                .into_response();
        }
    };
    if rate.count > i64::from(state.agent_token_rate_limit) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                axum::http::header::RETRY_AFTER,
                rate.retry_after_seconds.to_string(),
            )],
            Json(json!({
                "error":"Too many token requests",
                "code":"rate_limited",
                "retry_after_seconds":rate.retry_after_seconds,
                "limit":state.agent_token_rate_limit,
                "used":rate.count
            })),
        )
            .into_response();
    }
    let agent = match authenticate_api_key(store, &headers).await {
        Ok(agent) => agent,
        Err(AuthError::MissingBearer) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"Missing agent API key","code":"missing_api_key"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"Invalid agent API key","code":"invalid_api_key"})),
            )
                .into_response();
        }
    };
    let tenant_id = store.tenant_id().to_owned();
    let (access_token, access_token_expires_at) = match mint_agent_token(&state, &agent, &tenant_id)
    {
        Ok(token) => token,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"token_mint_failed"})),
            )
                .into_response();
        }
    };
    let _ = store
        .append_audit(
            "agent_token_minted",
            "agent",
            Some(&agent.agent_id),
            "agent",
            Some(&agent.agent_id),
            &json!({"action":"agent_token_mint","key_version":agent.key_version}),
        )
        .await;
    Json(AgentTokenResponse {
        access_token,
        access_token_expires_at,
        agent: AgentView {
            id: agent.id,
            workspace_id: tenant_id,
            agent_id: agent.agent_id,
            display_name: agent.name,
            status: agent.status,
            created_at: rfc3339_millis(agent.created_at_ms),
            revoked_at: agent.revoked_at_ms.map(rfc3339_millis),
        },
    })
    .into_response()
}

async fn rotate_key(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"service_unavailable"})),
        )
            .into_response();
    };
    match authenticate_user(&state, &headers) {
        Ok(user) if user.role == "workspace_admin" => {}
        Ok(_) => {
            return (StatusCode::FORBIDDEN, Json(json!({"error":"forbidden"}))).into_response();
        }
        Err(error) => return auth_error_response(error),
    }
    if agent_id.is_empty()
        || agent_id.len() > 160
        || !agent_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@-".contains(&byte))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_agent_id"})),
        )
            .into_response();
    }
    let existing = match store.agent_by_agent_id(&agent_id).await {
        Ok(Some(agent)) if agent.status == "active" => agent,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"agent_not_found"})),
            )
                .into_response();
        }
        Ok(Some(_)) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"agent_not_found"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"agent_rotation_failed"})),
            )
                .into_response();
        }
    };
    let api_key = new_api_key(&existing.id);
    let hash = match hash_api_key(&api_key) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"agent_rotation_failed"})),
            )
                .into_response();
        }
    };
    let rotated = match store
        .replace_agent_api_key_hash(&agent_id, existing.key_version, &hash)
        .await
    {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"agent_key_changed"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"agent_rotation_failed"})),
            )
                .into_response();
        }
    };
    Json(json!({
        "agent": {
            "id": rotated.id,
            "workspace_id": store.tenant_id(),
            "agent_id": rotated.agent_id,
            "display_name": rotated.name,
            "status": rotated.status,
            "created_at": rfc3339_millis(rotated.created_at_ms),
            "revoked_at": rotated.revoked_at_ms.map(rfc3339_millis)
        },
        "bootstrap_api_key": api_key
    }))
    .into_response()
}

async fn revoke_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"service_unavailable"})),
        )
            .into_response();
    };
    match authenticate_user(&state, &headers) {
        Ok(user) if user.role == "workspace_admin" => {}
        Ok(_) => {
            return (StatusCode::FORBIDDEN, Json(json!({"error":"forbidden"}))).into_response();
        }
        Err(error) => return auth_error_response(error),
    }
    match store.revoke_agent(&agent_id).await {
        Ok(true) => match store.agent_by_agent_id(&agent_id).await {
            Ok(Some(agent)) => {
                let record = crate::store::AdminAgentRecord {
                    id: agent.id,
                    agent_id: agent.agent_id,
                    name: agent.name,
                    status: agent.status,
                    created_at_ms: agent.created_at_ms,
                    revoked_at_ms: agent.revoked_at_ms,
                };
                Json(json!({"agent":agent_body(&record, store.tenant_id())})).into_response()
            }
            Ok(None) | Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"agent_revoke_failed"})),
            )
                .into_response(),
        },
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"agent_not_found"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"agent_revoke_failed"})),
        )
            .into_response(),
    }
}

fn client_ip(headers: &HeaderMap, peer: SocketAddr, state: &AppState) -> String {
    if state.trusted_proxy_addresses.contains(&peer.ip()) {
        if state.test_mode && peer.ip().is_loopback() {
            if let Some(forwarded) = headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                && let Some(address) = forwarded
                    .split(',')
                    .find_map(|value| value.trim().parse::<IpAddr>().ok())
            {
                return address.to_string();
            }
        } else if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        {
            let chain = forwarded
                .split(',')
                .filter_map(|value| value.trim().parse::<IpAddr>().ok())
                .collect::<Vec<_>>();
            for address in chain.iter().rev() {
                if !state.trusted_proxy_addresses.contains(address) {
                    return address.to_string();
                }
            }
            if let Some(address) = chain.first() {
                return address.to_string();
            }
        }
    }
    peer.ip().to_string()
}

fn auth_error_response(error: AuthError) -> Response {
    match error {
        AuthError::MissingBearer => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Missing bearer token"})),
        )
            .into_response(),
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Invalid token"})),
        )
            .into_response(),
    }
}
