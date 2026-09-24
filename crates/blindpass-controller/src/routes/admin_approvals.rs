// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::admin_session::{authenticated_session, valid_origin, valid_session_csrf};
use crate::store::{ApprovalDecisionOutcome, ApprovalRecord, AuditRecord, LocalSession};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blindpass_core::custody::sha256;
use serde::Deserialize;
use serde_json::{Value, json};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v3/admin/approvals", get(list_approvals))
        .route("/api/v3/admin/approvals/count", get(count_approvals))
        .route("/api/v3/admin/approvals/{reference}", get(get_approval))
        .route("/api/v3/admin/approvals/{reference}/approve", post(approve))
        .route("/api/v3/admin/approvals/{reference}/reject", post(reject))
        .route("/api/v3/admin/audit", get(list_audit))
        .route("/api/v3/admin/audit/exchange/{id}", get(exchange_audit))
}

#[derive(Deserialize)]
struct ApprovalQuery {
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct AuditQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecisionInput {
    expected_status: String,
}

async fn list_approvals(
    State(state): State<AppState>,
    Query(query): Query<ApprovalQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_approver(&state, &headers, false).await {
        return *response;
    }
    if query
        .status
        .as_deref()
        .is_some_and(|status| !matches!(status, "pending" | "approved" | "rejected"))
    {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_status",
            "approval status is invalid",
        );
    }
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_limit",
            "limit must be between 1 and 100",
        );
    }
    let cursor = match query.cursor.as_deref().map(decode_cursor).transpose() {
        Ok(cursor) => cursor,
        Err(_) => {
            return admin_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "approval cursor is invalid",
            );
        }
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let rows = match store
        .list_approvals(query.status.as_deref(), cursor, limit + 1)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let has_more = rows.len() > limit as usize;
    let mut page = rows;
    page.truncate(limit as usize);
    let next_cursor = has_more.then(|| page.last().map(approval_cursor)).flatten();
    Json(json!({
        "items":page.iter().map(approval_body).collect::<Vec<_>>(),
        "next_cursor":next_cursor
    }))
    .into_response()
}

async fn count_approvals(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_approver(&state, &headers, false).await {
        return *response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.count_pending_approvals().await {
        Ok(count) => Json(json!({"count":count})).into_response(),
        Err(_) => unavailable(),
    }
}

async fn get_approval(
    State(state): State<AppState>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_approver(&state, &headers, false).await {
        return *response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.get_approval(&reference).await {
        Ok(Some(approval)) => Json(approval_body(&approval)).into_response(),
        Ok(None) => admin_error(
            StatusCode::NOT_FOUND,
            "approval_not_found",
            "approval was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn approve(
    State(state): State<AppState>,
    Path(reference): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ApprovalDecisionInput>,
) -> Response {
    decide(state, reference, headers, body, "approved").await
}

async fn reject(
    State(state): State<AppState>,
    Path(reference): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ApprovalDecisionInput>,
) -> Response {
    decide(state, reference, headers, body, "rejected").await
}

async fn decide(
    state: AppState,
    reference: String,
    headers: HeaderMap,
    body: ApprovalDecisionInput,
    decision: &str,
) -> Response {
    let session = match require_approver(&state, &headers, true).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if body.expected_status != "pending" {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_expected_status",
            "expected_status must be pending",
        );
    }
    let Some(idempotency_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| (16..=128).contains(&value.len()))
    else {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "Idempotency-Key must contain 16 to 128 characters",
        );
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let approval = match store.get_approval(&reference).await {
        Ok(Some(approval)) => approval,
        Ok(None) => {
            return admin_error(
                StatusCode::NOT_FOUND,
                "approval_not_found",
                "approval was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    if !assigned_to_operator(&approval, &session) {
        return admin_error(
            StatusCode::FORBIDDEN,
            "approval_scope_denied",
            "approval is not assigned to this operator",
        );
    }
    let Some(key_hash) = sha256(idempotency_key.as_bytes()).ok().map(|digest| {
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }) else {
        return unavailable();
    };
    match store
        .decide_approval_idempotent(&reference, decision, &session.operator.id, &key_hash)
        .await
    {
        Ok(
            ApprovalDecisionOutcome::Applied(record) | ApprovalDecisionOutcome::Replayed(record),
        ) => Json(decision_body(&record)).into_response(),
        Ok(ApprovalDecisionOutcome::Conflict) => admin_error(
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "Idempotency-Key was already used for a different decision",
        ),
        Ok(ApprovalDecisionOutcome::NotFound) => admin_error(
            StatusCode::CONFLICT,
            "approval_not_pending",
            "approval is no longer pending or has expired",
        ),
        Err(_) => unavailable(),
    }
}

async fn list_audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_session(&state, &headers, false).await {
        return *response;
    }
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_limit",
            "limit must be between 1 and 100",
        );
    }
    let cursor = match query.cursor.as_deref().map(decode_cursor).transpose() {
        Ok(cursor) => cursor,
        Err(_) => {
            return admin_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "audit cursor is invalid",
            );
        }
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let rows = match store.list_audit_after_cursor(cursor, limit + 1).await {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let has_more = rows.len() > limit as usize;
    let mut page = rows;
    page.truncate(limit as usize);
    let next_cursor = has_more.then(|| page.last().map(audit_cursor)).flatten();
    Json(json!({
        "items":page.iter().map(audit_body).collect::<Vec<_>>(),
        "next_cursor":next_cursor
    }))
    .into_response()
}

async fn exchange_audit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_session(&state, &headers, false).await {
        return *response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.list_exchange_lifecycle(&id, 200).await {
        Ok(records) if !records.is_empty() => Json(json!({
            "items":records.iter().map(audit_body).collect::<Vec<_>>(),
            "next_cursor":Value::Null
        }))
        .into_response(),
        Ok(_) => admin_error(
            StatusCode::NOT_FOUND,
            "exchange_not_found",
            "exchange audit was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn require_approver(
    state: &AppState,
    headers: &HeaderMap,
    unsafe_method: bool,
) -> Result<LocalSession, Box<Response>> {
    let session = require_session(state, headers, unsafe_method).await?;
    if !matches!(session.operator.role.as_str(), "admin" | "operator") {
        return Err(Box::new(admin_error(
            StatusCode::FORBIDDEN,
            "role_denied",
            "administrator or operator role is required",
        )));
    }
    Ok(session)
}

async fn require_session(
    state: &AppState,
    headers: &HeaderMap,
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
    if unsafe_method && (!valid_origin(state, headers) || !valid_session_csrf(headers, &session)) {
        return Err(Box::new(admin_error(
            StatusCode::FORBIDDEN,
            "csrf_or_origin_denied",
            "origin or CSRF validation failed",
        )));
    }
    Ok(session)
}

fn assigned_to_operator(approval: &ApprovalRecord, session: &LocalSession) -> bool {
    !approval.approver_ids.is_empty()
        && approval
            .approver_ids
            .iter()
            .any(|id| id == &session.operator.id || id == &session.operator.username)
        && approval.approver_rings.is_empty()
}

fn approval_body(approval: &ApprovalRecord) -> Value {
    json!({
        "reference":approval.approval_reference,
        "status":approval.status,
        "requester_id":approval.requester_id,
        "secret_name":approval.secret_name,
        "purpose":approval.purpose,
        "created_at":approval.created_at_ms,
        "timeline":[]
    })
}

fn decision_body(approval: &ApprovalRecord) -> Value {
    json!({
        "approval_reference":approval.approval_reference,
        "status":approval.status,
        "decided_at":approval.decided_at_ms,
        "decided_by":approval.decided_by
    })
}

fn audit_body(audit: &AuditRecord) -> Value {
    json!({
        "id":audit.id,
        "event":audit.event_type,
        "actor_id":audit.actor_id,
        "resource_id":audit.resource_id,
        "created_at":audit.created_at_ms,
        "metadata":audit.metadata
    })
}

fn approval_cursor(approval: &ApprovalRecord) -> String {
    URL_SAFE_NO_PAD.encode(format!(
        "{}:{}",
        approval.created_at_ms, approval.approval_reference
    ))
}

fn audit_cursor(audit: &AuditRecord) -> String {
    URL_SAFE_NO_PAD.encode(format!("{}:{}", audit.created_at_ms, audit.id))
}

fn decode_cursor(cursor: &str) -> Result<(i64, String), ()> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| ())?;
    let cursor = String::from_utf8(bytes).map_err(|_| ())?;
    let (timestamp, identifier) = cursor.split_once(':').ok_or(())?;
    let timestamp = timestamp.parse::<i64>().map_err(|_| ())?;
    if identifier.is_empty() {
        return Err(());
    }
    Ok((timestamp, identifier.to_owned()))
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
