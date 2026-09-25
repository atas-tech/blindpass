// SPDX-License-Identifier: AGPL-3.0-only

//! Administrator-controlled workload registrations and fleet policy.

use crate::app::AppState;
use crate::routes::fleet::{api_error, require_operator, unavailable};
use crate::store::{
    ApprovalDecisionOutcome, ApprovalRecord, FleetPolicyRecord, GrantIssueDraft, GrantIssueOutcome,
    GrantRecord, GrantRevocationOutcome, OperationApprovalDraft, OperationApprovalRecord,
    OperationCreateOutcome, OperationDecisionOutcome, OperationRecord, WorkloadRecord,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blindpass_core::canon::canonicalize_json;
use blindpass_core::custody::sha256;
use blindpass_core::fleet::{
    ConsumptionMode, DocumentKind, Grant, Registration, Revocation, SignedEnvelope,
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v3/workloads",
            get(list_workloads).post(create_workload),
        )
        .route(
            "/api/v3/workloads/{id}",
            get(get_workload)
                .patch(update_workload)
                .delete(revoke_workload),
        )
        .route("/api/v3/policies", get(get_policy).put(update_policy))
        .route(
            "/api/v3/operations",
            get(list_operations).post(create_operation),
        )
        .route(
            "/api/v3/operations/{id}",
            get(get_operation).delete(cancel_operation),
        )
        .route("/api/v3/grants", get(list_grants))
        .route("/api/v3/grants/{id}", get(get_grant).delete(revoke_grant))
        .route("/api/v3/approvals", get(list_unified_approvals))
        .route("/api/v3/approvals/count", get(count_unified_approvals))
        .route("/api/v3/approvals/{id}", get(get_unified_approval))
        .route(
            "/api/v3/approvals/{id}/approve",
            post(approve_unified_approval),
        )
        .route(
            "/api/v3/approvals/{id}/reject",
            post(reject_unified_approval),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadCreateInput {
    node_id: String,
    name: String,
    unit: String,
    account: String,
    consumption_mode: String,
    local_ceiling_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadUpdateInput {
    expected_version: i64,
    unit: Option<String>,
    account: Option<String>,
    consumption_mode: Option<String>,
    local_ceiling_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyInput {
    expected_version: i64,
    rules: Vec<FleetRuleInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetRuleInput {
    id: String,
    action: String,
    mode: String,
    decision: String,
    approval_required: bool,
    max_ttl_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationInput {
    workload_id: String,
    action: String,
    mode: String,
    purpose: String,
    resource_id: String,
    invocation_id: String,
    ttl_seconds: u64,
    broker_event_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationDecisionInput {
    expected_status: String,
    expected_version: Option<i64>,
    operation_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ApprovalQuery {
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OperationQuery {
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct GrantQuery {
    node_id: Option<String>,
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct WorkloadQuery {
    node_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

async fn list_workloads(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WorkloadQuery>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, false, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_limit",
            "limit must be between 1 and 100",
        );
    }
    if query
        .node_id
        .as_deref()
        .is_some_and(|node_id| !valid_id(node_id))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_node_id",
            "node id is invalid",
        );
    }
    let cursor = match parse_cursor(query.cursor.as_deref()) {
        Ok(cursor) => cursor,
        Err(()) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "cursor is invalid",
            );
        }
    };
    let mut records = match store
        .list_workloads(query.node_id.as_deref(), limit + 1, cursor)
        .await
    {
        Ok(records) => records,
        Err(_) => return unavailable(),
    };
    let has_more = records.len() > limit as usize;
    records.truncate(limit as usize);
    let next_cursor = has_more
        .then(|| {
            records
                .last()
                .map(|row| cursor_for(row.created_at_ms, &row.id))
        })
        .flatten();
    Json(json!({"items":records.iter().map(workload_body).collect::<Vec<_>>(),"next_cursor":next_cursor})).into_response()
}

async fn get_workload(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, false, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.workload_by_id(&id).await {
        Ok(Some(record)) => Json(workload_body(&record)).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "workload_not_found",
            "workload was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn create_workload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WorkloadCreateInput>,
) -> Response {
    let operator = match require_operator(&state, &headers, true, true).await {
        Ok(operator) => operator,
        Err(response) => return response,
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let Some(issuer) = state.issuer_keypair.as_ref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet_disabled",
            "fleet authorization is not configured",
        );
    };
    let name = body.name.trim();
    if !valid_id(&body.node_id)
        || name.is_empty()
        || name.len() > 128
        || name.chars().any(char::is_control)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_workload",
            "node id or workload name is invalid",
        );
    }
    if let Err(message) = validate_workload_fields(
        &body.unit,
        &body.account,
        &body.consumption_mode,
        body.local_ceiling_seconds,
    ) {
        return api_error(StatusCode::BAD_REQUEST, "invalid_workload", message);
    }
    let policy = match store.fleet_policy().await {
        Ok(policy) => policy,
        Err(_) => return unavailable(),
    };
    let record = WorkloadRecord {
        id: random_id("wl_"),
        node_id: body.node_id,
        name: name.to_owned(),
        unit: body.unit,
        account: body.account,
        consumption_mode: body.consumption_mode,
        local_ceiling_seconds: i64::try_from(body.local_ceiling_seconds).unwrap_or_default(),
        registration_version: 1,
        status: "active".to_owned(),
        created_at_ms: 0,
        revoked_at_ms: None,
        version: 1,
    };
    let Some(registration_envelope_json) =
        signed_registration(&state, store, issuer, &record, policy.version, "active").await
    else {
        return unavailable();
    };
    let Some(policy_envelope_json) =
        signed_policy_snapshot(&state, store, issuer, policy.version, &policy.document_json).await
    else {
        return unavailable();
    };
    match store
        .create_workload(
            &record,
            &operator.operator.id,
            &registration_envelope_json,
            &policy_envelope_json,
        )
        .await
    {
        Ok(true) => match store.workload_by_id(&record.id).await {
            Ok(Some(saved)) => (StatusCode::CREATED, Json(workload_body(&saved))).into_response(),
            _ => unavailable(),
        },
        Ok(false) => api_error(
            StatusCode::CONFLICT,
            "node_unavailable",
            "node is unavailable or workload name is already registered",
        ),
        Err(_) => unavailable(),
    }
}

async fn update_workload(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<WorkloadUpdateInput>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, true, true).await {
        return response;
    }
    if body.expected_version <= 0
        || (body.unit.is_none()
            && body.account.is_none()
            && body.consumption_mode.is_none()
            && body.local_ceiling_seconds.is_none())
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_workload_update",
            "expected_version and at least one field change are required",
        );
    }
    if let Err(response) = require_if_match(&headers, body.expected_version) {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let Some(issuer) = state.issuer_keypair.as_ref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet_disabled",
            "fleet authorization is not configured",
        );
    };
    let current = match store.workload_by_id(&id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "workload_not_found",
                "workload was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    if current.version != body.expected_version || current.status != "active" {
        return api_error(
            StatusCode::CONFLICT,
            "workload_changed",
            "workload changed or is revoked",
        );
    }
    let unit = body.unit.as_deref().unwrap_or(&current.unit);
    let account = body.account.as_deref().unwrap_or(&current.account);
    let mode = body
        .consumption_mode
        .as_deref()
        .unwrap_or(&current.consumption_mode);
    let ceiling = body
        .local_ceiling_seconds
        .map(i64::try_from)
        .transpose()
        .ok()
        .flatten()
        .unwrap_or(current.local_ceiling_seconds);
    if body
        .local_ceiling_seconds
        .is_some_and(|value| i64::try_from(value).is_err())
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_workload",
            "local ceiling is invalid",
        );
    }
    if let Err(message) = validate_workload_fields(
        unit,
        account,
        mode,
        u64::try_from(ceiling).unwrap_or_default(),
    ) {
        return api_error(StatusCode::BAD_REQUEST, "invalid_workload", message);
    }
    let policy = match store.fleet_policy().await {
        Ok(policy) => policy,
        Err(_) => return unavailable(),
    };
    let mut updated = current.clone();
    updated.unit = unit.to_owned();
    updated.account = account.to_owned();
    updated.consumption_mode = mode.to_owned();
    updated.local_ceiling_seconds = ceiling;
    updated.registration_version += 1;
    updated.version += 1;
    let Some(envelope_json) =
        signed_registration(&state, store, issuer, &updated, policy.version, "active").await
    else {
        return unavailable();
    };
    let Some(policy_envelope_json) =
        signed_policy_snapshot(&state, store, issuer, policy.version, &policy.document_json).await
    else {
        return unavailable();
    };
    match store
        .update_workload(
            &id,
            body.expected_version,
            unit,
            account,
            mode,
            ceiling,
            &current.node_id,
            &envelope_json,
            &policy_envelope_json,
        )
        .await
    {
        Ok(true) => match store.workload_by_id(&id).await {
            Ok(Some(record)) => Json(workload_body(&record)).into_response(),
            _ => unavailable(),
        },
        Ok(false) => api_error(
            StatusCode::CONFLICT,
            "workload_changed",
            "workload changed before the update could be applied",
        ),
        Err(_) => unavailable(),
    }
}

async fn revoke_workload(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, true, true).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let Some(issuer) = state.issuer_keypair.as_ref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet_disabled",
            "fleet authorization is not configured",
        );
    };
    let current = match store.workload_by_id(&id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "workload_not_found",
                "workload was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    if current.status != "active" {
        return api_error(
            StatusCode::CONFLICT,
            "workload_revoked",
            "workload is already revoked",
        );
    }
    let policy = match store.fleet_policy().await {
        Ok(policy) => policy,
        Err(_) => return unavailable(),
    };
    let mut revoked = current.clone();
    revoked.status = "revoked".to_owned();
    revoked.registration_version += 1;
    revoked.version += 1;
    let Some(envelope_json) =
        signed_registration(&state, store, issuer, &revoked, policy.version, "revoked").await
    else {
        return unavailable();
    };
    let Some(policy_envelope_json) =
        signed_policy_snapshot(&state, store, issuer, policy.version, &policy.document_json).await
    else {
        return unavailable();
    };
    match store
        .revoke_workload(
            &id,
            &current.node_id,
            current.version,
            &envelope_json,
            &policy_envelope_json,
        )
        .await
    {
        Ok(true) => match store.workload_by_id(&id).await {
            Ok(Some(record)) => Json(workload_body(&record)).into_response(),
            _ => unavailable(),
        },
        Ok(false) => api_error(
            StatusCode::CONFLICT,
            "workload_changed",
            "workload changed before revocation",
        ),
        Err(_) => unavailable(),
    }
}

async fn get_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_operator(&state, &headers, false, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.fleet_policy().await {
        Ok(policy) => policy_body(policy),
        Err(_) => unavailable(),
    }
}

async fn update_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PolicyInput>,
) -> Response {
    let operator = match require_operator(&state, &headers, true, true).await {
        Ok(operator) => operator,
        Err(response) => return response,
    };
    if body.expected_version <= 0 || body.rules.len() > 256 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_policy",
            "policy version or rule count is invalid",
        );
    }
    if let Err(response) = require_if_match(&headers, body.expected_version) {
        return response;
    }
    let mut ids = std::collections::HashSet::new();
    let mut subjects = std::collections::HashSet::new();
    let mut canonical_rules = Vec::with_capacity(body.rules.len());
    for rule in &body.rules {
        if !valid_id(&rule.id)
            || !ids.insert(rule.id.as_str())
            || !subjects.insert((rule.action.as_str(), rule.mode.as_str()))
            || rule.action != "noop.marker"
            || !matches!(rule.mode.as_str(), "file" | "socket")
            || !matches!(
                rule.decision.as_str(),
                "allow" | "pending_approval" | "deny"
            )
            || rule.approval_required != (rule.decision == "pending_approval")
            || !(1..=3600).contains(&rule.max_ttl_seconds)
        {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_policy_rule",
                "policy rule is invalid or contradictory",
            );
        }
        canonical_rules.push(json!({
            "id":rule.id,"action":rule.action,"mode":rule.mode,"decision":rule.decision,
            "approval_required":rule.approval_required,"max_ttl_seconds":rule.max_ttl_seconds
        }));
    }
    let document = json!({"rules":canonical_rules});
    let document_json = match canonicalize_json(&document.to_string())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    {
        Some(value) => value,
        None => return unavailable(),
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let Some(issuer) = state.issuer_keypair.as_ref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet_disabled",
            "fleet authorization is not configured",
        );
    };
    let next_version = match body.expected_version.checked_add(1) {
        Some(version) => version,
        None => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_policy",
                "version is invalid",
            );
        }
    };
    let policy_envelope_json =
        match signed_policy_snapshot_for_rules(&state, store, issuer, next_version, &body.rules)
            .await
        {
            Some(document) => document,
            None => return unavailable(),
        };
    let node_ids = match store.active_node_ids().await {
        Ok(node_ids) => node_ids,
        Err(_) => return unavailable(),
    };
    let node_documents = node_ids
        .into_iter()
        .map(|node_id| (node_id, policy_envelope_json.clone()))
        .collect::<Vec<_>>();
    match store
        .replace_fleet_policy(
            body.expected_version,
            &document_json,
            &operator.operator.id,
            &node_documents,
        )
        .await
    {
        Ok(true) => match store.fleet_policy().await {
            Ok(policy) => policy_body(policy),
            Err(_) => unavailable(),
        },
        Ok(false) => api_error(
            StatusCode::CONFLICT,
            "policy_changed",
            "policy version is stale",
        ),
        Err(_) => unavailable(),
    }
}

async fn create_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<OperationInput>,
) -> Response {
    let operator = match require_fleet_operator(&state, &headers, true).await {
        Ok(operator) => operator,
        Err(response) => return response,
    };
    let Some(idempotency_key) = idempotency_key(&headers) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "Idempotency-Key must contain 16 to 128 safe characters",
        );
    };
    if !valid_id(&body.workload_id)
        || body.action != "noop.marker"
        || !matches!(body.mode.as_str(), "file" | "socket")
        || body.purpose.len() > 512
        || !valid_id(&body.resource_id)
        || !valid_id(&body.invocation_id)
        || !(1..=3600).contains(&body.ttl_seconds)
        || !(16..=128).contains(&body.broker_event_key.len())
        || !valid_id(&body.broker_event_key)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_operation",
            "operation fields are invalid",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let workload = match store.workload_by_id(&body.workload_id).await {
        Ok(Some(workload)) if workload.status == "active" => workload,
        Ok(Some(_)) => {
            return api_error(
                StatusCode::CONFLICT,
                "workload_unavailable",
                "workload is revoked",
            );
        }
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "workload_not_found",
                "workload was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    if workload.consumption_mode != body.mode {
        return api_error(
            StatusCode::FORBIDDEN,
            "workload_mode_denied",
            "operation mode differs from the administrator registration",
        );
    }
    let node = match store.node_by_id(&workload.node_id).await {
        Ok(Some(node)) if node.status == "active" => node,
        Ok(_) => {
            return api_error(
                StatusCode::CONFLICT,
                "node_unavailable",
                "workload node is unavailable",
            );
        }
        Err(_) => return unavailable(),
    };
    let now_ms = match store.database_now_ms().await {
        Ok(now_ms) => now_ms,
        Err(_) => return unavailable(),
    };
    if node
        .last_seen_at_ms
        .is_none_or(|seen| now_ms.saturating_sub(seen) > 120_000 || seen > now_ms + 60_000)
    {
        return api_error(
            StatusCode::CONFLICT,
            "node_offline",
            "operation requests require a recently connected node",
        );
    }
    let event = match store
        .node_event_by_key(&workload.node_id, &body.broker_event_key)
        .await
    {
        Ok(Some(event)) => event,
        Ok(None) => {
            return api_error(
                StatusCode::CONFLICT,
                "broker_evidence_required",
                "a recent broker-signed operation request is required",
            );
        }
        Err(_) => return unavailable(),
    };
    if event.kind != "operation_request"
        || now_ms.saturating_sub(event.received_at_ms) > 60_000
        || event.received_at_ms > now_ms.saturating_add(60_000)
    {
        return api_error(
            StatusCode::CONFLICT,
            "broker_evidence_stale",
            "broker operation evidence is stale or has the wrong event kind",
        );
    }
    let event_body: JsonValue = match serde_json::from_str(&event.body_json) {
        Ok(value) => value,
        Err(_) => return unavailable(),
    };
    if !operation_matches_broker_event(&body, &workload, &event_body, now_ms) {
        return api_error(
            StatusCode::CONFLICT,
            "broker_evidence_mismatch",
            "operation details do not match the signed broker event and workload registration",
        );
    }
    let policy = match store.fleet_policy().await {
        Ok(policy) => policy,
        Err(_) => return unavailable(),
    };
    let policy_rules: Vec<FleetRuleInput> =
        match serde_json::from_str::<JsonValue>(&policy.document_json)
            .ok()
            .and_then(|document| document.get("rules").cloned())
            .and_then(|rules| serde_json::from_value(rules).ok())
        {
            Some(rules) => rules,
            None => return unavailable(),
        };
    let rule = policy_rules
        .iter()
        .find(|rule| rule.action == body.action && rule.mode == body.mode);
    let decision = rule.map_or("deny", |rule| rule.decision.as_str());
    let policy_ttl = rule.map_or(3600, |rule| rule.max_ttl_seconds);
    let effective_ttl = body
        .ttl_seconds
        .min(policy_ttl)
        .min(u64::try_from(workload.local_ceiling_seconds).unwrap_or(0));
    if effective_ttl == 0 {
        return api_error(
            StatusCode::CONFLICT,
            "workload_ceiling_invalid",
            "workload local TTL ceiling is invalid",
        );
    }
    let effective_ttl_i64 = match i64::try_from(effective_ttl) {
        Ok(value) => value,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_operation",
                "TTL is invalid",
            );
        }
    };
    let decision = decision.to_owned();
    let expires_in_seconds = if decision == "pending_approval" {
        600_i64
    } else {
        effective_ttl_i64
    };
    let expires_at_ms = now_ms.saturating_add(expires_in_seconds.saturating_mul(1_000));
    let purpose = sanitize_purpose(&body.purpose);
    let requester_summary = json!({
        "operator_id":operator.operator.id,
        "requester":operator.operator.username,
        "action":body.action,
        "mode":body.mode,
        "resource_id":body.resource_id,
        "purpose":purpose
    });
    let verified_identity = json!({
        "node_id":workload.node_id,
        "workload_id":workload.id,
        "unit":workload.unit,
        "account":workload.account,
        "invocation_id":body.invocation_id,
        "observed_at":event_body["observed_at_ms"]
    });
    let requester_summary_json = match canonical_json_string(&requester_summary) {
        Some(value) => value,
        None => return unavailable(),
    };
    let verified_identity_json = match canonical_json_string(&verified_identity) {
        Some(value) => value,
        None => return unavailable(),
    };
    let request_material = json!({
        "event_key":body.broker_event_key,
        "event_hash":event.id,
        "requester_id":operator.operator.id
    });
    let Some(request_hash) = json_hash(&request_material) else {
        return unavailable();
    };
    let Some(idempotency_hash) = digest_hex(idempotency_key.as_bytes()) else {
        return unavailable();
    };
    let operation_id = random_id("op_");
    let status = match decision.as_str() {
        "allow" => "requested",
        "pending_approval" => "awaiting_approval",
        _ => "denied",
    };
    let decision_hash = json_hash(&json!({
        "policy_version":policy.version,
        "rule_id":rule.map(|rule| rule.id.as_str()),
        "decision":decision,
        "ttl_seconds":effective_ttl
    }));
    let record = OperationRecord {
        id: operation_id.clone(),
        workload_id: workload.id.clone(),
        node_id: workload.node_id.clone(),
        invocation_id: body.invocation_id.clone(),
        action: body.action.clone(),
        mode: body.mode.clone(),
        resource_id: body.resource_id.clone(),
        requested_ttl_seconds: effective_ttl_i64,
        broker_event_key: Some(body.broker_event_key.clone()),
        requested_by: operator.operator.id.clone(),
        purpose,
        policy_version: policy.version,
        decision: decision.clone(),
        decision_hash,
        status: status.to_owned(),
        approval_id: None,
        grant_id: None,
        idempotency_key: idempotency_hash,
        request_hash,
        result_json: None,
        created_at_ms: now_ms,
        expires_at_ms,
        completed_at_ms: None,
        version: 1,
    };
    let approval_draft = (decision == "pending_approval").then(|| OperationApprovalDraft {
        id: random_id("oa_"),
        idempotency_key: format!("oa-for-{}", operation_id),
        requester_summary_json,
        verified_identity_json,
        rule_id: rule.map_or_else(String::new, |rule| rule.id.clone()),
        expires_at_ms,
    });
    match store
        .create_operation(
            &record,
            &workload.unit,
            &workload.account,
            effective_ttl_i64,
            approval_draft.as_ref(),
        )
        .await
    {
        Ok(OperationCreateOutcome::Created(mut operation)) => {
            if operation.decision == "allow" {
                match ensure_operation_grants(&state, std::slice::from_ref(&operation.id)).await {
                    Ok(()) => {
                        if let Ok(Some(updated)) = store.operation_by_id(&operation.id).await {
                            operation = updated;
                        }
                    }
                    Err(GrantIssuanceError::Stale) => {
                        return api_error(
                            StatusCode::CONFLICT,
                            "authorization_changed",
                            "operation authorization changed before its grant could be issued",
                        );
                    }
                    Err(GrantIssuanceError::Unavailable) => return unavailable(),
                }
            }
            (StatusCode::CREATED, Json(operation_body(&operation))).into_response()
        }
        Ok(OperationCreateOutcome::Existing(mut operation)) => {
            if operation.decision == "allow" && operation.status == "requested" {
                match ensure_operation_grants(&state, std::slice::from_ref(&operation.id)).await {
                    Ok(()) => {
                        if let Ok(Some(updated)) = store.operation_by_id(&operation.id).await {
                            operation = updated;
                        }
                    }
                    Err(GrantIssuanceError::Stale) => {
                        return api_error(
                            StatusCode::CONFLICT,
                            "authorization_changed",
                            "operation authorization changed before its grant could be issued",
                        );
                    }
                    Err(GrantIssuanceError::Unavailable) => return unavailable(),
                }
            }
            Json(operation_body(&operation)).into_response()
        }
        Ok(OperationCreateOutcome::Conflict) => api_error(
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "the idempotency key or broker event was already used for a different operation",
        ),
        Ok(OperationCreateOutcome::Stale) => api_error(
            StatusCode::CONFLICT,
            "authorization_changed",
            "policy, workload, node or operation deadline changed",
        ),
        Err(_) => unavailable(),
    }
}

async fn list_operations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OperationQuery>,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, false).await {
        return response;
    }
    if query.status.as_deref().is_some_and(|status| {
        !matches!(
            status,
            "requested"
                | "awaiting_approval"
                | "granted"
                | "executing"
                | "completed"
                | "failed"
                | "uncertain"
                | "denied"
                | "revoked"
                | "cancelled"
        )
    }) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_status",
            "operation status is invalid",
        );
    }
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_limit",
            "limit must be between 1 and 100",
        );
    }
    let cursor = match parse_cursor(query.cursor.as_deref()) {
        Ok(cursor) => cursor,
        Err(()) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "operation cursor is invalid",
            );
        }
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let mut records = match store
        .list_operations(query.status.as_deref(), cursor, limit + 1)
        .await
    {
        Ok(records) => records,
        Err(_) => return unavailable(),
    };
    let has_more = records.len() > limit as usize;
    records.truncate(limit as usize);
    let next_cursor = has_more
        .then(|| {
            records
                .last()
                .map(|record| cursor_for(record.created_at_ms, &record.id))
        })
        .flatten();
    Json(json!({"items":records.iter().map(operation_body).collect::<Vec<_>>(),"next_cursor":next_cursor})).into_response()
}

async fn get_operation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.operation_by_id(&id).await {
        Ok(Some(record)) => Json(operation_body(&record)).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "operation_not_found",
            "operation was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn cancel_operation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, true).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let operation = match store.operation_by_id(&id).await {
        Ok(Some(operation)) => operation,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "operation_not_found",
                "operation was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    let Some(grant_id) = operation.grant_id else {
        return api_error(
            StatusCode::CONFLICT,
            "operation_not_cancellable",
            "operation has no active grant to cancel",
        );
    };
    perform_grant_revocation(&state, store, &grant_id, "cancelled").await
}

async fn list_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GrantQuery>,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, false).await {
        return response;
    }
    if query.status.as_deref().is_some_and(|status| {
        !matches!(
            status,
            "issued" | "delivered" | "consumed" | "revoked" | "expired"
        )
    }) || query.node_id.as_deref().is_some_and(|id| !valid_id(id))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant_filter",
            "grant filter is invalid",
        );
    }
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_limit",
            "limit must be between 1 and 100",
        );
    }
    let cursor = match parse_cursor(query.cursor.as_deref()) {
        Ok(cursor) => cursor,
        Err(()) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "grant cursor is invalid",
            );
        }
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let mut records = match store
        .list_grants(
            query.node_id.as_deref(),
            query.status.as_deref(),
            cursor,
            limit + 1,
        )
        .await
    {
        Ok(records) => records,
        Err(_) => return unavailable(),
    };
    let has_more = records.len() > limit as usize;
    records.truncate(limit as usize);
    let next_cursor = has_more
        .then(|| {
            records
                .last()
                .map(|record| cursor_for(record.created_at_ms, &record.id))
        })
        .flatten();
    Json(json!({"items":records.iter().map(grant_body).collect::<Vec<_>>(),"next_cursor":next_cursor})).into_response()
}

async fn get_grant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.grant_by_id(&id).await {
        Ok(Some(record)) => Json(grant_body(&record)).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "grant_not_found",
            "grant was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn revoke_grant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, true).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    perform_grant_revocation(&state, store, &id, "operator").await
}

async fn perform_grant_revocation(
    state: &AppState,
    store: &crate::store::Store,
    grant_id: &str,
    reason: &str,
) -> Response {
    let grant = match store.grant_by_id(grant_id).await {
        Ok(Some(grant)) => grant,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "grant_not_found",
                "grant was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    let envelope_json = if matches!(grant.status.as_str(), "consumed" | "revoked") {
        String::new()
    } else {
        let (Some(issuer), Some(key_id)) = (
            state.issuer_keypair.as_ref(),
            state.issuer_key_id.as_deref(),
        ) else {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "fleet_disabled",
                "fleet authorization is not configured",
            );
        };
        let now_ms = match store.database_now_ms().await {
            Ok(value) => value,
            Err(_) => return unavailable(),
        };
        let issuer_epoch = match store.issuer_epoch().await {
            Ok(value) => value,
            Err(_) => return unavailable(),
        };
        let Ok(revoked_at_ms) = u64::try_from(now_ms) else {
            return unavailable();
        };
        let retain_until_ms = now_ms
            .max(grant.expires_at_ms)
            .checked_add(7 * 24 * 60 * 60 * 1_000)
            .and_then(|value| u64::try_from(value).ok());
        let Some(retain_until_ms) = retain_until_ms else {
            return unavailable();
        };
        let revocation = Revocation {
            grant_id: grant_id.to_owned(),
            node_id: grant.node_id.clone(),
            reason: reason.to_owned(),
            revoked_at_ms,
            retain_until_ms,
            issuer_epoch,
        };
        let body = match revocation.to_value() {
            Ok(body) => body,
            Err(_) => return unavailable(),
        };
        let envelope = match SignedEnvelope::sign(
            DocumentKind::Revocation,
            body,
            key_id,
            issuer_epoch,
            issuer,
        ) {
            Ok(envelope) => envelope,
            Err(_) => return unavailable(),
        };
        let encoded = match envelope.to_json() {
            Ok(encoded) => encoded,
            Err(_) => return unavailable(),
        };
        match String::from_utf8(encoded) {
            Ok(value) => value,
            Err(_) => return unavailable(),
        }
    };
    match store.revoke_grant(grant_id, reason, &envelope_json).await {
        Ok(GrantRevocationOutcome::Revoked { grant_id, offline }) => Json(json!({
            "status": if offline { "not_revocable_offline" } else { "grant_revoked" },
            "grant_id": grant_id,
            "consumer_lifetime_seconds": null
        }))
        .into_response(),
        Ok(GrantRevocationOutcome::Consumed {
            grant_id,
            consumer_lifetime_seconds,
        }) => Json(json!({
            "status":"grant_revoked_after_consumption",
            "grant_id":grant_id,
            "consumer_lifetime_seconds":consumer_lifetime_seconds
        }))
        .into_response(),
        Ok(GrantRevocationOutcome::NotFound) => api_error(
            StatusCode::NOT_FOUND,
            "grant_not_found",
            "grant was not found",
        ),
        Ok(GrantRevocationOutcome::Conflict) => api_error(
            StatusCode::CONFLICT,
            "grant_not_revocable",
            "grant is no longer eligible for revocation",
        ),
        Err(_) => unavailable(),
    }
}

async fn list_unified_approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ApprovalQuery>,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, false).await {
        return response;
    }
    if query
        .status
        .as_deref()
        .is_some_and(|status| !matches!(status, "pending" | "approved" | "rejected" | "expired"))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_status",
            "approval status is invalid",
        );
    }
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_limit",
            "limit must be between 1 and 100",
        );
    }
    let cursor = match query
        .cursor
        .as_deref()
        .map(decode_unified_cursor)
        .transpose()
    {
        Ok(cursor) => cursor,
        Err(()) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "approval cursor is invalid",
            );
        }
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let exchange_cursor = cursor
        .as_ref()
        .and_then(|cursor| source_cursor(cursor, "exchange"));
    let operation_cursor = cursor
        .as_ref()
        .and_then(|cursor| source_cursor(cursor, "operation"));
    let exchanges = match store
        .list_approvals(query.status.as_deref(), exchange_cursor, limit + 1)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let operations = match store
        .list_operation_approvals(query.status.as_deref(), operation_cursor, limit + 1)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let mut items = exchanges
        .into_iter()
        .map(UnifiedApproval::Exchange)
        .chain(operations.into_iter().map(UnifiedApproval::Operation))
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    let has_more = items.len() > limit as usize;
    items.truncate(limit as usize);
    let next_cursor = has_more
        .then(|| {
            items
                .last()
                .and_then(|item| encode_unified_cursor(&item.cursor()))
        })
        .flatten();
    let exchange_count = match store.count_pending_approvals().await {
        Ok(count) => count,
        Err(_) => return unavailable(),
    };
    let operation_count = match store.count_pending_operation_approvals().await {
        Ok(count) => count,
        Err(_) => return unavailable(),
    };
    let Some(count) = exchange_count.checked_add(operation_count) else {
        return unavailable();
    };
    let Some(items) = items
        .iter()
        .map(UnifiedApproval::to_body)
        .collect::<Option<Vec<_>>>()
    else {
        return unavailable();
    };
    Json(json!({"items":items,"next_cursor":next_cursor,"count":count})).into_response()
}

async fn count_unified_approvals(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let exchange_count = match store.count_pending_approvals().await {
        Ok(count) => count,
        Err(_) => return unavailable(),
    };
    let operation_count = match store.count_pending_operation_approvals().await {
        Ok(count) => count,
        Err(_) => return unavailable(),
    };
    match exchange_count.checked_add(operation_count) {
        Some(count) => Json(json!({"count":count})).into_response(),
        None => unavailable(),
    }
}

async fn get_unified_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    if id.starts_with("oa_") {
        return match store.operation_approval_by_id(&id).await {
            Ok(Some(record)) => operation_approval_body(&record)
                .map(Json)
                .map(IntoResponse::into_response)
                .unwrap_or_else(unavailable),
            Ok(None) => api_error(
                StatusCode::NOT_FOUND,
                "approval_not_found",
                "approval was not found",
            ),
            Err(_) => unavailable(),
        };
    }
    match store.get_approval(&id).await {
        Ok(Some(record)) => Json(exchange_approval_body(&record)).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "approval_not_found",
            "approval was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn approve_unified_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<OperationDecisionInput>,
) -> Response {
    decide_unified_approval(state, id, headers, body, "approved").await
}

async fn reject_unified_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<OperationDecisionInput>,
) -> Response {
    decide_unified_approval(state, id, headers, body, "rejected").await
}

async fn decide_unified_approval(
    state: AppState,
    id: String,
    headers: HeaderMap,
    body: OperationDecisionInput,
    decision: &str,
) -> Response {
    let operator = match require_fleet_operator(&state, &headers, true).await {
        Ok(operator) => operator,
        Err(response) => return response,
    };
    if body.expected_status != "pending" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_expected_status",
            "expected_status must be pending",
        );
    }
    let Some(idempotency_key) = idempotency_key(&headers) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "Idempotency-Key must contain 16 to 128 safe characters",
        );
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    if id.starts_with("oa_") {
        let Some(expected_version) = body.expected_version.filter(|version| *version > 0) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_expected_version",
                "expected_version is required and must be positive",
            );
        };
        if let Err(response) = require_if_match(&headers, expected_version) {
            return response;
        }
        let Some(operation_ids) = body
            .operation_ids
            .filter(|ids| !ids.is_empty() && ids.len() <= 10 && ids.iter().all(|id| valid_id(id)))
        else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_operation_ids",
                "the exact operation group is required",
            );
        };
        let Some(key_hash) = digest_hex(idempotency_key.as_bytes()) else {
            return unavailable();
        };
        return match store
            .decide_operation_approval(
                &id,
                expected_version,
                &operation_ids,
                decision,
                &operator.operator.id,
                &key_hash,
            )
            .await
        {
            Ok(
                OperationDecisionOutcome::Applied(record)
                | OperationDecisionOutcome::Replayed(record),
            ) => {
                if decision == "approved" {
                    let operation_ids =
                        match serde_json::from_str::<Vec<String>>(&record.operation_ids_json) {
                            Ok(ids) => ids,
                            Err(_) => return unavailable(),
                        };
                    match ensure_operation_grants(&state, &operation_ids).await {
                        Ok(()) => {}
                        Err(GrantIssuanceError::Stale) => {
                            return api_error(
                                StatusCode::CONFLICT,
                                "authorization_changed",
                                "approval was recorded but current policy or workload state prevents grant issuance",
                            );
                        }
                        Err(GrantIssuanceError::Unavailable) => return unavailable(),
                    }
                }
                operation_approval_body(&record)
                    .map(Json)
                    .map(IntoResponse::into_response)
                    .unwrap_or_else(unavailable)
            }
            Ok(OperationDecisionOutcome::Conflict | OperationDecisionOutcome::StalePolicy) => {
                api_error(
                    StatusCode::CONFLICT,
                    "approval_conflict",
                    "approval is stale, policy changed, or the group/version does not match",
                )
            }
            Ok(OperationDecisionOutcome::NotFound) => api_error(
                StatusCode::NOT_FOUND,
                "approval_not_found",
                "approval was not found",
            ),
            Err(_) => unavailable(),
        };
    }
    if body.expected_version.is_some_and(|version| version != 1)
        || body
            .operation_ids
            .as_ref()
            .is_some_and(|ids| !ids.is_empty())
        || headers
            .get("if-match")
            .and_then(|value| value.to_str().ok())
            != Some("\"1\"")
    {
        return api_error(
            StatusCode::CONFLICT,
            "approval_conflict",
            "legacy approval version or group changed",
        );
    }
    let approval = match store.get_approval(&id).await {
        Ok(Some(approval)) => approval,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "approval_not_found",
                "approval was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    let assigned = !approval.approver_ids.is_empty()
        && approval.approver_ids.iter().any(|operator_id| {
            operator_id == &operator.operator.id || operator_id == &operator.operator.username
        })
        && approval.approver_rings.is_empty();
    if !assigned {
        return api_error(
            StatusCode::FORBIDDEN,
            "approval_scope_denied",
            "approval is not assigned to this operator",
        );
    }
    let Some(key_hash) = digest_hex(idempotency_key.as_bytes()) else {
        return unavailable();
    };
    match store
        .decide_approval_idempotent(&id, decision, &operator.operator.id, &key_hash)
        .await
    {
        Ok(
            ApprovalDecisionOutcome::Applied(record) | ApprovalDecisionOutcome::Replayed(record),
        ) => Json(json!({
            "kind":"exchange","reference":record.approval_reference,"status":record.status,
            "decided_at":record.decided_at_ms,"decided_by":record.decided_by
        }))
        .into_response(),
        Ok(ApprovalDecisionOutcome::Conflict) => api_error(
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "Idempotency-Key was already used for a different decision",
        ),
        Ok(ApprovalDecisionOutcome::NotFound) => api_error(
            StatusCode::CONFLICT,
            "approval_not_pending",
            "approval is no longer pending or has expired",
        ),
        Err(_) => unavailable(),
    }
}

enum UnifiedApproval {
    Exchange(ApprovalRecord),
    Operation(OperationApprovalRecord),
}

impl UnifiedApproval {
    fn sort_key(&self) -> (i64, u8, &str) {
        match self {
            Self::Exchange(record) => (record.created_at_ms, 0, &record.approval_reference),
            Self::Operation(record) => (record.created_at_ms, 1, &record.id),
        }
    }

    fn cursor(&self) -> UnifiedCursor {
        match self {
            Self::Exchange(record) => UnifiedCursor {
                created_at: record.created_at_ms,
                kind: "exchange".to_owned(),
                id: record.approval_reference.clone(),
            },
            Self::Operation(record) => UnifiedCursor {
                created_at: record.created_at_ms,
                kind: "operation".to_owned(),
                id: record.id.clone(),
            },
        }
    }

    fn to_body(&self) -> Option<JsonValue> {
        match self {
            Self::Exchange(record) => Some(exchange_approval_body(record)),
            Self::Operation(record) => operation_approval_body(record),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct UnifiedCursor {
    created_at: i64,
    kind: String,
    id: String,
}

fn encode_unified_cursor(cursor: &UnifiedCursor) -> Option<String> {
    serde_json::to_vec(cursor)
        .ok()
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_unified_cursor(value: &str) -> Result<UnifiedCursor, ()> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?;
    let cursor: UnifiedCursor = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if cursor.created_at <= 0
        || !matches!(cursor.kind.as_str(), "exchange" | "operation")
        || cursor.id.is_empty()
        || cursor.id.len() > 128
        || cursor.id.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(cursor)
}

fn source_cursor(cursor: &UnifiedCursor, source: &str) -> Option<(i64, String)> {
    if cursor.kind == source {
        return Some((cursor.created_at, cursor.id.clone()));
    }
    match (cursor.kind.as_str(), source) {
        ("exchange", "operation") => Some((cursor.created_at, String::new())),
        ("operation", "exchange") => Some((cursor.created_at, "~".to_owned())),
        _ => None,
    }
}

fn operation_matches_broker_event(
    input: &OperationInput,
    workload: &WorkloadRecord,
    event: &JsonValue,
    now_ms: i64,
) -> bool {
    let Some(fields) = event.as_object() else {
        return false;
    };
    if fields.len() != 11 {
        return false;
    }
    event["node_id"] == workload.node_id
        && event["workload_id"] == workload.id
        && event["unit"] == workload.unit
        && event["account"] == workload.account
        && event["invocation_id"] == input.invocation_id
        && event["action"] == input.action
        && event["mode"] == input.mode
        && event["purpose"] == input.purpose
        && event["resource_id"] == input.resource_id
        && event["ttl_seconds"].as_u64() == Some(input.ttl_seconds)
        && event["observed_at_ms"].as_i64().is_some_and(|observed_at| {
            observed_at > 0
                && now_ms.saturating_sub(observed_at) <= 60_000
                && observed_at <= now_ms.saturating_add(60_000)
        })
}

fn operation_body(record: &OperationRecord) -> JsonValue {
    json!({
        "id":record.id,"workload_id":record.workload_id,"node_id":record.node_id,
        "action":record.action,"mode":record.mode,"purpose":record.purpose,
        "resource_id":record.resource_id,
        "policy_version":record.policy_version,"decision":record.decision,
        "status":record.status,"approval_id":record.approval_id,"grant_id":record.grant_id,
        "result":record.result_json.as_deref().and_then(|value|serde_json::from_str::<JsonValue>(value).ok()),
        "created_at":record.created_at_ms,"expires_at":record.expires_at_ms,
        "completed_at":record.completed_at_ms,"version":record.version
    })
}

#[derive(Debug, Clone, Copy)]
enum GrantIssuanceError {
    Stale,
    Unavailable,
}

async fn ensure_operation_grants(
    state: &AppState,
    operation_ids: &[String],
) -> Result<(), GrantIssuanceError> {
    if operation_ids.is_empty() || operation_ids.len() > 10 {
        return Err(GrantIssuanceError::Stale);
    }
    let Some(store) = state.store.as_ref() else {
        return Err(GrantIssuanceError::Unavailable);
    };
    let Some(issuer) = state.issuer_keypair.as_ref() else {
        return Err(GrantIssuanceError::Unavailable);
    };
    let Some(key_id) = state.issuer_key_id.as_deref() else {
        return Err(GrantIssuanceError::Unavailable);
    };
    let epoch = store
        .issuer_epoch()
        .await
        .map_err(|_| GrantIssuanceError::Unavailable)?;
    let mut drafts = Vec::with_capacity(operation_ids.len());
    for operation_id in operation_ids {
        let operation = store
            .operation_by_id(operation_id)
            .await
            .map_err(|_| GrantIssuanceError::Unavailable)?
            .ok_or(GrantIssuanceError::Stale)?;
        if operation.status == "granted" {
            continue;
        }
        if operation.status != "requested" || operation.decision == "deny" {
            return Err(GrantIssuanceError::Stale);
        }
        let workload = store
            .workload_by_id(&operation.workload_id)
            .await
            .map_err(|_| GrantIssuanceError::Unavailable)?
            .filter(|workload| workload.status == "active")
            .ok_or(GrantIssuanceError::Stale)?;
        let node = store
            .node_by_id(&operation.node_id)
            .await
            .map_err(|_| GrantIssuanceError::Unavailable)?
            .filter(|node| node.status == "active")
            .ok_or(GrantIssuanceError::Stale)?;
        if workload.node_id != node.id
            || workload.consumption_mode != operation.mode
            || operation.policy_version <= 0
            || operation.requested_ttl_seconds <= 0
        {
            return Err(GrantIssuanceError::Stale);
        }
        let now_ms = store
            .database_now_ms()
            .await
            .map_err(|_| GrantIssuanceError::Unavailable)?;
        let local_ceiling = u64::try_from(workload.local_ceiling_seconds)
            .ok()
            .filter(|value| (1..=3600).contains(value))
            .ok_or(GrantIssuanceError::Stale)?;
        let ttl_seconds = u64::try_from(operation.requested_ttl_seconds)
            .map_err(|_| GrantIssuanceError::Stale)?
            .min(local_ceiling)
            .min(3600);
        let issued_at_ms = u64::try_from(now_ms).map_err(|_| GrantIssuanceError::Stale)?;
        let expires_at_ms = issued_at_ms
            .checked_add(ttl_seconds.saturating_mul(1_000))
            .ok_or(GrantIssuanceError::Stale)?;
        let grant = Grant {
            id: random_id("gr_"),
            operation_id: operation.id.clone(),
            node_id: operation.node_id.clone(),
            workload_id: operation.workload_id.clone(),
            invocation_id: operation.invocation_id.clone(),
            unit: workload.unit,
            account: workload.account,
            resource_id: operation.resource_id.clone(),
            recipient_key_id: format!("{}-{}", node.id, node.key_version),
            policy_version: u64::try_from(operation.policy_version)
                .map_err(|_| GrantIssuanceError::Stale)?,
            approval_reference: operation.approval_id.clone(),
            action: operation.action.clone(),
            mode: ConsumptionMode::parse(&operation.mode).ok_or(GrantIssuanceError::Stale)?,
            audience: "blindpass-node".to_owned(),
            issuer_epoch: epoch,
            issued_at_ms,
            expires_at_ms,
            local_ceiling_seconds: local_ceiling,
        };
        let envelope = SignedEnvelope::sign(
            DocumentKind::Grant,
            grant.to_value().map_err(|_| GrantIssuanceError::Stale)?,
            key_id,
            epoch,
            issuer,
        )
        .map_err(|_| GrantIssuanceError::Unavailable)?;
        let envelope_json = String::from_utf8(
            envelope
                .to_json()
                .map_err(|_| GrantIssuanceError::Unavailable)?,
        )
        .map_err(|_| GrantIssuanceError::Unavailable)?;
        drafts.push(GrantIssueDraft {
            grant,
            expected_operation_version: operation.version,
            envelope_json,
        });
    }
    if drafts.is_empty() {
        return Ok(());
    }
    match store
        .issue_operation_grants(&drafts)
        .await
        .map_err(|_| GrantIssuanceError::Unavailable)?
    {
        GrantIssueOutcome::Issued(_) | GrantIssueOutcome::Existing(_) => Ok(()),
        GrantIssueOutcome::Stale | GrantIssueOutcome::Conflict => Err(GrantIssuanceError::Stale),
    }
}

fn grant_body(record: &GrantRecord) -> JsonValue {
    json!({
        "id":record.id,"operation_id":record.operation_id,"node_id":record.node_id,
        "workload_id":record.workload_id,"invocation_id":record.invocation_id,
        "unit":record.unit,"account":record.account,"resource_id":record.resource_id,
        "recipient_key_id":record.recipient_key_id,"policy_version":record.policy_version,
        "approval_reference":record.approval_reference,"action":record.action,"mode":record.mode,
        "audience":record.audience,"issuer_epoch":record.issuer_epoch,
        "issued_at":record.issued_at_ms,"expires_at":record.expires_at_ms,"status":record.status
    })
}

fn operation_approval_body(record: &OperationApprovalRecord) -> Option<JsonValue> {
    Some(json!({
        "id":record.id,"kind":"operation",
        "operation_ids":serde_json::from_str::<Vec<String>>(&record.operation_ids_json).ok()?,
        "status":record.status,
        "requester_summary":serde_json::from_str::<JsonValue>(&record.requester_summary_json).ok()?,
        "verified_identity":serde_json::from_str::<JsonValue>(&record.verified_identity_json).ok()?,
        "rule_id":record.rule_id,"expires_at":record.expires_at_ms,"version":record.version
    }))
}

fn exchange_approval_body(record: &ApprovalRecord) -> JsonValue {
    json!({
        "kind":"exchange","reference":record.approval_reference,"status":record.status,
        "requester_id":record.requester_id,"secret_name":record.secret_name,
        "purpose":record.purpose,"created_at":record.created_at_ms,"timeline":[]
    })
}

fn workload_body(record: &WorkloadRecord) -> JsonValue {
    json!({
        "id":record.id,"node_id":record.node_id,"name":record.name,"unit":record.unit,
        "account":record.account,"consumption_mode":record.consumption_mode,
        "local_ceiling_seconds":record.local_ceiling_seconds,
        "registration_version":record.registration_version,"status":record.status,
        "created_at":record.created_at_ms,"version":record.version
    })
}

fn policy_body(policy: FleetPolicyRecord) -> Response {
    let document: JsonValue = match serde_json::from_str(&policy.document_json) {
        Ok(document) => document,
        Err(_) => return unavailable(),
    };
    let rules = document.get("rules").cloned().unwrap_or_else(|| json!([]));
    Json(json!({"version":policy.version,"rules":rules,"updated_at":policy.updated_at_ms,"updated_by":policy.updated_by})).into_response()
}

async fn signed_registration(
    state: &AppState,
    store: &crate::store::Store,
    issuer: &blindpass_core::signing::ed25519::Ed25519KeyPair,
    workload: &WorkloadRecord,
    policy_version: i64,
    status: &str,
) -> Option<String> {
    let key_id = state.issuer_key_id.as_deref()?;
    let epoch = store.issuer_epoch().await.ok()?;
    let body = Registration {
        node_id: workload.node_id.clone(),
        workload_id: workload.id.clone(),
        unit: workload.unit.clone(),
        account: workload.account.clone(),
        invocation_id: None,
        status: status.to_owned(),
        consumption_mode: ConsumptionMode::parse(&workload.consumption_mode)?,
        registration_version: u64::try_from(workload.registration_version).ok()?,
        policy_version: u64::try_from(policy_version).ok()?,
        local_ceiling_seconds: u64::try_from(workload.local_ceiling_seconds).ok()?,
    }
    .to_value()
    .ok()?;
    let envelope =
        SignedEnvelope::sign(DocumentKind::Registration, body, key_id, epoch, issuer).ok()?;
    String::from_utf8(envelope.to_json().ok()?).ok()
}

async fn signed_policy_snapshot(
    state: &AppState,
    store: &crate::store::Store,
    issuer: &blindpass_core::signing::ed25519::Ed25519KeyPair,
    policy_version: i64,
    document_json: &str,
) -> Option<String> {
    let document: JsonValue = serde_json::from_str(document_json).ok()?;
    let rules =
        serde_json::from_value::<Vec<FleetRuleInput>>(document.get("rules")?.clone()).ok()?;
    signed_policy_snapshot_for_rules(state, store, issuer, policy_version, &rules).await
}

async fn signed_policy_snapshot_for_rules(
    state: &AppState,
    store: &crate::store::Store,
    issuer: &blindpass_core::signing::ed25519::Ed25519KeyPair,
    policy_version: i64,
    rules: &[FleetRuleInput],
) -> Option<String> {
    let key_id = state.issuer_key_id.as_deref()?;
    let epoch = store.issuer_epoch().await.ok()?;
    let allowed_actions = rules
        .iter()
        .filter(|rule| rule.decision != "deny")
        .map(|rule| rule.action.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut allowed_modes = rules
        .iter()
        .filter(|rule| rule.decision != "deny")
        .filter_map(|rule| ConsumptionMode::parse(&rule.mode))
        .collect::<Vec<_>>();
    allowed_modes.sort_by_key(|mode| mode.as_str());
    allowed_modes.dedup();
    let ceiling = rules
        .iter()
        .filter(|rule| rule.decision != "deny")
        .map(|rule| rule.max_ttl_seconds)
        .max()
        .unwrap_or(1);
    let body = blindpass_core::fleet::PolicySnapshot {
        policy_version: u64::try_from(policy_version).ok()?,
        local_ceiling_seconds: ceiling,
        allowed_actions,
        allowed_modes: allowed_modes.into_iter().collect(),
    }
    .to_value()
    .ok()?;
    let envelope =
        SignedEnvelope::sign(DocumentKind::PolicySnapshot, body, key_id, epoch, issuer).ok()?;
    String::from_utf8(envelope.to_json().ok()?).ok()
}

fn validate_workload_fields(
    unit: &str,
    account: &str,
    mode: &str,
    ceiling: u64,
) -> Result<(), &'static str> {
    if unit.is_empty()
        || unit.len() > 256
        || unit.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("system unit is invalid");
    }
    if account.is_empty()
        || account.len() > 128
        || account
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("account mapping is invalid");
    }
    if !matches!(mode, "file" | "socket") {
        return Err("consumption mode is unsupported");
    }
    if !(1..=3600).contains(&ceiling) {
        return Err("local ceiling must be between 1 and 3600 seconds");
    }
    Ok(())
}

async fn require_fleet_operator(
    state: &AppState,
    headers: &HeaderMap,
    unsafe_method: bool,
) -> Result<crate::store::LocalSession, Response> {
    let operator = require_operator(state, headers, unsafe_method, false).await?;
    if !matches!(operator.operator.role.as_str(), "admin" | "operator") {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "role_denied",
            "administrator or operator role is required",
        ));
    }
    Ok(operator)
}

fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            (16..=128).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

fn digest_hex(value: &[u8]) -> Option<String> {
    sha256(value)
        .ok()
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn json_hash(value: &JsonValue) -> Option<String> {
    let canonical = canonical_json_string(value)?;
    digest_hex(canonical.as_bytes())
}

fn canonical_json_string(value: &JsonValue) -> Option<String> {
    let source = serde_json::to_string(value).ok()?;
    let canonical = canonicalize_json(&source).ok()?;
    String::from_utf8(canonical).ok()
}

fn sanitize_purpose(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(512)
        .collect()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn require_if_match(headers: &HeaderMap, expected_version: i64) -> Result<(), Response> {
    let Some(header) = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
    else {
        return Err(api_error(
            StatusCode::PRECONDITION_REQUIRED,
            "if_match_required",
            "If-Match must contain the expected resource version",
        ));
    };
    let Some(version) = header
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|version| *version > 0)
    else {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_if_match",
            "If-Match must be a quoted positive version",
        ));
    };
    if version != expected_version {
        return Err(api_error(
            StatusCode::CONFLICT,
            "version_conflict",
            "If-Match and expected_version do not match",
        ));
    }
    Ok(())
}

fn parse_cursor(value: Option<&str>) -> Result<Option<(i64, String)>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };
    let (created_at, id) = value.split_once('~').ok_or(())?;
    let created_at = created_at.parse::<i64>().map_err(|_| ())?;
    if created_at <= 0 || !valid_id(id) {
        return Err(());
    }
    Ok(Some((created_at, id.to_owned())))
}

fn cursor_for(created_at: i64, id: &str) -> String {
    format!("{created_at}~{id}")
}

fn random_id(prefix: &str) -> String {
    use rand::{RngCore, rngs::OsRng};
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{prefix}{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
