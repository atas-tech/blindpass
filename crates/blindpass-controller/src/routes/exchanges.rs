// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::auth::{
    AuthError, WorkloadIdentity, authenticate_user, authenticate_workload, current_seconds,
};
use crate::routes::secrets::workload_auth_error;
use crate::store::{ApprovalRecord, ExchangePolicyRecord, ExchangeRecord, LifecycleRecord, Store};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use blindpass_core::custody::sha256;
use blindpass_core::policy::{
    ExchangePolicyRule, PolicyDocument, PolicyInput, PolicyMode, SecretRegistryEntry,
    hash_policy_decision,
};
use blindpass_core::signing::derive_secret;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_CIPHERTEXT_LENGTH: usize = 524_288;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateExchangeBody {
    public_key: String,
    secret_name: String,
    purpose: String,
    fulfiller_hint: String,
    prior_exchange_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FulfillBody {
    fulfillment_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitBody {
    enc: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct PolicyResponse {
    mode: String,
    approval_required: bool,
    rule_id: String,
    reason: String,
    approval_reference: Option<String>,
    requester_ring: Option<String>,
    fulfiller_ring: Option<String>,
    secret_name: String,
}

#[derive(Debug, Serialize)]
struct ApprovalResponse {
    approval_reference: String,
    status: String,
    requester_id: String,
    fulfiller_hint: String,
    secret_name: String,
    purpose: String,
    rule_id: Option<String>,
    reason: String,
    requester_ring: Option<String>,
    fulfiller_ring: Option<String>,
    created_at: u64,
    decided_at: Option<u64>,
    decided_by: Option<String>,
    expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct FulfillmentClaims {
    exchange_id: String,
    requester_id: String,
    workspace_id: Option<String>,
    secret_name: String,
    purpose: String,
    policy_hash: String,
    approval_reference: Option<String>,
    sub: String,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Serialize)]
struct CreatedExchange {
    exchange_id: String,
    status: String,
    expires_at: u64,
    fulfillment_token: String,
    policy: PolicyResponse,
}

#[derive(Clone)]
struct ResolvedDecision {
    policy: ExchangePolicyRecord,
    allowed_fulfiller_id: Option<String>,
    approval_status: Option<String>,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v2/secret/exchange/request", post(create_exchange))
        .route("/api/v2/secret/exchange/fulfill", post(fulfill_exchange))
        .route("/api/v2/secret/exchange/submit/{id}", post(submit_exchange))
        .route(
            "/api/v2/secret/exchange/retrieve/{id}",
            get(retrieve_exchange),
        )
        .route("/api/v2/secret/exchange/status/{id}", get(exchange_status))
        .route(
            "/api/v2/secret/exchange/revoke/{id}",
            delete(revoke_exchange),
        )
        .route("/api/v2/secret/exchange/approval/{id}", get(get_approval))
        .route(
            "/api/v2/secret/exchange/approval/{id}/approve",
            post(approve_agent),
        )
        .route(
            "/api/v2/secret/exchange/approval/{id}/reject",
            post(reject_agent),
        )
        .route(
            "/api/v2/secret/exchange/admin/approval/{id}/approve",
            post(approve_admin),
        )
        .route(
            "/api/v2/secret/exchange/admin/approval/{id}/reject",
            post(reject_admin),
        )
        .route("/api/v2/audit/", get(list_audit))
}

async fn create_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateExchangeBody>,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    let secret_name = body.secret_name.trim();
    let purpose = body.purpose.trim();
    let fulfiller_hint = body.fulfiller_hint.trim();
    if body.public_key.len() > 2_048 {
        return validation_error("body/public_key must NOT have more than 2048 characters");
    }
    if !valid_base64(&body.public_key)
        || secret_name.len() < 3
        || secret_name.len() > 256
        || purpose.is_empty()
        || purpose.len() > 256
        || fulfiller_hint.is_empty()
        || fulfiller_hint.len() > 512
    {
        return validation_error("body/public_key must match pattern \"^[A-Za-z0-9+/]+={0,2}$\"");
    }
    if identity
        .workspace_id
        .as_deref()
        .is_some_and(|workspace| workspace != store.tenant_id())
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"workspace_mismatch"})),
        )
            .into_response();
    }
    let prior_id = body.prior_exchange_id.as_deref().unwrap_or("").trim();
    if !prior_id.is_empty() {
        let valid_prior = store
            .get_exchange(prior_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|prior| {
                prior.requester_id == identity.sub && prior.secret_name == secret_name
            });
        if !valid_prior {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"prior_exchange_id does not match requester or secret_name"})),
            )
                .into_response();
        }
    }
    let Some(decision) = resolve_policy(
        &state,
        store,
        &identity,
        secret_name,
        purpose,
        fulfiller_hint,
    )
    .await
    else {
        let _ = store
            .append_audit(
                "exchange_denied",
                "agent",
                Some(&identity.sub),
                "secret",
                Some(secret_name),
                &json!({"action":"exchange_request_denied","fulfiller_hint":fulfiller_hint}),
            )
            .await;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"Exchange not allowed"})),
        )
            .into_response();
    };
    if decision.policy.mode != "allow" {
        let event = if decision.policy.mode == "pending_approval" {
            "exchange_pending_approval"
        } else {
            "exchange_denied"
        };
        let action = if decision.policy.mode == "pending_approval" {
            "exchange_request_pending_approval"
        } else {
            "exchange_request_denied"
        };
        let _ = store
            .append_audit(
                event,
                "agent",
                Some(&identity.sub),
                "secret",
                Some(secret_name),
                &json!({
                    "action":action,
                    "policy_rule_id":decision.policy.rule_id,
                    "approval_reference":decision.policy.approval_reference,
                    "fulfiller_hint":fulfiller_hint
                }),
            )
            .await;
        let error = if decision.approval_status.as_deref() == Some("rejected") {
            "Exchange approval was rejected"
        } else if decision.policy.mode == "pending_approval" {
            "Exchange requires human approval"
        } else {
            "Exchange not allowed"
        };
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error":error,
                "approval_status":decision.approval_status,
                "policy":policy_response(&decision.policy)
            })),
        )
            .into_response();
    }
    let Some(allowed_fulfiller) = decision.allowed_fulfiller_id.as_deref() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"Exchange policy did not resolve an allowed fulfiller"})),
        )
            .into_response();
    };
    let exchange_id = random_hex_id();
    let policy_hash = match hash_policy_decision(
        &core_policy(&decision.policy),
        Some(allowed_fulfiller),
        Some(store.tenant_id()),
    ) {
        Ok(hash) => hash,
        Err(_) => return unavailable(),
    };
    let exchange = ExchangeRecord {
        exchange_id: exchange_id.clone(),
        requester_id: identity.sub.clone(),
        workspace_id: store.tenant_id().to_owned(),
        requester_public_key: body.public_key,
        secret_name: secret_name.to_owned(),
        purpose: purpose.to_owned(),
        fulfiller_hint: fulfiller_hint.to_owned(),
        allowed_fulfiller_id: Some(allowed_fulfiller.to_owned()),
        fulfilled_by: None,
        policy: decision.policy.clone(),
        policy_hash: policy_hash.clone(),
        status: "pending".to_owned(),
        prior_exchange_id: (!prior_id.is_empty()).then(|| prior_id.to_owned()),
        supersedes_exchange_id: (!prior_id.is_empty()).then(|| prior_id.to_owned()),
        created_at_ms: 0,
        expires_at_ms: 0,
        enc: None,
        ciphertext: None,
    };
    let created = match store
        .create_exchange(exchange, state.request_ttl_seconds)
        .await
    {
        Ok(created) => created,
        Err(_) => return unavailable(),
    };
    let expires_at = (created.expires_at_ms / 1_000) as u64;
    let token = match sign_fulfillment_token(
        &exchange_id,
        &identity.sub,
        Some(store.tenant_id()),
        secret_name,
        purpose,
        &policy_hash,
        decision.policy.approval_reference.as_deref(),
        expires_at,
        state.root_secret.as_bytes(),
    ) {
        Ok(token) => token,
        Err(_) => return unavailable(),
    };
    append_lifecycle(
        store,
        "exchange_requested",
        Some(&exchange_id),
        None,
        &identity.sub,
        secret_name,
        purpose,
        Some(fulfiller_hint),
        Some(&identity.sub),
        Some("pending"),
        decision.policy.rule_id.as_str(),
        json!({"prior_exchange_id":if prior_id.is_empty(){Value::Null}else{json!(prior_id)}}),
    )
    .await;
    let _ = store.append_audit("exchange_requested", "agent", Some(&identity.sub), "exchange", Some(&exchange_id), &json!({
        "action":"exchange_request","secret_name":secret_name,"policy_rule_id":decision.policy.rule_id,
        "approval_reference":decision.policy.approval_reference
    })).await;
    (
        StatusCode::CREATED,
        Json(CreatedExchange {
            exchange_id,
            status: "pending".to_owned(),
            expires_at,
            fulfillment_token: token,
            policy: policy_response(&decision.policy),
        }),
    )
        .into_response()
}

async fn fulfill_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FulfillBody>,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    let claims =
        match verify_fulfillment_token(&body.fulfillment_token, state.root_secret.as_bytes()) {
            Ok(claims) => claims,
            Err(()) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error":"Invalid fulfillment token"})),
                )
                    .into_response();
            }
        };
    let exchange = match store.get_exchange(&claims.exchange_id).await {
        Ok(Some(exchange)) => exchange,
        _ => return not_available(),
    };
    if exchange.requester_id != claims.requester_id
        || claims.workspace_id.as_deref() != Some(exchange.workspace_id.as_str())
        || exchange.secret_name != claims.secret_name
        || exchange.purpose != claims.purpose
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Exchange token no longer matches request"})),
        )
            .into_response();
    }
    if identity
        .workspace_id
        .as_deref()
        .is_some_and(|workspace| workspace != exchange.workspace_id)
    {
        return not_available();
    }
    if exchange.status != "pending" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Exchange is no longer pending"})),
        )
            .into_response();
    }
    if exchange.allowed_fulfiller_id.as_deref() != Some(identity.sub.as_str()) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Exchange policy no longer allows fulfillment"})),
        )
            .into_response();
    }
    let Some(current_decision) = resolve_policy_for_exchange(
        &state,
        store,
        &exchange.requester_id,
        Some(&exchange.workspace_id),
        &exchange.secret_name,
        &exchange.purpose,
        &identity.sub,
    )
    .await
    else {
        return unavailable();
    };
    if current_decision.policy.mode != "allow"
        || current_decision.allowed_fulfiller_id.as_deref() != Some(identity.sub.as_str())
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Exchange policy no longer allows fulfillment"})),
        )
            .into_response();
    }
    let current_hash = match hash_policy_decision(
        &core_policy(&current_decision.policy),
        current_decision.allowed_fulfiller_id.as_deref(),
        Some(&exchange.workspace_id),
    ) {
        Ok(hash) => hash,
        Err(_) => return unavailable(),
    };
    if current_hash != claims.policy_hash || current_hash != exchange.policy_hash {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Exchange policy changed; requester must create a new exchange"})),
        )
            .into_response();
    }
    let reserved = match store
        .reserve_exchange(&exchange.exchange_id, &identity.sub)
        .await
    {
        Ok(Some(exchange)) => exchange,
        _ => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"Exchange is no longer pending"})),
            )
                .into_response();
        }
    };
    append_lifecycle(
        store,
        "exchange_reserved",
        Some(&reserved.exchange_id),
        None,
        &reserved.requester_id,
        &reserved.secret_name,
        &reserved.purpose,
        Some(&reserved.fulfiller_hint),
        Some(&identity.sub),
        Some("reserved"),
        &reserved.policy.rule_id,
        Value::Null,
    )
    .await;
    let _ = store
        .append_audit(
            "exchange_reserved",
            "agent",
            Some(&identity.sub),
            "exchange",
            Some(&reserved.exchange_id),
            &json!({"action":"exchange_reserve","secret_name":reserved.secret_name}),
        )
        .await;
    Json(json!({
        "exchange_id":reserved.exchange_id,
        "status":reserved.status,
        "fulfilled_by":identity.sub,
        "requester_id":reserved.requester_id,
        "requester_public_key":reserved.requester_public_key,
        "secret_name":reserved.secret_name,
        "purpose":reserved.purpose,
        "expires_at":(reserved.expires_at_ms / 1000) as u64,
        "policy":policy_response(&reserved.policy)
    }))
    .into_response()
}

async fn submit_exchange(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SubmitBody>,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    if body.enc.len() > 4_096 {
        return validation_error("body/enc must NOT have more than 4096 characters");
    }
    if body.ciphertext.len() > MAX_CIPHERTEXT_LENGTH {
        return validation_error("body/ciphertext must NOT have more than 524288 characters");
    }
    if !valid_base64(&body.enc) {
        return validation_error("body/enc must match pattern \"^[A-Za-z0-9+/]+={0,2}$\"");
    }
    if !valid_base64(&body.ciphertext) {
        return validation_error("body/ciphertext must match pattern \"^[A-Za-z0-9+/]+={0,2}$\"");
    }
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    let exchange = match store.get_exchange(&id).await {
        Ok(Some(exchange)) => exchange,
        _ => return not_available(),
    };
    if identity
        .workspace_id
        .as_deref()
        .is_some_and(|workspace| workspace != exchange.workspace_id)
    {
        return not_available();
    }
    if exchange.status != "reserved" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Exchange is not reserved"})),
        )
            .into_response();
    }
    if exchange.fulfilled_by.as_deref() != Some(identity.sub.as_str()) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Exchange is reserved for a different fulfiller"})),
        )
            .into_response();
    }
    let submitted = match store
        .submit_exchange(
            &id,
            &identity.sub,
            &body.enc,
            &body.ciphertext,
            state.submitted_ttl_seconds,
        )
        .await
    {
        Ok(Some(exchange)) => exchange,
        _ => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"Exchange submission failed"})),
            )
                .into_response();
        }
    };
    append_lifecycle(
        store,
        "exchange_submitted",
        Some(&submitted.exchange_id),
        None,
        &submitted.requester_id,
        &submitted.secret_name,
        &submitted.purpose,
        Some(&submitted.fulfiller_hint),
        Some(&identity.sub),
        Some("submitted"),
        &submitted.policy.rule_id,
        Value::Null,
    )
    .await;
    let _ = store
        .append_audit(
            "exchange_submitted",
            "agent",
            Some(&identity.sub),
            "exchange",
            Some(&submitted.exchange_id),
            &json!({"action":"exchange_submit","secret_name":submitted.secret_name}),
        )
        .await;
    (
        StatusCode::CREATED,
        Json(json!({
            "status":"submitted","retrieve_by":(submitted.expires_at_ms / 1000) as u64,
            "fulfilled_by":identity.sub
        })),
    )
        .into_response()
}

async fn retrieve_exchange(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    let exchange = match store.get_exchange(&id).await {
        Ok(Some(exchange)) if exchange.requester_id == identity.sub => exchange,
        Ok(Some(_)) => return not_available(),
        _ => return not_available(),
    };
    if exchange.status != "submitted" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Exchange is not ready"})),
        )
            .into_response();
    }
    let retrieved = match store.consume_exchange(&id, &identity.sub).await {
        Ok(Some(exchange)) => exchange,
        _ => return not_available(),
    };
    append_lifecycle(
        store,
        "exchange_retrieved",
        Some(&id),
        None,
        &retrieved.requester_id,
        &retrieved.secret_name,
        &retrieved.purpose,
        Some(&retrieved.fulfiller_hint),
        Some(&identity.sub),
        Some("retrieved"),
        &retrieved.policy.rule_id,
        json!({"fulfilled_by":retrieved.fulfilled_by}),
    )
    .await;
    let _ = store
        .append_audit(
            "exchange_retrieved",
            "agent",
            Some(&identity.sub),
            "exchange",
            Some(&id),
            &json!({"action":"exchange_retrieve","secret_name":retrieved.secret_name}),
        )
        .await;
    Json(json!({
        "enc":retrieved.enc.unwrap_or_default(),
        "ciphertext":retrieved.ciphertext.unwrap_or_default(),
        "secret_name":retrieved.secret_name,
        "fulfilled_by":retrieved.fulfilled_by
    }))
    .into_response()
}

async fn exchange_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    match store.get_exchange(&id).await {
        Ok(Some(exchange)) if exchange.requester_id == identity.sub => {
            Json(json!({"status":exchange.status})).into_response()
        }
        _ => not_available(),
    }
}

async fn revoke_exchange(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    let exchange = match store.get_exchange(&id).await {
        Ok(Some(exchange)) => exchange,
        _ => return not_available(),
    };
    let issuer_admin = identity.admin == Some(true)
        && identity.workspace_id.as_deref() == Some(exchange.workspace_id.as_str());
    if exchange.requester_id != identity.sub && !issuer_admin {
        return not_available();
    }
    if exchange.status == "revoked" {
        return Json(json!({"status":"revoked"})).into_response();
    }
    let revoked = match store
        .revoke_exchange(
            &id,
            if issuer_admin {
                None
            } else {
                Some(&identity.sub)
            },
            state.revoked_ttl_seconds,
        )
        .await
    {
        Ok(Some(exchange)) => exchange,
        _ => return not_available(),
    };
    append_lifecycle(
        store,
        "exchange_revoked",
        Some(&id),
        None,
        &revoked.requester_id,
        &revoked.secret_name,
        &revoked.purpose,
        Some(&revoked.fulfiller_hint),
        Some(&identity.sub),
        Some("revoked"),
        &revoked.policy.rule_id,
        json!({"reason":if issuer_admin {"revoked by admin"} else {"revoked by requester"}}),
    )
    .await;
    let _ = store
        .append_audit(
            "exchange_revoked",
            "agent",
            Some(&identity.sub),
            "exchange",
            Some(&id),
            &json!({"action":"exchange_revoke","secret_name":revoked.secret_name}),
        )
        .await;
    Json(json!({"status":"revoked"})).into_response()
}

async fn get_approval(
    State(state): State<AppState>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    let approval = match store.get_approval(&reference).await {
        Ok(Some(approval)) => approval,
        _ => return not_available(),
    };
    if approval.requester_id != identity.sub && !approver_authorized(&approval, &identity.sub) {
        return not_available();
    }
    Json(approval_response(&approval)).into_response()
}

async fn approve_agent(
    State(state): State<AppState>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> Response {
    decide_agent_approval(state, reference, headers, "approved").await
}
async fn reject_agent(
    State(state): State<AppState>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> Response {
    decide_agent_approval(state, reference, headers, "rejected").await
}
async fn approve_admin(
    State(state): State<AppState>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> Response {
    decide_admin_approval(state, reference, headers, "approved").await
}
async fn reject_admin(
    State(state): State<AppState>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> Response {
    decide_admin_approval(state, reference, headers, "rejected").await
}

async fn decide_agent_approval(
    state: AppState,
    reference: String,
    headers: HeaderMap,
    status: &'static str,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    let approval = match store.get_approval(&reference).await {
        Ok(Some(approval)) => approval,
        _ => return not_available(),
    };
    if !approver_authorized(&approval, &identity.sub)
        || identity
            .workspace_id
            .as_deref()
            .is_some_and(|workspace| workspace != approval.workspace_id)
    {
        return not_available();
    }
    complete_approval(store, approval, &identity.sub, "agent", status).await
}

async fn decide_admin_approval(
    state: AppState,
    reference: String,
    headers: HeaderMap,
    status: &'static str,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let user = match authenticate_user(&state, &headers) {
        Ok(user) => user,
        Err(error) => return auth_error(error),
    };
    if !matches!(
        user.role.as_str(),
        "workspace_admin" | "workspace_operator" | "super_admin"
    ) {
        return (StatusCode::FORBIDDEN, Json(json!({"error":"forbidden"}))).into_response();
    }
    let approval = match store.get_approval(&reference).await {
        Ok(Some(approval)) if approval.workspace_id == user.workspace_id => approval,
        _ => return not_available(),
    };
    complete_approval(store, approval, &user.sub, "user", status).await
}

async fn complete_approval(
    store: &Store,
    approval: ApprovalRecord,
    actor_id: &str,
    actor_type: &str,
    status: &str,
) -> Response {
    if approval.status != "pending" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"Approval is no longer pending"})),
        )
            .into_response();
    }
    let decided = match store
        .decide_approval(&approval.approval_reference, status, actor_id)
        .await
    {
        Ok(Some(approval)) => approval,
        _ => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"Approval is no longer pending"})),
            )
                .into_response();
        }
    };
    append_lifecycle(
        store,
        "approval_decided",
        None,
        Some(&decided.approval_reference),
        &decided.requester_id,
        &decided.secret_name,
        &decided.purpose,
        Some(&decided.fulfiller_hint),
        Some(actor_id),
        Some(status),
        decided.rule_id.as_deref().unwrap_or(""),
        Value::Null,
    )
    .await;
    let event = if status == "approved" {
        "exchange_approved"
    } else {
        "exchange_rejected"
    };
    let _ = store.append_audit(event, actor_type, Some(actor_id), "approval", Some(&decided.approval_reference), &json!({
        "action":if status == "approved" {"exchange_approval_approve"} else {"exchange_approval_reject"},
        "purpose":decided.purpose,"secret_name":decided.secret_name
    })).await;
    Json(json!({
        "approval_reference":decided.approval_reference,
        "status":decided.status,
        "decided_at":decided.decided_at_ms.map(|value|(value / 1000) as u64),
        "decided_by":decided.decided_by
    }))
    .into_response()
}

async fn list_audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let user = match authenticate_user(&state, &headers) {
        Ok(user) => user,
        Err(error) => return auth_error(error),
    };
    if !matches!(
        user.role.as_str(),
        "workspace_admin" | "workspace_operator" | "workspace_viewer" | "super_admin"
    ) {
        return (StatusCode::FORBIDDEN, Json(json!({"error":"forbidden"}))).into_response();
    }
    if user.workspace_id != store.tenant_id() {
        return not_available();
    }
    let records = match store.list_audit(query.limit.unwrap_or(50)).await {
        Ok(records) => records,
        Err(_) => return unavailable(),
    };
    let records = records
        .into_iter()
        .map(|record| {
            json!({
                "id":record.id,
                "workspace_id":record.workspace_id,
                "event_type":record.event_type,
                "actor_id":record.actor_id,
                "actor_type":record.actor_type,
                "resource_id":record.resource_id,
                "metadata":record.metadata,
                "ip_address":Value::Null,
                "created_at":format_epoch_ms(record.created_at_ms)
            })
        })
        .collect::<Vec<_>>();
    Json(json!({"records":records,"next_cursor":Value::Null})).into_response()
}

async fn resolve_policy(
    state: &AppState,
    store: &Store,
    identity: &WorkloadIdentity,
    secret_name: &str,
    purpose: &str,
    fulfiller_hint: &str,
) -> Option<ResolvedDecision> {
    resolve_policy_for_exchange(
        state,
        store,
        &identity.sub,
        identity.workspace_id.as_deref(),
        secret_name,
        purpose,
        fulfiller_hint,
    )
    .await
}

async fn resolve_policy_for_exchange(
    state: &AppState,
    store: &Store,
    requester_id: &str,
    requester_workspace_id: Option<&str>,
    secret_name: &str,
    purpose: &str,
    fulfiller_hint: &str,
) -> Option<ResolvedDecision> {
    let (registry_values, rule_values): (Vec<Value>, Vec<Value>) =
        match store.policy_document().await.ok()? {
            Some(record) => {
                let document: Value = serde_json::from_str(&record.document_json).ok()?;
                (
                    document.get("secret_registry")?.as_array()?.clone(),
                    document.get("exchange_policy")?.as_array()?.clone(),
                )
            }
            None => (
                serde_json::from_str(state.secret_registry_json.as_deref()?).ok()?,
                serde_json::from_str(state.exchange_policy_json.as_deref()?).ok()?,
            ),
        };
    let registry = registry_values
        .iter()
        .filter_map(|entry| {
            Some(SecretRegistryEntry {
                secret_name: alias_string(entry, &["secretName", "secret_name"])?,
                classification: alias_string(entry, &["classification"])?,
                description: alias_string(entry, &["description"]),
            })
        })
        .collect::<Vec<_>>();
    let rules = rule_values
        .iter()
        .filter_map(parse_policy_rule)
        .collect::<Vec<_>>();
    let policy = PolicyDocument::new(registry, rules);
    let evaluation = policy.evaluate(&PolicyInput {
        requester_id,
        requester_workspace_id,
        secret_name,
        purpose,
        fulfiller_hint,
        fulfiller_workspace_id: Some(store.tenant_id()),
    })?;
    let mut decision = ExchangePolicyRecord {
        mode: evaluation.decision.mode.as_str().to_owned(),
        approval_required: evaluation.decision.approval_required,
        rule_id: evaluation.decision.rule_id,
        reason: evaluation.decision.reason,
        approval_reference: evaluation.decision.approval_reference,
        requester_ring: evaluation.decision.requester_ring,
        fulfiller_ring: evaluation.decision.fulfiller_ring,
        secret_name: evaluation.decision.secret_name,
    };
    if decision.mode != "pending_approval" {
        return Some(ResolvedDecision {
            policy: decision,
            allowed_fulfiller_id: evaluation.allowed_fulfiller_id,
            approval_status: None,
        });
    }
    let reference = decision.approval_reference.clone().unwrap_or_else(|| {
        approval_reference(
            requester_id,
            Some(store.tenant_id()),
            secret_name,
            purpose,
            fulfiller_hint,
            &decision.rule_id,
        )
    });
    decision.approval_reference = Some(reference.clone());
    let existing = store.get_approval(&reference).await.ok().flatten();
    if let Some(approval) = existing.filter(|approval| {
        approval.requester_id == requester_id
            && approval.workspace_id == store.tenant_id()
            && approval.secret_name == secret_name
            && approval.purpose == purpose
            && approval.fulfiller_hint == fulfiller_hint
            && approval.rule_id.as_deref() == Some(decision.rule_id.as_str())
    }) {
        if approval.status == "approved" {
            decision.mode = "allow".to_owned();
            decision.approval_required = false;
            decision.reason = approval.decided_by.as_ref().map_or_else(
                || "exchange approved".to_owned(),
                |by| format!("exchange approved by {by}"),
            );
            return Some(ResolvedDecision {
                policy: decision,
                allowed_fulfiller_id: Some(fulfiller_hint.to_owned()),
                approval_status: Some("approved".to_owned()),
            });
        }
        return Some(ResolvedDecision {
            policy: decision,
            allowed_fulfiller_id: None,
            approval_status: Some(approval.status),
        });
    }
    let created_at_ms = (current_seconds() as i64) * 1_000;
    let approval = ApprovalRecord {
        approval_reference: reference.clone(),
        requester_id: requester_id.to_owned(),
        workspace_id: store.tenant_id().to_owned(),
        secret_name: secret_name.to_owned(),
        purpose: purpose.to_owned(),
        fulfiller_hint: fulfiller_hint.to_owned(),
        rule_id: Some(decision.rule_id.clone()),
        reason: decision.reason.clone(),
        requester_ring: decision.requester_ring.clone(),
        fulfiller_ring: decision.fulfiller_ring.clone(),
        approver_ids: evaluation.approver_ids.unwrap_or_default(),
        approver_rings: evaluation.approver_rings.unwrap_or_default(),
        status: "pending".to_owned(),
        created_at_ms,
        expires_at_ms: created_at_ms + (state.approval_ttl_seconds as i64) * 1_000,
        decided_at_ms: None,
        decided_by: None,
    };
    if store.create_approval(&approval).await.is_err() {
        return None;
    }
    append_lifecycle(
        store,
        "approval_requested",
        None,
        Some(&reference),
        requester_id,
        secret_name,
        purpose,
        Some(fulfiller_hint),
        None,
        Some("pending"),
        &decision.rule_id,
        json!({"requester_ring":decision.requester_ring,"fulfiller_ring":decision.fulfiller_ring}),
    )
    .await;
    let _ = store.append_audit("exchange_approval_requested", "agent", Some(requester_id), "approval", Some(&reference), &json!({
        "action":"exchange_approval_request","purpose":purpose,"secret_name":secret_name,"policy_rule_id":decision.rule_id
    })).await;
    Some(ResolvedDecision {
        policy: decision,
        allowed_fulfiller_id: None,
        approval_status: Some("pending".to_owned()),
    })
}

#[allow(clippy::too_many_arguments)]
async fn append_lifecycle(
    store: &Store,
    event: &str,
    exchange_id: Option<&str>,
    approval_reference: Option<&str>,
    requester_id: &str,
    secret_name: &str,
    purpose: &str,
    fulfiller_hint: Option<&str>,
    actor_id: Option<&str>,
    status: Option<&str>,
    rule_id: &str,
    metadata: Value,
) {
    let _ = store
        .append_lifecycle(&LifecycleRecord {
            record_id: random_hex_id(),
            event_type: event.to_owned(),
            exchange_id: exchange_id.map(str::to_owned),
            approval_reference: approval_reference.map(str::to_owned),
            requester_id: requester_id.to_owned(),
            workspace_id: store.tenant_id().to_owned(),
            secret_name: secret_name.to_owned(),
            purpose: purpose.to_owned(),
            fulfiller_hint: fulfiller_hint.map(str::to_owned),
            actor_id: actor_id.map(str::to_owned),
            status: status.map(str::to_owned),
            prior_status: None,
            reason: None,
            policy_rule_id: Some(rule_id.to_owned()),
            metadata: Some(metadata),
            created_at_ms: 0,
        })
        .await;
}

fn policy_response(policy: &ExchangePolicyRecord) -> PolicyResponse {
    PolicyResponse {
        mode: policy.mode.clone(),
        approval_required: policy.approval_required,
        rule_id: policy.rule_id.clone(),
        reason: policy.reason.clone(),
        approval_reference: policy.approval_reference.clone(),
        requester_ring: policy.requester_ring.clone(),
        fulfiller_ring: policy.fulfiller_ring.clone(),
        secret_name: policy.secret_name.clone(),
    }
}

fn core_policy(policy: &ExchangePolicyRecord) -> blindpass_core::policy::PolicyDecision {
    blindpass_core::policy::PolicyDecision {
        mode: match policy.mode.as_str() {
            "pending_approval" => PolicyMode::PendingApproval,
            "deny" => PolicyMode::Deny,
            _ => PolicyMode::Allow,
        },
        approval_required: policy.approval_required,
        rule_id: policy.rule_id.clone(),
        reason: policy.reason.clone(),
        approval_reference: policy.approval_reference.clone(),
        requester_ring: policy.requester_ring.clone(),
        fulfiller_ring: policy.fulfiller_ring.clone(),
        secret_name: policy.secret_name.clone(),
    }
}

fn approval_response(approval: &ApprovalRecord) -> ApprovalResponse {
    ApprovalResponse {
        approval_reference: approval.approval_reference.clone(),
        status: approval.status.clone(),
        requester_id: approval.requester_id.clone(),
        fulfiller_hint: approval.fulfiller_hint.clone(),
        secret_name: approval.secret_name.clone(),
        purpose: approval.purpose.clone(),
        rule_id: approval.rule_id.clone(),
        reason: approval.reason.clone(),
        requester_ring: approval.requester_ring.clone(),
        fulfiller_ring: approval.fulfiller_ring.clone(),
        created_at: (approval.created_at_ms / 1_000) as u64,
        decided_at: approval.decided_at_ms.map(|value| (value / 1_000) as u64),
        decided_by: approval.decided_by.clone(),
        expires_at: (approval.expires_at_ms / 1_000) as u64,
    }
}

fn approver_authorized(approval: &ApprovalRecord, agent_id: &str) -> bool {
    (approval.approver_ids.is_empty()
        || approval
            .approver_ids
            .iter()
            .any(|candidate| candidate == agent_id))
        && (approval.approver_rings.is_empty()
            || ring_from_agent_id(agent_id).is_some_and(|ring| {
                approval
                    .approver_rings
                    .iter()
                    .any(|allowed| allowed == &ring)
            }))
}

fn ring_from_agent_id(agent_id: &str) -> Option<String> {
    let (_, suffix) = agent_id.split_once("/ring/")?;
    let ring = suffix.split('/').next()?.trim();
    (!ring.is_empty()).then(|| ring.to_owned())
}

fn approval_reference(
    requester: &str,
    workspace: Option<&str>,
    secret: &str,
    purpose: &str,
    fulfiller: &str,
    rule: &str,
) -> String {
    let requester = serde_json::to_string(requester).unwrap_or_default();
    let secret = serde_json::to_string(secret).unwrap_or_default();
    let purpose = serde_json::to_string(purpose).unwrap_or_default();
    let fulfiller = serde_json::to_string(fulfiller).unwrap_or_default();
    let rule = serde_json::to_string(rule).unwrap_or_default();
    let canonical = if let Some(workspace) = workspace {
        let workspace = serde_json::to_string(workspace).unwrap_or_default();
        format!(
            "{{\"requesterId\":{requester},\"workspaceId\":{workspace},\"secretName\":{secret},\"purpose\":{purpose},\"fulfillerHint\":{fulfiller},\"ruleId\":{rule}}}"
        )
    } else {
        format!(
            "{{\"requesterId\":{requester},\"secretName\":{secret},\"purpose\":{purpose},\"fulfillerHint\":{fulfiller},\"ruleId\":{rule}}}"
        )
    };
    let digest = sha256(canonical.as_bytes()).unwrap_or([0; 32]);
    format!("apr_{}", hex(&digest[..12]))
}

fn parse_policy_rule(value: &Value) -> Option<ExchangePolicyRule> {
    let mode = match alias_string(value, &["mode"]).as_deref().unwrap_or("allow") {
        "pending_approval" => PolicyMode::PendingApproval,
        "deny" => PolicyMode::Deny,
        _ => PolicyMode::Allow,
    };
    Some(ExchangePolicyRule {
        rule_id: alias_string(value, &["ruleId", "rule_id"])?,
        secret_name: alias_string(value, &["secretName", "secret_name"])?,
        requester_ids: alias_list(value, &["requesterIds", "requester_ids"]),
        fulfiller_ids: alias_list(value, &["fulfillerIds", "fulfiller_ids"]),
        approver_ids: alias_list(value, &["approverIds", "approver_ids"]),
        requester_rings: alias_list(value, &["requesterRings", "requester_rings"]),
        fulfiller_rings: alias_list(value, &["fulfillerRings", "fulfiller_rings"]),
        approver_rings: alias_list(value, &["approverRings", "approver_rings"]),
        purposes: alias_list(value, &["purposes"]),
        same_ring: alias_bool(value, &["sameRing", "same_ring"]),
        allowed_rings: alias_list(value, &["allowedRings", "allowed_rings"]),
        mode,
        approval_reference: alias_string(value, &["approvalReference", "approval_reference"]),
        reason: alias_string(value, &["reason"]),
    })
}

fn alias_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_owned)
}

fn alias_list(value: &Value, keys: &[&str]) -> Option<Vec<String>> {
    keys.iter().find_map(|key| value.get(*key)).map(|value| {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .or_else(|| {
                value.as_str().map(|values| {
                    values
                        .split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
            })
            .unwrap_or_default()
    })
}

fn alias_bool(value: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        value
            .get(*key)
            .is_some_and(|value| value.as_bool().unwrap_or(false))
    })
}

#[allow(clippy::too_many_arguments)]
fn sign_fulfillment_token(
    exchange_id: &str,
    requester_id: &str,
    workspace_id: Option<&str>,
    secret_name: &str,
    purpose: &str,
    policy_hash: &str,
    approval_reference: Option<&str>,
    expires_at: u64,
    root_secret: &[u8],
) -> Result<String, ()> {
    let secret = derive_secret(root_secret, "agent-fulfillment").map_err(|_| ())?;
    let now = current_seconds();
    let claims = FulfillmentClaims {
        exchange_id: exchange_id.to_owned(),
        requester_id: requester_id.to_owned(),
        workspace_id: workspace_id.map(str::to_owned),
        secret_name: secret_name.to_owned(),
        purpose: purpose.to_owned(),
        policy_hash: policy_hash.to_owned(),
        approval_reference: approval_reference.map(str::to_owned),
        sub: workspace_id.unwrap_or(requester_id).to_owned(),
        iss: "sps".to_owned(),
        aud: "agent-fulfill".to_owned(),
        iat: now,
        exp: expires_at,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| ())
}

fn verify_fulfillment_token(token: &str, root_secret: &[u8]) -> Result<FulfillmentClaims, ()> {
    let secret = derive_secret(root_secret, "agent-fulfillment").map_err(|_| ())?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["sps"]);
    validation.set_audience(&["agent-fulfill"]);
    decode::<FulfillmentClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| ())
}

fn valid_base64(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
}

fn random_hex_id() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

fn format_epoch_ms(milliseconds: i64) -> String {
    let seconds = milliseconds.div_euclid(1_000);
    let millis = milliseconds.rem_euclid(1_000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        day_seconds / 3600,
        (day_seconds / 60) % 60,
        day_seconds % 60
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + i64::from(m <= 2), m, d)
}

fn auth_error(error: AuthError) -> Response {
    let status = match error {
        AuthError::MissingBearer => StatusCode::UNAUTHORIZED,
        AuthError::InvalidToken | AuthError::InvalidClaims | AuthError::InvalidApiKey => {
            StatusCode::UNAUTHORIZED
        }
        AuthError::ProviderUnavailable => StatusCode::SERVICE_UNAVAILABLE,
    };
    let (message, code) = match error {
        AuthError::MissingBearer => ("Missing bearer token", "missing_bearer"),
        AuthError::InvalidToken | AuthError::InvalidClaims => ("Invalid token", "invalid_token"),
        AuthError::InvalidApiKey => ("Invalid agent API key", "invalid_api_key"),
        AuthError::ProviderUnavailable => ("Identity provider unavailable", "provider_unavailable"),
    };
    (status, Json(json!({"error":message,"code":code}))).into_response()
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":"service_unavailable"})),
    )
        .into_response()
}
fn not_available() -> Response {
    (StatusCode::GONE, Json(json!({"error":"Not available"}))).into_response()
}
fn validation_error(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"statusCode":400,"code":"FST_ERR_VALIDATION","error":"Bad Request","message":message})),
    )
        .into_response()
}
