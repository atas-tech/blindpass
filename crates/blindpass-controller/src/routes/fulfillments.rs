// SPDX-License-Identifier: AGPL-3.0-only

//! P10 cross-workload fulfillment API.
//!
//! An operator names two registered workloads and one credential name per
//! side. The controller decides from the `cross_workload` policy rules, asks a
//! named approver when the rule says so, and then relays only signed documents
//! and ciphertext sealed to a one-use key the recipient broker minted. No
//! response here carries plaintext, ciphertext, key material or signed
//! documents. `purpose` is operator-typed text and is labelled untrusted.

use super::authorization::{
    cursor_for, idempotency_key, json_hash, parse_cursor, random_id, require_fleet_operator,
    require_if_match, valid_id,
};
use crate::app::AppState;
use crate::routes::fleet::{api_error, operator_audit, unavailable};
use crate::store::{
    FulfillmentCreate, FulfillmentCreateOutcome, FulfillmentDecideOutcome, FulfillmentDecision,
    FulfillmentRecord, FulfillmentRevokeOutcome, Store,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use blindpass_core::fulfillment::{FulfillmentParty, FulfillmentTerms};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

const MAX_PURPOSE_CHARS: usize = 512;
const STATUSES: &[&str] = &[
    "awaiting_approval",
    "approved",
    "offered",
    "available",
    "recipient_consumed",
    "completed",
    "denied",
    "revoked",
    "expired",
    "failed",
    "uncertain",
];

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v3/fulfillments", get(list).post(create))
        .route("/api/v3/fulfillments/{id}", get(read).delete(revoke))
        .route("/api/v3/fulfillments/{id}/approve", post(approve))
        .route("/api/v3/fulfillments/{id}/reject", post(reject))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    issuer_workload_id: String,
    recipient_workload_id: String,
    issuer_credential: String,
    recipient_credential: String,
    purpose: String,
    #[serde(default)]
    prior_fulfillment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionInput {
    expected_version: i64,
    /// Fingerprints of the two enrolled node keys the approver verified.
    /// Required to approve; ignored when rejecting.
    #[serde(default)]
    issuer_fingerprint: Option<String>,
    #[serde(default)]
    recipient_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

/// Same rule the signed terms apply, checked early so a bad name is a `400`
/// at creation rather than a failure at approval.
fn valid_credential_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_purpose(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && value.chars().count() <= MAX_PURPOSE_CHARS
        && !value.chars().any(char::is_control)
}

fn disabled() -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "fulfillments_disabled",
        "cross-workload fulfillment is not enabled on this controller",
    )
}

fn invalid(message: &'static str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "invalid_fulfillment", message)
}

fn party_json(party: &FulfillmentParty) -> JsonValue {
    json!({
        "workload_id": party.workload_id,
        "node_id": party.node_id,
        "unit": party.unit,
        "credential": party.credential,
        "key_version": party.key_version,
        "registration_version": party.registration_version,
        "fingerprint": party.fingerprint,
    })
}

/// A fulfillment as the console reads it. The two parties come from the signed
/// terms once they exist; before approval they are the enrolled keys as they
/// stand now, which is what an approver must verify and bind.
async fn body(store: &Store, record: &FulfillmentRecord) -> Result<JsonValue, Response> {
    let mut parties = None;
    let mut terms_bound = false;
    if let Some(terms_json) = record.terms_json.as_deref() {
        let terms = blindpass_core::canon::parse_json(terms_json)
            .ok()
            .and_then(|value| FulfillmentTerms::from_value(&value).ok())
            .ok_or_else(unavailable)?;
        parties = Some((terms.issuer, terms.recipient));
        terms_bound = true;
    } else if record.status == "awaiting_approval" {
        parties = store
            .fulfillment_live_parties(record)
            .await
            .map_err(|_| unavailable())?;
    }
    let approver_ids = serde_json::from_str::<Vec<String>>(&record.approver_ids_json)
        .map_err(|_| unavailable())?;
    Ok(json!({
        "id": record.id,
        "status": record.status,
        "version": record.version,
        "mode": "reencrypt",
        "issuer": parties.as_ref().map_or_else(
            || json!({
                "workload_id": record.issuer_workload_id,
                "node_id": record.issuer_node_id,
                "credential": record.issuer_credential,
            }),
            |(issuer, _)| party_json(issuer),
        ),
        "recipient": parties.as_ref().map_or_else(
            || json!({
                "workload_id": record.recipient_workload_id,
                "node_id": record.recipient_node_id,
                "credential": record.recipient_credential,
            }),
            |(_, recipient)| party_json(recipient),
        ),
        "parties_bound": terms_bound,
        "requested_by": record.requested_by,
        "purpose": record.purpose,
        "untrusted_fields": ["purpose"],
        "policy_version": record.policy_version,
        "rule_id": record.rule_id,
        "decision": record.decision,
        "approval": {
            "status": record.approval_status,
            "approver_ids": approver_ids,
            "decided_by": record.decided_by,
            "decided_at": record.decided_at_ms,
        },
        "prior_fulfillment_id": record.prior_fulfillment_id,
        "ttl_seconds": record.ttl_seconds,
        "terms_digest": record.terms_digest,
        "failure_code": record.failure_code,
        "revocation_reason": record.revocation_reason,
        "delivery_revoked_at": record.delivery_revoked_at_ms,
        "provider_revocation": record.provider_revocation,
        "created_at": record.created_at_ms,
        "expires_at": record.expires_at_ms,
        "approved_at": record.approved_at_ms,
        "offered_at": record.offered_at_ms,
        "available_at": record.issuer_consumed_at_ms,
        "stored_at": record.recipient_consumed_at_ms,
        "completed_at": record.completed_at_ms,
        "closed_at": record.closed_at_ms,
    }))
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateInput>,
) -> Response {
    let operator = match require_fleet_operator(&state, &headers, true).await {
        Ok(operator) => operator,
        Err(response) => return response,
    };
    if !state.fulfillments_enabled {
        return disabled();
    }
    let Some(key) = idempotency_key(&headers) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "Idempotency-Key must contain 16 to 128 safe characters",
        );
    };
    if !valid_id(&input.issuer_workload_id)
        || !valid_id(&input.recipient_workload_id)
        || !valid_credential_name(&input.issuer_credential)
        || !valid_credential_name(&input.recipient_credential)
        || !valid_purpose(&input.purpose)
        || input
            .prior_fulfillment_id
            .as_deref()
            .is_some_and(|id| !valid_id(id))
    {
        return invalid("fulfillment fields are invalid");
    }
    if input.issuer_workload_id == input.recipient_workload_id {
        return api_error(
            StatusCode::BAD_REQUEST,
            "same_party",
            "issuer and recipient must be different workloads on different nodes",
        );
    }
    let (Some(store), Some(_)) = (state.store.as_ref(), state.issuer_keypair.as_ref()) else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet_disabled",
            "fleet authorization is not configured",
        );
    };
    let Some(request_hash) = json_hash(&json!({
        "issuer_workload_id": input.issuer_workload_id,
        "recipient_workload_id": input.recipient_workload_id,
        "issuer_credential": input.issuer_credential,
        "recipient_credential": input.recipient_credential,
        "purpose": input.purpose,
        "prior_fulfillment_id": input.prior_fulfillment_id,
    })) else {
        return unavailable();
    };
    let id = random_id("fu_");
    let audit = operator_audit(
        &operator,
        "fleet.fulfillment_requested",
        "fulfillment",
        &id,
        "requested",
        json!({
            "issuer_workload_id": input.issuer_workload_id,
            "recipient_workload_id": input.recipient_workload_id,
            "issuer_credential": input.issuer_credential,
            "recipient_credential": input.recipient_credential,
            "prior_fulfillment_id": input.prior_fulfillment_id,
        }),
    );
    let outcome = store
        .create_fulfillment(&FulfillmentCreate {
            id: &id,
            issuer_workload_id: &input.issuer_workload_id,
            recipient_workload_id: &input.recipient_workload_id,
            issuer_credential: &input.issuer_credential,
            recipient_credential: &input.recipient_credential,
            requested_by: &operator.operator.id,
            purpose: input.purpose.trim(),
            prior_fulfillment_id: input.prior_fulfillment_id.as_deref(),
            idempotency_key: key,
            request_hash: &request_hash,
            audit: &audit,
        })
        .await;
    let (status, record) = match outcome {
        Ok(FulfillmentCreateOutcome::Created(record)) => (StatusCode::CREATED, record),
        Ok(FulfillmentCreateOutcome::Existing(record)) => (StatusCode::OK, record),
        Ok(FulfillmentCreateOutcome::Conflict) => {
            return api_error(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "the idempotency key was used for a different request",
            );
        }
        Ok(FulfillmentCreateOutcome::Busy) => {
            return api_error(
                StatusCode::CONFLICT,
                "recipient_busy",
                "the recipient workload already has a live fulfillment",
            );
        }
        Ok(FulfillmentCreateOutcome::Unavailable(code)) => {
            return match code {
                "workload_not_found" => api_error(
                    StatusCode::NOT_FOUND,
                    "workload_not_found",
                    "a named workload was not found",
                ),
                "prior_invalid" => api_error(
                    StatusCode::CONFLICT,
                    "prior_invalid",
                    "the prior fulfillment is not a completed fulfillment for this recipient",
                ),
                _ => api_error(
                    StatusCode::CONFLICT,
                    "party_unavailable",
                    "a workload or its node is unavailable, or both are on one node",
                ),
            };
        }
        Err(_) => return unavailable(),
    };
    // A denial is a refusal to the caller; the denied row stays for audit.
    if record.status == "denied" && record.approval_status == "not_required" {
        return api_error(
            StatusCode::FORBIDDEN,
            "cross_workload_denied",
            "no cross-workload policy rule allows this issuer and recipient",
        );
    }
    match body(store, &record).await {
        Ok(value) => (status, Json(value)).into_response(),
        Err(response) => response,
    }
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if let Err(response) = require_fleet_operator(&state, &headers, false).await {
        return response;
    }
    if query
        .status
        .as_deref()
        .is_some_and(|status| !STATUSES.contains(&status))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_status",
            "fulfillment status is invalid",
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
    let Ok(cursor) = parse_cursor(query.cursor.as_deref()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "fulfillment cursor is invalid",
        );
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    // Converge expired and invalidated fulfillments before reading, as the
    // operation and grant lists do.
    if store
        .expire_fulfillments(state.fulfillments_enabled)
        .await
        .is_err()
    {
        return unavailable();
    }
    let mut records = match store
        .list_fulfillments(query.status.as_deref(), cursor, limit + 1)
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
    let mut items = Vec::with_capacity(records.len());
    for record in &records {
        match body(store, record).await {
            Ok(value) => items.push(value),
            Err(response) => return response,
        }
    }
    Json(json!({"items": items, "next_cursor": next_cursor})).into_response()
}

async fn read(
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
    if !valid_id(&id) {
        return not_found();
    }
    if store
        .expire_fulfillments(state.fulfillments_enabled)
        .await
        .is_err()
    {
        return unavailable();
    }
    match store.fulfillment_by_id(&id).await {
        Ok(Some(record)) => match body(store, &record).await {
            Ok(value) => Json(value).into_response(),
            Err(response) => response,
        },
        Ok(None) => not_found(),
        Err(_) => unavailable(),
    }
}

fn not_found() -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "fulfillment_not_found",
        "fulfillment was not found",
    )
}

async fn approve(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<DecisionInput>,
) -> Response {
    decide(state, id, headers, input, "approved").await
}

async fn reject(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<DecisionInput>,
) -> Response {
    decide(state, id, headers, input, "rejected").await
}

async fn decide(
    state: AppState,
    id: String,
    headers: HeaderMap,
    input: DecisionInput,
    decision: &'static str,
) -> Response {
    let operator = match require_fleet_operator(&state, &headers, true).await {
        Ok(operator) => operator,
        Err(response) => return response,
    };
    if !state.fulfillments_enabled && decision == "approved" {
        return disabled();
    }
    if !valid_id(&id) || input.expected_version <= 0 {
        return invalid("fulfillment decision fields are invalid");
    }
    if let Err(response) = require_if_match(&headers, input.expected_version) {
        return response;
    }
    let fingerprints = match (
        input.issuer_fingerprint.as_deref(),
        input.recipient_fingerprint.as_deref(),
    ) {
        (Some(issuer), Some(recipient))
            if [issuer, recipient]
                .iter()
                .all(|value| (1..=128).contains(&value.len())) =>
        {
            Some((issuer, recipient))
        }
        _ if decision == "approved" => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "fingerprints_required",
                "approval requires the issuer and recipient node fingerprints the approver verified",
            );
        }
        _ => None,
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let audit = operator_audit(
        &operator,
        "fleet.fulfillment_decided",
        "fulfillment",
        &id,
        decision,
        json!({"decision": decision, "expected_version": input.expected_version}),
    );
    let outcome = store
        .decide_fulfillment(&FulfillmentDecision {
            id: &id,
            expected_version: input.expected_version,
            decision,
            decided_by: &operator.operator.id,
            decider_username: &operator.operator.username,
            expected_fingerprints: fingerprints,
            audit: &audit,
        })
        .await;
    match outcome {
        Ok(
            FulfillmentDecideOutcome::Applied(record) | FulfillmentDecideOutcome::Replayed(record),
        ) => match body(store, &record).await {
            Ok(value) => Json(value).into_response(),
            Err(response) => response,
        },
        Ok(FulfillmentDecideOutcome::NotFound) => not_found(),
        Ok(FulfillmentDecideOutcome::ScopeDenied) => api_error(
            StatusCode::FORBIDDEN,
            "approval_scope_denied",
            "the policy rule does not name this operator as an approver",
        ),
        Ok(FulfillmentDecideOutcome::SelfApproval) => api_error(
            StatusCode::FORBIDDEN,
            "self_approval_denied",
            "an operator cannot approve their own fulfillment request",
        ),
        Ok(FulfillmentDecideOutcome::Conflict) => api_error(
            StatusCode::CONFLICT,
            "approval_conflict",
            "the fulfillment is no longer pending or its version changed",
        ),
        Ok(FulfillmentDecideOutcome::Stale) => api_error(
            StatusCode::CONFLICT,
            "authorization_changed",
            "the fulfillment expired, or policy, a workload or a node key changed since the request",
        ),
        Err(_) => unavailable(),
    }
}

async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let operator = match require_fleet_operator(&state, &headers, true).await {
        Ok(operator) => operator,
        Err(response) => return response,
    };
    if !valid_id(&id) {
        return not_found();
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.revoke_fulfillment(&id, &operator.operator.id).await {
        Ok(
            FulfillmentRevokeOutcome::Revoked(record)
            | FulfillmentRevokeOutcome::AlreadyClosed(record),
        ) => match body(store, &record).await {
            Ok(value) => Json(value).into_response(),
            Err(response) => response,
        },
        Ok(FulfillmentRevokeOutcome::NotFound) => not_found(),
        Err(_) => unavailable(),
    }
}
