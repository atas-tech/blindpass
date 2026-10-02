// SPDX-License-Identifier: AGPL-3.0-only

//! Independently configured fleet Source destinations and the scoped,
//! operator-bound Source link, metadata and ciphertext submit routes. The
//! controller never sees Source: the browser seals it to the broker's one-use
//! offer key and the controller stores and signs only public metadata and
//! HPKE ciphertext.
use super::auth::current_seconds;
use super::fleet::{api_error, operator_audit, require_operator, unavailable};
use crate::app::AppState;
use crate::store::{
    LocalSession, ProvisioningLinkOutcome, ProvisioningLinkRecord, ProvisioningMetadataOutcome,
    ProvisioningReceipt, ProvisioningSubmitOutcome, SourceBindingRecord, StoreError,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use blindpass_core::canon::canonicalize_json;
use blindpass_core::custody::sha256;
use blindpass_core::fleet::is_valid_opaque_id;
use blindpass_core::provisioning::BrowserProvisioningDelivery;
use blindpass_core::signing::{
    BrowserScope, VerifyError, sign_fleet_provisioning_capability,
    verify_fleet_provisioning_capability,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// A 64 KiB Source seals to about 88 KiB of base64url text; anything past
/// this is refused before parsing.
const SUBMIT_BODY_LIMIT: usize = 128 * 1024;

pub(crate) fn routes() -> Router<AppState> {
    // Only the ciphertext route carries the larger-than-JSON-default body cap.
    let submit_routes = Router::new()
        .route("/api/v3/fleet/provisioning/{id}/submit", post(submit))
        .layer(DefaultBodyLimit::max(SUBMIT_BODY_LIMIT));
    Router::new()
        .route(
            "/api/v3/nodes/{node_id}/source-bindings/{resource_id}",
            get(read_binding).put(update_binding),
        )
        .route(
            "/api/v3/admin/operations/{id}/provisioning-link",
            post(create_link),
        )
        .route(
            "/api/v3/fleet/provisioning/{id}/metadata",
            get(read_metadata),
        )
        .merge(submit_routes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingInput {
    source_unit: String,
    credential: String,
    expected_version: i64,
}

fn binding_body(record: SourceBindingRecord) -> Value {
    json!({"node_id":record.node_id,"resource_id":record.resource_id,"source_unit":record.source_unit,
        "credential":record.credential,"version":record.version,"updated_at":record.updated_at_ms})
}

async fn read_binding(
    State(state): State<AppState>,
    Path((node_id, resource_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, false, true).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.source_binding(&node_id, &resource_id).await {
        Ok(Some(record)) => Json(binding_body(record)).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "source_binding_not_found",
            "the source binding was not found",
        ),
        Err(_) => unavailable(),
    }
}

async fn update_binding(
    State(state): State<AppState>,
    Path((node_id, resource_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<BindingInput>,
) -> Response {
    let actor = match require_operator(&state, &headers, true, true).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let audit = operator_audit(
        &actor,
        "fleet.source_binding_updated",
        "node",
        &node_id,
        "updated",
        json!({"resource_id":resource_id,"source_unit":body.source_unit,"credential":body.credential,"expected_version":body.expected_version}),
    );
    match store
        .set_source_binding(
            &node_id,
            &resource_id,
            &body.source_unit,
            &body.credential,
            body.expected_version,
            &actor.operator.id,
            &audit,
        )
        .await
    {
        Ok(Some(record)) => Json(binding_body(record)).into_response(),
        Ok(None) => api_error(
            StatusCode::CONFLICT,
            "source_binding_conflict",
            "the node or source binding version changed",
        ),
        Err(StoreError::InvalidInput(_)) => api_error(
            StatusCode::BAD_REQUEST,
            "invalid_source_binding",
            "the source destination or version is invalid",
        ),
        Err(_) => unavailable(),
    }
}

#[derive(Deserialize)]
struct SignatureQuery {
    sig: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitInput {
    enc: String,
    ciphertext: String,
}

fn valid_link_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

/// Fleet Source collection belongs to named operators: administrators and
/// operators only, never a viewer, node or agent credential.
#[allow(clippy::result_large_err)] // Axum route helpers return its response type directly.
async fn named_operator(
    state: &AppState,
    headers: &HeaderMap,
    unsafe_method: bool,
) -> Result<LocalSession, Response> {
    let session = require_operator(state, headers, unsafe_method, false).await?;
    if !matches!(session.operator.role.as_str(), "admin" | "operator") {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "role_denied",
            "administrator or operator role is required",
        ));
    }
    Ok(session)
}

#[allow(clippy::result_large_err)] // Axum route helpers return its response type directly.
fn check_capability(
    state: &AppState,
    id: &str,
    scope: BrowserScope,
    signature: Option<&str>,
) -> Result<(), Response> {
    let Some(signature) = signature else {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "provisioning_capability_required",
            "a signed provisioning capability is required",
        ));
    };
    match verify_fleet_provisioning_capability(
        id,
        scope,
        signature,
        state.root_secret.as_bytes(),
        current_seconds(),
    ) {
        Ok(_) => Ok(()),
        Err(VerifyError::Expired) => Err(unavailable_link()),
        Err(VerifyError::Invalid) => Err(api_error(
            StatusCode::FORBIDDEN,
            "provisioning_capability_invalid",
            "the provisioning capability is invalid",
        )),
    }
}

fn unavailable_link() -> Response {
    api_error(
        StatusCode::GONE,
        "provisioning_unavailable",
        "the Source link is no longer available",
    )
}

fn owner_required() -> Response {
    api_error(
        StatusCode::FORBIDDEN,
        "provisioning_owner_required",
        "only the named Source owner may use this link",
    )
}

fn session_ended() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "session_required",
        "an active local session is required",
    )
}

fn link_body(state: &AppState, record: &ProvisioningLinkRecord) -> Option<Value> {
    // Round up so the coarse capability check never denies before the
    // authoritative millisecond deadline stored with the link.
    let expires = u64::try_from(record.expires_at_ms)
        .ok()?
        .checked_add(999)?
        .checked_div(1_000)?;
    let root = state.root_secret.as_bytes();
    let metadata =
        sign_fleet_provisioning_capability(&record.id, expires, BrowserScope::Metadata, root)
            .ok()?;
    let submit =
        sign_fleet_provisioning_capability(&record.id, expires, BrowserScope::Submit, root).ok()?;
    Some(json!({
        "id": record.id,
        "metadata_sig": metadata,
        "submit_sig": submit,
        "operator_id": record.operator_id,
        "operation_id": record.operation_id,
        "expires_at_ms": record.expires_at_ms,
        "input_path": format!(
            "/?kind=fleet&id={}&metadata_sig={metadata}&submit_sig={submit}",
            record.id
        ),
    }))
}

fn receipt_body(receipt: &ProvisioningReceipt) -> Value {
    json!({
        "status": "submitted",
        "offer_id": receipt.offer_id,
        "ciphertext_digest": receipt.ciphertext_digest,
        "delivery_digest": receipt.delivery_digest,
        "submitted_at_ms": receipt.submitted_at_ms,
        "expires_at_ms": receipt.expires_at_ms,
    })
}

async fn create_link(
    State(state): State<AppState>,
    Path(operation_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match named_operator(&state, &headers, true).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(key) = idempotency_key(&headers) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "an Idempotency-Key of 16 to 128 URL-safe characters is required",
        );
    };
    if !is_valid_opaque_id(&operation_id) {
        return api_error(
            StatusCode::NOT_FOUND,
            "operation_not_found",
            "the browser operation was not found",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let Ok(digest) = sha256(key.as_bytes()) else {
        return unavailable();
    };
    let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let (status, record) = match store
        .create_provisioning_link(&operation_id, &session, &hash)
        .await
    {
        Ok(ProvisioningLinkOutcome::Created(record)) => (StatusCode::CREATED, record),
        Ok(ProvisioningLinkOutcome::Existing(record)) => (StatusCode::OK, record),
        Ok(ProvisioningLinkOutcome::NotFound) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "operation_not_found",
                "the browser operation was not found",
            );
        }
        Ok(ProvisioningLinkOutcome::Forbidden) => return owner_required(),
        Ok(ProvisioningLinkOutcome::SessionEnded) => return session_ended(),
        Ok(ProvisioningLinkOutcome::NotReady) => {
            return api_error(
                StatusCode::CONFLICT,
                "provisioning_offer_pending",
                "the node has not published its recipient offer yet; retry shortly",
            );
        }
        Ok(ProvisioningLinkOutcome::Unavailable) => return unavailable_link(),
        Ok(ProvisioningLinkOutcome::Conflict) => {
            return api_error(
                StatusCode::CONFLICT,
                "provisioning_link_conflict",
                "a Source link already exists for this operation",
            );
        }
        Err(StoreError::InvalidInput(_)) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_provisioning_link",
                "the Source link request is invalid",
            );
        }
        Err(_) => return unavailable(),
    };
    match link_body(&state, &record) {
        Some(body) => (status, Json(body)).into_response(),
        None => unavailable(),
    }
}

async fn read_metadata(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SignatureQuery>,
    headers: HeaderMap,
) -> Response {
    let session = match named_operator(&state, &headers, false).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if !valid_link_id(&id) {
        return unavailable_link();
    }
    if let Err(response) =
        check_capability(&state, &id, BrowserScope::Metadata, query.sig.as_deref())
    {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.provisioning_metadata(&id, &session).await {
        Ok(ProvisioningMetadataOutcome::Ready(metadata)) => {
            let parse = |text: &str| {
                canonicalize_json(text)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            };
            let (Some(offer), Some(grant)) =
                (parse(&metadata.offer_json), parse(&metadata.grant_json))
            else {
                return unavailable();
            };
            Json(json!({
                "status": "ready",
                "server_time_ms": metadata.server_time_ms,
                "expires_at_ms": metadata.expires_at_ms,
                "offer": offer,
                "expected": {
                    "grant": grant,
                    "node_key_version": metadata.node_key_version,
                    "source_unit": metadata.source_unit,
                    "credential": metadata.credential,
                    "signing_public": metadata.signing_public,
                },
                "summary": {
                    "purpose": metadata.purpose,
                    "workload_name": metadata.workload_name,
                },
            }))
            .into_response()
        }
        Ok(ProvisioningMetadataOutcome::Submitted(receipt)) => {
            Json(receipt_body(&receipt)).into_response()
        }
        Ok(ProvisioningMetadataOutcome::Forbidden) => owner_required(),
        Ok(ProvisioningMetadataOutcome::SessionEnded) => session_ended(),
        Ok(ProvisioningMetadataOutcome::Unavailable) => unavailable_link(),
        Err(_) => unavailable(),
    }
}

fn invalid_submission() -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "invalid_provisioning_submission",
        "the encapsulation and ciphertext must be canonical bounded base64url text",
    )
}

async fn submit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SignatureQuery>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let session = match named_operator(&state, &headers, true).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if !valid_link_id(&id) {
        return unavailable_link();
    }
    if let Err(response) = check_capability(&state, &id, BrowserScope::Submit, query.sig.as_deref())
    {
        return response;
    }
    let Ok(body) = body else {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "provisioning_payload_too_large",
            "the submission exceeds the encrypted Source size limit",
        );
    };
    // Parse errors are never echoed: the body carries operator ciphertext.
    let Ok(input) = serde_json::from_slice::<SubmitInput>(&body) else {
        return invalid_submission();
    };
    if BrowserProvisioningDelivery::decode_sealed(&input.enc, &input.ciphertext).is_err() {
        return invalid_submission();
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store
        .submit_provisioning(&id, &session, &input.enc, &input.ciphertext)
        .await
    {
        Ok(ProvisioningSubmitOutcome::Created(receipt)) => {
            (StatusCode::CREATED, Json(receipt_body(&receipt))).into_response()
        }
        Ok(ProvisioningSubmitOutcome::Existing(receipt)) => {
            Json(receipt_body(&receipt)).into_response()
        }
        Ok(ProvisioningSubmitOutcome::Conflict) => api_error(
            StatusCode::CONFLICT,
            "provisioning_ciphertext_conflict",
            "a different ciphertext was already submitted for this link",
        ),
        Ok(ProvisioningSubmitOutcome::Forbidden) => owner_required(),
        Ok(ProvisioningSubmitOutcome::SessionEnded) => session_ended(),
        Ok(ProvisioningSubmitOutcome::Unavailable) => unavailable_link(),
        Err(StoreError::InvalidInput(_)) => invalid_submission(),
        Err(_) => unavailable(),
    }
}
