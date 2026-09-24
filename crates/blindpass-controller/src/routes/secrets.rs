// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::auth::{AuthError, WorkloadIdentity, authenticate_workload, current_seconds};
use crate::store::{SecretRequestStatus, Store};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use blindpass_core::signing::{
    BrowserScope, VerifyError, sign_browser_payload, verify_browser_payload,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::json;

const CONFIRMATION_ADJECTIVES: [&str; 8] = [
    "BLUE", "GREEN", "SILVER", "BRIGHT", "BOLD", "SWIFT", "CALM", "NOBLE",
];
const CONFIRMATION_NOUNS: [&str; 8] = [
    "FOX", "RIVER", "MOUNTAIN", "FALCON", "HARBOR", "PINE", "MEADOW", "FIELD",
];
const MAX_CIPHERTEXT_LENGTH: usize = 524_288;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v2/secret/request", post(create_request))
        .route("/api/v2/secret/metadata/{id}", get(metadata))
        .route("/api/v2/secret/submit/{id}", post(submit))
        .route("/api/v2/secret/status/{id}", get(status))
        .route("/api/v2/secret/retrieve/{id}", get(retrieve))
        .route("/api/v2/secret/revoke/{id}", delete(revoke))
        .route(
            "/api/v2/secret/browser-status/{id}/capability",
            post(issue_browser_status_capability),
        )
        .route("/api/v2/secret/browser-status/{id}", get(browser_status))
}

#[derive(Debug, Deserialize)]
struct CreateRequestBody {
    public_key: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct SubmitRequestBody {
    enc: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct SignatureQuery {
    sig: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreatedRequestResponse {
    request_id: String,
    confirmation_code: String,
    secret_url: String,
}

async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateRequestBody>,
) -> Response {
    let Some(store) = state.store.as_ref() else {
        return service_unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
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
    if body.description.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"description must not be blank","statusCode":400})),
        )
            .into_response();
    }
    if body.description.len() > 512 {
        return validation_error("body/description must NOT have more than 512 characters");
    }
    if !valid_base64(&body.public_key, 2_048) {
        return validation_error("body/public_key must match pattern \"^[A-Za-z0-9+/]+={0,2}$\"");
    }
    let confirmation_code = confirmation_code();
    let created = match store
        .create_secret_request_with_expiry(
            &identity.sub,
            &body.public_key,
            &body.description,
            &confirmation_code,
            state.request_ttl_seconds,
        )
        .await
    {
        Ok(created) => created,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"request_create_failed"})),
            )
                .into_response();
        }
    };
    let expires_at = u64::try_from(created.expires_at_ms.div_euclid(1_000)).unwrap_or_default();
    let metadata_sig = match sign_browser_payload(
        &created.id,
        expires_at,
        BrowserScope::Metadata,
        state.root_secret.as_bytes(),
    ) {
        Ok(signature) => signature,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"request_sign_failed"})),
            )
                .into_response();
        }
    };
    let submit_sig = match sign_browser_payload(
        &created.id,
        expires_at,
        BrowserScope::Submit,
        state.root_secret.as_bytes(),
    ) {
        Ok(signature) => signature,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"request_sign_failed"})),
            )
                .into_response();
        }
    };
    let secret_url = format!(
        "{}/?id={}&metadata_sig={}&submit_sig={}&api_url={}",
        state.ui_base_url,
        created.id,
        percent_encode(&metadata_sig),
        percent_encode(&submit_sig),
        percent_encode(&state.public_url)
    );
    (
        StatusCode::CREATED,
        Json(CreatedRequestResponse {
            request_id: created.id,
            confirmation_code,
            secret_url,
        }),
    )
        .into_response()
}

async fn metadata(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SignatureQuery>,
) -> Response {
    if !valid_request_id(&id) {
        return expired_request();
    }
    let Some(signature) = query.sig.as_deref() else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"Missing signature"})),
        )
            .into_response();
    };
    let expiry = match verify_browser_payload(
        &id,
        BrowserScope::Metadata,
        signature,
        state.root_secret.as_bytes(),
        current_seconds(),
    ) {
        Ok(expiry) => expiry,
        Err(VerifyError::Expired) => return expired_request(),
        Err(VerifyError::Invalid) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"Invalid signature"})),
            )
                .into_response();
        }
    };
    let Some(store) = state.store.as_ref() else {
        return service_unavailable();
    };
    let metadata = match store.secret_request_metadata(&id).await {
        Ok(Some(metadata)) if capability_within_expiry(expiry, metadata.expires_at_ms) => metadata,
        _ => return expired_request(),
    };
    Json(json!({
        "public_key": metadata.public_key,
        "description": metadata.description,
        "confirmation_code": metadata.confirmation_code,
        "expiry": expiry
    }))
    .into_response()
}

async fn submit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SignatureQuery>,
    Json(body): Json<SubmitRequestBody>,
) -> Response {
    if !valid_request_id(&id) {
        return expired_request();
    }
    let Some(signature) = query.sig.as_deref() else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"Missing signature"})),
        )
            .into_response();
    };
    match verify_browser_payload(
        &id,
        BrowserScope::Submit,
        signature,
        state.root_secret.as_bytes(),
        current_seconds(),
    ) {
        Ok(_) => {}
        Err(VerifyError::Expired) => return expired_request(),
        Err(VerifyError::Invalid) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"Invalid signature"})),
            )
                .into_response();
        }
    }
    if body.enc.len() > 4_096 {
        return validation_error("body/enc must NOT have more than 4096 characters");
    }
    if body.ciphertext.len() > MAX_CIPHERTEXT_LENGTH {
        return validation_error("body/ciphertext must NOT have more than 524288 characters");
    }
    if !valid_base64(&body.enc, 4_096) {
        return validation_error("body/enc must match pattern \"^[A-Za-z0-9+/]+={0,2}$\"");
    }
    if !valid_base64(&body.ciphertext, MAX_CIPHERTEXT_LENGTH) {
        return validation_error("body/ciphertext must match pattern \"^[A-Za-z0-9+/]+={0,2}$\"");
    }
    let Some(store) = state.store.as_ref() else {
        return service_unavailable();
    };
    let metadata = match store.secret_request_metadata(&id).await {
        Ok(Some(metadata)) => metadata,
        _ => return expired_request(),
    };
    match store
        .submit_secret_request(
            &id,
            &metadata.requester_agent_id,
            &body.enc,
            &body.ciphertext,
            state.submitted_ttl_seconds,
        )
        .await
    {
        Ok(true) => (StatusCode::CREATED, Json(json!({"status":"submitted"}))).into_response(),
        Ok(false) => match store
            .request_status(&id, &metadata.requester_agent_id)
            .await
        {
            Ok(Some(SecretRequestStatus::Submitted)) => (
                StatusCode::CONFLICT,
                Json(json!({"error":"Already submitted"})),
            )
                .into_response(),
            _ => expired_request(),
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"request_submit_failed"})),
        )
            .into_response(),
    }
}

async fn status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_request_id(&id) {
        return gone_status();
    }
    let Some(store) = state.store.as_ref() else {
        return service_unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    if foreign_tenant(&identity, store) {
        return gone_status();
    }
    match store.request_status(&id, &identity.sub).await {
        Ok(Some(SecretRequestStatus::Pending)) => Json(json!({"status":"pending"})).into_response(),
        Ok(Some(SecretRequestStatus::Submitted)) => {
            Json(json!({"status":"submitted"})).into_response()
        }
        _ => gone_status(),
    }
}

async fn retrieve(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_request_id(&id) {
        return not_available();
    }
    let Some(store) = state.store.as_ref() else {
        return service_unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    if foreign_tenant(&identity, store) {
        return not_available();
    }
    match store.request_status(&id, &identity.sub).await {
        Ok(Some(SecretRequestStatus::Pending)) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"Not submitted yet"})),
            )
                .into_response();
        }
        Ok(Some(SecretRequestStatus::Submitted)) => {}
        _ => return not_available(),
    }
    match store.consume_secret_request(&id, &identity.sub).await {
        Ok(Some(payload)) => {
            Json(json!({"enc":payload.enc,"ciphertext":payload.ciphertext})).into_response()
        }
        _ => not_available(),
    }
}

async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_request_id(&id) {
        return not_available();
    }
    let Some(store) = state.store.as_ref() else {
        return service_unavailable();
    };
    let identity = match authenticate_workload(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return workload_auth_error(error),
    };
    if foreign_tenant(&identity, store) {
        return not_available();
    }
    match store.delete_secret_request(&id, &identity.sub).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        _ => not_available(),
    }
}

async fn issue_browser_status_capability(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SignatureQuery>,
) -> Response {
    if !valid_request_id(&id) {
        return gone_status();
    }
    let Some(signature) = query.sig.as_deref() else {
        return gone_status();
    };
    let expiry = match verify_browser_payload(
        &id,
        BrowserScope::Metadata,
        signature,
        state.root_secret.as_bytes(),
        current_seconds(),
    ) {
        Ok(expiry) => expiry,
        Err(_) => return gone_status(),
    };
    let Some(store) = state.store.as_ref() else {
        return service_unavailable();
    };
    let metadata = match store.secret_request_metadata(&id).await {
        Ok(Some(metadata)) if capability_within_expiry(expiry, metadata.expires_at_ms) => metadata,
        _ => return gone_status(),
    };
    let _ = metadata;
    match sign_browser_payload(
        &id,
        expiry,
        BrowserScope::Status,
        state.root_secret.as_bytes(),
    ) {
        Ok(status_sig) => Json(json!({"status_sig":status_sig})).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"capability_issue_failed"})),
        )
            .into_response(),
    }
}

async fn browser_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SignatureQuery>,
) -> Response {
    if !valid_request_id(&id) {
        return gone_status();
    }
    let Some(signature) = query.sig.as_deref() else {
        return gone_status();
    };
    if verify_browser_payload(
        &id,
        BrowserScope::Status,
        signature,
        state.root_secret.as_bytes(),
        current_seconds(),
    )
    .is_err()
    {
        return gone_status();
    }
    let Some(store) = state.store.as_ref() else {
        return service_unavailable();
    };
    match store.browser_request_status(&id).await {
        Ok(Some(SecretRequestStatus::Pending)) => Json(json!({"status":"pending"})).into_response(),
        Ok(Some(SecretRequestStatus::Submitted)) => {
            Json(json!({"status":"submitted"})).into_response()
        }
        _ => gone_status(),
    }
}

pub(crate) fn workload_auth_error(error: AuthError) -> Response {
    match error {
        AuthError::MissingBearer => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Missing bearer token"})),
        )
            .into_response(),
        AuthError::ProviderUnavailable => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"Gateway JWK unavailable"})),
        )
            .into_response(),
        AuthError::InvalidClaims => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Invalid gateway claims"})),
        )
            .into_response(),
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Invalid token"})),
        )
            .into_response(),
    }
}

fn foreign_tenant(identity: &WorkloadIdentity, store: &Store) -> bool {
    identity
        .workspace_id
        .as_deref()
        .is_some_and(|workspace| workspace != store.tenant_id())
}

fn valid_request_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn capability_within_expiry(token_expiry_seconds: u64, request_expiry_milliseconds: i64) -> bool {
    i64::try_from(token_expiry_seconds.saturating_mul(1_000))
        .is_ok_and(|token_expiry| token_expiry <= request_expiry_milliseconds)
}

fn valid_base64(value: &str, maximum: usize) -> bool {
    if value.len() < 4 || value.len() > maximum {
        return false;
    }
    let mut padding = false;
    let mut padding_count = 0;
    for byte in value.bytes() {
        if byte == b'=' {
            padding = true;
            padding_count += 1;
            if padding_count > 2 {
                return false;
            }
        } else if padding || !(byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/') {
            return false;
        }
    }
    true
}

fn confirmation_code() -> String {
    let mut random = [0_u8; 3];
    OsRng.fill_bytes(&mut random);
    format!(
        "{}-{}-{:02}",
        CONFIRMATION_ADJECTIVES[(random[0] as usize) % CONFIRMATION_ADJECTIVES.len()],
        CONFIRMATION_NOUNS[(random[1] as usize) % CONFIRMATION_NOUNS.len()],
        random[2] % 100
    )
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn validation_error(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"statusCode":400,"code":"FST_ERR_VALIDATION","error":"Bad Request","message":message})),
    )
        .into_response()
}

fn expired_request() -> Response {
    (StatusCode::GONE, Json(json!({"error":"Request expired"}))).into_response()
}

fn gone_status() -> Response {
    (StatusCode::GONE, Json(json!({"status":"expired"}))).into_response()
}

fn not_available() -> Response {
    (StatusCode::GONE, Json(json!({"error":"Not available"}))).into_response()
}

fn service_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":"service_unavailable"})),
    )
        .into_response()
}
