// SPDX-License-Identifier: AGPL-3.0-only

//! Fleet enrollment and read-only node inventory.

use crate::app::AppState;
use crate::routes::admin_session::{authenticated_session, valid_origin, valid_session_csrf};
use crate::store::{EnrollmentRecord, LocalSession, NodeRecord};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blindpass_core::canon::canonicalize_json;
use blindpass_core::custody::{RecipientKeyPair, sha256};
use blindpass_core::fleet::{enrollment_proof_message, node_key_fingerprint};
use blindpass_core::signing::ed25519::verify;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};

const ENROLLMENT_TTL_SECONDS: u64 = 10 * 60;
const EXPECTED_NODE_PROTOCOL: &str = "blindpass-node/1";
const MAX_ENROLLMENT_METADATA_BYTES: usize = 16 * 1024;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v3/enrollments",
            get(list_enrollments).post(create_enrollment),
        )
        .route("/api/v3/enrollments/{id}", get(get_enrollment))
        .route("/api/v3/enrollments/{id}/approve", post(approve_enrollment))
        .route("/api/v3/enrollments/{id}/reject", post(reject_enrollment))
        .route("/api/v3/nodes", get(list_nodes))
        .route("/api/v3/nodes/{id}", get(get_node))
        .route("/api/v3/node/enroll", post(submit_node_enrollment))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentCreateInput {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentDecisionInput {
    expected_fingerprint: String,
    expected_version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentSubmission {
    token: String,
    signing_pub: String,
    recipient_pub: String,
    proof: String,
    protocol_version: String,
    capabilities: Value,
    host_facts: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

async fn create_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnrollmentCreateInput>,
) -> Response {
    let operator = match require_operator(&state, &headers, true, true).await {
        Ok(operator) => operator,
        Err(response) => return response,
    };
    let name = body.name.trim();
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_enrollment",
            "node name must be 1 to 128 printable bytes",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let id = random_id("en_");
    let node_id = random_id("nd_");
    let token = format!("{}_{}", id, random_secret());
    let Some(token_hash) = token_hash(&token) else {
        return unavailable();
    };
    match store
        .create_enrollment(
            &id,
            &node_id,
            name,
            &token_hash,
            &operator.operator.id,
            ENROLLMENT_TTL_SECONDS,
        )
        .await
    {
        Ok(expires_at_ms) => (
            StatusCode::CREATED,
            Json(json!({
                "id": id,
                "node_id": node_id,
                "token": token,
                "expires_at": expires_at_ms
            })),
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

async fn list_enrollments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, false, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let now = match store.database_now_ms().await {
        Ok(now) => now,
        Err(_) => return unavailable(),
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let cursor = match parse_cursor(query.cursor.as_deref()) {
        Ok(cursor) => cursor,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "cursor is invalid",
            );
        }
    };
    let mut records = match store.list_enrollments(limit + 1, cursor).await {
        Ok(records) => records,
        Err(_) => return unavailable(),
    };
    let has_more = records.len() > limit as usize;
    records.truncate(limit as usize);
    let next_cursor = if has_more {
        records
            .last()
            .map(|record| encode_cursor(record.created_at_ms, &record.id))
    } else {
        None
    };
    Json(json!({
        "items": records.iter().map(|record| enrollment_body(record, now)).collect::<Vec<_>>(),
        "next_cursor": next_cursor
    }))
    .into_response()
}

async fn get_enrollment(
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
    let record = match store.enrollment_by_id(&id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "enrollment_not_found",
                "enrollment was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    let now = match store.database_now_ms().await {
        Ok(now) => now,
        Err(_) => return unavailable(),
    };
    Json(enrollment_body(&record, now)).into_response()
}

async fn submit_node_enrollment(
    State(state): State<AppState>,
    Json(body): Json<EnrollmentSubmission>,
) -> Response {
    if state.issuer_keypair.is_none() {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet_disabled",
            "fleet authorization is not configured",
        );
    }
    if body.protocol_version != EXPECTED_NODE_PROTOCOL {
        return (
            StatusCode::UPGRADE_REQUIRED,
            Json(json!({
                "error":"protocol_version_unsupported",
                "min_protocol_version": EXPECTED_NODE_PROTOCOL
            })),
        )
            .into_response();
    }
    let Some((enrollment_id, _token_secret)) = parse_enrollment_token(&body.token) else {
        return enrollment_expired();
    };
    let Some(token_hash) = token_hash(&body.token) else {
        return unavailable();
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let enrollment = match store
        .issued_enrollment_by_token_hash(&enrollment_id, &token_hash)
        .await
    {
        Ok(Some(enrollment)) => enrollment,
        Ok(None) => return enrollment_expired(),
        Err(_) => return unavailable(),
    };
    let Some(signing_public_key) = decode_base64url(&body.signing_pub, 32) else {
        return invalid_enrollment();
    };
    let Some(recipient_public_key) = decode_base64url(&body.recipient_pub, 32) else {
        return invalid_enrollment();
    };
    let Some(proof) = decode_base64url(&body.proof, 64) else {
        return invalid_enrollment();
    };
    if RecipientKeyPair::seal(&recipient_public_key, b"", b"blindpass:fleet-enrollment").is_err() {
        return invalid_enrollment();
    }
    let message =
        match enrollment_proof_message(&body.token, &signing_public_key, &recipient_public_key) {
            Ok(message) => message,
            Err(_) => return invalid_enrollment(),
        };
    match verify(&signing_public_key, &message, &proof) {
        Ok(true) => {}
        Ok(false) => return invalid_enrollment(),
        Err(_) => return unavailable(),
    }
    if !matches!(body.capabilities, Value::Object(_))
        || !matches!(body.host_facts, Value::Object(_))
    {
        return invalid_enrollment();
    }
    let capabilities_json = match serde_json::to_string(&body.capabilities)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .and_then(|value| String::from_utf8(value).ok())
    {
        Some(value) if value.len() <= MAX_ENROLLMENT_METADATA_BYTES => value,
        _ => return invalid_enrollment(),
    };
    let host_facts_json = match serde_json::to_string(&body.host_facts) {
        Ok(value) if value.len() <= MAX_ENROLLMENT_METADATA_BYTES => value,
        _ => return invalid_enrollment(),
    };
    let fingerprint = match node_key_fingerprint(&signing_public_key, &recipient_public_key) {
        Ok(fingerprint) => fingerprint,
        Err(_) => return unavailable(),
    };
    let signing_pub = URL_SAFE_NO_PAD.encode(&signing_public_key);
    let recipient_pub = URL_SAFE_NO_PAD.encode(&recipient_public_key);
    match store
        .submit_enrollment(
            &enrollment.id,
            &enrollment.node_id,
            &token_hash,
            &enrollment.requested_name,
            &signing_pub,
            &recipient_pub,
            &fingerprint,
            &body.protocol_version,
            &capabilities_json,
            &host_facts_json,
        )
        .await
    {
        Ok(true) => (
            StatusCode::CREATED,
            Json(json!({
                "enrollment_id": enrollment.id,
                "node_id": enrollment.node_id,
                "tenant_id": store.tenant_id(),
                "fingerprint": fingerprint,
                "status":"submitted"
            })),
        )
            .into_response(),
        Ok(false) => enrollment_expired(),
        Err(_) => unavailable(),
    }
}

async fn approve_enrollment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EnrollmentDecisionInput>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, true, true).await {
        return response;
    }
    if !valid_fingerprint(&body.expected_fingerprint) || body.expected_version <= 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_decision",
            "fingerprint or version is invalid",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store
        .approve_enrollment(&id, body.expected_version, &body.expected_fingerprint)
        .await
    {
        Ok(Some(node)) => {
            let now = match store.database_now_ms().await {
                Ok(now) => now,
                Err(_) => return unavailable(),
            };
            match node_body(&node, now) {
                Some(body) => (StatusCode::OK, Json(body)).into_response(),
                None => unavailable(),
            }
        }
        Ok(None) => api_error(
            StatusCode::CONFLICT,
            "enrollment_changed",
            "enrollment changed, fingerprint did not match, or node name is already registered",
        ),
        Err(_) => unavailable(),
    }
}

async fn reject_enrollment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EnrollmentDecisionInput>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, true, true).await {
        return response;
    }
    if !valid_fingerprint(&body.expected_fingerprint) || body.expected_version <= 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_decision",
            "fingerprint or version is invalid",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store
        .reject_enrollment(&id, body.expected_version, &body.expected_fingerprint)
        .await
    {
        Ok(true) => match store.enrollment_by_id(&id).await {
            Ok(Some(record)) => match store.database_now_ms().await {
                Ok(now) => (StatusCode::OK, Json(enrollment_body(&record, now))).into_response(),
                Err(_) => unavailable(),
            },
            Ok(None) | Err(_) => unavailable(),
        },
        Ok(false) => api_error(
            StatusCode::CONFLICT,
            "enrollment_changed",
            "enrollment expired, changed, or the fingerprint did not match",
        ),
        Err(_) => unavailable(),
    }
}

async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers, false, false).await {
        return response;
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let now = match store.database_now_ms().await {
        Ok(now) => now,
        Err(_) => return unavailable(),
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let cursor = match parse_cursor(query.cursor.as_deref()) {
        Ok(cursor) => cursor,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "cursor is invalid",
            );
        }
    };
    let mut nodes = match store.list_nodes(limit + 1, cursor).await {
        Ok(nodes) => nodes,
        Err(_) => return unavailable(),
    };
    let has_more = nodes.len() > limit as usize;
    nodes.truncate(limit as usize);
    let next_cursor = if has_more {
        nodes
            .last()
            .map(|node| encode_cursor(node.created_at_ms, &node.id))
    } else {
        None
    };
    let Some(items) = nodes
        .iter()
        .map(|node| node_body(node, now))
        .collect::<Option<Vec<_>>>()
    else {
        return unavailable();
    };
    Json(json!({"items":items,"next_cursor":next_cursor})).into_response()
}

async fn get_node(
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
    let node = match store.node_by_id(&id).await {
        Ok(Some(node)) => node,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "node_not_found",
                "node was not found",
            );
        }
        Err(_) => return unavailable(),
    };
    let now = match store.database_now_ms().await {
        Ok(now) => now,
        Err(_) => return unavailable(),
    };
    match node_body(&node, now) {
        Some(body) => Json(body).into_response(),
        None => unavailable(),
    }
}

async fn require_operator(
    state: &AppState,
    headers: &HeaderMap,
    unsafe_method: bool,
    administrator_only: bool,
) -> Result<LocalSession, Response> {
    let session = authenticated_session(state.store.as_ref(), headers)
        .await
        .ok_or_else(|| {
            api_error(
                StatusCode::UNAUTHORIZED,
                "session_required",
                "an active local session is required",
            )
        })?;
    if session.operator.must_change_password {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "password_change_required",
            "change the temporary password before using fleet administration",
        ));
    }
    if administrator_only && session.operator.role != "admin" {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "role_denied",
            "administrator role is required",
        ));
    }
    if unsafe_method && (!valid_origin(state, headers) || !valid_session_csrf(headers, &session)) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "csrf_or_origin_denied",
            "origin or CSRF validation failed",
        ));
    }
    Ok(session)
}

fn enrollment_body(record: &EnrollmentRecord, now_ms: i64) -> Value {
    let status = if record.status == "issued" && record.expires_at_ms <= now_ms {
        "expired"
    } else {
        record.status.as_str()
    };
    json!({
        "id": record.id,
        "name": record.requested_name,
        "status": status,
        "fingerprint": record.fingerprint,
        "protocol_version": record.protocol_version,
        "capabilities": record.capabilities_json.as_deref().and_then(|value| serde_json::from_str::<Value>(value).ok()),
        "created_at": record.created_at_ms,
        "expires_at": record.expires_at_ms,
        "version": record.version
    })
}

fn node_body(record: &NodeRecord, now_ms: i64) -> Option<Value> {
    let status = if record.status == "revoked" {
        "revoked"
    } else {
        match record.last_seen_at_ms {
            Some(last_seen) if now_ms.saturating_sub(last_seen) <= 45_000 => "online",
            Some(last_seen) if now_ms.saturating_sub(last_seen) <= 120_000 => "stale",
            _ => "offline",
        }
    };
    let signing_key = decode_base64url(&record.signing_pub, 32)?;
    let recipient_key = decode_base64url(&record.recipient_pub, 32)?;
    let capabilities: Value = serde_json::from_str(&record.capabilities_json).ok()?;
    Some(json!({
        "id": record.id,
        "name": record.name,
        "status": status,
        "protocol_version": record.protocol_version,
        "capabilities": capabilities,
        "key_version": record.key_version,
        "signing_fingerprint": public_key_fingerprint(&signing_key)?,
        "recipient_fingerprint": public_key_fingerprint(&recipient_key)?,
        "last_seen_at": record.last_seen_at_ms,
        "last_poll_at": record.last_poll_at_ms,
        "created_at": record.created_at_ms,
        "version": record.version
    }))
}

fn parse_enrollment_token(token: &str) -> Option<(String, String)> {
    let token = token.strip_prefix("en_")?;
    let (uuid, secret) = token.split_once('_')?;
    if uuid.len() != 36 || decode_base64url(secret, 32).is_none() {
        return None;
    }
    Some((format!("en_{uuid}"), secret.to_owned()))
}

fn token_hash(token: &str) -> Option<String> {
    sha256(token.as_bytes())
        .ok()
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn public_key_fingerprint(public_key: &[u8]) -> Option<String> {
    sha256(public_key)
        .ok()
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn decode_base64url(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    (decoded.len() == expected_len && URL_SAFE_NO_PAD.encode(&decoded) == value).then_some(decoded)
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_cursor(value: Option<&str>) -> Result<Option<(i64, String)>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };
    let (created_at, id) = value.split_once('~').ok_or(())?;
    let created_at = created_at.parse::<i64>().map_err(|_| ())?;
    if created_at <= 0 || id.is_empty() || id.len() > 128 {
        return Err(());
    }
    Ok(Some((created_at, id.to_owned())))
}

fn encode_cursor(created_at: i64, id: &str) -> String {
    format!("{created_at}~{id}")
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let raw = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{prefix}{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..]
    )
}

fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn invalid_enrollment() -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "invalid_enrollment",
        "enrollment fields or key proof are invalid",
    )
}

fn enrollment_expired() -> Response {
    api_error(
        StatusCode::GONE,
        "enrollment_expired",
        "enrollment token is invalid, expired, or already used",
    )
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "not_ready",
        "controller state is unavailable",
    )
}

fn api_error(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({"error":error,"message":message}))).into_response()
}
