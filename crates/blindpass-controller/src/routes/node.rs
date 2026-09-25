// SPDX-License-Identifier: AGPL-3.0-only

//! Authenticated, node-initiated fleet transport endpoints.

use crate::app::AppState;
use crate::routes::auth::jwt_validation;
use crate::store::{InboxDocument, NodeEventInsert};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blindpass_core::canon::{canonicalize_json, parse_json};
use blindpass_core::custody::sha256;
use blindpass_core::fleet::{
    ApplicationAck, DocumentKind, SignedEnvelope, TimeReply, node_event_message,
    node_session_challenge_message,
};
use blindpass_core::signing::ed25519::verify;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, decode, encode};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use std::time::{Duration, Instant};

const NODE_PROTOCOL_VERSION: &str = "blindpass-node/1";
const NODE_SESSION_TTL_MS: i64 = 15 * 60 * 1_000;
const NODE_POLL_HOLD: Duration = Duration::from_secs(30);
const NODE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_NODE_EVENT_BYTES: usize = 64 * 1024;
const MAX_NODE_EVENTS_PER_REQUEST: usize = 100;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInput {
    node_id: String,
    key_version: i64,
    protocol_version: String,
    capabilities: JsonValue,
    nonce: Option<String>,
    signature: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PollInput {
    ack_seq: Option<i64>,
    health: Option<JsonValue>,
    time_challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsInput {
    events: Vec<NodeEventInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeEventInput {
    idempotency_key: String,
    kind: String,
    body: JsonValue,
    broker_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeSessionClaims {
    sub: String,
    node_id: String,
    tenant_id: String,
    sid: String,
    key_version: i64,
    issuer_epoch: i64,
    protocol_version: String,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v3/node/session", post(node_session))
        .route("/api/v3/node/poll", post(node_poll))
        .route("/api/v3/node/events", post(node_events))
}

async fn node_session(State(state): State<AppState>, Json(body): Json<SessionInput>) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    if body.protocol_version != NODE_PROTOCOL_VERSION {
        return protocol_mismatch();
    }
    if body.key_version <= 0 {
        return invalid_session();
    }
    let (capabilities_json, capabilities_hash) = match canonical_capabilities(&body.capabilities) {
        Ok(value) => value,
        Err(()) => return invalid_session(),
    };
    match (body.nonce.as_deref(), body.signature.as_deref()) {
        (None, None) => {
            if state.issuer_keypair.is_none() || state.issuer_key_id.is_none() {
                return unavailable();
            }
            let mut nonce_bytes = [0_u8; 32];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
            let Some(nonce_hash) = digest_hex(&nonce_bytes) else {
                return unavailable();
            };
            let challenge = match store
                .create_node_challenge(
                    &body.node_id,
                    body.key_version,
                    &nonce_hash,
                    &body.protocol_version,
                    &capabilities_json,
                    &capabilities_hash,
                )
                .await
            {
                Ok(Some(challenge)) => challenge,
                Ok(None) => {
                    return api_error(
                        StatusCode::UNAUTHORIZED,
                        "node_not_approved",
                        "node is not active or its protocol and capabilities do not match",
                    );
                }
                Err(_) => return unavailable(),
            };
            let issuer = state
                .issuer_keypair
                .as_ref()
                .expect("issuer presence checked above");
            let issuer_key_id = state
                .issuer_key_id
                .as_deref()
                .expect("issuer key id presence checked above");
            (
                StatusCode::OK,
                Json(json!({
                    "nonce": nonce,
                    "controller_time_ms": challenge.created_at_ms,
                    "expires_at_ms": challenge.expires_at_ms,
                    "issuer_pub": URL_SAFE_NO_PAD.encode(issuer.public_key()),
                    "issuer_kid": issuer_key_id,
                    "issuer_epoch": challenge.issuer_epoch,
                    "min_protocol_version": NODE_PROTOCOL_VERSION,
                    "audience": "blindpass-node",
                    "tenant_id": challenge.tenant_id,
                    "node_id": challenge.node_id,
                    "key_version": challenge.key_version,
                    "capabilities_hash": challenge.capabilities_hash
                })),
            )
                .into_response()
        }
        (Some(nonce), Some(signature)) => {
            let Some(nonce_bytes) = decode_base64url(nonce, 32) else {
                return invalid_session();
            };
            let Some(signature_bytes) = decode_base64url(signature, 64) else {
                return invalid_session();
            };
            let Some(nonce_hash) = digest_hex(&nonce_bytes) else {
                return unavailable();
            };
            let challenge = match store.node_challenge(&body.node_id, &nonce_hash).await {
                Ok(Some(challenge)) => challenge,
                Ok(None) => return invalid_challenge(),
                Err(_) => return unavailable(),
            };
            if challenge.protocol_version != body.protocol_version
                || challenge.key_version != body.key_version
                || challenge.capabilities_json != capabilities_json
                || challenge.capabilities_hash != capabilities_hash
            {
                return invalid_challenge();
            }
            let node = match store.node_by_id(&body.node_id).await {
                Ok(Some(node))
                    if node.status == "active"
                        || (node.status == "revoked" && node.revocation_pending) =>
                {
                    node
                }
                Ok(_) => return invalid_challenge(),
                Err(_) => return unavailable(),
            };
            if node.protocol_version != challenge.protocol_version
                || node.capabilities_json != challenge.capabilities_json
            {
                return invalid_challenge();
            }
            let signing_public = match store
                .node_signing_public_key(&node.id, challenge.key_version)
                .await
            {
                Ok(Some(public_key)) => public_key,
                Ok(None) => return invalid_challenge(),
                Err(_) => return unavailable(),
            };
            let Some(public_key) = decode_base64url(&signing_public, 32) else {
                return unavailable();
            };
            let mut message = match node_session_challenge_message(
                store.tenant_id(),
                &body.node_id,
                &challenge.protocol_version,
                nonce,
                &challenge.capabilities_hash,
                u64::try_from(challenge.key_version).unwrap_or_default(),
                u64::try_from(challenge.issuer_epoch).unwrap_or_default(),
                challenge.created_at_ms,
                challenge.expires_at_ms,
            ) {
                Ok(message) => message,
                Err(_) => return invalid_challenge(),
            };
            let signature_valid = verify(&public_key, &message, &signature_bytes);
            blindpass_core::secret::wipe(&mut message);
            match signature_valid {
                Ok(true) => {}
                Ok(false) => return invalid_challenge(),
                Err(_) => return unavailable(),
            }
            let now_ms = match store.database_now_ms().await {
                Ok(now_ms) => now_ms,
                Err(_) => return unavailable(),
            };
            let Some(expires_at_ms) = now_ms.checked_add(NODE_SESSION_TTL_MS) else {
                return unavailable();
            };
            let session_id = format!("ns_{}", random_urlsafe(24));
            let claims = NodeSessionClaims {
                sub: node.id.clone(),
                node_id: node.id,
                tenant_id: store.tenant_id().to_owned(),
                sid: session_id.clone(),
                key_version: challenge.key_version,
                issuer_epoch: challenge.issuer_epoch,
                protocol_version: challenge.protocol_version.clone(),
                iss: "blindpass-controller".to_owned(),
                aud: "blindpass-node".to_owned(),
                iat: u64::try_from(now_ms.div_euclid(1_000)).unwrap_or_default(),
                exp: u64::try_from((expires_at_ms + 999).div_euclid(1_000)).unwrap_or_default(),
            };
            let token = match encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(state.agent_jwt_secret.as_bytes()),
            ) {
                Ok(token) => token,
                Err(_) => return unavailable(),
            };
            let Some(token_hash) = digest_hex(token.as_bytes()) else {
                return unavailable();
            };
            match store
                .consume_node_challenge(
                    &challenge,
                    &nonce_hash,
                    &session_id,
                    &token_hash,
                    expires_at_ms,
                )
                .await
            {
                Ok(true) => (
                    StatusCode::OK,
                    Json(json!({
                        "token": token,
                        "expires_at_ms": expires_at_ms,
                        "session_id": session_id
                    })),
                )
                    .into_response(),
                Ok(false) => invalid_challenge(),
                Err(_) => unavailable(),
            }
        }
        _ => invalid_session(),
    }
}

async fn node_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PollInput>,
) -> Response {
    if body.ack_seq.is_some_and(|seq| seq < 0)
        || body
            .time_challenge
            .as_deref()
            .is_some_and(|challenge| decode_base64url(challenge, 32).is_none())
        || body.health.as_ref().is_some_and(|health| {
            !health.is_object() || serde_json::to_vec(health).is_ok_and(|v| v.len() > 16 * 1024)
        })
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_poll",
            "poll metadata is invalid",
        );
    }
    let claims = match authenticate_node(&state, &headers, true).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let deadline = Instant::now() + NODE_POLL_HOLD;
    let mut ack_seq = body.ack_seq;
    loop {
        let documents = match store.poll_node_inbox(&claims.node_id, ack_seq).await {
            Ok(documents) => documents,
            Err(_) => return unavailable(),
        };
        ack_seq = None;
        if !documents.is_empty() || Instant::now() >= deadline {
            return poll_response(
                &state,
                store,
                &claims.node_id,
                body.time_challenge.as_deref(),
                documents,
            )
            .await;
        }
        tokio::time::sleep(
            NODE_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        )
        .await;
    }
}

async fn poll_response(
    state: &AppState,
    store: &crate::store::Store,
    node_id: &str,
    time_challenge: Option<&str>,
    documents: Vec<InboxDocument>,
) -> Response {
    let mut output = Vec::with_capacity(documents.len());
    let mut highest_seq = None;
    for document in documents {
        let Ok(envelope) = serde_json::from_str::<JsonValue>(&document.envelope_json) else {
            return unavailable();
        };
        highest_seq = Some(document.seq);
        output.push(json!({"seq": document.seq, "envelope": envelope}));
    }
    let server_time_ms = match store.database_now_ms().await {
        Ok(value) => value,
        Err(_) => return unavailable(),
    };
    let time_reply = if let Some(challenge) = time_challenge {
        let (Some(issuer), Some(key_id)) = (
            state.issuer_keypair.as_ref(),
            state.issuer_key_id.as_deref(),
        ) else {
            return unavailable();
        };
        let Ok(controller_time_ms) = u64::try_from(server_time_ms) else {
            return unavailable();
        };
        let Ok(issuer_epoch) = store.issuer_epoch().await else {
            return unavailable();
        };
        let reply = TimeReply {
            node_id: node_id.to_owned(),
            challenge: challenge.to_owned(),
            controller_time_ms,
            issuer_epoch,
        };
        let Ok(body) = reply.to_value() else {
            return unavailable();
        };
        let Ok(envelope) =
            SignedEnvelope::sign(DocumentKind::TimeReply, body, key_id, issuer_epoch, issuer)
        else {
            return unavailable();
        };
        let Ok(bytes) = envelope.to_json() else {
            return unavailable();
        };
        let Ok(document) = serde_json::from_slice::<JsonValue>(&bytes) else {
            return unavailable();
        };
        Some(document)
    } else {
        None
    };
    Json(json!({
        "documents": output,
        "highest_seq": highest_seq,
        "server_time_ms": server_time_ms,
        "time_reply": time_reply
    }))
    .into_response()
}

async fn node_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EventsInput>,
) -> Response {
    let claims = match authenticate_node(&state, &headers, false).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if body.events.len() > MAX_NODE_EVENTS_PER_REQUEST {
        return api_error(
            StatusCode::BAD_REQUEST,
            "too_many_events",
            "event batch is too large",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let node = match store.node_by_id(&claims.node_id).await {
        Ok(Some(node))
            if node.status == "active" || (node.status == "revoked" && node.revocation_pending) =>
        {
            node
        }
        Ok(_) => return invalid_bearer(),
        Err(_) => return unavailable(),
    };
    let signing_public = match store
        .node_signing_public_key(&claims.node_id, claims.key_version)
        .await
    {
        Ok(Some(public_key)) => public_key,
        Ok(None) => return invalid_bearer(),
        Err(_) => return unavailable(),
    };
    let Some(public_key) = decode_base64url(&signing_public, 32) else {
        return unavailable();
    };
    let mut accepted = 0_u32;
    let mut duplicates = 0_u32;
    let mut accepted_keys = Vec::with_capacity(body.events.len());
    for event in body.events {
        let body_source = match serde_json::to_string(&event.body) {
            Ok(source) => source,
            Err(_) => return invalid_event(),
        };
        let Ok(body_bytes) = canonicalize_json(&body_source) else {
            return invalid_event();
        };
        if body_bytes.len() > MAX_NODE_EVENT_BYTES {
            return invalid_event();
        }
        let body_json = match std::str::from_utf8(&body_bytes) {
            Ok(value) => value,
            Err(_) => return invalid_event(),
        };
        let body_value = match parse_json(body_json) {
            Ok(value) => value,
            Err(_) => return invalid_event(),
        };
        let mut message = match node_event_message(
            &claims.node_id,
            &event.idempotency_key,
            &event.kind,
            &body_value,
        ) {
            Ok(message) => message,
            Err(_) => return invalid_event(),
        };
        let Some(signature) = decode_base64url(&event.broker_signature, 64) else {
            blindpass_core::secret::wipe(&mut message);
            return invalid_event();
        };
        let verified = verify(&public_key, &message, &signature);
        let Some(body_hash) = digest_hex(&message) else {
            blindpass_core::secret::wipe(&mut message);
            return unavailable();
        };
        let prior = match store
            .node_event_by_key(&claims.node_id, &event.idempotency_key)
            .await
        {
            Ok(prior) => prior,
            Err(_) => {
                blindpass_core::secret::wipe(&mut message);
                return unavailable();
            }
        };
        let exact_duplicate = prior
            .as_ref()
            .is_some_and(|record| record.body_hash == body_hash);
        let verified = match verified {
            Ok(true) => true,
            Ok(false) if exact_duplicate && node.rotation_pending => {
                let old_key = match store
                    .node_signing_public_key(&claims.node_id, node.key_version)
                    .await
                {
                    Ok(Some(public_key)) => decode_base64url(&public_key, 32),
                    Ok(None) => None,
                    Err(_) => {
                        blindpass_core::secret::wipe(&mut message);
                        return unavailable();
                    }
                };
                let Some(old_key) = old_key else {
                    blindpass_core::secret::wipe(&mut message);
                    return invalid_event();
                };
                match verify(&old_key, &message, &signature) {
                    Ok(valid) => valid,
                    Err(_) => {
                        blindpass_core::secret::wipe(&mut message);
                        return unavailable();
                    }
                }
            }
            Ok(false) => false,
            Err(_) => {
                blindpass_core::secret::wipe(&mut message);
                return unavailable();
            }
        };
        blindpass_core::secret::wipe(&mut message);
        if !verified
            || (node.rotation_pending && claims.key_version == node.key_version && !exact_duplicate)
            || (node.status == "revoked" && event.kind == "operation_request")
        {
            return invalid_event();
        }
        if node.rotation_pending
            && event.kind == "operation_request"
            && claims.key_version == node.pending_key_version.unwrap_or_default()
        {
            return invalid_event();
        }
        let insertion = match store
            .record_node_event(
                &format!("ne_{}", random_urlsafe(24)),
                &claims.node_id,
                &event.idempotency_key,
                &event.kind,
                body_json,
                &body_hash,
            )
            .await
        {
            Ok(NodeEventInsert::Inserted) => true,
            Ok(NodeEventInsert::Duplicate) => false,
            Ok(NodeEventInsert::Conflict) => {
                return api_error(
                    StatusCode::CONFLICT,
                    "event_idempotency_conflict",
                    "an idempotency key was already used for different event bytes",
                );
            }
            Err(_) => return unavailable(),
        };
        let applied = match event.kind.as_str() {
            "operation_result" => {
                store
                    .reconcile_node_operation_result(&claims.node_id, body_json)
                    .await
            }
            "audit" => {
                store
                    .record_node_audit_event(&claims.node_id, &event.idempotency_key, body_json)
                    .await
            }
            "operation_request" => Ok(()),
            _ => return invalid_event(),
        };
        if applied.is_err() {
            return invalid_event();
        }
        if insertion {
            accepted += 1;
        } else {
            duplicates += 1;
        }
        accepted_keys.push(event.idempotency_key);
    }
    if accepted_keys.is_empty() {
        return Json(json!({"accepted": accepted, "duplicates": duplicates, "ack": null}))
            .into_response();
    }
    let (Some(issuer), Some(key_id)) = (
        state.issuer_keypair.as_ref(),
        state.issuer_key_id.as_deref(),
    ) else {
        return unavailable();
    };
    let issuer_epoch = match store.issuer_epoch().await {
        Ok(epoch) => epoch,
        Err(_) => return unavailable(),
    };
    let acknowledged_at_ms = match store.database_now_ms().await {
        Ok(value) => match u64::try_from(value) {
            Ok(value) => value,
            Err(_) => return unavailable(),
        },
        Err(_) => return unavailable(),
    };
    let ack = ApplicationAck {
        node_id: claims.node_id,
        issuer_epoch,
        acknowledged_at_ms,
        event_keys: accepted_keys,
    };
    let Ok(ack_body) = ack.to_value() else {
        return unavailable();
    };
    let Ok(envelope) = SignedEnvelope::sign(
        DocumentKind::ApplicationAck,
        ack_body,
        key_id,
        issuer_epoch,
        issuer,
    ) else {
        return unavailable();
    };
    let Ok(envelope_bytes) = envelope.to_json() else {
        return unavailable();
    };
    let Ok(envelope_json) = serde_json::from_slice::<JsonValue>(&envelope_bytes) else {
        return unavailable();
    };
    Json(json!({"accepted": accepted, "duplicates": duplicates, "ack": envelope_json}))
        .into_response()
}

#[allow(clippy::result_large_err)] // Axum route helpers return its response type directly.
async fn authenticate_node(
    state: &AppState,
    headers: &HeaderMap,
    poll: bool,
) -> Result<NodeSessionClaims, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer") && !token.is_empty())
        .map(|(_, token)| token)
        .ok_or_else(invalid_bearer)?;
    let mut validation = jwt_validation(Algorithm::HS256);
    validation.set_issuer(&["blindpass-controller"]);
    validation.set_audience(&["blindpass-node"]);
    let claims = decode::<NodeSessionClaims>(
        token,
        &DecodingKey::from_secret(state.agent_jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| invalid_bearer())?
    .claims;
    let Some(store) = state.store.as_ref() else {
        return Err(unavailable());
    };
    if claims.sub != claims.node_id
        || claims.tenant_id != store.tenant_id()
        || claims.protocol_version != NODE_PROTOCOL_VERSION
        || claims.key_version <= 0
        || claims.issuer_epoch <= 0
        || claims.sid.is_empty()
    {
        return Err(invalid_bearer());
    }
    let Some(token_hash) = digest_hex(token.as_bytes()) else {
        return Err(unavailable());
    };
    match store
        .authenticate_node_session(
            &claims.sid,
            &claims.node_id,
            &token_hash,
            claims.key_version,
            claims.issuer_epoch,
            &claims.protocol_version,
            poll,
        )
        .await
    {
        Ok(true) => Ok(claims),
        Ok(false) => Err(invalid_bearer()),
        Err(_) => Err(unavailable()),
    }
}

fn canonical_capabilities(value: &JsonValue) -> Result<(String, String), ()> {
    if !value.is_object() {
        return Err(());
    }
    let source = serde_json::to_string(value).map_err(|_| ())?;
    let canonical = canonicalize_json(&source).map_err(|_| ())?;
    let text = String::from_utf8(canonical.clone()).map_err(|_| ())?;
    let hash = digest_hex(&canonical).ok_or(())?;
    Ok((text, hash))
}

fn decode_base64url(value: &str, expected_bytes: usize) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    (decoded.len() == expected_bytes && URL_SAFE_NO_PAD.encode(&decoded) == value)
        .then_some(decoded)
}

fn digest_hex(value: &[u8]) -> Option<String> {
    sha256(value)
        .ok()
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn random_urlsafe(byte_count: usize) -> String {
    let mut bytes = vec![0; byte_count];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn protocol_mismatch() -> Response {
    (
        StatusCode::UPGRADE_REQUIRED,
        Json(json!({
            "error":"protocol_version_unsupported",
            "min_protocol_version": NODE_PROTOCOL_VERSION
        })),
    )
        .into_response()
}

fn invalid_session() -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "invalid_node_session",
        "node session fields are invalid",
    )
}

fn invalid_challenge() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "invalid_node_challenge",
        "node challenge is invalid or expired",
    )
}

fn invalid_bearer() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "invalid_node_session",
        "node session is invalid or expired",
    )
}

fn invalid_event() -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "invalid_node_event",
        "node event or broker signature is invalid",
    )
}

fn unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "controller_unavailable",
        "controller could not process the node request",
    )
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(json!({"error":code, "message":message}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::{canonical_capabilities, decode_base64url, digest_hex};

    #[test]
    fn capabilities_are_canonical_and_hashed() {
        let capabilities = serde_json::json!({"z": 1, "a": true});
        let (canonical, hash) = canonical_capabilities(&capabilities).unwrap();
        assert_eq!(canonical, r#"{"a":true,"z":1}"#);
        assert_eq!(hash, digest_hex(canonical.as_bytes()).unwrap());
        assert!(canonical_capabilities(&serde_json::json!(null)).is_err());
        assert!(decode_base64url("A", 1).is_none());
    }
}
