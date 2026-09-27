// SPDX-License-Identifier: AGPL-3.0-only

//! Authenticated, node-initiated fleet transport endpoints.

use crate::app::AppState;
use crate::routes::auth::jwt_validation;
use crate::store::{
    InboxDocument, NodeEventInsert, NodeRecord, NodeSessionDraft, Store, StoreError,
};
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
use blindpass_core::secret::SecretBytes;
use blindpass_core::signing::ed25519::verify;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, decode, encode};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use std::time::{Duration, Instant};

const NODE_PROTOCOL_VERSION: &str = "blindpass-node/1";
const NODE_SESSION_TTL_MS: i64 = 15 * 60 * 1_000;
const NODE_CHALLENGE_TTL_MS: i64 = 60_000;
const NODE_SESSION_JWT_DOMAIN: &[u8] = b"blindpass:node-session-jwt:v1";
const NODE_CHALLENGE_MAC_DOMAIN: &[u8] = b"blindpass:node-session-challenge-mac:v1";
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

/// Keys derived from the agent JWT secret for the node channel only, so node
/// session tokens and challenge MACs never share a key with agent tokens.
pub(crate) struct NodeChannelKeys {
    pub(crate) session_jwt: SecretBytes,
    pub(crate) challenge_mac: SecretBytes,
}

impl NodeChannelKeys {
    pub(crate) fn derive(agent_jwt_secret: &[u8]) -> Self {
        Self {
            session_jwt: SecretBytes::new(
                hmac_sha256(agent_jwt_secret, NODE_SESSION_JWT_DOMAIN)
                    .expect("HMAC-SHA256 node session key derivation"),
            ),
            challenge_mac: SecretBytes::new(
                hmac_sha256(agent_jwt_secret, NODE_CHALLENGE_MAC_DOMAIN)
                    .expect("HMAC-SHA256 node challenge key derivation"),
            ),
        }
    }
}

/// HMAC-SHA256 through the HS256 primitive of the existing JWT dependency.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let encoded =
        jsonwebtoken::crypto::sign(message, &EncodingKey::from_secret(key), Algorithm::HS256)
            .ok()?;
    let digest = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    (digest.len() == 32).then_some(digest)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

/// Fields a stateless challenge authenticates. The nonce carries its own
/// issue time and a truncated controller MAC, so the relay can keep sending
/// exactly the 32-byte nonce it already handles.
struct ChallengeBinding<'a> {
    tenant_id: &'a str,
    node_id: &'a str,
    key_version: i64,
    capabilities_hash: &'a str,
    protocol_version: &'a str,
    issuer_epoch: i64,
    created_at_ms: i64,
    expires_at_ms: i64,
}

impl ChallengeBinding<'_> {
    fn tag(&self, key: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
        let mut message = b"blindpass:node-session-challenge:v1".to_vec();
        for field in [
            self.tenant_id.as_bytes(),
            self.node_id.as_bytes(),
            self.key_version.to_string().as_bytes(),
            self.capabilities_hash.as_bytes(),
            self.protocol_version.as_bytes(),
            self.issuer_epoch.to_string().as_bytes(),
            self.created_at_ms.to_string().as_bytes(),
            self.expires_at_ms.to_string().as_bytes(),
            prefix,
        ] {
            message.extend_from_slice(&u32::try_from(field.len()).ok()?.to_be_bytes());
            message.extend_from_slice(field);
        }
        let mut digest = hmac_sha256(key, &message)?;
        digest.truncate(CHALLENGE_TAG_BYTES);
        Some(digest)
    }
}

const CHALLENGE_TIME_BYTES: usize = 6;
const CHALLENGE_RANDOM_BYTES: usize = 10;
const CHALLENGE_TAG_BYTES: usize = 16;
const CHALLENGE_PREFIX_BYTES: usize = CHALLENGE_TIME_BYTES + CHALLENGE_RANDOM_BYTES;

fn issue_challenge_nonce(key: &[u8], binding: &ChallengeBinding<'_>) -> Option<[u8; 32]> {
    let created = u64::try_from(binding.created_at_ms).ok()?;
    if created >= 1 << 48 {
        return None;
    }
    let mut nonce = [0_u8; 32];
    nonce[..CHALLENGE_TIME_BYTES].copy_from_slice(&created.to_be_bytes()[2..]);
    OsRng.fill_bytes(&mut nonce[CHALLENGE_TIME_BYTES..CHALLENGE_PREFIX_BYTES]);
    let tag = binding.tag(key, &nonce[..CHALLENGE_PREFIX_BYTES])?;
    nonce[CHALLENGE_PREFIX_BYTES..].copy_from_slice(&tag);
    Some(nonce)
}

fn challenge_created_at(nonce: &[u8]) -> Option<i64> {
    let mut bytes = [0_u8; 8];
    bytes[2..].copy_from_slice(nonce.get(..CHALLENGE_TIME_BYTES)?);
    i64::try_from(u64::from_be_bytes(bytes)).ok()
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
    let (Some(issuer), Some(issuer_key_id)) = (
        state.issuer_keypair.as_ref(),
        state.issuer_key_id.as_deref(),
    ) else {
        return unavailable();
    };
    match (body.nonce.as_deref(), body.signature.as_deref()) {
        (None, None) => {
            // Phase 1 is read-only: no per-node state is written or deleted,
            // so an unauthenticated caller cannot disturb a real handshake.
            let context = match store
                .node_session_context(
                    &body.node_id,
                    body.key_version,
                    &body.protocol_version,
                    &capabilities_json,
                )
                .await
            {
                Ok(Some(context)) => context,
                Ok(None) => {
                    return api_error(
                        StatusCode::UNAUTHORIZED,
                        "node_not_approved",
                        "node is not active or its protocol and capabilities do not match",
                    );
                }
                Err(_) => return unavailable(),
            };
            let Some(expires_at_ms) = context.now_ms.checked_add(NODE_CHALLENGE_TTL_MS) else {
                return unavailable();
            };
            let binding = ChallengeBinding {
                tenant_id: &context.tenant_id,
                node_id: &context.node_id,
                key_version: context.key_version,
                capabilities_hash: &capabilities_hash,
                protocol_version: &body.protocol_version,
                issuer_epoch: context.issuer_epoch,
                created_at_ms: context.now_ms,
                expires_at_ms,
            };
            let Some(nonce) =
                issue_challenge_nonce(state.node_keys.challenge_mac.as_bytes(), &binding)
            else {
                return unavailable();
            };
            (
                StatusCode::OK,
                Json(json!({
                    "nonce": URL_SAFE_NO_PAD.encode(nonce),
                    "controller_time_ms": context.now_ms,
                    "expires_at_ms": expires_at_ms,
                    "issuer_pub": URL_SAFE_NO_PAD.encode(issuer.public_key()),
                    "issuer_kid": issuer_key_id,
                    "issuer_epoch": context.issuer_epoch,
                    "min_protocol_version": NODE_PROTOCOL_VERSION,
                    "audience": "blindpass-node",
                    "tenant_id": context.tenant_id,
                    "node_id": context.node_id,
                    "key_version": context.key_version,
                    "capabilities_hash": capabilities_hash
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
            let Some(created_at_ms) = challenge_created_at(&nonce_bytes) else {
                return invalid_challenge();
            };
            let Some(expires_at_ms) = created_at_ms.checked_add(NODE_CHALLENGE_TTL_MS) else {
                return invalid_challenge();
            };
            let context = match store
                .node_session_context(
                    &body.node_id,
                    body.key_version,
                    &body.protocol_version,
                    &capabilities_json,
                )
                .await
            {
                Ok(Some(context)) => context,
                Ok(None) => return invalid_challenge(),
                Err(_) => return unavailable(),
            };
            let binding = ChallengeBinding {
                tenant_id: &context.tenant_id,
                node_id: &context.node_id,
                key_version: context.key_version,
                capabilities_hash: &capabilities_hash,
                protocol_version: &body.protocol_version,
                issuer_epoch: context.issuer_epoch,
                created_at_ms,
                expires_at_ms,
            };
            let Some(expected_tag) = binding.tag(
                state.node_keys.challenge_mac.as_bytes(),
                &nonce_bytes[..CHALLENGE_PREFIX_BYTES],
            ) else {
                return unavailable();
            };
            if !constant_time_equal(&expected_tag, &nonce_bytes[CHALLENGE_PREFIX_BYTES..])
                || context.now_ms >= expires_at_ms
                || created_at_ms > context.now_ms.saturating_add(5_000)
            {
                return invalid_challenge();
            }
            let Some(nonce_hash) = digest_hex(&nonce_bytes) else {
                return unavailable();
            };
            let signing_public = match store
                .node_signing_public_key(&context.node_id, context.key_version)
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
                &context.tenant_id,
                &context.node_id,
                &body.protocol_version,
                nonce,
                &capabilities_hash,
                u64::try_from(context.key_version).unwrap_or_default(),
                u64::try_from(context.issuer_epoch).unwrap_or_default(),
                created_at_ms,
                expires_at_ms,
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
            let Some(session_expires_at_ms) = now_ms.checked_add(NODE_SESSION_TTL_MS) else {
                return unavailable();
            };
            let session_id = format!("ns_{}", random_urlsafe(24));
            let claims = NodeSessionClaims {
                sub: context.node_id.clone(),
                node_id: context.node_id.clone(),
                tenant_id: context.tenant_id.clone(),
                sid: session_id.clone(),
                key_version: context.key_version,
                issuer_epoch: context.issuer_epoch,
                protocol_version: body.protocol_version.clone(),
                iss: "blindpass-controller".to_owned(),
                aud: "blindpass-node".to_owned(),
                iat: u64::try_from(now_ms.div_euclid(1_000)).unwrap_or_default(),
                exp: u64::try_from((session_expires_at_ms + 999).div_euclid(1_000))
                    .unwrap_or_default(),
            };
            let token = match encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(state.node_keys.session_jwt.as_bytes()),
            ) {
                Ok(token) => token,
                Err(_) => return unavailable(),
            };
            let Some(token_hash) = digest_hex(token.as_bytes()) else {
                return unavailable();
            };
            let draft = NodeSessionDraft {
                node_id: context.node_id.clone(),
                key_version: context.key_version,
                issuer_epoch: context.issuer_epoch,
                protocol_version: body.protocol_version.clone(),
                capabilities_json,
                nonce_hash,
                challenge_expires_at_ms: expires_at_ms,
                session_id: session_id.clone(),
                token_hash,
                expires_at_ms: session_expires_at_ms,
            };
            match store.create_node_session(&draft).await {
                Ok(true) => (
                    StatusCode::OK,
                    Json(json!({
                        "token": token,
                        "expires_at_ms": session_expires_at_ms,
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
    // Signed into any time reply so the broker can subtract the long-poll
    // hold from its measured round trip.
    let challenge_received_at_ms = match store.database_now_ms().await {
        Ok(value) => value,
        Err(_) => return unavailable(),
    };
    let deadline = Instant::now() + NODE_POLL_HOLD;
    let mut ack_seq = body.ack_seq;
    loop {
        let documents = match store
            .poll_node_inbox(&claims.node_id, &claims.sid, ack_seq)
            .await
        {
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
                challenge_received_at_ms,
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
    challenge_received_at_ms: i64,
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
        let (Ok(controller_time_ms), Ok(challenge_received_at_ms)) = (
            u64::try_from(server_time_ms),
            u64::try_from(challenge_received_at_ms),
        ) else {
            return unavailable();
        };
        // A database clock step between the two reads must not produce an
        // arrival time after the stamp.
        let challenge_received_at_ms = challenge_received_at_ms.min(controller_time_ms);
        let Ok(issuer_epoch) = store.issuer_epoch().await else {
            return unavailable();
        };
        let reply = TimeReply {
            node_id: node_id.to_owned(),
            challenge: challenge.to_owned(),
            challenge_received_at_ms,
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
    let mut discarded = Vec::new();
    let mut rejected = JsonValue::Null;
    // Events apply in order. A correctly signed event that can never apply
    // is audited, discarded and acknowledged so it cannot stall the broker
    // queue. Any other failure stops the batch: events before it are
    // applied, recorded and acknowledged; it and later events are neither
    // recorded nor acknowledged, so the broker retries them.
    for event in &body.events {
        let outcome = match apply_node_event(store, &claims, &node, &public_key, event).await {
            Err(failure @ (EventFailure::Rejected | EventFailure::Conflict)) => match store
                .record_rejected_node_event(
                    &claims.node_id,
                    &event.idempotency_key,
                    &event.kind,
                    failure.code(),
                )
                .await
            {
                Ok(()) => {
                    accepted_keys.push(event.idempotency_key.clone());
                    discarded.push(json!({
                        "idempotency_key": event.idempotency_key,
                        "error": failure.code()
                    }));
                    continue;
                }
                Err(_) => Err(EventFailure::Unavailable),
            },
            outcome => outcome,
        };
        match outcome {
            Ok(true) => {
                accepted += 1;
                accepted_keys.push(event.idempotency_key.clone());
            }
            Ok(false) => {
                duplicates += 1;
                accepted_keys.push(event.idempotency_key.clone());
            }
            Err(failure) => {
                if accepted_keys.is_empty() {
                    return failure.response();
                }
                rejected = json!({
                    "idempotency_key": event.idempotency_key,
                    "error": failure.code()
                });
                break;
            }
        }
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
    Json(json!({
        "accepted": accepted,
        "duplicates": duplicates,
        "ack": envelope_json,
        "discarded": discarded,
        "rejected": rejected
    }))
    .into_response()
}

/// Why a node event was not accepted. `Invalid` covers events whose framing
/// or broker signature fails and is never acknowledged (400). `Rejected` and
/// `Conflict` are correctly signed events that can never apply; they are
/// audited and acknowledged as discarded. Store failures are transient (503).
enum EventFailure {
    Invalid,
    Rejected,
    Conflict,
    Unavailable,
}

impl EventFailure {
    fn from_store(error: &StoreError) -> Self {
        match error {
            StoreError::InvalidInput(_) | StoreError::MissingState(_) => Self::Invalid,
            _ => Self::Unavailable,
        }
    }

    /// Map a store error from applying an event whose signature verified.
    fn from_applied(error: &StoreError) -> Self {
        match error {
            StoreError::InvalidInput(_) | StoreError::MissingState(_) => Self::Rejected,
            _ => Self::Unavailable,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Invalid | Self::Rejected => "invalid_node_event",
            Self::Conflict => "event_idempotency_conflict",
            Self::Unavailable => "service_unavailable",
        }
    }

    fn response(&self) -> Response {
        match self {
            Self::Invalid | Self::Rejected => invalid_event(),
            Self::Conflict => api_error(
                StatusCode::CONFLICT,
                "event_idempotency_conflict",
                "an idempotency key was already used for different event bytes",
            ),
            Self::Unavailable => unavailable(),
        }
    }
}

/// Verify, apply and then record one node event. Returns `true` when newly
/// recorded and `false` for an exact duplicate, which is not re-applied.
/// Recording happens only after the event applied, so a recorded event is
/// always an applied one and a failed event leaves no row behind.
async fn apply_node_event(
    store: &Store,
    claims: &NodeSessionClaims,
    node: &NodeRecord,
    public_key: &[u8],
    event: &NodeEventInput,
) -> Result<bool, EventFailure> {
    let body_source = serde_json::to_string(&event.body).map_err(|_| EventFailure::Invalid)?;
    let body_bytes = canonicalize_json(&body_source).map_err(|_| EventFailure::Invalid)?;
    if body_bytes.len() > MAX_NODE_EVENT_BYTES {
        return Err(EventFailure::Invalid);
    }
    let body_json = std::str::from_utf8(&body_bytes).map_err(|_| EventFailure::Invalid)?;
    let body_value = parse_json(body_json).map_err(|_| EventFailure::Invalid)?;
    let mut message = node_event_message(
        &claims.node_id,
        &event.idempotency_key,
        &event.kind,
        &body_value,
    )
    .map_err(|_| EventFailure::Invalid)?;
    let outcome = verify_node_event(store, claims, node, public_key, event, &message).await;
    blindpass_core::secret::wipe(&mut message);
    let (body_hash, exact_duplicate) = outcome?;
    if exact_duplicate {
        return Ok(false);
    }
    // Events signed by a key that a pending rotation is replacing are retried
    // after the rotation completes; they are not discarded.
    if (node.rotation_pending && claims.key_version == node.key_version)
        || (node.rotation_pending
            && event.kind == "operation_request"
            && claims.key_version == node.pending_key_version.unwrap_or_default())
    {
        return Err(EventFailure::Invalid);
    }
    if node.status == "revoked" && event.kind == "operation_request" {
        return Err(EventFailure::Rejected);
    }
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
        "operation_request" => {
            // The request is evidence for a later operator request; its node
            // claim must match the authenticated session at ingestion.
            if event.body.get("node_id").and_then(JsonValue::as_str)
                != Some(claims.node_id.as_str())
            {
                return Err(EventFailure::Rejected);
            }
            Ok(())
        }
        _ => return Err(EventFailure::Invalid),
    };
    applied.map_err(|error| EventFailure::from_applied(&error))?;
    match store
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
        Ok(NodeEventInsert::Inserted) => Ok(true),
        Ok(NodeEventInsert::Duplicate) => Ok(false),
        Ok(NodeEventInsert::Conflict) => Err(EventFailure::Conflict),
        Err(error) => Err(EventFailure::from_store(&error)),
    }
}

/// Check the broker signature and prior recording. Returns the event hash
/// and whether the identical event was already applied.
async fn verify_node_event(
    store: &Store,
    claims: &NodeSessionClaims,
    node: &NodeRecord,
    public_key: &[u8],
    event: &NodeEventInput,
    message: &[u8],
) -> Result<(String, bool), EventFailure> {
    let signature = decode_base64url(&event.broker_signature, 64).ok_or(EventFailure::Invalid)?;
    let verified =
        verify(public_key, message, &signature).map_err(|_| EventFailure::Unavailable)?;
    let body_hash = digest_hex(message).ok_or(EventFailure::Unavailable)?;
    let prior = store
        .recorded_node_event(&claims.node_id, &event.idempotency_key)
        .await
        .map_err(|error| EventFailure::from_store(&error))?;
    let exact_duplicate = match prior {
        Some(record) if record.body_hash == body_hash => true,
        // Only a correctly signed event can be a conflict; a relay-corrupted
        // copy of a recorded key stays an unacknowledged signature failure.
        Some(_) if verified => return Err(EventFailure::Conflict),
        Some(_) => return Err(EventFailure::Invalid),
        None => false,
    };
    let verified = if !verified && exact_duplicate && node.rotation_pending {
        // Replays signed by the pre-rotation key stay acknowledgeable.
        let old_key = store
            .node_signing_public_key(&claims.node_id, node.key_version)
            .await
            .map_err(|error| EventFailure::from_store(&error))?
            .and_then(|key| decode_base64url(&key, 32))
            .ok_or(EventFailure::Invalid)?;
        verify(&old_key, message, &signature).map_err(|_| EventFailure::Unavailable)?
    } else {
        verified
    };
    if !verified {
        return Err(EventFailure::Invalid);
    }
    Ok((body_hash, exact_duplicate))
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
        &DecodingKey::from_secret(state.node_keys.session_jwt.as_bytes()),
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
