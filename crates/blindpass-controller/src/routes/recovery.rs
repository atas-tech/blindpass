// SPDX-License-Identifier: AGPL-3.0-only
//! Metadata-only recovery lane. Ordinary routes never inherit this admission.
use crate::{
    app::AppState,
    recovery_authority::{RecoveryChallenge, RecoveryReceiptState},
    store::{RecoveryApplicationSummary, StoreError},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
};
use blindpass_core::{
    canon::{canonicalize_value, parse_json},
    recovery::pages::{MAX_PAGE_BYTES, ReportPage},
    signing::{base64_url_decode, base64_url_encode},
};
use serde::Deserialize;
use serde_json::json;

pub(crate) fn is_recovery_path(path: &str) -> bool {
    matches!(path, "/api/recovery/request" | "/api/recovery/page")
}
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/recovery/request",
            post(report_request).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/recovery/page",
            post(report_page).layer(DefaultBodyLimit::max(MAX_PAGE_BYTES)),
        )
}
pub(crate) async fn metadata_gate(state: AppState, request: Request, next: Next) -> Response {
    let Some(owner) = state.recovery_owner().cloned() else {
        return crate::recovery_authority::fenced_response();
    };
    // Take the bounded slot before any authority round trip so a burst of
    // slow callers is refused cheaply instead of queueing on the one
    // authority connection.
    let Ok(_slot) = state.recovery_slots.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            Json(json!({"error":"recovery busy","code":"recovery_busy"})),
        )
            .into_response();
    };
    if owner.check_detached().await.is_err() {
        return crate::recovery_authority::fenced_response();
    }
    let Ok(_operation) = owner.begin_recovery_operation() else {
        return crate::recovery_authority::fenced_response();
    };
    tokio::select! {biased;
        _=owner.wait_fenced()=>crate::recovery_authority::fenced_response(),
        response=next.run(request)=>{
            if owner.check_detached().await.is_err() {crate::recovery_authority::fenced_response()} else {response}
        }
    }
}
fn invalid() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":"invalid recovery metadata","code":"invalid_recovery_metadata"})),
    )
        .into_response()
}
fn failure(error: StoreError) -> Response {
    match error {
        StoreError::InvalidInput(_) => invalid(),
        _ => crate::recovery_authority::fenced_response(),
    }
}
fn json_content(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestMetadata {
    version: u64,
    node_id: String,
    node_key_version: u64,
    broker_challenge: String,
}
fn status(
    challenge: &RecoveryChallenge,
    application: Option<RecoveryApplicationSummary>,
) -> Response {
    let state = match challenge.state {
        RecoveryReceiptState::Collecting => "collecting",
        RecoveryReceiptState::Covered => "covered",
        RecoveryReceiptState::Incomplete => "incomplete",
        RecoveryReceiptState::RebaseRequired => "rebase_required",
    };
    let application=application.map(|a|json!({"matched":a.matched,"unknown":a.unknown,"conflicting":a.conflicting,"unmapped":a.unmapped}));
    Json(json!({"version":1,"state":state,"next_page":challenge.next_page,"application":application,"activation_permitted":false})).into_response()
}
async fn report_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    if !json_content(&headers) {
        return invalid();
    }
    let Ok(input) = serde_json::from_slice::<RequestMetadata>(&bytes) else {
        return invalid();
    };
    if input.version != 1
        || !base64_url_decode(&input.broker_challenge, 32)
            .is_some_and(|bytes| base64_url_encode(&bytes) == input.broker_challenge)
    {
        return invalid();
    }
    let (Some(owner), Some(store)) = (state.recovery_owner(), state.store.as_ref()) else {
        return crate::recovery_authority::fenced_response();
    };
    let (challenge, application) = match store
        .resume_recovery_report(owner, &input.node_id, input.node_key_version)
        .await
    {
        Ok(value) => value,
        Err(error) => return failure(error),
    };
    if challenge.state != RecoveryReceiptState::Collecting {
        return status(&challenge, application);
    }
    match store
        .recovery_report_request(
            owner,
            &input.node_id,
            input.node_key_version,
            &input.broker_challenge,
        )
        .await
    {
        Ok(signed) => {
            let Ok(value) = signed.to_value() else {
                return invalid();
            };
            let Ok(canonical) = canonicalize_value(&value) else {
                return invalid();
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&canonical) else {
                return invalid();
            };
            Json(value).into_response()
        }
        Err(error) => failure(error),
    }
}
async fn report_page(State(state): State<AppState>, headers: HeaderMap, bytes: Bytes) -> Response {
    if !json_content(&headers) {
        return invalid();
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return invalid();
    };
    let Ok(value) = parse_json(text) else {
        return invalid();
    };
    let Some(fields) = value.as_object() else {
        return invalid();
    };
    if fields.len() != 2
        || fields.iter().filter(|(k, _)| k == "body").count() != 1
        || fields
            .iter()
            .filter(|(k, _)| k == "broker_signature")
            .count()
            != 1
    {
        return invalid();
    }
    let Some(body) = value.get("body") else {
        return invalid();
    };
    let Ok(body) = canonicalize_value(body) else {
        return invalid();
    };
    let Ok(body) = std::str::from_utf8(&body) else {
        return invalid();
    };
    let Ok(page) = ReportPage::from_json(body) else {
        return invalid();
    };
    let Some(signature) = value.get("broker_signature").and_then(|v| v.as_str()) else {
        return invalid();
    };
    let Some(decoded) =
        base64_url_decode(signature, 64).filter(|bytes| base64_url_encode(bytes) == signature)
    else {
        return invalid();
    };
    let (Some(owner), Some(store)) = (state.recovery_owner(), state.store.as_ref()) else {
        return crate::recovery_authority::fenced_response();
    };
    match store.receive_recovery_report(owner, &page, &decoded).await {
        Ok((challenge, application)) => status(&challenge, application),
        Err(error) => failure(error),
    }
}
