// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::admin_session::{authenticated_session, valid_origin, valid_session_csrf};
use crate::store::LocalSession;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v3/admin/policy", get(get_policy).put(replace_policy))
        .route("/api/v3/admin/policy/validate", post(validate_policy_route))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocumentInput {
    #[serde(alias = "secretRegistry")]
    secret_registry: Vec<Value>,
    #[serde(alias = "exchangePolicyRules")]
    #[serde(alias = "exchangePolicy")]
    exchange_policy: Vec<Value>,
}

impl PolicyDocumentInput {
    fn to_value(&self) -> Value {
        json!({
            "secret_registry": self.secret_registry,
            "exchange_policy": self.exchange_policy
        })
    }
}

pub(crate) fn validated_seed_policy_json(value: Value) -> Option<String> {
    let document: PolicyDocumentInput = serde_json::from_value(value).ok()?;
    if !validate_policy(&document).is_empty() {
        return None;
    }
    serde_json::to_string(&document.to_value()).ok()
}

async fn get_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match authenticated_session(state.store.as_ref(), &headers).await {
        Some(session) => session,
        None => {
            return admin_error(
                StatusCode::UNAUTHORIZED,
                "session_required",
                "an active local session is required",
            );
        }
    };
    let _ = session;
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store.policy_document().await {
        Ok(Some(record)) => match serde_json::from_str::<Value>(&record.document_json) {
            Ok(policy) => Json(json!({"version":record.version,"policy":policy})).into_response(),
            Err(_) => unavailable(),
        },
        Ok(None) => {
            let secret_registry = parse_config_array(state.secret_registry_json.as_deref());
            let exchange_policy = parse_config_array(state.exchange_policy_json.as_deref());
            Json(json!({
                "version":1,
                "policy":{"secret_registry":secret_registry,"exchange_policy":exchange_policy}
            }))
            .into_response()
        }
        Err(_) => unavailable(),
    }
}

async fn replace_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PolicyDocumentInput>,
) -> Response {
    let session = match require_admin(&state, &headers, true).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let errors = validate_policy(&body);
    if !errors.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_policy","message":"policy document is invalid","issues":errors})),
        )
            .into_response();
    }
    let Some(expected_version) = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_version)
    else {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "if_match_required",
            "If-Match must contain the current policy version",
        );
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let document = body.to_value();
    let document_json = match serde_json::to_string(&document) {
        Ok(json) => json,
        Err(_) => return unavailable(),
    };
    match store
        .replace_policy_document(expected_version, &document_json, &session.operator.id)
        .await
    {
        Ok(Some(version)) => Json(json!({"version":version,"policy":document})).into_response(),
        Ok(None) => admin_error(
            StatusCode::CONFLICT,
            "policy_version_conflict",
            "policy changed; reload before replacing it",
        ),
        Err(_) => unavailable(),
    }
}

async fn validate_policy_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PolicyDocumentInput>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, true).await {
        return *response;
    }
    let errors = validate_policy(&body);
    Json(json!({"valid":errors.is_empty(),"errors":errors})).into_response()
}

async fn require_admin(
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
    if session.operator.role != "admin" {
        return Err(Box::new(admin_error(
            StatusCode::FORBIDDEN,
            "role_denied",
            "administrator role is required",
        )));
    }
    if unsafe_method && (!valid_origin(state, headers) || !valid_session_csrf(headers, &session)) {
        return Err(Box::new(admin_error(
            StatusCode::FORBIDDEN,
            "csrf_or_origin_denied",
            "origin or CSRF validation failed",
        )));
    }
    Ok(session)
}

fn validate_policy(document: &PolicyDocumentInput) -> Vec<String> {
    let mut errors = Vec::new();
    if document.secret_registry.len() > 2_000 {
        errors.push("secret_registry: too many entries".to_owned());
    }
    if document.exchange_policy.len() > 5_000 {
        errors.push("exchange_policy: too many rules".to_owned());
    }
    let mut secret_names = BTreeSet::new();
    for (index, entry) in document.secret_registry.iter().enumerate() {
        let name = alias_string(entry, &["secretName", "secret_name"]);
        let classification = alias_string(entry, &["classification"]);
        if name.as_deref().is_none_or(str::is_empty) {
            errors.push(format!("secret_registry[{index}].secretName: required"));
        } else if !secret_names.insert(name.unwrap_or_default()) {
            errors.push(format!("secret_registry[{index}].secretName: duplicate"));
        }
        if classification.as_deref().is_none_or(str::is_empty) {
            errors.push(format!("secret_registry[{index}].classification: required"));
        }
    }
    let mut rule_ids = BTreeSet::new();
    for (index, rule) in document.exchange_policy.iter().enumerate() {
        let rule_id = alias_string(rule, &["ruleId", "rule_id"]);
        let secret_name = alias_string(rule, &["secretName", "secret_name"]);
        if rule_id.as_deref().is_none_or(str::is_empty) {
            errors.push(format!("exchange_policy[{index}].ruleId: required"));
        } else if !rule_ids.insert(rule_id.unwrap_or_default()) {
            errors.push(format!("exchange_policy[{index}].ruleId: duplicate"));
        }
        if secret_name.as_deref().is_none_or(str::is_empty) {
            errors.push(format!("exchange_policy[{index}].secretName: required"));
        } else if !secret_name
            .as_ref()
            .is_some_and(|name| secret_names.contains(name))
        {
            errors.push(format!(
                "exchange_policy[{index}].secretName: unknown registry entry"
            ));
        }
        if let Some(mode) = rule.get("mode").and_then(Value::as_str)
            && !matches!(mode, "allow" | "pending_approval" | "deny")
        {
            errors.push(format!("exchange_policy[{index}].mode: unsupported value"));
        }
        for key in [
            "requesterIds",
            "requester_ids",
            "fulfillerIds",
            "fulfiller_ids",
            "approverIds",
            "approver_ids",
            "requesterRings",
            "requester_rings",
            "fulfillerRings",
            "fulfiller_rings",
            "approverRings",
            "approver_rings",
            "purposes",
            "allowedRings",
            "allowed_rings",
        ] {
            if let Some(value) = rule.get(key)
                && !value
                    .as_array()
                    .is_some_and(|values| values.iter().all(Value::is_string))
            {
                errors.push(format!(
                    "exchange_policy[{index}].{key}: must be an array of strings"
                ));
            }
        }
        for key in ["sameRing", "same_ring"] {
            if let Some(value) = rule.get(key)
                && !value.is_boolean()
            {
                errors.push(format!("exchange_policy[{index}].{key}: must be a boolean"));
            }
        }
    }
    errors
}

fn alias_string(value: &Value, aliases: &[&str]) -> Option<String> {
    aliases
        .iter()
        .find_map(|alias| value.get(*alias).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn parse_config_array(source: Option<&str>) -> Vec<Value> {
    source
        .and_then(|source| serde_json::from_str(source).ok())
        .unwrap_or_default()
}

fn parse_version(value: &str) -> Option<i64> {
    value
        .trim()
        .trim_matches('"')
        .parse::<i64>()
        .ok()
        .filter(|v| *v > 0)
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
