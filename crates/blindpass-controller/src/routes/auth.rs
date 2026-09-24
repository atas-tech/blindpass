// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::store::{AgentCredential, Store};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

const AGENT_ACCESS_TTL_SECONDS: u64 = 15 * 60;

#[derive(Debug)]
pub(crate) enum AuthError {
    MissingBearer,
    InvalidToken,
    InvalidApiKey,
    ProviderUnavailable,
    InvalidClaims,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingBearer => "Missing bearer token",
            Self::InvalidToken => "Invalid token",
            Self::InvalidApiKey => "Invalid agent API key",
            Self::ProviderUnavailable => "Gateway JWK unavailable",
            Self::InvalidClaims => "Invalid gateway claims",
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WorkloadIdentity {
    pub(crate) sub: String,
    pub(crate) role: String,
    pub(crate) workspace_id: Option<String>,
    pub(crate) workload_mode: Option<String>,
    pub(crate) admin: Option<bool>,
    pub(crate) auth_provider: Option<String>,
    pub(crate) spiffe_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct UserIdentity {
    pub(crate) sub: String,
    pub(crate) role: String,
    pub(crate) workspace_id: String,
    pub(crate) sid: Option<String>,
    pub(crate) force_password_change: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenClaims {
    sub: String,
    role: String,
    workspace_id: Option<String>,
    workload_mode: Option<String>,
    admin: Option<bool>,
    auth_provider: Option<String>,
    spiffe_id: Option<String>,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    sid: Option<String>,
    force_password_change: Option<bool>,
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then_some(token.trim())
}

pub(crate) fn api_key_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        && let Some((scheme, token)) = value.split_once(' ')
        && scheme.eq_ignore_ascii_case("bearer")
        && token.trim().starts_with("ak_")
    {
        return Some(token.trim().to_owned());
    }
    headers
        .get("x-agent-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(crate) fn parse_agent_key_id(api_key: &str) -> Option<&str> {
    let value = api_key.strip_prefix("ak_")?;
    let (id, secret) = value.split_once('_')?;
    if id.len() != 36
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() || byte == b'-')
        || secret.len() < 20
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return None;
    }
    Some(id)
}

pub(crate) fn hash_api_key(api_key: &str) -> Result<String, &'static str> {
    let mut salt_bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|_| "could not encode agent key salt")?;
    Argon2::default()
        .hash_password(api_key.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "could not hash agent key")
}

pub(crate) fn verify_api_key(api_key: &str, encoded_hash: &str) -> bool {
    PasswordHash::new(encoded_hash).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(api_key.as_bytes(), &hash)
            .is_ok()
    })
}

pub(crate) fn new_api_key(agent_row_id: &str) -> String {
    let mut secret = [0_u8; 24];
    OsRng.fill_bytes(&mut secret);
    format!("ak_{agent_row_id}_{}", URL_SAFE_NO_PAD.encode(secret))
}

pub(crate) fn hash_refresh_token(token: &str) -> Option<String> {
    blindpass_core::custody::sha256(token.as_bytes())
        .ok()
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn mint_agent_token(
    state: &AppState,
    agent: &AgentCredential,
    tenant_id: &str,
) -> Result<(String, u64), &'static str> {
    let now = current_seconds();
    let expiry = now + AGENT_ACCESS_TTL_SECONDS;
    let claims = TokenClaims {
        sub: agent.agent_id.clone(),
        role: "gateway".to_owned(),
        workspace_id: Some(tenant_id.to_owned()),
        workload_mode: Some("hosted".to_owned()),
        admin: None,
        auth_provider: None,
        spiffe_id: None,
        iss: "sps".to_owned(),
        aud: "sps-agent".to_owned(),
        iat: now,
        exp: expiry,
        sid: None,
        force_password_change: None,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.agent_jwt_secret.as_bytes()),
    )
    .map(|token| (token, expiry))
    .map_err(|_| "agent token could not be minted")
}

pub(crate) fn mint_seed_admin_token(
    state: &AppState,
    operator_id: &str,
    tenant_id: &str,
) -> Result<String, &'static str> {
    let now = current_seconds();
    let claims = TokenClaims {
        sub: operator_id.to_owned(),
        role: "workspace_admin".to_owned(),
        workspace_id: Some(tenant_id.to_owned()),
        workload_mode: None,
        admin: None,
        auth_provider: None,
        spiffe_id: None,
        iss: "sps".to_owned(),
        aud: "sps-user".to_owned(),
        iat: now,
        exp: now + 15 * 60,
        sid: Some(format!("test-{operator_id}")),
        force_password_change: Some(false),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.agent_jwt_secret.as_bytes()),
    )
    .map_err(|_| "test administrator token could not be minted")
}

pub(crate) fn authenticate_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserIdentity, AuthError> {
    let token = bearer_token(headers).ok_or(AuthError::MissingBearer)?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["sps"]);
    validation.set_audience(&["sps-user"]);
    let decoded = decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(state.agent_jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AuthError::InvalidToken)?;
    let claims = decoded.claims;
    let workspace_id = claims.workspace_id.ok_or(AuthError::InvalidToken)?;
    Ok(UserIdentity {
        sub: claims.sub,
        role: claims.role,
        workspace_id,
        sid: claims.sid,
        force_password_change: claims.force_password_change.unwrap_or(false),
    })
}

pub(crate) async fn authenticate_workload(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<WorkloadIdentity, AuthError> {
    let token = bearer_token(headers).ok_or(AuthError::MissingBearer)?;
    if let Some(identity) = verify_agent_token(state, token) {
        return Ok(identity);
    }
    verify_external_token(state, token)
}

fn verify_agent_token(state: &AppState, token: &str) -> Option<WorkloadIdentity> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["sps"]);
    validation.set_audience(&["sps-agent"]);
    let claims = decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(state.agent_jwt_secret.as_bytes()),
        &validation,
    )
    .ok()?
    .claims;
    if claims.role != "gateway" {
        return None;
    }
    Some(WorkloadIdentity {
        sub: claims.sub,
        role: claims.role,
        workspace_id: claims.workspace_id,
        workload_mode: claims.workload_mode,
        admin: claims.admin,
        auth_provider: claims.auth_provider,
        spiffe_id: claims.spiffe_id,
    })
}

fn verify_external_token(state: &AppState, token: &str) -> Result<WorkloadIdentity, AuthError> {
    let Some(raw_providers) = state.agent_auth_providers_json.as_deref() else {
        return Err(AuthError::InvalidToken);
    };
    let providers =
        serde_json::from_str::<Value>(raw_providers).map_err(|_| AuthError::ProviderUnavailable)?;
    let providers = providers.as_array().ok_or(AuthError::ProviderUnavailable)?;
    let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
    for provider in providers {
        let Some(path) = value_string(provider, &["jwks_file", "jwksFile"]) else {
            // URL providers are rejected by config validation until a bounded
            // HTTPS JWKS transport is configured; never silently trust an
            // unverified token.
            continue;
        };
        let jwks_text =
            std::fs::read_to_string(path).map_err(|_| AuthError::ProviderUnavailable)?;
        let jwks = serde_json::from_str::<JwkSet>(&jwks_text)
            .map_err(|_| AuthError::ProviderUnavailable)?;
        let Some(kid) = header.kid.as_deref() else {
            continue;
        };
        let Some(jwk) = jwks.find(kid) else {
            continue;
        };
        if !jwk_algorithm_matches(&jwk.algorithm, header.alg) {
            continue;
        }
        let key = DecodingKey::from_jwk(jwk).map_err(|_| AuthError::ProviderUnavailable)?;
        let mut validation = Validation::new(header.alg);
        let issuers = value_list(provider, &["issuers", "issuer"]);
        let audiences = value_list(provider, &["audiences", "audience"]);
        if !issuers.is_empty() {
            let values = issuers.iter().map(String::as_str).collect::<Vec<_>>();
            validation.set_issuer(&values);
        }
        if !audiences.is_empty() {
            let values = audiences.iter().map(String::as_str).collect::<Vec<_>>();
            validation.set_audience(&values);
        }
        let value = decode::<Value>(token, &key, &validation)
            .map_err(|_| AuthError::InvalidToken)?
            .claims;
        let sub = value
            .get("sub")
            .and_then(Value::as_str)
            .filter(|sub| !sub.trim().is_empty())
            .ok_or(AuthError::InvalidClaims)?;
        let role = value
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if role != "gateway" {
            return Err(AuthError::InvalidClaims);
        }
        let spiffe_id = value
            .get("spiffe_id")
            .and_then(Value::as_str)
            .or_else(|| sub.starts_with("spiffe://").then_some(sub))
            .map(str::to_owned);
        if value_bool(provider, &["require_spiffe", "requireSpiffe"]) && spiffe_id.is_none() {
            return Err(AuthError::InvalidClaims);
        }
        return Ok(WorkloadIdentity {
            sub: sub.to_owned(),
            role: role.to_owned(),
            workspace_id: value
                .get("workspace_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            workload_mode: value
                .get("workload_mode")
                .and_then(Value::as_str)
                .map(str::to_owned),
            admin: value.get("admin").and_then(Value::as_bool),
            auth_provider: value_string(provider, &["name"]),
            spiffe_id,
        });
    }
    Err(AuthError::InvalidToken)
}

fn jwk_algorithm_matches(parameters: &AlgorithmParameters, algorithm: Algorithm) -> bool {
    match parameters {
        AlgorithmParameters::RSA(_) => matches!(
            algorithm,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
        ),
        AlgorithmParameters::EllipticCurve(_) => {
            matches!(algorithm, Algorithm::ES256 | Algorithm::ES384)
        }
        AlgorithmParameters::OctetKeyPair(_) => algorithm == Algorithm::EdDSA,
        AlgorithmParameters::OctetKey(_) => false,
    }
}

pub(crate) async fn authenticate_api_key(
    store: &Store,
    headers: &HeaderMap,
) -> Result<AgentCredential, AuthError> {
    let api_key = api_key_from_headers(headers).ok_or(AuthError::MissingBearer)?;
    let id = parse_agent_key_id(&api_key).ok_or(AuthError::InvalidApiKey)?;
    let agent = store
        .agent_by_key_id(id)
        .await
        .map_err(|_| AuthError::InvalidApiKey)?
        .filter(|agent| agent.status == "active")
        .ok_or(AuthError::InvalidApiKey)?;
    if !verify_api_key(&api_key, &agent.api_key_hash) {
        return Err(AuthError::InvalidApiKey);
    }
    Ok(agent)
}

#[derive(Deserialize)]
pub(crate) struct SeedRequest {
    pub(crate) agents: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct SeedResponse {
    pub(crate) access_token: String,
    pub(crate) workspace_id: String,
    pub(crate) user_id: String,
    pub(crate) agents: std::collections::BTreeMap<String, String>,
}

pub(crate) async fn test_seed(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<SeedRequest>,
) -> Result<axum::Json<SeedResponse>, (axum::http::StatusCode, axum::Json<Value>)> {
    let Some(store) = state.store.as_ref() else {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error":"not_ready"})),
        ));
    };
    let valid = headers
        .get("x-blindpass-seed-token")
        .and_then(|header| header.to_str().ok())
        .zip(state.test_seed_token.as_deref())
        .is_some_and(|(provided, expected)| {
            constant_equal(provided.as_bytes(), expected.as_bytes())
        });
    if !state.test_mode || !valid {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error":"not_found"})),
        ));
    }
    if body.agents.is_empty() || body.agents.len() > 64 {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error":"invalid_agents"})),
        ));
    }
    let mut agents = std::collections::BTreeMap::new();
    for agent_id in body.agents {
        let row_id = random_uuid();
        let api_key = new_api_key(&row_id);
        let hash = hash_api_key(&api_key).map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error":"seed_failed"})),
            )
        })?;
        let created = store
            .create_agent_with_id(
                &row_id,
                &agent_id,
                &format!("{agent_id} Display"),
                ring_from_id(&agent_id),
                &hash,
            )
            .await
            .map_err(|_| {
                (
                    axum::http::StatusCode::CONFLICT,
                    axum::Json(serde_json::json!({"error":"seed_failed"})),
                )
            })?;
        let _ = created;
        agents.insert(agent_id, api_key);
    }
    let user_id = random_uuid();
    let access_token =
        mint_seed_admin_token(&state, &user_id, store.tenant_id()).map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error":"seed_failed"})),
            )
        })?;
    Ok(axum::Json(SeedResponse {
        access_token,
        workspace_id: store.tenant_id().to_owned(),
        user_id,
        agents,
    }))
}

pub(crate) fn current_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn value_string(value: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .map(str::to_owned)
}

fn value_list(value: &Value, names: &[&str]) -> Vec<String> {
    for name in names {
        if let Some(values) = value.get(*name).and_then(Value::as_array) {
            return values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
        }
        if let Some(value) = value.get(*name).and_then(Value::as_str) {
            return value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect();
        }
    }
    Vec::new()
}

fn value_bool(value: &Value, names: &[&str]) -> bool {
    names.iter().any(|name| {
        value.get(*name).is_some_and(|value| {
            value.as_bool().unwrap_or(false)
                || value.as_str().is_some_and(|value| {
                    matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
                })
        })
    })
}

fn ring_from_id(agent_id: &str) -> Option<&str> {
    agent_id.split_once("/ring/")?.1.split('/').next()
}

fn random_uuid() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let raw = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..]
    )
}

pub(crate) fn constant_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}
