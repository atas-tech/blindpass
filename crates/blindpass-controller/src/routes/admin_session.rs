// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::auth::{constant_equal, hash_api_key, hash_refresh_token, verify_api_key};
use crate::store::{LocalOperator, LocalSession, Store};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};

const SESSION_COOKIE: &str = "bp_session";
const REFRESH_COOKIE: &str = "bp_refresh";
const CSRF_COOKIE: &str = "bp_csrf";
const SESSION_IDLE_SECONDS: u64 = 12 * 60 * 60;
const REFRESH_COOKIE_PATH: &str = "/api/v3/admin/session/refresh";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v3/admin/session/login", post(login))
        .route("/api/v3/admin/session/logout", post(logout))
        .route("/api/v3/admin/session/refresh", post(refresh))
        .route("/api/v3/admin/session", get(current_session))
        .route(
            "/api/v3/admin/session/change-password",
            post(change_password),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginInput {
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePasswordInput {
    current_password: String,
    new_password: String,
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginInput>,
) -> Response {
    if !valid_origin(&state, &headers) || !valid_pre_session_csrf(&headers) {
        return admin_error(
            StatusCode::FORBIDDEN,
            "origin_or_csrf_denied",
            "origin or pre-session CSRF check failed",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    if body.username.trim().is_empty() || body.password.is_empty() {
        return admin_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid username or password",
        );
    }
    let operator = match store.operator_by_username(body.username.trim()).await {
        Ok(Some(operator)) if operator.disabled_at_ms.is_none() => operator,
        Ok(_) => {
            return admin_error(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "invalid username or password",
            );
        }
        Err(_) => return unavailable(),
    };
    if !verify_api_key(&body.password, &operator.password_hash) {
        return admin_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid username or password",
        );
    }
    let refresh_token = random_token();
    let Some(refresh_hash) = hash_refresh_token(&refresh_token) else {
        return unavailable();
    };
    let session = match store
        .create_browser_session(&operator.id, &refresh_hash, state.refresh_token_ttl_seconds)
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => {
            return admin_error(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "invalid username or password",
            );
        }
        Err(_) => return unavailable(),
    };
    session_response(StatusCode::OK, &state, session, Some(&refresh_token))
}

async fn current_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let Some(session_id) = cookie(&headers, SESSION_COOKIE) else {
        return admin_error(
            StatusCode::UNAUTHORIZED,
            "session_required",
            "an active local session is required",
        );
    };
    if !store
        .touch_browser_session(&session_id)
        .await
        .unwrap_or(false)
    {
        return admin_error(
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "the local session is expired or revoked",
        );
    }
    match store.browser_session_by_id(&session_id).await {
        Ok(Some(session)) => (StatusCode::OK, Json(session_body(&session))).into_response(),
        Ok(None) => admin_error(
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "the local session is expired or revoked",
        ),
        Err(_) => unavailable(),
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !valid_origin(&state, &headers) {
        return admin_error(
            StatusCode::FORBIDDEN,
            "origin_denied",
            "origin is not allowed",
        );
    }
    let Some(session) = authenticated_session(state.store.as_ref(), &headers).await else {
        return admin_error(
            StatusCode::UNAUTHORIZED,
            "session_required",
            "an active local session is required",
        );
    };
    if !valid_session_csrf(&headers, &session) {
        return admin_error(
            StatusCode::FORBIDDEN,
            "csrf_denied",
            "CSRF validation failed",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    if store
        .revoke_browser_session(&session.session_id)
        .await
        .is_err()
    {
        return unavailable();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_cookies(&state, response.headers_mut());
    response
}

async fn refresh(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !valid_origin(&state, &headers) {
        return admin_error(
            StatusCode::FORBIDDEN,
            "origin_denied",
            "origin is not allowed",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let Some(refresh_token) = cookie(&headers, REFRESH_COOKIE) else {
        return admin_error(
            StatusCode::UNAUTHORIZED,
            "refresh_required",
            "an active refresh credential is required",
        );
    };
    let Some(refresh_hash) = hash_refresh_token(&refresh_token) else {
        return unavailable();
    };
    let session = match store.browser_session_for_refresh_hash(&refresh_hash).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return admin_error(
                StatusCode::UNAUTHORIZED,
                "refresh_invalid",
                "the refresh credential is invalid",
            );
        }
        Err(_) => return unavailable(),
    };
    if !valid_session_csrf(&headers, &session) {
        return admin_error(
            StatusCode::FORBIDDEN,
            "csrf_denied",
            "CSRF validation failed",
        );
    }
    let next_refresh = random_token();
    let Some(next_hash) = hash_refresh_token(&next_refresh) else {
        return unavailable();
    };
    match store
        .rotate_browser_session(&refresh_hash, &next_hash, state.refresh_token_ttl_seconds)
        .await
    {
        Ok(Some(next)) => session_response(StatusCode::OK, &state, next, Some(&next_refresh)),
        Ok(None) => admin_error(
            StatusCode::UNAUTHORIZED,
            "refresh_invalid",
            "the refresh credential is expired, revoked, or replayed",
        ),
        Err(_) => unavailable(),
    }
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordInput>,
) -> Response {
    if !valid_origin(&state, &headers) {
        return admin_error(
            StatusCode::FORBIDDEN,
            "origin_denied",
            "origin is not allowed",
        );
    }
    let Some(session) = authenticated_session(state.store.as_ref(), &headers).await else {
        return admin_error(
            StatusCode::UNAUTHORIZED,
            "session_required",
            "an active local session is required",
        );
    };
    if !valid_session_csrf(&headers, &session) {
        return admin_error(
            StatusCode::FORBIDDEN,
            "csrf_denied",
            "CSRF validation failed",
        );
    }
    if body.new_password.len() < 12 || body.new_password.len() > 1_024 {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "invalid_password",
            "new password does not meet the length requirements",
        );
    }
    if !verify_api_key(&body.current_password, &session.operator.password_hash) {
        return admin_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "current password is incorrect",
        );
    }
    let password_hash = match hash_api_key(&body.new_password) {
        Ok(hash) => hash,
        Err(_) => return unavailable(),
    };
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    match store
        .change_operator_password(&session.operator.id, &session.session_id, &password_hash)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => admin_error(
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "the operator is no longer active",
        ),
        Err(_) => unavailable(),
    }
}

pub(crate) async fn authenticated_session(
    store: Option<&Store>,
    headers: &HeaderMap,
) -> Option<LocalSession> {
    let store = store?;
    let session_id = cookie(headers, SESSION_COOKIE)?;
    if !store.touch_browser_session(&session_id).await.ok()? {
        return None;
    }
    store.browser_session_by_id(&session_id).await.ok()?
}

pub(crate) fn session_response(
    status: StatusCode,
    state: &AppState,
    session: LocalSession,
    refresh_token: Option<&str>,
) -> Response {
    let mut response = (status, Json(session_body(&session))).into_response();
    set_session_cookies(state, response.headers_mut(), &session, refresh_token);
    response
}

fn session_body(session: &LocalSession) -> Value {
    json!({
        "operator": operator_body(&session.operator),
        "csrf_token": session.csrf_secret,
        "expires_at": session.expires_at_ms,
        "must_change_password": session.operator.must_change_password
    })
}

pub(crate) fn operator_body(operator: &LocalOperator) -> Value {
    json!({
        "id": operator.id,
        "username": operator.username,
        "display_name": operator.display_name,
        "role": operator.role,
        "disabled_at": operator.disabled_at_ms
    })
}

fn set_session_cookies(
    state: &AppState,
    headers: &mut HeaderMap,
    session: &LocalSession,
    refresh_token: Option<&str>,
) {
    let secure = if state.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let session_cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; Max-Age={SESSION_IDLE_SECONDS}; HttpOnly; SameSite=Strict{secure}",
        session.session_id
    );
    append_cookie(headers, &session_cookie);
    if let Some(refresh_token) = refresh_token {
        let refresh_cookie = format!(
            "{REFRESH_COOKIE}={refresh_token}; Path={REFRESH_COOKIE_PATH}; Max-Age={}; HttpOnly; SameSite=Strict{secure}",
            state.refresh_token_ttl_seconds
        );
        append_cookie(headers, &refresh_cookie);
    }
    let csrf_cookie = format!(
        "{CSRF_COOKIE}={}; Path=/; Max-Age={}; SameSite=Strict{secure}",
        session.csrf_secret, state.refresh_token_ttl_seconds
    );
    append_cookie(headers, &csrf_cookie);
}

fn clear_cookies(state: &AppState, headers: &mut HeaderMap) {
    let secure = if state.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    append_cookie(
        headers,
        &format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{secure}"),
    );
    append_cookie(
        headers,
        &format!(
            "{REFRESH_COOKIE}=; Path={REFRESH_COOKIE_PATH}; Max-Age=0; HttpOnly; SameSite=Strict{secure}"
        ),
    );
    append_cookie(
        headers,
        &format!("{CSRF_COOKIE}=; Path=/; Max-Age=0; SameSite=Strict{secure}"),
    );
}

fn append_cookie(headers: &mut HeaderMap, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub(crate) fn valid_origin(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    origin == state.public_url
        || origin == state.ui_base_url
        || state
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
}

fn valid_pre_session_csrf(headers: &HeaderMap) -> bool {
    let Some(header_token) = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(cookie_token) = cookie(headers, CSRF_COOKIE) else {
        return false;
    };
    constant_equal(header_token.as_bytes(), cookie_token.as_bytes())
}

pub(crate) fn valid_session_csrf(headers: &HeaderMap, session: &LocalSession) -> bool {
    let Some(header_token) = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(cookie_token) = cookie(headers, CSRF_COOKIE) else {
        return false;
    };
    constant_equal(header_token.as_bytes(), session.csrf_secret.as_bytes())
        && constant_equal(cookie_token.as_bytes(), session.csrf_secret.as_bytes())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key.trim() == name).then(|| value.trim().to_owned()))
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
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
