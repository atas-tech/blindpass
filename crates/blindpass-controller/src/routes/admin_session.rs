// SPDX-License-Identifier: AGPL-3.0-only

use crate::app::AppState;
use crate::routes::agents::client_ip;
use crate::routes::auth::{constant_equal, hash_api_key, hash_refresh_token, verify_api_key};
use crate::store::{LocalOperator, LocalSession, SessionKind, Store, StoreError};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;

const LOGIN_ACCOUNT_LIMIT: u32 = 10;
const LOGIN_IP_LIMIT: u32 = 30;
const LOGIN_WINDOW_MS: u64 = 60_000;

pub(crate) const SESSION_COOKIE: &str = "bp_session";
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
    /// `desktop` selects the approval app's bearer transport (P04-D3);
    /// absent or `browser` keeps the cookie session.
    #[serde(default)]
    kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopRefreshInput {
    kind: String,
    refresh_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePasswordInput {
    current_password: String,
    new_password: String,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginInput>,
) -> Response {
    match body.kind.as_deref() {
        None | Some("browser") => {}
        Some("desktop") => return desktop_login(&state, &headers, peer, &body).await,
        Some(_) => {
            return admin_error(
                StatusCode::BAD_REQUEST,
                "invalid_session_kind",
                "kind must be browser or desktop",
            );
        }
    }
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
    let operator = match verified_operator(&state, store, &headers, peer, &body).await {
        Ok(operator) => operator,
        Err(response) => return *response,
    };
    let refresh_token = random_token();
    let Some(refresh_hash) = hash_refresh_token(&refresh_token) else {
        return unavailable();
    };
    let session = match store
        .create_browser_session(
            &operator.id,
            &operator.password_hash,
            &refresh_hash,
            state.refresh_token_ttl_seconds,
        )
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

async fn verified_operator(
    state: &AppState,
    store: &Store,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: &LoginInput,
) -> Result<LocalOperator, Box<Response>> {
    let invalid = || {
        Box::new(admin_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid username or password",
        ))
    };
    if body.username.trim().is_empty() || body.password.is_empty() || body.password.len() > 1_024 {
        return Err(invalid());
    }
    let username = body.username.trim().to_ascii_lowercase();
    let account_key = match blindpass_core::custody::sha256(username.as_bytes()) {
        Ok(digest) => digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        Err(_) => return Err(Box::new(unavailable())),
    };
    let ip = client_ip(headers, peer, state);
    for (key, limit) in [
        (format!("operator-login-ip:{ip}"), LOGIN_IP_LIMIT),
        (
            format!("operator-login-account:{account_key}"),
            LOGIN_ACCOUNT_LIMIT,
        ),
    ] {
        let window = match store.consume_rate_limit(&key, limit, LOGIN_WINDOW_MS).await {
            Ok(window) => window,
            Err(_) => return Err(Box::new(unavailable())),
        };
        if window.count > i64::from(limit) {
            let mut response = admin_error(
                StatusCode::TOO_MANY_REQUESTS,
                "login_rate_limited",
                "too many sign-in attempts; try again later",
            );
            if let Ok(value) = HeaderValue::from_str(&window.retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return Err(Box::new(response));
        }
    }
    let operator = match store.operator_by_username(body.username.trim()).await {
        Ok(Some(operator)) if operator.disabled_at_ms.is_none() => operator,
        Ok(_) => return Err(invalid()),
        Err(_) => return Err(Box::new(unavailable())),
    };
    let permit = match state.login_hash_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Err(Box::new(admin_error(
                StatusCode::TOO_MANY_REQUESTS,
                "login_busy",
                "sign-in is busy; try again later",
            )));
        }
    };
    let password = blindpass_core::secret::SecretBytes::from_slice(body.password.as_bytes());
    let encoded_hash = operator.password_hash.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        std::str::from_utf8(password.as_bytes())
            .is_ok_and(|password| verify_api_key(password, &encoded_hash))
    })
    .await
    .map_err(|_| Box::new(unavailable()))?;
    if !verified {
        return Err(invalid());
    }
    Ok(operator)
}

/// P04-D3 desktop login. The approval app is not a browser: it sends no
/// `Origin`, and a request that carries one is refused so page script can
/// never hold these tokens. Nothing is set as a cookie, so there is no
/// ambient credential and no CSRF value. A temporary password is refused
/// without creating a session; it is changed in the console.
async fn desktop_login(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: &LoginInput,
) -> Response {
    if headers.contains_key(header::ORIGIN) {
        return desktop_origin_denied();
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let operator = match verified_operator(state, store, headers, peer, body).await {
        Ok(operator) => operator,
        Err(response) => return *response,
    };
    if operator.must_change_password {
        return admin_error(
            StatusCode::FORBIDDEN,
            "password_change_required",
            "change the temporary password in the console before signing in here",
        );
    }
    let refresh_token = random_token();
    let Some(refresh_hash) = hash_refresh_token(&refresh_token) else {
        return unavailable();
    };
    match store
        .create_session(
            SessionKind::Desktop,
            &operator.id,
            &operator.password_hash,
            &refresh_hash,
            state.refresh_token_ttl_seconds,
        )
        .await
    {
        Ok(Some(session)) => desktop_session_response(&session, &refresh_token),
        Ok(None) => admin_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid username or password",
        ),
        Err(_) => unavailable(),
    }
}

fn desktop_session_response(session: &LocalSession, refresh_token: &str) -> Response {
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "kind": "desktop",
            "operator": operator_body(&session.operator),
            "access_token": session.session_id,
            "refresh_token": refresh_token,
            "expires_at": session.expires_at_ms,
            "must_change_password": session.operator.must_change_password
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn desktop_origin_denied() -> Response {
    admin_error(
        StatusCode::FORBIDDEN,
        "desktop_origin_denied",
        "desktop session credentials are not accepted from a browser origin",
    )
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Whether a request takes the desktop transport: a bearer and no
/// `Origin`. A browser request always carries `Origin` on these routes, so
/// page script presenting a desktop token falls through to the cookie path
/// and is refused there.
pub(crate) fn presents_desktop_bearer(headers: &HeaderMap) -> bool {
    headers.contains_key(header::AUTHORIZATION) && !headers.contains_key(header::ORIGIN)
}

/// Resolve a desktop bearer. The caller has already chosen the desktop
/// transport; a request with an `Origin` is refused, and a browser session id
/// presented as a bearer does not resolve because sessions are kind-scoped.
#[allow(clippy::result_large_err)] // Axum route helpers return its response type directly.
pub(crate) async fn desktop_session(
    store: Option<&Store>,
    headers: &HeaderMap,
) -> Result<LocalSession, Response> {
    if headers.contains_key(header::ORIGIN) {
        return Err(desktop_origin_denied());
    }
    let expired = || {
        admin_error(
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "the desktop session is expired or revoked",
        )
    };
    let Some(store) = store else {
        return Err(unavailable());
    };
    let Some(token) = bearer_token(headers) else {
        return Err(admin_error(
            StatusCode::UNAUTHORIZED,
            "session_required",
            "an active desktop session is required",
        ));
    };
    match store.touch_session(SessionKind::Desktop, token).await {
        Ok(true) => {}
        Ok(false) => return Err(expired()),
        Err(StoreError::InvalidInput(_)) => return Err(expired()),
        Err(_) => return Err(unavailable()),
    }
    match store.session_by_id(SessionKind::Desktop, token).await {
        Ok(Some(session)) => Ok(session),
        Ok(None) => Err(expired()),
        Err(StoreError::InvalidInput(_)) => Err(expired()),
        Err(_) => Err(unavailable()),
    }
}

fn desktop_session_body(session: &LocalSession) -> Value {
    json!({
        "kind": "desktop",
        "operator": operator_body(&session.operator),
        "expires_at": session.expires_at_ms,
        "must_change_password": session.operator.must_change_password
    })
}

async fn desktop_refresh(state: &AppState, body: &[u8]) -> Response {
    let Ok(input) = serde_json::from_slice::<DesktopRefreshInput>(body) else {
        return admin_error(
            StatusCode::FORBIDDEN,
            "origin_denied",
            "origin is not allowed",
        );
    };
    if input.kind != "desktop" || input.refresh_token.is_empty() {
        return admin_error(
            StatusCode::FORBIDDEN,
            "origin_denied",
            "origin is not allowed",
        );
    }
    let Some(store) = state.store.as_ref() else {
        return unavailable();
    };
    let Some(refresh_hash) = hash_refresh_token(&input.refresh_token) else {
        return unavailable();
    };
    let next_refresh = random_token();
    let Some(next_hash) = hash_refresh_token(&next_refresh) else {
        return unavailable();
    };
    match store
        .rotate_session(
            SessionKind::Desktop,
            &refresh_hash,
            &next_hash,
            state.refresh_token_ttl_seconds,
        )
        .await
    {
        Ok(Some(next)) if !next.operator.must_change_password => {
            desktop_session_response(&next, &next_refresh)
        }
        Ok(Some(next)) => {
            let _ = store
                .revoke_session(SessionKind::Desktop, &next.session_id)
                .await;
            admin_error(
                StatusCode::FORBIDDEN,
                "password_change_required",
                "change the temporary password in the console before signing in here",
            )
        }
        Ok(None) => admin_error(
            StatusCode::UNAUTHORIZED,
            "refresh_invalid",
            "the refresh credential is expired, revoked, or replayed",
        ),
        Err(_) => unavailable(),
    }
}

async fn current_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if presents_desktop_bearer(&headers) {
        return match desktop_session(state.store.as_ref(), &headers).await {
            Ok(session) => (StatusCode::OK, Json(desktop_session_body(&session))).into_response(),
            Err(response) => response,
        };
    }
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
    if presents_desktop_bearer(&headers) {
        let session = match desktop_session(state.store.as_ref(), &headers).await {
            Ok(session) => session,
            Err(response) => return response,
        };
        let Some(store) = state.store.as_ref() else {
            return unavailable();
        };
        return match store
            .revoke_session(SessionKind::Desktop, &session.session_id)
            .await
        {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(_) => unavailable(),
        };
    }
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

async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Browsers always send Origin on this POST; the desktop app never does
    // and presents its refresh token in the body instead of a cookie.
    if !headers.contains_key(header::ORIGIN) {
        return desktop_refresh(&state, &body).await;
    }
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
        .change_operator_password(
            &session.operator.id,
            &session.session_id,
            &session.operator.password_hash,
            &password_hash,
        )
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

/// Routes an operator may use while `must_change_password` is set:
/// reading and ending the session, refreshing it and changing the
/// password. Every other matched `/api/v3/admin/` route is refused so a
/// temporary password from bootstrap, reset or a test fixture cannot be
/// used for administration.
const PASSWORD_CHANGE_EXEMPT_ROUTES: &[&str] = &[
    "/api/v3/admin/bootstrap",
    "/api/v3/admin/session",
    "/api/v3/admin/session/login",
    "/api/v3/admin/session/logout",
    "/api/v3/admin/session/refresh",
    "/api/v3/admin/session/change-password",
    "/api/v3/admin/test/seed",
];

pub(crate) async fn forced_password_change_gate(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !path.starts_with("/api/v3/admin/") || PASSWORD_CHANGE_EXEMPT_ROUTES.contains(&path) {
        return next.run(request).await;
    }
    if let (Some(store), Some(session_id)) = (
        state.store.as_ref(),
        cookie(request.headers(), SESSION_COOKIE),
    ) {
        match store.browser_session_by_id(&session_id).await {
            Ok(Some(session)) if session.operator.must_change_password => {
                return admin_error(
                    StatusCode::FORBIDDEN,
                    "password_change_required",
                    "change the temporary password before using other administration routes",
                );
            }
            Ok(_) => {}
            Err(_) => return unavailable(),
        }
    }
    next.run(request).await
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

pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
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
