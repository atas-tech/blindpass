// SPDX-License-Identifier: AGPL-3.0-only

use crate::config::Config;
use crate::routes::{self, agents, exchanges, secrets};
use crate::store::Store;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use blindpass_core::secret::SecretBytes;
use serde::Serialize;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

const BROWSER_STATUS_ADOPTED: bool = true;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Option<Store>,
    pub(crate) root_secret: Arc<SecretBytes>,
    pub(crate) agent_jwt_secret: Arc<SecretBytes>,
    pub(crate) agent_auth_providers_json: Option<String>,
    pub(crate) secret_registry_json: Option<String>,
    pub(crate) exchange_policy_json: Option<String>,
    pub(crate) public_url: String,
    pub(crate) ui_base_url: String,
    pub(crate) allowed_origins: Vec<String>,
    pub(crate) test_mode: bool,
    pub(crate) test_seed_token: Option<Arc<SecretBytes>>,
    pub(crate) trusted_proxy_addresses: Vec<IpAddr>,
    pub(crate) request_ttl_seconds: u64,
    pub(crate) submitted_ttl_seconds: u64,
    pub(crate) revoked_ttl_seconds: u64,
    pub(crate) approval_ttl_seconds: u64,
    pub(crate) refresh_token_ttl_seconds: u64,
    pub(crate) agent_token_rate_limit: u32,
    pub(crate) agent_token_rate_window_ms: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Serialize)]
struct ReadinessChecks {
    database: &'static str,
}

#[derive(Serialize)]
struct ReadinessResponse {
    ok: bool,
    checks: ReadinessChecks,
}

#[derive(Serialize)]
struct CapabilitiesResponse {
    api: [&'static str; 2],
    version: &'static str,
    schema_version: u32,
    setup_required: bool,
    features: CapabilitiesFeatures,
}

#[derive(Serialize)]
struct CapabilitiesFeatures {
    browser_status: bool,
}

pub fn build_app(config: Config, store: Option<Store>) -> Router {
    let body_limit_bytes = config.body_limit_bytes();
    let allowed_origins = config
        .allowed_origins()
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect::<Vec<_>>();
    let request_id = HeaderName::from_static("x-request-id");
    let state = AppState {
        store,
        root_secret: Arc::new(SecretBytes::from_slice(config.root_secret())),
        agent_jwt_secret: Arc::new(SecretBytes::from_slice(config.agent_jwt_secret())),
        agent_auth_providers_json: config.agent_auth_providers_json().map(str::to_owned),
        secret_registry_json: config.secret_registry_json().map(str::to_owned),
        exchange_policy_json: config.exchange_policy_json().map(str::to_owned),
        public_url: config.public_url().to_owned(),
        ui_base_url: config.ui_base_url().to_owned(),
        allowed_origins: config.allowed_origins().to_vec(),
        test_mode: config.is_test_mode(),
        test_seed_token: config
            .test_seed_token()
            .map(|token| Arc::new(SecretBytes::from_slice(token))),
        trusted_proxy_addresses: config.trusted_proxy_addresses().to_vec(),
        request_ttl_seconds: config.request_ttl_seconds(),
        submitted_ttl_seconds: config.submitted_ttl_seconds(),
        revoked_ttl_seconds: config.revoked_ttl_seconds(),
        approval_ttl_seconds: config.approval_ttl_seconds(),
        refresh_token_ttl_seconds: config.refresh_token_ttl_seconds(),
        agent_token_rate_limit: config.agent_token_rate_limit(),
        agent_token_rate_window_ms: config.agent_token_rate_window_ms(),
    };

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v3/capabilities", get(capabilities))
        .merge(agents::routes())
        .merge(routes::admin_routes())
        .merge(exchanges::routes())
        .merge(secrets::routes())
        .merge(routes::test_seed_routes(state.test_mode))
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
        .layer(RequestBodyLimitLayer::new(body_limit_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(10),
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(allowed_origins))
                .allow_methods(AllowMethods::list([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ]))
                .allow_headers(AllowHeaders::list([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    HeaderName::from_static("x-agent-api-key"),
                    HeaderName::from_static("x-csrf-token"),
                    HeaderName::from_static("x-blindpass-bootstrap-token"),
                    HeaderName::from_static("x-blindpass-seed-token"),
                    HeaderName::from_static("x-blindpass-test-seed-token"),
                    HeaderName::from_static("idempotency-key"),
                    HeaderName::from_static("if-match"),
                ]))
                .allow_credentials(true),
        )
        .layer(middleware::from_fn(normalize_allowed_preflight))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<_>| {
                    // Deliberately omit URI, headers and bodies. Compatibility
                    // query strings carry signed capabilities.
                    tracing::info_span!("http_request", method = %request.method())
                })
                .on_request(())
                .on_response(|response: &Response, latency: Duration, _span: &tracing::Span| {
                    tracing::info!(status = %response.status(), latency_ms = latency.as_millis());
                }),
        )
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .layer(middleware::from_fn(normalize_compat_errors))
}

async fn normalize_compat_errors(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    let (status, body) = if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({
                "statusCode":413,
                "code":"FST_ERR_CTP_BODY_TOO_LARGE",
                "error":"Payload Too Large",
                "message":"Request body is too large"
            }),
        )
    } else if response.status() == StatusCode::NOT_FOUND
        && !response.headers().contains_key(header::CONTENT_TYPE)
    {
        (
            StatusCode::NOT_FOUND,
            json!({
                "statusCode":404,
                "error":"Not Found",
                "message":format!("Route {}:{} not found", method, path)
            }),
        )
    } else {
        return response;
    };
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    *response.body_mut() = Body::from(
        serde_json::to_vec(&body).expect("compatibility error JSON serialization is infallible"),
    );
    response
}

async fn normalize_allowed_preflight(request: Request, next: Next) -> Response {
    let is_preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
    let mut response = next.run(request).await;
    if is_preflight
        && response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        && response.status().is_success()
    {
        *response.status_mut() = StatusCode::NO_CONTENT;
    }
    response
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    headers
        .entry(HeaderName::from_static("x-content-type-options"))
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(HeaderName::from_static("referrer-policy"))
        .or_insert(HeaderValue::from_static("no-referrer"));
    response
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn readyz(State(state): State<AppState>) -> Response {
    let ready = match state.store.as_ref() {
        Some(store) => store.is_ready().await,
        None => false,
    };
    let payload = ReadinessResponse {
        ok: ready,
        checks: ReadinessChecks {
            database: if ready { "up" } else { "down" },
        },
    };
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(payload)).into_response()
}

async fn capabilities(State(state): State<AppState>) -> Response {
    let setup_required = match state.store.as_ref() {
        Some(store) => match store.has_active_admin().await {
            Ok(has_admin) => !has_admin,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"error":"not_ready"})),
                )
                    .into_response();
            }
        },
        None => true,
    };
    Json(CapabilitiesResponse {
        api: ["compat.v2", "admin.v3"],
        version: env!("CARGO_PKG_VERSION"),
        schema_version: 1,
        setup_required,
        features: CapabilitiesFeatures {
            browser_status: BROWSER_STATUS_ADOPTED,
        },
    })
    .into_response()
}
