// SPDX-License-Identifier: AGPL-3.0-only

use crate::config::Config;
use crate::routes::{self, agents, exchanges, secrets};
use crate::store::{FleetSigner, SCHEMA_VERSION, Store, StoreError};
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use blindpass_core::secret::SecretBytes;
use blindpass_core::signing::base64_url_encode;
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use serde::Serialize;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

const BROWSER_STATUS_ADOPTED: bool = true;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Option<Store>,
    pub(crate) root_secret: Arc<SecretBytes>,
    pub(crate) agent_jwt_secret: Arc<SecretBytes>,
    pub(crate) node_keys: Arc<routes::node::NodeChannelKeys>,
    pub(crate) issuer_keypair: Option<Arc<Ed25519KeyPair>>,
    pub(crate) issuer_key_id: Option<String>,
    pub(crate) agent_auth_providers_json: Option<String>,
    pub(crate) secret_registry_json: Option<String>,
    pub(crate) exchange_policy_json: Option<String>,
    pub(crate) public_url: String,
    pub(crate) ui_base_url: String,
    pub(crate) allowed_origins: Vec<String>,
    pub(crate) test_mode: bool,
    pub(crate) test_seed_token: Option<Arc<SecretBytes>>,
    pub(crate) trusted_proxy_peers: Vec<crate::proxy::TrustedProxy>,
    pub(crate) proxy_required: bool,
    pub(crate) proxy_authorities: Vec<String>,
    pub(crate) tls_enabled: bool,
    pub(crate) request_ttl_seconds: u64,
    pub(crate) submitted_ttl_seconds: u64,
    pub(crate) revoked_ttl_seconds: u64,
    pub(crate) approval_ttl_seconds: u64,
    pub(crate) refresh_token_ttl_seconds: u64,
    pub(crate) agent_token_rate_limit: u32,
    pub(crate) agent_request_rate_limit: u32,
    pub(crate) agent_exchange_rate_limit: u32,
    pub(crate) agent_token_rate_window_ms: u64,
    pub(crate) agent_rate_window_ms: u64,
    pub(crate) abuse_limits: crate::config::AbuseLimits,
    pub(crate) session_absolute_seconds: u64,
    pub(crate) login_hash_slots: Arc<Semaphore>,
    ownership: Option<Arc<crate::recovery_authority::ProcessOwnership>>,
    pub(crate) recovery_slots: Arc<Semaphore>,
    authority_required: bool,
}

impl AppState {
    pub(crate) fn recovery_owner(
        &self,
    ) -> Option<&Arc<crate::recovery_authority::ProcessOwnership>> {
        self.ownership.as_ref().filter(|owner| {
            owner.is_recovering() && self.store.as_ref().is_some_and(Store::recovery_required)
        })
    }

    pub(crate) async fn legacy_authority_keys(
        &self,
    ) -> Result<crate::legacy_authority::LegacyAuthorityKeys, StoreError> {
        if self.authority_required && self.ownership.is_none() {
            return Err(StoreError::AuthorityFenced);
        }
        let store = self
            .store
            .as_ref()
            .ok_or(StoreError::MissingState("store"))?;
        let epoch = store.legacy_authority_epoch().await?;
        let keys = crate::legacy_authority::LegacyAuthorityKeys::derive(
            self.root_secret.as_bytes(),
            self.agent_jwt_secret.as_bytes(),
            store.tenant_id(),
            epoch,
        )?;
        if store.recovery_required() {
            return Err(StoreError::RecoveryRequired);
        }
        if self
            .ownership
            .as_ref()
            .is_some_and(|owner| owner.is_fenced())
        {
            return Err(StoreError::AuthorityFenced);
        }
        Ok(keys)
    }
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Serialize)]
struct ReadinessChecks {
    database: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority: Option<&'static str>,
}

#[derive(Serialize)]
struct ReadinessResponse {
    ok: bool,
    checks: ReadinessChecks,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

#[derive(Serialize)]
struct CapabilitiesResponse {
    api: Vec<&'static str>,
    version: &'static str,
    schema_version: u32,
    setup_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_pub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_epoch: Option<u64>,
    features: CapabilitiesFeatures,
    limits: CapabilitiesLimits,
}

/// Operator sign-in limits, published so a client or operator can read the
/// configured values instead of guessing (P07-D4).
#[derive(Serialize)]
struct CapabilitiesLimits {
    login: CapabilitiesLoginLimits,
    session: CapabilitiesSessionLimits,
}

#[derive(Serialize)]
struct CapabilitiesSessionLimits {
    absolute_seconds: u64,
    idle_seconds: u64,
}

#[derive(Serialize)]
struct CapabilitiesLoginLimits {
    account_failures: u32,
    account_total_failures: u32,
    ip_failures: u32,
    window_seconds: u64,
    lockout_seconds: u64,
}

#[derive(Serialize)]
struct CapabilitiesFeatures {
    browser_status: bool,
    fleet_authorization: bool,
}

pub fn build_app(config: Config, store: Option<Store>) -> Router {
    build_app_inner(config, store, None)
}

/// Recovery integration candidate. Bind the holder to the local identity;
/// active handling also checks the local epoch. These checks do not establish
/// complete restored-state reconciliation or source shutdown.
/// Production `serve` acquires a protected guard before opening its store and
/// uses this builder. Full restore reconciliation and source shutdown are
/// separate requirements; the builder never activates a generation.
pub fn build_app_with_ownership(
    config: Config,
    store: Option<Store>,
    ownership: Arc<crate::recovery_authority::ProcessOwnership>,
) -> Router {
    let identity_matches = match (store.as_ref(), config.issuer_keypair()) {
        (Some(store), Some(keypair)) => ownership.matches_controller(
            store.tenant_id(),
            &format!("ed25519-{}", base64_url_encode(keypair.public_key())),
        ),
        _ => false,
    };
    if !identity_matches {
        ownership.fence();
    }
    if let (Some(store), Some(keypair)) = (store.as_ref(), config.issuer_keypair()) {
        let key_id = format!("ed25519-{}", base64_url_encode(keypair.public_key()));
        if store.bind_ownership(ownership.clone(), &key_id).is_err() {
            ownership.fence();
        }
    }
    build_app_inner(config, store, Some(ownership))
}

fn build_app_inner(
    config: Config,
    store: Option<Store>,
    ownership: Option<Arc<crate::recovery_authority::ProcessOwnership>>,
) -> Router {
    let authority_required = !config.is_test_mode() || config.authority_url().is_some();
    // Build the lookalike-account hash off the request path so the first
    // unknown-username sign-in costs the same as every other.
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn_blocking(|| {
            let _ = crate::routes::auth::dummy_password_hash();
        });
    }
    let body_limit_bytes = config.body_limit_bytes();
    let allowed_origins = config
        .allowed_origins()
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect::<Vec<_>>();
    let request_id = HeaderName::from_static("x-request-id");
    let issuer_keypair = config.issuer_keypair().cloned();
    let issuer_key_id = issuer_keypair
        .as_ref()
        .map(|keypair| format!("ed25519-{}", base64_url_encode(keypair.public_key())));
    let store =
        store.map(|store| store.with_session_absolute_seconds(config.session_absolute_seconds()));
    let store = match (store, issuer_keypair.as_ref()) {
        (Some(store), Some(keypair)) => {
            Some(store.with_fleet_signer(FleetSigner::new(Arc::clone(keypair))))
        }
        (store, _) => store,
    };
    let state = AppState {
        store,
        root_secret: Arc::new(SecretBytes::from_slice(config.root_secret())),
        agent_jwt_secret: Arc::new(SecretBytes::from_slice(config.agent_jwt_secret())),
        node_keys: Arc::new(routes::node::NodeChannelKeys::derive(
            config.agent_jwt_secret(),
        )),
        issuer_keypair,
        issuer_key_id,
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
        trusted_proxy_peers: config.trusted_proxy_peers().to_vec(),
        proxy_required: config.proxy_required(),
        tls_enabled: config.tls_config().is_some(),
        proxy_authorities: [config.public_url(), config.ui_base_url()]
            .iter()
            .filter_map(|origin| origin.parse::<axum::http::Uri>().ok())
            .filter_map(|uri| {
                uri.authority()
                    .map(|authority| authority.as_str().to_owned())
            })
            .collect(),
        request_ttl_seconds: config.request_ttl_seconds(),
        submitted_ttl_seconds: config.submitted_ttl_seconds(),
        revoked_ttl_seconds: config.revoked_ttl_seconds(),
        approval_ttl_seconds: config.approval_ttl_seconds(),
        refresh_token_ttl_seconds: config.refresh_token_ttl_seconds(),
        agent_token_rate_limit: config.agent_token_rate_limit(),
        agent_request_rate_limit: config.agent_request_rate_limit(),
        agent_exchange_rate_limit: config.agent_exchange_rate_limit(),
        agent_token_rate_window_ms: config.agent_token_rate_window_ms(),
        agent_rate_window_ms: config.agent_rate_window_ms(),
        abuse_limits: config.abuse_limits(),
        session_absolute_seconds: config.session_absolute_seconds(),
        login_hash_slots: Arc::new(Semaphore::new(4)),
        recovery_slots: Arc::new(Semaphore::new(4)),
        ownership,
        authority_required,
    };

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v3/capabilities", get(capabilities))
        .merge(agents::routes())
        .merge(routes::admin_routes())
        .merge(exchanges::routes())
        .merge(secrets::routes())
        .merge(routes::node_routes())
        .merge(routes::recovery::routes())
        .merge(routes::test_seed_routes(state.test_mode))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            routes::forced_password_change_gate,
        ))
        .fallback(crate::embedded_ui::fallback)
        .with_state(state.clone())
        .layer(middleware::from_fn(security_headers))
        .layer(RequestBodyLimitLayer::new(body_limit_bytes))
        .layer(middleware::from_fn(request_timeout))
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
                // A separately hosted input page reads Date to derive its
                // expiry countdown from the controller clock (P04 slice 9).
                .expose_headers(ExposeHeaders::list([header::DATE]))
                .allow_credentials(true),
        )
        .layer(middleware::from_fn(normalize_allowed_preflight))
        .layer(middleware::from_fn_with_state(state.clone(), authority_gate))
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
        .layer(middleware::from_fn_with_state(state, enforce_proxy))
}

async fn authority_gate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if routes::recovery::is_recovery_path(request.uri().path()) {
        return routes::recovery::metadata_gate(state, request, next).await;
    }
    if !matches!(request.uri().path(), "/healthz" | "/readyz") {
        if state.authority_required && state.ownership.is_none() {
            return crate::recovery_authority::fenced_response();
        }
        if state.store.as_ref().is_some_and(Store::recovery_required) {
            return crate::recovery_authority::fenced_response();
        }
        validate_owner_epoch(&state).await;
    }
    match state.ownership {
        Some(ownership) => {
            crate::recovery_authority::ownership_gate(State(ownership), request, next).await
        }
        None => next.run(request).await,
    }
}

/// Runs on its own task: a disconnecting unauthenticated client must not drop
/// the epoch read midway. A real timeout, error or panic still fences.
async fn validate_owner_epoch(state: &AppState) {
    let detached = state.clone();
    if tokio::spawn(async move { validate_owner_epoch_inline(&detached).await })
        .await
        .is_err()
        && let Some(ownership) = state.ownership.as_ref()
    {
        ownership.fence();
    }
}

async fn validate_owner_epoch_inline(state: &AppState) {
    let Some(ownership) = state.ownership.as_ref().filter(|owner| owner.is_active()) else {
        return;
    };
    let matches = match state.store.as_ref() {
        Some(store) => {
            match tokio::time::timeout(Duration::from_secs(3), store.issuer_epoch()).await {
                Ok(Ok(epoch)) => ownership.matches_epoch(epoch),
                _ => false,
            }
        }
        None => false,
    };
    if !matches {
        ownership.fence();
    }
}

async fn enforce_proxy(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !state.proxy_required {
        let mut response = next.run(request).await;
        if state.tls_enabled {
            response.headers_mut().insert(
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000"),
            );
        }
        return response;
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    // Only local, read-only probes may bypass the ingress edge. No API/UI
    // handler, including preflight and public capabilities, shares this bypass.
    if matches!(request.method(), &Method::GET | &Method::HEAD)
        && matches!(request.uri().path(), "/healthz" | "/readyz")
        && peer.is_some_and(|ip| ip.is_loopback())
    {
        return next.run(request).await;
    }
    let headers = request.headers();
    let one = |name: &str| {
        let mut values = headers.get_all(name).iter();
        let value = values.next()?.to_str().ok()?;
        if values.next().is_some() {
            None
        } else {
            Some(value)
        }
    };
    let host = one("host");
    let forwarded_host = one("x-forwarded-host");
    let valid = peer.is_some_and(|ip| {
        state
            .trusted_proxy_peers
            .iter()
            .any(|network| network.contains(ip))
    }) && host.is_some_and(|host| {
        state
            .proxy_authorities
            .iter()
            .any(|authority| authority.eq_ignore_ascii_case(host))
    }) && host
        .zip(forwarded_host)
        .is_some_and(|(host, forwarded)| host.eq_ignore_ascii_case(forwarded))
        && one("x-forwarded-proto") == Some("https")
        && one("x-forwarded-for").is_some_and(|address| address.parse::<IpAddr>().is_ok())
        && !headers.contains_key("forwarded");
    if !valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"proxy_required"})),
        )
            .into_response();
    }
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    response
}

async fn request_timeout(request: Request, next: Next) -> Response {
    let timeout = if request.uri().path() == "/api/v3/node/poll" {
        Duration::from_secs(35)
    } else {
        Duration::from_secs(10)
    };
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
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
    if state.authority_required && state.ownership.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessResponse {
                ok: false,
                checks: ReadinessChecks {
                    database: "down",
                    authority: Some("down"),
                },
                reason: Some("recovery_required"),
            }),
        )
            .into_response();
    }
    let database_reason = match state.store.as_ref() {
        Some(store) => store
            .database_readiness()
            .await
            .err()
            .as_ref()
            .map(store_failure_reason),
        None => Some("store_unavailable"),
    };
    validate_owner_epoch(&state).await;
    let authority = match state.ownership {
        Some(ownership) if ownership.check_detached().await.is_err() => Some("down"),
        Some(ownership) if !ownership.is_active() => Some("fenced"),
        Some(_) => Some("up"),
        None => None,
    };
    let reason = database_reason.or_else(|| {
        if state.store.as_ref().is_some_and(Store::recovery_required) {
            return Some("recovery_required");
        }
        authority
            .filter(|check| *check != "up")
            .map(|_| "recovery_required")
    });
    let ready = reason.is_none();
    let payload = ReadinessResponse {
        ok: ready,
        checks: ReadinessChecks {
            database: if database_reason.is_none() {
                "up"
            } else {
                "down"
            },
            authority,
        },
        reason,
    };
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(payload)).into_response()
}

/// Diagnostic vocabulary shared by readiness and production startup. Only
/// known classes are exposed; driver details may contain credentials or paths.
pub fn store_failure_reason(error: &StoreError) -> &'static str {
    match error {
        StoreError::MissingState(_) => "state_missing",
        StoreError::UnsupportedSchemaVersion => "schema_mismatch",
        StoreError::ClockRegression
        | StoreError::ClockFenced
        | StoreError::ClockSourceUnavailable
        | StoreError::AuthorityFenced
        | StoreError::RecoveryRequired => "recovery_required",
        StoreError::InvalidInput("controller database permissions") => "permissions_invalid",
        StoreError::InvalidInput(crate::handoff::RETIRED) => "handoff_retired",
        StoreError::InvalidInput(crate::handoff::STALE) => "handoff_stale",
        StoreError::Database(sqlx::Error::Database(error))
            if error
                .code()
                .as_deref()
                .is_some_and(|code| matches!(code, "13" | "53100")) =>
        {
            "disk_full"
        }
        _ => "store_unavailable",
    }
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
    let issuer_epoch = match (state.issuer_keypair.as_ref(), state.store.as_ref()) {
        (Some(_), Some(store)) => match store.issuer_epoch().await {
            Ok(epoch) => Some(epoch),
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"error":"not_ready"})),
                )
                    .into_response();
            }
        },
        (Some(_), None) => Some(1),
        (None, _) => None,
    };
    Json(CapabilitiesResponse {
        api: if state.issuer_keypair.is_some() {
            vec!["compat.v2", "admin.v3", "fleet.v3"]
        } else {
            vec!["compat.v2", "admin.v3"]
        },
        version: env!("CARGO_PKG_VERSION"),
        schema_version: u32::try_from(SCHEMA_VERSION).expect("schema version fits u32"),
        setup_required,
        issuer_pub: state
            .issuer_keypair
            .as_ref()
            .map(|keypair| base64_url_encode(keypair.public_key())),
        issuer_kid: state.issuer_key_id,
        issuer_epoch,
        features: CapabilitiesFeatures {
            browser_status: BROWSER_STATUS_ADOPTED,
            fleet_authorization: state.issuer_keypair.is_some(),
        },
        limits: CapabilitiesLimits {
            login: CapabilitiesLoginLimits {
                account_failures: state.abuse_limits.login_account_failures,
                account_total_failures: state.abuse_limits.login_account_total_failures,
                ip_failures: state.abuse_limits.login_ip_failures,
                window_seconds: state.abuse_limits.login_window_seconds,
                lockout_seconds: state.abuse_limits.login_lockout_seconds,
            },
            session: CapabilitiesSessionLimits {
                absolute_seconds: state.session_absolute_seconds,
                idle_seconds: crate::store::SESSION_IDLE_SECONDS,
            },
        },
    })
    .into_response()
}
