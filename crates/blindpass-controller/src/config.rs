// SPDX-License-Identifier: AGPL-3.0-only

//! Validated controller configuration. Secret values are read from credential
//! files and are never included in error messages or a `Debug` representation.

use crate::proxy::TrustedProxy;
use axum::http::Uri;
use blindpass_core::deployment::{Directory, read_private_file};
use blindpass_core::secret::SecretBytes;
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_BODY_LIMIT_BYTES: usize = 1024 * 1024;
const MIN_KEY_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    CredentialFile(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(formatter, "missing configuration: {field}"),
            Self::Invalid(field) => write!(formatter, "invalid configuration: {field}"),
            Self::CredentialFile(field) => {
                write!(formatter, "unreadable or unsafe credential file: {field}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

pub struct Config {
    listen: SocketAddr,
    public_url: String,
    ui_base_url: String,
    database_url: String,
    authority: Option<AuthoritySettings>,
    root_secret: SecretBytes,
    agent_jwt_secret: SecretBytes,
    issuer_keypair: Option<Arc<Ed25519KeyPair>>,
    agent_auth_providers_json: Option<String>,
    secret_registry_json: Option<String>,
    exchange_policy_json: Option<String>,
    allowed_origins: Vec<String>,
    trusted_proxy_peers: Vec<TrustedProxy>,
    proxy_required: bool,
    fulfillments_enabled: bool,
    tls_config: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    body_limit_bytes: usize,
    agent_token_rate_limit: u32,
    agent_request_rate_limit: u32,
    agent_exchange_rate_limit: u32,
    audit_retention_days: u32,
    request_ttl_seconds: u64,
    submitted_ttl_seconds: u64,
    revoked_ttl_seconds: u64,
    approval_ttl_seconds: u64,
    refresh_token_ttl_seconds: u64,
    agent_token_rate_window_ms: u64,
    agent_rate_window_ms: u64,
    clock_tolerance_ms: u64,
    abuse_limits: AbuseLimits,
    session_absolute_seconds: u64,
    admin_socket_path: PathBuf,
    test_mode: bool,
    test_seed_token: Option<SecretBytes>,
    log_format: LogFormat,
}

/// P07-D4 operator sign-in and bootstrap abuse limits. Failures count; a
/// successful sign-in never consumes budget. Every value is published in
/// `/api/v3/capabilities` `limits`, except the state caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbuseLimits {
    /// Failed sign-ins for one account from one source address inside
    /// `window_seconds` before that account/source pair is locked. A guesser
    /// at one address locks only itself, never the operator elsewhere.
    pub login_account_failures: u32,
    /// Failed sign-ins for one account from any sources inside the window
    /// before the account is locked for everyone. Bounds distributed
    /// guessing; always at least `login_account_failures`.
    pub login_account_total_failures: u32,
    /// Failed sign-ins per client address inside `window_seconds`.
    pub login_ip_failures: u32,
    /// Failure counting window for the account and address counters.
    pub login_window_seconds: u64,
    /// How long an account stays locked once it reaches the failure limit.
    pub login_lockout_seconds: u64,
    /// Cap on live per-account failure rows for usernames that do not exist.
    pub login_tracked_accounts: u32,
    /// Failed bootstrap attempts per peer shard inside the bootstrap window.
    pub bootstrap_failures_per_peer: u32,
    /// Failed bootstrap attempts for the whole controller inside the window.
    pub bootstrap_failures_global: u32,
}

// Credentials have no Debug representation and stay outside controller state.
// Offline backup verification does not need them; serving and maintenance do.
struct AuthoritySettings {
    url: String,
    tenant_id: String,
    owner_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Text,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_variables(std::env::vars())
    }

    /// Configuration for commands that read the shared configuration file but never listen (the backup
    /// job, the handoff commands). A remote direct-TLS controller binds a wildcard address and receives
    /// its certificate only through the serving units, so the serve-time rule "no unrestricted bind
    /// without TLS or a proxy" must not apply here; every other rule does. The bind is pinned to
    /// loopback and is never opened by these commands.
    pub fn from_env_offline() -> Result<Self, ConfigError> {
        Self::from_variables_offline(std::env::vars())
    }

    pub fn from_variables_offline<K, V, I>(variables: I) -> Result<Self, ConfigError>
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        let mut values = variables
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect::<BTreeMap<String, String>>();
        values.insert("BLINDPASS_LISTEN".into(), "127.0.0.1:3200".into());
        Self::from_map(&values)
    }

    /// Build configuration from an explicit variable set. This is public so
    /// integration tests can validate production and test profiles without
    /// mutating process-global environment state.
    pub fn from_variables<K, V, I>(variables: I) -> Result<Self, ConfigError>
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        let values = variables
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect::<BTreeMap<_, _>>();
        Self::from_map(&values)
    }

    fn from_map(values: &BTreeMap<String, String>) -> Result<Self, ConfigError> {
        let test_mode_value = values.get("BLINDPASS_TEST_MODE").map(String::as_str);
        let test_mode = match test_mode_value {
            None | Some("") | Some("0") => false,
            Some("1") => true,
            Some(_) => return Err(ConfigError::Invalid("BLINDPASS_TEST_MODE")),
        };
        let has_test_override = values
            .keys()
            .any(|key| key.starts_with("BLINDPASS_TEST_") && key != "BLINDPASS_TEST_MODE");
        if has_test_override && !test_mode {
            return Err(ConfigError::Invalid(
                "BLINDPASS_TEST_* requires BLINDPASS_TEST_MODE=1",
            ));
        }
        if test_mode
            && values
                .get("NODE_ENV")
                .is_some_and(|value| value.eq_ignore_ascii_case("production"))
        {
            return Err(ConfigError::Invalid("BLINDPASS_TEST_MODE in production"));
        }

        let listen = value(values, "BLINDPASS_LISTEN")
            .unwrap_or("127.0.0.1:3200")
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Invalid("BLINDPASS_LISTEN"))?;

        let public_url = required(values, "BLINDPASS_PUBLIC_URL")?;
        validate_origin(public_url, "BLINDPASS_PUBLIC_URL")?;
        let ui_base_url = required(values, "BLINDPASS_UI_BASE_URL")?;
        validate_origin(ui_base_url, "BLINDPASS_UI_BASE_URL")?;

        // Layout roots are explicit opt-ins. Legacy per-file configuration is
        // retained; merely validating config never creates replacement state.
        let keys_dir = private_directory(values, "BLINDPASS_KEYS_DIR")?;
        let data_dir = private_directory(values, "BLINDPASS_DATA_DIR")?;
        let database_url = match (
            value(values, "BLINDPASS_DATABASE_URL"),
            value(values, "BLINDPASS_DATABASE_URL_FILE"),
        ) {
            (None, None) if data_dir.is_some() => {
                sqlite_layout_url(data_dir.as_deref().expect("explicit data directory"))
            }
            (Some(_), Some(_)) | (None, None) => {
                return Err(ConfigError::Invalid(
                    "exactly one of BLINDPASS_DATABASE_URL and BLINDPASS_DATABASE_URL_FILE",
                ));
            }
            (Some(_), None) if !test_mode => {
                return Err(ConfigError::Invalid(
                    "BLINDPASS_DATABASE_URL must be file-backed outside test mode",
                ));
            }
            (Some(url), None) => url.trim().to_owned(),
            (None, Some(path)) => read_text_file(path, "BLINDPASS_DATABASE_URL_FILE")?,
        };
        if !database_url.starts_with("sqlite:")
            && !database_url.starts_with("postgres://")
            && !database_url.starts_with("postgresql://")
        {
            return Err(ConfigError::Invalid("BLINDPASS_DATABASE_URL"));
        }
        validate_postgres_query_parameters(&database_url)?;

        let root_path = credential_path(
            values,
            keys_dir.as_deref(),
            "BLINDPASS_ROOT_SECRET_FILE",
            "root-secret",
        );
        let agent_path = credential_path(
            values,
            keys_dir.as_deref(),
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            "agent-jwt-secret",
        );
        let issuer_path = credential_path(
            values,
            keys_dir.as_deref(),
            "BLINDPASS_ISSUER_KEY_FILE",
            "issuer-key",
        );
        let root_secret = read_secret_file(
            root_path
                .as_deref()
                .ok_or(ConfigError::Missing("BLINDPASS_ROOT_SECRET_FILE"))?,
            "BLINDPASS_ROOT_SECRET_FILE",
            MIN_KEY_BYTES,
        )?;
        let agent_jwt_secret = read_secret_file(
            agent_path
                .as_deref()
                .ok_or(ConfigError::Missing("BLINDPASS_AGENT_JWT_SECRET_FILE"))?,
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            MIN_KEY_BYTES,
        )?;
        let issuer_keypair = match issuer_path.as_deref() {
            Some(path) => {
                let seed = read_secret_file(path, "BLINDPASS_ISSUER_KEY_FILE", 32)?;
                if seed.as_bytes().len() != 32 {
                    return Err(ConfigError::CredentialFile("BLINDPASS_ISSUER_KEY_FILE"));
                }
                Some(Arc::new(
                    Ed25519KeyPair::from_seed(seed.as_bytes())
                        .map_err(|_| ConfigError::CredentialFile("BLINDPASS_ISSUER_KEY_FILE"))?,
                ))
            }
            None if test_mode => None,
            None => return Err(ConfigError::Missing("BLINDPASS_ISSUER_KEY_FILE")),
        };

        let authority = read_authority_settings(values)?;
        if authority.is_some() && issuer_keypair.is_none() {
            return Err(ConfigError::Missing("BLINDPASS_ISSUER_KEY_FILE"));
        }

        let agent_auth_providers_json = value(values, "BLINDPASS_AGENT_AUTH_PROVIDERS_JSON")
            .map(validate_auth_providers)
            .transpose()?;

        let secret_registry_json = value(values, "BLINDPASS_SECRET_REGISTRY_JSON")
            .map(|source| validate_json_array(source, "BLINDPASS_SECRET_REGISTRY_JSON"))
            .transpose()?;
        let exchange_policy_json = value(values, "BLINDPASS_EXCHANGE_POLICY_JSON")
            .map(|source| validate_json_array(source, "BLINDPASS_EXCHANGE_POLICY_JSON"))
            .transpose()?;
        if secret_registry_json.is_some() || exchange_policy_json.is_some() {
            let array = |source: Option<&String>| {
                source
                    .and_then(|source| serde_json::from_str::<Vec<serde_json::Value>>(source).ok())
                    .unwrap_or_default()
            };
            let errors = crate::routes::admin_policy::environment_policy_errors(
                array(secret_registry_json.as_ref()),
                array(exchange_policy_json.as_ref()),
            );
            if let Some(error) = errors.first() {
                return Err(ConfigError::Invalid(
                    if error.starts_with("secret_registry") {
                        "BLINDPASS_SECRET_REGISTRY_JSON"
                    } else {
                        "BLINDPASS_EXCHANGE_POLICY_JSON"
                    },
                ));
            }
        }

        let allowed_origins = value(values, "BLINDPASS_CORS_ALLOWED_ORIGINS")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(|origin| {
                validate_origin(origin, "BLINDPASS_CORS_ALLOWED_ORIGINS")?;
                Ok(origin.to_owned())
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        // A boolean proxy trust switch would trust attacker-supplied
        // X-Forwarded-For values from every peer. Accept only explicit IPs
        // or canonical restricted CIDRs.
        let proxy_required = match value(values, "BLINDPASS_PROXY_REQUIRED") {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => return Err(ConfigError::Invalid("BLINDPASS_PROXY_REQUIRED")),
        };
        // P10 cross-workload fulfillment is off unless an operator opts in. A
        // restart with the flag cleared closes every live fulfillment.
        let fulfillments_enabled = match value(values, "BLINDPASS_FULFILLMENTS_ENABLED") {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => return Err(ConfigError::Invalid("BLINDPASS_FULFILLMENTS_ENABLED")),
        };
        let trusted_proxy_peers = value(values, "BLINDPASS_TRUST_PROXY")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .map(|proxy| {
                proxy
                    .parse()
                    .map_err(|_| ConfigError::Invalid("BLINDPASS_TRUST_PROXY"))
            })
            .collect::<Result<Vec<TrustedProxy>, _>>();
        let trusted_proxy_peers =
            if value(values, "BLINDPASS_TRUST_PROXY").is_none_or(str::is_empty) {
                Vec::new()
            } else {
                trusted_proxy_peers?
            };
        // Every shipped native, image and Compose profile sets
        // BLINDPASS_PROXY_REQUIRED=1, so it marks a production profile even
        // when NODE_ENV is unset. Test mode there would skip the ownership
        // requirement, mount the seed route and trust loopback forwarding.
        if test_mode && proxy_required {
            return Err(ConfigError::Invalid("BLINDPASS_TEST_MODE in production"));
        }
        if proxy_required
            && (trusted_proxy_peers.is_empty()
                || !public_url.starts_with("https://")
                || !ui_base_url.starts_with("https://"))
        {
            return Err(ConfigError::Invalid(
                "BLINDPASS_PROXY_REQUIRED requires HTTPS origins and explicit proxy peers",
            ));
        }
        let tls_cert = value(values, "BLINDPASS_TLS_CERT_FILE");
        let tls_key = value(values, "BLINDPASS_TLS_KEY_FILE");
        let tls_config = match (tls_cert, tls_key) {
            (None, None) => None,
            (Some(cert), Some(key)) => {
                if !public_url.starts_with("https://") || !ui_base_url.starts_with("https://") {
                    return Err(ConfigError::Invalid("built-in TLS requires HTTPS origins"));
                }
                Some(
                    crate::tls::load_config(Path::new(cert), Path::new(key))
                        .map_err(ConfigError::CredentialFile)?,
                )
            }
            _ => {
                return Err(ConfigError::Invalid(
                    "both BLINDPASS_TLS_CERT_FILE and BLINDPASS_TLS_KEY_FILE are required",
                ));
            }
        };
        if listen.ip().is_unspecified() && !test_mode && !proxy_required && tls_config.is_none() {
            return Err(ConfigError::Invalid(
                "BLINDPASS_LISTEN must not be an unrestricted bind",
            ));
        }

        let body_limit_bytes = parse_range(
            values,
            "BLINDPASS_BODY_LIMIT_BYTES",
            DEFAULT_BODY_LIMIT_BYTES,
            1_024,
            64 * 1024 * 1024,
        )?;
        let agent_token_rate_limit =
            parse_range(values, "BLINDPASS_AGENT_TOKEN_RATE_LIMIT", 5, 1, 1_000)?;
        let agent_request_rate_limit =
            parse_range(values, "BLINDPASS_AGENT_REQUEST_RATE_LIMIT", 60, 1, 10_000)?;
        let agent_exchange_rate_limit =
            parse_range(values, "BLINDPASS_AGENT_EXCHANGE_RATE_LIMIT", 60, 1, 10_000)?;
        let audit_retention_days =
            parse_range(values, "BLINDPASS_AUDIT_RETENTION_DAYS", 90, 1, 3_650)?;
        let request_ttl_seconds =
            parse_range(values, "BLINDPASS_TEST_REQUEST_TTL_SECONDS", 180, 1, 86_400)?;
        let submitted_ttl_seconds = parse_range(
            values,
            "BLINDPASS_TEST_SUBMITTED_TTL_SECONDS",
            60,
            1,
            86_400,
        )?;
        let revoked_ttl_seconds =
            parse_range(values, "BLINDPASS_TEST_REVOKED_TTL_SECONDS", 300, 1, 86_400)?;
        let approval_ttl_seconds = parse_range(
            values,
            "BLINDPASS_TEST_APPROVAL_TTL_SECONDS",
            600,
            1,
            86_400,
        )?;
        let refresh_token_ttl_seconds = parse_range(
            values,
            "BLINDPASS_TEST_REFRESH_TOKEN_TTL_SECONDS",
            30 * 24 * 60 * 60,
            1,
            365 * 24 * 60 * 60,
        )?;
        let agent_token_rate_window_ms = parse_range(
            values,
            "BLINDPASS_TEST_AGENT_TOKEN_RATE_WINDOW_MS",
            60_000,
            100,
            3_600_000,
        )?;
        let agent_rate_window_seconds =
            parse_range(values, "BLINDPASS_AGENT_RATE_WINDOW_SECONDS", 60, 1, 3_600)?;
        let agent_rate_window_ms = parse_range(
            values,
            "BLINDPASS_TEST_AGENT_RATE_WINDOW_MS",
            agent_rate_window_seconds * 1_000,
            1,
            3_600_000,
        )?;
        let clock_tolerance_ms =
            parse_range(values, "BLINDPASS_CLOCK_TOLERANCE_MS", 2_000, 250, 60_000)?;
        let abuse_limits = AbuseLimits {
            login_account_failures: parse_range(
                values,
                "BLINDPASS_LOGIN_ACCOUNT_FAILURES",
                10,
                1,
                100_000,
            )?,
            login_account_total_failures: parse_range(
                values,
                "BLINDPASS_LOGIN_ACCOUNT_TOTAL_FAILURES",
                50,
                1,
                1_000_000,
            )?,
            login_ip_failures: parse_range(values, "BLINDPASS_LOGIN_IP_FAILURES", 30, 1, 100_000)?,
            login_window_seconds: parse_range(
                values,
                "BLINDPASS_LOGIN_WINDOW_SECONDS",
                900,
                1,
                86_400,
            )?,
            login_lockout_seconds: parse_range(
                values,
                "BLINDPASS_LOGIN_LOCKOUT_SECONDS",
                900,
                1,
                86_400,
            )?,
            login_tracked_accounts: parse_range(
                values,
                "BLINDPASS_LOGIN_TRACKED_ACCOUNTS",
                10_000,
                16,
                1_000_000,
            )?,
            bootstrap_failures_per_peer: parse_range(
                values,
                "BLINDPASS_BOOTSTRAP_FAILURES_PER_PEER",
                10,
                1,
                100_000,
            )?,
            bootstrap_failures_global: parse_range(
                values,
                "BLINDPASS_BOOTSTRAP_FAILURES_GLOBAL",
                100,
                1,
                1_000_000,
            )?,
        };
        let session_absolute_seconds = parse_range(
            values,
            "BLINDPASS_SESSION_ABSOLUTE_SECONDS",
            7 * 24 * 60 * 60,
            3_600,
            30 * 24 * 60 * 60,
        )?;
        if abuse_limits.login_account_total_failures < abuse_limits.login_account_failures {
            return Err(ConfigError::Invalid(
                "BLINDPASS_LOGIN_ACCOUNT_TOTAL_FAILURES below BLINDPASS_LOGIN_ACCOUNT_FAILURES",
            ));
        }
        let test_seed_token = value(values, "BLINDPASS_TEST_SEED_TOKEN")
            .map(|token| {
                if token.len() < MIN_KEY_BYTES {
                    return Err(ConfigError::Invalid("BLINDPASS_TEST_SEED_TOKEN"));
                }
                Ok::<SecretBytes, ConfigError>(SecretBytes::from_slice(token.as_bytes()))
            })
            .transpose()?;
        if test_seed_token.is_some() && !test_mode {
            return Err(ConfigError::Invalid("BLINDPASS_TEST_SEED_TOKEN"));
        }
        let log_format = match value(values, "BLINDPASS_LOG_FORMAT").unwrap_or("json") {
            "json" => LogFormat::Json,
            "text" => LogFormat::Text,
            _ => return Err(ConfigError::Invalid("BLINDPASS_LOG_FORMAT")),
        };
        let admin_socket_path = PathBuf::from(
            value(values, "BLINDPASS_ADMIN_SOCKET_PATH")
                .unwrap_or("/run/blindpass-controller/admin.sock"),
        );
        if !admin_socket_path.is_absolute() {
            return Err(ConfigError::Invalid(
                "BLINDPASS_ADMIN_SOCKET_PATH must be absolute",
            ));
        }

        Ok(Self {
            listen,
            public_url: public_url.to_owned(),
            ui_base_url: ui_base_url.to_owned(),
            database_url,
            authority,
            root_secret,
            agent_jwt_secret,
            issuer_keypair,
            agent_auth_providers_json,
            secret_registry_json,
            exchange_policy_json,
            allowed_origins,
            trusted_proxy_peers,
            proxy_required,
            fulfillments_enabled,
            tls_config,
            body_limit_bytes,
            agent_token_rate_limit,
            agent_request_rate_limit,
            agent_exchange_rate_limit,
            audit_retention_days,
            request_ttl_seconds,
            submitted_ttl_seconds,
            revoked_ttl_seconds,
            approval_ttl_seconds,
            refresh_token_ttl_seconds,
            agent_token_rate_window_ms,
            agent_rate_window_ms,
            clock_tolerance_ms,
            abuse_limits,
            session_absolute_seconds,
            admin_socket_path,
            test_mode,
            test_seed_token,
            log_format,
        })
    }

    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    /// Stateful production commands require the protected authority. Explicit
    /// isolated test mode may omit it; a supplied partial/unsafe set never passes.
    pub fn require_authority(&self) -> Result<(), ConfigError> {
        if self.authority.is_none() && !self.test_mode {
            return Err(ConfigError::Missing("BLINDPASS_AUTHORITY_URL_FILE"));
        }
        Ok(())
    }

    pub fn authority_url(&self) -> Option<&str> {
        self.authority
            .as_ref()
            .map(|authority| authority.url.as_str())
    }

    pub fn authority_context(&self) -> Option<crate::recovery_authority::AuthorityContext> {
        let authority = self.authority.as_ref()?;
        let keypair = self.issuer_keypair.as_ref()?;
        Some(crate::recovery_authority::AuthorityContext {
            tenant_id: authority.tenant_id.clone(),
            issuer_key_id: blindpass_core::signing::issuer_key_id(keypair.public_key()),
            owner_id: authority.owner_id.clone(),
        })
    }

    #[must_use]
    pub fn body_limit_bytes(&self) -> usize {
        self.body_limit_bytes
    }

    #[must_use]
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    #[must_use]
    pub fn is_test_mode(&self) -> bool {
        self.test_mode
    }

    /// In-process component fixtures only: a production-shaped configuration
    /// (proxy required, protected authority) served with test mode on, which
    /// `from_variables` refuses on purpose. It is reachable from code, never
    /// from the environment or a profile; `tests/production_flags.rs` pins that
    /// no non-test source calls it.
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_fixture_mode(mut self) -> Self {
        self.test_mode = true;
        self
    }

    #[must_use]
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }

    #[must_use]
    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    #[must_use]
    pub fn ui_base_url(&self) -> &str {
        &self.ui_base_url
    }

    #[must_use]
    pub fn trusted_proxy_peers(&self) -> &[TrustedProxy] {
        &self.trusted_proxy_peers
    }

    #[must_use]
    pub fn proxy_required(&self) -> bool {
        self.proxy_required
    }

    #[must_use]
    pub fn fulfillments_enabled(&self) -> bool {
        self.fulfillments_enabled
    }

    #[must_use]
    pub fn tls_config(&self) -> Option<Arc<tokio_rustls::rustls::ServerConfig>> {
        self.tls_config.clone()
    }

    #[must_use]
    pub fn agent_jwt_secret(&self) -> &[u8] {
        self.agent_jwt_secret.as_bytes()
    }

    #[must_use]
    pub fn issuer_keypair(&self) -> Option<&Arc<Ed25519KeyPair>> {
        self.issuer_keypair.as_ref()
    }

    #[must_use]
    pub fn root_secret(&self) -> &[u8] {
        self.root_secret.as_bytes()
    }

    #[must_use]
    pub fn test_seed_token(&self) -> Option<&[u8]> {
        self.test_seed_token.as_ref().map(SecretBytes::as_bytes)
    }

    #[must_use]
    pub fn agent_auth_providers_json(&self) -> Option<&str> {
        self.agent_auth_providers_json.as_deref()
    }

    #[must_use]
    pub fn secret_registry_json(&self) -> Option<&str> {
        self.secret_registry_json.as_deref()
    }

    #[must_use]
    pub fn exchange_policy_json(&self) -> Option<&str> {
        self.exchange_policy_json.as_deref()
    }

    #[must_use]
    pub fn agent_token_rate_limit(&self) -> u32 {
        self.agent_token_rate_limit
    }

    #[must_use]
    pub fn agent_request_rate_limit(&self) -> u32 {
        self.agent_request_rate_limit
    }

    #[must_use]
    pub fn agent_exchange_rate_limit(&self) -> u32 {
        self.agent_exchange_rate_limit
    }

    #[must_use]
    pub fn audit_retention_days(&self) -> u32 {
        self.audit_retention_days
    }

    #[must_use]
    pub fn request_ttl_seconds(&self) -> u64 {
        self.request_ttl_seconds
    }

    #[must_use]
    pub fn submitted_ttl_seconds(&self) -> u64 {
        self.submitted_ttl_seconds
    }

    #[must_use]
    pub fn revoked_ttl_seconds(&self) -> u64 {
        self.revoked_ttl_seconds
    }

    #[must_use]
    pub fn approval_ttl_seconds(&self) -> u64 {
        self.approval_ttl_seconds
    }

    #[must_use]
    pub fn refresh_token_ttl_seconds(&self) -> u64 {
        self.refresh_token_ttl_seconds
    }

    #[must_use]
    pub fn agent_token_rate_window_ms(&self) -> u64 {
        self.agent_token_rate_window_ms
    }

    #[must_use]
    pub fn agent_rate_window_ms(&self) -> u64 {
        self.agent_rate_window_ms
    }

    #[must_use]
    pub fn clock_tolerance_ms(&self) -> u64 {
        self.clock_tolerance_ms
    }

    #[must_use]
    pub fn abuse_limits(&self) -> AbuseLimits {
        self.abuse_limits
    }

    /// Longest an operator session can live from its sign-in, however often
    /// it refreshes.
    #[must_use]
    pub fn session_absolute_seconds(&self) -> u64 {
        self.session_absolute_seconds
    }

    #[must_use]
    pub fn admin_socket_path(&self) -> &Path {
        &self.admin_socket_path
    }
}

fn value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    values
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    key: &'static str,
) -> Result<&'a str, ConfigError> {
    value(values, key).ok_or(ConfigError::Missing(key))
}

/// External workload providers must name a JWKS file. URL providers are
/// rejected rather than skipped at request time, because the controller has
/// no bounded HTTPS JWKS transport.
pub(crate) fn validate_postgres_query_parameters(source: &str) -> Result<(), ConfigError> {
    const KEY: &str = "BLINDPASS_DATABASE_URL options";
    if source.starts_with("sqlite:") {
        return Ok(());
    }
    // SQLx warns with both name and value for unknown parameters. Validate
    // query names before any SQLx parser can copy protected input into logs.
    // URL fragments are not part of the query; empty form segments are ignored.
    let source = source.split('#').next().unwrap_or(source);
    let Some((_, query)) = source.split_once('?') else {
        return Ok(());
    };
    for item in query.split('&').filter(|item| !item.is_empty()) {
        let encoded = item.split('=').next().unwrap_or_default().as_bytes();
        let mut decoded = Vec::with_capacity(encoded.len().min(128));
        let mut index = 0;
        while index < encoded.len() {
            let byte = match encoded[index] {
                b'%' => {
                    let digits = encoded
                        .get(index + 1..index + 3)
                        .ok_or(ConfigError::Invalid(KEY))?;
                    let high = (digits[0] as char)
                        .to_digit(16)
                        .ok_or(ConfigError::Invalid(KEY))?;
                    let low = (digits[1] as char)
                        .to_digit(16)
                        .ok_or(ConfigError::Invalid(KEY))?;
                    index += 2;
                    (high * 16 + low) as u8
                }
                b'+' => b' ',
                byte => byte,
            };
            decoded.push(byte);
            if decoded.len() > 128 {
                return Err(ConfigError::Invalid(KEY));
            }
            index += 1;
        }
        let name = std::str::from_utf8(&decoded).map_err(|_| ConfigError::Invalid(KEY))?;
        let known = matches!(
            name,
            "sslmode"
                | "ssl-mode"
                | "sslrootcert"
                | "ssl-root-cert"
                | "ssl-ca"
                | "sslcert"
                | "ssl-cert"
                | "sslkey"
                | "ssl-key"
                | "statement-cache-capacity"
                | "host"
                | "hostaddr"
                | "port"
                | "dbname"
                | "user"
                | "password"
                | "application_name"
                | "options"
        ) || name
            .strip_prefix("options[")
            .and_then(|key| key.strip_suffix(']'))
            .is_some_and(|key| {
                !key.is_empty()
                    && key.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                    })
            });
        if !known {
            return Err(ConfigError::Invalid(KEY));
        }
    }
    Ok(())
}

fn validate_auth_providers(source: &str) -> Result<String, ConfigError> {
    const KEY: &str = "BLINDPASS_AGENT_AUTH_PROVIDERS_JSON";
    let providers =
        serde_json::from_str::<serde_json::Value>(source).map_err(|_| ConfigError::Invalid(KEY))?;
    let providers = providers.as_array().ok_or(ConfigError::Invalid(KEY))?;
    for provider in providers {
        let text = |names: [&str; 2]| {
            names
                .iter()
                .find_map(|name| provider.get(*name))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        };
        if !provider.is_object()
            || text(["jwks_url", "jwksUrl"]).is_some()
            || text(["jwks_file", "jwksFile"]).is_none()
        {
            return Err(ConfigError::Invalid(KEY));
        }
    }
    Ok(source.to_owned())
}

fn validate_json_array(source: &str, key: &'static str) -> Result<String, ConfigError> {
    let parsed =
        serde_json::from_str::<serde_json::Value>(source).map_err(|_| ConfigError::Invalid(key))?;
    if !parsed.is_array() {
        return Err(ConfigError::Invalid(key));
    }
    Ok(source.to_owned())
}

fn parse_range<T>(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: T,
    minimum: T,
    maximum: T,
) -> Result<T, ConfigError>
where
    T: std::str::FromStr + PartialOrd + Copy,
{
    let Some(value) = value(values, key) else {
        return Ok(default);
    };
    let parsed = value.parse().map_err(|_| ConfigError::Invalid(key))?;
    if parsed < minimum || parsed > maximum {
        return Err(ConfigError::Invalid(key));
    }
    Ok(parsed)
}

fn read_authority_settings(
    values: &BTreeMap<String, String>,
) -> Result<Option<AuthoritySettings>, ConfigError> {
    if values.contains_key("BLINDPASS_AUTHORITY_URL") {
        return Err(ConfigError::Invalid(
            "BLINDPASS_AUTHORITY_URL must be file-backed",
        ));
    }
    let fields = [
        "BLINDPASS_AUTHORITY_URL_FILE",
        "BLINDPASS_CONTROLLER_TENANT_ID",
        "BLINDPASS_CONTROLLER_OWNER_ID",
    ];
    if !fields.iter().any(|field| values.contains_key(*field)) {
        return Ok(None);
    }
    let url = read_text_file(required(values, fields[0])?, fields[0])?;
    if !(url.starts_with("postgres://") || url.starts_with("postgresql://"))
        || validate_postgres_query_parameters(&url).is_err()
    {
        return Err(ConfigError::Invalid(fields[0]));
    }
    let identity = |field| -> Result<String, ConfigError> {
        let id = required(values, field)?;
        if id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(ConfigError::Invalid(field));
        }
        Ok(id.to_owned())
    };
    Ok(Some(AuthoritySettings {
        url,
        tenant_id: identity(fields[1])?,
        owner_id: identity(fields[2])?,
    }))
}

fn read_text_file(path: &str, field: &'static str) -> Result<String, ConfigError> {
    let contents = read_private_file(Path::new(path), 16 * 1024)
        .map_err(|_| ConfigError::CredentialFile(field))?;
    let contents =
        std::str::from_utf8(contents.as_bytes()).map_err(|_| ConfigError::CredentialFile(field))?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::CredentialFile(field));
    }
    Ok(trimmed.to_owned())
}

fn read_secret_file(
    path: &str,
    field: &'static str,
    minimum: usize,
) -> Result<SecretBytes, ConfigError> {
    let contents =
        read_private_file(Path::new(path), 4096).map_err(|_| ConfigError::CredentialFile(field))?;
    if contents.len() < minimum {
        return Err(ConfigError::CredentialFile(field));
    }
    Ok(contents)
}

fn private_directory(
    values: &BTreeMap<String, String>,
    field: &'static str,
) -> Result<Option<PathBuf>, ConfigError> {
    let Some(path) = value(values, field) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(ConfigError::Invalid(field));
    }
    Directory::open_private(&path).map_err(|_| ConfigError::CredentialFile(field))?;
    Ok(Some(path))
}

fn credential_path(
    values: &BTreeMap<String, String>,
    directory: Option<&Path>,
    field: &'static str,
    name: &str,
) -> Option<String> {
    value(values, field)
        .map(str::to_owned)
        .or_else(|| directory.map(|path| path.join(name).to_string_lossy().into_owned()))
}

fn sqlite_layout_url(directory: &Path) -> String {
    use std::fmt::Write;
    use std::os::unix::ffi::OsStrExt;
    let path = directory.join("controller.db");
    let mut url = String::from("sqlite://");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-_.~".contains(byte) {
            url.push(char::from(*byte));
        } else {
            write!(&mut url, "%{byte:02X}").expect("write to string");
        }
    }
    url.push_str("?mode=rwc");
    url
}

fn validate_origin(value: &str, field: &'static str) -> Result<(), ConfigError> {
    let uri = value
        .parse::<Uri>()
        .map_err(|_| ConfigError::Invalid(field))?;
    let scheme = uri.scheme_str().ok_or(ConfigError::Invalid(field))?;
    let authority = uri.authority().ok_or(ConfigError::Invalid(field))?;
    if (scheme != "http" && scheme != "https")
        || authority.as_str().contains('@')
        || uri
            .path_and_query()
            .is_some_and(|path| path.as_str() != "/")
    {
        return Err(ConfigError::Invalid(field));
    }
    Ok(())
}
