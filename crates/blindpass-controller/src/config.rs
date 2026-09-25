// SPDX-License-Identifier: AGPL-3.0-only

//! Validated controller configuration. Secret values are read from credential
//! files and are never included in error messages or a `Debug` representation.

use axum::http::Uri;
use blindpass_core::secret::SecretBytes;
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
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
    root_secret: SecretBytes,
    agent_jwt_secret: SecretBytes,
    issuer_keypair: Option<Arc<Ed25519KeyPair>>,
    agent_auth_providers_json: Option<String>,
    secret_registry_json: Option<String>,
    exchange_policy_json: Option<String>,
    allowed_origins: Vec<String>,
    trusted_proxy_addresses: Vec<IpAddr>,
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
    admin_socket_path: PathBuf,
    test_mode: bool,
    test_seed_token: Option<SecretBytes>,
    log_format: LogFormat,
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
        if listen.ip().is_unspecified() && !test_mode {
            return Err(ConfigError::Invalid(
                "BLINDPASS_LISTEN must not be an unrestricted bind",
            ));
        }

        let public_url = required(values, "BLINDPASS_PUBLIC_URL")?;
        validate_origin(public_url, "BLINDPASS_PUBLIC_URL")?;
        let ui_base_url = required(values, "BLINDPASS_UI_BASE_URL")?;
        validate_origin(ui_base_url, "BLINDPASS_UI_BASE_URL")?;

        let database_url = match (
            value(values, "BLINDPASS_DATABASE_URL"),
            value(values, "BLINDPASS_DATABASE_URL_FILE"),
        ) {
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

        let root_secret = read_secret_file(
            required(values, "BLINDPASS_ROOT_SECRET_FILE")?,
            "BLINDPASS_ROOT_SECRET_FILE",
            MIN_KEY_BYTES,
        )?;
        let agent_jwt_secret = read_secret_file(
            required(values, "BLINDPASS_AGENT_JWT_SECRET_FILE")?,
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            MIN_KEY_BYTES,
        )?;
        let issuer_keypair = match value(values, "BLINDPASS_ISSUER_KEY_FILE") {
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
        // X-Forwarded-For values from every peer. Accept only explicit IPs.
        let trusted_proxy_addresses = value(values, "BLINDPASS_TRUST_PROXY")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|proxy| !proxy.is_empty())
            .map(|proxy| {
                proxy
                    .parse()
                    .map_err(|_| ConfigError::Invalid("BLINDPASS_TRUST_PROXY"))
            })
            .collect::<Result<Vec<IpAddr>, _>>()?;

        let tls_cert = value(values, "BLINDPASS_TLS_CERT_FILE");
        let tls_key = value(values, "BLINDPASS_TLS_KEY_FILE");
        if tls_cert.is_some() || tls_key.is_some() {
            return Err(ConfigError::Invalid(
                "TLS terminates at the configured reverse proxy; built-in TLS is not enabled",
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
            root_secret,
            agent_jwt_secret,
            issuer_keypair,
            agent_auth_providers_json,
            secret_registry_json,
            exchange_policy_json,
            allowed_origins,
            trusted_proxy_addresses,
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
    pub fn trusted_proxy_addresses(&self) -> &[IpAddr] {
        &self.trusted_proxy_addresses
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

fn read_text_file(path: &str, field: &'static str) -> Result<String, ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).map_err(|_| ConfigError::CredentialFile(field))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ConfigError::CredentialFile(field));
    }
    let contents =
        std::fs::read_to_string(Path::new(path)).map_err(|_| ConfigError::CredentialFile(field))?;
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
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).map_err(|_| ConfigError::CredentialFile(field))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ConfigError::CredentialFile(field));
    }
    let contents = std::fs::read(path).map_err(|_| ConfigError::CredentialFile(field))?;
    if contents.len() < minimum {
        return Err(ConfigError::CredentialFile(field));
    }
    Ok(SecretBytes::new(contents))
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
