// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded HTTPS requests through the system curl binary.
//!
//! The binary receives authorization and request data through stdin as a
//! curl config stream. Credentials are not placed in argv, environment
//! variables, temporary files or stderr output.

use blindpass_core::canon::{MAX_CANONICAL_JSON_BYTES, canonicalize_json};
use blindpass_core::secret::wipe;
use std::fmt;
use std::io::{Read, Write};
use std::net::Ipv6Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

const CURL_PATH: &str = "/usr/bin/curl";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_TIMEOUT_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    InvalidOrigin,
    InvalidPath,
    InvalidToken,
    InvalidJson,
    InvalidTimeout,
    ClientUnavailable,
    RequestFailed,
    ResponseTooLarge,
    InvalidResponse,
    ProtocolMismatch,
    HttpStatus,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOrigin => "controller URL must be an HTTPS origin",
            Self::InvalidPath => "controller API path is invalid",
            Self::InvalidToken => "node token is invalid",
            Self::InvalidJson => "request body is not canonical protocol JSON",
            Self::InvalidTimeout => "request timeout is outside the supported range",
            Self::ClientUnavailable => "system curl client is unavailable",
            Self::RequestFailed => "HTTPS request failed",
            Self::ResponseTooLarge => "HTTPS response exceeded the configured size limit",
            Self::InvalidResponse => "HTTPS response was malformed",
            Self::ProtocolMismatch => "controller requires an unsupported node protocol",
            Self::HttpStatus => "controller returned a non-success status",
        })
    }
}

impl std::error::Error for TransportError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsTransport {
    origin: String,
}

impl HttpsTransport {
    pub fn new(origin: &str) -> Result<Self, TransportError> {
        let origin = origin.strip_suffix('/').unwrap_or(origin);
        if origin.len() > 2_048
            || !origin.starts_with("https://")
            || origin.bytes().any(|byte| {
                byte.is_ascii_whitespace() || matches!(byte, b'@' | b'?' | b'#' | b'\\' | b'"')
            })
        {
            return Err(TransportError::InvalidOrigin);
        }
        let authority = origin
            .strip_prefix("https://")
            .ok_or(TransportError::InvalidOrigin)?;
        if !valid_authority(authority) {
            return Err(TransportError::InvalidOrigin);
        }
        Ok(Self {
            origin: origin.to_owned(),
        })
    }

    pub fn post_json(
        &self,
        api_path: &str,
        token: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        self.request_json("POST", api_path, Some(token), Some(body), timeout)
    }

    /// Make a public JSON POST without adding an Authorization header. The
    /// one-use enrollment token stays inside the bounded stdin config pipe.
    pub fn post_public_json(
        &self,
        api_path: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        self.request_json("POST", api_path, None, Some(body), timeout)
    }

    pub fn get_json(&self, api_path: &str, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        self.request_json("GET", api_path, None, None, timeout)
    }

    fn request_json(
        &self,
        method: &str,
        api_path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        validate_path(api_path)?;
        if let Some(token) = token {
            validate_token(token)?;
        }
        if let Some(body) = body {
            if body.len() > MAX_CANONICAL_JSON_BYTES
                || canonicalize_json(
                    std::str::from_utf8(body).map_err(|_| TransportError::InvalidJson)?,
                )
                .is_err()
            {
                return Err(TransportError::InvalidJson);
            }
        }
        if method != "GET" && method != "POST" {
            return Err(TransportError::InvalidPath);
        }
        let timeout_seconds = timeout
            .as_secs()
            .saturating_add(u64::from(timeout.subsec_nanos() > 0));
        if timeout.is_zero() || timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(TransportError::InvalidTimeout);
        }
        let url = format!("{}{api_path}", self.origin);
        let mut config = build_config(&url, method, token, body, timeout_seconds);
        let mut child = Command::new(CURL_PATH)
            .arg("--disable")
            .arg("--config")
            .arg("-")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| TransportError::ClientUnavailable)?;
        let write_result = child
            .stdin
            .take()
            .ok_or(TransportError::RequestFailed)?
            .write_all(&config);
        wipe(&mut config);
        if write_result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TransportError::RequestFailed);
        }

        let mut response = Vec::new();
        let read_result = child
            .stdout
            .take()
            .ok_or(TransportError::RequestFailed)?
            .take((MAX_RESPONSE_BYTES + 5) as u64)
            .read_to_end(&mut response);
        if read_result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TransportError::RequestFailed);
        }
        if response.len() > MAX_RESPONSE_BYTES + 4 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TransportError::ResponseTooLarge);
        }
        let exit_status = child.wait().map_err(|_| TransportError::RequestFailed)?;
        if !exit_status.success() {
            return Err(TransportError::RequestFailed);
        }
        parse_response(&response)
    }
}

fn valid_authority(authority: &str) -> bool {
    if authority.is_empty() {
        return false;
    }
    if let Some(address) = authority.strip_prefix('[') {
        let Some((address, suffix)) = address.split_once(']') else {
            return false;
        };
        if address.parse::<Ipv6Addr>().is_err() {
            return false;
        }
        return suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port);
    }
    if authority.contains('[') || authority.contains(']') {
        return false;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        Some(_) => return false,
        None => (authority, None),
    };
    let valid_host = !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    valid_host && port.is_none_or(valid_port)
}

fn valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port > 0)
}

fn validate_path(path: &str) -> Result<(), TransportError> {
    if !path.starts_with("/api/v3/")
        || path.len() > 512
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        || path.split('/').any(|part| part == ".." || part == ".")
    {
        return Err(TransportError::InvalidPath);
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), TransportError> {
    if token.is_empty()
        || token.len() > 4_096
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~'))
    {
        return Err(TransportError::InvalidToken);
    }
    Ok(())
}

fn build_config(
    url: &str,
    method: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
    timeout_seconds: u64,
) -> Vec<u8> {
    let mut config = Vec::with_capacity(
        body.map_or(0, <[u8]>::len) + token.map_or(0, str::len) + url.len() + 256,
    );
    append_quoted_option(&mut config, "proto", b"=https");
    append_quoted_option(&mut config, "silent", b"true");
    append_quoted_option(&mut config, "show-error", b"true");
    append_quoted_option(&mut config, "connect-timeout", b"5");
    append_quoted_option(
        &mut config,
        "max-time",
        timeout_seconds.to_string().as_bytes(),
    );
    append_quoted_option(
        &mut config,
        "max-filesize",
        (MAX_RESPONSE_BYTES as u64 + 1).to_string().as_bytes(),
    );
    append_quoted_option(&mut config, "request", method.as_bytes());
    if body.is_some() {
        append_quoted_option(&mut config, "header", b"Content-Type: application/json");
    }
    if let Some(token) = token {
        let mut authorization = b"Authorization: Bearer ".to_vec();
        authorization.extend_from_slice(token.as_bytes());
        append_quoted_option(&mut config, "header", &authorization);
        wipe(&mut authorization);
    }
    if let Some(body) = body {
        append_quoted_option(&mut config, "data-binary", body);
    }
    append_quoted_option(&mut config, "url", url.as_bytes());
    append_quoted_option(&mut config, "write-out", b"\\n%{http_code}");
    config
}

fn append_quoted_option(config: &mut Vec<u8>, name: &str, value: &[u8]) {
    config.extend_from_slice(name.as_bytes());
    config.extend_from_slice(b" = \"");
    for byte in value {
        match byte {
            b'"' | b'\\' => {
                config.push(b'\\');
                config.push(*byte);
            }
            b'\n' => config.extend_from_slice(b"\\n"),
            b'\r' => config.extend_from_slice(b"\\r"),
            b'\t' => config.extend_from_slice(b"\\t"),
            _ => config.push(*byte),
        }
    }
    config.extend_from_slice(b"\"\n");
}

fn parse_response(response: &[u8]) -> Result<Vec<u8>, TransportError> {
    let status_start = response
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or(TransportError::InvalidResponse)?;
    let status = response
        .get(status_start + 1..)
        .filter(|status| status.len() == 3 && status.iter().all(u8::is_ascii_digit))
        .ok_or(TransportError::InvalidResponse)?;
    let status = u16::from(status[0] - b'0') * 100
        + u16::from(status[1] - b'0') * 10
        + u16::from(status[2] - b'0');
    if !(200..300).contains(&status) {
        if status == 426 {
            return Err(TransportError::ProtocolMismatch);
        }
        return Err(TransportError::HttpStatus);
    }
    let body = &response[..status_start];
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(TransportError::ResponseTooLarge);
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::{
        HttpsTransport, TransportError, build_config, parse_response, validate_path, validate_token,
    };
    use std::time::Duration;

    #[test]
    fn accepts_only_https_origins_and_fixed_api_paths() {
        assert!(HttpsTransport::new("https://controller.example").is_ok());
        for origin in [
            "http://controller.example",
            "https://user@controller.example",
            "https://controller.example/path",
            "https://controller.example?query=1",
            "https://controller.example#fragment",
            "https://controller.example\\evil",
        ] {
            assert_eq!(
                HttpsTransport::new(origin),
                Err(TransportError::InvalidOrigin),
                "{origin}"
            );
        }
        assert!(validate_path("/api/v3/node/poll").is_ok());
        assert!(validate_path("/api/v3/node/../admin").is_err());
        assert!(validate_path("https://elsewhere.invalid/api/v3/node/poll").is_err());
    }

    #[test]
    fn authorization_data_is_in_config_stdin_and_never_a_command_argument() {
        let config = build_config(
            "https://controller.example/api/v3/node/poll",
            "POST",
            Some("short-lived.token_123"),
            Some(br#"{"ack_seq":0}"#),
            35,
        );
        let config = String::from_utf8(config).unwrap();
        assert!(config.contains("Authorization: Bearer short-lived.token_123"));
        assert!(config.contains("data-binary = \"{\\\"ack_seq\\\":0}\""));
        assert!(config.contains("proto = \"=https\""));
        assert!(!validate_token("bad\ntoken").is_ok());
        assert!(validate_token("en_123.a-b").is_ok());
        let public = build_config(
            "https://controller.example/api/v3/capabilities",
            "GET",
            None,
            None,
            5,
        );
        let public = String::from_utf8(public).unwrap();
        assert!(!public.contains("Authorization"));
        assert!(public.contains("request = \"GET\""));
    }

    #[test]
    fn response_status_is_removed_and_non_success_bodies_are_not_returned() {
        assert_eq!(
            parse_response(b"{\"ok\":true}\n200"),
            Ok(b"{\"ok\":true}".to_vec())
        );
        assert_eq!(
            parse_response(b"private-body\n403"),
            Err(TransportError::HttpStatus)
        );
        assert_eq!(
            parse_response(b"protocol mismatch details\n426"),
            Err(TransportError::ProtocolMismatch)
        );
        assert_eq!(
            parse_response(b"response"),
            Err(TransportError::InvalidResponse)
        );
    }

    #[test]
    fn request_body_and_timeout_are_validated_before_spawning_curl() {
        let client = HttpsTransport::new("https://controller.example").unwrap();
        assert_eq!(
            client.post_json(
                "/api/v3/node/poll",
                "token",
                b"{\"amount\":1.5}",
                Duration::from_secs(10)
            ),
            Err(TransportError::InvalidJson)
        );
        assert_eq!(
            client.post_json(
                "/api/v3/node/poll",
                "token",
                b"{}",
                Duration::from_secs(301)
            ),
            Err(TransportError::InvalidTimeout)
        );
    }
}
