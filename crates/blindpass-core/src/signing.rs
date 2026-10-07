// SPDX-License-Identifier: AGPL-3.0-only

//! Dependency-free signing contracts shared by the controller and broker.

use crate::custody::{CryptoError, hmac_sha256};
use crate::secret::wipe;
use std::fmt;

pub mod ed25519;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserScope {
    Metadata,
    Submit,
    Status,
}

impl BrowserScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Submit => "submit",
            Self::Status => "status",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Invalid,
    Expired,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "invalid signed capability",
            Self::Expired => "expired signed capability",
        })
    }
}

impl std::error::Error for VerifyError {}

pub fn derive_secret(root_secret: &[u8], domain: &str) -> Result<String, CryptoError> {
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        return Err(CryptoError::UnsupportedHost("invalid signing domain"));
    }
    let mut input = b"blindpass:".to_vec();
    input.extend_from_slice(domain.as_bytes());
    let mut digest = hmac_sha256(root_secret, &input)?;
    wipe(&mut input);
    let secret = base64_url_encode(&digest);
    wipe(&mut digest);
    Ok(secret)
}

pub fn sign_browser_payload(
    request_id: &str,
    expires_at: u64,
    scope: BrowserScope,
    root_secret: &[u8],
) -> Result<String, CryptoError> {
    if !valid_request_id(request_id) || expires_at == 0 {
        return Err(CryptoError::UnsupportedHost("invalid browser capability"));
    }
    let derived = derive_secret(root_secret, "browser-sig")?;
    let canonical = format!("{request_id}.{expires_at}.{}", scope.as_str());
    let mut digest = hmac_sha256(derived.as_bytes(), canonical.as_bytes())?;
    let signature = base64_url_encode(&digest);
    wipe(&mut digest);
    Ok(format!("{expires_at}.{signature}"))
}

pub fn verify_browser_payload(
    request_id: &str,
    scope: BrowserScope,
    token: &str,
    root_secret: &[u8],
    now_seconds: u64,
) -> Result<u64, VerifyError> {
    if !valid_request_id(request_id) {
        return Err(VerifyError::Invalid);
    }
    let (expiry, signature) = token.split_once('.').ok_or(VerifyError::Invalid)?;
    if signature.contains('.')
        || signature.len() != 43
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(VerifyError::Invalid);
    }
    let expires_at = expiry.parse::<u64>().map_err(|_| VerifyError::Invalid)?;
    if expires_at == 0 {
        return Err(VerifyError::Invalid);
    }
    if expires_at < now_seconds {
        return Err(VerifyError::Expired);
    }
    let expected = sign_browser_payload(request_id, expires_at, scope, root_secret)
        .map_err(|_| VerifyError::Invalid)?;
    let (_, expected_signature) = expected.split_once('.').ok_or(VerifyError::Invalid)?;
    if !constant_time_equal(signature.as_bytes(), expected_signature.as_bytes()) {
        return Err(VerifyError::Invalid);
    }
    Ok(expires_at)
}

/// Fleet Source provisioning capabilities use their own derived key and a
/// distinct canonical prefix, so a legacy exchange capability (`browser-sig`)
/// can never authorize a fleet link and the reverse. Only the metadata and
/// submit scopes exist; the link also binds a named operator in controller
/// state, which this signature alone never grants.
const FLEET_PROVISIONING_DOMAIN: &str = "fleet-provisioning-sig";

fn fleet_scope(scope: BrowserScope) -> Option<&'static str> {
    match scope {
        BrowserScope::Metadata | BrowserScope::Submit => Some(scope.as_str()),
        BrowserScope::Status => None,
    }
}

fn fleet_provisioning_signature(
    link_id: &str,
    expires_at: u64,
    scope: BrowserScope,
    root_secret: &[u8],
) -> Result<String, CryptoError> {
    let scope = fleet_scope(scope)
        .filter(|_| valid_request_id(link_id) && expires_at != 0)
        .ok_or(CryptoError::UnsupportedHost(
            "invalid fleet provisioning capability",
        ))?;
    let derived = derive_secret(root_secret, FLEET_PROVISIONING_DOMAIN)?;
    let canonical = format!("fleet-provisioning.{link_id}.{expires_at}.{scope}");
    let mut digest = hmac_sha256(derived.as_bytes(), canonical.as_bytes())?;
    let signature = base64_url_encode(&digest);
    wipe(&mut digest);
    Ok(signature)
}

/// `expires_at` is in seconds; callers round the real millisecond deadline up
/// so this coarse check never denies before the authoritative database check.
pub fn sign_fleet_provisioning_capability(
    link_id: &str,
    expires_at: u64,
    scope: BrowserScope,
    root_secret: &[u8],
) -> Result<String, CryptoError> {
    let signature = fleet_provisioning_signature(link_id, expires_at, scope, root_secret)?;
    Ok(format!("{expires_at}.{signature}"))
}

pub fn verify_fleet_provisioning_capability(
    link_id: &str,
    scope: BrowserScope,
    token: &str,
    root_secret: &[u8],
    now_seconds: u64,
) -> Result<u64, VerifyError> {
    if !valid_request_id(link_id) || fleet_scope(scope).is_none() {
        return Err(VerifyError::Invalid);
    }
    let (expiry, signature) = token.split_once('.').ok_or(VerifyError::Invalid)?;
    if signature.contains('.')
        || signature.len() != 43
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(VerifyError::Invalid);
    }
    let expires_at = expiry.parse::<u64>().map_err(|_| VerifyError::Invalid)?;
    if expires_at == 0 {
        return Err(VerifyError::Invalid);
    }
    // Authenticate before reporting expiry so a stale forged token learns
    // nothing about the link.
    let expected = fleet_provisioning_signature(link_id, expires_at, scope, root_secret)
        .map_err(|_| VerifyError::Invalid)?;
    if !constant_time_equal(signature.as_bytes(), expected.as_bytes()) {
        return Err(VerifyError::Invalid);
    }
    if expires_at < now_seconds {
        return Err(VerifyError::Expired);
    }
    Ok(expires_at)
}

/// The authority/ledger identifier of an issuer signing key: `ed25519-` plus
/// the unpadded base64url public key. Public data; never derived from or
/// containing the seed.
#[must_use]
pub fn issuer_key_id(public_key: &[u8]) -> String {
    format!("ed25519-{}", base64_url_encode(public_key))
}

pub fn base64_url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((input.len() * 4).div_ceil(3));
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or_default();
        let third = chunk.get(2).copied().unwrap_or_default();
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

/// Decode canonical, unpadded base64url text and require the expected length.
pub fn base64_url_decode(input: &str, expected_len: usize) -> Option<Vec<u8>> {
    if input.is_empty()
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    if bits > 0 && accumulator & ((1_u32 << bits) - 1) != 0 {
        return None;
    }
    (output.len() == expected_len && base64_url_encode(&output) == input).then_some(output)
}

fn valid_request_id(request_id: &str) -> bool {
    request_id.len() == 64
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::{
        BrowserScope, VerifyError, derive_secret, sign_browser_payload,
        sign_fleet_provisioning_capability, verify_browser_payload,
        verify_fleet_provisioning_capability,
    };

    const ROOT_SECRET: &[u8] = b"p00-vector-root-secret";
    const REQUEST_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn domain_separated_secrets_match_the_cross_runtime_vector() {
        assert_eq!(
            derive_secret(ROOT_SECRET, "browser-sig").unwrap(),
            "wH9iVWHWBxdNCoa5EoYZQ-PP9Axey8C0Jwrwpz7Exuc"
        );
        assert_eq!(
            derive_secret(ROOT_SECRET, "agent-fulfillment").unwrap(),
            "77uVRAIUqv-1ek5FF03jVB6z9dGZZbSK_TvCJTuM-cc"
        );
    }

    #[test]
    fn browser_capabilities_match_the_cross_runtime_vector_and_keep_scopes_separate() {
        let metadata = sign_browser_payload(
            REQUEST_ID,
            1_893_456_000,
            BrowserScope::Metadata,
            ROOT_SECRET,
        )
        .unwrap();
        let submit =
            sign_browser_payload(REQUEST_ID, 1_893_456_000, BrowserScope::Submit, ROOT_SECRET)
                .unwrap();
        assert_eq!(
            metadata,
            "1893456000.QiWsb6-OdGimp89Li--_FXx0vecvkjPFlEXG7XIMebU"
        );
        assert_eq!(
            submit,
            "1893456000.sPZHTFHnECuhdZtEVdHcw_CZVQwEk7c2viseMrYK4F0"
        );
        assert_eq!(
            verify_browser_payload(
                REQUEST_ID,
                BrowserScope::Metadata,
                &metadata,
                ROOT_SECRET,
                1_893_455_999
            ),
            Ok(1_893_456_000)
        );
        assert_eq!(
            verify_browser_payload(
                REQUEST_ID,
                BrowserScope::Submit,
                &metadata,
                ROOT_SECRET,
                1_893_455_999
            ),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            verify_browser_payload(
                REQUEST_ID,
                BrowserScope::Metadata,
                &metadata,
                ROOT_SECRET,
                1_893_456_001
            ),
            Err(VerifyError::Expired)
        );
    }

    #[test]
    fn fleet_provisioning_capabilities_use_a_distinct_domain_and_keep_scopes_separate() {
        let metadata = sign_fleet_provisioning_capability(
            REQUEST_ID,
            1_893_456_000,
            BrowserScope::Metadata,
            ROOT_SECRET,
        )
        .unwrap();
        let submit = sign_fleet_provisioning_capability(
            REQUEST_ID,
            1_893_456_000,
            BrowserScope::Submit,
            ROOT_SECRET,
        )
        .unwrap();
        assert_ne!(metadata, submit);
        let legacy_metadata = sign_browser_payload(
            REQUEST_ID,
            1_893_456_000,
            BrowserScope::Metadata,
            ROOT_SECRET,
        )
        .unwrap();
        let legacy_submit =
            sign_browser_payload(REQUEST_ID, 1_893_456_000, BrowserScope::Submit, ROOT_SECRET)
                .unwrap();
        assert_ne!(metadata, legacy_metadata);
        assert_ne!(submit, legacy_submit);
        assert_eq!(
            verify_fleet_provisioning_capability(
                REQUEST_ID,
                BrowserScope::Metadata,
                &metadata,
                ROOT_SECRET,
                1_893_455_999
            ),
            Ok(1_893_456_000)
        );
        // A legacy exchange capability is never a fleet capability, and the
        // reverse, even with the same request id, expiry, scope and root.
        assert_eq!(
            verify_fleet_provisioning_capability(
                REQUEST_ID,
                BrowserScope::Metadata,
                &legacy_metadata,
                ROOT_SECRET,
                1_893_455_999
            ),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            verify_browser_payload(
                REQUEST_ID,
                BrowserScope::Metadata,
                &metadata,
                ROOT_SECRET,
                1_893_455_999
            ),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            verify_fleet_provisioning_capability(
                REQUEST_ID,
                BrowserScope::Submit,
                &metadata,
                ROOT_SECRET,
                1_893_455_999
            ),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            verify_fleet_provisioning_capability(
                REQUEST_ID,
                BrowserScope::Metadata,
                &metadata,
                ROOT_SECRET,
                1_893_456_001
            ),
            Err(VerifyError::Expired)
        );
        assert_eq!(
            verify_fleet_provisioning_capability(
                REQUEST_ID,
                BrowserScope::Metadata,
                &metadata,
                b"another-root-secret",
                1_893_455_999
            ),
            Err(VerifyError::Invalid)
        );
        let other_link = "b".repeat(64);
        assert_eq!(
            verify_fleet_provisioning_capability(
                &other_link,
                BrowserScope::Metadata,
                &metadata,
                ROOT_SECRET,
                1_893_455_999
            ),
            Err(VerifyError::Invalid)
        );
        // A tampered expiry does not verify under the original signature.
        let (_, signature) = metadata.split_once('.').unwrap();
        assert_eq!(
            verify_fleet_provisioning_capability(
                REQUEST_ID,
                BrowserScope::Metadata,
                &format!("1893456001.{signature}"),
                ROOT_SECRET,
                1_893_455_999
            ),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn fleet_provisioning_capabilities_refuse_status_scope_and_malformed_inputs() {
        assert!(
            sign_fleet_provisioning_capability(
                REQUEST_ID,
                1_893_456_000,
                BrowserScope::Status,
                ROOT_SECRET
            )
            .is_err()
        );
        assert!(
            sign_fleet_provisioning_capability(
                "short",
                1_893_456_000,
                BrowserScope::Submit,
                ROOT_SECRET
            )
            .is_err()
        );
        assert!(
            sign_fleet_provisioning_capability(REQUEST_ID, 0, BrowserScope::Submit, ROOT_SECRET)
                .is_err()
        );
        for token in ["", "1893456000", "1893456000.short", "x.AAAA", ".x"] {
            assert_eq!(
                verify_fleet_provisioning_capability(
                    REQUEST_ID,
                    BrowserScope::Submit,
                    token,
                    ROOT_SECRET,
                    1
                ),
                Err(VerifyError::Invalid),
                "{token}"
            );
        }
        assert_eq!(
            verify_fleet_provisioning_capability(
                REQUEST_ID,
                BrowserScope::Status,
                "1893456000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ROOT_SECRET,
                1
            ),
            Err(VerifyError::Invalid)
        );
    }
}
