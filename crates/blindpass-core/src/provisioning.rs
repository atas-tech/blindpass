// SPDX-License-Identifier: AGPL-3.0-only

//! Browser-source HPKE binding and signed recipient offers. Callers supply
//! independently trusted enrollment and authenticated grant state; these
//! primitives do not perform grant admission or one-use key custody.

use crate::canon::{Value, canonicalize_value, parse_json};
use crate::fleet::{ConsumptionMode, DocumentKind, Grant, SignedEnvelope, is_valid_opaque_id};
use crate::signing::ed25519::Ed25519KeyPair;
use crate::signing::{base64_url_decode, base64_url_encode};
use std::fmt;

const DOMAIN: &[u8] = b"blindpass:fleet-browser-source:v1\0";
const MAX_METADATA_BYTES: usize = 16_384;
const FIELDS: &[&str] = &[
    "version",
    "purpose",
    "offer_id",
    "node_key_version",
    "source_unit",
    "credential",
    "recipient_public",
    "issued_at_ms",
    "expires_at_ms",
    "grant",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidProvisioningBinding;
impl fmt::Display for InvalidProvisioningBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid_provisioning_binding")
    }
}
impl std::error::Error for InvalidProvisioningBinding {}
type Result<T> = std::result::Result<T, InvalidProvisioningBinding>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProvisioningBinding {
    pub offer_id: String,
    pub node_key_version: u64,
    pub source_unit: String,
    pub credential: String,
    pub recipient_public: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub grant: Grant,
}

fn number(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(InvalidProvisioningBinding)
}
fn string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(InvalidProvisioningBinding)
}
fn identifier(value: &str, maximum: usize, unit: bool) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.starts_with('.')
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'-' | b'.')
                || unit && matches!(b, b'@' | b':')
        })
        && (!unit || value.ends_with(".service"))
}

impl BrowserProvisioningBinding {
    pub fn from_json(source: &str) -> Result<Self> {
        if source.len() > MAX_METADATA_BYTES {
            return Err(InvalidProvisioningBinding);
        }
        Self::from_value(&parse_json(source).map_err(|_| InvalidProvisioningBinding)?)
    }
    pub fn from_value(value: &Value) -> Result<Self> {
        let fields = value.as_object().ok_or(InvalidProvisioningBinding)?;
        if fields.len() != FIELDS.len()
            || fields
                .iter()
                .any(|(key, _)| !FIELDS.contains(&key.as_str()))
            || number(value, "version")? != 1
            || string(value, "purpose")? != "browser_source"
        {
            return Err(InvalidProvisioningBinding);
        }
        let binding = Self {
            offer_id: string(value, "offer_id")?,
            node_key_version: number(value, "node_key_version")?,
            source_unit: string(value, "source_unit")?,
            credential: string(value, "credential")?,
            recipient_public: string(value, "recipient_public")?,
            issued_at_ms: number(value, "issued_at_ms")?,
            expires_at_ms: number(value, "expires_at_ms")?,
            grant: Grant::from_value(value.get("grant").ok_or(InvalidProvisioningBinding)?)
                .map_err(|_| InvalidProvisioningBinding)?,
        };
        binding.to_value()?;
        Ok(binding)
    }
    pub fn to_value(&self) -> Result<Value> {
        let grant = self
            .grant
            .to_value()
            .map_err(|_| InvalidProvisioningBinding)?;
        let public =
            base64_url_decode(&self.recipient_public, 32).ok_or(InvalidProvisioningBinding)?;
        if !is_valid_opaque_id(&self.offer_id)
            || self.offer_id.len() < 16
            || self.node_key_version == 0
            || !identifier(&self.source_unit, 255, true)
            || !identifier(&self.credential, 128, false)
            || !identifier(&self.grant.unit, 255, true)
            || !is_valid_opaque_id(&self.grant.resource_id)
            || self
                .grant
                .request_event_key
                .as_ref()
                .is_none_or(|key| key.len() < 16 || !is_valid_opaque_id(key))
            || self
                .grant
                .approval_reference
                .as_ref()
                .is_some_and(|key| !is_valid_opaque_id(key))
            || public.len() != 32
            || public.iter().all(|b| *b == 0)
            || base64_url_encode(&public) != self.recipient_public
            || self.grant.mode != ConsumptionMode::BrowserSession
            || self.grant.action != "browser.session"
            || self.grant.invocation_id.len() != 32
            || !self
                .grant
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.grant.recipient_key_id
                != format!("{}-{}", self.grant.node_id, self.node_key_version)
            || self.issued_at_ms < self.grant.issued_at_ms
            || self.expires_at_ms > self.grant.expires_at_ms
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > 180_000
        {
            return Err(InvalidProvisioningBinding);
        }
        let value = Value::Object(vec![
            ("version".to_owned(), Value::Unsigned(1)),
            (
                "purpose".to_owned(),
                Value::String("browser_source".to_owned()),
            ),
            ("offer_id".to_owned(), Value::String(self.offer_id.clone())),
            (
                "node_key_version".to_owned(),
                Value::Unsigned(self.node_key_version),
            ),
            (
                "source_unit".to_owned(),
                Value::String(self.source_unit.clone()),
            ),
            (
                "credential".to_owned(),
                Value::String(self.credential.clone()),
            ),
            (
                "recipient_public".to_owned(),
                Value::String(self.recipient_public.clone()),
            ),
            (
                "issued_at_ms".to_owned(),
                Value::Unsigned(self.issued_at_ms),
            ),
            (
                "expires_at_ms".to_owned(),
                Value::Unsigned(self.expires_at_ms),
            ),
            ("grant".to_owned(), grant),
        ]);
        let bytes = canonicalize_value(&value).map_err(|_| InvalidProvisioningBinding)?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(InvalidProvisioningBinding);
        }
        Ok(value)
    }
    pub fn to_json(&self) -> Result<Vec<u8>> {
        canonicalize_value(&self.to_value()?).map_err(|_| InvalidProvisioningBinding)
    }
    pub fn aad(&self) -> Result<Vec<u8>> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&self.to_json()?);
        Ok(bytes)
    }
    /// `current` must already be authenticated against the controller pin and
    /// current broker registration/policy. Equality alone grants no authority.
    pub fn validate_against(
        &self,
        current: &Grant,
        node_key_version: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.to_value()?;
        if &self.grant != current
            || self.node_key_version != node_key_version
            || now_ms < self.issued_at_ms
            || now_ms >= self.expires_at_ms
        {
            return Err(InvalidProvisioningBinding);
        }
        Ok(())
    }
}

/// Sign only a fully validated offer under the enrolled broker's key version.
/// The caller must first authenticate current grant and fixed local destination.
pub fn sign_browser_recipient_offer(
    binding: &BrowserProvisioningBinding,
    issuer: &Ed25519KeyPair,
) -> Result<SignedEnvelope> {
    let kid = format!("{}-{}", binding.grant.node_id, binding.node_key_version);
    SignedEnvelope::sign(
        DocumentKind::RecipientOffer,
        binding.to_value()?,
        &kid,
        binding.node_key_version,
        issuer,
    )
    .map_err(|_| InvalidProvisioningBinding)
}

/// The public key and `current` grant must come from independently trusted
/// enrollment/authorization state, never from the unverified offer itself.
pub fn verify_browser_recipient_offer(
    offer: &SignedEnvelope,
    signing_public: &[u8],
    current: &Grant,
    node_key_version: u64,
    now_ms: u64,
    source_unit: &str,
    credential: &str,
) -> Result<BrowserProvisioningBinding> {
    if offer.kind() != DocumentKind::RecipientOffer || offer.epoch() != node_key_version {
        return Err(InvalidProvisioningBinding);
    }
    let binding = BrowserProvisioningBinding::from_value(offer.body())?;
    binding.validate_against(current, node_key_version, now_ms)?;
    let kid = format!("{}-{}", current.node_id, node_key_version);
    if binding.source_unit != source_unit
        || binding.credential != credential
        || !offer
            .verify(signing_public, &kid, node_key_version)
            .map_err(|_| InvalidProvisioningBinding)?
    {
        return Err(InvalidProvisioningBinding);
    }
    Ok(binding)
}

/// Ciphertext submitted by an authorized operator. This body is not authority
/// until a current controller-signed ProvisioningDelivery envelope is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProvisioningDelivery {
    pub binding: BrowserProvisioningBinding,
    pub enc: String,
    pub ciphertext: String,
}
impl BrowserProvisioningDelivery {
    pub fn from_value(value: &Value) -> Result<Self> {
        let fields = value.as_object().ok_or(InvalidProvisioningBinding)?;
        if fields.len() != 3
            || fields
                .iter()
                .any(|(key, _)| !matches!(key.as_str(), "binding" | "enc" | "ciphertext"))
        {
            return Err(InvalidProvisioningBinding);
        }
        let delivery = Self {
            binding: BrowserProvisioningBinding::from_value(
                value.get("binding").ok_or(InvalidProvisioningBinding)?,
            )?,
            enc: string(value, "enc")?,
            ciphertext: string(value, "ciphertext")?,
        };
        delivery.to_value()?;
        Ok(delivery)
    }
    pub fn sealed_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Self::decode_sealed(&self.enc, &self.ciphertext)
    }
    /// Canonical, bounded encapsulation and ciphertext without any binding, so
    /// a relay can refuse malformed submissions before touching authority state.
    pub fn decode_sealed(enc: &str, ciphertext: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let enc_bytes = base64_url_decode(enc, 32).ok_or(InvalidProvisioningBinding)?;
        let length = ciphertext
            .len()
            .checked_mul(3)
            .ok_or(InvalidProvisioningBinding)?
            / 4;
        if !(16..=65_552).contains(&length) || enc_bytes.iter().all(|byte| *byte == 0) {
            return Err(InvalidProvisioningBinding);
        }
        let ciphertext_bytes =
            base64_url_decode(ciphertext, length).ok_or(InvalidProvisioningBinding)?;
        if base64_url_encode(&enc_bytes) != enc
            || base64_url_encode(&ciphertext_bytes) != ciphertext
        {
            return Err(InvalidProvisioningBinding);
        }
        Ok((enc_bytes, ciphertext_bytes))
    }
    pub fn to_value(&self) -> Result<Value> {
        self.sealed_bytes()?;
        let value = Value::Object(vec![
            ("binding".into(), self.binding.to_value()?),
            ("enc".into(), Value::String(self.enc.clone())),
            ("ciphertext".into(), Value::String(self.ciphertext.clone())),
        ]);
        if canonicalize_value(&value)
            .map_err(|_| InvalidProvisioningBinding)?
            .len()
            > 131_072
        {
            return Err(InvalidProvisioningBinding);
        }
        Ok(value)
    }
}
