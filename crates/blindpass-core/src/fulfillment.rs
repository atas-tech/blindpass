// SPDX-License-Identifier: AGPL-3.0-only

//! P10 cross-workload fulfillment documents.
//!
//! One issuer broker re-seals a credential it already holds to a **one-use** key
//! that the recipient broker minted and signed, and signs the sealed result with
//! its node key. HPKE base mode authenticates nobody, so the issuer signature is
//! the only evidence of who sealed; a successful decryption proves nothing about
//! the sender. These functions verify structure and signatures against keys the
//! caller took from controller-signed terms. They perform no custody access and
//! no authorization: a caller must still check its own local ceilings.

use crate::canon::{Value, canonicalize_value, parse_json};
use crate::custody::{RecipientKeyPair, sha256};
use crate::fleet::{
    DocumentError, DocumentKind, SignedEnvelope, expect_fields, is_valid_opaque_id,
    node_key_fingerprint, required_number, required_string, valid_sha256_hex, validate_token,
    validate_unit,
};
use crate::signing::ed25519::Ed25519KeyPair;
use crate::signing::{base64_url_decode, base64_url_encode};

pub type FulfillmentError = DocumentError;
type Result<T> = std::result::Result<T, DocumentError>;

pub const MODE_REENCRYPT: &str = "reencrypt";
/// Approval to loader read, and therefore the longest a set of terms may live.
pub const MAX_FULFILLMENT_LIFETIME_MS: u64 = 600_000;
/// One-use recipient key lifetime.
pub const MAX_OFFER_LIFETIME_MS: u64 = 180_000;
/// Keeps every fulfillment document under the ordinary 64 KiB node document cap.
pub const MAX_PLAINTEXT_BYTES: u64 = 8 * 1024;
const AEAD_TAG_BYTES: usize = 16;

const TERMS_DOMAIN: &[u8] = b"blindpass:fleet-fulfillment-terms:v1\0";
const INFO_DOMAIN: &[u8] = b"blindpass:fleet-fulfillment-info:v1\0";
const AAD_DOMAIN: &[u8] = b"blindpass:fleet-fulfillment-aad:v1\0";

fn invalid(label: &'static str) -> DocumentError {
    DocumentError::Invalid(label)
}

fn long_id(value: &str, label: &'static str) -> Result<()> {
    if value.len() < 16 || !is_valid_opaque_id(value) {
        return Err(invalid(label));
    }
    Ok(())
}

fn credential_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(invalid("credential name"));
    }
    Ok(())
}

fn public_key(value: &str, label: &'static str) -> Result<Vec<u8>> {
    let bytes = base64_url_decode(value, 32).ok_or(invalid(label))?;
    if bytes.iter().all(|b| *b == 0) || base64_url_encode(&bytes) != value {
        return Err(invalid(label));
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn envelope_value(envelope: &SignedEnvelope) -> Result<Value> {
    let json = envelope.to_json()?;
    Ok(parse_json(
        std::str::from_utf8(&json).map_err(|_| invalid("envelope encoding"))?,
    )?)
}

/// Re-parse a freshly signed envelope so its body carries canonical key order,
/// making structural equality agree with an envelope parsed off the wire.
fn normalized(envelope: SignedEnvelope) -> Result<SignedEnvelope> {
    let json = envelope.to_json()?;
    SignedEnvelope::from_json(std::str::from_utf8(&json).map_err(|_| invalid("envelope"))?)
}

fn envelope_from_value(value: &Value, kind: DocumentKind) -> Result<SignedEnvelope> {
    let bytes = canonicalize_value(value)?;
    let envelope =
        SignedEnvelope::from_json(std::str::from_utf8(&bytes).map_err(|_| invalid("envelope"))?)?;
    if envelope.kind() != kind {
        return Err(invalid("envelope kind"));
    }
    Ok(envelope)
}

fn string_field(value: &Value, key: &str) -> Result<String> {
    Ok(required_string(value, key)?.to_owned())
}

fn optional_string(value: &Value, key: &str, label: &'static str) -> Result<Option<String>> {
    value
        .get(key)
        .map(|v| v.as_str().map(str::to_owned).ok_or(invalid(label)))
        .transpose()
}

// ---------------------------------------------------------------- terms

/// One side of a fulfillment as the controller attests it: the registered
/// workload and the enrolled node keys the operator approved by fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentParty {
    pub node_id: String,
    pub workload_id: String,
    pub unit: String,
    pub credential: String,
    pub registration_version: u64,
    pub key_version: u64,
    pub signing_public: String,
    pub recipient_public: String,
    pub fingerprint: String,
}

impl FulfillmentParty {
    pub fn from_value(value: &Value) -> Result<Self> {
        expect_fields(
            value,
            &[
                "node_id",
                "workload_id",
                "unit",
                "credential",
                "registration_version",
                "key_version",
                "signing_public",
                "recipient_public",
                "fingerprint",
            ],
            &[],
        )?;
        let party = Self {
            node_id: string_field(value, "node_id")?,
            workload_id: string_field(value, "workload_id")?,
            unit: string_field(value, "unit")?,
            credential: string_field(value, "credential")?,
            registration_version: required_number(value, "registration_version")?,
            key_version: required_number(value, "key_version")?,
            signing_public: string_field(value, "signing_public")?,
            recipient_public: string_field(value, "recipient_public")?,
            fingerprint: string_field(value, "fingerprint")?,
        };
        party.to_value()?;
        Ok(party)
    }

    pub fn to_value(&self) -> Result<Value> {
        if !is_valid_opaque_id(&self.node_id) || !is_valid_opaque_id(&self.workload_id) {
            return Err(invalid("fulfillment party identifier"));
        }
        validate_unit(&self.unit)?;
        credential_name(&self.credential)?;
        if self.registration_version == 0 || self.key_version == 0 {
            return Err(invalid("fulfillment party version"));
        }
        let signing = public_key(&self.signing_public, "party signing key")?;
        let recipient = public_key(&self.recipient_public, "party recipient key")?;
        if node_key_fingerprint(&signing, &recipient)? != self.fingerprint {
            return Err(invalid("party fingerprint"));
        }
        Ok(Value::Object(vec![
            ("node_id".into(), Value::String(self.node_id.clone())),
            (
                "workload_id".into(),
                Value::String(self.workload_id.clone()),
            ),
            ("unit".into(), Value::String(self.unit.clone())),
            ("credential".into(), Value::String(self.credential.clone())),
            (
                "registration_version".into(),
                Value::Unsigned(self.registration_version),
            ),
            ("key_version".into(), Value::Unsigned(self.key_version)),
            (
                "signing_public".into(),
                Value::String(self.signing_public.clone()),
            ),
            (
                "recipient_public".into(),
                Value::String(self.recipient_public.clone()),
            ),
            (
                "fingerprint".into(),
                Value::String(self.fingerprint.clone()),
            ),
        ]))
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        public_key(&self.signing_public, "party signing key")
    }

    /// The signer key id every node-signed fulfillment envelope uses.
    #[must_use]
    pub fn key_id(&self) -> String {
        format!("{}-{}", self.node_id, self.key_version)
    }
}

/// The immutable contract both brokers hold. Purpose text is deliberately
/// absent: it is untrusted display text and never selects a party or a mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentTerms {
    pub fulfillment_id: String,
    pub tenant_id: String,
    pub issuer: FulfillmentParty,
    pub recipient: FulfillmentParty,
    pub policy_version: u64,
    pub rule_id: String,
    pub approval_reference: Option<String>,
    pub prior_fulfillment_id: Option<String>,
    pub max_plaintext_bytes: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub issuer_epoch: u64,
}

impl FulfillmentTerms {
    pub fn from_value(value: &Value) -> Result<Self> {
        expect_fields(
            value,
            &[
                "version",
                "fulfillment_id",
                "tenant_id",
                "mode",
                "issuer",
                "recipient",
                "policy_version",
                "rule_id",
                "max_plaintext_bytes",
                "issued_at_ms",
                "expires_at_ms",
                "issuer_epoch",
            ],
            &["approval_reference", "prior_fulfillment_id"],
        )?;
        if required_number(value, "version")? != 1
            || required_string(value, "mode")? != MODE_REENCRYPT
        {
            return Err(invalid("fulfillment terms version or mode"));
        }
        let terms = Self {
            fulfillment_id: string_field(value, "fulfillment_id")?,
            tenant_id: string_field(value, "tenant_id")?,
            issuer: FulfillmentParty::from_value(value.get("issuer").ok_or(invalid("issuer"))?)?,
            recipient: FulfillmentParty::from_value(
                value.get("recipient").ok_or(invalid("recipient"))?,
            )?,
            policy_version: required_number(value, "policy_version")?,
            rule_id: string_field(value, "rule_id")?,
            approval_reference: optional_string(value, "approval_reference", "approval reference")?,
            prior_fulfillment_id: optional_string(value, "prior_fulfillment_id", "prior id")?,
            max_plaintext_bytes: required_number(value, "max_plaintext_bytes")?,
            issued_at_ms: required_number(value, "issued_at_ms")?,
            expires_at_ms: required_number(value, "expires_at_ms")?,
            issuer_epoch: required_number(value, "issuer_epoch")?,
        };
        terms.to_value()?;
        Ok(terms)
    }

    pub fn to_value(&self) -> Result<Value> {
        long_id(&self.fulfillment_id, "fulfillment id")?;
        if !is_valid_opaque_id(&self.tenant_id) {
            return Err(invalid("tenant id"));
        }
        validate_token(&self.rule_id, "rule id")?;
        if let Some(reference) = &self.approval_reference {
            validate_token(reference, "approval reference")?;
        }
        if let Some(prior) = &self.prior_fulfillment_id {
            long_id(prior, "prior fulfillment id")?;
        }
        if self.issuer.node_id == self.recipient.node_id
            || self.issuer.workload_id == self.recipient.workload_id
            || self.policy_version == 0
            || self.issuer_epoch == 0
            || self.max_plaintext_bytes == 0
            || self.max_plaintext_bytes > MAX_PLAINTEXT_BYTES
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_FULFILLMENT_LIFETIME_MS
        {
            return Err(invalid("fulfillment terms binding or lifetime"));
        }
        let mut fields = vec![
            ("version".into(), Value::Unsigned(1)),
            (
                "fulfillment_id".into(),
                Value::String(self.fulfillment_id.clone()),
            ),
            ("tenant_id".into(), Value::String(self.tenant_id.clone())),
            ("mode".into(), Value::String(MODE_REENCRYPT.into())),
            ("issuer".into(), self.issuer.to_value()?),
            ("recipient".into(), self.recipient.to_value()?),
            (
                "policy_version".into(),
                Value::Unsigned(self.policy_version),
            ),
            ("rule_id".into(), Value::String(self.rule_id.clone())),
            (
                "max_plaintext_bytes".into(),
                Value::Unsigned(self.max_plaintext_bytes),
            ),
            ("issued_at_ms".into(), Value::Unsigned(self.issued_at_ms)),
            ("expires_at_ms".into(), Value::Unsigned(self.expires_at_ms)),
            ("issuer_epoch".into(), Value::Unsigned(self.issuer_epoch)),
        ];
        if let Some(reference) = &self.approval_reference {
            fields.push((
                "approval_reference".into(),
                Value::String(reference.clone()),
            ));
        }
        if let Some(prior) = &self.prior_fulfillment_id {
            fields.push(("prior_fulfillment_id".into(), Value::String(prior.clone())));
        }
        Ok(Value::Object(fields))
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut input = TERMS_DOMAIN.to_vec();
        input.extend(canonicalize_value(&self.to_value()?)?);
        Ok(sha256(&input)?)
    }

    pub fn digest_hex(&self) -> Result<String> {
        Ok(hex(&self.digest()?))
    }

    /// Both signed halves of a transfer must lie inside these terms.
    fn contains_window(&self, issued_at_ms: u64, expires_at_ms: u64) -> bool {
        issued_at_ms >= self.issued_at_ms && expires_at_ms <= self.expires_at_ms
    }
}

// ---------------------------------------------------------------- offer

/// The recipient broker's one-use key for one fulfillment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentOffer {
    pub fulfillment_id: String,
    pub terms_digest: String,
    pub offer_id: String,
    pub node_id: String,
    pub node_key_version: u64,
    pub recipient_public: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl FulfillmentOffer {
    pub fn from_value(value: &Value) -> Result<Self> {
        expect_fields(
            value,
            &[
                "fulfillment_id",
                "terms_digest",
                "offer_id",
                "node_id",
                "node_key_version",
                "recipient_public",
                "issued_at_ms",
                "expires_at_ms",
            ],
            &[],
        )?;
        let offer = Self {
            fulfillment_id: string_field(value, "fulfillment_id")?,
            terms_digest: string_field(value, "terms_digest")?,
            offer_id: string_field(value, "offer_id")?,
            node_id: string_field(value, "node_id")?,
            node_key_version: required_number(value, "node_key_version")?,
            recipient_public: string_field(value, "recipient_public")?,
            issued_at_ms: required_number(value, "issued_at_ms")?,
            expires_at_ms: required_number(value, "expires_at_ms")?,
        };
        offer.to_value()?;
        Ok(offer)
    }

    pub fn to_value(&self) -> Result<Value> {
        long_id(&self.fulfillment_id, "fulfillment id")?;
        long_id(&self.offer_id, "offer id")?;
        if !valid_sha256_hex(&self.terms_digest)
            || !is_valid_opaque_id(&self.node_id)
            || self.node_key_version == 0
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_OFFER_LIFETIME_MS
        {
            return Err(invalid("fulfillment offer binding or lifetime"));
        }
        public_key(&self.recipient_public, "offer key")?;
        Ok(Value::Object(vec![
            (
                "fulfillment_id".into(),
                Value::String(self.fulfillment_id.clone()),
            ),
            (
                "terms_digest".into(),
                Value::String(self.terms_digest.clone()),
            ),
            ("offer_id".into(), Value::String(self.offer_id.clone())),
            ("node_id".into(), Value::String(self.node_id.clone())),
            (
                "node_key_version".into(),
                Value::Unsigned(self.node_key_version),
            ),
            (
                "recipient_public".into(),
                Value::String(self.recipient_public.clone()),
            ),
            ("issued_at_ms".into(), Value::Unsigned(self.issued_at_ms)),
            ("expires_at_ms".into(), Value::Unsigned(self.expires_at_ms)),
        ]))
    }

    fn recipient_key(&self) -> Result<Vec<u8>> {
        public_key(&self.recipient_public, "offer key")
    }
}

/// Sign an offer under the recipient node's signing key. The epoch of a node
/// signed envelope is the node key version, as for the browser recipient offer.
pub fn sign_offer(offer: &FulfillmentOffer, node_key: &Ed25519KeyPair) -> Result<SignedEnvelope> {
    normalized(SignedEnvelope::sign(
        DocumentKind::FulfillmentOffer,
        offer.to_value()?,
        &format!("{}-{}", offer.node_id, offer.node_key_version),
        offer.node_key_version,
        node_key,
    )?)
}

/// Verify an offer against controller-attested terms and the current time.
pub fn verify_offer(
    envelope: &SignedEnvelope,
    terms: &FulfillmentTerms,
    now_ms: u64,
) -> Result<FulfillmentOffer> {
    if envelope.kind() != DocumentKind::FulfillmentOffer {
        return Err(invalid("offer kind"));
    }
    let offer = FulfillmentOffer::from_value(envelope.body())?;
    let recipient = &terms.recipient;
    if offer.fulfillment_id != terms.fulfillment_id
        || offer.terms_digest != terms.digest_hex()?
        || offer.node_id != recipient.node_id
        || offer.node_key_version != recipient.key_version
        || envelope.epoch() != recipient.key_version
        || !terms.contains_window(offer.issued_at_ms, offer.expires_at_ms)
        || now_ms < offer.issued_at_ms
        || now_ms >= offer.expires_at_ms
        || !envelope.verify(
            &recipient.signing_bytes()?,
            &recipient.key_id(),
            recipient.key_version,
        )?
    {
        return Err(invalid("fulfillment offer"));
    }
    Ok(offer)
}

// ------------------------------------------------------------ submission

/// The issuer node's signed, sealed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentSubmit {
    pub fulfillment_id: String,
    pub terms_digest: String,
    pub offer_id: String,
    pub node_id: String,
    pub node_key_version: u64,
    pub enc: String,
    pub ciphertext: String,
    pub ciphertext_digest: String,
    pub issued_at_ms: u64,
}

impl FulfillmentSubmit {
    pub fn from_value(value: &Value) -> Result<Self> {
        expect_fields(
            value,
            &[
                "fulfillment_id",
                "terms_digest",
                "offer_id",
                "node_id",
                "node_key_version",
                "enc",
                "ciphertext",
                "ciphertext_digest",
                "issued_at_ms",
            ],
            &[],
        )?;
        let submit = Self {
            fulfillment_id: string_field(value, "fulfillment_id")?,
            terms_digest: string_field(value, "terms_digest")?,
            offer_id: string_field(value, "offer_id")?,
            node_id: string_field(value, "node_id")?,
            node_key_version: required_number(value, "node_key_version")?,
            enc: string_field(value, "enc")?,
            ciphertext: string_field(value, "ciphertext")?,
            ciphertext_digest: string_field(value, "ciphertext_digest")?,
            issued_at_ms: required_number(value, "issued_at_ms")?,
        };
        submit.to_value()?;
        Ok(submit)
    }

    pub fn to_value(&self) -> Result<Value> {
        long_id(&self.fulfillment_id, "fulfillment id")?;
        long_id(&self.offer_id, "offer id")?;
        if !valid_sha256_hex(&self.terms_digest)
            || !valid_sha256_hex(&self.ciphertext_digest)
            || !is_valid_opaque_id(&self.node_id)
            || self.node_key_version == 0
            || self.issued_at_ms == 0
        {
            return Err(invalid("fulfillment submission binding"));
        }
        self.sealed_bytes()?;
        Ok(Value::Object(vec![
            (
                "fulfillment_id".into(),
                Value::String(self.fulfillment_id.clone()),
            ),
            (
                "terms_digest".into(),
                Value::String(self.terms_digest.clone()),
            ),
            ("offer_id".into(), Value::String(self.offer_id.clone())),
            ("node_id".into(), Value::String(self.node_id.clone())),
            (
                "node_key_version".into(),
                Value::Unsigned(self.node_key_version),
            ),
            ("enc".into(), Value::String(self.enc.clone())),
            ("ciphertext".into(), Value::String(self.ciphertext.clone())),
            (
                "ciphertext_digest".into(),
                Value::String(self.ciphertext_digest.clone()),
            ),
            ("issued_at_ms".into(), Value::Unsigned(self.issued_at_ms)),
        ]))
    }

    /// Canonical, bounded encapsulation and ciphertext.
    pub fn sealed_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let enc = public_key(&self.enc, "encapsulation")?;
        let length = self
            .ciphertext
            .len()
            .checked_mul(3)
            .ok_or(invalid("ciphertext"))?
            / 4;
        let maximum = usize::try_from(MAX_PLAINTEXT_BYTES).map_err(|_| invalid("ciphertext"))?
            + AEAD_TAG_BYTES;
        if !(AEAD_TAG_BYTES + 1..=maximum).contains(&length) {
            return Err(invalid("ciphertext length"));
        }
        let ciphertext =
            base64_url_decode(&self.ciphertext, length).ok_or(invalid("ciphertext"))?;
        if base64_url_encode(&ciphertext) != self.ciphertext {
            return Err(invalid("ciphertext encoding"));
        }
        Ok((enc, ciphertext))
    }

    fn computed_digest(&self) -> Result<String> {
        let (enc, ciphertext) = self.sealed_bytes()?;
        let mut input = enc;
        input.extend_from_slice(&ciphertext);
        Ok(hex(&sha256(&input)?))
    }
}

/// HPKE `info`: binds the immutable terms.
pub fn fulfillment_info(terms: &FulfillmentTerms) -> Result<Vec<u8>> {
    let mut info = INFO_DOMAIN.to_vec();
    info.extend_from_slice(&terms.digest()?);
    Ok(info)
}

/// HPKE AAD: binds the terms to the one specific one-use key and offer.
pub fn fulfillment_aad(offer: &FulfillmentOffer) -> Result<Vec<u8>> {
    let mut aad = AAD_DOMAIN.to_vec();
    aad.extend(canonicalize_value(&Value::Object(vec![
        ("offer_id".into(), Value::String(offer.offer_id.clone())),
        (
            "recipient_public".into(),
            Value::String(offer.recipient_public.clone()),
        ),
        (
            "terms_digest".into(),
            Value::String(offer.terms_digest.clone()),
        ),
    ]))?);
    Ok(aad)
}

fn offer_matches_terms(offer: &FulfillmentOffer, terms: &FulfillmentTerms) -> Result<()> {
    if offer.fulfillment_id != terms.fulfillment_id
        || offer.terms_digest != terms.digest_hex()?
        || offer.node_id != terms.recipient.node_id
        || offer.node_key_version != terms.recipient.key_version
        || !terms.contains_window(offer.issued_at_ms, offer.expires_at_ms)
    {
        return Err(invalid("offer does not match terms"));
    }
    Ok(())
}

/// Seal `plaintext` to the verified one-use offer key and sign the result with
/// the issuer node key. The caller supplies an offer already checked with
/// [`verify_offer`], and owns wiping `plaintext`.
pub fn seal_submit(
    terms: &FulfillmentTerms,
    offer: &FulfillmentOffer,
    plaintext: &[u8],
    issuer_key: &Ed25519KeyPair,
    now_ms: u64,
) -> Result<SignedEnvelope> {
    offer_matches_terms(offer, terms)?;
    let maximum = usize::try_from(terms.max_plaintext_bytes.min(MAX_PLAINTEXT_BYTES))
        .map_err(|_| invalid("plaintext bound"))?;
    if plaintext.is_empty()
        || plaintext.len() > maximum
        || issuer_key.public_key().as_slice() != terms.issuer.signing_bytes()?.as_slice()
        || now_ms < offer.issued_at_ms
        || now_ms >= offer.expires_at_ms
        || now_ms < terms.issued_at_ms
        || now_ms >= terms.expires_at_ms
    {
        return Err(invalid("fulfillment sealing bound"));
    }
    let sealed = RecipientKeyPair::seal_with_info(
        &offer.recipient_key()?,
        plaintext,
        &fulfillment_info(terms)?,
        &fulfillment_aad(offer)?,
    )?;
    let mut digest_input = sealed.enc.clone();
    digest_input.extend_from_slice(&sealed.ciphertext);
    let submit = FulfillmentSubmit {
        fulfillment_id: terms.fulfillment_id.clone(),
        terms_digest: offer.terms_digest.clone(),
        offer_id: offer.offer_id.clone(),
        node_id: terms.issuer.node_id.clone(),
        node_key_version: terms.issuer.key_version,
        enc: base64_url_encode(&sealed.enc),
        ciphertext: base64_url_encode(&sealed.ciphertext),
        ciphertext_digest: hex(&sha256(&digest_input)?),
        issued_at_ms: now_ms,
    };
    normalized(SignedEnvelope::sign(
        DocumentKind::FulfillmentSubmit,
        submit.to_value()?,
        &terms.issuer.key_id(),
        terms.issuer.key_version,
        issuer_key,
    )?)
}

/// Verify the issuer node's signature and every binding to the terms and the
/// offer. This is the only evidence of the sender.
pub fn verify_submit(
    envelope: &SignedEnvelope,
    terms: &FulfillmentTerms,
    offer: &FulfillmentOffer,
) -> Result<FulfillmentSubmit> {
    if envelope.kind() != DocumentKind::FulfillmentSubmit {
        return Err(invalid("submission kind"));
    }
    offer_matches_terms(offer, terms)?;
    let submit = FulfillmentSubmit::from_value(envelope.body())?;
    let issuer = &terms.issuer;
    if submit.fulfillment_id != terms.fulfillment_id
        || submit.terms_digest != terms.digest_hex()?
        || submit.offer_id != offer.offer_id
        || submit.node_id != issuer.node_id
        || submit.node_key_version != issuer.key_version
        || envelope.epoch() != issuer.key_version
        || submit.ciphertext_digest != submit.computed_digest()?
        || !terms.contains_window(submit.issued_at_ms, submit.issued_at_ms.saturating_add(1))
        || !envelope.verify(
            &issuer.signing_bytes()?,
            &issuer.key_id(),
            issuer.key_version,
        )?
    {
        return Err(invalid("fulfillment submission"));
    }
    Ok(submit)
}

// ------------------------------------------------------ controller documents

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FulfillmentSide {
    Issuer,
    Recipient,
}

impl FulfillmentSide {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Recipient => "recipient",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "issuer" => Some(Self::Issuer),
            "recipient" => Some(Self::Recipient),
            _ => None,
        }
    }
}

/// Controller-signed, one per side. The recipient side carries only the terms;
/// the issuer side additionally carries the recipient broker's signed offer, so
/// the issuer seals to a key the recipient node itself minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentAuthorization {
    pub side: FulfillmentSide,
    pub terms: FulfillmentTerms,
    pub offer: Option<SignedEnvelope>,
}

impl FulfillmentAuthorization {
    pub fn from_value(value: &Value) -> Result<Self> {
        expect_fields(value, &["side", "terms"], &["offer"])?;
        let side = FulfillmentSide::parse(required_string(value, "side")?)
            .ok_or(invalid("authorization side"))?;
        let offer = value
            .get("offer")
            .map(|v| envelope_from_value(v, DocumentKind::FulfillmentOffer))
            .transpose()?;
        let authorization = Self {
            side,
            terms: FulfillmentTerms::from_value(value.get("terms").ok_or(invalid("terms"))?)?,
            offer,
        };
        authorization.to_value()?;
        Ok(authorization)
    }

    pub fn to_value(&self) -> Result<Value> {
        let mut fields = vec![
            ("side".into(), Value::String(self.side.as_str().into())),
            ("terms".into(), self.terms.to_value()?),
        ];
        match (self.side, &self.offer) {
            (FulfillmentSide::Recipient, None) => {}
            (FulfillmentSide::Issuer, Some(offer)) => {
                if offer.kind() != DocumentKind::FulfillmentOffer {
                    return Err(invalid("authorization offer kind"));
                }
                let parsed = FulfillmentOffer::from_value(offer.body())?;
                offer_matches_terms(&parsed, &self.terms)?;
                fields.push(("offer".into(), envelope_value(offer)?));
            }
            _ => return Err(invalid("authorization offer presence")),
        }
        Ok(Value::Object(fields))
    }
}

/// Controller-signed, to the recipient node: terms, its own offer and the
/// issuer's signed submission, verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentDelivery {
    pub terms: FulfillmentTerms,
    pub offer: SignedEnvelope,
    pub submit: SignedEnvelope,
}

impl FulfillmentDelivery {
    pub fn from_value(value: &Value) -> Result<Self> {
        expect_fields(value, &["terms", "offer", "submit"], &[])?;
        let delivery = Self {
            terms: FulfillmentTerms::from_value(value.get("terms").ok_or(invalid("terms"))?)?,
            offer: envelope_from_value(
                value.get("offer").ok_or(invalid("offer"))?,
                DocumentKind::FulfillmentOffer,
            )?,
            submit: envelope_from_value(
                value.get("submit").ok_or(invalid("submit"))?,
                DocumentKind::FulfillmentSubmit,
            )?,
        };
        delivery.to_value()?;
        Ok(delivery)
    }

    pub fn to_value(&self) -> Result<Value> {
        let offer = FulfillmentOffer::from_value(self.offer.body())?;
        offer_matches_terms(&offer, &self.terms)?;
        let submit = FulfillmentSubmit::from_value(self.submit.body())?;
        if submit.fulfillment_id != self.terms.fulfillment_id
            || submit.terms_digest != offer.terms_digest
            || submit.offer_id != offer.offer_id
        {
            return Err(invalid("delivery bindings"));
        }
        Ok(Value::Object(vec![
            ("terms".into(), self.terms.to_value()?),
            ("offer".into(), envelope_value(&self.offer)?),
            ("submit".into(), envelope_value(&self.submit)?),
        ]))
    }

    /// Check both node signatures against the keys in the terms. The recipient
    /// broker must still confirm that the offer is its own live one-use key.
    pub fn verify(&self, now_ms: u64) -> Result<(FulfillmentOffer, FulfillmentSubmit)> {
        let offer = verify_offer(&self.offer, &self.terms, now_ms)?;
        let submit = verify_submit(&self.submit, &self.terms, &offer)?;
        Ok((offer, submit))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Operator,
    Expired,
    Policy,
    Recovery,
    FeatureDisabled,
    Failed,
}

impl RevocationReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Expired => "expired",
            Self::Policy => "policy",
            Self::Recovery => "recovery",
            Self::FeatureDisabled => "feature_disabled",
            Self::Failed => "failed",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "operator" => Self::Operator,
            "expired" => Self::Expired,
            "policy" => Self::Policy,
            "recovery" => Self::Recovery,
            "feature_disabled" => Self::FeatureDisabled,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// Controller-signed, to both nodes. Deletes only what the brokers hold for the
/// fulfillment; it recalls nothing the recipient unit already read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentRevocation {
    pub fulfillment_id: String,
    pub terms_digest: String,
    pub node_id: String,
    pub reason: RevocationReason,
    pub revoked_at_ms: u64,
    pub retain_until_ms: u64,
    pub issuer_epoch: u64,
}

impl FulfillmentRevocation {
    pub fn from_value(value: &Value) -> Result<Self> {
        expect_fields(
            value,
            &[
                "fulfillment_id",
                "terms_digest",
                "node_id",
                "reason",
                "revoked_at_ms",
                "retain_until_ms",
                "issuer_epoch",
            ],
            &[],
        )?;
        let revocation = Self {
            fulfillment_id: string_field(value, "fulfillment_id")?,
            terms_digest: string_field(value, "terms_digest")?,
            node_id: string_field(value, "node_id")?,
            reason: RevocationReason::parse(required_string(value, "reason")?)
                .ok_or(invalid("revocation reason"))?,
            revoked_at_ms: required_number(value, "revoked_at_ms")?,
            retain_until_ms: required_number(value, "retain_until_ms")?,
            issuer_epoch: required_number(value, "issuer_epoch")?,
        };
        revocation.to_value()?;
        Ok(revocation)
    }

    pub fn to_value(&self) -> Result<Value> {
        long_id(&self.fulfillment_id, "fulfillment id")?;
        if !valid_sha256_hex(&self.terms_digest)
            || !is_valid_opaque_id(&self.node_id)
            || self.revoked_at_ms == 0
            || self.retain_until_ms < self.revoked_at_ms
            || self.issuer_epoch == 0
        {
            return Err(invalid("fulfillment revocation binding"));
        }
        Ok(Value::Object(vec![
            (
                "fulfillment_id".into(),
                Value::String(self.fulfillment_id.clone()),
            ),
            (
                "terms_digest".into(),
                Value::String(self.terms_digest.clone()),
            ),
            ("node_id".into(), Value::String(self.node_id.clone())),
            ("reason".into(), Value::String(self.reason.as_str().into())),
            ("revoked_at_ms".into(), Value::Unsigned(self.revoked_at_ms)),
            (
                "retain_until_ms".into(),
                Value::Unsigned(self.retain_until_ms),
            ),
            ("issuer_epoch".into(), Value::Unsigned(self.issuer_epoch)),
        ]))
    }
}

// ----------------------------------------------------------- node results

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultState {
    /// Recipient broker opened the delivery and holds the credential.
    Stored,
    /// The recipient unit read the credential through the loader.
    Consumed,
    /// Either broker refused or could not complete; `code` says why.
    Failed,
}

impl ResultState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Consumed => "consumed",
            Self::Failed => "failed",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "stored" => Self::Stored,
            "consumed" => Self::Consumed,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// Body of a `fulfillment_result` node event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentResult {
    pub fulfillment_id: String,
    pub terms_digest: String,
    pub side: FulfillmentSide,
    pub state: ResultState,
    pub code: Option<String>,
    pub observed_at_ms: u64,
}

impl FulfillmentResult {
    pub fn from_value(value: &Value) -> Result<Self> {
        expect_fields(
            value,
            &[
                "fulfillment_id",
                "terms_digest",
                "side",
                "state",
                "observed_at_ms",
            ],
            &["code"],
        )?;
        let result = Self {
            fulfillment_id: string_field(value, "fulfillment_id")?,
            terms_digest: string_field(value, "terms_digest")?,
            side: FulfillmentSide::parse(required_string(value, "side")?)
                .ok_or(invalid("result side"))?,
            state: ResultState::parse(required_string(value, "state")?)
                .ok_or(invalid("result state"))?,
            code: optional_string(value, "code", "result code")?,
            observed_at_ms: required_number(value, "observed_at_ms")?,
        };
        result.to_value()?;
        Ok(result)
    }

    pub fn to_value(&self) -> Result<Value> {
        long_id(&self.fulfillment_id, "fulfillment id")?;
        if !valid_sha256_hex(&self.terms_digest) || self.observed_at_ms == 0 {
            return Err(invalid("fulfillment result binding"));
        }
        match (self.side, self.state, &self.code) {
            (FulfillmentSide::Recipient, ResultState::Stored | ResultState::Consumed, None) => {}
            (_, ResultState::Failed, Some(code))
                if !code.is_empty()
                    && code.len() <= 64
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()) => {}
            _ => return Err(invalid("fulfillment result state")),
        }
        let mut fields = vec![
            (
                "fulfillment_id".into(),
                Value::String(self.fulfillment_id.clone()),
            ),
            (
                "terms_digest".into(),
                Value::String(self.terms_digest.clone()),
            ),
            ("side".into(), Value::String(self.side.as_str().into())),
            ("state".into(), Value::String(self.state.as_str().into())),
            (
                "observed_at_ms".into(),
                Value::Unsigned(self.observed_at_ms),
            ),
        ];
        if let Some(code) = &self.code {
            fields.push(("code".into(), Value::String(code.clone())));
        }
        Ok(Value::Object(fields))
    }
}

/// Epoch rules shared with `fleet::validate_document_body`.
pub(crate) fn validate_body(kind: DocumentKind, body: &Value, epoch: u64) -> Result<()> {
    match kind {
        DocumentKind::FulfillmentAuthorization => {
            if FulfillmentAuthorization::from_value(body)?
                .terms
                .issuer_epoch
                != epoch
            {
                return Err(invalid("fulfillment authorization epoch"));
            }
        }
        DocumentKind::FulfillmentDelivery => {
            if FulfillmentDelivery::from_value(body)?.terms.issuer_epoch != epoch {
                return Err(invalid("fulfillment delivery epoch"));
            }
        }
        DocumentKind::FulfillmentRevocation => {
            if FulfillmentRevocation::from_value(body)?.issuer_epoch != epoch {
                return Err(invalid("fulfillment revocation epoch"));
            }
        }
        DocumentKind::FulfillmentOffer => {
            if FulfillmentOffer::from_value(body)?.node_key_version != epoch {
                return Err(invalid("fulfillment offer key epoch"));
            }
        }
        DocumentKind::FulfillmentSubmit => {
            if FulfillmentSubmit::from_value(body)?.node_key_version != epoch {
                return Err(invalid("fulfillment submission key epoch"));
            }
        }
        _ => return Err(invalid("not a fulfillment document")),
    }
    Ok(())
}
