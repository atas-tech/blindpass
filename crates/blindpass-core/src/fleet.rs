// SPDX-License-Identifier: AGPL-3.0-only

//! Signed, versioned documents exchanged between the controller and a node.

use crate::canon::{CanonicalError, Value, canonicalize_value, parse_json};
use crate::custody::{CryptoError, sha256};
use crate::signing::base64_url_encode;
use crate::signing::ed25519::{Ed25519KeyPair, verify};
use std::collections::HashSet;
use std::fmt;

const DOCUMENT_VERSION: u64 = 1;
const DOCUMENT_DOMAIN: &[u8] = b"blindpass:fleet-document:v1\0";
const SIGNATURE_BYTES: usize = 64;
const ENROLLMENT_DOMAIN: &[u8] = b"blindpass:fleet-enrollment-proof:v1\0";
const FINGERPRINT_DOMAIN: &[u8] = b"blindpass:fleet-node-fingerprint:v1\0";
const NODE_CHALLENGE_DOMAIN: &[u8] = b"blindpass:fleet-node-challenge:v1\0";
const NODE_EVENT_DOMAIN: &[u8] = b"blindpass:fleet-node-event:v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    Registration,
    PolicySnapshot,
    Grant,
    Revocation,
    NodeRevocation,
    NodeKeyRotation,
    TimeReply,
    ApplicationAck,
    OperationResult,
    AuditEvent,
}

/// Construct the exact message a newly generated node signing key must sign
/// to prove possession during one-use enrollment.
pub fn enrollment_proof_message(
    token: &str,
    signing_public_key: &[u8],
    recipient_public_key: &[u8],
) -> Result<Vec<u8>, DocumentError> {
    if token.len() < 48
        || token.len() > 256
        || signing_public_key.len() != 32
        || recipient_public_key.len() != 32
    {
        return Err(DocumentError::Invalid("enrollment proof binding"));
    }
    let fields = [token.as_bytes(), signing_public_key, recipient_public_key];
    let mut message = Vec::with_capacity(
        ENROLLMENT_DOMAIN.len() + fields.iter().map(|field| field.len() + 4).sum::<usize>(),
    );
    message.extend_from_slice(ENROLLMENT_DOMAIN);
    for field in fields {
        let length = u32::try_from(field.len())
            .map_err(|_| DocumentError::Invalid("enrollment proof field"))?;
        message.extend_from_slice(&length.to_be_bytes());
        message.extend_from_slice(field);
    }
    Ok(message)
}

/// Fingerprint both node public keys as one operator-verifiable identity.
pub fn node_key_fingerprint(
    signing_public_key: &[u8],
    recipient_public_key: &[u8],
) -> Result<String, CryptoError> {
    if signing_public_key.len() != 32 || recipient_public_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut input = Vec::with_capacity(FINGERPRINT_DOMAIN.len() + 64);
    input.extend_from_slice(FINGERPRINT_DOMAIN);
    input.extend_from_slice(signing_public_key);
    input.extend_from_slice(recipient_public_key);
    let digest = sha256(&input)?;
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Canonical, domain-separated message the broker signs for a node channel
/// challenge. The capability hash binds the negotiation to its enrollment
/// snapshot without asking the relay to authorize capability changes.
#[allow(clippy::too_many_arguments)] // Keep every signed challenge binding explicit at call sites.
pub fn node_session_challenge_message(
    tenant_id: &str,
    node_id: &str,
    protocol_version: &str,
    nonce: &str,
    capabilities_hash: &str,
    key_version: u64,
    issuer_epoch: u64,
    controller_time_ms: i64,
    expires_at_ms: i64,
) -> Result<Vec<u8>, DocumentError> {
    if !valid_identifier(tenant_id)
        || !valid_identifier(node_id)
        || protocol_version != "blindpass-node/1"
        || nonce.len() != 43
        || !valid_base64url_text(nonce)
        || !valid_sha256_hex(capabilities_hash)
        || key_version == 0
        || issuer_epoch == 0
        || controller_time_ms <= 0
        || expires_at_ms <= controller_time_ms
        || expires_at_ms.saturating_sub(controller_time_ms) > 60_000
    {
        return Err(DocumentError::Invalid("node challenge binding"));
    }
    canonical_domain_message(
        NODE_CHALLENGE_DOMAIN,
        &Value::Object(vec![
            (
                "audience".to_owned(),
                Value::String("blindpass-node".to_owned()),
            ),
            (
                "capabilities_hash".to_owned(),
                Value::String(capabilities_hash.to_owned()),
            ),
            (
                "controller_time_ms".to_owned(),
                Value::Integer(controller_time_ms),
            ),
            ("expires_at_ms".to_owned(), Value::Integer(expires_at_ms)),
            ("issuer_epoch".to_owned(), Value::Unsigned(issuer_epoch)),
            ("key_version".to_owned(), Value::Unsigned(key_version)),
            ("node_id".to_owned(), Value::String(node_id.to_owned())),
            ("nonce".to_owned(), Value::String(nonce.to_owned())),
            (
                "protocol_version".to_owned(),
                Value::String(protocol_version.to_owned()),
            ),
            ("tenant_id".to_owned(), Value::String(tenant_id.to_owned())),
        ]),
    )
}

/// Canonical event bytes signed by the broker. This is metadata protocol
/// input; event bodies are bounded and can never contain a plaintext secret.
pub fn node_event_message(
    node_id: &str,
    idempotency_key: &str,
    kind: &str,
    body: &Value,
) -> Result<Vec<u8>, DocumentError> {
    if !valid_identifier(node_id)
        || idempotency_key.len() < 16
        || idempotency_key.len() > 128
        || !idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || !matches!(kind, "operation_request" | "operation_result" | "audit")
        || !matches!(body, Value::Object(_))
    {
        return Err(DocumentError::Invalid("node event binding"));
    }
    canonical_domain_message(
        NODE_EVENT_DOMAIN,
        &Value::Object(vec![
            ("body".to_owned(), body.clone()),
            (
                "idempotency_key".to_owned(),
                Value::String(idempotency_key.to_owned()),
            ),
            ("kind".to_owned(), Value::String(kind.to_owned())),
            ("node_id".to_owned(), Value::String(node_id.to_owned())),
        ]),
    )
}

fn canonical_domain_message(domain: &[u8], value: &Value) -> Result<Vec<u8>, DocumentError> {
    let canonical = canonicalize_value(value)?;
    let mut message = Vec::with_capacity(domain.len() + canonical.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&canonical);
    Ok(message)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_base64url_text(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

impl DocumentKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::PolicySnapshot => "policy_snapshot",
            Self::Grant => "grant",
            Self::Revocation => "revocation",
            Self::NodeRevocation => "node_revocation",
            Self::NodeKeyRotation => "node_key_rotation",
            Self::TimeReply => "time_reply",
            Self::ApplicationAck => "application_ack",
            Self::OperationResult => "operation_result",
            Self::AuditEvent => "audit_event",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "registration" => Self::Registration,
            "policy_snapshot" => Self::PolicySnapshot,
            "grant" => Self::Grant,
            "revocation" => Self::Revocation,
            "node_revocation" => Self::NodeRevocation,
            "node_key_rotation" => Self::NodeKeyRotation,
            "time_reply" => Self::TimeReply,
            "application_ack" => Self::ApplicationAck,
            "operation_result" => Self::OperationResult,
            "audit_event" => Self::AuditEvent,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub enum DocumentError {
    Canonical(CanonicalError),
    Crypto(CryptoError),
    Invalid(&'static str),
}

impl fmt::Display for DocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => write!(formatter, "invalid signed document: {error}"),
            Self::Crypto(_) => {
                formatter.write_str("signed document cryptographic operation failed")
            }
            Self::Invalid(reason) => write!(formatter, "invalid signed document: {reason}"),
        }
    }
}

impl std::error::Error for DocumentError {}

impl From<CanonicalError> for DocumentError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<CryptoError> for DocumentError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// The controller signs every envelope field except `sig`, including the
/// protocol domain, document version, key id and recovery epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    kind: DocumentKind,
    body: Value,
    key_id: String,
    epoch: u64,
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedEnvelope {
    pub fn sign(
        kind: DocumentKind,
        body: Value,
        key_id: &str,
        epoch: u64,
        issuer: &Ed25519KeyPair,
    ) -> Result<Self, DocumentError> {
        validate_key_id(key_id)?;
        if epoch == 0 {
            return Err(DocumentError::Invalid("issuer epoch"));
        }
        if !matches!(body, Value::Object(_)) {
            return Err(DocumentError::Invalid("body must be an object"));
        }
        validate_document_body(kind, &body, epoch)?;
        let unsigned = Self {
            kind,
            body,
            key_id: key_id.to_owned(),
            epoch,
            signature: [0; SIGNATURE_BYTES],
        };
        let message = unsigned.signing_bytes()?;
        let signature = issuer.sign(&message)?;
        Ok(Self {
            signature,
            ..unsigned
        })
    }

    pub fn from_json(source: &str) -> Result<Self, DocumentError> {
        let value = parse_json(source)?;
        let fields = value
            .as_object()
            .ok_or(DocumentError::Invalid("envelope must be an object"))?;
        if fields.len() != 6 {
            return Err(DocumentError::Invalid("unexpected envelope fields"));
        }
        let version = field(&value, "v")
            .and_then(Value::as_u64)
            .ok_or(DocumentError::Invalid("document version"))?;
        if version != DOCUMENT_VERSION {
            return Err(DocumentError::Invalid("unsupported document version"));
        }
        let kind_name = field(&value, "kind")
            .and_then(Value::as_str)
            .ok_or(DocumentError::Invalid("document kind"))?;
        let kind = DocumentKind::parse(kind_name)
            .ok_or(DocumentError::Invalid("unsupported document kind"))?;
        let body = field(&value, "body")
            .filter(|value| matches!(value, Value::Object(_)))
            .cloned()
            .ok_or(DocumentError::Invalid("body must be an object"))?;
        let key_id = field(&value, "kid")
            .and_then(Value::as_str)
            .ok_or(DocumentError::Invalid("key id"))?;
        validate_key_id(key_id)?;
        let epoch = field(&value, "epoch")
            .and_then(Value::as_u64)
            .filter(|epoch| *epoch > 0)
            .ok_or(DocumentError::Invalid("issuer epoch"))?;
        validate_document_body(kind, &body, epoch)?;
        let encoded_signature = field(&value, "sig")
            .and_then(Value::as_str)
            .ok_or(DocumentError::Invalid("signature"))?;
        let signature_bytes = decode_base64_url(encoded_signature)?;
        let signature: [u8; SIGNATURE_BYTES] = signature_bytes
            .try_into()
            .map_err(|_| DocumentError::Invalid("signature length"))?;
        Ok(Self {
            kind,
            body,
            key_id: key_id.to_owned(),
            epoch,
            signature,
        })
    }

    pub fn verify(
        &self,
        issuer_public_key: &[u8],
        expected_key_id: &str,
        highest_epoch: u64,
    ) -> Result<bool, DocumentError> {
        if self.key_id != expected_key_id || self.epoch < highest_epoch {
            return Ok(false);
        }
        validate_document_body(self.kind, &self.body, self.epoch)?;
        let message = self.signing_bytes()?;
        Ok(verify(issuer_public_key, &message, &self.signature)?)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, DocumentError> {
        let mut fields = self.unsigned_fields();
        fields.push((
            "sig".to_owned(),
            Value::String(base64_url_encode(&self.signature)),
        ));
        Ok(canonicalize_value(&Value::Object(fields))?)
    }

    pub fn body_json(&self) -> Result<Vec<u8>, DocumentError> {
        Ok(canonicalize_value(&self.body)?)
    }

    #[must_use]
    pub const fn kind(&self) -> DocumentKind {
        self.kind
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn body(&self) -> &Value {
        &self.body
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, DocumentError> {
        let mut message = DOCUMENT_DOMAIN.to_vec();
        message.extend(canonicalize_value(&Value::Object(self.unsigned_fields()))?);
        Ok(message)
    }

    fn unsigned_fields(&self) -> Vec<(String, Value)> {
        vec![
            ("body".to_owned(), self.body.clone()),
            ("epoch".to_owned(), Value::Unsigned(self.epoch)),
            ("kid".to_owned(), Value::String(self.key_id.clone())),
            (
                "kind".to_owned(),
                Value::String(self.kind.as_str().to_owned()),
            ),
            ("v".to_owned(), Value::Unsigned(DOCUMENT_VERSION)),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumptionMode {
    File,
    Socket,
    BrowserSession,
}

impl ConsumptionMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Socket => "socket",
            Self::BrowserSession => "browser_session",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "file" => Self::File,
            "socket" => Self::Socket,
            "browser_session" => Self::BrowserSession,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub node_id: String,
    pub workload_id: String,
    pub unit: String,
    pub account: String,
    pub invocation_id: Option<String>,
    pub status: String,
    pub consumption_mode: ConsumptionMode,
    pub registration_version: u64,
    pub policy_version: u64,
    pub local_ceiling_seconds: u64,
}

impl Registration {
    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        expect_fields(
            value,
            &[
                "node_id",
                "workload_id",
                "unit",
                "account",
                "consumption_mode",
                "status",
                "registration_version",
                "policy_version",
                "local_ceiling_seconds",
            ],
            &["invocation_id"],
        )?;
        let mode = ConsumptionMode::parse(required_string(value, "consumption_mode")?)
            .ok_or(DocumentError::Invalid("consumption mode"))?;
        let registration = Self {
            node_id: required_string(value, "node_id")?.to_owned(),
            workload_id: required_string(value, "workload_id")?.to_owned(),
            unit: required_string(value, "unit")?.to_owned(),
            account: required_string(value, "account")?.to_owned(),
            invocation_id: value
                .get("invocation_id")
                .map(|invocation| {
                    invocation
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(DocumentError::Invalid("invocation id"))
                })
                .transpose()?,
            status: required_string(value, "status")?.to_owned(),
            consumption_mode: mode,
            registration_version: required_number(value, "registration_version")?,
            policy_version: required_number(value, "policy_version")?,
            local_ceiling_seconds: required_number(value, "local_ceiling_seconds")?,
        };
        registration.to_value()?;
        Ok(registration)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        validate_token(&self.node_id, "node id")?;
        validate_token(&self.workload_id, "workload id")?;
        validate_unit(&self.unit)?;
        validate_account(&self.account)?;
        if let Some(invocation_id) = &self.invocation_id {
            validate_token(invocation_id, "invocation id")?;
        }
        if !matches!(self.status.as_str(), "active" | "revoked") {
            return Err(DocumentError::Invalid("registration status"));
        }
        validate_ceiling(self.local_ceiling_seconds)?;
        if self.registration_version == 0 || self.policy_version == 0 {
            return Err(DocumentError::Invalid("registration or policy version"));
        }
        let mut fields = vec![
            ("account".to_owned(), Value::String(self.account.clone())),
            (
                "consumption_mode".to_owned(),
                Value::String(self.consumption_mode.as_str().to_owned()),
            ),
            (
                "local_ceiling_seconds".to_owned(),
                Value::Unsigned(self.local_ceiling_seconds),
            ),
            ("node_id".to_owned(), Value::String(self.node_id.clone())),
            (
                "policy_version".to_owned(),
                Value::Unsigned(self.policy_version),
            ),
            (
                "registration_version".to_owned(),
                Value::Unsigned(self.registration_version),
            ),
            ("status".to_owned(), Value::String(self.status.clone())),
            ("unit".to_owned(), Value::String(self.unit.clone())),
            (
                "workload_id".to_owned(),
                Value::String(self.workload_id.clone()),
            ),
        ];
        if let Some(invocation_id) = &self.invocation_id {
            fields.push((
                "invocation_id".to_owned(),
                Value::String(invocation_id.clone()),
            ));
        }
        Ok(Value::Object(fields))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub policy_version: u64,
    pub local_ceiling_seconds: u64,
    pub allowed_actions: Vec<String>,
    pub allowed_modes: Vec<ConsumptionMode>,
}

impl PolicySnapshot {
    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        expect_fields(
            value,
            &[
                "policy_version",
                "local_ceiling_seconds",
                "allowed_actions",
                "allowed_modes",
            ],
            &[],
        )?;
        let allowed_actions = value
            .get("allowed_actions")
            .and_then(Value::as_array)
            .ok_or(DocumentError::Invalid("allowed actions"))?
            .iter()
            .map(|action| {
                action
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(DocumentError::Invalid("allowed action"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allowed_modes = value
            .get("allowed_modes")
            .and_then(Value::as_array)
            .ok_or(DocumentError::Invalid("allowed modes"))?
            .iter()
            .map(|mode| {
                mode.as_str()
                    .and_then(ConsumptionMode::parse)
                    .ok_or(DocumentError::Invalid("consumption mode"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let policy = Self {
            policy_version: required_number(value, "policy_version")?,
            local_ceiling_seconds: required_number(value, "local_ceiling_seconds")?,
            allowed_actions,
            allowed_modes,
        };
        policy.to_value()?;
        Ok(policy)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        validate_ceiling(self.local_ceiling_seconds)?;
        if self.policy_version == 0
            || self.allowed_actions.len() > 100
            || self.allowed_modes.len() > 3
        {
            return Err(DocumentError::Invalid("policy snapshot bounds"));
        }
        for action in &self.allowed_actions {
            if action.is_empty()
                || action.len() > 100
                || !action
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.')
            {
                return Err(DocumentError::Invalid("policy action"));
            }
        }
        let mut actions = self.allowed_actions.clone();
        actions.sort();
        actions.dedup();
        if actions.len() != self.allowed_actions.len() {
            return Err(DocumentError::Invalid("duplicate policy action"));
        }
        let mut modes = self
            .allowed_modes
            .iter()
            .map(|mode| mode.as_str().to_owned())
            .collect::<Vec<_>>();
        modes.sort();
        modes.dedup();
        if modes.len() != self.allowed_modes.len() {
            return Err(DocumentError::Invalid("duplicate consumption mode"));
        }
        Ok(Value::Object(vec![
            (
                "allowed_actions".to_owned(),
                Value::Array(actions.into_iter().map(Value::String).collect()),
            ),
            (
                "allowed_modes".to_owned(),
                Value::Array(modes.into_iter().map(Value::String).collect()),
            ),
            (
                "local_ceiling_seconds".to_owned(),
                Value::Unsigned(self.local_ceiling_seconds),
            ),
            (
                "policy_version".to_owned(),
                Value::Unsigned(self.policy_version),
            ),
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub operation_id: String,
    pub node_id: String,
    pub workload_id: String,
    pub invocation_id: String,
    pub unit: String,
    pub account: String,
    pub resource_id: String,
    pub recipient_key_id: String,
    pub policy_version: u64,
    pub approval_reference: Option<String>,
    pub action: String,
    pub mode: ConsumptionMode,
    pub audience: String,
    pub issuer_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub local_ceiling_seconds: u64,
}

impl Grant {
    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        expect_fields(
            value,
            &[
                "id",
                "operation_id",
                "node_id",
                "workload_id",
                "invocation_id",
                "unit",
                "account",
                "resource_id",
                "recipient_key_id",
                "policy_version",
                "action",
                "mode",
                "audience",
                "issuer_epoch",
                "issued_at_ms",
                "expires_at_ms",
                "local_ceiling_seconds",
            ],
            &["approval_reference"],
        )?;
        let mode = ConsumptionMode::parse(required_string(value, "mode")?)
            .ok_or(DocumentError::Invalid("consumption mode"))?;
        let grant = Self {
            id: required_string(value, "id")?.to_owned(),
            operation_id: required_string(value, "operation_id")?.to_owned(),
            node_id: required_string(value, "node_id")?.to_owned(),
            workload_id: required_string(value, "workload_id")?.to_owned(),
            invocation_id: required_string(value, "invocation_id")?.to_owned(),
            unit: required_string(value, "unit")?.to_owned(),
            account: required_string(value, "account")?.to_owned(),
            resource_id: required_string(value, "resource_id")?.to_owned(),
            recipient_key_id: required_string(value, "recipient_key_id")?.to_owned(),
            policy_version: required_number(value, "policy_version")?,
            approval_reference: value
                .get("approval_reference")
                .map(|reference| {
                    reference
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(DocumentError::Invalid("approval reference"))
                })
                .transpose()?,
            action: required_string(value, "action")?.to_owned(),
            mode,
            audience: required_string(value, "audience")?.to_owned(),
            issuer_epoch: required_number(value, "issuer_epoch")?,
            issued_at_ms: required_number(value, "issued_at_ms")?,
            expires_at_ms: required_number(value, "expires_at_ms")?,
            local_ceiling_seconds: required_number(value, "local_ceiling_seconds")?,
        };
        grant.to_value()?;
        Ok(grant)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        for (value, label) in [
            (self.id.as_str(), "grant id"),
            (self.operation_id.as_str(), "operation id"),
            (self.node_id.as_str(), "node id"),
            (self.workload_id.as_str(), "workload id"),
            (self.invocation_id.as_str(), "invocation id"),
            (self.resource_id.as_str(), "resource id"),
        ] {
            validate_token(value, label)?;
        }
        validate_unit(&self.unit)?;
        validate_account(&self.account)?;
        validate_token(&self.recipient_key_id, "recipient key id")?;
        validate_ceiling(self.local_ceiling_seconds)?;
        if self.policy_version == 0
            || self.issuer_epoch == 0
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > 3_600_000
            || self.audience != "blindpass-node"
            || self.action != "noop.marker"
        {
            return Err(DocumentError::Invalid("grant binding or lifetime"));
        }
        let mut fields = vec![
            ("account".to_owned(), Value::String(self.account.clone())),
            ("action".to_owned(), Value::String(self.action.clone())),
            ("audience".to_owned(), Value::String(self.audience.clone())),
            (
                "expires_at_ms".to_owned(),
                Value::Unsigned(self.expires_at_ms),
            ),
            ("id".to_owned(), Value::String(self.id.clone())),
            (
                "invocation_id".to_owned(),
                Value::String(self.invocation_id.clone()),
            ),
            (
                "issued_at_ms".to_owned(),
                Value::Unsigned(self.issued_at_ms),
            ),
            (
                "issuer_epoch".to_owned(),
                Value::Unsigned(self.issuer_epoch),
            ),
            (
                "local_ceiling_seconds".to_owned(),
                Value::Unsigned(self.local_ceiling_seconds),
            ),
            (
                "mode".to_owned(),
                Value::String(self.mode.as_str().to_owned()),
            ),
            ("node_id".to_owned(), Value::String(self.node_id.clone())),
            (
                "operation_id".to_owned(),
                Value::String(self.operation_id.clone()),
            ),
            (
                "policy_version".to_owned(),
                Value::Unsigned(self.policy_version),
            ),
            (
                "recipient_key_id".to_owned(),
                Value::String(self.recipient_key_id.clone()),
            ),
            (
                "resource_id".to_owned(),
                Value::String(self.resource_id.clone()),
            ),
            ("unit".to_owned(), Value::String(self.unit.clone())),
            (
                "workload_id".to_owned(),
                Value::String(self.workload_id.clone()),
            ),
        ];
        if let Some(reference) = &self.approval_reference {
            validate_token(reference, "approval reference")?;
            fields.push((
                "approval_reference".to_owned(),
                Value::String(reference.clone()),
            ));
        }
        Ok(Value::Object(fields))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub grant_id: String,
    pub node_id: String,
    pub reason: String,
    pub revoked_at_ms: u64,
    pub retain_until_ms: u64,
    pub issuer_epoch: u64,
}

impl Revocation {
    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        expect_fields(
            value,
            &[
                "grant_id",
                "node_id",
                "reason",
                "revoked_at_ms",
                "retain_until_ms",
                "issuer_epoch",
            ],
            &[],
        )?;
        let revocation = Self {
            grant_id: required_string(value, "grant_id")?.to_owned(),
            node_id: required_string(value, "node_id")?.to_owned(),
            reason: required_string(value, "reason")?.to_owned(),
            revoked_at_ms: required_number(value, "revoked_at_ms")?,
            retain_until_ms: required_number(value, "retain_until_ms")?,
            issuer_epoch: required_number(value, "issuer_epoch")?,
        };
        revocation.to_value()?;
        Ok(revocation)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        validate_token(&self.grant_id, "grant id")?;
        validate_token(&self.node_id, "node id")?;
        if !matches!(
            self.reason.as_str(),
            "operator" | "policy" | "expired" | "cancelled" | "key_rotation"
        ) || self.revoked_at_ms == 0
            || self.retain_until_ms <= self.revoked_at_ms
            || self.issuer_epoch == 0
        {
            return Err(DocumentError::Invalid("revocation binding"));
        }
        Ok(Value::Object(vec![
            ("grant_id".to_owned(), Value::String(self.grant_id.clone())),
            (
                "issuer_epoch".to_owned(),
                Value::Unsigned(self.issuer_epoch),
            ),
            ("node_id".to_owned(), Value::String(self.node_id.clone())),
            ("reason".to_owned(), Value::String(self.reason.clone())),
            (
                "retain_until_ms".to_owned(),
                Value::Unsigned(self.retain_until_ms),
            ),
            (
                "revoked_at_ms".to_owned(),
                Value::Unsigned(self.revoked_at_ms),
            ),
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRevocation {
    pub node_id: String,
    pub revoked_at_ms: u64,
    pub issuer_epoch: u64,
}

/// A broker generated replacement key pair, approved by an operator and
/// delivered as a controller signed document. The broker verifies that the
/// public keys match its locally staged private pair before activating it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeKeyRotation {
    pub node_id: String,
    pub rotation_id: String,
    pub from_key_version: u64,
    pub to_key_version: u64,
    pub signing_public: String,
    pub recipient_public: String,
    pub fingerprint: String,
    pub issuer_epoch: u64,
}

impl NodeKeyRotation {
    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        expect_fields(
            value,
            &[
                "node_id",
                "rotation_id",
                "from_key_version",
                "to_key_version",
                "signing_public",
                "recipient_public",
                "fingerprint",
                "issuer_epoch",
            ],
            &[],
        )?;
        let rotation = Self {
            node_id: required_string(value, "node_id")?.to_owned(),
            rotation_id: required_string(value, "rotation_id")?.to_owned(),
            from_key_version: required_number(value, "from_key_version")?,
            to_key_version: required_number(value, "to_key_version")?,
            signing_public: required_string(value, "signing_public")?.to_owned(),
            recipient_public: required_string(value, "recipient_public")?.to_owned(),
            fingerprint: required_string(value, "fingerprint")?.to_owned(),
            issuer_epoch: required_number(value, "issuer_epoch")?,
        };
        rotation.to_value()?;
        Ok(rotation)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        validate_token(&self.node_id, "node id")?;
        validate_token(&self.rotation_id, "rotation id")?;
        if self.from_key_version == 0
            || self.from_key_version.checked_add(1) != Some(self.to_key_version)
            || self.issuer_epoch == 0
        {
            return Err(DocumentError::Invalid("node key rotation version"));
        }
        let signing_public = decode_base64_url(&self.signing_public)?;
        let recipient_public = decode_base64_url(&self.recipient_public)?;
        if signing_public.len() != 32 || recipient_public.len() != 32 {
            return Err(DocumentError::Invalid("node key rotation public key"));
        }
        if node_key_fingerprint(&signing_public, &recipient_public)? != self.fingerprint {
            return Err(DocumentError::Invalid("node key rotation fingerprint"));
        }
        Ok(Value::Object(vec![
            (
                "fingerprint".to_owned(),
                Value::String(self.fingerprint.clone()),
            ),
            (
                "from_key_version".to_owned(),
                Value::Unsigned(self.from_key_version),
            ),
            (
                "issuer_epoch".to_owned(),
                Value::Unsigned(self.issuer_epoch),
            ),
            ("node_id".to_owned(), Value::String(self.node_id.clone())),
            (
                "recipient_public".to_owned(),
                Value::String(self.recipient_public.clone()),
            ),
            (
                "rotation_id".to_owned(),
                Value::String(self.rotation_id.clone()),
            ),
            (
                "signing_public".to_owned(),
                Value::String(self.signing_public.clone()),
            ),
            (
                "to_key_version".to_owned(),
                Value::Unsigned(self.to_key_version),
            ),
        ]))
    }
}

impl NodeRevocation {
    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        expect_fields(value, &["node_id", "revoked_at_ms", "issuer_epoch"], &[])?;
        let revocation = Self {
            node_id: required_string(value, "node_id")?.to_owned(),
            revoked_at_ms: required_number(value, "revoked_at_ms")?,
            issuer_epoch: required_number(value, "issuer_epoch")?,
        };
        revocation.to_value()?;
        Ok(revocation)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        validate_token(&self.node_id, "node id")?;
        if self.revoked_at_ms == 0 || self.issuer_epoch == 0 {
            return Err(DocumentError::Invalid("node revocation binding"));
        }
        Ok(Value::Object(vec![
            (
                "issuer_epoch".to_owned(),
                Value::Unsigned(self.issuer_epoch),
            ),
            ("node_id".to_owned(), Value::String(self.node_id.clone())),
            (
                "revoked_at_ms".to_owned(),
                Value::Unsigned(self.revoked_at_ms),
            ),
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeReply {
    pub node_id: String,
    pub challenge: String,
    pub controller_time_ms: u64,
    pub issuer_epoch: u64,
}

impl TimeReply {
    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        expect_fields(
            value,
            &["node_id", "challenge", "controller_time_ms", "issuer_epoch"],
            &[],
        )?;
        let reply = Self {
            node_id: required_string(value, "node_id")?.to_owned(),
            challenge: required_string(value, "challenge")?.to_owned(),
            controller_time_ms: required_number(value, "controller_time_ms")?,
            issuer_epoch: required_number(value, "issuer_epoch")?,
        };
        reply.to_value()?;
        Ok(reply)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        validate_token(&self.node_id, "node id")?;
        validate_token(&self.challenge, "time challenge")?;
        if self.controller_time_ms == 0 || self.issuer_epoch == 0 {
            return Err(DocumentError::Invalid("time reply binding"));
        }
        Ok(Value::Object(vec![
            (
                "challenge".to_owned(),
                Value::String(self.challenge.clone()),
            ),
            (
                "controller_time_ms".to_owned(),
                Value::Unsigned(self.controller_time_ms),
            ),
            (
                "issuer_epoch".to_owned(),
                Value::Unsigned(self.issuer_epoch),
            ),
            ("node_id".to_owned(), Value::String(self.node_id.clone())),
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationAck {
    pub node_id: String,
    pub issuer_epoch: u64,
    pub acknowledged_at_ms: u64,
    pub event_keys: Vec<String>,
}

impl ApplicationAck {
    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        expect_fields(
            value,
            &[
                "node_id",
                "issuer_epoch",
                "acknowledged_at_ms",
                "event_keys",
            ],
            &[],
        )?;
        let event_keys = value
            .get("event_keys")
            .and_then(Value::as_array)
            .ok_or(DocumentError::Invalid("application acknowledgement keys"))?
            .iter()
            .map(|key| {
                key.as_str()
                    .map(str::to_owned)
                    .ok_or(DocumentError::Invalid("application acknowledgement key"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ack = Self {
            node_id: required_string(value, "node_id")?.to_owned(),
            issuer_epoch: required_number(value, "issuer_epoch")?,
            acknowledged_at_ms: required_number(value, "acknowledged_at_ms")?,
            event_keys,
        };
        ack.to_value()?;
        Ok(ack)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        validate_token(&self.node_id, "node id")?;
        if self.issuer_epoch == 0
            || self.acknowledged_at_ms == 0
            || self.event_keys.is_empty()
            || self.event_keys.len() > 100
        {
            return Err(DocumentError::Invalid("application acknowledgement bounds"));
        }
        let mut unique = HashSet::new();
        for key in &self.event_keys {
            if key.len() < 16
                || key.len() > 128
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || !unique.insert(key.as_str())
            {
                return Err(DocumentError::Invalid("application acknowledgement key"));
            }
        }
        Ok(Value::Object(vec![
            (
                "acknowledged_at_ms".to_owned(),
                Value::Unsigned(self.acknowledged_at_ms),
            ),
            (
                "event_keys".to_owned(),
                Value::Array(self.event_keys.iter().cloned().map(Value::String).collect()),
            ),
            (
                "issuer_epoch".to_owned(),
                Value::Unsigned(self.issuer_epoch),
            ),
            ("node_id".to_owned(), Value::String(self.node_id.clone())),
        ]))
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.get(name)
}

fn validate_document_body(
    kind: DocumentKind,
    body: &Value,
    envelope_epoch: u64,
) -> Result<(), DocumentError> {
    match kind {
        DocumentKind::Registration => {
            Registration::from_value(body)?;
        }
        DocumentKind::PolicySnapshot => {
            PolicySnapshot::from_value(body)?;
        }
        DocumentKind::Grant => {
            if Grant::from_value(body)?.issuer_epoch != envelope_epoch {
                return Err(DocumentError::Invalid("grant issuer epoch"));
            }
        }
        DocumentKind::Revocation => {
            if Revocation::from_value(body)?.issuer_epoch != envelope_epoch {
                return Err(DocumentError::Invalid("revocation issuer epoch"));
            }
        }
        DocumentKind::NodeRevocation => {
            if NodeRevocation::from_value(body)?.issuer_epoch != envelope_epoch {
                return Err(DocumentError::Invalid("node revocation issuer epoch"));
            }
        }
        DocumentKind::NodeKeyRotation => {
            if NodeKeyRotation::from_value(body)?.issuer_epoch != envelope_epoch {
                return Err(DocumentError::Invalid("node key rotation issuer epoch"));
            }
        }
        DocumentKind::TimeReply => {
            if TimeReply::from_value(body)?.issuer_epoch != envelope_epoch {
                return Err(DocumentError::Invalid("time reply issuer epoch"));
            }
        }
        DocumentKind::ApplicationAck => {
            if ApplicationAck::from_value(body)?.issuer_epoch != envelope_epoch {
                return Err(DocumentError::Invalid("application acknowledgement epoch"));
            }
        }
        DocumentKind::OperationResult | DocumentKind::AuditEvent => {
            if !matches!(body, Value::Object(_)) {
                return Err(DocumentError::Invalid("body must be an object"));
            }
        }
    }
    Ok(())
}

fn expect_fields(value: &Value, required: &[&str], optional: &[&str]) -> Result<(), DocumentError> {
    let fields = value
        .as_object()
        .ok_or(DocumentError::Invalid("body must be an object"))?;
    let mut names = HashSet::new();
    for (name, _) in fields {
        if !names.insert(name.as_str())
            || (!required.contains(&name.as_str()) && !optional.contains(&name.as_str()))
        {
            return Err(DocumentError::Invalid("unexpected body fields"));
        }
    }
    if required.iter().any(|required| !names.contains(required)) {
        return Err(DocumentError::Invalid("missing body field"));
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, DocumentError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or(DocumentError::Invalid("body string field"))
}

fn required_number(value: &Value, name: &str) -> Result<u64, DocumentError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(DocumentError::Invalid("body integer field"))
}

fn validate_key_id(value: &str) -> Result<(), DocumentError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(DocumentError::Invalid("key id"));
    }
    Ok(())
}

fn validate_token(value: &str, label: &'static str) -> Result<(), DocumentError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(DocumentError::Invalid(label));
    }
    Ok(())
}

fn validate_unit(value: &str) -> Result<(), DocumentError> {
    if value.is_empty()
        || value.len() > 255
        || !value.ends_with(".service")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b':' | b'-')
        })
    {
        return Err(DocumentError::Invalid("system unit"));
    }
    Ok(())
}

fn validate_account(value: &str) -> Result<(), DocumentError> {
    if !is_valid_account_identifier(value) {
        return Err(DocumentError::Invalid("account"));
    }
    Ok(())
}

/// Accept a constrained Linux account name or a canonical non-root UID
/// selector used when the broker binds a peer directly to its kernel UID.
pub fn is_valid_account_identifier(value: &str) -> bool {
    let account_name = value.len() <= 32
        && !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        });
    let uid_selector = value.strip_prefix("uid:").is_some_and(|digits| {
        !digits.is_empty()
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && digits
                .parse::<u32>()
                .is_ok_and(|uid| uid > 0 && uid.to_string() == digits)
    });
    account_name || uid_selector
}

fn validate_ceiling(value: u64) -> Result<(), DocumentError> {
    if !(1..=3_600).contains(&value) {
        return Err(DocumentError::Invalid("local ceiling"));
    }
    Ok(())
}

fn decode_base64_url(value: &str) -> Result<Vec<u8>, DocumentError> {
    if value.is_empty()
        || value.len() % 4 == 1
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DocumentError::Invalid("base64url signature"));
    }
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(DocumentError::Invalid("base64url signature")),
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
        if bits == 0 {
            accumulator = 0;
        } else {
            accumulator &= (1_u32 << bits) - 1;
        }
    }
    if bits > 0 && accumulator & ((1_u32 << bits) - 1) != 0 {
        return Err(DocumentError::Invalid("base64url signature"));
    }
    if base64_url_encode(&output) != value {
        return Err(DocumentError::Invalid("non-canonical base64url signature"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{
        ApplicationAck, ConsumptionMode, DocumentKind, Grant, NodeKeyRotation, PolicySnapshot,
        Registration, SignedEnvelope, enrollment_proof_message, node_event_message,
        node_key_fingerprint, node_session_challenge_message,
    };
    use crate::canon::{Value, canonicalize_json};
    use crate::signing::ed25519::Ed25519KeyPair;

    const KEY_ID: &str = "controller-1";

    fn issuer() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed(&[9; 32]).unwrap()
    }

    #[test]
    fn enrollment_proof_binds_one_use_token_and_both_public_keys() {
        let signing = Ed25519KeyPair::from_seed(&[7; 32]).unwrap();
        let recipient = [8; 32];
        let message = enrollment_proof_message(
            "en_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            signing.public_key(),
            &recipient,
        )
        .unwrap();
        let signature = signing.sign(&message).unwrap();
        assert!(super::verify(signing.public_key(), &message, &signature).unwrap());
        let changed = enrollment_proof_message(
            "en_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            signing.public_key(),
            &recipient,
        )
        .unwrap();
        assert!(!super::verify(signing.public_key(), &changed, &signature).unwrap());
        assert_ne!(
            node_key_fingerprint(signing.public_key(), &recipient).unwrap(),
            node_key_fingerprint(signing.public_key(), &[9; 32]).unwrap()
        );
    }

    #[test]
    fn node_challenge_binds_identity_epoch_and_protocol_fields() {
        let nonce = "A".repeat(43);
        let message = node_session_challenge_message(
            "tenant-a",
            "nd_node-a",
            "blindpass-node/1",
            &nonce,
            &"a".repeat(64),
            1,
            3,
            1_800_000_000_000,
            1_800_000_060_000,
        )
        .unwrap();
        let key = Ed25519KeyPair::from_seed(&[7; 32]).unwrap();
        let signature = key.sign(&message).unwrap();
        assert!(super::verify(key.public_key(), &message, &signature).unwrap());

        for changed in [
            node_session_challenge_message(
                "tenant-b",
                "nd_node-a",
                "blindpass-node/1",
                &nonce,
                &"a".repeat(64),
                1,
                3,
                1_800_000_000_000,
                1_800_000_060_000,
            ),
            node_session_challenge_message(
                "tenant-a",
                "nd_node-b",
                "blindpass-node/1",
                &nonce,
                &"a".repeat(64),
                1,
                3,
                1_800_000_000_000,
                1_800_000_060_000,
            ),
            node_session_challenge_message(
                "tenant-a",
                "nd_node-a",
                "blindpass-node/1",
                &nonce,
                &"a".repeat(64),
                1,
                4,
                1_800_000_000_000,
                1_800_000_060_000,
            ),
            node_session_challenge_message(
                "tenant-a",
                "nd_node-a",
                "blindpass-node/1",
                &nonce,
                &"a".repeat(64),
                2,
                3,
                1_800_000_000_000,
                1_800_000_060_000,
            ),
            node_session_challenge_message(
                "tenant-a",
                "nd_node-a",
                "blindpass-node/2",
                &nonce,
                &"a".repeat(64),
                1,
                3,
                1_800_000_000_000,
                1_800_000_060_000,
            ),
        ] {
            assert!(changed.is_err() || changed.unwrap() != message);
        }
        assert!(
            node_session_challenge_message(
                "tenant-a",
                "nd_node-a",
                "blindpass-node/1",
                &nonce,
                &"A".repeat(64),
                1,
                3,
                1_800_000_000_000,
                1_800_000_060_000,
            )
            .is_err()
        );
        assert!(
            node_session_challenge_message(
                "tenant-a",
                "nd_node-a",
                "blindpass-node/1",
                &nonce,
                &"a".repeat(64),
                1,
                3,
                1_800_000_000_000,
                1_800_000_061_000,
            )
            .is_err()
        );
    }

    #[test]
    fn node_event_signature_message_binds_node_key_kind_and_body() {
        let body = Value::Object(vec![("result".to_owned(), Value::String("ok".to_owned()))]);
        let message =
            node_event_message("nd_node-a", "event_1234567890", "operation_result", &body).unwrap();
        let key = Ed25519KeyPair::from_seed(&[8; 32]).unwrap();
        let signature = key.sign(&message).unwrap();
        assert!(super::verify(key.public_key(), &message, &signature).unwrap());
        assert_ne!(
            message,
            node_event_message("nd_node-b", "event_1234567890", "operation_result", &body).unwrap()
        );
        assert_ne!(
            message,
            node_event_message("nd_node-a", "event_1234567890", "audit", &body).unwrap()
        );
        assert_ne!(
            message,
            node_event_message(
                "nd_node-a",
                "event_1234567890",
                "operation_result",
                &Value::Object(vec![(
                    "result".to_owned(),
                    Value::String("failed".to_owned())
                )]),
            )
            .unwrap()
        );
        assert!(node_event_message("nd_node-a", "short", "audit", &body).is_err());
        assert!(
            node_event_message("nd_node-a", "event_1234567890", "untrusted_kind", &body,).is_err()
        );
    }

    #[test]
    fn signed_envelopes_round_trip_and_bind_every_envelope_field() {
        let issuer = issuer();
        let body = Value::Object(vec![
            ("node_id".to_owned(), Value::String("node-a".to_owned())),
            ("version".to_owned(), Value::Unsigned(4)),
        ]);
        let envelope =
            SignedEnvelope::sign(DocumentKind::OperationResult, body, KEY_ID, 3, &issuer).unwrap();
        let json = envelope.to_json().unwrap();
        let parsed = SignedEnvelope::from_json(std::str::from_utf8(&json).unwrap()).unwrap();
        assert_eq!(parsed, envelope);
        assert!(parsed.verify(issuer.public_key(), KEY_ID, 3).unwrap());
        assert!(!parsed.verify(issuer.public_key(), "other-key", 3).unwrap());
        assert!(!parsed.verify(issuer.public_key(), KEY_ID, 4).unwrap());

        let modified = String::from_utf8(json)
            .unwrap()
            .replace("\"epoch\":3", "\"epoch\":4");
        let modified = SignedEnvelope::from_json(&modified).unwrap();
        assert!(!modified.verify(issuer.public_key(), KEY_ID, 3).unwrap());
    }

    #[test]
    fn application_ack_is_controller_signed_node_bound_and_unique() {
        let issuer = issuer();
        let ack = ApplicationAck {
            node_id: "node-a".to_owned(),
            issuer_epoch: 3,
            acknowledged_at_ms: 1_800_000_000_000,
            event_keys: vec!["event_1234567890123456".to_owned()],
        };
        let envelope = SignedEnvelope::sign(
            DocumentKind::ApplicationAck,
            ack.to_value().unwrap(),
            KEY_ID,
            3,
            &issuer,
        )
        .unwrap();
        let parsed =
            SignedEnvelope::from_json(std::str::from_utf8(&envelope.to_json().unwrap()).unwrap())
                .unwrap();
        assert_eq!(parsed.kind(), DocumentKind::ApplicationAck);
        assert!(parsed.verify(issuer.public_key(), KEY_ID, 3).unwrap());
        assert_eq!(ApplicationAck::from_value(parsed.body()).unwrap(), ack);
        let mut duplicate = ack;
        duplicate
            .event_keys
            .push("event_1234567890123456".to_owned());
        assert!(duplicate.to_value().is_err());
    }

    #[test]
    fn node_key_rotation_is_signed_and_requires_a_consecutive_key_version() {
        let issuer = issuer();
        let signing_key = Ed25519KeyPair::from_seed(&[7; 32]).unwrap();
        let signing_public = crate::signing::base64_url_encode(signing_key.public_key());
        let recipient_public = crate::signing::base64_url_encode(&[8; 32]);
        let fingerprint = node_key_fingerprint(signing_key.public_key(), &[8; 32]).unwrap();
        let rotation = NodeKeyRotation {
            node_id: "nd_node-a".to_owned(),
            rotation_id: "rot_12345678901234567890123456789012".to_owned(),
            from_key_version: 1,
            to_key_version: 2,
            signing_public,
            recipient_public,
            fingerprint,
            issuer_epoch: 3,
        };
        let value = rotation.to_value().unwrap();
        let restored = NodeKeyRotation::from_value(&value).unwrap();
        assert_eq!(restored, rotation);

        let envelope =
            SignedEnvelope::sign(DocumentKind::NodeKeyRotation, value, KEY_ID, 3, &issuer).unwrap();
        let parsed =
            SignedEnvelope::from_json(std::str::from_utf8(&envelope.to_json().unwrap()).unwrap())
                .unwrap();
        assert_eq!(parsed.kind(), DocumentKind::NodeKeyRotation);
        assert!(parsed.verify(issuer.public_key(), KEY_ID, 3).unwrap());

        let mut skipped_version = rotation.clone();
        skipped_version.to_key_version = 3;
        assert!(skipped_version.to_value().is_err());
        let mut bad_fingerprint = rotation;
        bad_fingerprint.fingerprint = "A".repeat(64);
        assert!(bad_fingerprint.to_value().is_err());
    }

    #[test]
    fn signed_envelopes_reject_duplicate_fields_unknown_fields_and_bad_signatures() {
        let issuer = issuer();
        let body = Value::Object(vec![(
            "node_id".to_owned(),
            Value::String("node-a".to_owned()),
        )]);
        let envelope =
            SignedEnvelope::sign(DocumentKind::OperationResult, body, KEY_ID, 1, &issuer).unwrap();
        let encoded = std::str::from_utf8(&envelope.to_json().unwrap())
            .unwrap()
            .to_owned();
        let duplicate = encoded.replacen("{", "{\"epoch\":1,", 1);
        assert!(SignedEnvelope::from_json(&duplicate).is_err());
        let unknown = encoded.replacen("{", "{\"extra\":1,", 1);
        assert!(SignedEnvelope::from_json(&unknown).is_err());
        let changed = encoded.replace("node-a", "node-b");
        let changed = SignedEnvelope::from_json(&changed).unwrap();
        assert!(!changed.verify(issuer.public_key(), KEY_ID, 1).unwrap());
    }

    #[test]
    fn typed_registrations_and_grants_enforce_pilot_bindings() {
        let registration = Registration {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            unit: "backup.service".to_owned(),
            account: "backup".to_owned(),
            invocation_id: Some("invocation-1".to_owned()),
            status: "active".to_owned(),
            consumption_mode: ConsumptionMode::Socket,
            registration_version: 1,
            policy_version: 2,
            local_ceiling_seconds: 120,
        };
        assert!(registration.to_value().is_ok());
        let mut uid_registration = registration.clone();
        uid_registration.account = "uid:986".to_owned();
        assert!(uid_registration.to_value().is_ok());
        for invalid_account in ["uid:0", "uid:0986", "uid:4294967296", "uid:+986"] {
            uid_registration.account = invalid_account.to_owned();
            assert!(uid_registration.to_value().is_err(), "{invalid_account}");
        }
        let mut invalid_registration = registration;
        invalid_registration.unit = "../backup.service".to_owned();
        assert!(invalid_registration.to_value().is_err());

        let grant = Grant {
            id: "grant-a".to_owned(),
            operation_id: "operation-a".to_owned(),
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            invocation_id: "invocation-1".to_owned(),
            unit: "backup.service".to_owned(),
            account: "backup".to_owned(),
            resource_id: "resource-a".to_owned(),
            recipient_key_id: "node-a-1".to_owned(),
            policy_version: 2,
            approval_reference: Some("oa_123".to_owned()),
            action: "noop.marker".to_owned(),
            mode: ConsumptionMode::Socket,
            audience: "blindpass-node".to_owned(),
            issuer_epoch: 1,
            issued_at_ms: 100,
            expires_at_ms: 200,
            local_ceiling_seconds: 60,
        };
        assert!(grant.to_value().is_ok());
        let mut uid_grant = grant.clone();
        uid_grant.account = "uid:986".to_owned();
        assert!(uid_grant.to_value().is_ok());
        let mut invalid_grant = grant;
        invalid_grant.audience = "agent".to_owned();
        assert!(invalid_grant.to_value().is_err());
    }

    #[test]
    fn empty_policy_snapshot_is_a_valid_fail_closed_policy() {
        let policy = PolicySnapshot {
            policy_version: 2,
            local_ceiling_seconds: 60,
            allowed_actions: Vec::new(),
            allowed_modes: Vec::new(),
        };
        let value = policy.to_value().unwrap();
        let restored = PolicySnapshot::from_value(&value).unwrap();
        assert_eq!(restored, policy);
    }

    #[test]
    fn body_json_is_canonicalized_before_it_is_signed() {
        let source = r#"{"version":2,"name":"node-a"}"#;
        let canonical = canonicalize_json(source).unwrap();
        let parsed_body =
            crate::canon::parse_json(std::str::from_utf8(&canonical).unwrap()).unwrap();
        let signed = SignedEnvelope::sign(
            DocumentKind::OperationResult,
            parsed_body,
            KEY_ID,
            1,
            &issuer(),
        )
        .unwrap();
        assert_eq!(signed.body_json().unwrap(), canonical);
    }
}
