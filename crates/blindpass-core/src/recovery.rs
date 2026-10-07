// SPDX-License-Identifier: AGPL-3.0-only

//! Strict consumed-report metadata for stale-restore reconciliation.
//!
//! This module verifies a broker signature and its recovery context. It does
//! not establish enrolled-key trust, consume a challenge, prove journal
//! completeness or authorize issuance. Those checks belong to the recovery
//! consumer and its protected, non-restored authority record. Generic live
//! node-event admission remains closed until that consumer is implemented.

use crate::canon::{Value, canonicalize_value, parse_json};
use crate::fleet::{DocumentError, is_valid_opaque_id, node_event_message_bytes};
use crate::signing::ed25519::verify;
use crate::signing::{base64_url_decode, base64_url_encode};

pub mod pages;

pub const MAX_CONSUMED_REPORT_RECORDS: usize = 128;
pub const MAX_CONSUMED_REPORT_BYTES: usize = 64 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const REPORT_FIELDS: &[&str] = &[
    "version",
    "tenant_id",
    "node_id",
    "node_key_version",
    "issuer_key_id",
    "recovery_id",
    "recovery_generation",
    "observed_issuer_epoch",
    "challenge",
    "records",
];
const RECORD_FIELDS: &[&str] = &["grant_id", "operation_id", "issuer_epoch", "outcome"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumedOutcome {
    Consumed,
    Revoked,
    /// Consumed/delivered authority whose provider/session cleanup is unresolved.
    Uncertain,
}

impl ConsumedOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Uncertain => "uncertain",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedRecord {
    pub grant_id: String,
    pub operation_id: String,
    pub issuer_epoch: u64,
    pub outcome: ConsumedOutcome,
}

/// A bounded journal report. Records have strictly ascending grant IDs, with
/// no duplicates. More than the supported record limit must be refused, never
/// silently truncated or interpreted as a complete journal. Pagination and
/// durable completeness proof are separate integration requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedReport {
    pub tenant_id: String,
    pub node_id: String,
    pub node_key_version: u64,
    pub issuer_key_id: String,
    pub recovery_id: String,
    pub recovery_generation: u64,
    pub observed_issuer_epoch: u64,
    pub challenge: String,
    pub records: Vec<ConsumedRecord>,
}

/// Expected bindings from current recovery authority and enrolled broker
/// identity. Never construct this context from a stale snapshot alone.
pub struct ReportContext<'a> {
    pub tenant_id: &'a str,
    pub node_id: &'a str,
    pub node_key_version: u64,
    pub issuer_key_id: &'a str,
    pub recovery_id: &'a str,
    pub recovery_generation: u64,
    pub minimum_observed_epoch: u64,
    pub challenge: &'a str,
}

impl ConsumedReport {
    pub fn from_json(source: &str) -> Result<Self, DocumentError> {
        if source.len() > MAX_CONSUMED_REPORT_BYTES {
            return Err(invalid());
        }
        Self::from_value(&parse_json(source)?)
    }

    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        exact_fields(value, REPORT_FIELDS)?;
        if number(value, "version")? != 1 {
            return Err(invalid());
        }
        let entries = value
            .get("records")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        if entries.len() > MAX_CONSUMED_REPORT_RECORDS {
            return Err(invalid());
        }
        let mut records = Vec::with_capacity(entries.len());
        for entry in entries {
            exact_fields(entry, RECORD_FIELDS)?;
            let outcome = match text(entry, "outcome")? {
                "consumed" => ConsumedOutcome::Consumed,
                "revoked" => ConsumedOutcome::Revoked,
                "uncertain" => ConsumedOutcome::Uncertain,
                _ => return Err(invalid()),
            };
            records.push(ConsumedRecord {
                grant_id: text(entry, "grant_id")?.into(),
                operation_id: text(entry, "operation_id")?.into(),
                issuer_epoch: number(entry, "issuer_epoch")?,
                outcome,
            });
        }
        let report = Self {
            tenant_id: text(value, "tenant_id")?.into(),
            node_id: text(value, "node_id")?.into(),
            node_key_version: number(value, "node_key_version")?,
            issuer_key_id: text(value, "issuer_key_id")?.into(),
            recovery_id: text(value, "recovery_id")?.into(),
            recovery_generation: number(value, "recovery_generation")?,
            observed_issuer_epoch: number(value, "observed_issuer_epoch")?,
            challenge: text(value, "challenge")?.into(),
            records,
        };
        // This also bounds encoded size and rejects oversized string fields.
        report.to_value()?;
        Ok(report)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        self.validate()?;
        let value = Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("tenant_id".into(), Value::String(self.tenant_id.clone())),
            ("node_id".into(), Value::String(self.node_id.clone())),
            (
                "node_key_version".into(),
                Value::Unsigned(self.node_key_version),
            ),
            (
                "issuer_key_id".into(),
                Value::String(self.issuer_key_id.clone()),
            ),
            (
                "recovery_id".into(),
                Value::String(self.recovery_id.clone()),
            ),
            (
                "recovery_generation".into(),
                Value::Unsigned(self.recovery_generation),
            ),
            (
                "observed_issuer_epoch".into(),
                Value::Unsigned(self.observed_issuer_epoch),
            ),
            ("challenge".into(), Value::String(self.challenge.clone())),
            (
                "records".into(),
                Value::Array(
                    self.records
                        .iter()
                        .map(|record| {
                            Value::Object(vec![
                                ("grant_id".into(), Value::String(record.grant_id.clone())),
                                (
                                    "operation_id".into(),
                                    Value::String(record.operation_id.clone()),
                                ),
                                ("issuer_epoch".into(), Value::Unsigned(record.issuer_epoch)),
                                (
                                    "outcome".into(),
                                    Value::String(record.outcome.as_str().into()),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        if canonicalize_value(&value)?.len() > MAX_CONSUMED_REPORT_BYTES {
            return Err(invalid());
        }
        Ok(value)
    }

    pub fn signing_message(&self, event_key: &str) -> Result<Vec<u8>, DocumentError> {
        if !(16..=128).contains(&event_key.len()) || !is_valid_opaque_id(event_key) {
            return Err(invalid());
        }
        let body = self.to_value()?;
        let message = node_event_message_bytes(&self.node_id, event_key, "consumed_report", &body)?;
        // Bound the complete event as well as its body.
        if message.len() > MAX_CONSUMED_REPORT_BYTES {
            return Err(invalid());
        }
        Ok(message)
    }

    /// Verify context and signature only. The public key must come from a
    /// currently trusted enrolled identity; successful verification does not
    /// consume the challenge, acknowledge completeness, close a provider
    /// session, remove quarantine or authorize a restored controller.
    pub fn verify(
        &self,
        event_key: &str,
        expected: &ReportContext<'_>,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(), DocumentError> {
        let message = self.signing_message(event_key)?;
        if !safe_positive(expected.minimum_observed_epoch)
            || self.observed_issuer_epoch < expected.minimum_observed_epoch
            || self.tenant_id != expected.tenant_id
            || self.node_id != expected.node_id
            || self.node_key_version != expected.node_key_version
            || self.issuer_key_id != expected.issuer_key_id
            || self.recovery_id != expected.recovery_id
            || self.recovery_generation != expected.recovery_generation
            || self.challenge != expected.challenge
        {
            return Err(DocumentError::Invalid("consumed report context"));
        }
        if !verify(public_key, &message, signature)? {
            return Err(DocumentError::Invalid("consumed report signature"));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), DocumentError> {
        if ![
            &self.tenant_id,
            &self.node_id,
            &self.issuer_key_id,
            &self.recovery_id,
        ]
        .iter()
        .all(|value| is_valid_opaque_id(value))
            || !safe_positive(self.node_key_version)
            || !safe_positive(self.recovery_generation)
            || !safe_positive(self.observed_issuer_epoch)
            || self.observed_issuer_epoch > self.recovery_generation
            || self.records.len() > MAX_CONSUMED_REPORT_RECORDS
        {
            return Err(invalid());
        }
        let challenge = base64_url_decode(&self.challenge, 32).ok_or_else(invalid)?;
        if base64_url_encode(&challenge) != self.challenge {
            return Err(invalid());
        }
        let mut previous: Option<&str> = None;
        for record in &self.records {
            if !is_valid_opaque_id(&record.grant_id)
                || !is_valid_opaque_id(&record.operation_id)
                || !safe_positive(record.issuer_epoch)
                || record.issuer_epoch > self.observed_issuer_epoch
                || previous.is_some_and(|id| id >= record.grant_id.as_str())
            {
                return Err(invalid());
            }
            previous = Some(&record.grant_id);
        }
        Ok(())
    }
}

fn invalid() -> DocumentError {
    DocumentError::Invalid("consumed report")
}

fn safe_positive(value: u64) -> bool {
    (1..=MAX_SAFE_INTEGER).contains(&value)
}

fn exact_fields(value: &Value, expected: &[&str]) -> Result<(), DocumentError> {
    let fields = value.as_object().ok_or_else(invalid)?;
    if fields.len() != expected.len()
        || expected
            .iter()
            .any(|name| fields.iter().filter(|(key, _)| key == name).count() != 1)
    {
        return Err(invalid());
    }
    Ok(())
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, DocumentError> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if text.len() > 128 {
        return Err(invalid());
    }
    Ok(text)
}

fn number(value: &Value, field: &str) -> Result<u64, DocumentError> {
    let number = value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    if !safe_positive(number) {
        return Err(invalid());
    }
    Ok(number)
}
