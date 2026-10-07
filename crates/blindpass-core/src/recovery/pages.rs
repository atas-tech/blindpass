// SPDX-License-Identifier: AGPL-3.0-only

//! Version-2 immutable consumption-history pages. Delivery completeness is
//! distinct from history coverage, effect completion and recovery permission.
//! Enrolled key/context trust and one-use challenge consumption must come from
//! the protected recovery consumer, independently of restored controller state.

use crate::canon::{Value, canonicalize_value, parse_json};
use crate::custody::sha256;
use crate::fleet::{DocumentError, is_valid_opaque_id, node_event_message_bytes};
use crate::signing::ed25519::{Ed25519KeyPair, verify};
use crate::signing::{base64_url_decode, base64_url_encode};

pub const RECORDS_PER_PAGE: u64 = 128;
pub const MAX_HISTORY_RECORDS: u64 = 1_000_000;
pub const MAX_PAGE_BYTES: usize = 64 * 1024;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const MANIFEST_FIELDS: &[&str] = &[
    "version",
    "tenant_id",
    "node_id",
    "node_key_version",
    "issuer_key_id",
    "recovery_id",
    "recovery_generation",
    "challenge",
    "report_id",
    "observed_issuer_epoch",
    "history_id",
    "pruned_through_ms",
    "unmapped_records",
    "total_records",
    "page_count",
    "records_digest",
];
const RECORD_FIELDS: &[&str] = &[
    "grant_id",
    "operation_id",
    "issuer_epoch",
    "expires_at_ms",
    "outcome",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportIdentity {
    pub tenant_id: String,
    pub node_id: String,
    pub node_key_version: u64,
    pub issuer_key_id: String,
    pub recovery_id: String,
    pub recovery_generation: u64,
    pub challenge: String,
}

impl ReportIdentity {
    fn validate(&self) -> Result<(), DocumentError> {
        if ![
            &self.tenant_id,
            &self.node_id,
            &self.issuer_key_id,
            &self.recovery_id,
        ]
        .iter()
        .all(|value| is_valid_opaque_id(value))
            || !positive(self.node_key_version)
            || !positive(self.recovery_generation)
            || !nonce(&self.challenge)
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn fields(&self) -> Vec<(String, Value)> {
        vec![
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
            ("challenge".into(), Value::String(self.challenge.clone())),
        ]
    }

    fn from_value(value: &Value) -> Result<Self, DocumentError> {
        let identity = Self {
            tenant_id: text(value, "tenant_id")?.into(),
            node_id: text(value, "node_id")?.into(),
            node_key_version: integer(value, "node_key_version")?,
            issuer_key_id: text(value, "issuer_key_id")?.into(),
            recovery_id: text(value, "recovery_id")?.into(),
            recovery_generation: integer(value, "recovery_generation")?,
            challenge: text(value, "challenge")?.into(),
        };
        identity.validate()?;
        Ok(identity)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryCoverage {
    /// None means unknown genesis; zero rows do not change that fact.
    pub history_id: Option<String>,
    pub pruned_through_ms: u64,
    pub unmapped_records: u64,
}

impl HistoryCoverage {
    /// Coverage of this time range only; never a provider or activation proof.
    pub fn covers(&self, snapshot_controller_time_ms: u64) -> bool {
        positive(snapshot_controller_time_ms)
            && self.history_id.as_ref().is_some_and(|id| nonce(id))
            && self.unmapped_records == 0
            && snapshot_controller_time_ms > self.pruned_through_ms
    }
}

/// A durable one-use intent. Its effect/provider fate is always uncertain in
/// this protocol. Unmapped legacy rows have neither operation nor epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRecord {
    pub grant_id: String,
    pub expires_at_ms: u64,
    pub operation_id: Option<String>,
    pub issuer_epoch: Option<u64>,
}

impl IntentRecord {
    fn validate(&self) -> Result<(), DocumentError> {
        let correlation = match (&self.operation_id, self.issuer_epoch) {
            (None, None) => true,
            (Some(operation), Some(epoch)) => is_valid_opaque_id(operation) && positive(epoch),
            _ => false,
        };
        if !is_valid_opaque_id(&self.grant_id) || !positive(self.expires_at_ms) || !correlation {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        self.validate()?;
        Ok(Value::Object(vec![
            ("grant_id".into(), Value::String(self.grant_id.clone())),
            ("expires_at_ms".into(), Value::Unsigned(self.expires_at_ms)),
            (
                "operation_id".into(),
                self.operation_id
                    .as_ref()
                    .map_or(Value::Null, |id| Value::String(id.clone())),
            ),
            (
                "issuer_epoch".into(),
                self.issuer_epoch.map_or(Value::Null, Value::Unsigned),
            ),
            ("outcome".into(), Value::String("uncertain".into())),
        ]))
    }

    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        exact(value, RECORD_FIELDS)?;
        if text(value, "outcome")? != "uncertain" {
            return Err(invalid());
        }
        let operation_id = optional_text(value, "operation_id")?;
        let issuer_epoch = match value.get("issuer_epoch") {
            Some(Value::Null) => None,
            Some(value) => Some(value.as_u64().ok_or_else(invalid)?),
            None => return Err(invalid()),
        };
        let record = Self {
            grant_id: text(value, "grant_id")?.into(),
            expires_at_ms: integer(value, "expires_at_ms")?,
            operation_id,
            issuer_epoch,
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportManifest {
    pub identity: ReportIdentity,
    pub report_id: String,
    /// Original observations may exceed the proposed generation. Preserve
    /// them so protected recovery can reserve a higher generation.
    pub observed_issuer_epoch: u64,
    pub coverage: HistoryCoverage,
    pub total_records: u64,
    pub records_digest: String,
}

impl ReportManifest {
    pub fn page_count(&self) -> u64 {
        self.total_records.div_ceil(RECORDS_PER_PAGE).max(1)
    }

    fn validate(&self) -> Result<(), DocumentError> {
        self.identity.validate()?;
        if !nonce(&self.report_id)
            || !nonce(&self.records_digest)
            || !positive(self.observed_issuer_epoch)
            || self.total_records > MAX_HISTORY_RECORDS
            || self.coverage.pruned_through_ms > MAX_SAFE
            || self.coverage.unmapped_records > self.total_records
            || self
                .coverage
                .history_id
                .as_ref()
                .is_some_and(|id| !nonce(id))
            || (self.coverage.history_id.is_none() && self.coverage.pruned_through_ms != 0)
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        self.validate()?;
        let mut fields = self.identity.fields();
        fields.extend([
            ("version".into(), Value::Unsigned(2)),
            ("report_id".into(), Value::String(self.report_id.clone())),
            (
                "observed_issuer_epoch".into(),
                Value::Unsigned(self.observed_issuer_epoch),
            ),
            (
                "history_id".into(),
                self.coverage
                    .history_id
                    .as_ref()
                    .map_or(Value::Null, |id| Value::String(id.clone())),
            ),
            (
                "pruned_through_ms".into(),
                Value::Unsigned(self.coverage.pruned_through_ms),
            ),
            (
                "unmapped_records".into(),
                Value::Unsigned(self.coverage.unmapped_records),
            ),
            ("total_records".into(), Value::Unsigned(self.total_records)),
            ("page_count".into(), Value::Unsigned(self.page_count())),
            (
                "records_digest".into(),
                Value::String(self.records_digest.clone()),
            ),
        ]);
        Ok(Value::Object(fields))
    }

    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        exact(value, MANIFEST_FIELDS)?;
        if integer(value, "version")? != 2 {
            return Err(invalid());
        }
        let manifest = Self {
            identity: ReportIdentity::from_value(value)?,
            report_id: text(value, "report_id")?.into(),
            observed_issuer_epoch: integer(value, "observed_issuer_epoch")?,
            coverage: HistoryCoverage {
                history_id: optional_text(value, "history_id")?,
                pruned_through_ms: integer(value, "pruned_through_ms")?,
                unmapped_records: integer(value, "unmapped_records")?,
            },
            total_records: integer(value, "total_records")?,
            records_digest: text(value, "records_digest")?.into(),
        };
        manifest.validate()?;
        if integer(value, "page_count")? != manifest.page_count() {
            return Err(invalid());
        }
        Ok(manifest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportPage {
    pub manifest: ReportManifest,
    pub page_index: u64,
    pub records: Vec<IntentRecord>,
}

impl ReportPage {
    pub fn from_json(source: &str) -> Result<Self, DocumentError> {
        if source.len() > MAX_PAGE_BYTES {
            return Err(invalid());
        }
        Self::from_value(&parse_json(source)?)
    }

    pub fn from_value(value: &Value) -> Result<Self, DocumentError> {
        let mut expected = MANIFEST_FIELDS.to_vec();
        expected.extend(["page_index", "records"]);
        exact(value, &expected)?;
        let header = Value::Object(
            value
                .as_object()
                .ok_or_else(invalid)?
                .iter()
                .filter(|(key, _)| MANIFEST_FIELDS.contains(&key.as_str()))
                .cloned()
                .collect(),
        );
        let entries = value
            .get("records")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        if entries.len() > RECORDS_PER_PAGE as usize {
            return Err(invalid());
        }
        let page = Self {
            manifest: ReportManifest::from_value(&header)?,
            page_index: integer(value, "page_index")?,
            records: entries
                .iter()
                .map(IntentRecord::from_value)
                .collect::<Result<_, _>>()?,
        };
        page.to_value()?;
        Ok(page)
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        self.manifest.validate()?;
        if self.page_index >= self.manifest.page_count() {
            return Err(invalid());
        }
        let remaining = self.manifest.total_records - self.page_index * RECORDS_PER_PAGE;
        if self.records.len() as u64 != remaining.min(RECORDS_PER_PAGE) {
            return Err(invalid());
        }
        let mut previous: Option<&str> = None;
        for record in &self.records {
            record.validate()?;
            if record
                .issuer_epoch
                .is_some_and(|epoch| epoch > self.manifest.observed_issuer_epoch)
                || previous.is_some_and(|id| id >= record.grant_id.as_str())
            {
                return Err(invalid());
            }
            previous = Some(&record.grant_id);
        }
        let Value::Object(mut fields) = self.manifest.to_value()? else {
            return Err(invalid());
        };
        fields.extend([
            ("page_index".into(), Value::Unsigned(self.page_index)),
            (
                "records".into(),
                Value::Array(
                    self.records
                        .iter()
                        .map(IntentRecord::to_value)
                        .collect::<Result<_, _>>()?,
                ),
            ),
        ]);
        let value = Value::Object(fields);
        if canonicalize_value(&value)?.len() > MAX_PAGE_BYTES {
            return Err(invalid());
        }
        Ok(value)
    }

    pub fn signing_message(&self) -> Result<Vec<u8>, DocumentError> {
        let event = format!("history_{}_{}", self.manifest.report_id, self.page_index);
        let message = node_event_message_bytes(
            &self.manifest.identity.node_id,
            &event,
            "consumed_report_page",
            &self.to_value()?,
        )?;
        if message.len() > MAX_PAGE_BYTES {
            return Err(invalid());
        }
        Ok(message)
    }

    /// The expected identity and public key must come from current protected
    /// enrollment, not a restored row, report body or self-supplied key.
    pub fn verify(
        &self,
        expected: &ReportIdentity,
        minimum_observed_epoch: u64,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<VerifiedPage, DocumentError> {
        expected.validate()?;
        if &self.manifest.identity != expected
            || !positive(minimum_observed_epoch)
            || self.manifest.observed_issuer_epoch < minimum_observed_epoch
        {
            return Err(invalid());
        }
        if !verify(public_key, &self.signing_message()?, signature)? {
            return Err(invalid());
        }
        Ok(VerifiedPage(self.clone()))
    }
}

/// Constructible only after signature/context verification. Its presence
/// still does not prove provenance, nonce freshness or protected activation.
pub struct VerifiedPage(ReportPage);
impl VerifiedPage {
    pub fn page(&self) -> &ReportPage {
        &self.0
    }
}

/// A controller-authenticated request for broker-owned metadata. No records,
/// signing body or observed epoch may be supplied by the relay caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRequest {
    pub identity: ReportIdentity,
    pub broker_challenge: String,
    pub report_id: Option<String>,
    pub page_index: u64,
}

impl ReportRequest {
    fn to_value(&self) -> Result<Value, DocumentError> {
        self.identity.validate()?;
        if !nonce(&self.broker_challenge)
            || self.report_id.as_ref().is_some_and(|id| !nonce(id))
            || (self.report_id.is_none() && self.page_index != 0)
            || self.page_index >= MAX_HISTORY_RECORDS.div_ceil(RECORDS_PER_PAGE)
        {
            return Err(invalid());
        }
        let mut fields = self.identity.fields();
        fields.extend([
            ("version".into(), Value::Unsigned(1)),
            (
                "broker_challenge".into(),
                Value::String(self.broker_challenge.clone()),
            ),
            (
                "report_id".into(),
                self.report_id
                    .as_ref()
                    .map_or(Value::Null, |id| Value::String(id.clone())),
            ),
            ("page_index".into(), Value::Unsigned(self.page_index)),
        ]);
        Ok(Value::Object(fields))
    }

    fn from_value(value: &Value) -> Result<Self, DocumentError> {
        exact(
            value,
            &[
                "version",
                "tenant_id",
                "node_id",
                "node_key_version",
                "issuer_key_id",
                "recovery_id",
                "recovery_generation",
                "challenge",
                "broker_challenge",
                "report_id",
                "page_index",
            ],
        )?;
        if integer(value, "version")? != 1 {
            return Err(invalid());
        }
        let request = Self {
            identity: ReportIdentity::from_value(value)?,
            broker_challenge: text(value, "broker_challenge")?.into(),
            report_id: optional_text(value, "report_id")?,
            page_index: integer(value, "page_index")?,
        };
        request.to_value()?;
        Ok(request)
    }

    fn signing_message(&self) -> Result<Vec<u8>, DocumentError> {
        let mut bytes = b"blindpass:controller-recovery-report:v1\0".to_vec();
        bytes.extend(canonicalize_value(&self.to_value()?)?);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReportRequest {
    pub request: ReportRequest,
    pub controller_signature: String,
}

impl SignedReportRequest {
    pub fn sign(request: ReportRequest, key: &Ed25519KeyPair) -> Result<Self, DocumentError> {
        let controller_signature = base64_url_encode(&key.sign(&request.signing_message()?)?);
        Ok(Self {
            request,
            controller_signature,
        })
    }

    pub fn to_value(&self) -> Result<Value, DocumentError> {
        let bytes = base64_url_decode(&self.controller_signature, 64).ok_or_else(invalid)?;
        if base64_url_encode(&bytes) != self.controller_signature {
            return Err(invalid());
        }
        Ok(Value::Object(vec![
            ("body".into(), self.request.to_value()?),
            (
                "controller_signature".into(),
                Value::String(self.controller_signature.clone()),
            ),
        ]))
    }

    pub fn from_json(source: &str) -> Result<Self, DocumentError> {
        if source.len() > 4_096 {
            return Err(invalid());
        }
        let value = parse_json(source)?;
        exact(&value, &["body", "controller_signature"])?;
        let signed = Self {
            request: ReportRequest::from_value(value.get("body").ok_or_else(invalid)?)?,
            controller_signature: text(&value, "controller_signature")?.into(),
        };
        signed.to_value()?;
        Ok(signed)
    }

    /// Signature only. Broker scope/current version and a fresh local nonce
    /// must be checked before reading history or advancing any issuer pin.
    pub fn verify(&self, pinned_controller_public: &[u8]) -> Result<(), DocumentError> {
        self.to_value()?;
        let signature = base64_url_decode(&self.controller_signature, 64).ok_or_else(invalid)?;
        if !verify(
            pinned_controller_public,
            &self.request.signing_message()?,
            &signature,
        )? {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Hash chain H0=SHA256(domain || canonical manifest excluding records_digest),
/// Hn=SHA256(Hn-1 || canonical intent n). Counts, order and unmapped rows are
/// checked explicitly. Memory stays bounded independently of history length.
pub struct PageDigest {
    manifest: ReportManifest,
    state: [u8; 32],
    count: u64,
    unmapped: u64,
    previous: Option<String>,
}

impl PageDigest {
    pub fn new(manifest: &ReportManifest) -> Result<Self, DocumentError> {
        let Value::Object(mut fields) = manifest.to_value()? else {
            return Err(invalid());
        };
        fields.retain(|(key, _)| key != "records_digest");
        let mut bytes = b"blindpass:recovery-history:v2\0".to_vec();
        bytes.extend(canonicalize_value(&Value::Object(fields))?);
        Ok(Self {
            manifest: manifest.clone(),
            state: sha256(&bytes)?,
            count: 0,
            unmapped: 0,
            previous: None,
        })
    }

    pub fn push(&mut self, record: &IntentRecord) -> Result<(), DocumentError> {
        record.validate()?;
        if self.count >= self.manifest.total_records
            || record
                .issuer_epoch
                .is_some_and(|epoch| epoch > self.manifest.observed_issuer_epoch)
            || self
                .previous
                .as_ref()
                .is_some_and(|id| id >= &record.grant_id)
        {
            return Err(invalid());
        }
        let mut bytes = self.state.to_vec();
        bytes.extend(canonicalize_value(&record.to_value()?)?);
        self.state = sha256(&bytes)?;
        self.count += 1;
        self.unmapped += u64::from(record.operation_id.is_none());
        self.previous = Some(record.grant_id.clone());
        Ok(())
    }

    pub fn finish(self) -> Result<String, DocumentError> {
        if self.count != self.manifest.total_records
            || self.unmapped != self.manifest.coverage.unmapped_records
        {
            return Err(invalid());
        }
        Ok(base64_url_encode(&self.state))
    }
}

/// In-memory delivery verifier. A controller must separately stage receipts
/// durably and atomically consume its challenge only after full coverage.
#[derive(Default)]
pub struct PageAccumulator {
    digest: Option<PageDigest>,
    next_page: u64,
    finished: bool,
    poisoned: bool,
}

impl PageAccumulator {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn complete(&self) -> bool {
        self.finished && !self.poisoned
    }

    pub fn push(&mut self, verified: VerifiedPage) -> Result<bool, DocumentError> {
        let result = self.push_inner(verified.0);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn push_inner(&mut self, page: ReportPage) -> Result<bool, DocumentError> {
        if self.poisoned || self.finished || page.page_index != self.next_page {
            return Err(invalid());
        }
        if self.digest.is_none() {
            self.digest = Some(PageDigest::new(&page.manifest)?);
        }
        let digest = self.digest.as_mut().ok_or_else(invalid)?;
        if digest.manifest != page.manifest {
            return Err(invalid());
        }
        for record in &page.records {
            digest.push(record)?;
        }
        self.next_page += 1;
        if self.next_page == page.manifest.page_count() {
            let computed = self.digest.take().ok_or_else(invalid)?.finish()?;
            if computed != page.manifest.records_digest {
                return Err(invalid());
            }
            self.finished = true;
        }
        Ok(self.finished)
    }
}

fn positive(number: u64) -> bool {
    (1..=MAX_SAFE).contains(&number)
}
fn nonce(value: &str) -> bool {
    base64_url_decode(value, 32).is_some_and(|bytes| base64_url_encode(&bytes) == value)
}
fn invalid() -> DocumentError {
    DocumentError::Invalid("recovery report page")
}
fn exact(value: &Value, names: &[&str]) -> Result<(), DocumentError> {
    let fields = value.as_object().ok_or_else(invalid)?;
    if fields.len() != names.len()
        || names
            .iter()
            .any(|name| fields.iter().filter(|(key, _)| key == name).count() != 1)
    {
        return Err(invalid());
    }
    Ok(())
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, DocumentError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|text| text.len() <= 128)
        .ok_or_else(invalid)
}
fn optional_text(value: &Value, name: &str) -> Result<Option<String>, DocumentError> {
    match value.get(name) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.len() <= 128 => Ok(Some(text.clone())),
        _ => Err(invalid()),
    }
}
fn integer(value: &Value, name: &str) -> Result<u64, DocumentError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .filter(|number| *number <= MAX_SAFE)
        .ok_or_else(invalid)
}
