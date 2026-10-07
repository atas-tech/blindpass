// SPDX-License-Identifier: AGPL-3.0-only

//! P10 cross-workload fulfillment state.
//!
//! This is the only module that reads or writes `cross_fulfillments` and
//! `cross_fulfillment_payloads`. No v2 exchange route, operation, grant or
//! provisioning code touches them, so a legacy handler cannot reach a fleet
//! payload. The controller handles only metadata and ciphertext sealed to a key
//! the recipient broker minted; it never holds plaintext. Every transition is
//! one transaction that also writes its audit row and queues the signed
//! documents it announces.

use super::{
    AuditDraft, Database, NodeEventInsert, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    audit::{insert_audit_postgres, insert_audit_sqlite},
    authorization::{enqueue_node_document_postgres, enqueue_node_document_sqlite},
};
use blindpass_core::canon::canonicalize_value;
use blindpass_core::fleet::{DocumentKind, SignedEnvelope, node_key_fingerprint};
use blindpass_core::fulfillment::{
    FulfillmentAuthorization, FulfillmentDelivery, FulfillmentOffer, FulfillmentParty,
    FulfillmentResult, FulfillmentRevocation, FulfillmentSide, FulfillmentTerms, ResultState,
    RevocationReason, verify_offer, verify_submit,
};
use serde_json::{Value as JsonValue, json};
use sqlx::Row;

/// Statuses that hold the recipient's single slot. `uncertain` keeps it until
/// an operator reconciles the fulfillment.
pub const ACTIVE_STATUSES: &[&str] = &[
    "awaiting_approval",
    "approved",
    "offered",
    "available",
    "recipient_consumed",
    "uncertain",
];
const TTL_CAP_SECONDS: i64 = 600;
/// Node clock lead the controller tolerates on a recipient offer.
const OFFER_SKEW_MS: u64 = 30_000;
const TOMBSTONE_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
/// Rows closed by one sweep pass.
const SWEEP_BATCH: i64 = 200;

const COLUMNS: &str = "id, issuer_workload_id, recipient_workload_id, issuer_node_id, \
    recipient_node_id, issuer_credential, recipient_credential, requested_by, purpose, \
    policy_version, rule_id, decision, approver_ids_json, approval_status, decided_by, \
    decided_at, prior_fulfillment_id, ttl_seconds, terms_json, terms_digest, offer_json, \
    issuer_key_version, recipient_key_version, issuer_registration_version, \
    recipient_registration_version, status, idempotency_key, request_hash, failure_code, \
    revocation_reason, delivery_revoked_at, provider_revocation, created_at, expires_at, \
    approved_at, offered_at, issuer_consumed_at, recipient_consumed_at, completed_at, \
    closed_at, version";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentRecord {
    pub id: String,
    pub issuer_workload_id: String,
    pub recipient_workload_id: String,
    pub issuer_node_id: String,
    pub recipient_node_id: String,
    pub issuer_credential: String,
    pub recipient_credential: String,
    pub requested_by: String,
    /// Untrusted display text. Never selects a party, mode or rule.
    pub purpose: String,
    pub policy_version: i64,
    pub rule_id: String,
    pub decision: String,
    pub approver_ids_json: String,
    pub approval_status: String,
    pub decided_by: Option<String>,
    pub decided_at_ms: Option<i64>,
    pub prior_fulfillment_id: Option<String>,
    pub ttl_seconds: i64,
    pub terms_json: Option<String>,
    pub terms_digest: Option<String>,
    pub offer_json: Option<String>,
    pub issuer_key_version: Option<i64>,
    pub recipient_key_version: Option<i64>,
    pub issuer_registration_version: Option<i64>,
    pub recipient_registration_version: Option<i64>,
    pub status: String,
    pub idempotency_key: String,
    pub request_hash: String,
    pub failure_code: Option<String>,
    pub revocation_reason: Option<String>,
    pub delivery_revoked_at_ms: Option<i64>,
    pub provider_revocation: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub approved_at_ms: Option<i64>,
    pub offered_at_ms: Option<i64>,
    pub issuer_consumed_at_ms: Option<i64>,
    pub recipient_consumed_at_ms: Option<i64>,
    pub completed_at_ms: Option<i64>,
    pub closed_at_ms: Option<i64>,
    pub version: i64,
}

macro_rules! record_from {
    ($row:expr) => {{
        let r = &$row;
        FulfillmentRecord {
            id: r.try_get("id").map_err(StoreError::Database)?,
            issuer_workload_id: r
                .try_get("issuer_workload_id")
                .map_err(StoreError::Database)?,
            recipient_workload_id: r
                .try_get("recipient_workload_id")
                .map_err(StoreError::Database)?,
            issuer_node_id: r.try_get("issuer_node_id").map_err(StoreError::Database)?,
            recipient_node_id: r
                .try_get("recipient_node_id")
                .map_err(StoreError::Database)?,
            issuer_credential: r
                .try_get("issuer_credential")
                .map_err(StoreError::Database)?,
            recipient_credential: r
                .try_get("recipient_credential")
                .map_err(StoreError::Database)?,
            requested_by: r.try_get("requested_by").map_err(StoreError::Database)?,
            purpose: r.try_get("purpose").map_err(StoreError::Database)?,
            policy_version: r.try_get("policy_version").map_err(StoreError::Database)?,
            rule_id: r.try_get("rule_id").map_err(StoreError::Database)?,
            decision: r.try_get("decision").map_err(StoreError::Database)?,
            approver_ids_json: r
                .try_get("approver_ids_json")
                .map_err(StoreError::Database)?,
            approval_status: r.try_get("approval_status").map_err(StoreError::Database)?,
            decided_by: r.try_get("decided_by").map_err(StoreError::Database)?,
            decided_at_ms: r.try_get("decided_at").map_err(StoreError::Database)?,
            prior_fulfillment_id: r
                .try_get("prior_fulfillment_id")
                .map_err(StoreError::Database)?,
            ttl_seconds: r.try_get("ttl_seconds").map_err(StoreError::Database)?,
            terms_json: r.try_get("terms_json").map_err(StoreError::Database)?,
            terms_digest: r.try_get("terms_digest").map_err(StoreError::Database)?,
            offer_json: r.try_get("offer_json").map_err(StoreError::Database)?,
            issuer_key_version: r
                .try_get("issuer_key_version")
                .map_err(StoreError::Database)?,
            recipient_key_version: r
                .try_get("recipient_key_version")
                .map_err(StoreError::Database)?,
            issuer_registration_version: r
                .try_get("issuer_registration_version")
                .map_err(StoreError::Database)?,
            recipient_registration_version: r
                .try_get("recipient_registration_version")
                .map_err(StoreError::Database)?,
            status: r.try_get("status").map_err(StoreError::Database)?,
            idempotency_key: r.try_get("idempotency_key").map_err(StoreError::Database)?,
            request_hash: r.try_get("request_hash").map_err(StoreError::Database)?,
            failure_code: r.try_get("failure_code").map_err(StoreError::Database)?,
            revocation_reason: r
                .try_get("revocation_reason")
                .map_err(StoreError::Database)?,
            delivery_revoked_at_ms: r
                .try_get("delivery_revoked_at")
                .map_err(StoreError::Database)?,
            provider_revocation: r
                .try_get("provider_revocation")
                .map_err(StoreError::Database)?,
            created_at_ms: r.try_get("created_at").map_err(StoreError::Database)?,
            expires_at_ms: r.try_get("expires_at").map_err(StoreError::Database)?,
            approved_at_ms: r.try_get("approved_at").map_err(StoreError::Database)?,
            offered_at_ms: r.try_get("offered_at").map_err(StoreError::Database)?,
            issuer_consumed_at_ms: r
                .try_get("issuer_consumed_at")
                .map_err(StoreError::Database)?,
            recipient_consumed_at_ms: r
                .try_get("recipient_consumed_at")
                .map_err(StoreError::Database)?,
            completed_at_ms: r.try_get("completed_at").map_err(StoreError::Database)?,
            closed_at_ms: r.try_get("closed_at").map_err(StoreError::Database)?,
            version: r.try_get("version").map_err(StoreError::Database)?,
        }
    }};
}

/// Run one body in a transaction on whichever backend is configured. The body
/// is written once; the identifiers it names are bound per backend: `conv`
/// rewrites `?` placeholders, `now` is the clock-guarded database time
/// expression, `lock` and `join_lock` are row-lock suffixes, `audit` and
/// `enqueue` are the backend's audit and node-inbox writers.
macro_rules! in_tx {
    ($store:expr, |$tx:ident, $conv:ident, $now:ident, $lock:ident, $join_lock:ident, $audit:ident, $enqueue:ident| $body:block) => {{
        match &$store.database {
            Database::Sqlite(pool) => {
                let $conv = |s: &str| s.to_owned();
                let $now: &str = SQLITE_NOW_MS;
                let $lock: &str = "";
                let $join_lock: &str = "";
                let $audit = insert_audit_sqlite;
                let $enqueue = enqueue_node_document_sqlite;
                let mut $tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *$tx)
                    .await
                    .map_err(StoreError::Database)?;
                $body
            }
            Database::Postgres(pool) => {
                let $conv = super::pg;
                let $now: &str = POSTGRES_NOW_MS;
                let $lock: &str = " FOR UPDATE";
                let $join_lock: &str = " FOR UPDATE OF w, n";
                let $audit = insert_audit_postgres;
                let $enqueue = enqueue_node_document_postgres;
                let mut $tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT issuer_epoch FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .execute(&mut *$tx)
                    .await
                    .map_err(StoreError::Database)?;
                $body
            }
        }
    }};
}

/// One side's registered workload and enrolled node, read inside the
/// transaction that acts on it.
#[derive(Debug, Clone)]
struct PartyRow {
    node_id: String,
    unit: String,
    workload_status: String,
    registration_version: i64,
    local_ceiling_seconds: i64,
    node_status: String,
    signing_pub: String,
    recipient_pub: String,
    key_version: i64,
    blocked: bool,
}

impl PartyRow {
    fn usable(&self) -> bool {
        self.workload_status == "active" && self.node_status == "active" && !self.blocked
    }
}

const PARTY_SELECT: &str = "SELECT w.node_id, w.unit, w.status AS workload_status, \
    w.registration_version, w.local_ceiling_seconds, n.status AS node_status, n.signing_pub, \
    n.recipient_pub, n.key_version, \
    CAST(CASE WHEN EXISTS (SELECT 1 FROM node_key_rotations r WHERE r.node_id = n.id) \
      OR EXISTS (SELECT 1 FROM node_revocation_queue q WHERE q.node_id = n.id) \
      THEN 1 ELSE 0 END AS BIGINT) AS blocked \
    FROM workloads w JOIN nodes n ON n.id = w.node_id AND n.tenant_id = w.tenant_id \
    WHERE w.id = ? AND w.tenant_id = ?";

macro_rules! party_from {
    ($row:expr) => {{
        let r = &$row;
        let blocked: i64 = r.try_get("blocked").map_err(StoreError::Database)?;
        PartyRow {
            node_id: r.try_get("node_id").map_err(StoreError::Database)?,
            unit: r.try_get("unit").map_err(StoreError::Database)?,
            workload_status: r.try_get("workload_status").map_err(StoreError::Database)?,
            registration_version: r
                .try_get("registration_version")
                .map_err(StoreError::Database)?,
            local_ceiling_seconds: r
                .try_get("local_ceiling_seconds")
                .map_err(StoreError::Database)?,
            node_status: r.try_get("node_status").map_err(StoreError::Database)?,
            signing_pub: r.try_get("signing_pub").map_err(StoreError::Database)?,
            recipient_pub: r.try_get("recipient_pub").map_err(StoreError::Database)?,
            key_version: r.try_get("key_version").map_err(StoreError::Database)?,
            blocked: blocked != 0,
        }
    }};
}

fn party_terms(
    row: &PartyRow,
    workload_id: &str,
    credential: &str,
) -> Result<FulfillmentParty, StoreError> {
    let signing = blindpass_core::signing::base64_url_decode(&row.signing_pub, 32)
        .ok_or(StoreError::InvalidInput("node signing key"))?;
    let recipient = blindpass_core::signing::base64_url_decode(&row.recipient_pub, 32)
        .ok_or(StoreError::InvalidInput("node recipient key"))?;
    Ok(FulfillmentParty {
        node_id: row.node_id.clone(),
        workload_id: workload_id.to_owned(),
        unit: row.unit.clone(),
        credential: credential.to_owned(),
        registration_version: u64::try_from(row.registration_version)
            .map_err(|_| StoreError::InvalidInput("registration version"))?,
        key_version: u64::try_from(row.key_version)
            .map_err(|_| StoreError::InvalidInput("node key version"))?,
        signing_public: row.signing_pub.clone(),
        recipient_public: row.recipient_pub.clone(),
        fingerprint: node_key_fingerprint(&signing, &recipient)
            .map_err(|_| StoreError::InvalidInput("node fingerprint"))?,
    })
}

/// The cross-workload policy decision for one issuer and recipient pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossDecision {
    pub rule_id: String,
    pub decision: String,
    pub ttl_seconds: i64,
    pub approver_ids: Vec<String>,
}

/// First matching rule wins; no match, an unreadable document or an empty
/// selector denies. Selectors are explicit workload ids with no wildcard.
pub fn evaluate_cross_policy(document_json: &str, issuer: &str, recipient: &str) -> CrossDecision {
    let denied = CrossDecision {
        rule_id: "default_deny".to_owned(),
        decision: "deny".to_owned(),
        ttl_seconds: TTL_CAP_SECONDS,
        approver_ids: Vec::new(),
    };
    let Ok(document) = serde_json::from_str::<JsonValue>(document_json) else {
        return denied;
    };
    let Some(rules) = document.get("cross_workload").and_then(JsonValue::as_array) else {
        return denied;
    };
    let contains = |rule: &JsonValue, key: &str, id: &str| {
        rule.get(key)
            .and_then(JsonValue::as_array)
            .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(id)))
    };
    for rule in rules {
        if !contains(rule, "issuer_workload_ids", issuer)
            || !contains(rule, "recipient_workload_ids", recipient)
        {
            continue;
        }
        let (Some(rule_id), Some(decision)) = (
            rule.get("id").and_then(JsonValue::as_str),
            rule.get("decision").and_then(JsonValue::as_str),
        ) else {
            return denied;
        };
        if !matches!(decision, "allow" | "pending_approval" | "deny") {
            return denied;
        }
        let ttl = rule
            .get("max_ttl_seconds")
            .and_then(JsonValue::as_i64)
            .unwrap_or(TTL_CAP_SECONDS)
            .clamp(1, TTL_CAP_SECONDS);
        let approver_ids = rule
            .get("approver_ids")
            .and_then(JsonValue::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        return CrossDecision {
            rule_id: rule_id.to_owned(),
            decision: decision.to_owned(),
            ttl_seconds: ttl,
            approver_ids,
        };
    }
    denied
}

/// Inputs to creating a fulfillment.
pub struct FulfillmentCreate<'a> {
    pub id: &'a str,
    pub issuer_workload_id: &'a str,
    pub recipient_workload_id: &'a str,
    pub issuer_credential: &'a str,
    pub recipient_credential: &'a str,
    pub requested_by: &'a str,
    pub purpose: &'a str,
    pub prior_fulfillment_id: Option<&'a str>,
    pub idempotency_key: &'a str,
    pub request_hash: &'a str,
    pub audit: &'a AuditDraft,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfillmentCreateOutcome {
    Created(Box<FulfillmentRecord>),
    Existing(Box<FulfillmentRecord>),
    /// The idempotency key was used for a different request.
    Conflict,
    /// The recipient workload already has a live fulfillment.
    Busy,
    /// A named workload, node or prior fulfillment cannot take part.
    Unavailable(&'static str),
}

/// Inputs to an approval decision.
pub struct FulfillmentDecision<'a> {
    pub id: &'a str,
    pub expected_version: i64,
    pub decision: &'a str,
    pub decided_by: &'a str,
    pub decider_username: &'a str,
    /// Issuer and recipient node fingerprints the approver verified. An
    /// approval is refused when either enrolled key changed since.
    pub expected_fingerprints: Option<(&'a str, &'a str)>,
    pub audit: &'a AuditDraft,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfillmentDecideOutcome {
    Applied(Box<FulfillmentRecord>),
    Replayed(Box<FulfillmentRecord>),
    NotFound,
    Conflict,
    ScopeDenied,
    SelfApproval,
    /// Expired, or the policy, workload or node changed since the request.
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfillmentRevokeOutcome {
    Revoked(Box<FulfillmentRecord>),
    AlreadyClosed(Box<FulfillmentRecord>),
    NotFound,
}

/// What one sweep closed, for the operator log and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FulfillmentSweep {
    pub expired: u64,
    pub uncertain: u64,
    pub failed: u64,
    pub revoked: u64,
}

fn unix_u64(value: i64, label: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::InvalidInput(label))
}

fn sign_document(
    store: &Store,
    kind: DocumentKind,
    body: blindpass_core::canon::Value,
    epoch: i64,
) -> Result<String, StoreError> {
    let signer = store
        .fleet_signer
        .as_ref()
        .ok_or(StoreError::MissingState("fulfillment issuer"))?;
    signer.sign(kind, body, unix_u64(epoch, "issuer epoch")?)
}

fn revocation_document(
    store: &Store,
    record: &FulfillmentRecord,
    node_id: &str,
    reason: RevocationReason,
    now: i64,
    epoch: i64,
) -> Result<String, StoreError> {
    let digest = record
        .terms_digest
        .clone()
        .ok_or(StoreError::MissingState("fulfillment terms"))?;
    let revocation = FulfillmentRevocation {
        fulfillment_id: record.id.clone(),
        terms_digest: digest,
        node_id: node_id.to_owned(),
        reason,
        revoked_at_ms: unix_u64(now, "revocation time")?,
        retain_until_ms: unix_u64(now.saturating_add(TOMBSTONE_RETENTION_MS), "retention")?,
        issuer_epoch: unix_u64(epoch, "issuer epoch")?,
    };
    sign_document(
        store,
        DocumentKind::FulfillmentRevocation,
        revocation
            .to_value()
            .map_err(|_| StoreError::InvalidInput("fulfillment revocation"))?,
        epoch,
    )
}

fn recipient_authorization_document(
    store: &Store,
    terms: &FulfillmentTerms,
    epoch: i64,
) -> Result<String, StoreError> {
    sign_document(
        store,
        DocumentKind::FulfillmentAuthorization,
        FulfillmentAuthorization {
            side: FulfillmentSide::Recipient,
            terms: terms.clone(),
            offer: None,
        }
        .to_value()
        .map_err(|_| StoreError::InvalidInput("fulfillment authorization"))?,
        epoch,
    )
}

/// Build, sign and queue the recipient authorization, and move the row to
/// `approved`. Evaluates to `Err(code)` with a stable code, and writes
/// nothing, when either party cannot take part or the approver's expected
/// fingerprints no longer match the enrolled keys.
macro_rules! authorize {
    ($store:expr, $tx:ident, $conv:ident, $join_lock:ident, $enqueue:ident,
     $record:expr, $now_ms:expr, $epoch:expr, $approval_reference:expr, $expected:expr) => {{
        let record: &FulfillmentRecord = $record;
        let now_ms: i64 = $now_ms;
        let epoch: i64 = $epoch;
        let expected: Option<(&str, &str)> = $expected;
        'authorize: {
            let mut parties = Vec::with_capacity(2);
            for workload_id in [&record.issuer_workload_id, &record.recipient_workload_id] {
                let row = sqlx::query(&$conv(&format!("{PARTY_SELECT}{}", $join_lock)))
                    .bind(workload_id)
                    .bind(&$store.tenant_id)
                    .fetch_optional(&mut *$tx)
                    .await
                    .map_err(StoreError::Database)?;
                parties.push(match row {
                    Some(row) => Some(party_from!(row)),
                    None => None,
                });
            }
            let (Some(issuer), Some(recipient)) = (parties.remove(0), parties.remove(0)) else {
                break 'authorize Err("party_unavailable");
            };
            if !issuer.usable()
                || !recipient.usable()
                || issuer.node_id != record.issuer_node_id
                || recipient.node_id != record.recipient_node_id
            {
                break 'authorize Err("party_unavailable");
            }
            let policy_version: Option<i64> = sqlx::query_scalar(&$conv(
                "SELECT version FROM fleet_policies WHERE tenant_id = ?",
            ))
            .bind(&$store.tenant_id)
            .fetch_optional(&mut *$tx)
            .await
            .map_err(StoreError::Database)?;
            if policy_version.unwrap_or(1) != record.policy_version {
                break 'authorize Err("policy_changed");
            }
            let issuer_party = party_terms(
                &issuer,
                &record.issuer_workload_id,
                &record.issuer_credential,
            )?;
            let recipient_party = party_terms(
                &recipient,
                &record.recipient_workload_id,
                &record.recipient_credential,
            )?;
            if let Some((issuer_fingerprint, recipient_fingerprint)) = expected
                && (issuer_party.fingerprint != issuer_fingerprint
                    || recipient_party.fingerprint != recipient_fingerprint)
            {
                break 'authorize Err("fingerprint_changed");
            }
            let ceiling = issuer
                .local_ceiling_seconds
                .min(recipient.local_ceiling_seconds)
                .min(record.ttl_seconds)
                .max(1);
            let terms = FulfillmentTerms {
                fulfillment_id: record.id.clone(),
                tenant_id: $store.tenant_id.clone(),
                issuer: issuer_party,
                recipient: recipient_party,
                policy_version: unix_u64(record.policy_version, "policy version")?,
                rule_id: record.rule_id.clone(),
                approval_reference: $approval_reference,
                prior_fulfillment_id: record.prior_fulfillment_id.clone(),
                max_plaintext_bytes: blindpass_core::fulfillment::MAX_PLAINTEXT_BYTES,
                issued_at_ms: unix_u64(now_ms, "issue time")?,
                expires_at_ms: unix_u64(
                    now_ms.saturating_add(ceiling.saturating_mul(1_000)),
                    "expiry",
                )?,
                issuer_epoch: unix_u64(epoch, "issuer epoch")?,
            };
            let terms_value = terms
                .to_value()
                .map_err(|_| StoreError::InvalidInput("fulfillment terms"))?;
            let terms_json = String::from_utf8(
                canonicalize_value(&terms_value)
                    .map_err(|_| StoreError::InvalidInput("fulfillment terms"))?,
            )
            .map_err(|_| StoreError::InvalidInput("fulfillment terms"))?;
            let digest = terms
                .digest_hex()
                .map_err(|_| StoreError::InvalidInput("fulfillment terms"))?;
            let document = recipient_authorization_document($store, &terms, epoch)?;
            $enqueue(&mut $tx, &recipient.node_id, &document).await?;
            let expires_at = i64::try_from(terms.expires_at_ms)
                .map_err(|_| StoreError::InvalidInput("expiry"))?;
            sqlx::query(&$conv(
                "UPDATE cross_fulfillments SET status = 'approved', terms_json = ?, \
                 terms_digest = ?, issuer_key_version = ?, recipient_key_version = ?, \
                 issuer_registration_version = ?, recipient_registration_version = ?, \
                 approved_at = ?, expires_at = ?, version = version + 1 \
                 WHERE id = ? AND tenant_id = ?",
            ))
            .bind(&terms_json)
            .bind(&digest)
            .bind(issuer.key_version)
            .bind(recipient.key_version)
            .bind(issuer.registration_version)
            .bind(recipient.registration_version)
            .bind(now_ms)
            .bind(expires_at)
            .bind(&record.id)
            .bind(&$store.tenant_id)
            .execute(&mut *$tx)
            .await
            .map_err(StoreError::Database)?;
            Ok::<(), &'static str>(())
        }
    }};
}

/// Move a live fulfillment to a closed status, delete its payload and, when
/// authority was issued, queue a signed revocation to both nodes. Returns the
/// closed record, or `None` when the row is not in one of `$from`.
macro_rules! close {
    ($store:expr, $tx:ident, $conv:ident, $now:ident, $lock:ident, $enqueue:ident, $audit:ident,
     $id:expr, $from:expr, $status:expr, $code:expr, $reason:expr, $actor:expr, $action:expr) => {{
        let id: &str = $id;
        let row = sqlx::query(&$conv(&format!(
            "SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?{}",
            $lock
        )))
        .bind(id)
        .bind(&$store.tenant_id)
        .fetch_optional(&mut *$tx)
        .await
        .map_err(StoreError::Database)?;
        match row {
            None => None,
            Some(row) => {
                let record = record_from!(row);
                if !$from.contains(&record.status.as_str()) {
                    None
                } else {
                    let meta = sqlx::query(&format!(
                        "SELECT issuer_epoch, {} AS now_ms FROM controller_meta WHERE id = 1",
                        $now
                    ))
                    .fetch_one(&mut *$tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let epoch: i64 = meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
                    let now_ms: i64 = meta.try_get("now_ms").map_err(StoreError::Database)?;
                    let authorized = record.terms_digest.is_some();
                    let code: Option<&str> = $code;
                    let reason: &str = $reason;
                    if authorized {
                        let revocation = RevocationReason::parse($reason)
                            .ok_or(StoreError::InvalidInput("revocation reason"))?;
                        for node_id in [&record.issuer_node_id, &record.recipient_node_id] {
                            let document =
                                revocation_document($store, &record, node_id, revocation, now_ms, epoch)?;
                            $enqueue(&mut $tx, node_id, &document).await?;
                        }
                    }
                    sqlx::query(&$conv("DELETE FROM cross_fulfillment_payloads WHERE fulfillment_id = ? AND tenant_id = ?"))
                        .bind(id)
                        .bind(&$store.tenant_id)
                        .execute(&mut *$tx)
                        .await
                        .map_err(StoreError::Database)?;
                    sqlx::query(&$conv(
                        "UPDATE cross_fulfillments SET status = ?, failure_code = ?, \
                         revocation_reason = ?, delivery_revoked_at = ?, closed_at = ?, \
                         version = version + 1 WHERE id = ? AND tenant_id = ?",
                    ))
                    .bind($status)
                    .bind(code)
                    .bind(reason)
                    .bind(authorized.then_some(now_ms))
                    // `uncertain` keeps the recipient slot and is not closed
                    // until an operator reconciles it.
                    .bind(($status != "uncertain").then_some(now_ms))
                    .bind(id)
                    .bind(&$store.tenant_id)
                    .execute(&mut *$tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let audit = AuditDraft {
                        action: $action.to_owned(),
                        actor_type: if $actor.is_some() { "operator" } else { "system" }.to_owned(),
                        actor_id: $actor.map(str::to_owned),
                        target_type: "fulfillment".to_owned(),
                        target_id: Some(id.to_owned()),
                        metadata: json!({
                            "outcome": $status,
                            "failure_code": code,
                            "revocation_reason": reason,
                            "authority_issued": authorized,
                            "provider_revocation": record.provider_revocation,
                            "issuer_node_id": record.issuer_node_id,
                            "recipient_node_id": record.recipient_node_id,
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    };
                    $audit(&mut $tx, &$store.tenant_id, &audit).await?;
                    let row = sqlx::query(&$conv(&format!(
                        "SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?"
                    )))
                    .bind(id)
                    .bind(&$store.tenant_id)
                    .fetch_one(&mut *$tx)
                    .await
                    .map_err(StoreError::Database)?;
                    Some(record_from!(row))
                }
            }
        }
    }};
}

enum ParsedEvent {
    Offer(SignedEnvelope, FulfillmentOffer),
    Submit(
        SignedEnvelope,
        blindpass_core::fulfillment::FulfillmentSubmit,
    ),
    Result(FulfillmentResult),
}

impl ParsedEvent {
    fn parse(kind: &str, body_json: &str) -> Result<Self, StoreError> {
        let invalid = StoreError::InvalidInput("fulfillment event");
        match kind {
            "fulfillment_offer" => {
                let envelope = SignedEnvelope::from_json(body_json).map_err(|_| invalid)?;
                let offer = FulfillmentOffer::from_value(envelope.body())
                    .map_err(|_| StoreError::InvalidInput("fulfillment offer"))?;
                if envelope.kind() != DocumentKind::FulfillmentOffer {
                    return Err(StoreError::InvalidInput("fulfillment offer kind"));
                }
                Ok(Self::Offer(envelope, offer))
            }
            "fulfillment_submit" => {
                let envelope = SignedEnvelope::from_json(body_json).map_err(|_| invalid)?;
                let submit =
                    blindpass_core::fulfillment::FulfillmentSubmit::from_value(envelope.body())
                        .map_err(|_| StoreError::InvalidInput("fulfillment submission"))?;
                if envelope.kind() != DocumentKind::FulfillmentSubmit {
                    return Err(StoreError::InvalidInput("fulfillment submission kind"));
                }
                Ok(Self::Submit(envelope, submit))
            }
            "fulfillment_result" => {
                let value = blindpass_core::canon::parse_json(body_json).map_err(|_| invalid)?;
                Ok(Self::Result(
                    FulfillmentResult::from_value(&value)
                        .map_err(|_| StoreError::InvalidInput("fulfillment result"))?,
                ))
            }
            _ => Err(invalid),
        }
    }

    fn fulfillment_id(&self) -> &str {
        match self {
            Self::Offer(_, offer) => &offer.fulfillment_id,
            Self::Submit(_, submit) => &submit.fulfillment_id,
            Self::Result(result) => &result.fulfillment_id,
        }
    }
}

impl Store {
    pub async fn fulfillment_by_id(
        &self,
        id: &str,
    ) -> Result<Option<FulfillmentRecord>, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let sql =
                format!("SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?");
            match &self.database {
                Database::Sqlite(pool) => {
                    let row = sqlx::query(&sql)
                        .bind(id)
                        .bind(&self.tenant_id)
                        .fetch_optional(pool)
                        .await
                        .map_err(StoreError::Database)?;
                    Ok(match row {
                        Some(row) => Some(record_from!(row)),
                        None => None,
                    })
                }
                Database::Postgres(pool) => {
                    let row = sqlx::query(&super::pg(&sql))
                        .bind(id)
                        .bind(&self.tenant_id)
                        .fetch_optional(pool)
                        .await
                        .map_err(StoreError::Database)?;
                    Ok(match row {
                        Some(row) => Some(record_from!(row)),
                        None => None,
                    })
                }
            }
        })
        .await
    }

    pub async fn list_fulfillments(
        &self,
        status: Option<&str>,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<FulfillmentRecord>, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let limit = i64::from(limit.clamp(1, 101));
            let status = status.unwrap_or("");
            let sql = format!(
                "SELECT {COLUMNS} FROM cross_fulfillments WHERE tenant_id = ? \
                 AND (? = '' OR status = ?) \
                 AND (? IS NULL OR created_at < ? OR (created_at = ? AND id < ?)) \
                 ORDER BY created_at DESC, id DESC LIMIT ?"
            );
            macro_rules! list {
                ($pool:expr, $sql:expr, $cast:expr) => {{
                    let rows = sqlx::query($sql)
                        .bind(&self.tenant_id)
                        .bind(status)
                        .bind(status)
                        .bind(cursor.as_ref().map(|value| value.0))
                        .bind(cursor.as_ref().map(|value| value.0))
                        .bind(cursor.as_ref().map(|value| value.0))
                        .bind(cursor.as_ref().map(|value| value.1.as_str()))
                        .bind(limit)
                        .fetch_all($pool)
                        .await
                        .map_err(StoreError::Database)?;
                    let mut records = Vec::with_capacity(rows.len());
                    for row in &rows {
                        records.push(record_from!(row));
                    }
                    Ok(records)
                }};
            }
            match &self.database {
                Database::Sqlite(pool) => list!(pool, &sql, ()),
                Database::Postgres(pool) => list!(pool, &super::pg(&sql), ()),
            }
        })
        .await
    }

    pub async fn create_fulfillment(
        &self,
        input: &FulfillmentCreate<'_>,
    ) -> Result<FulfillmentCreateOutcome, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            in_tx!(self, |tx, conv, now, lock, join_lock, audit, enqueue| {
                let existing = sqlx::query(&conv(&format!(
                    "SELECT {COLUMNS} FROM cross_fulfillments \
                     WHERE tenant_id = ? AND requested_by = ? AND idempotency_key = ?"
                )))
                .bind(&self.tenant_id)
                .bind(input.requested_by)
                .bind(input.idempotency_key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if let Some(row) = existing {
                    let existing = record_from!(row);
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(if existing.request_hash == input.request_hash {
                        FulfillmentCreateOutcome::Existing(Box::new(existing))
                    } else {
                        FulfillmentCreateOutcome::Conflict
                    });
                }
                let meta = sqlx::query(&format!(
                    "SELECT issuer_epoch, {now} AS now_ms FROM controller_meta WHERE id = 1"
                ))
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let epoch: i64 = meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
                let now_ms: i64 = meta.try_get("now_ms").map_err(StoreError::Database)?;
                let mut rows = Vec::with_capacity(2);
                for workload_id in [input.issuer_workload_id, input.recipient_workload_id] {
                    let row = sqlx::query(&conv(&format!("{PARTY_SELECT}{join_lock}")))
                        .bind(workload_id)
                        .bind(&self.tenant_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                    rows.push(match row {
                        Some(row) => Some(party_from!(row)),
                        None => None,
                    });
                }
                let (Some(issuer), Some(recipient)) = (rows.remove(0), rows.remove(0)) else {
                    return Ok(FulfillmentCreateOutcome::Unavailable("workload_not_found"));
                };
                if !issuer.usable() || !recipient.usable() {
                    return Ok(FulfillmentCreateOutcome::Unavailable("party_unavailable"));
                }
                if issuer.node_id == recipient.node_id
                    || input.issuer_workload_id == input.recipient_workload_id
                {
                    return Ok(FulfillmentCreateOutcome::Unavailable("same_party"));
                }
                if let Some(prior) = input.prior_fulfillment_id {
                    let prior_ok: Option<String> = sqlx::query_scalar(&conv(
                        "SELECT status FROM cross_fulfillments WHERE id = ? AND tenant_id = ? \
                         AND recipient_workload_id = ?",
                    ))
                    .bind(prior)
                    .bind(&self.tenant_id)
                    .bind(input.recipient_workload_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    if !matches!(
                        prior_ok.as_deref(),
                        Some("completed" | "recipient_consumed")
                    ) {
                        return Ok(FulfillmentCreateOutcome::Unavailable("prior_invalid"));
                    }
                }
                let busy: bool = sqlx::query_scalar(&conv(&format!(
                    "SELECT EXISTS(SELECT 1 FROM cross_fulfillments WHERE tenant_id = ? \
                     AND recipient_workload_id = ? AND status IN ({}))",
                    ACTIVE_STATUSES
                        .iter()
                        .map(|status| format!("'{status}'"))
                        .collect::<Vec<_>>()
                        .join(",")
                )))
                .bind(&self.tenant_id)
                .bind(input.recipient_workload_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if busy {
                    return Ok(FulfillmentCreateOutcome::Busy);
                }
                let policy = sqlx::query(&conv(
                    "SELECT version, document_json FROM fleet_policies WHERE tenant_id = ?",
                ))
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let (policy_version, document_json) = match policy {
                    Some(row) => (
                        row.try_get::<i64, _>("version")
                            .map_err(StoreError::Database)?,
                        row.try_get::<String, _>("document_json")
                            .map_err(StoreError::Database)?,
                    ),
                    None => (1, "{\"rules\":[]}".to_owned()),
                };
                let decided = evaluate_cross_policy(
                    &document_json,
                    input.issuer_workload_id,
                    input.recipient_workload_id,
                );
                let (status, approval_status) = match decided.decision.as_str() {
                    "deny" => ("denied", "not_required"),
                    "pending_approval" => ("awaiting_approval", "pending"),
                    _ => ("awaiting_approval", "not_required"),
                };
                let expires_at = now_ms.saturating_add(TTL_CAP_SECONDS * 1_000);
                let inserted = sqlx::query(&conv(
                    "INSERT INTO cross_fulfillments (id, tenant_id, issuer_workload_id, \
                     recipient_workload_id, issuer_node_id, recipient_node_id, issuer_credential, \
                     recipient_credential, mode, requested_by, purpose, policy_version, rule_id, \
                     decision, approver_ids_json, approval_status, prior_fulfillment_id, \
                     ttl_seconds, status, idempotency_key, request_hash, created_at, expires_at, \
                     closed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'reencrypt', ?, ?, ?, ?, ?, ?, ?, \
                     ?, ?, ?, ?, ?, ?, ?, ?)",
                ))
                .bind(input.id)
                .bind(&self.tenant_id)
                .bind(input.issuer_workload_id)
                .bind(input.recipient_workload_id)
                .bind(&issuer.node_id)
                .bind(&recipient.node_id)
                .bind(input.issuer_credential)
                .bind(input.recipient_credential)
                .bind(input.requested_by)
                .bind(input.purpose)
                .bind(policy_version)
                .bind(&decided.rule_id)
                .bind(&decided.decision)
                .bind(
                    serde_json::to_string(&decided.approver_ids)
                        .map_err(|_| StoreError::InvalidInput("approver ids"))?,
                )
                .bind(approval_status)
                .bind(input.prior_fulfillment_id)
                .bind(decided.ttl_seconds)
                .bind(status)
                .bind(input.idempotency_key)
                .bind(input.request_hash)
                .bind(now_ms)
                .bind(expires_at)
                .bind((status == "denied").then_some(now_ms))
                .execute(&mut *tx)
                .await;
                match inserted {
                    Ok(_) => {}
                    Err(error)
                        if error
                            .as_database_error()
                            .is_some_and(|database| database.is_unique_violation()) =>
                    {
                        return Ok(FulfillmentCreateOutcome::Busy);
                    }
                    Err(error) => return Err(StoreError::Database(error)),
                }
                let created = sqlx::query(&conv(&format!(
                    "SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?"
                )))
                .bind(input.id)
                .bind(&self.tenant_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let mut created = record_from!(created);
                if decided.decision == "allow" {
                    if let Err(code) = authorize!(
                        self, tx, conv, join_lock, enqueue, &created, now_ms, epoch, None, None
                    ) {
                        return Ok(FulfillmentCreateOutcome::Unavailable(code));
                    }
                    let row = sqlx::query(&conv(&format!(
                        "SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?"
                    )))
                    .bind(input.id)
                    .bind(&self.tenant_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    created = record_from!(row);
                }
                let audit_draft = input
                    .audit
                    .clone()
                    .with_detail("decision", decided.decision.clone().into())
                    .with_detail("rule_id", decided.rule_id.clone().into())
                    .with_detail("status", created.status.clone().into())
                    .with_detail("issuer_node_id", created.issuer_node_id.clone().into())
                    .with_detail(
                        "recipient_node_id",
                        created.recipient_node_id.clone().into(),
                    );
                audit(&mut tx, &self.tenant_id, &audit_draft).await?;
                let _ = lock;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(FulfillmentCreateOutcome::Created(Box::new(created)))
            })
        })
        .await
    }

    pub async fn decide_fulfillment(
        &self,
        input: &FulfillmentDecision<'_>,
    ) -> Result<FulfillmentDecideOutcome, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let target_status = if input.decision == "approved" {
                "approved"
            } else {
                "denied"
            };
            in_tx!(self, |tx, conv, now, lock, join_lock, audit, enqueue| {
                let row = sqlx::query(&conv(&format!(
                    "SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?{lock}"
                )))
                .bind(input.id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(row) = row else {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(FulfillmentDecideOutcome::NotFound);
                };
                let record = record_from!(row);
                if record.status == target_status
                    && record.version == input.expected_version.saturating_add(1)
                    && record.decided_by.as_deref() == Some(input.decided_by)
                {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(FulfillmentDecideOutcome::Replayed(Box::new(record)));
                }
                if !matches!(input.decision, "approved" | "rejected")
                    || (input.decision == "approved" && input.expected_fingerprints.is_none())
                    || record.status != "awaiting_approval"
                    || record.approval_status != "pending"
                    || record.version != input.expected_version
                {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(FulfillmentDecideOutcome::Conflict);
                }
                let approvers: Vec<String> = serde_json::from_str(&record.approver_ids_json)
                    .map_err(|_| StoreError::InvalidInput("approver ids"))?;
                if !approvers.iter().any(|approver| {
                    approver == input.decided_by || approver == input.decider_username
                }) {
                    let denied = input
                        .audit
                        .clone()
                        .with_detail("outcome", "approval_scope_denied".into());
                    audit(&mut tx, &self.tenant_id, &denied).await?;
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(FulfillmentDecideOutcome::ScopeDenied);
                }
                if record.requested_by == input.decided_by {
                    let denied = input
                        .audit
                        .clone()
                        .with_detail("outcome", "self_approval_denied".into());
                    audit(&mut tx, &self.tenant_id, &denied).await?;
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(FulfillmentDecideOutcome::SelfApproval);
                }
                let meta = sqlx::query(&format!(
                    "SELECT issuer_epoch, {now} AS now_ms FROM controller_meta WHERE id = 1"
                ))
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let epoch: i64 = meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
                let now_ms: i64 = meta.try_get("now_ms").map_err(StoreError::Database)?;
                if input.decision == "rejected" {
                    sqlx::query(&conv(
                        "UPDATE cross_fulfillments SET status = 'denied', approval_status = 'rejected', \
                         decided_by = ?, decided_at = ?, closed_at = ?, version = version + 1 \
                         WHERE id = ? AND tenant_id = ?",
                    ))
                    .bind(input.decided_by)
                    .bind(now_ms)
                    .bind(now_ms)
                    .bind(input.id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                } else {
                    if record.expires_at_ms <= now_ms {
                        sqlx::query(&conv(
                            "UPDATE cross_fulfillments SET status = 'expired', closed_at = ?, \
                             version = version + 1 WHERE id = ? AND tenant_id = ?",
                        ))
                        .bind(now_ms)
                        .bind(input.id)
                        .bind(&self.tenant_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                        tx.commit().await.map_err(StoreError::Database)?;
                        return Ok(FulfillmentDecideOutcome::Stale);
                    }
                    sqlx::query(&conv(
                        "UPDATE cross_fulfillments SET approval_status = 'approved', \
                         decided_by = ?, decided_at = ? WHERE id = ? AND tenant_id = ?",
                    ))
                    .bind(input.decided_by)
                    .bind(now_ms)
                    .bind(input.id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let reference = format!("fa_{}", &record.id[record.id.len().saturating_sub(24)..]);
                    if authorize!(
                        self,
                        tx,
                        conv,
                        join_lock,
                        enqueue,
                        &record,
                        now_ms,
                        epoch,
                        Some(reference),
                        input.expected_fingerprints
                    )
                    .is_err()
                    {
                        // Nothing was queued or changed beyond this transaction.
                        return Ok(FulfillmentDecideOutcome::Stale);
                    }
                }
                let row = sqlx::query(&conv(&format!(
                    "SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?"
                )))
                .bind(input.id)
                .bind(&self.tenant_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let applied = record_from!(row);
                let audit_draft = input
                    .audit
                    .clone()
                    .with_detail("outcome", target_status.into())
                    .with_detail("rule_id", applied.rule_id.clone().into())
                    .with_detail("terms_digest", applied.terms_digest.clone().into());
                audit(&mut tx, &self.tenant_id, &audit_draft).await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(FulfillmentDecideOutcome::Applied(Box::new(applied)))
            })
        })
        .await
    }

    pub async fn revoke_fulfillment(
        &self,
        id: &str,
        operator_id: &str,
    ) -> Result<FulfillmentRevokeOutcome, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            in_tx!(self, |tx, conv, now, lock, join_lock, audit, enqueue| {
                let _ = join_lock;
                let closed = close!(
                    self,
                    tx,
                    conv,
                    now,
                    lock,
                    enqueue,
                    audit,
                    id,
                    ACTIVE_STATUSES,
                    "revoked",
                    None,
                    "operator",
                    Some(operator_id),
                    "fleet.fulfillment_revoked"
                );
                match closed {
                    Some(record) => {
                        tx.commit().await.map_err(StoreError::Database)?;
                        Ok(FulfillmentRevokeOutcome::Revoked(Box::new(record)))
                    }
                    None => {
                        let row = sqlx::query(&conv(&format!(
                            "SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?"
                        )))
                        .bind(id)
                        .bind(&self.tenant_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                        tx.commit().await.map_err(StoreError::Database)?;
                        Ok(match row {
                            Some(row) => FulfillmentRevokeOutcome::AlreadyClosed(Box::new(
                                record_from!(row),
                            )),
                            None => FulfillmentRevokeOutcome::NotFound,
                        })
                    }
                }
            })
        })
        .await
    }

    /// Verify and apply one node-signed fulfillment event. The outer broker
    /// signature was verified by the node transport; the inner envelope or
    /// result is independently checked against the stored terms here.
    pub(crate) async fn record_fulfillment_event(
        &self,
        node_id: &str,
        key: &str,
        kind: &str,
        body_json: &str,
        body_hash: &str,
    ) -> Result<NodeEventInsert, StoreError> {
        let parsed = ParsedEvent::parse(kind, body_json)?;
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let fulfillment_id = parsed.fulfillment_id().to_owned();
            in_tx!(self, |tx, conv, now, lock, join_lock, audit, enqueue| {
                let prior: Option<String> = sqlx::query_scalar(&conv(
                    "SELECT body_hash FROM node_events WHERE node_id = ? AND idempotency_key = ?",
                ))
                .bind(node_id)
                .bind(key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if let Some(prior) = prior {
                    return Ok(if prior == body_hash {
                        NodeEventInsert::Duplicate
                    } else {
                        NodeEventInsert::Conflict
                    });
                }
                let row = sqlx::query(&conv(&format!(
                    "SELECT {COLUMNS} FROM cross_fulfillments WHERE id = ? AND tenant_id = ?{lock}"
                )))
                .bind(&fulfillment_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .ok_or(StoreError::InvalidInput("unknown fulfillment"))?;
                let record = record_from!(row);
                let meta = sqlx::query(&format!(
                    "SELECT issuer_epoch, {now} AS now_ms FROM controller_meta WHERE id = 1"
                ))
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let epoch: i64 = meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
                let now_ms: i64 = meta.try_get("now_ms").map_err(StoreError::Database)?;
                let now_u64 = unix_u64(now_ms, "event time")?;
                let terms = record
                    .terms_json
                    .as_deref()
                    .map(|json| {
                        blindpass_core::canon::parse_json(json)
                            .map_err(|_| StoreError::InvalidInput("fulfillment terms"))
                            .and_then(|value| {
                                FulfillmentTerms::from_value(&value)
                                    .map_err(|_| StoreError::InvalidInput("fulfillment terms"))
                            })
                    })
                    .transpose()?
                    .ok_or(StoreError::InvalidInput("fulfillment not authorized"))?;
                if record.terms_digest.as_deref()
                    != Some(
                        &terms
                            .digest_hex()
                            .map_err(|_| StoreError::InvalidInput("fulfillment terms"))?,
                    )
                {
                    return Err(StoreError::InvalidInput("fulfillment terms digest"));
                }
                // The enrolled key the event must have been signed under must
                // still be this node's current key, and nothing may be pending.
                let node_check = |expected_node: &str, expected_version: u64, node: &PartyRow| {
                    node.node_id == expected_node
                        && node.node_status == "active"
                        && !node.blocked
                        && u64::try_from(node.key_version).ok() == Some(expected_version)
                };
                let audit_action: &str;
                let audit_details: JsonValue;
                match &parsed {
                    ParsedEvent::Offer(envelope, parsed_offer) => {
                        if record.status != "approved" || record.recipient_node_id != node_id {
                            return Err(StoreError::InvalidInput("fulfillment offer state"));
                        }
                        if terms.issuer_epoch != unix_u64(epoch, "issuer epoch")? {
                            return Err(StoreError::InvalidInput("fulfillment epoch"));
                        }
                        // A node clock may run slightly ahead of the controller.
                        // Accept that skew, never an offer from further in the
                        // future, and verify at the later of the two instants.
                        if parsed_offer.issued_at_ms > now_u64.saturating_add(OFFER_SKEW_MS) {
                            return Err(StoreError::InvalidInput("fulfillment offer time"));
                        }
                        let offer = verify_offer(
                            envelope,
                            &terms,
                            now_u64.max(parsed_offer.issued_at_ms),
                        )
                        .map_err(|_| StoreError::InvalidInput("fulfillment offer"))?;
                        let recipient_row_raw = sqlx::query(&conv(&format!("{PARTY_SELECT}{join_lock}")))
                            .bind(&record.recipient_workload_id)
                            .bind(&self.tenant_id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(StoreError::Database)?;
                        let recipient_row = match recipient_row_raw {
                            Some(row) => party_from!(row),
                            None => return Err(StoreError::InvalidInput("fulfillment recipient")),
                        };
                        if !node_check(
                            node_id,
                            terms.recipient.key_version,
                            &recipient_row,
                        ) || i64::try_from(terms.recipient.registration_version).ok()
                            != Some(recipient_row.registration_version)
                            || recipient_row.workload_status != "active"
                        {
                            return Err(StoreError::InvalidInput("fulfillment recipient state"));
                        }
                        let policy_version: Option<i64> = sqlx::query_scalar(&conv(
                            "SELECT version FROM fleet_policies WHERE tenant_id = ?",
                        ))
                        .bind(&self.tenant_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                        if policy_version.unwrap_or(1) != record.policy_version {
                            return Err(StoreError::InvalidInput("fulfillment policy"));
                        }
                        let authorization = FulfillmentAuthorization {
                            side: FulfillmentSide::Issuer,
                            terms: terms.clone(),
                            offer: Some(envelope.clone()),
                        };
                        let document = sign_document(
                            self,
                            DocumentKind::FulfillmentAuthorization,
                            authorization
                                .to_value()
                                .map_err(|_| StoreError::InvalidInput("fulfillment authorization"))?,
                            epoch,
                        )?;
                        enqueue(&mut tx, &record.issuer_node_id, &document).await?;
                        let offer_json = String::from_utf8(
                            envelope
                                .to_json()
                                .map_err(|_| StoreError::InvalidInput("fulfillment offer"))?,
                        )
                        .map_err(|_| StoreError::InvalidInput("fulfillment offer"))?;
                        sqlx::query(&conv(
                            "UPDATE cross_fulfillments SET status = 'offered', offer_json = ?, \
                             offered_at = ?, version = version + 1 WHERE id = ? AND tenant_id = ?",
                        ))
                        .bind(&offer_json)
                        .bind(now_ms)
                        .bind(&record.id)
                        .bind(&self.tenant_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                        audit_action = "fleet.fulfillment_offer_recorded";
                        audit_details = json!({"offer_id": offer.offer_id});
                    }
                    ParsedEvent::Submit(envelope, _) => {
                        if record.status != "offered" || record.issuer_node_id != node_id {
                            return Err(StoreError::InvalidInput("fulfillment submission state"));
                        }
                        if terms.issuer_epoch != unix_u64(epoch, "issuer epoch")?
                            || terms.expires_at_ms <= now_u64
                        {
                            return Err(StoreError::InvalidInput("fulfillment submission epoch"));
                        }
                        let offer_envelope = SignedEnvelope::from_json(
                            record
                                .offer_json
                                .as_deref()
                                .ok_or(StoreError::InvalidInput("fulfillment offer"))?,
                        )
                        .map_err(|_| StoreError::InvalidInput("fulfillment offer"))?;
                        let offer = FulfillmentOffer::from_value(offer_envelope.body())
                            .map_err(|_| StoreError::InvalidInput("fulfillment offer"))?;
                        let submit = verify_submit(envelope, &terms, &offer)
                            .map_err(|_| StoreError::InvalidInput("fulfillment submission"))?;
                        let issuer_row_raw = sqlx::query(&conv(&format!("{PARTY_SELECT}{join_lock}")))
                            .bind(&record.issuer_workload_id)
                            .bind(&self.tenant_id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(StoreError::Database)?;
                        let issuer_row = match issuer_row_raw {
                            Some(row) => party_from!(row),
                            None => return Err(StoreError::InvalidInput("fulfillment issuer")),
                        };
                        if !node_check(node_id, terms.issuer.key_version, &issuer_row)
                            || i64::try_from(terms.issuer.registration_version).ok()
                                != Some(issuer_row.registration_version)
                            || issuer_row.workload_status != "active"
                        {
                            return Err(StoreError::InvalidInput("fulfillment issuer state"));
                        }
                        let submit_json = String::from_utf8(
                            envelope
                                .to_json()
                                .map_err(|_| StoreError::InvalidInput("fulfillment submission"))?,
                        )
                        .map_err(|_| StoreError::InvalidInput("fulfillment submission"))?;
                        sqlx::query(&conv(
                            "INSERT INTO cross_fulfillment_payloads \
                             (fulfillment_id, tenant_id, submit_json, ciphertext_digest, created_at) \
                             VALUES (?, ?, ?, ?, ?)",
                        ))
                        .bind(&record.id)
                        .bind(&self.tenant_id)
                        .bind(&submit_json)
                        .bind(&submit.ciphertext_digest)
                        .bind(now_ms)
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                        let delivery = FulfillmentDelivery {
                            terms: terms.clone(),
                            offer: offer_envelope,
                            submit: envelope.clone(),
                        };
                        let document = sign_document(
                            self,
                            DocumentKind::FulfillmentDelivery,
                            delivery
                                .to_value()
                                .map_err(|_| StoreError::InvalidInput("fulfillment delivery"))?,
                            epoch,
                        )?;
                        enqueue(&mut tx, &record.recipient_node_id, &document).await?;
                        sqlx::query(&conv(
                            "UPDATE cross_fulfillments SET status = 'available', \
                             issuer_consumed_at = ?, version = version + 1 \
                             WHERE id = ? AND tenant_id = ?",
                        ))
                        .bind(now_ms)
                        .bind(&record.id)
                        .bind(&self.tenant_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                        audit_action = "fleet.fulfillment_submitted";
                        audit_details = json!({
                            "offer_id": submit.offer_id,
                            "ciphertext_digest": submit.ciphertext_digest,
                        });
                    }
                    ParsedEvent::Result(result) => {
                        if result.terms_digest != terms.digest_hex().map_err(|_| StoreError::InvalidInput("terms"))? {
                            return Err(StoreError::InvalidInput("fulfillment result terms"));
                        }
                        let expected_node = match result.side {
                            FulfillmentSide::Issuer => &record.issuer_node_id,
                            FulfillmentSide::Recipient => &record.recipient_node_id,
                        };
                        if expected_node != node_id {
                            return Err(StoreError::InvalidInput("fulfillment result node"));
                        }
                        audit_action = "fleet.fulfillment_result";
                        audit_details = json!({
                            "side": result.side.as_str(),
                            "state": result.state.as_str(),
                            "code": result.code,
                            "applied_to": record.status,
                        });
                        match (result.side, result.state) {
                            (FulfillmentSide::Recipient, ResultState::Stored)
                                if matches!(record.status.as_str(), "available" | "uncertain") =>
                            {
                                sqlx::query(&conv("DELETE FROM cross_fulfillment_payloads WHERE fulfillment_id = ? AND tenant_id = ?"))
                                    .bind(&record.id).bind(&self.tenant_id)
                                    .execute(&mut *tx).await.map_err(StoreError::Database)?;
                                if record.status == "uncertain" {
                                    // The deadline already passed and revocations
                                    // went out; the broker drops an unread credential
                                    // at expiry, so a late `stored` only reconciles
                                    // the record. A late `consumed` completes it.
                                    sqlx::query(&conv(
                                        "UPDATE cross_fulfillments SET status = 'expired', \
                                         recipient_consumed_at = ?, failure_code = 'stored_not_consumed', \
                                         closed_at = ?, version = version + 1 \
                                         WHERE id = ? AND tenant_id = ?",
                                    ))
                                    .bind(now_ms).bind(now_ms).bind(&record.id).bind(&self.tenant_id)
                                    .execute(&mut *tx).await.map_err(StoreError::Database)?;
                                } else {
                                    sqlx::query(&conv(
                                        "UPDATE cross_fulfillments SET status = 'recipient_consumed', \
                                         recipient_consumed_at = ?, failure_code = NULL, \
                                         version = version + 1 WHERE id = ? AND tenant_id = ?",
                                    ))
                                    .bind(now_ms).bind(&record.id).bind(&self.tenant_id)
                                    .execute(&mut *tx).await.map_err(StoreError::Database)?;
                                }
                            }
                            (FulfillmentSide::Recipient, ResultState::Consumed)
                                if matches!(
                                    record.status.as_str(),
                                    "available" | "recipient_consumed" | "uncertain"
                                ) =>
                            {
                                sqlx::query(&conv("DELETE FROM cross_fulfillment_payloads WHERE fulfillment_id = ? AND tenant_id = ?"))
                                    .bind(&record.id).bind(&self.tenant_id)
                                    .execute(&mut *tx).await.map_err(StoreError::Database)?;
                                sqlx::query(&conv(
                                    "UPDATE cross_fulfillments SET status = 'completed', \
                                     recipient_consumed_at = COALESCE(recipient_consumed_at, ?), \
                                     completed_at = ?, closed_at = ?, failure_code = NULL, \
                                     version = version + 1 WHERE id = ? AND tenant_id = ?",
                                ))
                                .bind(now_ms).bind(now_ms).bind(now_ms)
                                .bind(&record.id).bind(&self.tenant_id)
                                .execute(&mut *tx).await.map_err(StoreError::Database)?;
                            }
                            (_, ResultState::Failed)
                                if matches!(
                                    record.status.as_str(),
                                    "approved" | "offered" | "available" | "recipient_consumed" | "uncertain"
                                ) =>
                            {
                                let code = result.code.as_deref();
                                let closed = close!(
                                    self,
                                    tx,
                                    conv,
                                    now,
                                    lock,
                                    enqueue,
                                    audit,
                                    &record.id,
                                    ["approved", "offered", "available", "recipient_consumed", "uncertain"],
                                    "failed",
                                    code,
                                    "failed",
                                    None::<&str>,
                                    "fleet.fulfillment_failed"
                                );
                                if closed.is_none() {
                                    return Err(StoreError::InvalidInput("fulfillment result state"));
                                }
                            }
                            // A result for a closed fulfillment is recorded as
                            // evidence only; it can never resurrect authority.
                            _ => {}
                        }
                    }
                }
                sqlx::query(&conv(
                    "INSERT INTO node_events (id, node_id, idempotency_key, kind, body_json, \
                     body_hash, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ))
                .bind(format!("ne_{}", super::new_hex_id()))
                .bind(node_id)
                .bind(key)
                .bind(kind)
                .bind(body_json)
                .bind(body_hash)
                .bind(now_ms)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let evidence = AuditDraft {
                    action: audit_action.to_owned(),
                    actor_type: "node".to_owned(),
                    actor_id: Some(node_id.to_owned()),
                    target_type: "fulfillment".to_owned(),
                    target_id: Some(record.id.clone()),
                    metadata: {
                        let mut metadata = audit_details
                            .as_object()
                            .cloned()
                            .unwrap_or_default();
                        metadata.insert("node_id".to_owned(), json!(node_id));
                        metadata.insert("terms_digest".to_owned(), json!(record.terms_digest));
                        metadata
                    },
                };
                audit(&mut tx, &self.tenant_id, &evidence).await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(NodeEventInsert::Inserted)
            })
        })
        .await
    }

    /// Close every fulfillment that can no longer complete: past its deadline,
    /// or whose node, registration, policy or key changed, or all of them when
    /// the feature is disabled. Idempotent; bounded per pass.
    pub async fn expire_fulfillments(&self, enabled: bool) -> Result<FulfillmentSweep, StoreError> {
        // Each read below and each close is its own owned operation; nesting
        // them inside one would claim the ownership latch twice.
        let now_ms = self.database_now_ms().await?;
        let candidates = self.live_fulfillment_ids().await?;
        let mut summary = FulfillmentSweep::default();
        for id in candidates {
            let Some(record) = self.fulfillment_by_id(&id).await? else {
                continue;
            };
            let Some((status, code, reason)) = self.sweep_verdict(&record, now_ms, enabled).await?
            else {
                continue;
            };
            let closed = self
                .run_owned(async {
                    self.checkpoint_clock().await?;
                    in_tx!(self, |tx, conv, now, lock, join_lock, audit, enqueue| {
                        let _ = join_lock;
                        let closed = close!(
                            self,
                            tx,
                            conv,
                            now,
                            lock,
                            enqueue,
                            audit,
                            &id,
                            ACTIVE_STATUSES,
                            status,
                            code,
                            reason,
                            None::<&str>,
                            "fleet.fulfillment_closed"
                        );
                        tx.commit().await.map_err(StoreError::Database)?;
                        Ok::<bool, StoreError>(closed.is_some())
                    })
                })
                .await?;
            if closed {
                match status {
                    "expired" => summary.expired += 1,
                    "uncertain" => summary.uncertain += 1,
                    "failed" => summary.failed += 1,
                    _ => summary.revoked += 1,
                }
            }
        }
        Ok(summary)
    }

    /// Remove terminal fulfillment lineage older than the audit retention, so
    /// lineage and audit age out together. Payloads of closed rows are already
    /// gone; any stray one is deleted first. Returns the rows removed.
    pub async fn prune_fulfillments(&self, retention_days: u32) -> Result<u64, StoreError> {
        let retention_ms = i64::from(retention_days)
            .checked_mul(86_400_000)
            .filter(|value| *value > 0)
            .ok_or(StoreError::InvalidInput("fulfillment retention"))?;
        self.run_owned(async {
            self.checkpoint_clock().await?;
            const TERMINAL: &str = "('completed','denied','revoked','expired','failed')";
            match &self.database {
                Database::Sqlite(pool) => {
                    let stale = format!(
                        "tenant_id = ? AND status IN {TERMINAL} AND closed_at IS NOT NULL \
                         AND closed_at <= {SQLITE_NOW_MS} - ?"
                    );
                    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                    sqlx::query(&format!(
                        "DELETE FROM cross_fulfillment_payloads WHERE fulfillment_id IN \
                         (SELECT id FROM cross_fulfillments WHERE {stale})"
                    ))
                    .bind(&self.tenant_id)
                    .bind(retention_ms)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let removed =
                        sqlx::query(&format!("DELETE FROM cross_fulfillments WHERE {stale}"))
                            .bind(&self.tenant_id)
                            .bind(retention_ms)
                            .execute(&mut *tx)
                            .await
                            .map_err(StoreError::Database)?
                            .rows_affected();
                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(removed)
                }
                Database::Postgres(pool) => {
                    let stale = format!(
                        "tenant_id = $1 AND status IN {TERMINAL} AND closed_at IS NOT NULL \
                         AND closed_at <= {POSTGRES_NOW_MS} - $2::BIGINT"
                    );
                    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                    sqlx::query(&format!(
                        "DELETE FROM cross_fulfillment_payloads WHERE fulfillment_id IN \
                         (SELECT id FROM cross_fulfillments WHERE {stale})"
                    ))
                    .bind(&self.tenant_id)
                    .bind(retention_ms)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let removed =
                        sqlx::query(&format!("DELETE FROM cross_fulfillments WHERE {stale}"))
                            .bind(&self.tenant_id)
                            .bind(retention_ms)
                            .execute(&mut *tx)
                            .await
                            .map_err(StoreError::Database)?
                            .rows_affected();
                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(removed)
                }
            }
        })
        .await
    }

    async fn live_fulfillment_ids(&self) -> Result<Vec<String>, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let sql = format!(
                "SELECT id FROM cross_fulfillments WHERE tenant_id = ? AND status IN ({}) \
                 ORDER BY created_at, id LIMIT {SWEEP_BATCH}",
                ACTIVE_STATUSES
                    .iter()
                    .map(|status| format!("'{status}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            macro_rules! ids {
                ($pool:expr, $sql:expr) => {{
                    let rows = sqlx::query($sql)
                        .bind(&self.tenant_id)
                        .fetch_all($pool)
                        .await
                        .map_err(StoreError::Database)?;
                    let mut ids = Vec::with_capacity(rows.len());
                    for row in &rows {
                        ids.push(
                            row.try_get::<String, _>("id")
                                .map_err(StoreError::Database)?,
                        );
                    }
                    Ok(ids)
                }};
            }
            match &self.database {
                Database::Sqlite(pool) => ids!(pool, &sql),
                Database::Postgres(pool) => ids!(pool, &super::pg(&sql)),
            }
        })
        .await
    }

    /// Decide whether one live fulfillment must close now, returning the new
    /// status, an optional failure code and the revocation reason.
    async fn sweep_verdict(
        &self,
        record: &FulfillmentRecord,
        now_ms: i64,
        enabled: bool,
    ) -> Result<Option<(&'static str, Option<&'static str>, &'static str)>, StoreError> {
        if !enabled {
            return Ok(Some(("revoked", None, "feature_disabled")));
        }
        if record.expires_at_ms <= now_ms {
            return Ok(Some(match record.status.as_str() {
                "available" => ("uncertain", Some("no_recipient_result"), "expired"),
                "recipient_consumed" => ("expired", Some("stored_not_consumed"), "expired"),
                "uncertain" => return Ok(None),
                _ => ("expired", None, "expired"),
            }));
        }
        if record.terms_digest.is_none() || record.status == "uncertain" {
            return Ok(None);
        }
        let policy = self.fleet_policy().await?;
        if policy.version != record.policy_version {
            return Ok(Some(("failed", Some("policy_changed"), "policy")));
        }
        for (workload_id, node_id, key_version, registration_version) in [
            (
                &record.issuer_workload_id,
                &record.issuer_node_id,
                record.issuer_key_version,
                record.issuer_registration_version,
            ),
            (
                &record.recipient_workload_id,
                &record.recipient_node_id,
                record.recipient_key_version,
                record.recipient_registration_version,
            ),
        ] {
            let party = self.party_snapshot(workload_id).await?;
            let Some(party) = party else {
                return Ok(Some(("failed", Some("workload_changed"), "failed")));
            };
            if party.node_id != *node_id || party.node_status != "active" {
                return Ok(Some(("failed", Some("node_revoked"), "failed")));
            }
            if Some(party.key_version) != key_version {
                return Ok(Some(("failed", Some("node_key_rotated"), "failed")));
            }
            if party.workload_status != "active"
                || Some(party.registration_version) != registration_version
            {
                return Ok(Some(("failed", Some("workload_changed"), "failed")));
            }
        }
        Ok(None)
    }

    /// Current issuer and recipient as the controller would bind them into
    /// terms: the enrolled node keys and fingerprints an approver verifies.
    /// `None` when either workload or node is gone or unusable.
    pub async fn fulfillment_live_parties(
        &self,
        record: &FulfillmentRecord,
    ) -> Result<Option<(FulfillmentParty, FulfillmentParty)>, StoreError> {
        let issuer = self.party_snapshot(&record.issuer_workload_id).await?;
        let recipient = self.party_snapshot(&record.recipient_workload_id).await?;
        let (Some(issuer), Some(recipient)) = (issuer, recipient) else {
            return Ok(None);
        };
        if !issuer.usable()
            || !recipient.usable()
            || issuer.node_id != record.issuer_node_id
            || recipient.node_id != record.recipient_node_id
        {
            return Ok(None);
        }
        Ok(Some((
            party_terms(
                &issuer,
                &record.issuer_workload_id,
                &record.issuer_credential,
            )?,
            party_terms(
                &recipient,
                &record.recipient_workload_id,
                &record.recipient_credential,
            )?,
        )))
    }

    async fn party_snapshot(&self, workload_id: &str) -> Result<Option<PartyRow>, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            self.party_snapshot_inner(workload_id).await
        })
        .await
    }

    async fn party_snapshot_inner(
        &self,
        workload_id: &str,
    ) -> Result<Option<PartyRow>, StoreError> {
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query(PARTY_SELECT)
                    .bind(workload_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(match row {
                    Some(row) => Some(party_from!(row)),
                    None => None,
                })
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(&super::pg(PARTY_SELECT))
                    .bind(workload_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(match row {
                    Some(row) => Some(party_from!(row)),
                    None => None,
                })
            }
        }
    }
}
