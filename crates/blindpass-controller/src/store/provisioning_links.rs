// SPDX-License-Identifier: AGPL-3.0-only

//! Scoped Source collection. One immutable link belongs to a named operator
//! and the original grant; metadata only reads, and the first valid submit
//! atomically commits a ciphertext receipt, one controller-signed
//! `provisioning_delivery` inbox document and a safe audit event. The
//! controller stores HPKE ciphertext and public metadata only; plaintext and
//! recipient private keys never reach it.
use super::{
    AuditDraft, Database, LocalSession, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    audit::{insert_audit_postgres, insert_audit_sqlite},
    authorization::{enqueue_node_document_postgres, enqueue_node_document_sqlite},
    new_hex_id,
    operators::{SESSION_IDLE_MS, hash_session_token},
};
use blindpass_core::canon::canonicalize_value;
use blindpass_core::custody::sha256;
use blindpass_core::fleet::{DocumentKind, Grant, SignedEnvelope};
use blindpass_core::provisioning::{
    BrowserProvisioningBinding, BrowserProvisioningDelivery, verify_browser_recipient_offer,
};
use blindpass_core::signing::base64_url_decode;
use serde_json::json;
use sqlx::Row;

/// One immutable link: the original grant's named Source owner, the original
/// public offer and its deadline. Capabilities are derived from this row and
/// never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningLinkRecord {
    pub id: String,
    pub node_id: String,
    pub operation_id: String,
    pub grant_id: String,
    pub offer_id: String,
    pub operator_id: String,
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
}

/// The immutable record of the first accepted ciphertext. It holds digests
/// only: the ciphertext itself lives in the signed delivery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningReceipt {
    pub offer_id: String,
    pub ciphertext_digest: String,
    pub delivery_digest: String,
    pub submitted_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningLinkOutcome {
    Created(ProvisioningLinkRecord),
    Existing(ProvisioningLinkRecord),
    NotFound,
    Forbidden,
    SessionEnded,
    /// The original grant is live but the node has not published its offer.
    NotReady,
    Unavailable,
    Conflict,
}

/// Everything the input page needs, derived from independently trusted
/// controller state. `grant_json` is the original controller-signed grant
/// body, `signing_public` the enrolled broker key and `source_unit` /
/// `credential` the administrator-configured destination; none of them is read
/// from the offer being verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningMetadata {
    pub offer_json: String,
    pub grant_json: String,
    pub node_key_version: u64,
    pub signing_public: String,
    pub source_unit: String,
    pub credential: String,
    pub expires_at_ms: i64,
    pub server_time_ms: i64,
    pub purpose: String,
    pub workload_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningMetadataOutcome {
    Ready(Box<ProvisioningMetadata>),
    Submitted(ProvisioningReceipt),
    Forbidden,
    SessionEnded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningSubmitOutcome {
    Created(ProvisioningReceipt),
    Existing(ProvisioningReceipt),
    Conflict,
    Forbidden,
    SessionEnded,
    Unavailable,
}

/// Where Source collection stands for one operation, as the console reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningPhase {
    /// Not a browser operation, or no grant has been issued for it.
    NotApplicable,
    /// A grant is live but the node has not published its recipient offer.
    AwaitingOffer,
    /// The signed offer is live and no link exists yet.
    OfferReady,
    /// The named owner's link exists and the offer is still live.
    LinkIssued,
    /// A ciphertext receipt is committed.
    Submitted,
    /// Authority or the original deadline ended before any receipt.
    Expired,
}

impl ProvisioningPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::AwaitingOffer => "awaiting_offer",
            Self::OfferReady => "offer_ready",
            Self::LinkIssued => "link_issued",
            Self::Submitted => "submitted",
            Self::Expired => "expired",
        }
    }
}

/// Secret-free console state: never a capability, key, offer or ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisioningStatus {
    pub phase: ProvisioningPhase,
    pub offer_expires_at_ms: Option<i64>,
    /// True only for the named Source owner while the original offer is live.
    pub can_provide: bool,
}

impl ProvisioningStatus {
    pub const fn without_offer(phase: ProvisioningPhase) -> Self {
        Self {
            phase,
            offer_expires_at_ms: None,
            can_provide: false,
        }
    }
}

/// Why current authority could not be established. Never carries state that
/// would tell a caller which authority check failed beyond the owner check.
enum Denial {
    Forbidden,
    NotReady,
    Unavailable,
}

struct OfferRow {
    id: String,
    json: String,
    expires_at: i64,
    binding_version: i64,
}

struct Authority {
    binding: BrowserProvisioningBinding,
    grant_json: String,
    signing_public: String,
    key_version: u64,
    unit: String,
    credential: String,
    purpose: String,
    workload_name: String,
    /// Whether the session's operator is the named Source owner. Always true
    /// for the acting routes, which refuse before constructing this.
    owner: bool,
    now: i64,
}

const NODE_SELECT: &str = "SELECT signing_pub,key_version FROM nodes WHERE id=? AND tenant_id=?
    AND status='active' AND NOT EXISTS (SELECT 1 FROM node_key_rotations r WHERE r.node_id=nodes.id)
    AND NOT EXISTS (SELECT 1 FROM node_revocation_queue q WHERE q.node_id=nodes.id)";
const SQLITE_GRANT_EVIDENCE: &str = "SELECT envelope_json FROM node_inbox WHERE node_id=? AND json_extract(envelope_json,'$.kind')='grant' AND json_extract(envelope_json,'$.body.id')=? ORDER BY seq LIMIT 1";
const POSTGRES_GRANT_EVIDENCE: &str = "SELECT envelope_json FROM node_inbox WHERE node_id=? AND envelope_json::jsonb->>'kind'='grant' AND envelope_json::jsonb#>>'{body,id}'=? ORDER BY seq LIMIT 1";
const CONTEXT_SELECT: &str = "SELECT s.source_unit,s.credential,s.version AS binding_version,s.updated_by,
    o.decision,o.purpose,w.name AS workload_name,a.status AS approval_status,a.decided_by
    FROM grants g JOIN operations o ON o.id=g.operation_id AND o.tenant_id=g.tenant_id
    JOIN workloads w ON w.id=g.workload_id AND w.tenant_id=g.tenant_id
    JOIN fleet_policies p ON p.tenant_id=g.tenant_id
    JOIN fleet_source_bindings s ON s.tenant_id=g.tenant_id AND s.node_id=g.node_id AND s.resource_id=o.resource_id
    LEFT JOIN operation_approvals a ON a.id=o.approval_id AND a.tenant_id=o.tenant_id
    WHERE g.id=? AND g.tenant_id=? AND g.node_id=? AND g.operation_id=? AND g.workload_id=?
    AND g.status IN ('issued','delivered') AND g.consumed_at IS NULL AND g.expires_at>?
    AND g.issuer_epoch=? AND g.policy_version=? AND g.issued_at=? AND g.expires_at=?
    AND g.recipient_key_id=? AND g.action='browser.session' AND g.mode='browser_session'
    AND o.status='granted' AND o.grant_id=g.id AND o.expires_at>?
    AND o.invocation_id=? AND o.resource_id=? AND o.broker_event_key=? AND o.policy_version=?
    AND o.action='browser.session' AND o.mode='browser_session'
    AND w.status='active' AND w.node_id=g.node_id AND w.registration_version=?
    AND w.unit=? AND w.account=? AND w.consumption_mode='browser_session' AND p.version=?";
const LINK_COLUMNS: &str =
    "id,node_id,operation_id,grant_id,offer_id,operator_id,expires_at,created_at";
const RECEIPT_COLUMNS: &str = "offer_id,ciphertext_digest,delivery_digest,submitted_at,expires_at";

fn hex_digest(parts: &[&[u8]]) -> Result<String, StoreError> {
    let mut joined = Vec::new();
    for part in parts {
        joined.extend_from_slice(part);
        joined.push(0);
    }
    sha256(&joined)
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
        .map_err(|_| StoreError::InvalidInput("provisioning digest"))
}

fn link_from_row<'r, R: Row>(row: &'r R) -> Result<ProvisioningLinkRecord, StoreError>
where
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(ProvisioningLinkRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        operation_id: row.try_get("operation_id").map_err(StoreError::Database)?,
        grant_id: row.try_get("grant_id").map_err(StoreError::Database)?,
        offer_id: row.try_get("offer_id").map_err(StoreError::Database)?,
        operator_id: row.try_get("operator_id").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
    })
}

fn receipt_from_row<'r, R: Row>(row: &'r R) -> Result<ProvisioningReceipt, StoreError>
where
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(ProvisioningReceipt {
        offer_id: row.try_get("offer_id").map_err(StoreError::Database)?,
        ciphertext_digest: row
            .try_get("ciphertext_digest")
            .map_err(StoreError::Database)?,
        delivery_digest: row
            .try_get("delivery_digest")
            .map_err(StoreError::Database)?,
        submitted_at_ms: row.try_get("submitted_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
    })
}

/// Whether the session's operator still holds the exact credential and role
/// the HTTP layer authenticated. A logout, removal, password change or role
/// change since then ends it.
macro_rules! session_live {
    ($tx:expr, $convert:expr, $now:expr, $session:expr) => {{
        let hashed = hash_session_token(&$session.session_id)?;
        let live: Option<String> = sqlx::query_scalar(&$convert(&format!(
            "SELECT o.id FROM operator_sessions s JOIN operators o ON o.id=s.operator_id
             WHERE s.id=? AND s.operator_id=? AND s.kind='browser' AND s.revoked_at IS NULL
             AND s.expires_at>{now} AND s.last_seen_at+{idle}>{now}
             AND o.disabled_at IS NULL AND o.password_hash=? AND o.role=?",
            now = $now,
            idle = SESSION_IDLE_MS
        )))
        .bind(&hashed)
        .bind(&$session.operator.id)
        .bind(&$session.operator.password_hash)
        .bind(&$session.operator.role)
        .fetch_optional(&mut *$tx)
        .await
        .map_err(StoreError::Database)?;
        live.is_some()
    }};
}

/// Re-establish, inside the caller's transaction and after every lock, that
/// the original grant, enrolled key, configured destination and the original
/// signed offer still agree and that this operator is the named owner. The
/// database clock is sampled again after the locks so a lock wait cannot
/// extend any deadline.
macro_rules! authority_core {
    ($enforce_owner:expr, $self:expr, $tx:expr, $convert:expr, $now:expr, $node_lock:expr,
     $context_lock:expr, $grant_evidence:expr, $session:expr, $node_id:expr, $grant_id:expr,
     $offer:expr) => {
        'authority: {
            let signer = $self
                .fleet_signer
                .as_ref()
                .ok_or(StoreError::MissingState("provisioning issuer"))?;
            let node = sqlx::query(&$convert(&format!("{NODE_SELECT}{}", $node_lock)))
                .bind($node_id)
                .bind(&$self.tenant_id)
                .fetch_optional(&mut *$tx)
                .await
                .map_err(StoreError::Database)?;
            let Some(node) = node else {
                break 'authority Err(Denial::Unavailable);
            };
            let signing_public: String =
                node.try_get("signing_pub").map_err(StoreError::Database)?;
            let key_version: i64 = node.try_get("key_version").map_err(StoreError::Database)?;
            let (Some(signing_bytes), Ok(key_version)) = (
                base64_url_decode(&signing_public, 32),
                u64::try_from(key_version),
            ) else {
                break 'authority Err(Denial::Unavailable);
            };
            let meta = sqlx::query(&format!(
                "SELECT issuer_epoch, {} AS now_ms FROM controller_meta WHERE id=1",
                $now
            ))
            .fetch_one(&mut *$tx)
            .await
            .map_err(StoreError::Database)?;
            let epoch: i64 = meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
            let before: i64 = meta.try_get("now_ms").map_err(StoreError::Database)?;
            let Ok(epoch) = u64::try_from(epoch) else {
                break 'authority Err(Denial::Unavailable);
            };
            let original: Option<String> = sqlx::query_scalar(&$convert($grant_evidence))
                .bind($node_id)
                .bind($grant_id)
                .fetch_optional(&mut *$tx)
                .await
                .map_err(StoreError::Database)?;
            let Some(Ok(original)) = original.as_deref().map(SignedEnvelope::from_json) else {
                break 'authority Err(Denial::Unavailable);
            };
            if original.kind() != DocumentKind::Grant
                || !original
                    .verify(signer.keypair.public_key(), &signer.key_id, epoch)
                    .unwrap_or(false)
            {
                break 'authority Err(Denial::Unavailable);
            }
            let Ok(grant) = Grant::from_value(original.body()) else {
                break 'authority Err(Denial::Unavailable);
            };
            let Ok(grant_json) = canonicalize_value(original.body())
                .map_err(|_| ())
                .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
            else {
                break 'authority Err(Denial::Unavailable);
            };
            let policy_version = i64::try_from(grant.policy_version).ok();
            let registration_version = i64::try_from(grant.registration_version).ok();
            let (Some(policy_version), Some(registration_version)) =
                (policy_version, registration_version)
            else {
                break 'authority Err(Denial::Unavailable);
            };
            let (Ok(issued_at), Ok(expires_at), Ok(epoch_i64)) = (
                i64::try_from(grant.issued_at_ms),
                i64::try_from(grant.expires_at_ms),
                i64::try_from(epoch),
            ) else {
                break 'authority Err(Denial::Unavailable);
            };
            let context = sqlx::query(&$convert(&format!("{CONTEXT_SELECT} {}", $context_lock)))
                .bind(&grant.id)
                .bind(&$self.tenant_id)
                .bind($node_id)
                .bind(&grant.operation_id)
                .bind(&grant.workload_id)
                .bind(before)
                .bind(epoch_i64)
                .bind(policy_version)
                .bind(issued_at)
                .bind(expires_at)
                .bind(&grant.recipient_key_id)
                .bind(before)
                .bind(&grant.invocation_id)
                .bind(&grant.resource_id)
                .bind(grant.request_event_key.as_deref())
                .bind(policy_version)
                .bind(registration_version)
                .bind(&grant.unit)
                .bind(&grant.account)
                .bind(policy_version)
                .fetch_optional(&mut *$tx)
                .await
                .map_err(StoreError::Database)?;
            let Some(context) = context else {
                break 'authority Err(Denial::Unavailable);
            };
            let unit: String = context
                .try_get("source_unit")
                .map_err(StoreError::Database)?;
            let credential: String = context
                .try_get("credential")
                .map_err(StoreError::Database)?;
            let binding_version: i64 = context
                .try_get("binding_version")
                .map_err(StoreError::Database)?;
            let updated_by: String = context
                .try_get("updated_by")
                .map_err(StoreError::Database)?;
            let decision: String = context.try_get("decision").map_err(StoreError::Database)?;
            let purpose: String = context.try_get("purpose").map_err(StoreError::Database)?;
            let workload_name: String = context
                .try_get("workload_name")
                .map_err(StoreError::Database)?;
            let approval_status: Option<String> = context
                .try_get("approval_status")
                .map_err(StoreError::Database)?;
            let decided_by: Option<String> = context
                .try_get("decided_by")
                .map_err(StoreError::Database)?;
            let operator = &$session.operator;
            let owner = match decision.as_str() {
                "pending_approval" => {
                    approval_status.as_deref() == Some("approved")
                        && decided_by.as_deref() == Some(operator.id.as_str())
                        && matches!(operator.role.as_str(), "admin" | "operator")
                }
                "allow" => updated_by == operator.id && operator.role == "admin",
                _ => false,
            };
            // The routes that act for the operator always enforce ownership. Only
            // the read-only console state reports it instead, so a non-owner can
            // still see where Source collection stands without being able to act.
            if $enforce_owner && !owner {
                break 'authority Err(Denial::Forbidden);
            }
            let Some(offer) = $offer.as_ref() else {
                break 'authority Err(Denial::NotReady);
            };
            // A PostgreSQL authority-row lock may wait beyond every deadline.
            let now: i64 = sqlx::query_scalar(&format!("SELECT {}", $now))
                .fetch_one(&mut *$tx)
                .await
                .map_err(StoreError::Database)?;
            let Ok(now_ms) = u64::try_from(now) else {
                break 'authority Err(Denial::Unavailable);
            };
            let Ok(envelope) = SignedEnvelope::from_json(&offer.json) else {
                break 'authority Err(Denial::Unavailable);
            };
            let Ok(binding) = verify_browser_recipient_offer(
                &envelope,
                &signing_bytes,
                &grant,
                key_version,
                now_ms,
                &unit,
                &credential,
            ) else {
                break 'authority Err(Denial::Unavailable);
            };
            if binding.offer_id != offer.id
                || offer.binding_version != binding_version
                || offer.expires_at <= now
                || i64::try_from(binding.expires_at_ms).ok() != Some(offer.expires_at)
            {
                break 'authority Err(Denial::Unavailable);
            }
            Ok(Authority {
                binding,
                grant_json,
                signing_public,
                key_version,
                unit,
                credential,
                purpose,
                workload_name,
                owner,
                now,
            })
        }
    };
}

/// Every acting route: the operator must be the named Source owner.
macro_rules! authority {
    ($($arguments:tt)*) => {
        authority_core!(true, $($arguments)*)
    };
}

macro_rules! offer_for {
    ($self:expr, $tx:expr, $convert:expr, $where_sql:expr, $first:expr) => {{
        let row = sqlx::query(&$convert(&format!(
            "SELECT id,offer_json,expires_at,source_binding_version FROM fleet_provisioning_offers
             WHERE tenant_id=? AND {}",
            $where_sql
        )))
        .bind(&$self.tenant_id)
        .bind($first)
        .fetch_optional(&mut *$tx)
        .await
        .map_err(StoreError::Database)?;
        match row {
            Some(row) => Some(OfferRow {
                id: row.try_get("id").map_err(StoreError::Database)?,
                json: row.try_get("offer_json").map_err(StoreError::Database)?,
                expires_at: row.try_get("expires_at").map_err(StoreError::Database)?,
                binding_version: row
                    .try_get("source_binding_version")
                    .map_err(StoreError::Database)?,
            }),
            None => None,
        }
    }};
}

impl Store {
    /// Create the one immutable link for an original browser grant. The caller
    /// has authenticated the browser session, role, Origin and CSRF; this
    /// transaction independently re-checks the session, current authority and
    /// that the operator is the named Source owner. An exact retry returns the
    /// original link; any other key or operator cannot replace it.
    pub async fn create_provisioning_link(
        &self,
        operation_id: &str,
        session: &LocalSession,
        idempotency_hash: &str,
    ) -> Result<ProvisioningLinkOutcome, StoreError> {
        self.checkpoint_clock().await?;
        if !blindpass_core::fleet::is_valid_opaque_id(operation_id) || idempotency_hash.len() != 64
        {
            return Err(StoreError::InvalidInput("provisioning link request"));
        }
        macro_rules! create {
            ($pool:expr,$convert:expr,$now:expr,$meta_lock:expr,$node_lock:expr,$context_lock:expr,$evidence:expr,$audit:path) => {{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query($meta_lock)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if !session_live!(tx, $convert, $now, session) {
                    return Ok(ProvisioningLinkOutcome::SessionEnded);
                }
                let grant = sqlx::query(&$convert(
                    "SELECT g.id,g.node_id FROM grants g JOIN operations o ON o.id=g.operation_id AND o.tenant_id=g.tenant_id
                     WHERE g.operation_id=? AND g.tenant_id=? AND o.action='browser.session' AND o.mode='browser_session'",
                ))
                .bind(operation_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(grant) = grant else {
                    return Ok(ProvisioningLinkOutcome::NotFound);
                };
                let grant_id: String = grant.try_get("id").map_err(StoreError::Database)?;
                let node_id: String = grant.try_get("node_id").map_err(StoreError::Database)?;
                let offer = offer_for!(self, tx, $convert, "grant_id=?", &grant_id);
                let verdict = authority!(
                    self, tx, $convert, $now, $node_lock, $context_lock, $evidence, session,
                    &node_id, &grant_id, offer
                );
                let authority = match verdict {
                    Ok(authority) => authority,
                    Err(Denial::Forbidden) => return Ok(ProvisioningLinkOutcome::Forbidden),
                    Err(Denial::NotReady) => return Ok(ProvisioningLinkOutcome::NotReady),
                    Err(Denial::Unavailable) => return Ok(ProvisioningLinkOutcome::Unavailable),
                };
                let existing = sqlx::query(&$convert(&format!(
                    "SELECT {LINK_COLUMNS},idempotency_hash FROM fleet_provisioning_links WHERE tenant_id=? AND grant_id=?"
                )))
                .bind(&self.tenant_id)
                .bind(&grant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if let Some(existing) = existing {
                    let hash: String = existing
                        .try_get("idempotency_hash")
                        .map_err(StoreError::Database)?;
                    let record = link_from_row(&existing)?;
                    return Ok(if hash == idempotency_hash && record.operator_id == session.operator.id {
                        ProvisioningLinkOutcome::Existing(record)
                    } else {
                        ProvisioningLinkOutcome::Conflict
                    });
                }
                let reused: Option<String> = sqlx::query_scalar(&$convert(
                    "SELECT id FROM fleet_provisioning_links WHERE tenant_id=? AND operator_id=? AND idempotency_hash=?",
                ))
                .bind(&self.tenant_id)
                .bind(&session.operator.id)
                .bind(idempotency_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if reused.is_some() {
                    return Ok(ProvisioningLinkOutcome::Conflict);
                }
                let record = ProvisioningLinkRecord {
                    id: new_hex_id(),
                    node_id: node_id.clone(),
                    operation_id: operation_id.to_owned(),
                    grant_id: grant_id.clone(),
                    offer_id: authority.binding.offer_id.clone(),
                    operator_id: session.operator.id.clone(),
                    expires_at_ms: i64::try_from(authority.binding.expires_at_ms)
                        .map_err(|_| StoreError::InvalidInput("provisioning link expiry"))?,
                    created_at_ms: authority.now,
                };
                sqlx::query(&$convert(
                    "INSERT INTO fleet_provisioning_links
                     (id,tenant_id,node_id,operation_id,grant_id,offer_id,operator_id,idempotency_hash,expires_at,created_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?)",
                ))
                .bind(&record.id)
                .bind(&self.tenant_id)
                .bind(&record.node_id)
                .bind(&record.operation_id)
                .bind(&record.grant_id)
                .bind(&record.offer_id)
                .bind(&record.operator_id)
                .bind(idempotency_hash)
                .bind(record.expires_at_ms)
                .bind(record.created_at_ms)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let audit = AuditDraft::operator(
                    &session.operator.id,
                    "fleet.provisioning_link_created",
                    "operation",
                    operation_id,
                    "created",
                    json!({"node_id":record.node_id,"grant_id":record.grant_id,"offer_id":record.offer_id,
                        "expires_at_ms":record.expires_at_ms}),
                );
                $audit(&mut tx, &self.tenant_id, &audit).await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(ProvisioningLinkOutcome::Created(record))
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => create!(
                pool,
                |s: &str| s.to_owned(),
                SQLITE_NOW_MS,
                "UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1",
                "",
                "",
                SQLITE_GRANT_EVIDENCE,
                insert_audit_sqlite
            ),
            Database::Postgres(pool) => create!(
                pool,
                super::pg,
                POSTGRES_NOW_MS,
                "SELECT issuer_epoch FROM controller_meta WHERE id=1 FOR UPDATE",
                " FOR UPDATE",
                "FOR UPDATE OF g,o,w,p,s",
                POSTGRES_GRANT_EVIDENCE,
                insert_audit_postgres
            ),
        }
    }

    /// Read-only link status. Repeated reads and browser prefetch never
    /// consume the offer key, create a delivery or take an authority lock.
    pub async fn provisioning_metadata(
        &self,
        link_id: &str,
        session: &LocalSession,
    ) -> Result<ProvisioningMetadataOutcome, StoreError> {
        self.checkpoint_clock().await?;
        macro_rules! read {
            ($pool:expr,$convert:expr,$now:expr,$evidence:expr) => {{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                let link = sqlx::query(&$convert(&format!(
                    "SELECT {LINK_COLUMNS} FROM fleet_provisioning_links WHERE id=? AND tenant_id=?"
                )))
                .bind(link_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(link) = link else {
                    return Ok(ProvisioningMetadataOutcome::Unavailable);
                };
                let link = link_from_row(&link)?;
                if link.operator_id != session.operator.id {
                    return Ok(ProvisioningMetadataOutcome::Forbidden);
                }
                if !session_live!(tx, $convert, $now, session) {
                    return Ok(ProvisioningMetadataOutcome::SessionEnded);
                }
                let receipt = sqlx::query(&$convert(&format!(
                    "SELECT {RECEIPT_COLUMNS} FROM fleet_provisioning_receipts WHERE link_id=? AND tenant_id=?"
                )))
                .bind(link_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if let Some(receipt) = receipt {
                    return Ok(ProvisioningMetadataOutcome::Submitted(receipt_from_row(&receipt)?));
                }
                let offer = offer_for!(self, tx, $convert, "id=?", &link.offer_id);
                let verdict = authority!(
                    self, tx, $convert, $now, "", "", $evidence, session,
                    &link.node_id, &link.grant_id, offer
                );
                let authority = match verdict {
                    Ok(authority) => authority,
                    Err(Denial::Forbidden) => return Ok(ProvisioningMetadataOutcome::Forbidden),
                    Err(_) => return Ok(ProvisioningMetadataOutcome::Unavailable),
                };
                if link.expires_at_ms <= authority.now {
                    return Ok(ProvisioningMetadataOutcome::Unavailable);
                }
                let offer_json = offer
                    .as_ref()
                    .map(|offer| offer.json.clone())
                    .ok_or(StoreError::MissingState("provisioning offer"))?;
                Ok(ProvisioningMetadataOutcome::Ready(Box::new(ProvisioningMetadata {
                    offer_json,
                    grant_json: authority.grant_json,
                    node_key_version: authority.key_version,
                    signing_public: authority.signing_public,
                    source_unit: authority.unit,
                    credential: authority.credential,
                    expires_at_ms: link.expires_at_ms,
                    server_time_ms: authority.now,
                    purpose: authority.purpose,
                    workload_name: authority.workload_name,
                })))
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => read!(
                pool,
                |s: &str| s.to_owned(),
                SQLITE_NOW_MS,
                SQLITE_GRANT_EVIDENCE
            ),
            Database::Postgres(pool) => {
                read!(pool, super::pg, POSTGRES_NOW_MS, POSTGRES_GRANT_EVIDENCE)
            }
        }
    }

    /// Commit the first valid ciphertext for a link. The receipt, the signed
    /// `provisioning_delivery` inbox document and the audit event commit
    /// together or not at all. Exact retries return the original receipt; a
    /// different ciphertext conflicts; neither re-enqueues a delivery.
    pub async fn submit_provisioning(
        &self,
        link_id: &str,
        session: &LocalSession,
        enc: &str,
        ciphertext: &str,
    ) -> Result<ProvisioningSubmitOutcome, StoreError> {
        self.checkpoint_clock().await?;
        BrowserProvisioningDelivery::decode_sealed(enc, ciphertext)
            .map_err(|_| StoreError::InvalidInput("provisioning ciphertext"))?;
        let ciphertext_digest = hex_digest(&[enc.as_bytes(), ciphertext.as_bytes()])?;
        macro_rules! submit {
            ($pool:expr,$convert:expr,$now:expr,$meta_lock:expr,$node_lock:expr,$context_lock:expr,$evidence:expr,$audit:path,$enqueue:path) => {{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query($meta_lock)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let link = sqlx::query(&$convert(&format!(
                    "SELECT {LINK_COLUMNS} FROM fleet_provisioning_links WHERE id=? AND tenant_id=?"
                )))
                .bind(link_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(link) = link else {
                    return Ok(ProvisioningSubmitOutcome::Unavailable);
                };
                let link = link_from_row(&link)?;
                if link.operator_id != session.operator.id {
                    return Ok(ProvisioningSubmitOutcome::Forbidden);
                }
                if !session_live!(tx, $convert, $now, session) {
                    return Ok(ProvisioningSubmitOutcome::SessionEnded);
                }
                let receipt = sqlx::query(&$convert(&format!(
                    "SELECT {RECEIPT_COLUMNS} FROM fleet_provisioning_receipts WHERE link_id=? AND tenant_id=?"
                )))
                .bind(link_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if let Some(receipt) = receipt {
                    // Reconciliation of an already committed receipt grants no
                    // new authority and never reopens, requeues or renews it.
                    let receipt = receipt_from_row(&receipt)?;
                    return Ok(if receipt.ciphertext_digest == ciphertext_digest {
                        ProvisioningSubmitOutcome::Existing(receipt)
                    } else {
                        ProvisioningSubmitOutcome::Conflict
                    });
                }
                let offer = offer_for!(self, tx, $convert, "id=?", &link.offer_id);
                let verdict = authority!(
                    self, tx, $convert, $now, $node_lock, $context_lock, $evidence, session,
                    &link.node_id, &link.grant_id, offer
                );
                let authority = match verdict {
                    Ok(authority) => authority,
                    Err(Denial::Forbidden) => return Ok(ProvisioningSubmitOutcome::Forbidden),
                    Err(_) => return Ok(ProvisioningSubmitOutcome::Unavailable),
                };
                if link.expires_at_ms <= authority.now {
                    return Ok(ProvisioningSubmitOutcome::Unavailable);
                }
                let delivery = BrowserProvisioningDelivery {
                    binding: authority.binding.clone(),
                    enc: enc.to_owned(),
                    ciphertext: ciphertext.to_owned(),
                };
                let signer = self
                    .fleet_signer
                    .as_ref()
                    .ok_or(StoreError::MissingState("provisioning issuer"))?;
                let body = delivery
                    .to_value()
                    .map_err(|_| StoreError::InvalidInput("provisioning delivery"))?;
                // The envelope epoch is the original grant's issuer epoch, which
                // the authority check proved is still the controller's current one.
                let envelope = signer.sign(
                    DocumentKind::ProvisioningDelivery,
                    body,
                    authority.binding.grant.issuer_epoch,
                )?;
                let delivery_digest = hex_digest(&[envelope.as_bytes()])?;
                let receipt = ProvisioningReceipt {
                    offer_id: authority.binding.offer_id.clone(),
                    ciphertext_digest: ciphertext_digest.clone(),
                    delivery_digest,
                    submitted_at_ms: authority.now,
                    expires_at_ms: link.expires_at_ms,
                };
                sqlx::query(&$convert(
                    "INSERT INTO fleet_provisioning_receipts
                     (link_id,tenant_id,node_id,grant_id,offer_id,operator_id,ciphertext_digest,delivery_digest,submitted_at,expires_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?)",
                ))
                .bind(link_id)
                .bind(&self.tenant_id)
                .bind(&link.node_id)
                .bind(&link.grant_id)
                .bind(&receipt.offer_id)
                .bind(&session.operator.id)
                .bind(&receipt.ciphertext_digest)
                .bind(&receipt.delivery_digest)
                .bind(receipt.submitted_at_ms)
                .bind(receipt.expires_at_ms)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                $enqueue(&mut tx, &link.node_id, &envelope).await?;
                let audit = AuditDraft::operator(
                    &session.operator.id,
                    "fleet.source_submitted",
                    "operation",
                    &link.operation_id,
                    "submitted",
                    json!({"node_id":link.node_id,"grant_id":link.grant_id,"offer_id":receipt.offer_id,
                        "ciphertext_digest":receipt.ciphertext_digest,"delivery_digest":receipt.delivery_digest}),
                );
                $audit(&mut tx, &self.tenant_id, &audit).await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(ProvisioningSubmitOutcome::Created(receipt))
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => submit!(
                pool,
                |s: &str| s.to_owned(),
                SQLITE_NOW_MS,
                "UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1",
                "",
                "",
                SQLITE_GRANT_EVIDENCE,
                insert_audit_sqlite,
                enqueue_node_document_sqlite
            ),
            Database::Postgres(pool) => submit!(
                pool,
                super::pg,
                POSTGRES_NOW_MS,
                "SELECT issuer_epoch FROM controller_meta WHERE id=1 FOR UPDATE",
                " FOR UPDATE",
                "FOR UPDATE OF g,o,w,p,s",
                POSTGRES_GRANT_EVIDENCE,
                insert_audit_postgres,
                enqueue_node_document_postgres
            ),
        }
    }

    /// The secret-free state of Source collection for one operation, for the
    /// operator console. It runs the same current-authority check as the link,
    /// metadata and submit routes (grant, operation, workload registration,
    /// policy, issuer epoch, enrolled key, destination version and the original
    /// signed offer), so `can_provide` is never a weaker rule than the link
    /// route. It only reads: it takes no authority lock and never consumes,
    /// creates or renews anything.
    pub async fn provisioning_status(
        &self,
        operation_id: &str,
        session: &LocalSession,
    ) -> Result<ProvisioningStatus, StoreError> {
        if !blindpass_core::fleet::is_valid_opaque_id(operation_id) {
            return Ok(ProvisioningStatus::without_offer(
                ProvisioningPhase::NotApplicable,
            ));
        }
        self.checkpoint_clock().await?;
        macro_rules! read {
            ($pool:expr,$convert:expr,$now:expr,$evidence:expr) => {{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                let grant = sqlx::query(&$convert(
                    "SELECT g.id,g.node_id FROM grants g JOIN operations o ON o.id=g.operation_id AND o.tenant_id=g.tenant_id
                     WHERE g.operation_id=? AND g.tenant_id=? AND o.action='browser.session' AND o.mode='browser_session'",
                ))
                .bind(operation_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(grant) = grant else {
                    return Ok(ProvisioningStatus::without_offer(ProvisioningPhase::NotApplicable));
                };
                let grant_id: String = grant.try_get("id").map_err(StoreError::Database)?;
                let node_id: String = grant.try_get("node_id").map_err(StoreError::Database)?;
                let receipt: Option<i64> = sqlx::query_scalar(&$convert(
                    "SELECT submitted_at FROM fleet_provisioning_receipts WHERE grant_id=? AND tenant_id=?",
                ))
                .bind(&grant_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if receipt.is_some() {
                    return Ok(ProvisioningStatus::without_offer(ProvisioningPhase::Submitted));
                }
                let link_row = sqlx::query(&$convert(&format!(
                    "SELECT {LINK_COLUMNS} FROM fleet_provisioning_links WHERE tenant_id=? AND grant_id=?"
                )))
                .bind(&self.tenant_id)
                .bind(&grant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let link = match link_row.as_ref() {
                    Some(row) => Some(link_from_row(row)?),
                    None => None,
                };
                let offer = match &link {
                    Some(link) => offer_for!(self, tx, $convert, "id=?", &link.offer_id),
                    None => offer_for!(self, tx, $convert, "grant_id=?", &grant_id),
                };
                let live = session_live!(tx, $convert, $now, session);
                let verdict = authority_core!(
                    false, self, tx, $convert, $now, "", "", $evidence, session,
                    &node_id, &grant_id, offer
                );
                Ok(match verdict {
                    Ok(authority) => match &link {
                        Some(link) if link.expires_at_ms <= authority.now => {
                            ProvisioningStatus::without_offer(ProvisioningPhase::Expired)
                        }
                        Some(link) => ProvisioningStatus {
                            phase: ProvisioningPhase::LinkIssued,
                            offer_expires_at_ms: Some(link.expires_at_ms),
                            can_provide: authority.owner
                                && live
                                && link.operator_id == session.operator.id,
                        },
                        None => ProvisioningStatus {
                            phase: ProvisioningPhase::OfferReady,
                            offer_expires_at_ms: i64::try_from(authority.binding.expires_at_ms).ok(),
                            can_provide: authority.owner && live,
                        },
                    },
                    Err(Denial::NotReady) => {
                        ProvisioningStatus::without_offer(ProvisioningPhase::AwaitingOffer)
                    }
                    // Not enforced here, so a refusal for ownership cannot occur;
                    // fail closed if it ever did.
                    Err(Denial::Forbidden | Denial::Unavailable) => {
                        ProvisioningStatus::without_offer(ProvisioningPhase::Expired)
                    }
                })
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => read!(
                pool,
                |s: &str| s.to_owned(),
                SQLITE_NOW_MS,
                SQLITE_GRANT_EVIDENCE
            ),
            Database::Postgres(pool) => {
                read!(pool, super::pg, POSTGRES_NOW_MS, POSTGRES_GRANT_EVIDENCE)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::hex_digest;

    #[test]
    fn digests_separate_their_parts() {
        let joined = hex_digest(&[b"ab", b"c"]).unwrap();
        assert_ne!(joined, hex_digest(&[b"a", b"bc"]).unwrap());
        assert_eq!(joined.len(), 64);
        assert!(
            joined
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
