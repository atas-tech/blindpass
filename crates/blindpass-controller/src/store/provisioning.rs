// SPDX-License-Identifier: AGPL-3.0-only

//! Independent destination configuration and atomic ingestion of public offers.
//! This module never accepts Source or an operator ciphertext submission.
use super::{
    AuditDraft, Database, NodeEventInsert, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    audit::{insert_audit_postgres, insert_audit_sqlite},
};
use blindpass_core::canon::canonicalize_json;
use blindpass_core::fleet::{DocumentKind, Grant, SignedEnvelope, is_valid_opaque_id};
use blindpass_core::provisioning::{BrowserProvisioningBinding, verify_browser_recipient_offer};
use blindpass_core::signing::base64_url_decode;
use serde_json::json;
use sqlx::Row;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBindingRecord {
    pub node_id: String,
    pub resource_id: String,
    pub source_unit: String,
    pub credential: String,
    pub version: i64,
    pub updated_at_ms: i64,
    pub updated_by: String,
}

fn valid_destination(unit: &str, credential: &str) -> bool {
    fn identifier(value: &str, maximum: usize, unit: bool) -> bool {
        !value.is_empty()
            && value.len() <= maximum
            && !value.starts_with('.')
            && value.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'_' | b'-' | b'.')
                    || unit && matches!(b, b'@' | b':')
            })
    }
    unit.ends_with(".service") && identifier(unit, 255, true) && identifier(credential, 128, false)
}

impl Store {
    pub async fn source_binding(
        &self,
        node_id: &str,
        resource_id: &str,
    ) -> Result<Option<SourceBindingRecord>, StoreError> {
        self.checkpoint_clock().await?;
        macro_rules! read {
            ($pool:expr, $convert:expr) => {{
                let row = sqlx::query(&$convert("SELECT source_unit, credential, version, updated_at, updated_by
                    FROM fleet_source_bindings WHERE tenant_id=? AND node_id=? AND resource_id=?"))
                    .bind(&self.tenant_id).bind(node_id).bind(resource_id).fetch_optional($pool).await.map_err(StoreError::Database)?;
                row.map(|row| Ok(SourceBindingRecord { node_id:node_id.into(), resource_id:resource_id.into(),
                    source_unit:row.try_get("source_unit").map_err(StoreError::Database)?,
                    credential:row.try_get("credential").map_err(StoreError::Database)?,
                    version:row.try_get("version").map_err(StoreError::Database)?,
                    updated_at_ms:row.try_get("updated_at").map_err(StoreError::Database)?,
                    updated_by:row.try_get("updated_by").map_err(StoreError::Database)? })).transpose()
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => read!(pool, |s: &str| s.to_owned()),
            Database::Postgres(pool) => read!(pool, super::pg),
        }
    }

    /// Origin, CSRF and administrator role are enforced by the HTTP caller.
    #[allow(clippy::too_many_arguments)] // Optimistic destination update and actor audit are one transaction.
    pub async fn set_source_binding(
        &self,
        node_id: &str,
        resource_id: &str,
        unit: &str,
        credential: &str,
        expected_version: i64,
        actor_id: &str,
        audit: &AuditDraft,
    ) -> Result<Option<SourceBindingRecord>, StoreError> {
        self.checkpoint_clock().await?;
        if !is_valid_opaque_id(node_id)
            || !is_valid_opaque_id(resource_id)
            || !valid_destination(unit, credential)
            || expected_version < 0
            || expected_version == i64::MAX
        {
            return Err(StoreError::InvalidInput("source binding"));
        }
        macro_rules! update {
            ($pool:expr,$convert:expr,$now:expr,$lock:expr,$node_lock:expr,$audit:path) => {{
                let mut tx=$pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query($lock).execute(&mut *tx).await.map_err(StoreError::Database)?;
                let active:Option<String>=sqlx::query_scalar(&$convert(&format!("SELECT id FROM nodes WHERE id=? AND tenant_id=?
                    AND status='active' AND NOT EXISTS (SELECT 1 FROM node_key_rotations r WHERE r.node_id=nodes.id) AND NOT EXISTS (SELECT 1 FROM node_revocation_queue q WHERE q.node_id=nodes.id) {}", $node_lock)))
                    .bind(node_id).bind(&self.tenant_id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
                if active.is_none() { return Ok(None); }
                let now:i64=sqlx::query_scalar(&format!("SELECT {}",$now)).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                let version=expected_version+1;
                let changed=sqlx::query(&$convert("INSERT INTO fleet_source_bindings
                    (tenant_id,node_id,resource_id,source_unit,credential,version,updated_at,updated_by)
                    SELECT ?,?,?,?,?,?,?,? WHERE ?=0
                    ON CONFLICT (tenant_id,node_id,resource_id) DO NOTHING"))
                    .bind(&self.tenant_id).bind(node_id).bind(resource_id).bind(unit).bind(credential)
                    .bind(version).bind(now).bind(actor_id).bind(expected_version)
                    .execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                let changed=if expected_version>0 {
                    sqlx::query(&$convert("UPDATE fleet_source_bindings SET source_unit=?,credential=?,version=?,updated_at=?,updated_by=?
                        WHERE tenant_id=? AND node_id=? AND resource_id=? AND version=?"))
                        .bind(unit).bind(credential).bind(version).bind(now).bind(actor_id).bind(&self.tenant_id)
                        .bind(node_id).bind(resource_id).bind(expected_version).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected()
                } else {changed};
                if changed!=1 {return Ok(None);}
                $audit(&mut tx,&self.tenant_id,audit).await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(Some(SourceBindingRecord {node_id:node_id.into(),resource_id:resource_id.into(),source_unit:unit.into(),
                    credential:credential.into(),version,updated_at_ms:now,updated_by:actor_id.into()}))
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => update!(
                pool,
                |s: &str| s.to_owned(),
                SQLITE_NOW_MS,
                "UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1",
                "",
                insert_audit_sqlite
            ),
            Database::Postgres(pool) => update!(
                pool,
                super::pg,
                POSTGRES_NOW_MS,
                "SELECT issuer_epoch FROM controller_meta WHERE id=1 FOR UPDATE",
                "FOR UPDATE",
                insert_audit_postgres
            ),
        }
    }

    /// The outer broker event signature was verified by the node transport.
    /// The inner offer is independently verified here under current enrollment,
    /// destination and original signed grant authority, inside the transaction.
    pub(crate) async fn record_browser_recipient_offer(
        &self,
        node_id: &str,
        key: &str,
        body_json: &str,
        body_hash: &str,
    ) -> Result<NodeEventInsert, StoreError> {
        self.checkpoint_clock().await?;
        let offer = SignedEnvelope::from_json(body_json)
            .map_err(|_| StoreError::InvalidInput("recipient offer"))?;
        if offer.kind() != DocumentKind::RecipientOffer {
            return Err(StoreError::InvalidInput("recipient offer kind"));
        }
        let untrusted = BrowserProvisioningBinding::from_value(offer.body())
            .map_err(|_| StoreError::InvalidInput("recipient offer binding"))?;
        if untrusted.grant.node_id != node_id {
            return Err(StoreError::InvalidInput("recipient offer node"));
        }
        let offer_json = String::from_utf8(
            canonicalize_json(body_json)
                .map_err(|_| StoreError::InvalidInput("recipient offer"))?,
        )
        .map_err(|_| StoreError::InvalidInput("recipient offer"))?;
        let signer = self
            .fleet_signer
            .as_ref()
            .ok_or(StoreError::MissingState("provisioning issuer"))?;
        macro_rules! ingest {
            ($pool:expr,$convert:expr,$now:expr,$meta_lock:expr,$node_lock:expr,$context_lock:expr,$grant_select:expr,$receipt_select:expr,$audit:path) => {{
                let mut tx=$pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query($meta_lock).execute(&mut *tx).await.map_err(StoreError::Database)?;
                let prior:Option<String>=sqlx::query_scalar(&$convert("SELECT body_hash FROM node_events WHERE node_id=? AND idempotency_key=?"))
                    .bind(node_id).bind(key).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
                if let Some(prior)=prior {return Ok(if prior==body_hash {NodeEventInsert::Duplicate}else{NodeEventInsert::Conflict});}
                // A retained event receipt prevents resurrection after offer rows
                // are removed; neither a new event key nor a successor key renews it.
                let seen:Option<String>=sqlx::query_scalar(&$convert($receipt_select))
                    .bind(node_id).bind(&untrusted.grant.id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
                if seen.is_some() {return Ok(NodeEventInsert::Conflict);}
                let node=sqlx::query(&$convert($node_lock)).bind(node_id).bind(&self.tenant_id)
                    .fetch_optional(&mut *tx).await.map_err(StoreError::Database)?
                    .ok_or(StoreError::InvalidInput("recipient offer enrollment"))?;
                let signing_pub:String=node.try_get("signing_pub").map_err(StoreError::Database)?;
                let key_version:i64=node.try_get("key_version").map_err(StoreError::Database)?;
                let signing_pub=base64_url_decode(&signing_pub,32).ok_or(StoreError::InvalidInput("recipient offer enrollment key"))?;
                let meta=sqlx::query(&format!("SELECT issuer_epoch, {} AS now_ms FROM controller_meta WHERE id=1",$now))
                    .fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                let epoch:i64=meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
                let now:i64=meta.try_get("now_ms").map_err(StoreError::Database)?;
                let epoch=u64::try_from(epoch).map_err(|_|StoreError::InvalidInput("recipient offer epoch"))?;
                let original:Option<String>=sqlx::query_scalar(&$convert($grant_select))
                    .bind(node_id).bind(&untrusted.grant.id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
                let original=SignedEnvelope::from_json(&original.ok_or(StoreError::InvalidInput("original signed grant evidence"))?)
                    .map_err(|_|StoreError::InvalidInput("original signed grant evidence"))?;
                if original.kind()!=DocumentKind::Grant || !original.verify(signer.keypair.public_key(),&signer.key_id,epoch)
                    .map_err(|_|StoreError::InvalidInput("original signed grant evidence"))? {
                    return Err(StoreError::InvalidInput("original signed grant evidence"));
                }
                let grant=Grant::from_value(original.body()).map_err(|_|StoreError::InvalidInput("original signed grant"))?;
                let context=sqlx::query(&$convert(&format!("SELECT s.source_unit,s.credential,s.version AS binding_version
                    FROM grants g JOIN operations o ON o.id=g.operation_id AND o.tenant_id=g.tenant_id
                    JOIN workloads w ON w.id=g.workload_id AND w.tenant_id=g.tenant_id
                    JOIN fleet_policies p ON p.tenant_id=g.tenant_id
                    JOIN fleet_source_bindings s ON s.tenant_id=g.tenant_id AND s.node_id=g.node_id AND s.resource_id=o.resource_id
                    WHERE g.id=? AND g.tenant_id=? AND g.node_id=? AND g.operation_id=? AND g.workload_id=?
                    AND g.status IN ('issued','delivered') AND g.consumed_at IS NULL AND g.expires_at>?
                    AND g.issuer_epoch=? AND g.policy_version=? AND g.issued_at=? AND g.expires_at=?
                    AND g.recipient_key_id=? AND g.action='browser.session' AND g.mode='browser_session'
                    AND o.status='granted' AND o.grant_id=g.id AND o.expires_at>?
                    AND o.invocation_id=? AND o.resource_id=? AND o.broker_event_key=? AND o.policy_version=?
                    AND o.action='browser.session' AND o.mode='browser_session'
                    AND w.status='active' AND w.node_id=g.node_id AND w.registration_version=?
                    AND w.unit=? AND w.account=? AND w.consumption_mode='browser_session' AND p.version=? {}",$context_lock)))
                    .bind(&grant.id).bind(&self.tenant_id).bind(node_id).bind(&grant.operation_id).bind(&grant.workload_id)
                    .bind(now).bind(i64::try_from(epoch).map_err(|_|StoreError::InvalidInput("recipient offer epoch"))?)
                    .bind(i64::try_from(grant.policy_version).map_err(|_|StoreError::InvalidInput("recipient offer policy"))?)
                    .bind(i64::try_from(grant.issued_at_ms).map_err(|_|StoreError::InvalidInput("recipient offer issue time"))?)
                    .bind(i64::try_from(grant.expires_at_ms).map_err(|_|StoreError::InvalidInput("recipient offer expiry"))?)
                    .bind(&grant.recipient_key_id).bind(now).bind(&grant.invocation_id).bind(&grant.resource_id)
                    .bind(grant.request_event_key.as_deref()).bind(i64::try_from(grant.policy_version).map_err(|_|StoreError::InvalidInput("recipient offer policy"))?)
                    .bind(i64::try_from(grant.registration_version).map_err(|_|StoreError::InvalidInput("recipient offer registration"))?)
                    .bind(&grant.unit).bind(&grant.account).bind(i64::try_from(grant.policy_version).map_err(|_|StoreError::InvalidInput("recipient offer policy"))?)
                    .fetch_optional(&mut *tx).await.map_err(StoreError::Database)?
                    .ok_or(StoreError::InvalidInput("recipient offer authority"))?;
                let unit:String=context.try_get("source_unit").map_err(StoreError::Database)?;
                let credential:String=context.try_get("credential").map_err(StoreError::Database)?;
                let version:i64=context.try_get("binding_version").map_err(StoreError::Database)?;
                // A PostgreSQL authority-row lock may wait beyond the original
                // deadline. Sample the checked database clock after every lock.
                let now:i64=sqlx::query_scalar(&format!("SELECT {}",$now)).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                let now_u64=u64::try_from(now).map_err(|_|StoreError::InvalidInput("recipient offer time"))?;
                let binding=verify_browser_recipient_offer(&offer,&signing_pub,&grant,
                    u64::try_from(key_version).map_err(|_|StoreError::InvalidInput("recipient offer key version"))?,now_u64,&unit,&credential)
                    .map_err(|_|StoreError::InvalidInput("recipient offer authority"))?;
                let inserted=sqlx::query(&$convert("INSERT INTO fleet_provisioning_offers
                    (id,tenant_id,node_id,operation_id,grant_id,source_binding_version,offer_json,issued_at,expires_at,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING"))
                    .bind(&binding.offer_id).bind(&self.tenant_id).bind(node_id).bind(&grant.operation_id).bind(&grant.id)
                    .bind(version).bind(&offer_json).bind(i64::try_from(binding.issued_at_ms).map_err(|_|StoreError::InvalidInput("offer time"))?)
                    .bind(i64::try_from(binding.expires_at_ms).map_err(|_|StoreError::InvalidInput("offer expiry"))?).bind(now)
                    .execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                if inserted!=1 {return Ok(NodeEventInsert::Conflict);}
                sqlx::query(&$convert("INSERT INTO node_events (id,node_id,idempotency_key,kind,body_json,body_hash,received_at)
                    VALUES (?, ?, ?, 'recipient_offer', ?, ?, ?)"))
                    .bind(format!("ne_{}",super::new_hex_id())).bind(node_id).bind(key).bind(body_json).bind(body_hash).bind(now)
                    .execute(&mut *tx).await.map_err(StoreError::Database)?;
                let audit=AuditDraft {actor_type:"node".into(),actor_id:Some(node_id.into()),
                    action:"fleet.recipient_offer_recorded".into(),target_type:"provisioning_offer".into(),target_id:Some(binding.offer_id),
                    metadata:json!({"outcome":"recorded","node_id":node_id,"operation_id":grant.operation_id,
                        "grant_id":grant.id,"source_binding_version":version}).as_object().unwrap().clone()};
                $audit(&mut tx,&self.tenant_id,&audit).await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(NodeEventInsert::Inserted)
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => ingest!(
                pool,
                |s: &str| s.to_owned(),
                SQLITE_NOW_MS,
                "UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1",
                "SELECT signing_pub,key_version FROM nodes WHERE id=? AND tenant_id=? AND status='active' AND NOT EXISTS (SELECT 1 FROM node_key_rotations r WHERE r.node_id=nodes.id) AND NOT EXISTS (SELECT 1 FROM node_revocation_queue q WHERE q.node_id=nodes.id)",
                "",
                "SELECT envelope_json FROM node_inbox WHERE node_id=? AND json_extract(envelope_json,'$.kind')='grant' AND json_extract(envelope_json,'$.body.id')=? ORDER BY seq LIMIT 1",
                "SELECT id FROM node_events WHERE node_id=? AND kind='recipient_offer' AND json_extract(body_json,'$.body.grant.id')=? LIMIT 1",
                insert_audit_sqlite
            ),
            Database::Postgres(pool) => ingest!(
                pool,
                super::pg,
                POSTGRES_NOW_MS,
                "SELECT issuer_epoch FROM controller_meta WHERE id=1 FOR UPDATE",
                "SELECT signing_pub,key_version FROM nodes WHERE id=? AND tenant_id=? AND status='active' AND NOT EXISTS (SELECT 1 FROM node_key_rotations r WHERE r.node_id=nodes.id) AND NOT EXISTS (SELECT 1 FROM node_revocation_queue q WHERE q.node_id=nodes.id) FOR UPDATE",
                "FOR UPDATE OF g,o,w,p,s",
                "SELECT envelope_json FROM node_inbox WHERE node_id=? AND envelope_json::jsonb->>'kind'='grant' AND envelope_json::jsonb#>>'{body,id}'=? ORDER BY seq LIMIT 1",
                "SELECT id FROM node_events WHERE node_id=? AND kind='recipient_offer' AND body_json::jsonb#>>'{body,grant,id}'=? LIMIT 1",
                insert_audit_postgres
            ),
        }
    }
}
