// SPDX-License-Identifier: AGPL-3.0-only
//! Durable recovery metadata outside controller backups. Coverage is not
//! provider reconciliation, source-stop proof, node admission or activation.
use super::{AuthorityError, ProcessOwnership, deadline, safe_integer};
use blindpass_core::canon::{canonicalize_value, parse_json};
use blindpass_core::custody::sha256;
use blindpass_core::fleet::is_valid_opaque_id;
use blindpass_core::recovery::pages::{
    PageAccumulator, ReportIdentity, ReportManifest, ReportPage,
};
use blindpass_core::signing::{base64_url_decode, base64_url_encode};
use rand::{RngCore, rngs::OsRng};
use sqlx::{Row, postgres::PgRow};
use std::{sync::Arc, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReceiptScope {
    pub recovery_id: String,
    pub snapshot_epoch: u64,
    pub snapshot_time_ms: u64,
    pub backup_digest: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReceiptState {
    Collecting,
    Covered,
    Incomplete,
    RebaseRequired,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryChallenge {
    pub identity: ReportIdentity,
    pub scope: RecoveryReceiptScope,
    pub signing_public: String,
    pub trust_revision: u64,
    pub node_revoked: bool,
    pub minimum_observed_epoch: u64,
    pub next_page: u64,
    pub manifest: Option<ReportManifest>,
    pub state: RecoveryReceiptState,
    pub consumed: bool,
}
fn nonce(value: &str) -> bool {
    base64_url_decode(value, 32).is_some_and(|bytes| base64_url_encode(&bytes) == value)
}
impl RecoveryReceiptScope {
    pub(crate) fn validate(&self) -> Result<(), AuthorityError> {
        if !is_valid_opaque_id(&self.recovery_id)
            || !safe_integer(self.snapshot_epoch)
            || !safe_integer(self.snapshot_time_ms)
            || !nonce(&self.backup_digest)
        {
            return Err(AuthorityError::InvalidInput);
        }
        Ok(())
    }
}
fn number(row: &PgRow, name: &str) -> Result<u64, AuthorityError> {
    u64::try_from(
        row.try_get::<i64, _>(name)
            .map_err(|_| AuthorityError::Unavailable)?,
    )
    .map_err(|_| AuthorityError::Unavailable)
}
pub(super) fn conflict(error: sqlx::Error) -> AuthorityError {
    match &error {
        sqlx::Error::Database(error)
            if matches!(
                error.code().as_deref(),
                Some("23505" | "23514" | "P0001" | "40001" | "40P01")
            ) =>
        {
            AuthorityError::Conflict
        }
        _ => AuthorityError::Unavailable,
    }
}
impl ProcessOwnership {
    fn parse_challenge(&self, row: PgRow) -> Result<RecoveryChallenge, AuthorityError> {
        let string = |name| {
            row.try_get::<String, _>(name)
                .map_err(|_| AuthorityError::Unavailable)
        };
        if string("tenant_id")? != self.context.tenant_id
            || string("issuer_key_id")? != self.context.issuer_key_id
            || string("owner_id")? != self.context.owner_id
            || number(&row, "epoch")? != self.record.epoch
            || number(&row, "authority_revision")? != self.record.revision
        {
            return Err(AuthorityError::Unavailable);
        }
        let scope = RecoveryReceiptScope {
            recovery_id: string("recovery_id")?,
            snapshot_epoch: number(&row, "snapshot_epoch")?,
            snapshot_time_ms: number(&row, "snapshot_time_ms")?,
            backup_digest: string("backup_digest")?,
        };
        scope.validate().map_err(|_| AuthorityError::Unavailable)?;
        let identity = ReportIdentity {
            tenant_id: self.context.tenant_id.clone(),
            issuer_key_id: self.context.issuer_key_id.clone(),
            node_id: string("node_id")?,
            node_key_version: number(&row, "node_key_version")?,
            recovery_id: scope.recovery_id.clone(),
            recovery_generation: self.record.epoch,
            challenge: string("nonce")?,
        };
        let signing_public = string("signing_public")?;
        let trust_revision = number(&row, "trust_revision")?;
        let minimum_observed_epoch = number(&row, "minimum_observed_epoch")?;
        let next_page = number(&row, "next_page")?;
        let manifest_source = row
            .try_get::<Option<String>, _>("manifest_json")
            .map_err(|_| AuthorityError::Unavailable)?;
        let manifest = manifest_source
            .map(|source| {
                let value = parse_json(&source).map_err(|_| AuthorityError::Unavailable)?;
                let parsed =
                    ReportManifest::from_value(&value).map_err(|_| AuthorityError::Unavailable)?;
                if canonicalize_value(&parsed.to_value().map_err(|_| AuthorityError::Unavailable)?)
                    .map_err(|_| AuthorityError::Unavailable)?
                    != source.as_bytes()
                    || parsed.identity != identity
                {
                    return Err(AuthorityError::Unavailable);
                }
                Ok(parsed)
            })
            .transpose()?;
        let state = match string("state")?.as_str() {
            "collecting" => RecoveryReceiptState::Collecting,
            "covered" => RecoveryReceiptState::Covered,
            "incomplete" => RecoveryReceiptState::Incomplete,
            "rebase_required" => RecoveryReceiptState::RebaseRequired,
            _ => return Err(AuthorityError::Unavailable),
        };
        let consumed = row
            .try_get::<bool, _>("consumed")
            .map_err(|_| AuthorityError::Unavailable)?;
        if !is_valid_opaque_id(&identity.node_id)
            || !nonce(&identity.challenge)
            || !nonce(&signing_public)
            || !safe_integer(identity.node_key_version)
            || !safe_integer(trust_revision)
            || !safe_integer(minimum_observed_epoch)
            || scope.snapshot_epoch >= identity.recovery_generation
            || next_page > 7813
            || (manifest.is_none()) != (next_page == 0)
            || consumed != (state == RecoveryReceiptState::Covered)
            || (state != RecoveryReceiptState::Collecting
                && manifest
                    .as_ref()
                    .is_none_or(|m| next_page != m.page_count()))
        {
            return Err(AuthorityError::Unavailable);
        }
        Ok(RecoveryChallenge {
            identity,
            scope,
            signing_public,
            trust_revision,
            node_revoked: row
                .try_get("node_revoked")
                .map_err(|_| AuthorityError::Unavailable)?,
            minimum_observed_epoch,
            next_page,
            manifest,
            state,
            consumed,
        })
    }
    // All writes use separately committed SQL statements. Definite conflicts
    // acknowledge their outcome; cancellation/unavailability remains uncertain.
    pub(super) async fn receipt_work<T>(
        self: &Arc<Self>,
        write: bool,
        future: impl std::future::Future<Output = Result<T, AuthorityError>>,
    ) -> Result<T, AuthorityError> {
        self.check().await?;
        let mut operation = self.begin_recovery_operation()?.database_work();
        if !write {
            // Cancelling a metadata SELECT is not uncertain server mutation.
            operation.acknowledge();
        }
        let result=deadline(async {tokio::select! {biased;_=self.wait_fenced()=>Err(AuthorityError::Unavailable),result=future=>result}}).await;
        if result.is_ok()
            || matches!(
                result,
                Err(AuthorityError::Conflict | AuthorityError::InvalidInput)
            )
        {
            operation.acknowledge();
        }
        if matches!(result, Err(AuthorityError::Unavailable)) {
            self.fence();
            return result;
        }
        self.check().await?;
        result
    }
    pub async fn open_recovery_challenge(
        self: &Arc<Self>,
        scope: &RecoveryReceiptScope,
        node_id: &str,
        key_version: u64,
    ) -> Result<RecoveryChallenge, AuthorityError> {
        scope.validate()?;
        if !is_valid_opaque_id(node_id)
            || !safe_integer(key_version)
            || scope.snapshot_epoch >= self.record.epoch
        {
            return Err(AuthorityError::InvalidInput);
        }
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| AuthorityError::Unavailable)?;
        let fresh = base64_url_encode(&bytes);
        self.receipt_work(true,async {
            let row=sqlx::query("SELECT * FROM blindpass_authority.open_recovery_challenge($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
                .bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(&self.context.owner_id).bind(self.record.epoch as i64).bind(self.record.revision as i64).bind(self.backend_pid).bind(self.process_token.as_bytes())
                .bind(&scope.recovery_id).bind(node_id).bind(key_version as i64).bind(scope.snapshot_epoch as i64).bind(scope.snapshot_time_ms as i64).bind(&scope.backup_digest).bind(&fresh)
                .fetch_optional(&self.pool).await.map_err(conflict)?.ok_or(AuthorityError::Conflict)?;
            self.parse_challenge(row)
        }).await
    }
    pub async fn recovery_challenge(
        self: &Arc<Self>,
        recovery_id: &str,
        node_id: &str,
    ) -> Result<Option<RecoveryChallenge>, AuthorityError> {
        if !is_valid_opaque_id(recovery_id) || !is_valid_opaque_id(node_id) {
            return Err(AuthorityError::InvalidInput);
        }
        self.receipt_work(false,async {
            let row=sqlx::query("SELECT * FROM blindpass_authority.recovery_challenges WHERE tenant_id=$1 AND issuer_key_id=$2 AND owner_id=$3 AND epoch=$4 AND authority_revision=$5 AND recovery_id=$6 AND node_id=$7")
                .bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(&self.context.owner_id).bind(self.record.epoch as i64).bind(self.record.revision as i64).bind(recovery_id).bind(node_id)
                .fetch_optional(&self.pool).await.map_err(|_|AuthorityError::Unavailable)?;
            row.map(|row|self.parse_challenge(row)).transpose()
        }).await
    }
    pub async fn stage_recovery_page(
        self: &Arc<Self>,
        recovery_id: &str,
        node_id: &str,
        page: &ReportPage,
        signature: &[u8],
    ) -> Result<RecoveryChallenge, AuthorityError> {
        let challenge = self
            .recovery_challenge(recovery_id, node_id)
            .await?
            .ok_or(AuthorityError::Conflict)?;
        if challenge.state != RecoveryReceiptState::Collecting {
            return Err(AuthorityError::Conflict);
        }
        let public =
            base64_url_decode(&challenge.signing_public, 32).ok_or(AuthorityError::Unavailable)?;
        page.verify(
            &challenge.identity,
            challenge.minimum_observed_epoch,
            &public,
            signature,
        )
        .map_err(|_| AuthorityError::InvalidInput)?;
        let header = canonicalize_value(
            &page
                .manifest
                .to_value()
                .map_err(|_| AuthorityError::InvalidInput)?,
        )
        .map_err(|_| AuthorityError::InvalidInput)?;
        let source =
            canonicalize_value(&page.to_value().map_err(|_| AuthorityError::InvalidInput)?)
                .map_err(|_| AuthorityError::InvalidInput)?;
        let header = std::str::from_utf8(&header).map_err(|_| AuthorityError::InvalidInput)?;
        let source = std::str::from_utf8(&source).map_err(|_| AuthorityError::InvalidInput)?;
        self.receipt_work(true,async {
            let row=sqlx::query("SELECT * FROM blindpass_authority.stage_recovery_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)")
                .bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(&self.context.owner_id).bind(self.record.epoch as i64).bind(self.record.revision as i64).bind(self.backend_pid).bind(self.process_token.as_bytes())
                .bind(recovery_id).bind(node_id).bind(&challenge.identity.challenge).bind(challenge.trust_revision as i64).bind(page.page_index as i64).bind(header).bind(source).bind(base64_url_encode(signature))
                .fetch_optional(&self.pool).await.map_err(conflict)?.ok_or(AuthorityError::Conflict)?;
            self.parse_challenge(row)
        }).await
    }
    /// Reverify bounded batches of protected pages and the complete ordered
    /// digest, then atomically consume this challenge. A covered result attests
    /// to this history range only. It must never directly enable node/grant use.
    pub async fn finish_recovery_report(
        self: &Arc<Self>,
        recovery_id: &str,
        node_id: &str,
    ) -> Result<RecoveryChallenge, AuthorityError> {
        let challenge = self
            .recovery_challenge(recovery_id, node_id)
            .await?
            .ok_or(AuthorityError::Conflict)?;
        if challenge.state != RecoveryReceiptState::Collecting {
            return Err(AuthorityError::Conflict);
        }
        let manifest = challenge
            .manifest
            .as_ref()
            .ok_or(AuthorityError::Conflict)?;
        if challenge.next_page != manifest.page_count() {
            return Err(AuthorityError::Conflict);
        }
        self.check().await?;
        let operation = self.begin_recovery_operation()?;
        let public =
            base64_url_decode(&challenge.signing_public, 32).ok_or(AuthorityError::Unavailable)?;
        let verified = tokio::select! {biased;
            _=self.wait_fenced()=>Err(AuthorityError::Unavailable),
            result=tokio::time::timeout(Duration::from_secs(30),async {
                let mut accumulator=PageAccumulator::new();let mut index=0;
                while index<challenge.next_page {
                    let rows=sqlx::query("SELECT page_index,page_json,signature FROM blindpass_authority.recovery_pages WHERE tenant_id=$1 AND recovery_id=$2 AND node_id=$3 AND page_index>=$4 AND page_index<$5 ORDER BY page_index")
                        .bind(&self.context.tenant_id).bind(recovery_id).bind(node_id).bind(index as i64).bind((index+8).min(challenge.next_page) as i64)
                        .fetch_all(&self.pool).await.map_err(|_|AuthorityError::Unavailable)?;
                    if rows.is_empty() {return Err(AuthorityError::Conflict);}
                    for row in rows {
                        if number(&row,"page_index")?!=index {return Err(AuthorityError::Conflict);}
                        let source=row.try_get::<String,_>("page_json").map_err(|_|AuthorityError::Unavailable)?;
                        let signature=row.try_get::<String,_>("signature").map_err(|_|AuthorityError::Unavailable)?;
                        let signature=base64_url_decode(&signature,64).ok_or(AuthorityError::Conflict)?;
                        let page=ReportPage::from_json(&source).map_err(|_|AuthorityError::Conflict)?;
                        if &page.manifest!=manifest {return Err(AuthorityError::Conflict);}
                        let page=page.verify(&challenge.identity,challenge.minimum_observed_epoch,&public,&signature).map_err(|_|AuthorityError::Conflict)?;
                        accumulator.push(page).map_err(|_|AuthorityError::Conflict)?;index+=1;
                    }
                }
                if !accumulator.complete(){return Err(AuthorityError::Conflict);}Ok(())
            })=>result.unwrap_or(Err(AuthorityError::Unavailable)),
        };
        if verified == Err(AuthorityError::Unavailable) {
            self.fence();
        }
        verified?;
        self.check().await?;
        let header =
            canonicalize_value(&manifest.to_value().map_err(|_| AuthorityError::Conflict)?)
                .map_err(|_| AuthorityError::Conflict)?;
        let header_digest = sha256(&header).map_err(|_| AuthorityError::Unavailable)?;
        let result=self.receipt_work(true,async {
            let row=sqlx::query("SELECT * FROM blindpass_authority.finish_recovery_challenge($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)")
                .bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(&self.context.owner_id).bind(self.record.epoch as i64).bind(self.record.revision as i64).bind(self.backend_pid).bind(self.process_token.as_bytes())
                .bind(recovery_id).bind(node_id).bind(&challenge.identity.challenge).bind(challenge.trust_revision as i64).bind(challenge.next_page as i64).bind(header_digest.as_slice())
                .bind(manifest.coverage.covers(challenge.scope.snapshot_time_ms)).bind(manifest.observed_issuer_epoch as i64)
                .fetch_optional(&self.pool).await.map_err(conflict)?.ok_or(AuthorityError::Conflict)?;
            self.parse_challenge(row)
        }).await;
        drop(operation);
        result
    }
}

impl ProcessOwnership {
    /// Exact metadata transport retry after terminal collection. This checks a
    /// persisted page; it never stages again or consumes an already used nonce.
    pub(crate) async fn verify_stored_recovery_page(
        self: &Arc<Self>,
        challenge: &RecoveryChallenge,
        page: &ReportPage,
        signature: &[u8],
    ) -> Result<(), AuthorityError> {
        self.validate_report_trust(challenge).await?;
        if challenge.manifest.as_ref() != Some(&page.manifest)
            || page.page_index >= challenge.next_page
        {
            return Err(AuthorityError::Conflict);
        }
        let public =
            base64_url_decode(&challenge.signing_public, 32).ok_or(AuthorityError::Unavailable)?;
        page.verify(
            &challenge.identity,
            challenge.minimum_observed_epoch,
            &public,
            signature,
        )
        .map_err(|_| AuthorityError::InvalidInput)?;
        let source =
            canonicalize_value(&page.to_value().map_err(|_| AuthorityError::InvalidInput)?)
                .map_err(|_| AuthorityError::InvalidInput)?;
        self.receipt_work(false,async {
            let row=sqlx::query_as::<_,(String,String)>("SELECT page_json,signature FROM blindpass_authority.recovery_pages WHERE tenant_id=$1 AND recovery_id=$2 AND node_id=$3 AND page_index=$4")
                .bind(&self.context.tenant_id).bind(&challenge.scope.recovery_id).bind(&challenge.identity.node_id).bind(page.page_index as i64)
                .fetch_optional(&self.pool).await.map_err(|_|AuthorityError::Unavailable)?.ok_or(AuthorityError::Conflict)?;
            if row.0.as_bytes()!=source || row.1!=base64_url_encode(signature) {return Err(AuthorityError::Conflict);}
            Ok(())
        }).await?;
        if self
            .recovery_challenge(&challenge.scope.recovery_id, &challenge.identity.node_id)
            .await?
            .as_ref()
            != Some(challenge)
        {
            return Err(AuthorityError::Conflict);
        }
        self.validate_report_trust(challenge).await
    }
}
