// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded protected-page rereads for one local transaction. No admission API.
use super::{
    AuthorityError, BrokerTrustState, OwnershipOperation, ProcessOwnership, RecoveryChallenge,
    RecoveryReceiptState,
};
use blindpass_core::{
    recovery::pages::{PageAccumulator, ReportPage},
    signing::base64_url_decode,
};
use sqlx::Row;
use std::{collections::VecDeque, sync::Arc};

pub(crate) struct RecoveryReportReader {
    owner: Arc<ProcessOwnership>,
    pub(crate) challenge: RecoveryChallenge,
    _operation: OwnershipOperation,
    accumulator: PageAccumulator,
    pending: VecDeque<(i64, String, String)>,
    index: u64,
    finished: bool,
}

impl ProcessOwnership {
    pub(crate) async fn validate_report_trust(
        self: &Arc<Self>,
        challenge: &RecoveryChallenge,
    ) -> Result<(), AuthorityError> {
        let trust = self
            .broker_trust(&challenge.identity.node_id)
            .await?
            .ok_or(AuthorityError::Conflict)?;
        let key_matches = (trust.identity.key_version == challenge.identity.node_key_version
            && trust.identity.signing_public == challenge.signing_public)
            || trust.identity.pending.as_ref().is_some_and(|pending| {
                pending.key_version == challenge.identity.node_key_version
                    && pending.signing_public == challenge.signing_public
            });
        if trust.revision != challenge.trust_revision
            || (trust.identity.state == BrokerTrustState::Revoked) != challenge.node_revoked
            || !key_matches
        {
            return Err(AuthorityError::Conflict);
        }
        Ok(())
    }

    pub(crate) async fn read_covered_recovery_report(
        self: &Arc<Self>,
        challenge: RecoveryChallenge,
    ) -> Result<RecoveryReportReader, AuthorityError> {
        self.check().await?;
        let operation = self.begin_recovery_operation()?;
        let manifest = challenge
            .manifest
            .as_ref()
            .ok_or(AuthorityError::Conflict)?;
        if challenge.state != RecoveryReceiptState::Covered
            || !challenge.consumed
            || challenge.next_page != manifest.page_count()
            || !manifest.coverage.covers(challenge.scope.snapshot_time_ms)
            || manifest.observed_issuer_epoch >= challenge.identity.recovery_generation
        {
            return Err(AuthorityError::Conflict);
        }
        self.validate_report_trust(&challenge).await?;
        Ok(RecoveryReportReader {
            owner: self.clone(),
            challenge,
            _operation: operation,
            accumulator: PageAccumulator::new(),
            pending: VecDeque::new(),
            index: 0,
            finished: false,
        })
    }
}

impl RecoveryReportReader {
    /// Call through EOF before committing. Every returned page is authenticated,
    /// but only EOF verifies complete ordered digest and unchanged protected context.
    pub(crate) async fn next_page(&mut self) -> Result<Option<ReportPage>, AuthorityError> {
        let result = self.next_inner().await;
        if result == Err(AuthorityError::Unavailable) {
            self.owner.fence();
        }
        result
    }

    async fn next_inner(&mut self) -> Result<Option<ReportPage>, AuthorityError> {
        self.owner.check().await?;
        if self.finished {
            return Ok(None);
        }
        if self.index == self.challenge.next_page {
            if !self.pending.is_empty() || !self.accumulator.complete() {
                return Err(AuthorityError::Conflict);
            }
            let current = self
                .owner
                .recovery_challenge(
                    &self.challenge.scope.recovery_id,
                    &self.challenge.identity.node_id,
                )
                .await?
                .ok_or(AuthorityError::Conflict)?;
            if current != self.challenge {
                return Err(AuthorityError::Conflict);
            }
            self.owner.validate_report_trust(&self.challenge).await?;
            self.finished = true;
            return Ok(None);
        }
        if self.pending.is_empty() {
            let rows = sqlx::query("SELECT page_index,page_json,signature FROM blindpass_authority.recovery_pages WHERE tenant_id=$1 AND recovery_id=$2 AND node_id=$3 AND page_index>=$4 AND page_index<$5 ORDER BY page_index")
                .bind(&self.owner.context.tenant_id).bind(&self.challenge.scope.recovery_id)
                .bind(&self.challenge.identity.node_id).bind(self.index as i64)
                .bind((self.index+8).min(self.challenge.next_page) as i64)
                .fetch_all(&self.owner.pool).await.map_err(|_|AuthorityError::Unavailable)?;
            for row in rows {
                self.pending.push_back((
                    row.try_get("page_index")
                        .map_err(|_| AuthorityError::Unavailable)?,
                    row.try_get("page_json")
                        .map_err(|_| AuthorityError::Unavailable)?,
                    row.try_get("signature")
                        .map_err(|_| AuthorityError::Unavailable)?,
                ));
            }
        }
        let (index, source, signature) =
            self.pending.pop_front().ok_or(AuthorityError::Conflict)?;
        if index != self.index as i64 {
            return Err(AuthorityError::Conflict);
        }
        let page = ReportPage::from_json(&source).map_err(|_| AuthorityError::Conflict)?;
        if self.challenge.manifest.as_ref() != Some(&page.manifest) {
            return Err(AuthorityError::Conflict);
        }
        let public = base64_url_decode(&self.challenge.signing_public, 32)
            .ok_or(AuthorityError::Conflict)?;
        let signature = base64_url_decode(&signature, 64).ok_or(AuthorityError::Conflict)?;
        let verified = page
            .verify(
                &self.challenge.identity,
                self.challenge.minimum_observed_epoch,
                &public,
                &signature,
            )
            .map_err(|_| AuthorityError::Conflict)?;
        self.accumulator
            .push(verified)
            .map_err(|_| AuthorityError::Conflict)?;
        self.index += 1;
        self.owner.check().await?;
        Ok(Some(page))
    }
}
