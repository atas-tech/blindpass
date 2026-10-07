// SPDX-License-Identifier: AGPL-3.0-only
//! Scoped recovering collection. Report status cannot authorize ordinary work.

use crate::{
    recovery_authority::{
        AuthorityError, ProcessOwnership, RecoveryChallenge, RecoveryReceiptScope,
    },
    store::{Store, StoreError},
};
use blindpass_core::recovery::pages::ReportPage;
use std::sync::Arc;

pub(super) fn authority<T>(result: Result<T, AuthorityError>) -> Result<T, StoreError> {
    result.map_err(|error| match error {
        AuthorityError::Conflict | AuthorityError::InvalidInput => {
            StoreError::InvalidInput("recovery report")
        }
        AuthorityError::Unavailable => StoreError::AuthorityFenced,
    })
}

impl Store {
    pub(super) async fn scoped_recovery_challenge(
        &self,
        owner: &Arc<ProcessOwnership>,
        scope: &RecoveryReceiptScope,
        node: &str,
    ) -> Result<RecoveryChallenge, StoreError> {
        let challenge = authority(owner.recovery_challenge(&scope.recovery_id, node).await)?
            .ok_or(StoreError::InvalidInput("recovery report"))?;
        if challenge.scope != *scope {
            return Err(StoreError::InvalidInput("recovery report snapshot context"));
        }
        Ok(challenge)
    }

    async fn checked_recovery_result(
        &self,
        owner: &Arc<ProcessOwnership>,
        expected: &RecoveryReceiptScope,
        challenge: RecoveryChallenge,
    ) -> Result<RecoveryChallenge, StoreError> {
        // A late external commit cannot be hidden by a changed local snapshot.
        // Re-reading validates the signature and live binding before delivery.
        if self.recovery_receipt_scope(owner).await? != *expected || challenge.scope != *expected {
            owner.fence();
            return Err(StoreError::AuthorityFenced);
        }
        Ok(challenge)
    }

    /// Metadata collection under the authenticated local archive scope. The
    /// external authority alone selects current/approved pending broker keys.
    pub async fn open_recovery_report(
        &self,
        owner: &Arc<ProcessOwnership>,
        node: &str,
        version: u64,
    ) -> Result<RecoveryChallenge, StoreError> {
        let scope = self.recovery_receipt_scope(owner).await?;
        let challenge = authority(owner.open_recovery_challenge(&scope, node, version).await)?;
        self.checked_recovery_result(owner, &scope, challenge).await
    }

    /// No caller-supplied snapshot metadata or restored node key can replace
    /// the locally authenticated scope and independently protected challenge.
    pub async fn stage_recovery_report(
        &self,
        owner: &Arc<ProcessOwnership>,
        page: &ReportPage,
        signature: &[u8],
    ) -> Result<RecoveryChallenge, StoreError> {
        let scope = self.recovery_receipt_scope(owner).await?;
        if page.manifest.identity.recovery_id != scope.recovery_id {
            return Err(StoreError::InvalidInput("recovery report"));
        }
        let node = &page.manifest.identity.node_id;
        self.scoped_recovery_challenge(owner, &scope, node).await?;
        let challenge = authority(
            owner
                .stage_recovery_page(&scope.recovery_id, node, page, signature)
                .await,
        )?;
        self.checked_recovery_result(owner, &scope, challenge).await
    }

    /// Coverage status is metadata only. This neither applies broker records
    /// to local operations nor releases node/provider quarantine or admission.
    pub async fn finish_recovery_report(
        &self,
        owner: &Arc<ProcessOwnership>,
        node: &str,
    ) -> Result<RecoveryChallenge, StoreError> {
        let scope = self.recovery_receipt_scope(owner).await?;
        self.scoped_recovery_challenge(owner, &scope, node).await?;
        let challenge = authority(owner.finish_recovery_report(&scope.recovery_id, node).await)?;
        self.checked_recovery_result(owner, &scope, challenge).await
    }
}

impl Store {
    /// Domain-limited metadata request. Protected identity and staged frontier
    /// cannot be supplied by the caller; the broker checks its own fresh nonce.
    pub async fn recovery_report_request(
        &self,
        owner: &Arc<ProcessOwnership>,
        node: &str,
        version: u64,
        broker_nonce: &str,
    ) -> Result<blindpass_core::recovery::pages::SignedReportRequest, StoreError> {
        use crate::recovery_authority::RecoveryReceiptState;
        use blindpass_core::{
            recovery::pages::{ReportRequest, SignedReportRequest},
            signing::{base64_url_decode, base64_url_encode},
        };
        if !base64_url_decode(broker_nonce, 32)
            .is_some_and(|bytes| base64_url_encode(&bytes) == broker_nonce)
        {
            return Err(StoreError::InvalidInput("broker recovery nonce"));
        }
        let challenge = self.open_recovery_report(owner, node, version).await?;
        if challenge.state != RecoveryReceiptState::Collecting
            || challenge.consumed
            || challenge
                .manifest
                .as_ref()
                .is_some_and(|manifest| challenge.next_page >= manifest.page_count())
        {
            return Err(StoreError::InvalidInput("recovery report frontier"));
        }
        let _operation = owner
            .begin_recovery_operation()
            .map_err(|_| StoreError::AuthorityFenced)?;
        let signer = self
            .fleet_signer
            .as_ref()
            .ok_or(StoreError::MissingState("issuer signer"))?;
        let signed = SignedReportRequest::sign(
            ReportRequest {
                identity: challenge.identity.clone(),
                broker_challenge: broker_nonce.to_owned(),
                report_id: challenge
                    .manifest
                    .as_ref()
                    .map(|manifest| manifest.report_id.clone()),
                page_index: challenge.next_page,
            },
            &signer.keypair,
        )
        .map_err(|_| StoreError::InvalidInput("recovery report request"))?;
        // Native signing is synchronous, but its result must not escape a lost
        // holder or changed authenticated archive/protected challenge.
        let scope = self.recovery_receipt_scope(owner).await?;
        let current = self.scoped_recovery_challenge(owner, &scope, node).await?;
        if current != challenge {
            owner.fence();
            return Err(StoreError::AuthorityFenced);
        }
        authority(owner.validate_report_trust(&current).await)?;
        owner
            .check()
            .await
            .map_err(|_| StoreError::AuthorityFenced)?;
        Ok(signed)
    }
}

impl Store {
    async fn complete_collected_recovery_report(
        &self,
        owner: &Arc<ProcessOwnership>,
        mut challenge: RecoveryChallenge,
    ) -> Result<(RecoveryChallenge, Option<super::RecoveryApplicationSummary>), StoreError> {
        use crate::recovery_authority::RecoveryReceiptState;
        if challenge.state == RecoveryReceiptState::Collecting
            && challenge
                .manifest
                .as_ref()
                .is_some_and(|manifest| challenge.next_page == manifest.page_count())
        {
            challenge = self
                .finish_recovery_report(owner, &challenge.identity.node_id)
                .await?;
        }
        let application = if challenge.state == RecoveryReceiptState::Covered {
            Some(
                self.apply_recovery_report(owner, &challenge.identity.node_id)
                    .await?,
            )
        } else {
            None
        };
        self.checked_recovery_result(owner, &challenge.scope.clone(), challenge.clone())
            .await?;
        Ok((challenge, application))
    }

    /// Resumes already durable complete/consumed receipts after response loss
    /// or restart. Partial progress still requires broker-signed pages.
    pub async fn resume_recovery_report(
        &self,
        owner: &Arc<ProcessOwnership>,
        node: &str,
        version: u64,
    ) -> Result<(RecoveryChallenge, Option<super::RecoveryApplicationSummary>), StoreError> {
        let challenge = self.open_recovery_report(owner, node, version).await?;
        self.complete_collected_recovery_report(owner, challenge)
            .await
    }

    /// Exact terminal retries return metadata only after checking the stored
    /// signature/page and re-verifying application. Nonce consumption stays once.
    pub async fn receive_recovery_report(
        &self,
        owner: &Arc<ProcessOwnership>,
        page: &ReportPage,
        signature: &[u8],
    ) -> Result<(RecoveryChallenge, Option<super::RecoveryApplicationSummary>), StoreError> {
        use crate::recovery_authority::RecoveryReceiptState;
        let scope = self.recovery_receipt_scope(owner).await?;
        if page.manifest.identity.recovery_id != scope.recovery_id {
            return Err(StoreError::InvalidInput("recovery report"));
        }
        let challenge = self
            .scoped_recovery_challenge(owner, &scope, &page.manifest.identity.node_id)
            .await?;
        let challenge = if challenge.state == RecoveryReceiptState::Collecting {
            self.stage_recovery_report(owner, page, signature).await?
        } else {
            authority(
                owner
                    .verify_stored_recovery_page(&challenge, page, signature)
                    .await,
            )?;
            challenge
        };
        self.complete_collected_recovery_report(owner, challenge)
            .await
    }
}
