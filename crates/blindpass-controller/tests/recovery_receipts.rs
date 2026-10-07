// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_controller::recovery_authority::{
    Authority, AuthorityContext, BrokerTrustDraft, BrokerTrustState, PendingBrokerKey,
    ProcessOwnership, RecoveryChallenge, RecoveryReceiptScope, RecoveryReceiptState,
};
use blindpass_core::recovery::pages::{
    HistoryCoverage, IntentRecord, PageDigest, ReportManifest, ReportPage,
};
use blindpass_core::signing::{base64_url_decode, base64_url_encode, ed25519::Ed25519KeyPair};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;

struct Fixture {
    admin: PgPool,
    runtime: PgPool,
    authority: Authority,
    context: AuthorityContext,
    owner: Arc<ProcessOwnership>,
    signer: Ed25519KeyPair,
}
impl Fixture {
    async fn new() -> Self {
        Self::configured(None, false).await
    }
    async fn configured(rotation: Option<bool>, revoked: bool) -> Self {
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").unwrap())
            .await
            .unwrap();
        let url = std::env::var("P06_TEST_AUTHORITY_URL").unwrap();
        let runtime = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let authority = Authority::connect_existing(&url).await.unwrap();
        let context = AuthorityContext {
            tenant_id: format!(
                "RC_DUMMY_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),
            issuer_key_id: "RC_DUMMY_ISSUER".into(),
            owner_id: "RC_DUMMY_OWNER".into(),
        };
        sqlx::query(
            "INSERT INTO blindpass_authority.recovery_authority VALUES ($1,$2,$3,7,1,'active')",
        )
        .bind(&context.tenant_id)
        .bind(&context.issuer_key_id)
        .bind(&context.owner_id)
        .execute(&admin)
        .await
        .unwrap();
        let active = authority.read(&context).await.unwrap();
        let holder = Arc::new(authority.claim_process(&context, &active).await.unwrap());
        let original = Ed25519KeyPair::from_seed(&[71; 32]).unwrap();
        let candidate = Ed25519KeyPair::from_seed(&[79; 32]).unwrap();
        let mut draft = BrokerTrustDraft {
            node_id: "node_dummy_receipt".into(),
            key_version: 1,
            signing_public: base64_url_encode(original.public_key()),
            recipient_public: base64_url_encode(&[72; 32]),
            state: BrokerTrustState::Active,
            pending: None,
        };
        holder.publish_broker_trust(0, &draft).await.unwrap();
        let mut revision = 1;
        if let Some(acknowledged) = rotation {
            draft.pending = Some(PendingBrokerKey {
                key_version: 2,
                rotation_id: "rotation_dummy_receipt".into(),
                signing_public: base64_url_encode(candidate.public_key()),
                recipient_public: base64_url_encode(&[80; 32]),
            });
            revision = holder
                .publish_broker_trust(revision, &draft)
                .await
                .unwrap()
                .revision;
            if acknowledged {
                let approved = draft.pending.take().unwrap();
                draft.key_version = approved.key_version;
                draft.signing_public = approved.signing_public;
                draft.recipient_public = approved.recipient_public;
                revision = holder
                    .publish_broker_trust(revision, &draft)
                    .await
                    .unwrap()
                    .revision;
            }
        }
        if revoked {
            draft.state = BrokerTrustState::Revoked;
            draft.pending = None;
            holder.publish_broker_trust(revision, &draft).await.unwrap();
        }
        let signer = if rotation.is_some() {
            candidate
        } else {
            original
        };
        holder.quiesce().await.unwrap();
        drop(holder);
        sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1").bind(&context.tenant_id).execute(&admin).await.unwrap();
        let fenced = authority.read(&context).await.unwrap();
        let record = authority
            .reserve_recovery(&context, fenced.revision, 7)
            .await
            .unwrap();
        let owner = Arc::new(authority.claim_process(&context, &record).await.unwrap());
        Self {
            admin,
            runtime,
            authority,
            context,
            owner,
            signer,
        }
    }
    async fn resume(&mut self) {
        self.owner.quiesce().await.unwrap();
        let record = self.authority.read(&self.context).await.unwrap();
        self.owner = Arc::new(
            self.authority
                .claim_process(&self.context, &record)
                .await
                .unwrap(),
        );
    }
    async fn close(self) {
        self.owner.quiesce().await.unwrap();
        drop(self.owner);
        self.authority.close().await;
        self.runtime.close().await;
        self.admin.close().await;
    }
}
fn scope(id: &str) -> RecoveryReceiptScope {
    RecoveryReceiptScope {
        recovery_id: id.into(),
        snapshot_epoch: 7,
        snapshot_time_ms: 1000,
        backup_digest: base64_url_encode(&[73; 32]),
    }
}
fn pages(
    challenge: &RecoveryChallenge,
    count: usize,
    observed: u64,
    coverage: HistoryCoverage,
) -> Vec<ReportPage> {
    let records: Vec<_> = (0..count)
        .map(|i| IntentRecord {
            grant_id: format!("grant_{i:08}"),
            operation_id: (coverage.unmapped_records == 0).then(|| format!("operation_{i:08}")),
            issuer_epoch: (coverage.unmapped_records == 0).then_some(7),
            expires_at_ms: 2000,
        })
        .collect();
    let mut manifest = ReportManifest {
        identity: challenge.identity.clone(),
        report_id: base64_url_encode(&[74; 32]),
        observed_issuer_epoch: observed,
        coverage,
        total_records: count as u64,
        records_digest: base64_url_encode(&[0; 32]),
    };
    let mut digest = PageDigest::new(&manifest).unwrap();
    for record in &records {
        digest.push(record).unwrap();
    }
    manifest.records_digest = digest.finish().unwrap();
    (0..manifest.page_count())
        .map(|i| ReportPage {
            manifest: manifest.clone(),
            page_index: i,
            records: records[(i as usize * 128)..records.len().min((i as usize + 1) * 128)]
                .to_vec(),
        })
        .collect()
}
fn known() -> HistoryCoverage {
    HistoryCoverage {
        history_id: Some(base64_url_encode(&[75; 32])),
        pruned_through_ms: 0,
        unmapped_records: 0,
    }
}
async fn stage(f: &Fixture, page: &ReportPage) -> RecoveryChallenge {
    let signature = f.signer.sign(&page.signing_message().unwrap()).unwrap();
    f.owner
        .stage_recovery_page(
            &page.manifest.identity.recovery_id,
            &page.manifest.identity.node_id,
            page,
            &signature,
        )
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_rc01_rc02_rc03_current_key_pages_and_nonce_survive_reacquisition_and_complete_once() {
    let mut f = Fixture::new().await;
    for count in [0, 1, 128, 129, 384] {
        let s = scope(&format!("recovery_count_{count}"));
        let challenge = f
            .owner
            .open_recovery_challenge(&s, "node_dummy_receipt", 1)
            .await
            .unwrap();
        assert_eq!(
            base64_url_decode(&challenge.identity.challenge, 32)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(challenge.state, RecoveryReceiptState::Collecting);
        assert_eq!(challenge.next_page, 0);
        assert_eq!(
            f.owner
                .open_recovery_challenge(&s, "node_dummy_receipt", 1)
                .await
                .unwrap(),
            challenge
        );
        let report = pages(&challenge, count, 7, known());
        for page in &report {
            let stored = stage(&f, page).await;
            assert_eq!(stored.next_page, page.page_index + 1);
            assert_eq!(
                stage(&f, page).await,
                stored,
                "pending exact retry must not duplicate a page"
            );
            f.resume().await;
            assert_eq!(
                f.owner
                    .recovery_challenge(&s.recovery_id, "node_dummy_receipt")
                    .await
                    .unwrap(),
                Some(stored)
            );
        }
        let completed = f
            .owner
            .finish_recovery_report(&s.recovery_id, "node_dummy_receipt")
            .await
            .unwrap();
        assert_eq!(completed.state, RecoveryReceiptState::Covered);
        assert!(completed.consumed);
        assert!(
            f.owner
                .finish_recovery_report(&s.recovery_id, "node_dummy_receipt")
                .await
                .is_err()
        );
        let signature = f
            .signer
            .sign(&report[0].signing_message().unwrap())
            .unwrap();
        assert!(
            f.owner
                .stage_recovery_page(&s.recovery_id, "node_dummy_receipt", &report[0], &signature)
                .await
                .is_err()
        );
        f.resume().await;
        assert_eq!(
            f.owner
                .open_recovery_challenge(&s, "node_dummy_receipt", 1)
                .await
                .unwrap(),
            completed,
            "reopening must retain consumed authority"
        );
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_rc02_rc04_forgery_gap_conflicting_header_and_digest_never_consume() {
    let f = Fixture::new().await;
    let s = scope("recovery_bad_pages");
    let challenge = f
        .owner
        .open_recovery_challenge(&s, "node_dummy_receipt", 1)
        .await
        .unwrap();
    assert!(
        f.owner
            .open_recovery_challenge(&s, "unknown_node", 1)
            .await
            .is_err()
    );
    assert!(
        f.owner
            .open_recovery_challenge(&s, "node_dummy_receipt", 2)
            .await
            .is_err()
    );
    let mut wrong_scope = s.clone();
    wrong_scope.backup_digest = base64_url_encode(&[76; 32]);
    assert!(
        f.owner
            .open_recovery_challenge(&wrong_scope, "node_dummy_receipt", 1)
            .await
            .is_err()
    );
    let report = pages(&challenge, 129, 7, known());
    let forged = Ed25519KeyPair::from_seed(&[77; 32])
        .unwrap()
        .sign(&report[0].signing_message().unwrap())
        .unwrap();
    assert!(
        f.owner
            .stage_recovery_page(&s.recovery_id, "node_dummy_receipt", &report[0], &forged)
            .await
            .is_err()
    );
    let signature = f
        .signer
        .sign(&report[1].signing_message().unwrap())
        .unwrap();
    assert!(
        f.owner
            .stage_recovery_page(&s.recovery_id, "node_dummy_receipt", &report[1], &signature)
            .await
            .is_err()
    );
    assert_eq!(
        f.owner
            .recovery_challenge(&s.recovery_id, "node_dummy_receipt")
            .await
            .unwrap()
            .unwrap()
            .next_page,
        0
    );
    stage(&f, &report[0]).await;
    let mut changed = report[1].clone();
    changed.manifest.report_id = base64_url_encode(&[78; 32]);
    let signature = f.signer.sign(&changed.signing_message().unwrap()).unwrap();
    assert!(
        f.owner
            .stage_recovery_page(&s.recovery_id, "node_dummy_receipt", &changed, &signature)
            .await
            .is_err()
    );
    assert!(
        f.owner
            .finish_recovery_report(&s.recovery_id, "node_dummy_receipt")
            .await
            .is_err()
    );
    assert!(
        !f.owner
            .recovery_challenge(&s.recovery_id, "node_dummy_receipt")
            .await
            .unwrap()
            .unwrap()
            .consumed
    );
    let s = scope("recovery_bad_digest");
    let challenge = f
        .owner
        .open_recovery_challenge(&s, "node_dummy_receipt", 1)
        .await
        .unwrap();
    let mut page = pages(&challenge, 1, 7, known()).remove(0);
    page.manifest.records_digest = base64_url_encode(&[0; 32]);
    stage(&f, &page).await;
    assert!(
        f.owner
            .finish_recovery_report(&s.recovery_id, "node_dummy_receipt")
            .await
            .is_err()
    );
    assert!(
        !f.owner
            .recovery_challenge(&s.recovery_id, "node_dummy_receipt")
            .await
            .unwrap()
            .unwrap()
            .consumed
    );
    f.owner.check().await.unwrap();
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_rc05_unknown_pruned_unmapped_and_higher_epochs_never_release_coverage() {
    let f = Fixture::new().await;
    for (id, count, coverage) in [
        (
            "unknown",
            0,
            HistoryCoverage {
                history_id: None,
                pruned_through_ms: 0,
                unmapped_records: 0,
            },
        ),
        (
            "pruned",
            0,
            HistoryCoverage {
                history_id: known().history_id,
                pruned_through_ms: 1000,
                unmapped_records: 0,
            },
        ),
        (
            "unmapped",
            1,
            HistoryCoverage {
                history_id: known().history_id,
                pruned_through_ms: 0,
                unmapped_records: 1,
            },
        ),
    ] {
        let s = scope(id);
        let challenge = f
            .owner
            .open_recovery_challenge(&s, "node_dummy_receipt", 1)
            .await
            .unwrap();
        for page in pages(&challenge, count, 7, coverage) {
            stage(&f, &page).await;
        }
        let result = f
            .owner
            .finish_recovery_report(id, "node_dummy_receipt")
            .await
            .unwrap();
        assert_eq!(result.state, RecoveryReceiptState::Incomplete);
        assert!(!result.consumed);
    }
    for observed in [8, 9] {
        let id = format!("higher_{observed}");
        let challenge = f
            .owner
            .open_recovery_challenge(&scope(&id), "node_dummy_receipt", 1)
            .await
            .unwrap();
        let page = pages(&challenge, 0, observed, known()).remove(0);
        stage(&f, &page).await;
        let result = f
            .owner
            .finish_recovery_report(&id, "node_dummy_receipt")
            .await
            .unwrap();
        assert_eq!(result.state, RecoveryReceiptState::RebaseRequired);
        assert!(!result.consumed);
    }
    f.owner.quiesce().await.unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1").bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let fenced = f.authority.read(&f.context).await.unwrap();
    let rebased = f
        .authority
        .reserve_recovery(&f.context, fenced.revision, 7)
        .await
        .unwrap();
    assert_eq!(
        rebased.epoch, 10,
        "protected observations, not stale caller input, determine the new reservation"
    );
    drop(f.owner);
    f.authority.close().await;
    f.runtime.close().await;
    f.admin.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_rc04_pending_and_rotated_revoked_keys_preserve_independent_trust() {
    for (acknowledged, revoked) in [(false, false), (true, true)] {
        let f = Fixture::configured(Some(acknowledged), revoked).await;
        let s = scope("recovery_current_key");
        if acknowledged {
            assert!(
                f.owner
                    .open_recovery_challenge(&s, "node_dummy_receipt", 1)
                    .await
                    .is_err()
            );
        }
        let challenge = f
            .owner
            .open_recovery_challenge(&s, "node_dummy_receipt", 2)
            .await
            .unwrap();
        assert_eq!(
            challenge.signing_public,
            base64_url_encode(f.signer.public_key())
        );
        assert_eq!(challenge.node_revoked, revoked);
        let prior = f
            .owner
            .broker_trust("node_dummy_receipt")
            .await
            .unwrap()
            .unwrap();
        let page = pages(&challenge, 0, 7, known()).remove(0);
        let retired = Ed25519KeyPair::from_seed(&[71; 32])
            .unwrap()
            .sign(&page.signing_message().unwrap())
            .unwrap();
        assert!(
            f.owner
                .stage_recovery_page(&s.recovery_id, "node_dummy_receipt", &page, &retired)
                .await
                .is_err()
        );
        stage(&f, &page).await;
        let receipt = f
            .owner
            .finish_recovery_report(&s.recovery_id, "node_dummy_receipt")
            .await
            .unwrap();
        assert_eq!(receipt.state, RecoveryReceiptState::Covered);
        assert_eq!(receipt.node_revoked, revoked);
        assert_eq!(
            f.owner
                .broker_trust("node_dummy_receipt")
                .await
                .unwrap()
                .unwrap(),
            prior,
            "coverage must not acknowledge rotation or revive a revoked node"
        );
        assert!(
            f.owner.begin_operation().is_err(),
            "covered history never grants active admission"
        );
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_rc06_actual_blocked_stage_socket_loss_latches_uncertainty_without_reset() {
    use std::time::Duration;
    let f = Fixture::new().await;
    let s = scope("recovery_socket_loss");
    let challenge = f
        .owner
        .open_recovery_challenge(&s, "node_dummy_receipt", 1)
        .await
        .unwrap();
    let page = pages(&challenge, 0, 7, known()).remove(0);
    let signature = f.signer.sign(&page.signing_message().unwrap()).unwrap();
    let mut blocker = f.admin.begin().await.unwrap();
    sqlx::query("SELECT tenant_id FROM blindpass_authority.recovery_challenges WHERE tenant_id=$1 AND recovery_id=$2 FOR UPDATE")
        .bind(&f.context.tenant_id).bind(&s.recovery_id).execute(&mut *blocker).await.unwrap();
    let writer = {
        let owner = f.owner.clone();
        let id = s.recovery_id.clone();
        tokio::spawn(async move {
            owner
                .stage_recovery_page(&id, "node_dummy_receipt", &page, &signature)
                .await
        })
    };
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2),async {loop {
        let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks AS locks JOIN pg_stat_activity AS activity ON activity.pid=locks.pid WHERE activity.datname=current_database() AND activity.usename=$1 AND NOT locks.granted AND locks.locktype='transactionid')").bind(&role).fetch_one(&f.runtime).await.unwrap();
        if blocked {break;}tokio::time::sleep(Duration::from_millis(10)).await;
    }}).await.expect("actual signed-page writer must reach its lock wait");
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(f.owner.backend_pid())
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    assert!(terminated);
    assert!(f.owner.check().await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_secs(3), writer)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(f.owner.is_fenced());
    assert!(f.owner.has_uncertain_database_work());
    assert!(f.owner.quiesce().await.is_err());
    assert!(
        f.owner
            .open_recovery_challenge(&s, "node_dummy_receipt", 1)
            .await
            .is_err()
    );
    blocker.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(4),async {loop {
        let running:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks AS locks JOIN pg_stat_activity AS activity ON activity.pid=locks.pid WHERE activity.datname=current_database() AND activity.usename=$1 AND locks.relation='blindpass_authority.recovery_challenges'::regclass)").bind(&role).fetch_one(&f.admin).await.unwrap();
        if !running {break;}tokio::time::sleep(Duration::from_millis(10)).await;
    }}).await.expect("owned server work must end before inspecting its uncertain result");
    let retained:(String,bool,i64)=sqlx::query_as("SELECT nonce,consumed,next_page FROM blindpass_authority.recovery_challenges WHERE tenant_id=$1 AND recovery_id=$2")
        .bind(&f.context.tenant_id).bind(&s.recovery_id).fetch_one(&f.admin).await.unwrap();
    assert_eq!(retained.0, challenge.identity.challenge);
    assert!(!retained.1);
    assert!((0..=1).contains(&retained.2));
    assert!(f.owner.has_uncertain_database_work());
    drop(f.owner);
    f.authority.close().await;
    f.runtime.close().await;
    f.admin.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_rc07_runtime_cannot_reset_pages_nonces_observations_or_use_write_capable_credentials()
{
    let f = Fixture::new().await;
    let s = scope("recovery_permissions");
    let challenge = f
        .owner
        .open_recovery_challenge(&s, "node_dummy_receipt", 1)
        .await
        .unwrap();
    stage(&f, &pages(&challenge, 0, 7, known()).remove(0)).await;
    for statement in [
        "UPDATE blindpass_authority.recovery_challenges SET next_page=0,manifest_json=NULL",
        "DELETE FROM blindpass_authority.recovery_challenges",
        "TRUNCATE blindpass_authority.recovery_challenges",
        "UPDATE blindpass_authority.recovery_pages SET signature='dummy'",
        "DELETE FROM blindpass_authority.recovery_pages",
        "TRUNCATE blindpass_authority.recovery_pages",
        "UPDATE blindpass_authority.broker_observations SET observed_epoch=1",
        "DELETE FROM blindpass_authority.broker_observations",
        "TRUNCATE blindpass_authority.broker_observations",
    ] {
        assert!(sqlx::query(statement).execute(&f.runtime).await.is_err());
    }
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    assert!(
        role.starts_with("p06_authority_")
            && role
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    sqlx::query(&format!(
        "GRANT UPDATE(page_json) ON blindpass_authority.recovery_pages TO {role}"
    ))
    .execute(&f.admin)
    .await
    .unwrap();
    assert!(
        Authority::connect_existing(&std::env::var("P06_TEST_AUTHORITY_URL").unwrap())
            .await
            .is_err()
    );
    sqlx::query(&format!(
        "REVOKE UPDATE(page_json) ON blindpass_authority.recovery_pages FROM {role}"
    ))
    .execute(&f.admin)
    .await
    .unwrap();
    let scope_before = f
        .owner
        .recovery_challenge(&s.recovery_id, "node_dummy_receipt")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(scope_before.next_page, 1);
    assert_eq!(
        scope_before.identity.challenge,
        challenge.identity.challenge
    );
    f.close().await;
}
