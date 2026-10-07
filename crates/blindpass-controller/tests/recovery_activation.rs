// SPDX-License-Identifier: AGPL-3.0-only
//! P06-D30..D32: protected activation of a restored (`recovering`) authority record.
use blindpass_controller::recovery_authority::{
    Authority, AuthorityContext, BrokerTrustDraft, BrokerTrustState, ProcessOwnership,
    RecoveryReceiptScope, ReviewKey,
};
use blindpass_core::recovery::pages::{
    HistoryCoverage, IntentRecord, PageDigest, ReportManifest, ReportPage,
};
use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;

struct Node {
    id: String,
    signer: Ed25519KeyPair,
}
struct Fixture {
    admin: PgPool,
    runtime: PgPool,
    authority: Authority,
    context: AuthorityContext,
    owner: Option<Arc<ProcessOwnership>>,
    nodes: Vec<Node>,
}
impl Fixture {
    async fn new(nodes: usize) -> Self {
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
                "RA_DUMMY_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),
            issuer_key_id: "RA_DUMMY_ISSUER".into(),
            owner_id: "RA_DUMMY_OWNER".into(),
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
        let mut made = Vec::new();
        for i in 0..nodes {
            let signer = Ed25519KeyPair::from_seed(&[(71 + i) as u8; 32]).unwrap();
            let id = format!("node_dummy_act{i}");
            let draft = BrokerTrustDraft {
                node_id: id.clone(),
                key_version: 1,
                signing_public: base64_url_encode(signer.public_key()),
                recipient_public: base64_url_encode(&[(120 + i) as u8; 32]),
                state: BrokerTrustState::Active,
                pending: None,
            };
            holder.publish_broker_trust(0, &draft).await.unwrap();
            made.push(Node { id, signer });
        }
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
            owner: Some(owner),
            nodes: made,
        }
    }
    fn owner(&self) -> &Arc<ProcessOwnership> {
        self.owner.as_ref().unwrap()
    }
    /// The recovering controller stops: its guard session ends.
    async fn stop_owner(&mut self) {
        let owner = self.owner.take().unwrap();
        owner.quiesce().await.unwrap();
    }
    async fn start_owner(&mut self) {
        let record = self.authority.read(&self.context).await.unwrap();
        self.owner = Some(Arc::new(
            self.authority
                .claim_process(&self.context, &record)
                .await
                .unwrap(),
        ));
    }
    async fn cover(&self, index: usize) {
        let node = &self.nodes[index];
        let s = RecoveryReceiptScope {
            recovery_id: format!("recovery_act_{index}"),
            snapshot_epoch: 7,
            snapshot_time_ms: 1000,
            backup_digest: base64_url_encode(&[73; 32]),
        };
        let challenge = self
            .owner()
            .open_recovery_challenge(&s, &node.id, 1)
            .await
            .unwrap();
        let record = IntentRecord {
            grant_id: "grant_00000000".into(),
            operation_id: Some("operation_00000000".into()),
            issuer_epoch: Some(7),
            expires_at_ms: 2000,
        };
        let mut manifest = ReportManifest {
            identity: challenge.identity.clone(),
            report_id: base64_url_encode(&[74; 32]),
            observed_issuer_epoch: 7,
            coverage: HistoryCoverage {
                history_id: Some(base64_url_encode(&[75; 32])),
                pruned_through_ms: 0,
                unmapped_records: 0,
            },
            total_records: 1,
            records_digest: base64_url_encode(&[0; 32]),
        };
        let mut digest = PageDigest::new(&manifest).unwrap();
        digest.push(&record).unwrap();
        manifest.records_digest = digest.finish().unwrap();
        let page = ReportPage {
            manifest,
            page_index: 0,
            records: vec![record],
        };
        let signature = node.signer.sign(&page.signing_message().unwrap()).unwrap();
        self.owner()
            .stage_recovery_page(&s.recovery_id, &node.id, &page, &signature)
            .await
            .unwrap();
        let done = self
            .owner()
            .finish_recovery_report(&s.recovery_id, &node.id)
            .await
            .unwrap();
        assert!(done.consumed);
    }
    async fn decide_one(&self) {
        let key = item("operation_00000000");
        self.owner()
            .decide_recovery_item(&key, "accept", "operator_dummy", "checked")
            .await
            .unwrap();
    }
    async fn complete(&self) {
        let count = self.owner().recovery_decisions().await.unwrap().len() as u64;
        self.owner().complete_recovery_review(count).await.unwrap();
    }
    async fn attest(&self) -> Result<i64, String> {
        sqlx::query_scalar("SELECT blindpass_authority.attest_source_stop($1,$2,$3,$4,$5,$6)")
            .bind(&self.context.tenant_id)
            .bind(&self.context.issuer_key_id)
            .bind(&self.context.owner_id)
            .bind("host_dummy_source")
            .bind("admin_dummy")
            .bind("source host powered off")
            .fetch_one(&self.admin)
            .await
            .map_err(|e| e.to_string())
    }
    async fn revision(&self) -> u64 {
        self.authority.read(&self.context).await.unwrap().revision
    }
    async fn activate(&self, pool: &PgPool) -> Result<(i64, i64, String), String> {
        let revision = self.revision().await as i64;
        sqlx::query_as("SELECT * FROM blindpass_authority.activate_recovery($1,$2,$3,$4)")
            .bind(&self.context.tenant_id)
            .bind(&self.context.issuer_key_id)
            .bind(&self.context.owner_id)
            .bind(revision)
            .fetch_one(pool)
            .await
            .map_err(|e| e.to_string())
    }
    async fn close(mut self) {
        if let Some(owner) = self.owner.take() {
            owner.quiesce().await.unwrap();
        }
        self.authority.close().await;
        self.runtime.close().await;
        self.admin.close().await;
    }
}
fn item(subject: &str) -> ReviewKey {
    ReviewKey {
        category: "operation".into(),
        subject_id: subject.into(),
        related_id: String::new(),
    }
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra01_every_unmet_gate_is_named_and_nothing_activates() {
    let mut f = Fixture::new(1).await;
    assert_eq!(
        f.owner().recovery_activation_gaps().await.unwrap(),
        ["source_stop_missing", "review_incomplete", "node_uncovered"]
    );
    f.stop_owner().await;
    let refused = f.activate(&f.admin).await.unwrap_err();
    for gap in ["source_stop_missing", "review_incomplete", "node_uncovered"] {
        assert!(refused.contains(gap), "{refused}");
    }
    assert!(!refused.contains("source_process_live"), "{refused}");
    f.start_owner().await;
    let live = f.activate(&f.admin).await.unwrap_err();
    assert!(live.contains("source_process_live"), "{live}");
    assert_eq!(
        f.authority.read(&f.context).await.unwrap().phase,
        "recovering"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra02_the_runtime_role_can_neither_attest_nor_activate() {
    let mut f = Fixture::new(1).await;
    f.cover(0).await;
    f.decide_one().await;
    f.complete().await;
    f.stop_owner().await;
    f.attest().await.unwrap();
    for sql in [
        "SELECT blindpass_authority.attest_source_stop($1,$2,$3,'host_x','op_x','n')::text",
        "SELECT (blindpass_authority.activate_recovery($1,$2,$3,2)).phase",
    ] {
        let err = sqlx::query_scalar::<_, String>(sql)
            .bind(&f.context.tenant_id)
            .bind(&f.context.issuer_key_id)
            .bind(&f.context.owner_id)
            .fetch_one(&f.runtime)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("permission denied"), "{err}");
    }
    for table in [
        "recovery_source_stop",
        "recovery_node_waivers",
        "recovery_review_decisions",
        "recovery_review_complete",
    ] {
        let err = sqlx::query(&format!(
            "DELETE FROM blindpass_authority.{table} WHERE tenant_id=$1"
        ))
        .bind(&f.context.tenant_id)
        .execute(&f.runtime)
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("permission denied"), "{table}: {err}");
    }
    assert_eq!(
        f.authority.read(&f.context).await.unwrap().phase,
        "recovering"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra03_attestation_needs_a_free_guard_a_recovering_record_and_is_insert_only() {
    let mut f = Fixture::new(1).await;
    let live = f.attest().await.unwrap_err();
    assert!(
        live.contains("could not obtain lock") || live.contains("55P03"),
        "{live}"
    );
    f.stop_owner().await;
    let epoch = f.attest().await.unwrap();
    assert_eq!(epoch, 8);
    let again = f.attest().await.unwrap_err();
    assert!(again.contains("duplicate key"), "{again}");
    for sql in [
        "UPDATE blindpass_authority.recovery_source_stop SET host_id='other_host' WHERE tenant_id=$1",
        "DELETE FROM blindpass_authority.recovery_source_stop WHERE tenant_id=$1",
    ] {
        let err = sqlx::query(sql)
            .bind(&f.context.tenant_id)
            .execute(&f.admin)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("insert-only") || err.contains("forbidden"),
            "{err}"
        );
    }
    let row: (String, String) = sqlx::query_as("SELECT host_id,attested_by FROM blindpass_authority.recovery_source_stop WHERE tenant_id=$1")
        .bind(&f.context.tenant_id)
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(row, ("host_dummy_source".into(), "admin_dummy".into()));
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra03b_attestation_for_a_fenced_or_active_record_is_refused() {
    let f = Fixture::new(1).await;
    let other = AuthorityContext {
        tenant_id: format!("{}_other", f.context.tenant_id),
        ..f.context.clone()
    };
    for phase in ["fenced", "active"] {
        sqlx::query("INSERT INTO blindpass_authority.recovery_authority VALUES ($1,$2,$3,7,1,$4) ON CONFLICT (tenant_id) DO UPDATE SET phase=EXCLUDED.phase,revision=blindpass_authority.recovery_authority.revision+1")
            .bind(&other.tenant_id)
            .bind(&other.issuer_key_id)
            .bind(&other.owner_id)
            .bind(phase)
            .execute(&f.admin)
            .await
            .unwrap();
        let err = sqlx::query_scalar::<_, i64>(
            "SELECT blindpass_authority.attest_source_stop($1,$2,$3,'host_x','admin_dummy','n')",
        )
        .bind(&other.tenant_id)
        .bind(&other.issuer_key_id)
        .bind(&other.owner_id)
        .fetch_one(&f.admin)
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("no matching recovering record"),
            "{phase}: {err}"
        );
        let revision: i64 = sqlx::query_scalar(
            "SELECT revision FROM blindpass_authority.recovery_authority WHERE tenant_id=$1",
        )
        .bind(&other.tenant_id)
        .fetch_one(&f.admin)
        .await
        .unwrap();
        let err = sqlx::query_scalar::<_, String>(
            "SELECT (blindpass_authority.activate_recovery($1,$2,$3,$4)).phase",
        )
        .bind(&other.tenant_id)
        .bind(&other.issuer_key_id)
        .bind(&other.owner_id)
        .bind(revision)
        .fetch_one(&f.admin)
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("not_recovering"), "{phase}: {err}");
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra04_decisions_are_replaceable_until_completion_and_final_afterwards() {
    let f = Fixture::new(1).await;
    let key = item("operation_00000001");
    let owner = f.owner();
    owner
        .decide_recovery_item(&key, "reject", "operator_dummy", "unknown")
        .await
        .unwrap();
    owner
        .decide_recovery_item(&key, "revoke", "operator_two", "")
        .await
        .unwrap();
    let decisions = owner.recovery_decisions().await.unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].decision, "revoke");
    assert_eq!(decisions[0].operator_id, "operator_two");
    for (category, decision, operator) in [
        ("bogus", "accept", "operator_dummy"),
        ("operation", "maybe", "operator_dummy"),
        ("operation", "accept", "bad operator"),
        ("operation", "accept", ""),
    ] {
        let bad = ReviewKey {
            category: category.into(),
            ..key.clone()
        };
        assert!(
            owner
                .decide_recovery_item(&bad, decision, operator, "n")
                .await
                .is_err()
        );
    }
    assert!(
        owner.complete_recovery_review(2).await.is_err(),
        "count must equal the decisions held"
    );
    assert!(owner.complete_recovery_review(0).await.is_err());
    owner.complete_recovery_review(1).await.unwrap();
    owner.complete_recovery_review(1).await.unwrap();
    assert!(
        owner
            .decide_recovery_item(&key, "accept", "operator_dummy", "late")
            .await
            .is_err()
    );
    assert!(
        owner
            .decide_recovery_item(
                &item("operation_00000002"),
                "accept",
                "operator_dummy",
                "late"
            )
            .await
            .is_err()
    );
    let err = sqlx::query("UPDATE blindpass_authority.recovery_review_decisions SET decision='accept' WHERE tenant_id=$1")
        .bind(&f.context.tenant_id)
        .execute(&f.admin)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("final after completion"), "{err}");
    assert_eq!(
        owner.recovery_decisions().await.unwrap()[0].decision,
        "revoke"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra05_only_the_live_recovering_holder_can_write_review_evidence() {
    let mut f = Fixture::new(1).await;
    let owner = f.owner().clone();
    f.stop_owner().await;
    assert!(
        owner
            .decide_recovery_item(&item("operation_00000009"), "accept", "operator_dummy", "x")
            .await
            .is_err()
    );
    assert!(owner.complete_recovery_review(0).await.is_err());
    assert!(
        owner
            .waive_recovery_node("node_dummy_act0", "operator_dummy", "x")
            .await
            .is_err()
    );
    let held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blindpass_authority.recovery_review_decisions WHERE tenant_id=$1",
    )
    .bind(&f.context.tenant_id)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(held, 0);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra06_success_activates_once_and_the_source_can_never_serve_again() {
    let mut f = Fixture::new(1).await;
    f.cover(0).await;
    f.decide_one().await;
    f.complete().await;
    assert!(
        f.owner().recovery_activation_gaps().await.unwrap() == ["source_stop_missing"],
        "only the attestation is missing"
    );
    let stale = f.authority.read(&f.context).await.unwrap();
    assert!(!f.owner().recovery_activation_recorded(8).await.unwrap());
    f.stop_owner().await;
    f.attest().await.unwrap();
    let (epoch, revision, phase) = f.activate(&f.admin).await.unwrap();
    assert_eq!(
        (epoch, revision, phase.as_str()),
        (8, stale.revision as i64 + 1, "active")
    );
    let record = f.authority.read(&f.context).await.unwrap();
    assert_eq!((record.phase.as_str(), record.epoch), ("active", 8));
    let again = f.activate(&f.admin).await.unwrap_err();
    assert!(again.contains("not_recovering"), "{again}");
    f.start_owner().await;
    assert!(f.owner().recovery_activation_recorded(8).await.unwrap());
    assert!(!f.owner().recovery_activation_recorded(9).await.unwrap());
    f.stop_owner().await;
    assert!(
        f.authority.claim_process(&f.context, &stale).await.is_err(),
        "a reservation holder from before activation cannot claim"
    );
    let gaps: Vec<String> =
        sqlx::query_scalar("SELECT blindpass_authority.recovery_activation_gaps($1,$2,$3,TRUE)")
            .bind(&f.context.tenant_id)
            .bind(&f.context.issuer_key_id)
            .bind(&f.context.owner_id)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(gaps, ["not_recovering"]);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra07_multi_node_needs_every_node_covered_or_named_waived() {
    let mut f = Fixture::new(3).await;
    f.cover(0).await;
    f.decide_one().await;
    f.complete().await;
    f.stop_owner().await;
    f.attest().await.unwrap();
    let err = f.activate(&f.admin).await.unwrap_err();
    assert!(err.contains("node_uncovered"), "{err}");
    // Review completion froze waivers: the waiver path is closed after completion.
    f.start_owner().await;
    assert!(
        f.owner()
            .waive_recovery_node("node_dummy_act1", "operator_dummy", "late")
            .await
            .is_err()
    );
    f.close().await;

    let mut f = Fixture::new(3).await;
    f.cover(0).await;
    f.owner()
        .waive_recovery_node("node_dummy_act1", "operator_dummy", "hardware lost")
        .await
        .unwrap();
    assert!(
        f.owner()
            .waive_recovery_node("node_dummy_act0", "operator_dummy", "covered")
            .await
            .is_err(),
        "a covered node is not waivable"
    );
    assert!(
        f.owner()
            .waive_recovery_node("node_unknown_x", "operator_dummy", "x")
            .await
            .is_err()
    );
    let gaps = f.owner().recovery_activation_gaps().await.unwrap();
    assert!(gaps.contains(&"node_uncovered".to_string()), "{gaps:?}");
    f.owner()
        .waive_recovery_node("node_dummy_act2", "operator_dummy", "decommissioned")
        .await
        .unwrap();
    f.decide_one().await;
    f.complete().await;
    let coverage = f.owner().recovery_coverage().await.unwrap();
    let state = |id: &str| coverage.iter().find(|c| c.node_id == id).unwrap().clone();
    assert!(
        state("node_dummy_act0").receipt.as_deref() == Some("covered")
            && !state("node_dummy_act0").waived
    );
    assert!(state("node_dummy_act1").waived && state("node_dummy_act1").revoked);
    assert!(state("node_dummy_act2").waived && state("node_dummy_act2").revoked);
    f.stop_owner().await;
    f.attest().await.unwrap();
    f.activate(&f.admin).await.unwrap();
    let trust: Vec<(String, String)> = sqlx::query_as("SELECT node_id,state FROM blindpass_authority.broker_trust WHERE tenant_id=$1 ORDER BY node_id")
        .bind(&f.context.tenant_id)
        .fetch_all(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        trust,
        [
            ("node_dummy_act0".to_string(), "active".to_string()),
            ("node_dummy_act1".to_string(), "revoked".to_string()),
            ("node_dummy_act2".to_string(), "revoked".to_string()),
        ]
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra08_review_incomplete_blocks_activation_even_with_everything_else_met() {
    let mut f = Fixture::new(1).await;
    f.cover(0).await;
    f.decide_one().await;
    f.stop_owner().await;
    f.attest().await.unwrap();
    let err = f.activate(&f.admin).await.unwrap_err();
    assert!(err.contains("review_incomplete"), "{err}");
    assert!(
        !err.contains("node_uncovered") && !err.contains("source_stop_missing"),
        "{err}"
    );
    f.start_owner().await;
    f.complete().await;
    f.stop_owner().await;
    f.activate(&f.admin).await.unwrap();
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority"]
async fn p06_ra09_fence_then_ordinary_activation_leaves_no_activation_proof() {
    let mut f = Fixture::new(1).await;
    f.stop_owner().await;
    // The two existing administrator scripts, applied in order to a recovering record.
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1 AND phase IN ('active','recovering')")
        .bind(&f.context.tenant_id)
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1 AND phase IN ('fenced','active')")
        .bind(&f.context.tenant_id)
        .execute(&f.admin)
        .await
        .unwrap();
    f.start_owner().await;
    assert_eq!(f.authority.read(&f.context).await.unwrap().phase, "active");
    assert!(
        !f.owner().recovery_activation_recorded(8).await.unwrap(),
        "only activate_recovery records activation proof"
    );
    f.close().await;
}
