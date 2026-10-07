// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_controller::recovery_authority::{
    Authority, AuthorityContext, AuthorityError, AuthorityRecord,
};
mod support;

use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX: u64 = 9_007_199_254_740_991;

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_pt04_socket_loss_during_blocked_registry_work_preserves_uncertainty() {
    use blindpass_controller::recovery_authority::{BrokerTrustDraft, BrokerTrustState};
    use blindpass_core::signing::base64_url_encode;
    let f = Fixture::new(253).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let active = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &active)
            .await
            .unwrap(),
    );
    let mut draft = BrokerTrustDraft {
        node_id: "node_dummy_socket_loss".into(),
        key_version: 1,
        signing_public: base64_url_encode(&[31; 32]),
        recipient_public: base64_url_encode(&[33; 32]),
        state: BrokerTrustState::Active,
        pending: None,
    };
    let initial = owner.publish_broker_trust(0, &draft).await.unwrap();
    let mut blocker = f.admin.begin().await.unwrap();
    sqlx::query("SELECT tenant_id FROM blindpass_authority.recovery_authority WHERE tenant_id=$1 FOR UPDATE")
        .bind(&f.context.tenant_id).execute(&mut *blocker).await.unwrap();
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    draft.state = BrokerTrustState::Revoked;
    let publisher = {
        let owner = owner.clone();
        let draft = draft.clone();
        tokio::spawn(async move { owner.publish_broker_trust(initial.revision, &draft).await })
    };
    tokio::time::timeout(Duration::from_secs(2),async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks AS locks JOIN pg_stat_activity AS activity ON activity.pid=locks.pid WHERE activity.datname=current_database() AND activity.usename=$1 AND NOT locks.granted AND locks.locktype='transactionid')")
                .bind(&role).fetch_one(&f.runtime).await.unwrap();
            if blocked {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("actual registry writer must reach the PostgreSQL lock wait");
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(owner.backend_pid())
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    assert!(terminated);
    assert!(owner.check().await.is_err());
    let result = tokio::time::timeout(Duration::from_secs(3), publisher)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, Err(AuthorityError::Unavailable));
    assert!(owner.is_fenced());
    assert!(owner.has_uncertain_database_work());
    assert!(
        owner
            .publish_broker_trust(initial.revision, &draft)
            .await
            .is_err()
    );
    assert!(owner.broker_trust(&draft.node_id).await.is_err());
    assert!(owner.quiesce().await.is_err());
    blocker.rollback().await.unwrap();
    // A submitted server statement can outlive its caller. Either retained
    // active metadata or a conservative revocation is uncertain, never success
    // or permission to clear the latch. Observe after server work has ended.
    tokio::time::timeout(Duration::from_secs(4),async {
        loop {
            let running: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks AS locks JOIN pg_stat_activity AS activity ON activity.pid=locks.pid WHERE activity.datname=current_database() AND activity.usename=$1 AND locks.relation='blindpass_authority.recovery_authority'::regclass)")
                .bind(&role).fetch_one(&f.admin).await.unwrap();
            if !running {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("bounded fixture server work must finish");
    let state: (i64,String) = sqlx::query_as("SELECT revision,state FROM blindpass_authority.broker_trust WHERE tenant_id=$1 AND node_id=$2")
        .bind(&f.context.tenant_id).bind(&draft.node_id).fetch_one(&f.admin).await.unwrap();
    assert!(state == (1, "active".into()) || state == (2, "revoked".into()));
    assert!(
        f.authority
            .claim_process(&f.context, &active)
            .await
            .is_err()
    );
    assert!(owner.has_uncertain_database_work());
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority and owned controller backend"]
async fn p06_pt06_actual_owned_enrollment_rotation_ack_and_revocation_publish_current_trust() {
    use blindpass_controller::recovery_authority::BrokerTrustState;
    use blindpass_core::signing::base64_url_encode;
    use serde_json::json;
    let mut h = support::Harness::start().await;
    let f = Fixture::with_context(
        1,
        Some(AuthorityContext {
            tenant_id: h.store.tenant_id().into(),
            issuer_key_id: h.issuer_key_id.clone(),
            owner_id: "P06_DUMMY_HOST".into(),
        }),
    )
    .await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let active = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &active)
            .await
            .unwrap(),
    );
    h.restart_server_with_ownership(owner.clone()).await;
    let keys = support::NodeKeys::from_seed(61);
    let node_id = h.enroll_node("current-trust-node", &keys).await;
    let original = owner
        .broker_trust(&node_id)
        .await
        .unwrap()
        .expect("approved enrollment must publish independent current trust");
    assert_eq!(original.identity.key_version, 1);
    assert_eq!(
        original.identity.signing_public,
        base64_url_encode(keys.signing.public_key())
    );
    let candidate = support::NodeKeys::from_seed(63);
    let staged = h
        .call(
            &h.admin,
            "POST",
            &format!("/api/v3/nodes/{node_id}/rotate-key"),
            &[],
            Some(&json!({
                "expected_key_version":1,"expected_fingerprint":candidate.fingerprint(),
                "signing_pub":base64_url_encode(candidate.signing.public_key()),
                "recipient_pub":base64_url_encode(candidate.recipient.public_key())
            })),
        )
        .await;
    assert_eq!(staged.status, 202, "{}", staged.body);
    let pending = owner.broker_trust(&node_id).await.unwrap().unwrap();
    assert_eq!(pending.identity.key_version, 1);
    let rotation = pending.identity.pending.as_ref().unwrap();
    assert_eq!(rotation.key_version, 2);
    assert_eq!(
        rotation.signing_public,
        base64_url_encode(candidate.signing.public_key())
    );
    let bearer = h.open_session(&node_id, 2, &candidate).await;
    let event = support::signed_event(
        &node_id,
        &candidate.signing,
        &format!("rotation_{}", rotation.rotation_id),
        "audit",
        json!({
            "action":"node_key_rotation_applied","fingerprint":candidate.fingerprint(),"key_version":2,
            "node_id":node_id,"rotation_id":rotation.rotation_id
        }),
    );
    let acknowledged = h
        .request(
            "POST",
            "/api/v3/node/events",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
            ],
            Some(&event),
        )
        .await;
    assert_eq!(acknowledged.status, 200, "{}", acknowledged.body);
    let current = owner.broker_trust(&node_id).await.unwrap().unwrap();
    assert_eq!(current.identity.key_version, 2);
    assert_eq!(
        current.identity.signing_public,
        base64_url_encode(candidate.signing.public_key())
    );
    assert!(current.identity.pending.is_none());
    let revoked = h
        .call(
            &h.admin,
            "DELETE",
            &format!("/api/v3/nodes/{node_id}"),
            &[],
            Some(&json!({})),
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    let tombstone = owner.broker_trust(&node_id).await.unwrap().unwrap();
    assert_eq!(tombstone.identity.state, BrokerTrustState::Revoked);
    assert_eq!(tombstone.identity.key_version, 2);

    // A rotation already approved before revocation may be acknowledged late.
    // Recording that key must preserve the revoked state.
    let old = support::NodeKeys::from_seed(65);
    let late_id = h.enroll_node("late-revoked-rotation", &old).await;
    let late = support::NodeKeys::from_seed(67);
    let staged = h
        .call(
            &h.admin,
            "POST",
            &format!("/api/v3/nodes/{late_id}/rotate-key"),
            &[],
            Some(&json!({
                "expected_key_version":1,"expected_fingerprint":late.fingerprint(),
                "signing_pub":base64_url_encode(late.signing.public_key()),
                "recipient_pub":base64_url_encode(late.recipient.public_key())
            })),
        )
        .await;
    assert_eq!(staged.status, 202, "{}", staged.body);
    let pending = owner
        .broker_trust(&late_id)
        .await
        .unwrap()
        .unwrap()
        .identity
        .pending
        .unwrap();
    let revoked = h
        .call(
            &h.admin,
            "DELETE",
            &format!("/api/v3/nodes/{late_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    let bearer = h.open_session(&late_id, 2, &late).await;
    let event = support::signed_event(
        &late_id,
        &late.signing,
        &format!("rotation_{}", pending.rotation_id),
        "audit",
        json!({
            "action":"node_key_rotation_applied","fingerprint":late.fingerprint(),"key_version":2,
            "node_id":late_id,"rotation_id":pending.rotation_id
        }),
    );
    let acknowledged = h
        .request(
            "POST",
            "/api/v3/node/events",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
            ],
            Some(&event),
        )
        .await;
    assert_eq!(acknowledged.status, 200, "{}", acknowledged.body);
    let final_revoked = owner.broker_trust(&late_id).await.unwrap().unwrap();
    assert_eq!(final_revoked.identity.key_version, 2);
    assert_eq!(final_revoked.identity.state, BrokerTrustState::Revoked);
    assert!(final_revoked.identity.pending.is_none());
    owner.quiesce().await.unwrap();
    drop(h);
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority and owned controller backend"]
async fn p06_pt04_external_revocation_survives_a_failed_controller_commit_and_fences() {
    let mut h = support::Harness::start().await;
    let f = Fixture::with_context(
        1,
        Some(AuthorityContext {
            tenant_id: h.store.tenant_id().into(),
            issuer_key_id: h.issuer_key_id.clone(),
            owner_id: "P06_DUMMY_HOST".into(),
        }),
    )
    .await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let active = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &active)
            .await
            .unwrap(),
    );
    h.restart_server_with_ownership(owner.clone()).await;
    let node_id = h
        .enroll_node("failed-commit-trust", &support::NodeKeys::from_seed(71))
        .await;
    h.execute("CREATE TABLE p06_commit_failure (node_id TEXT REFERENCES nodes(id) DEFERRABLE INITIALLY DEFERRED)",vec![]).await;
    match &h.backend {
        support::Backend::Sqlite(_) => {
            h.execute("CREATE TRIGGER p06_revocation_commit_failure AFTER UPDATE OF status ON nodes WHEN NEW.status='revoked' BEGIN INSERT INTO p06_commit_failure VALUES ('P06_DUMMY_MISSING_NODE'); END",vec![]).await;
        }
        support::Backend::Postgres(_) => {
            h.execute("CREATE FUNCTION p06_revocation_commit_failure() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN INSERT INTO p06_commit_failure VALUES ('P06_DUMMY_MISSING_NODE'); RETURN NEW; END; $$",vec![]).await;
            h.execute("CREATE TRIGGER p06_revocation_commit_failure AFTER UPDATE OF status ON nodes FOR EACH ROW WHEN (NEW.status='revoked') EXECUTE FUNCTION p06_revocation_commit_failure()",vec![]).await;
        }
    }
    let response = h
        .call(
            &h.admin,
            "DELETE",
            &format!("/api/v3/nodes/{node_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(response.status, 503, "{}", response.body);
    assert!(owner.is_fenced());
    assert!(owner.has_uncertain_database_work());
    let state: String = sqlx::query_scalar(
        "SELECT state FROM blindpass_authority.broker_trust WHERE tenant_id=$1 AND node_id=$2",
    )
    .bind(&f.context.tenant_id)
    .bind(&node_id)
    .fetch_one(&f.runtime)
    .await
    .unwrap();
    assert_eq!(state, "revoked");
    let still_active = h
        .scalar_i64(
            "SELECT COUNT(*) FROM nodes WHERE id=? AND status='active'",
            vec![node_id.into()],
        )
        .await;
    assert_eq!(
        still_active, 1,
        "failed controller commit must not roll external revocation back"
    );
    assert!(owner.quiesce().await.is_err());
    // Exact owned fixture cleanup only; termination is not source-stop proof.
    sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
        .bind(owner.backend_pid())
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    assert!(
        f.authority
            .claim_process(&f.context, &active)
            .await
            .is_err()
    );
    drop(h);
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_pt02_pt03_current_keys_pending_rotation_and_revocation_are_external_and_monotonic() {
    use blindpass_controller::recovery_authority::{
        BrokerTrustDraft, BrokerTrustState, PendingBrokerKey,
    };
    use blindpass_core::signing::base64_url_encode;
    let f = Fixture::new(252).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let active = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &active)
            .await
            .unwrap(),
    );
    let first = BrokerTrustDraft {
        node_id: "node_dummy_current_trust".into(),
        key_version: 1,
        signing_public: base64_url_encode(&[11; 32]),
        recipient_public: base64_url_encode(&[12; 32]),
        state: BrokerTrustState::Active,
        pending: None,
    };
    let initial = owner.publish_broker_trust(0, &first).await.unwrap();
    assert_eq!(initial.revision, 1);
    assert_eq!(initial.identity, first);
    assert_eq!(
        owner.broker_trust(&first.node_id).await.unwrap(),
        Some(initial.clone())
    );
    assert_eq!(
        owner.publish_broker_trust(0, &first).await.unwrap(),
        initial
    );
    let mut wrong = first.clone();
    wrong.signing_public = base64_url_encode(&[13; 32]);
    assert!(
        owner
            .publish_broker_trust(initial.revision, &wrong)
            .await
            .is_err()
    );
    assert_eq!(
        owner.broker_trust(&first.node_id).await.unwrap(),
        Some(initial.clone())
    );
    let mut staged = first.clone();
    staged.pending = Some(PendingBrokerKey {
        key_version: 2,
        rotation_id: "rotation_dummy_current_trust".into(),
        signing_public: base64_url_encode(&[14; 32]),
        recipient_public: base64_url_encode(&[15; 32]),
    });
    let pending = owner
        .publish_broker_trust(initial.revision, &staged)
        .await
        .unwrap();
    assert_eq!(pending.revision, 2);
    let mut conflicting_pending = staged.clone();
    conflicting_pending.pending.as_mut().unwrap().signing_public = base64_url_encode(&[16; 32]);
    assert!(
        owner
            .publish_broker_trust(pending.revision, &conflicting_pending)
            .await
            .is_err()
    );
    let candidate = staged.pending.unwrap();
    let rotated = BrokerTrustDraft {
        node_id: first.node_id.clone(),
        key_version: 2,
        signing_public: candidate.signing_public,
        recipient_public: candidate.recipient_public,
        state: BrokerTrustState::Active,
        pending: None,
    };
    let current = owner
        .publish_broker_trust(pending.revision, &rotated)
        .await
        .unwrap();
    assert_eq!(current.revision, 3);
    assert!(
        owner
            .publish_broker_trust(current.revision, &first)
            .await
            .is_err()
    );
    let mut revoked = rotated.clone();
    revoked.state = BrokerTrustState::Revoked;
    let tombstone = owner
        .publish_broker_trust(current.revision, &revoked)
        .await
        .unwrap();
    assert_eq!(tombstone.revision, 4);
    assert!(
        owner
            .publish_broker_trust(tombstone.revision, &rotated)
            .await
            .is_err()
    );
    assert!(
        sqlx::query(
            "UPDATE blindpass_authority.broker_trust SET state='active' WHERE tenant_id=$1"
        )
        .bind(&f.context.tenant_id)
        .execute(&f.runtime)
        .await
        .is_err()
    );
    owner.quiesce().await.unwrap();
    drop(owner);
    f.fence_fixture().await;
    let fenced = f.authority.read(&f.context).await.unwrap();
    let recovering = f
        .authority
        .reserve_recovery(&f.context, fenced.revision, active.epoch)
        .await
        .unwrap();
    let reader = Arc::new(
        f.authority
            .claim_process(&f.context, &recovering)
            .await
            .unwrap(),
    );
    assert_eq!(
        reader.broker_trust(&first.node_id).await.unwrap(),
        Some(tombstone.clone())
    );
    assert!(
        reader
            .publish_broker_trust(tombstone.revision, &rotated)
            .await
            .is_err()
    );
    assert_eq!(
        reader.broker_trust(&first.node_id).await.unwrap(),
        Some(tombstone)
    );
    reader.quiesce().await.unwrap();
    drop(reader);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_pt01_process_registration_requires_proof_from_the_held_connection() {
    let f = Fixture::new(251).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let active = f.authority.read(&f.context).await.unwrap();
    let named_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    let accepted: bool = sqlx::query_scalar(
        "SELECT blindpass_authority.register_active_process($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&f.context.tenant_id)
    .bind(&f.context.issuer_key_id)
    .bind(&f.context.owner_id)
    .bind(active.epoch as i64)
    .bind(active.revision as i64)
    .bind(named_pid)
    .bind(vec![251_u8; 32])
    .fetch_one(&f.runtime)
    .await
    .unwrap();
    assert!(
        !accepted,
        "a caller-named PID without held-connection proof registered an active attempt"
    );
    let attempts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blindpass_authority.active_process WHERE tenant_id=$1",
    )
    .bind(&f.context.tenant_id)
    .fetch_one(&f.runtime)
    .await
    .unwrap();
    assert_eq!(attempts, 0);
    // A role can acquire arbitrary advisory locks on its own socket. Those
    // cannot impersonate the tenant's exclusive authority connection.
    let mut unrelated = f.runtime.acquire().await.unwrap().detach();
    sqlx::query("BEGIN").execute(&mut unrelated).await.unwrap();
    let unrelated_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut unrelated)
        .await
        .unwrap();
    let dummy_token = vec![250_u8; 32];
    let digest = blindpass_core::custody::sha256(&dummy_token).unwrap();
    for offset in [0, 8] {
        let first = i32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap());
        let second = i32::from_be_bytes(digest[offset + 4..offset + 8].try_into().unwrap());
        sqlx::query("SELECT pg_advisory_xact_lock($1,$2)")
            .bind(first)
            .bind(second)
            .execute(&mut unrelated)
            .await
            .unwrap();
    }
    let accepted: bool = sqlx::query_scalar(
        "SELECT blindpass_authority.register_active_process($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&f.context.tenant_id)
    .bind(&f.context.issuer_key_id)
    .bind(&f.context.owner_id)
    .bind(active.epoch as i64)
    .bind(active.revision as i64)
    .bind(unrelated_pid)
    .bind(dummy_token)
    .fetch_one(&f.runtime)
    .await
    .unwrap();
    assert!(
        !accepted,
        "unrelated advisory locks impersonated the tenant authority connection"
    );
    drop(unrelated);
    let actual = f
        .authority
        .claim_process(&f.context, &active)
        .await
        .unwrap();
    actual.check().await.unwrap();
    actual.quiesce().await.unwrap();
    drop(actual);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op12_fencing_retains_guard_until_all_admitted_operations_end() {
    let f = Fixture::new(101).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active', revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    let first = owner.begin_operation().unwrap();
    let second = owner.begin_operation().unwrap();
    f.fence_fixture().await;
    assert!(owner.check().await.is_err());
    assert!(owner.begin_operation().is_err());
    let fenced = f.authority.read(&f.context).await.unwrap();
    assert!(
        f.authority
            .reserve_recovery(&f.context, fenced.revision, 101)
            .await
            .is_err()
    );
    let started = Instant::now();
    assert!(owner.quiesce().await.is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(first);
    assert!(
        f.authority
            .reserve_recovery(&f.context, fenced.revision, 101)
            .await
            .is_err()
    );
    drop(second);
    owner.quiesce().await.unwrap();
    assert!(owner.is_fenced());
    assert!(owner.begin_operation().is_err());
    let reserved = f
        .authority
        .reserve_recovery(&f.context, fenced.revision, 101)
        .await
        .unwrap();
    assert_eq!(reserved.epoch, 102);
    assert_eq!(reserved.phase, "recovering");
    drop(owner);
    f.close().await;
}

struct Fixture {
    admin: PgPool,
    runtime: PgPool,
    authority: Authority,
    context: AuthorityContext,
}

impl Fixture {
    async fn new(epoch: u64) -> Self {
        Self::with_context(epoch, None).await
    }

    async fn with_context(epoch: u64, context: Option<AuthorityContext>) -> Self {
        let admin_url =
            std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").expect("isolated administrator");
        let url = std::env::var("P06_TEST_AUTHORITY_URL").expect("isolated restricted runtime");
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&admin_url)
            .await
            .unwrap();
        let runtime = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let context = context.unwrap_or_else(|| AuthorityContext {
            tenant_id: format!(
                "P06_DUMMY_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),
            issuer_key_id: "P06_DUMMY_ISSUER".into(),
            owner_id: "P06_DUMMY_OWNER".into(),
        });
        sqlx::query("INSERT INTO blindpass_authority.recovery_authority (tenant_id, issuer_key_id, owner_id, epoch, revision, phase) VALUES ($1, $2, $3, $4, 1, 'fenced')")
            .bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id)
            .bind(epoch as i64).execute(&admin).await.unwrap();
        let authority = Authority::connect_existing(&url).await.unwrap();
        Self {
            admin,
            runtime,
            authority,
            context,
        }
    }

    async fn fence_fixture(&self) {
        // Test administrator transition only: this does not prove an issuer stopped.
        sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced', revision=revision+1 WHERE tenant_id=$1")
            .bind(&self.context.tenant_id).execute(&self.admin).await.unwrap();
    }

    async fn close(self) {
        self.authority.close().await;
        self.runtime.close().await;
        self.admin.close().await;
        // The wrapper removes the entire owned database/roles. Rows cannot be deleted.
    }
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_oa01_runtime_cannot_reset_protected_ledger_or_initialize_missing_identity() {
    let f = Fixture::new(7).await;
    let before = f.authority.read(&f.context).await.unwrap();
    for sql in [
        "UPDATE blindpass_authority.recovery_authority SET epoch=1",
        "DELETE FROM blindpass_authority.recovery_authority",
        "TRUNCATE blindpass_authority.recovery_authority",
        "ALTER TABLE blindpass_authority.recovery_authority ADD COLUMN dummy TEXT",
        "CREATE TABLE blindpass_authority.dummy (id INT)",
        "CREATE OR REPLACE FUNCTION blindpass_authority.reserve_recovery(TEXT,TEXT,TEXT,BIGINT,BIGINT) RETURNS TABLE(epoch BIGINT, revision BIGINT, phase TEXT) LANGUAGE SQL AS 'SELECT 1::BIGINT,1::BIGINT,''active''::TEXT'",
        "INSERT INTO blindpass_authority.recovery_authority VALUES ('dummy','dummy','dummy',1,1,'fenced')",
    ] {
        assert!(sqlx::query(sql).execute(&f.runtime).await.is_err());
    }
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    let invalid = AuthorityContext {
        owner_id: "P06 DUMMY INVALID".into(),
        ..f.context.clone()
    };
    assert_eq!(
        f.authority.read(&invalid).await.unwrap_err(),
        AuthorityError::InvalidInput
    );
    let missing = AuthorityContext {
        tenant_id: "P06_DUMMY_ABSENT".into(),
        ..f.context.clone()
    };
    assert!(f.authority.read(&missing).await.is_err());
    assert!(f.authority.reserve_recovery(&missing, 1, 1).await.is_err());
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    // Ordinary owner DML also cannot lower HWM, skip revisions, delete, or
    // change the issuer key. Independently administered superuser is trusted.
    for sql in [
        "UPDATE blindpass_authority.recovery_authority SET epoch=1, revision=revision+1 WHERE tenant_id=$1",
        "UPDATE blindpass_authority.recovery_authority SET revision=revision+2 WHERE tenant_id=$1",
        "UPDATE blindpass_authority.recovery_authority SET issuer_key_id='OTHER', revision=revision+1 WHERE tenant_id=$1",
        "DELETE FROM blindpass_authority.recovery_authority WHERE tenant_id=$1",
    ] {
        assert!(
            sqlx::query(sql)
                .bind(&f.context.tenant_id)
                .execute(&f.admin)
                .await
                .is_err()
        );
    }
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_oa01b_startup_refuses_missing_layout_controller_database_and_admin_credentials() {
    let f = Fixture::new(3).await;
    let admin_url = std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").unwrap();
    let url = std::env::var("P06_TEST_AUTHORITY_URL").unwrap();
    assert!(Authority::connect_existing(&admin_url).await.is_err());
    sqlx::query(
        "ALTER TABLE blindpass_authority.authority_layout RENAME TO authority_layout_absent",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    let refused = Authority::connect_existing(&url).await.is_err();
    let recreated: bool = sqlx::query_scalar(
        "SELECT to_regclass('blindpass_authority.authority_layout') IS NOT NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE blindpass_authority.authority_layout_absent RENAME TO authority_layout",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    assert!(refused && !recreated);
    sqlx::query("CREATE TABLE public.controller_meta (id BIGINT)")
        .execute(&f.admin)
        .await
        .unwrap();
    let refused = Authority::connect_existing(&url).await.is_err();
    sqlx::query("DROP TABLE public.controller_meta")
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(refused);
    let current = Authority::connect_existing(&url).await.unwrap();
    assert_eq!(current.read(&f.context).await.unwrap().epoch, 3);
    current.close().await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_oa01c_noninherited_administrator_membership_is_not_a_runtime_credential() {
    let url = std::env::var("P06_TEST_AUTHORITY_MEMBER_URL").expect("isolated member role");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let (member, can_create): (bool, bool) = sqlx::query_as(
        "SELECT pg_has_role(current_user, nspowner, 'MEMBER'), has_schema_privilege(current_user, nspname, 'CREATE') FROM pg_namespace WHERE nspname='blindpass_authority'",
    ).fetch_one(&pool).await.unwrap();
    assert!(
        member && !can_create,
        "NOINHERIT fixture must hide ordinary owner privileges"
    );
    let owner: String = sqlx::query_scalar(
        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='blindpass_authority'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        owner.starts_with("p06_authority_")
            && owner
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    sqlx::query(&format!("SET ROLE {owner}"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT has_schema_privilege(current_user, 'blindpass_authority', 'CREATE')"
        )
        .fetch_one(&pool)
        .await
        .unwrap()
    );
    sqlx::query("RESET ROLE").execute(&pool).await.unwrap();
    pool.close().await;
    assert!(
        Authority::connect_existing(&url).await.is_err(),
        "SET ROLE capability must refuse"
    );
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_oa02_committed_reservations_outlive_stale_snapshots_and_interrupted_recovery() {
    let f = Fixture::new(21).await;
    for (observed, expected) in [(2, 22), (3, 23), (40, 41), (1, 42)] {
        let state = f.authority.read(&f.context).await.unwrap();
        let reserved = f
            .authority
            .reserve_recovery(&f.context, state.revision, observed)
            .await
            .unwrap();
        assert_eq!(reserved.epoch, expected);
        assert_eq!(reserved.revision, state.revision + 1);
        assert_eq!(reserved.phase, "recovering");
        assert!(
            f.authority
                .reserve_recovery(&f.context, reserved.revision, observed)
                .await
                .is_err()
        );
        assert_eq!(f.authority.read(&f.context).await.unwrap(), reserved);
        f.fence_fixture().await;
    }
    assert_eq!(f.authority.read(&f.context).await.unwrap().epoch, 42);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_oa03_concurrent_revision_reservations_and_wrong_context_fail_closed() {
    let f = Fixture::new(5).await;
    let before = f.authority.read(&f.context).await.unwrap();
    for context in [
        AuthorityContext {
            owner_id: "P06_DUMMY_OTHER_OWNER".into(),
            ..f.context.clone()
        },
        AuthorityContext {
            issuer_key_id: "P06_DUMMY_OTHER_KEY".into(),
            ..f.context.clone()
        },
    ] {
        assert!(f.authority.read(&context).await.is_err());
        assert!(f.authority.reserve_recovery(&context, 1, 5).await.is_err());
    }
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    let (a, b) = tokio::join!(
        f.authority.reserve_recovery(&f.context, 1, 5),
        f.authority.reserve_recovery(&f.context, 1, 5)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let final_state = f.authority.read(&f.context).await.unwrap();
    assert_eq!((final_state.epoch, final_state.revision), (6, 2));
    // This is a database-state fixture, not activation of a real controller.
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active', revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let active = f.authority.read(&f.context).await.unwrap();
    assert!(
        f.authority
            .reserve_recovery(&f.context, active.revision, active.epoch)
            .await
            .is_err()
    );
    assert_eq!(f.authority.read(&f.context).await.unwrap(), active);
    f.close().await;
}

#[tokio::test]
async fn p06_oa08_invalid_urls_have_fixed_diagnostics_before_connection() {
    for url in [
        "sqlite::memory:",
        "postgres://DUMMY:DUMMY@127.0.0.1:1/DUMMY?P06_OPTION_CANARY=P06_VALUE_CANARY",
        "postgres://DUMMY:DUMMY@127.0.0.1:1/DUMMY?%GG=x",
    ] {
        let error = Authority::connect_existing(url)
            .await
            .err()
            .expect("static refusal");
        assert_eq!(error, AuthorityError::InvalidInput);
        let diagnostic = format!("{error:?} {error}");
        for canary in ["DUMMY", "CANARY", "postgres://", "sqlite:"] {
            assert!(!diagnostic.contains(canary));
        }
    }
}

#[tokio::test]
async fn p06_oa10_remote_authority_requires_verified_transport_before_connection() {
    // Non-loopback hosts must verify the server; sqlx would otherwise prefer
    // TLS but silently fall back to plaintext. Refusal precedes any network.
    for url in [
        "postgres://DUMMY:DUMMY@db.authority.invalid:5432/DUMMY",
        "postgres://DUMMY:DUMMY@db.authority.invalid:5432/DUMMY?sslmode=prefer",
        "postgres://DUMMY:DUMMY@db.authority.invalid:5432/DUMMY?sslmode=require",
        "postgres://DUMMY:DUMMY@10.255.255.1:5432/DUMMY?sslmode=disable",
    ] {
        let start = Instant::now();
        let error = Authority::connect_existing(url)
            .await
            .err()
            .expect("static refusal");
        assert_eq!(error, AuthorityError::InvalidInput, "{url}");
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "contacted the network"
        );
        assert!(!format!("{error:?} {error}").contains("DUMMY"));
    }
    // Verified remote modes and local transports are not refused statically
    // (these then fail as unavailable because nothing listens).
    for url in [
        "postgres://DUMMY:DUMMY@db.authority.invalid:5432/DUMMY?sslmode=verify-full",
        "postgres://DUMMY:DUMMY@db.authority.invalid:5432/DUMMY?sslmode=verify-ca",
        "postgres://DUMMY:DUMMY@127.0.0.1:1/DUMMY",
        "postgres://DUMMY:DUMMY@localhost:1/DUMMY?sslmode=disable",
    ] {
        let error = Authority::connect_existing(url)
            .await
            .err()
            .expect("nothing listens");
        assert_eq!(error, AuthorityError::Unavailable, "{url}");
    }
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_oa09_safe_integer_exhaustion_refuses_without_mutating_ledger() {
    let f = Fixture::new(MAX).await;
    let before = f.authority.read(&f.context).await.unwrap();
    for (revision, observed) in [(0, 1), (MAX + 1, 1), (1, 0), (1, MAX + 1), (1, MAX)] {
        assert!(
            f.authority
                .reserve_recovery(&f.context, revision, observed)
                .await
                .is_err()
        );
        assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op01_exactly_one_connection_holds_each_tenant_guard() {
    let f = Fixture::new(11).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let url = std::env::var("P06_TEST_AUTHORITY_URL").unwrap();
    let second = Authority::connect_existing(&url).await.unwrap();
    let (a, b) = tokio::join!(
        f.authority.claim_process(&f.context, &before),
        second.claim_process(&f.context, &before)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let holder = a.or(b).ok().unwrap();
    holder.check().await.unwrap();
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    let other = Fixture::new(3).await;
    let other_record = other.authority.read(&other.context).await.unwrap();
    let independent = other
        .authority
        .claim_process(&other.context, &other_record)
        .await
        .unwrap();
    independent.check().await.unwrap();
    holder.check().await.unwrap();
    drop(independent);
    other.close().await;
    drop(holder);
    second.close().await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op02_mismatching_context_record_and_missing_identity_do_not_leak_a_guard() {
    let f = Fixture::new(12).await;
    let before = f.authority.read(&f.context).await.unwrap();
    for bad in [
        AuthorityContext {
            owner_id: "OTHER".into(),
            ..f.context.clone()
        },
        AuthorityContext {
            issuer_key_id: "OTHER".into(),
            ..f.context.clone()
        },
        AuthorityContext {
            tenant_id: "ABSENT".into(),
            ..f.context.clone()
        },
        AuthorityContext {
            owner_id: "INVALID SPACE".into(),
            ..f.context.clone()
        },
    ] {
        assert!(f.authority.claim_process(&bad, &before).await.is_err());
    }
    for bad in [
        AuthorityRecord {
            epoch: 13,
            ..before.clone()
        },
        AuthorityRecord {
            revision: 2,
            ..before.clone()
        },
        AuthorityRecord {
            phase: "active".into(),
            ..before.clone()
        },
        AuthorityRecord {
            epoch: 0,
            ..before.clone()
        },
        AuthorityRecord {
            epoch: MAX + 1,
            ..before.clone()
        },
        AuthorityRecord {
            phase: "UNKNOWN".into(),
            ..before.clone()
        },
    ] {
        assert!(f.authority.claim_process(&f.context, &bad).await.is_err());
    }
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    let holder = f
        .authority
        .claim_process(&f.context, &before)
        .await
        .unwrap();
    holder.check().await.unwrap();
    drop(holder);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op03_guard_cannot_be_reset_and_unsupported_layout_is_not_repaired() {
    let f = Fixture::new(12).await;
    for pool in [&f.runtime, &f.admin] {
        for sql in [
            "DELETE FROM blindpass_authority.process_guard WHERE tenant_id=$1",
            "UPDATE blindpass_authority.process_guard SET tenant_id='OTHER' WHERE tenant_id=$1",
        ] {
            assert!(
                sqlx::query(sql)
                    .bind(&f.context.tenant_id)
                    .execute(pool)
                    .await
                    .is_err()
            );
        }
        assert!(
            sqlx::query("TRUNCATE blindpass_authority.process_guard")
                .execute(pool)
                .await
                .is_err()
        );
    }
    assert!(
        sqlx::query("INSERT INTO blindpass_authority.process_guard VALUES ('OTHER')")
            .execute(&f.runtime)
            .await
            .is_err()
    );
    let url = std::env::var("P06_TEST_AUTHORITY_URL").unwrap();
    sqlx::query("ALTER TABLE blindpass_authority.authority_layout DROP CONSTRAINT authority_layout_version_check").execute(&f.admin).await.unwrap();
    for unsupported in [1_i64, 2, 3, 4, 6] {
        sqlx::query("UPDATE blindpass_authority.authority_layout SET version=$1")
            .bind(unsupported)
            .execute(&f.admin)
            .await
            .unwrap();
        assert!(Authority::connect_existing(&url).await.is_err());
        let version: i64 =
            sqlx::query_scalar("SELECT version FROM blindpass_authority.authority_layout")
                .fetch_one(&f.admin)
                .await
                .unwrap();
        assert_eq!(
            version, unsupported,
            "startup must never repair an unsupported layout"
        );
    }
    sqlx::query("UPDATE blindpass_authority.authority_layout SET version=5")
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE blindpass_authority.authority_layout ADD CONSTRAINT authority_layout_version_check CHECK (version=5)").execute(&f.admin).await.unwrap();
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
    sqlx::query(&format!("REVOKE EXECUTE ON FUNCTION blindpass_authority.claim_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,BYTEA) FROM {role}")).execute(&f.admin).await.unwrap();
    let missing_grant_refused = Authority::connect_existing(&url).await.is_err();
    sqlx::query(&format!("GRANT EXECUTE ON FUNCTION blindpass_authority.claim_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,BYTEA) TO {role}")).execute(&f.admin).await.unwrap();
    assert!(missing_grant_refused);
    sqlx::query(&format!(
        "GRANT UPDATE(tenant_id) ON blindpass_authority.process_guard TO {role}"
    ))
    .execute(&f.admin)
    .await
    .unwrap();
    let guard_write_refused = Authority::connect_existing(&url).await.is_err();
    sqlx::query(&format!(
        "REVOKE UPDATE(tenant_id) ON blindpass_authority.process_guard FROM {role}"
    ))
    .execute(&f.admin)
    .await
    .unwrap();
    assert!(guard_write_refused);
    let current = Authority::connect_existing(&url).await.unwrap();
    current.close().await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op04_reservation_and_transfer_refuse_until_holder_is_externally_fenced() {
    let f = Fixture::new(22).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let holder = f
        .authority
        .claim_process(&f.context, &before)
        .await
        .unwrap();
    assert!(
        f.authority
            .reserve_recovery(&f.context, before.revision, 22)
            .await
            .is_err()
    );
    assert!(sqlx::query("UPDATE blindpass_authority.recovery_authority SET owner_id='OTHER', revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.is_err());
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    f.fence_fixture().await;
    assert!(holder.check().await.is_err());
    assert!(holder.is_fenced());
    let current = f.authority.read(&f.context).await.unwrap();
    assert_eq!(
        (current.epoch, current.revision, current.phase.as_str()),
        (22, 2, "fenced")
    );
    assert!(holder.check().await.is_err());
    let fresh = f
        .authority
        .claim_process(&f.context, &current)
        .await
        .unwrap();
    fresh.check().await.unwrap();
    assert!(holder.is_fenced());
    drop(fresh);
    drop(holder);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op05_exact_backend_loss_latches_holder_without_reconnect_or_hwm_rollback() {
    let f = Fixture::new(35).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let holder = f
        .authority
        .claim_process(&f.context, &before)
        .await
        .unwrap();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(holder.backend_pid())
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    assert!(terminated);
    assert!(holder.check().await.is_err());
    assert!(holder.is_fenced());
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    let fresh = f
        .authority
        .claim_process(&f.context, &before)
        .await
        .unwrap();
    fresh.check().await.unwrap();
    assert!(holder.check().await.is_err());
    drop(fresh);
    drop(holder);
    f.close().await;
}

struct FaultProxy {
    port: u16,
    pause: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl FaultProxy {
    async fn start() -> Self {
        let target_port: u16 = std::env::var("P06_TEST_AUTHORITY_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (pause, receiver) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut client, _) = accepted.unwrap();
                        let mut receiver = receiver.clone();
                        clients.spawn(async move {
                            let mut server = tokio::net::TcpStream::connect(("127.0.0.1",target_port)).await.unwrap();
                            loop {
                                while *receiver.borrow() {
                                    if receiver.changed().await.is_err() { return; }
                                }
                                tokio::select! {
                                    biased;
                                    changed = receiver.changed() => if changed.is_err() { return; },
                                    _ = tokio::io::copy_bidirectional(&mut client,&mut server) => return,
                                }
                            }
                        });
                    }
                    _ = clients.join_next(), if !clients.is_empty() => {},
                }
            }
        });
        Self { port, pause, task }
    }
    fn url(&self) -> String {
        // Only the disposable fixture's private URL; never format it in assertions.
        let url = std::env::var("P06_TEST_AUTHORITY_URL").unwrap();
        let (prefix, suffix) = url.rsplit_once(':').unwrap();
        let (_, database) = suffix.split_once('/').unwrap();
        format!("{prefix}:{}/{database}", self.port)
    }
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op06_owned_network_blackhole_has_bounded_permanent_fence() {
    let f = Fixture::new(41).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let proxy = FaultProxy::start().await;
    let authority = Authority::connect_existing(&proxy.url()).await.unwrap();
    let holder = authority.claim_process(&f.context, &before).await.unwrap();
    holder.check().await.unwrap();
    proxy.pause.send(true).unwrap();
    let start = Instant::now();
    assert_eq!(
        holder.check().await.unwrap_err(),
        AuthorityError::Unavailable
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(holder.is_fenced());
    proxy.pause.send(false).unwrap();
    assert_eq!(authority.read(&f.context).await.unwrap(), before);
    assert!(holder.check().await.is_err());
    // Deadline cancellation closes its socket: the old transaction releases.
    let fresh = f
        .authority
        .claim_process(&f.context, &before)
        .await
        .unwrap();
    fresh.check().await.unwrap();
    drop(fresh);
    drop(holder);
    authority.close().await;
    drop(proxy);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op07_drop_releases_socket_guard_without_changing_durable_metadata() {
    let f = Fixture::new(50).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let holder = f
        .authority
        .claim_process(&f.context, &before)
        .await
        .unwrap();
    drop(holder);
    let holder = f
        .authority
        .claim_process(&f.context, &before)
        .await
        .unwrap();
    holder.check().await.unwrap();
    drop(holder);
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    let reserved = f
        .authority
        .reserve_recovery(&f.context, before.revision, 50)
        .await
        .unwrap();
    assert_eq!(
        (reserved.epoch, reserved.revision, reserved.phase.as_str()),
        (51, 2, "recovering")
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op08_idle_monitor_detects_loss_and_stops_without_reclaiming() {
    let f = Fixture::new(55).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let holder = Arc::new(
        f.authority
            .claim_process(&f.context, &before)
            .await
            .unwrap(),
    );
    let task = holder.spawn_monitor();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(holder.backend_pid())
        .fetch_one(&f.runtime)
        .await
        .unwrap();
    assert!(terminated);
    tokio::time::timeout(Duration::from_secs(5), holder.wait_fenced())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert!(holder.is_fenced());
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    drop(holder);
    f.close().await;
}

struct HttpServer {
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for HttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl HttpServer {
    async fn start(app: axum::Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self { address, task }
    }
}

fn http_config(directory: &support::TestDirectory) -> blindpass_controller::config::Config {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut fields = vec![
        ("BLINDPASS_TEST_MODE".to_owned(), "1".to_owned()),
        (
            "BLINDPASS_CORS_ALLOWED_ORIGINS".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
        ),
        (
            "BLINDPASS_DATABASE_URL".to_owned(),
            "sqlite::memory:".to_owned(),
        ),
        (
            "BLINDPASS_PUBLIC_URL".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
        ),
        (
            "BLINDPASS_UI_BASE_URL".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
        ),
    ];
    for (field, name, byte) in [
        ("BLINDPASS_ROOT_SECRET_FILE", "root", b'R'),
        ("BLINDPASS_AGENT_JWT_SECRET_FILE", "agent", b'A'),
        ("BLINDPASS_ISSUER_KEY_FILE", "issuer", b'I'),
    ] {
        let file = directory.file(name);
        std::fs::write(&file, [byte; 32]).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        fields.push((field.to_owned(), file.to_str().unwrap().to_owned()));
    }
    blindpass_controller::config::Config::from_variables(fields).unwrap()
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op09a_real_router_protects_all_methods_api_ui_and_fallback_during_fence() {
    let directory = support::TestDirectory::new();
    let config = http_config(&directory);
    let url = format!("sqlite://{}", directory.file("router.db").display());
    let store = blindpass_controller::store::Store::connect(&url)
        .await
        .unwrap();
    let f = Fixture::with_context(1, Some(controller_context(&store, &config))).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let candidate = Arc::new(
        f.authority
            .claim_process(&f.context, &before)
            .await
            .unwrap(),
    );
    let server = HttpServer::start(blindpass_controller::app::build_app_with_ownership(
        http_config(&directory),
        Some(store.clone()),
        candidate.clone(),
    ))
    .await;
    assert!(!candidate.is_active());
    assert_eq!(
        support::raw_request(server.address, "GET", "/healthz", &[], None)
            .await
            .status,
        200
    );
    let ready = support::raw_request(server.address, "GET", "/readyz", &[], None).await;
    assert_eq!(ready.status, 503);
    assert_eq!(ready.body["checks"]["database"], "up");
    assert_eq!(ready.body["checks"]["authority"], "fenced");
    assert_eq!(
        support::raw_request(server.address, "GET", "/api/v3/capabilities", &[], None)
            .await
            .status,
        503
    );
    assert!(
        !candidate.is_fenced(),
        "a held recovering/fenced candidate is not activated"
    );
    drop(server);
    candidate.quiesce().await.unwrap();
    drop(candidate);
    store.close().await;
    drop(store);
    let store = blindpass_controller::store::Store::connect_existing(&url, 1000)
        .await
        .unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    // Explicit administrator state fixture, not a restore/unfence protocol.
    let active_record = f.authority.read(&f.context).await.unwrap();
    let holder = Arc::new(
        f.authority
            .claim_process(&f.context, &active_record)
            .await
            .unwrap(),
    );
    let server = HttpServer::start(blindpass_controller::app::build_app_with_ownership(
        http_config(&directory),
        Some(store.clone()),
        holder.clone(),
    ))
    .await;
    assert_eq!(
        support::raw_request(server.address, "GET", "/readyz", &[], None)
            .await
            .status,
        200
    );
    assert_eq!(
        support::raw_request(server.address, "GET", "/api/v3/capabilities", &[], None)
            .await
            .status,
        200
    );
    let preflight_headers = [
        ("Origin", "http://127.0.0.1:8080"),
        ("Access-Control-Request-Method", "GET"),
    ];
    assert_eq!(
        support::raw_request(
            server.address,
            "OPTIONS",
            "/api/v3/capabilities",
            &preflight_headers,
            None
        )
        .await
        .status,
        204
    );
    let monitor = holder.spawn_monitor();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
            .bind(holder.backend_pid())
            .fetch_one(&f.runtime)
            .await
            .unwrap()
    );
    tokio::time::timeout(Duration::from_secs(5), holder.wait_fenced())
        .await
        .unwrap();
    monitor.await.unwrap();
    for method in [
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
    ] {
        for path in [
            "/api/v3/capabilities",
            "/api/v2/agents/token",
            "/api/v2/secret/request",
            "/api/v2/secret/retrieve/DUMMY",
            "/api/v2/secret/exchange/request",
            "/api/v3/admin/bootstrap",
            "/api/v3/admin/session/login",
            "/api/v3/admin/session",
            "/api/v3/node/poll",
            "/api/v3/fleet/provisioning/DUMMY/submit",
            "/api/v3/grants/DUMMY",
            "/api/v3/policies",
            "/api/v3/approvals/count",
            "/input/",
            "/assets/DUMMY.js",
            "/not-found",
            "/healthz/",
            "/%68ealthz",
        ] {
            let response = support::raw_request(server.address, method, path, &[], None).await;
            assert_eq!(response.status, 503, "{method} {path}");
            assert!(
                response
                    .headers
                    .iter()
                    .any(|(name, value)| name == "cache-control" && value == "no-store")
            );
        }
    }
    assert_eq!(
        support::raw_request(
            server.address,
            "OPTIONS",
            "/api/v3/capabilities",
            &preflight_headers,
            None
        )
        .await
        .status,
        503
    );
    println!(
        "P06-OP09a protected_requests=144 preflight_before=204 preflight_after=503 local_identity_bound=true"
    );
    let ready = support::raw_request(server.address, "GET", "/readyz", &[], None).await;
    assert_eq!(ready.status, 503);
    assert_eq!(ready.body["checks"]["database"], "up");
    assert_eq!(ready.body["checks"]["authority"], "down");
    assert_eq!(
        support::raw_request(server.address, "GET", "/healthz", &[], None)
            .await
            .status,
        200
    );
    assert_eq!(f.authority.read(&f.context).await.unwrap(), active_record);
    assert!(holder.is_fenced());
    drop(server);
    drop(holder);
    store.close().await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op09b_authority_loss_cancels_a_pending_handler_before_delivery() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let f = Fixture::new(65).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let current = f.authority.read(&f.context).await.unwrap();
    let holder = Arc::new(
        f.authority
            .claim_process(&f.context, &current)
            .await
            .unwrap(),
    );
    let entered = Arc::new(tokio::sync::Notify::new());
    let cancelled = Arc::new(AtomicBool::new(false));
    struct Pending(Arc<AtomicBool>);
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let app = axum::Router::new()
        .route(
            "/pending",
            axum::routing::get({
                let entered = entered.clone();
                let cancelled = cancelled.clone();
                move || {
                    let entered = entered.clone();
                    let cancelled = cancelled.clone();
                    async move {
                        let _guard = Pending(cancelled);
                        entered.notify_one();
                        std::future::pending::<()>().await;
                        "P06_MUST_NOT_DELIVER"
                    }
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            holder.clone(),
            blindpass_controller::recovery_authority::ownership_gate,
        ));
    let server = HttpServer::start(app).await;
    let address = server.address;
    let request =
        tokio::spawn(
            async move { support::raw_request(address, "GET", "/pending", &[], None).await },
        );
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let monitor = holder.spawn_monitor();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
            .bind(holder.backend_pid())
            .fetch_one(&f.runtime)
            .await
            .unwrap()
    );
    let response = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 503);
    assert!(!response.body.to_string().contains("P06_MUST_NOT_DELIVER"));
    assert!(cancelled.load(Ordering::Acquire));
    monitor.await.unwrap();
    assert_eq!(f.authority.read(&f.context).await.unwrap(), current);
    drop(server);
    drop(holder);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op06b_connect_read_and_reserve_are_bounded_under_owned_network_fault() {
    let f = Fixture::new(71).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let proxy = FaultProxy::start().await;
    proxy.pause.send(true).unwrap();
    let start = Instant::now();
    assert!(Authority::connect_existing(&proxy.url()).await.is_err());
    assert!(start.elapsed() < Duration::from_secs(5));
    println!(
        "P06-OP06b connect_ms={} bounded=true",
        start.elapsed().as_millis()
    );
    proxy.pause.send(false).unwrap();
    let authority = Authority::connect_existing(&proxy.url()).await.unwrap();
    assert_eq!(authority.read(&f.context).await.unwrap(), before);
    proxy.pause.send(true).unwrap();
    let start = Instant::now();
    assert_eq!(
        authority.read(&f.context).await.unwrap_err(),
        AuthorityError::Unavailable
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    println!(
        "P06-OP06b read_ms={} bounded=true",
        start.elapsed().as_millis()
    );
    let wrong_context = AuthorityContext {
        owner_id: "OTHER".into(),
        ..f.context.clone()
    };
    let start = Instant::now();
    assert_eq!(
        authority
            .reserve_recovery(&wrong_context, before.revision, 71)
            .await
            .unwrap_err(),
        AuthorityError::Unavailable
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    println!(
        "P06-OP06b reserve_ms={} bounded=true",
        start.elapsed().as_millis()
    );
    // Wrong owner prevents any late/ambiguous server-side reservation. This
    // case verifies deadlines, not an interrupted successful commit protocol.
    proxy.pause.send(false).unwrap();
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    assert_eq!(authority.read(&f.context).await.unwrap(), before);
    authority.close().await;
    drop(proxy);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op06c_cancelled_check_closes_guard_and_never_reclaims() {
    let f = Fixture::new(72).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let proxy = FaultProxy::start().await;
    let authority = Authority::connect_existing(&proxy.url()).await.unwrap();
    let holder = Arc::new(authority.claim_process(&f.context, &before).await.unwrap());
    holder.check().await.unwrap();
    proxy.pause.send(true).unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let check = tokio::spawn({
        let holder = holder.clone();
        let entered = entered.clone();
        async move {
            entered.notify_one();
            holder.check().await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    assert!(!check.is_finished());
    check.abort();
    assert!(check.await.unwrap_err().is_cancelled());
    assert!(holder.is_fenced());
    proxy.pause.send(false).unwrap();
    assert_eq!(f.authority.read(&f.context).await.unwrap(), before);
    assert!(holder.check().await.is_err());
    let fresh = f
        .authority
        .claim_process(&f.context, &before)
        .await
        .unwrap();
    fresh.check().await.unwrap();
    drop(fresh);
    drop(holder);
    authority.close().await;
    drop(proxy);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op06d_dropped_request_does_not_cancel_a_detached_gate_check() {
    // An unauthenticated client disconnect drops its handler future. The gate
    // check must finish on its own task so that is not a loss of proof.
    let f = Fixture::new(73).await;
    let before = f.authority.read(&f.context).await.unwrap();
    let proxy = FaultProxy::start().await;
    let authority = Authority::connect_existing(&proxy.url()).await.unwrap();
    let holder = Arc::new(authority.claim_process(&f.context, &before).await.unwrap());
    holder.check().await.unwrap();
    proxy.pause.send(true).unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let request = tokio::spawn({
        let holder = holder.clone();
        let entered = entered.clone();
        async move {
            entered.notify_one();
            holder.check_detached().await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    assert!(!request.is_finished());
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    proxy.pause.send(false).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!holder.is_fenced());
    holder.check().await.unwrap();
    drop(holder);
    authority.close().await;
    drop(proxy);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op10_active_revision_is_one_use_even_after_connection_loss() {
    let f = Fixture::new(81).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let active = f.authority.read(&f.context).await.unwrap();
    let holder = f
        .authority
        .claim_process(&f.context, &active)
        .await
        .unwrap();
    holder.check().await.unwrap();
    assert!(holder.is_active());
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
            .bind(holder.backend_pid())
            .fetch_one(&f.runtime)
            .await
            .unwrap()
    );
    assert!(holder.check().await.is_err());
    assert!(holder.is_fenced());
    assert!(
        f.authority
            .claim_process(&f.context, &active)
            .await
            .is_err(),
        "same active revision cannot be reclaimed after disconnect"
    );
    assert_eq!(f.authority.read(&f.context).await.unwrap(), active);
    for pool in [&f.runtime, &f.admin] {
        assert!(
            sqlx::query("DELETE FROM blindpass_authority.active_process WHERE tenant_id=$1")
                .bind(&f.context.tenant_id)
                .execute(pool)
                .await
                .is_err()
        );
        assert!(
            sqlx::query(
                "UPDATE blindpass_authority.active_process SET backend_pid=1 WHERE tenant_id=$1"
            )
            .bind(&f.context.tenant_id)
            .execute(pool)
            .await
            .is_err()
        );
        assert!(
            sqlx::query("TRUNCATE blindpass_authority.active_process")
                .execute(pool)
                .await
                .is_err()
        );
    }
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM blindpass_authority.active_process WHERE tenant_id=$1 AND epoch=$2 AND revision=$3")
        .bind(&f.context.tenant_id).bind(active.epoch as i64).bind(active.revision as i64).fetch_one(&f.runtime).await.unwrap();
    assert_eq!(attempts, 1);
    f.fence_fixture().await;
    let fenced = f.authority.read(&f.context).await.unwrap();
    let reservation = f
        .authority
        .reserve_recovery(&f.context, fenced.revision, active.epoch)
        .await
        .unwrap();
    assert_eq!(reservation.epoch, active.epoch + 1);
    let recovery_candidate = f
        .authority
        .claim_process(&f.context, &reservation)
        .await
        .unwrap();
    assert!(!recovery_candidate.is_active());
    recovery_candidate.check().await.unwrap();
    drop(recovery_candidate);
    drop(holder);
    f.close().await;
}

fn controller_context(
    store: &blindpass_controller::store::Store,
    config: &blindpass_controller::config::Config,
) -> AuthorityContext {
    AuthorityContext {
        tenant_id: store.tenant_id().to_owned(),
        issuer_key_id: format!(
            "ed25519-{}",
            blindpass_core::signing::base64_url_encode(
                config.issuer_keypair().unwrap().public_key()
            )
        ),
        owner_id: "P06_DUMMY_OWNER".into(),
    }
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op11a_router_refuses_wrong_tenant_issuer_or_missing_local_store() {
    for mismatch in ["tenant", "issuer", "store"] {
        let directory = support::TestDirectory::new();
        let config = http_config(&directory);
        let store = blindpass_controller::store::Store::connect("sqlite::memory:")
            .await
            .unwrap();
        let mut context = controller_context(&store, &config);
        match mismatch {
            "tenant" => context.tenant_id.push_str("_OTHER"),
            "issuer" => context.issuer_key_id = "OTHER".into(),
            _ => {}
        }
        let f = Fixture::with_context(1, Some(context)).await;
        let current = f.authority.read(&f.context).await.unwrap();
        let holder = Arc::new(
            f.authority
                .claim_process(&f.context, &current)
                .await
                .unwrap(),
        );
        let local = if mismatch == "store" {
            None
        } else {
            Some(store.clone())
        };
        let app =
            blindpass_controller::app::build_app_with_ownership(config, local, holder.clone());
        assert!(
            holder.is_fenced(),
            "controller {mismatch} mismatch must latch fenced"
        );
        let server = HttpServer::start(app).await;
        assert_eq!(
            support::raw_request(server.address, "GET", "/healthz", &[], None)
                .await
                .status,
            200
        );
        assert_eq!(
            support::raw_request(server.address, "GET", "/readyz", &[], None)
                .await
                .status,
            503
        );
        assert_eq!(
            support::raw_request(server.address, "GET", "/api/v3/capabilities", &[], None)
                .await
                .status,
            503
        );
        drop(server);
        drop(holder);
        store.close().await;
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op11b_stale_or_future_local_epoch_cannot_serve_under_active_external_record() {
    for (external_epoch, local_epoch, close_store) in [(5, 1, false), (1, 2, false), (1, 1, true)] {
        let directory = support::TestDirectory::new();
        let config = http_config(&directory);
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.file("controller.db").display()
        );
        let store = blindpass_controller::store::Store::connect(&url)
            .await
            .unwrap();
        let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
        sqlx::query("UPDATE controller_meta SET issuer_epoch=? WHERE id=1")
            .bind(local_epoch)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let f =
            Fixture::with_context(external_epoch, Some(controller_context(&store, &config))).await;
        sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
            .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
        let active = f.authority.read(&f.context).await.unwrap();
        let holder = Arc::new(
            f.authority
                .claim_process(&f.context, &active)
                .await
                .unwrap(),
        );
        if close_store {
            store.close().await;
        }
        let server = HttpServer::start(blindpass_controller::app::build_app_with_ownership(
            config,
            Some(store.clone()),
            holder.clone(),
        ))
        .await;
        assert_eq!(
            support::raw_request(server.address, "GET", "/api/v3/capabilities", &[], None)
                .await
                .status,
            503
        );
        assert!(holder.is_fenced());
        assert_eq!(
            support::raw_request(server.address, "GET", "/readyz", &[], None)
                .await
                .status,
            503
        );
        assert_eq!(
            support::raw_request(server.address, "GET", "/healthz", &[], None)
                .await
                .status,
            200
        );
        if close_store {
            assert!(store.issuer_epoch().await.is_err());
        } else {
            assert_eq!(store.issuer_epoch().await.unwrap(), local_epoch as u64);
        }
        assert_eq!(f.authority.read(&f.context).await.unwrap(), active);
        drop(server);
        drop(holder);
        store.close().await;
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op13a_existing_store_clones_and_signer_share_irreversible_binding() {
    use blindpass_controller::store::{FleetSigner, Store};
    use blindpass_core::fleet::{DocumentKind, TimeReply};
    fn reply(epoch: u64) -> blindpass_core::canon::Value {
        TimeReply {
            node_id: "P06_DUMMY_NODE".into(),
            challenge: blindpass_core::signing::base64_url_encode(&[9; 32]),
            challenge_received_at_ms: 1000,
            controller_time_ms: 1000,
            issuer_epoch: epoch,
        }
        .to_value()
        .unwrap()
    }
    let directory = support::TestDirectory::new();
    let config = http_config(&directory);
    let store = Store::connect("sqlite::memory:")
        .await
        .unwrap()
        .with_fleet_signer(FleetSigner::new(config.issuer_keypair().unwrap().clone()));
    let old_clone = store.clone();
    let f = Fixture::with_context(1, Some(controller_context(&store, &config))).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active', revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    store
        .bind_ownership(owner.clone(), &f.context.issuer_key_id)
        .unwrap();
    old_clone
        .bind_ownership(owner.clone(), &f.context.issuer_key_id)
        .unwrap();
    assert!(old_clone.database_now_ms().await.is_ok());
    assert!(
        old_clone
            .sign_node_document(DocumentKind::TimeReply, reply(1), 1)
            .await
            .is_ok()
    );
    assert!(
        old_clone
            .sign_node_document(DocumentKind::TimeReply, reply(2), 2)
            .await
            .is_err()
    );
    owner.fence();
    assert_eq!(
        old_clone.database_now_ms().await.unwrap_err().to_string(),
        "controller ownership is fenced"
    );
    assert!(
        old_clone
            .create_agent_with_id("P06_DUMMY_AGENT", "dummy", "dummy", None, "hash")
            .await
            .is_err()
    );
    assert!(old_clone.sweep_expired(60).await.is_err());
    assert!(old_clone.monitor_clock().await.is_err());
    assert!(
        old_clone
            .sign_node_document(DocumentKind::TimeReply, reply(1), 1)
            .await
            .is_err()
    );
    f.fence_fixture().await;
    let fenced = f.authority.read(&f.context).await.unwrap();
    let other = Arc::new(
        f.authority
            .claim_process(&f.context, &fenced)
            .await
            .unwrap(),
    );
    assert!(
        old_clone
            .bind_ownership(other.clone(), &f.context.issuer_key_id)
            .is_err()
    );
    assert!(owner.is_fenced() && other.is_fenced());
    assert!(old_clone.database_now_ms().await.is_err());
    drop(other);
    drop(owner);
    drop(old_clone);
    store.close().await;
    drop(store);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op13b_fencing_cancels_actual_blocked_one_use_sqlite_retrieval() {
    use blindpass_controller::store::{FleetSigner, Store};
    use blindpass_core::clock::{ClockSample, ClockSource, SystemClock};
    struct ObservedClock(Arc<tokio::sync::Notify>);
    impl ClockSource for ObservedClock {
        fn sample(&self) -> Result<ClockSample, blindpass_core::clock::ClockError> {
            self.0.notify_one();
            SystemClock.sample()
        }
    }
    let directory = support::TestDirectory::new();
    let config = http_config(&directory);
    let url = format!("sqlite://{}", directory.file("one-use.db").display());
    let entered = Arc::new(tokio::sync::Notify::new());
    let store =
        Store::connect_with_clock_source(&url, Arc::new(ObservedClock(entered.clone())), 1000)
            .await
            .unwrap()
            .with_fleet_signer(FleetSigner::new(config.issuer_keypair().unwrap().clone()));
    let id = store
        .create_secret_request("P06_DUMMY_AGENT", "dummy-key", "dummy", "dummy", 60)
        .await
        .unwrap();
    assert!(
        store
            .submit_secret_request(&id, "P06_DUMMY_AGENT", "dummy-enc", "dummy-ciphertext", 60)
            .await
            .unwrap()
    );
    let f = Fixture::with_context(1, Some(controller_context(&store, &config))).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active', revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    store
        .bind_ownership(owner.clone(), &f.context.issuer_key_id)
        .unwrap();
    // Initialization/request setup also sampled this clock. Consume its
    // coalesced notification before observing the newly admitted retrieval.
    let _ = tokio::time::timeout(Duration::from_millis(1), entered.notified()).await;
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    let mut lock = pool.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *lock)
        .await
        .unwrap();
    // Clear clock notifications from setup; the next sample proves the
    // protected store future passed authority admission into its checkpoint.
    while tokio::time::timeout(Duration::from_millis(1), entered.notified())
        .await
        .is_ok()
    {}
    let task = tokio::spawn({
        let store = store.clone();
        let id = id.clone();
        async move { store.consume_secret_request(&id, "P06_DUMMY_AGENT").await }
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    assert!(!task.is_finished());
    owner.fence();
    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "controller ownership is fenced"
    );
    sqlx::query("ROLLBACK").execute(&mut *lock).await.unwrap();
    drop(lock);
    // Drain the Store pool's worker/transaction before the final independent
    // read. This proves this cancelled transaction did not commit later;
    // cancellation alone does not establish that for arbitrary mutations.
    assert!(owner.has_uncertain_database_work());
    assert!(owner.quiesce().await.is_err());
    store.close().await;
    // Read directly through the test administrator pool; never unbind Store.
    let status: String = sqlx::query_scalar("SELECT status FROM secret_requests WHERE id=?")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "submitted");
    // An independently verified fixture outcome is not an authorized reset.
    assert!(owner.quiesce().await.is_err());
    pool.close().await;
    store.close().await;
    drop(store);
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_op13c_direct_signing_checks_live_authority_identity_and_local_epoch() {
    use blindpass_controller::store::{FleetSigner, Store};
    use blindpass_core::fleet::{DocumentKind, TimeReply};
    for fault in ["backend", "epoch", "issuer"] {
        let directory = support::TestDirectory::new();
        let config = http_config(&directory);
        let store = Store::connect("sqlite::memory:")
            .await
            .unwrap()
            .with_fleet_signer(FleetSigner::new(config.issuer_keypair().unwrap().clone()));
        let epoch = if fault == "epoch" { 2 } else { 1 };
        let f = Fixture::with_context(epoch, Some(controller_context(&store, &config))).await;
        sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active', revision=revision+1 WHERE tenant_id=$1")
            .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
        let record = f.authority.read(&f.context).await.unwrap();
        let owner = Arc::new(
            f.authority
                .claim_process(&f.context, &record)
                .await
                .unwrap(),
        );
        let issuer = if fault == "issuer" {
            "P06_DUMMY_WRONG_ISSUER"
        } else {
            &f.context.issuer_key_id
        };
        let binding = store.bind_ownership(owner.clone(), issuer);
        assert_eq!(binding.is_ok(), fault != "issuer");
        if fault == "backend" {
            assert!(
                sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
                    .bind(owner.backend_pid())
                    .fetch_one(&f.runtime)
                    .await
                    .unwrap()
            );
        }
        let reply = TimeReply {
            node_id: "P06_DUMMY_NODE".into(),
            challenge: blindpass_core::signing::base64_url_encode(&[9; 32]),
            challenge_received_at_ms: 1000,
            controller_time_ms: 1000,
            issuer_epoch: epoch,
        }
        .to_value()
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            store.sign_node_document(DocumentKind::TimeReply, reply, epoch),
        )
        .await
        .unwrap();
        assert_eq!(
            result.unwrap_err().to_string(),
            "controller ownership is fenced"
        );
        assert!(owner.is_fenced());
        assert_eq!(store.issuer_epoch().await.unwrap(), 1);
        assert_eq!(f.authority.read(&f.context).await.unwrap(), record);
        owner.quiesce().await.unwrap();
        store.close().await;
        drop(store);
        drop(owner);
        f.close().await;
    }
}

impl HttpServer {
    async fn start_owned(
        app: axum::Router,
        owner: Arc<blindpass_controller::recovery_authority::ProcessOwnership>,
    ) -> Self {
        use axum::serve::ListenerExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let listener =
            blindpass_controller::owned_transport::OwnedListener::new(listener, Some(owner))
                .tap_io(|_| {});
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self { address, task }
    }
}

fn accepted_socket_fd_exists(inode: &str) -> bool {
    let target = format!("socket:[{inode}]");
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .any(|path| path.to_str() == Some(target.as_str()))
}

async fn accepted_socket_inode(
    server: std::net::SocketAddr,
    client: std::net::SocketAddr,
) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let sockets = std::fs::read_to_string("/proc/self/net/tcp").unwrap();
            for line in sockets.lines().skip(1) {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() > 9
                    && fields[1].ends_with(&format!(":{:04X}", server.port()))
                    && fields[2].ends_with(&format!(":{:04X}", client.port()))
                    && fields[3] == "01"
                    && accepted_socket_fd_exists(fields[9])
                {
                    return fields[9].to_owned();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned process never accepted the exact test socket")
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_qf02_quiescence_closes_the_actual_backpressured_response_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new(151).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1").bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let current = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &current)
            .await
            .unwrap(),
    );
    const TAIL: &[u8] = b"P06_MUST_NOT_DELIVER_LATE_TRANSPORT_TAIL";
    let app = axum::Router::new()
        .route(
            "/large",
            axum::routing::get(
                |axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
                    std::net::SocketAddr,
                >| async move {
                    let mut body = vec![b'x'; 8 * 1024 * 1024];
                    body.extend_from_slice(TAIL);
                    axum::http::Response::builder()
                        .header("x-p06-peer", peer.to_string())
                        .body(axum::body::Body::from(body))
                        .unwrap()
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            owner.clone(),
            blindpass_controller::recovery_authority::ownership_gate,
        ));
    let server = HttpServer::start_owned(app, owner.clone()).await;
    let mut client = tokio::net::TcpStream::connect(server.address)
        .await
        .unwrap();
    let peer = client.local_addr().unwrap();
    client
        .write_all(b"GET /large HTTP/1.1\r\nHost: p06.invalid\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    let mut header = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(client.read(&mut byte).await.unwrap(), 1);
            header.push(byte[0]);
            assert!(header.len() < 4096);
        }
    })
    .await
    .unwrap();
    let text = String::from_utf8(header).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"));
    assert!(
        text.lines()
            .any(|line| line == format!("x-p06-peer: {peer}")),
        "listener changed the original peer address"
    );
    let inode = accepted_socket_inode(server.address, peer).await;
    f.fence_fixture().await;
    owner.quiesce().await.unwrap();
    assert!(
        !accepted_socket_fd_exists(&inode),
        "quiescence released ownership while its response socket stayed open"
    );
    let mut queued = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut queued)).await;
    assert!(read.is_ok(), "fenced response socket did not close");
    assert!(
        !queued.windows(TAIL.len()).any(|window| window == TAIL),
        "response tail was delivered after local quiescence"
    );
    assert!(
        queued.len() < 8 * 1024 * 1024,
        "backpressure fixture did not leave pending response bytes"
    );
    let fenced = f.authority.read(&f.context).await.unwrap();
    assert_eq!(
        f.authority
            .reserve_recovery(&f.context, fenced.revision, 151)
            .await
            .unwrap()
            .epoch,
        152
    );
    drop(client);
    drop(server);
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_qf03_idle_connection_is_closed_before_quiescence_can_release_the_guard() {
    use tokio::io::AsyncReadExt;
    let f = Fixture::new(153).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1").bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let current = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &current)
            .await
            .unwrap(),
    );
    let server = HttpServer::start_owned(axum::Router::new(), owner.clone()).await;
    let mut client = tokio::net::TcpStream::connect(server.address)
        .await
        .unwrap();
    let inode = accepted_socket_inode(server.address, client.local_addr().unwrap()).await;
    f.fence_fixture().await;
    owner.quiesce().await.unwrap();
    assert!(
        !accepted_socket_fd_exists(&inode),
        "idle accepted socket outlived local quiescence"
    );
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "fenced idle connection stayed readable"
    );
    let fenced = f.authority.read(&f.context).await.unwrap();
    assert_eq!(
        f.authority
            .reserve_recovery(&f.context, fenced.revision, 153)
            .await
            .unwrap()
            .epoch,
        154
    );
    drop(client);
    drop(server);
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable PostgreSQL authority with restricted runtime role"]
async fn p06_qf03_idle_http_connection_has_the_actual_sixty_second_lifetime_bound() {
    use tokio::io::AsyncReadExt;
    let f = Fixture::new(155).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1").bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let current = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &current)
            .await
            .unwrap(),
    );
    let server = HttpServer::start_owned(axum::Router::new(), owner.clone()).await;
    let mut client = tokio::net::TcpStream::connect(server.address)
        .await
        .unwrap();
    let inode = accepted_socket_inode(server.address, client.local_addr().unwrap()).await;
    let started = Instant::now();
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(63), client.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "idle transport exceeded its sixty-second lifetime"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(58),
        "idle connection ended before the expected bound"
    );
    assert!(!accepted_socket_fd_exists(&inode));
    assert!(
        owner.is_active(),
        "one idle timeout must not fence the issuer itself"
    );
    f.fence_fixture().await;
    owner.quiesce().await.unwrap();
    drop(client);
    drop(server);
    drop(owner);
    f.close().await;
}
