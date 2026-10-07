// SPDX-License-Identifier: AGPL-3.0-only
//! Recovery metadata fixtures only; these are not signed broker recovery reports.
use blindpass_controller::{
    recovery_authority::{Authority, AuthorityContext, ProcessOwnership, ReviewKey},
    store::{FleetSigner, RecoveryReviewItem, SCHEMA_VERSION, Store},
};
use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{os::unix::fs::PermissionsExt, sync::Arc};
mod support;
use support::{Bind, Harness};

struct Fixture {
    h: Harness,
    store: Store,
    admin: PgPool,
    authority: Authority,
    context: AuthorityContext,
    owner: Arc<ProcessOwnership>,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_phase("recovering").await
    }

    async fn with_phase(phase: &str) -> Self {
        assert!(matches!(phase, "recovering" | "fenced" | "active"));
        let h = Harness::start().await;
        assert_eq!(
            h.call(&h.admin, "GET", "/api/v3/admin/session", &[], None)
                .await
                .status,
            200
        );
        seed(&h).await;
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(
                &std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").expect("isolated authority admin"),
            )
            .await
            .unwrap();
        let authority = Authority::connect_existing(
            &std::env::var("P06_TEST_AUTHORITY_URL").expect("restricted authority runtime"),
        )
        .await
        .unwrap();
        let context = AuthorityContext {
            tenant_id: h.store.tenant_id().into(),
            issuer_key_id: h.issuer_key_id.clone(),
            owner_id: "P06_DUMMY_OWNER".into(),
        };
        sqlx::query("INSERT INTO blindpass_authority.recovery_authority (tenant_id,issuer_key_id,owner_id,epoch,revision,phase) VALUES ($1,$2,$3,9,1,'fenced')")
            .bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id).execute(&admin).await.unwrap();
        let record = if phase == "recovering" {
            let record = authority.reserve_recovery(&context, 1, 9).await.unwrap();
            assert_eq!(record.epoch, 10);
            record
        } else {
            if phase == "active" {
                sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
                    .bind(&context.tenant_id).execute(&admin).await.unwrap();
            }
            authority.read(&context).await.unwrap()
        };
        let owner = Arc::new(authority.claim_process(&context, &record).await.unwrap());
        let store = h.store.clone().with_fleet_signer(FleetSigner::new(Arc::new(
            Ed25519KeyPair::from_seed(&[support::ISSUER_SEED; 32]).unwrap(),
        )));
        store
            .bind_ownership(owner.clone(), &context.issuer_key_id)
            .unwrap();
        Self {
            h,
            store,
            admin,
            authority,
            context,
            owner,
        }
    }
    async fn close(self) {
        if self.owner.has_uncertain_database_work() {
            assert!(self.owner.quiesce().await.is_err());
        } else {
            self.owner.quiesce().await.unwrap();
        }
        self.store.close().await;
        match &self.h.backend {
            support::Backend::Sqlite(p) => p.close().await,
            support::Backend::Postgres(p) => p.close().await,
        }
        self.authority.close().await;
        self.admin.close().await;
    }
}

async fn seed(h: &Harness) {
    let tenant = h.store.tenant_id();
    let node = support::NodeKeys::from_seed(41);
    h.execute("INSERT INTO nodes (id,tenant_id,name,signing_pub,recipient_pub,key_version,status,protocol_version,capabilities_json,created_at) VALUES ('P06_NODE',?,'dummy',?,?,1,'active','3','{}',1)",vec![tenant.into(),base64_url_encode(node.signing.public_key()).into(),base64_url_encode(node.recipient.public_key()).into()]).await;
    h.execute("INSERT INTO workloads (id,tenant_id,node_id,name,unit,account,consumption_mode,local_ceiling_seconds,registration_version,status,created_by,created_at) VALUES ('P06_WORKLOAD',?,'P06_NODE','dummy','dummy.service','dummy','file',60,1,'active','dummy',1)",vec![tenant.into()]).await;
    h.execute("INSERT INTO agents (id,tenant_id,agent_id,name,api_key_hash,status,created_at) VALUES ('P06_AGENT',?,'P06_DUMMY_AGENT','dummy','P06_DUMMY_HASH','active',1)",vec![tenant.into()]).await;
    for (id, role, disabled) in [
        ("P06_OPERATOR", "operator", None),
        ("P06_VIEWER", "viewer", Some(42)),
    ] {
        h.execute("INSERT INTO operators (id,username,display_name,password_hash,role,created_at,disabled_at) VALUES (?,?,'dummy','P06_DUMMY_HASH',?,1,?)",vec![id.into(),id.into(),role.into(),Bind::Int(disabled.unwrap_or(0))]).await;
        if disabled.is_none() {
            h.execute(
                "UPDATE operators SET disabled_at=NULL WHERE id=?",
                vec![id.into()],
            )
            .await;
        }
    }
    for sql in [
        "INSERT INTO secret_requests (id,tenant_id,requester_agent_id,public_key,description,confirmation_code,status,created_at,expires_at,enc,ciphertext) VALUES ('P06_REQUEST',?,'P06_DUMMY_AGENT','dummy','dummy','dummy','submitted',1,9999999999999,'P06_DUMMY_ENC','P06_DUMMY_CIPHERTEXT')",
        "INSERT INTO exchanges (id,tenant_id,requester_agent_id,requester_public_key,secret_name,purpose,fulfiller_hint,policy_decision_json,policy_hash,status,created_at,expires_at,enc,ciphertext) VALUES ('P06_EXCHANGE',?,'P06_DUMMY_AGENT','dummy','dummy','dummy','dummy','{}','dummy','submitted',1,9999999999999,'P06_DUMMY_ENC','P06_DUMMY_CIPHERTEXT')",
        "INSERT INTO approvals (reference,tenant_id,requester_agent_id,secret_name,purpose,fulfiller_hint,reason,approver_ids_json,approver_rings_json,status,created_at,expires_at) VALUES ('P06_APPROVAL',?,'P06_DUMMY_AGENT','dummy','dummy','dummy','dummy','[]','[]','approved',1,9999999999999)",
        "INSERT INTO enrollment_requests (id,tenant_id,token_hash,created_by,created_at,expires_at,status) VALUES ('P06_ENROLL',?,'P06_DUMMY_ENROLL_HASH','dummy',1,9999999999999,'submitted')",
        "INSERT INTO policies (tenant_id,version,document_json,source,updated_at) VALUES (?,1,'{\"P06_DUMMY\":\"policy\"}','dummy',1)",
        "INSERT INTO fleet_policies (tenant_id,version,document_json,updated_at,updated_by) VALUES (?,1,'{\"P06_DUMMY\":\"policy\"}',1,'dummy')",
        "INSERT INTO node_challenges (id,tenant_id,node_id,nonce_hash,key_version,issuer_epoch,protocol_version,capabilities_json,capabilities_hash,created_at,expires_at) VALUES ('P06_CHALLENGE',?,'P06_NODE','P06_DUMMY_NONCE',1,1,'3','{}','P06_DUMMY_HASH',1,9999999999999)",
        "INSERT INTO fleet_source_bindings (tenant_id,node_id,resource_id,source_unit,credential,version,updated_at,updated_by) VALUES (?,'P06_NODE','P06_RESOURCE','dummy.service','dummy',1,1,'dummy')",
        "INSERT INTO idempotency_keys (tenant_id,actor_id,operation,key_hash,request_hash,response_json,created_at,expires_at) VALUES (?,'dummy','dummy','P06_DUMMY_HASH','P06_DUMMY_HASH','{\"P06_DUMMY\":\"response\"}',1,9999999999999)",
    ] {
        h.execute(sql, vec![tenant.into()]).await;
    }
    h.execute("INSERT INTO bootstrap_tokens (token_hash,expires_at) VALUES ('P06_DUMMY_BOOTSTRAP',9999999999999)",vec![]).await;
    h.execute("INSERT INTO node_sessions (id,node_id,nonce_hash,token_hash,created_at,expires_at) VALUES ('P06_SESSION','P06_NODE','P06_DUMMY_NONCE','P06_DUMMY_TOKEN_HASH',1,9999999999999)",vec![]).await;
    h.execute("INSERT INTO node_inbox (node_id,seq,envelope_json,created_at) VALUES ('P06_NODE',1,'{\"P06_DUMMY\":\"delivery\"}',1)",vec![]).await;
    h.execute("INSERT INTO node_key_rotations (node_id,rotation_id,from_key_version,to_key_version,signing_pub,recipient_pub,fingerprint,created_at) VALUES ('P06_NODE','P06_ROTATION',1,2,'P06_DUMMY_PUBLIC','P06_DUMMY_PUBLIC','P06_DUMMY_FINGERPRINT',1)",vec![]).await;
    for (index, status) in [
        "requested",
        "awaiting_approval",
        "granted",
        "executing",
        "completed",
        "failed",
        "uncertain",
        "denied",
        "revoked",
        "cancelled",
    ]
    .iter()
    .enumerate()
    {
        let operation = format!("P06_OP_{index}");
        let grant = format!("P06_GRANT_{index}");
        h.execute("INSERT INTO operations (id,tenant_id,workload_id,node_id,invocation_id,action,mode,requested_by,purpose,policy_version,decision,status,idempotency_key,request_hash,created_at,expires_at) VALUES (?,?,'P06_WORKLOAD','P06_NODE',?,'dummy','file','dummy','dummy',1,'allow',?,?,'P06_DUMMY_HASH',1,9999999999999)",vec![operation.clone().into(),tenant.into(),operation.clone().into(),(*status).into(),operation.clone().into()]).await;
        h.execute("INSERT INTO grants (id,tenant_id,operation_id,node_id,workload_id,invocation_id,account,resource_id,recipient_key_id,policy_version,request_use_id,unit,action,mode,audience,issuer_epoch,issued_at,expires_at,body_json,signature,status,created_at) VALUES (?,?,?,'P06_NODE','P06_WORKLOAD',?,'dummy','P06_RESOURCE','dummy',1,?,'dummy.service','dummy','file','dummy',1,1,9999999999999,'{}','P06_DUMMY_SIGNATURE',?,1)",vec![grant.into(),tenant.into(),operation.clone().into(),operation.clone().into(),operation.into(),if index==4{"consumed"}else{"issued"}.into()]).await;
    }
    h.execute("INSERT INTO operation_approvals (id,tenant_id,operation_ids_json,requester_summary_json,verified_identity_json,rule_id,status,expires_at,idempotency_key,created_at) VALUES ('P06_FLEET_APPROVAL',?,'[]','{}','{}','P06_DUMMY_RULE','pending',9999999999999,'P06_DUMMY_IDEMPOTENCY',1)",vec![tenant.into()]).await;
    h.execute("INSERT INTO fleet_provisioning_offers (id,tenant_id,node_id,operation_id,grant_id,source_binding_version,offer_json,issued_at,expires_at,created_at) VALUES ('P06_OFFER',?,'P06_NODE','P06_OP_0','P06_GRANT_0',1,'{}',1,9999999999999,1)",vec![tenant.into()]).await;
    h.execute("INSERT INTO fleet_provisioning_links (id,tenant_id,node_id,operation_id,grant_id,offer_id,operator_id,idempotency_hash,expires_at,created_at) VALUES ('P06_LINK',?,'P06_NODE','P06_OP_0','P06_GRANT_0','P06_OFFER','dummy','P06_DUMMY_HASH',9999999999999,1)",vec![tenant.into()]).await;
    h.execute("INSERT INTO cross_fulfillments (id,tenant_id,issuer_workload_id,recipient_workload_id,issuer_node_id,recipient_node_id,issuer_credential,recipient_credential,mode,requested_by,purpose,policy_version,rule_id,decision,approver_ids_json,approval_status,ttl_seconds,terms_digest,status,idempotency_key,request_hash,created_at,expires_at) VALUES ('P10_FULFILLMENT',?,'P06_WORKLOAD','P06_WORKLOAD','P06_NODE','P06_NODE','dummy','dummy','reencrypt','dummy','dummy',1,'P06_DUMMY_RULE','allow','[]','not_required',60,'P06_DUMMY_DIGEST','available','P06_DUMMY_IDEMPOTENCY','P06_DUMMY_HASH',1,9999999999999)",vec![tenant.into()]).await;
    h.execute("INSERT INTO cross_fulfillment_payloads (fulfillment_id,tenant_id,submit_json,ciphertext_digest,created_at) VALUES ('P10_FULFILLMENT',?,'{}','P06_DUMMY_DIGEST',1)",vec![tenant.into()]).await;
    h.execute("INSERT INTO fleet_provisioning_receipts (link_id,tenant_id,node_id,grant_id,offer_id,operator_id,ciphertext_digest,delivery_digest,submitted_at,expires_at) VALUES ('P06_LINK',?,'P06_NODE','P06_GRANT_0','P06_OFFER','dummy','P06_DUMMY_DIGEST','P06_DUMMY_DIGEST',1,9999999999999)",vec![tenant.into()]).await;
}

async fn assert_invalidated(f: &Fixture) {
    for table in [
        "secret_requests",
        "exchanges",
        "approvals",
        "enrollment_requests",
        "operation_approvals",
        "bootstrap_tokens",
        "operator_sessions",
        "node_sessions",
        "node_challenges",
        "idempotency_keys",
        "node_inbox",
        "fleet_provisioning_links",
        "fleet_provisioning_offers",
        "cross_fulfillment_payloads",
    ] {
        assert_eq!(
            f.h.scalar_i64(&format!("SELECT COUNT(*) FROM {table}"), vec![])
                .await,
            0,
            "{table}"
        );
    }
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM cross_fulfillments WHERE status='revoked' AND revocation_reason='recovery' AND delivery_revoked_at IS NOT NULL",
            vec![]
        )
        .await,
        1,
        "live fulfillments end on recovery and keep their lineage"
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT issuer_epoch FROM controller_meta WHERE id=1",
            vec![]
        )
        .await,
        10
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM operations WHERE status='uncertain' AND version=2",
            vec![]
        )
        .await,
        10
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM grant_tombstones WHERE retain_until=9007199254740991",
            vec![]
        )
        .await,
        10
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM grants WHERE status='issued' OR status='delivered'",
            vec![]
        )
        .await,
        0
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM grants WHERE status='consumed'",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM agents WHERE status='revoked' AND key_version=2",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM operators WHERE disabled_at IS NULL",
            vec![]
        )
        .await,
        0
    );
    assert_eq!(f.h.scalar_i64("SELECT COUNT(*) FROM operators WHERE id='P06_VIEWER' AND role='viewer' AND disabled_at=42",vec![]).await,1);
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM workloads WHERE status='revoked' AND version=2",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM controller_recovery_nodes WHERE state='quarantined'",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM controller_recovery_operations",
            vec![]
        )
        .await,
        10
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM controller_recovery_reviews WHERE state='quarantined'",
            vec![]
        )
        .await,
        9
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM fleet_provisioning_receipts", vec![])
            .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM policies", vec![])
            .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM fleet_policies", vec![])
            .await,
        1
    );
    assert!(f.store.recovery_required());
    assert!(f.store.readiness().await.is_err());
    assert!(!f.owner.is_active());
    assert_eq!(
        f.authority.read(&f.context).await.unwrap().phase,
        "recovering"
    );
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_ri01_atomic_invalidation_and_quarantine_cover_all_restored_authority() {
    let f = Fixture::new().await;
    let status = f
        .store
        .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    assert_eq!(status.phase, "invalidated");
    assert_eq!(status.snapshot_epoch, 1);
    assert_eq!(status.target_epoch, 10);
    let summary = status.summary.unwrap();
    assert_eq!(summary.operations, 10);
    assert_eq!(summary.grants, 10);
    assert_eq!(summary.fulfillments, 1);
    assert_eq!(summary.nodes, 1);
    assert_eq!(summary.reviews, 9);
    assert_invalidated(&f).await;
    let again = f
        .store
        .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    assert_eq!(again.phase, "invalidated");
    assert_invalidated(&f).await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_ri07_postgres_recovery_transactions_use_repeatable_read() {
    let f = Fixture::new().await;
    if matches!(&f.h.backend, support::Backend::Sqlite(_)) {
        // SQLite transactions are serializable already.
        f.close().await;
        return;
    }
    f.h.execute(
        "CREATE TABLE p06_isolation_probe (level TEXT NOT NULL, relation TEXT NOT NULL)",
        vec![],
    )
    .await;
    f.h.execute("CREATE FUNCTION p06_isolation_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO p06_isolation_probe VALUES (current_setting('transaction_isolation'), TG_TABLE_NAME); RETURN NEW; END $$", vec![]).await;
    for table in ["controller_recoveries", "grants", "operations"] {
        f.h.execute(&format!("CREATE TRIGGER p06_note_{table} AFTER INSERT OR UPDATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION p06_isolation_note()"), vec![]).await;
    }
    f.store
        .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    let support::Backend::Postgres(pool) = &f.h.backend else {
        unreachable!()
    };
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT level, relation FROM p06_isolation_probe")
            .fetch_all(pool)
            .await
            .unwrap();
    for relation in ["controller_recoveries", "grants", "operations"] {
        assert!(
            rows.iter().any(|(_, r)| r == relation),
            "probe never saw {relation}"
        );
    }
    assert!(
        rows.iter().all(|(level, _)| level == "repeatable read"),
        "recovery transaction ran below repeatable read: {rows:?}"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_ri02_failure_rolls_back_bulk_state_but_intent_survives_restart_and_retry() {
    let f = Fixture::new().await;
    match &f.h.backend {
        support::Backend::Sqlite(_) => {
            f.h.execute("CREATE TRIGGER p06_fail BEFORE UPDATE ON grants BEGIN SELECT RAISE(ABORT,'P06_DUMMY_INJECTION'); END",vec![]).await;
        }
        support::Backend::Postgres(_) => {
            f.h.execute("CREATE FUNCTION p06_fail() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'P06_DUMMY_INJECTION'; END $$",vec![]).await;
            f.h.execute("CREATE TRIGGER p06_fail BEFORE UPDATE ON grants FOR EACH ROW EXECUTE FUNCTION p06_fail()",vec![]).await;
        }
    }
    assert!(
        f.store
            .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
            .await
            .is_err()
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT issuer_epoch FROM controller_meta WHERE id=1",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
            .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM operations WHERE version=1", vec![])
            .await,
        10
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM controller_recovery_operations",
            vec![]
        )
        .await,
        0
    );
    let prepared = f.store.recovery_status().await.unwrap().unwrap();
    assert_eq!(prepared.phase, "prepared");
    assert!(prepared.summary.is_none());
    assert!(f.owner.has_uncertain_database_work());
    assert!(f.owner.quiesce().await.is_err());
    let Fixture {
        mut h,
        store,
        admin,
        authority,
        context,
        owner,
    } = f;
    store.close().await;
    drop(store);
    h.restart_server().await;
    // Fixture restart only: dispose the entire old immutable binding, rather
    // than resetting an uncertain owner after independently observing rollback.
    let old_owner = Arc::downgrade(&owner);
    drop(owner);
    assert!(old_owner.upgrade().is_none());
    assert_eq!(
        h.request("GET", "/api/v3/capabilities", &[], None)
            .await
            .status,
        503
    );
    match &h.backend {
        support::Backend::Sqlite(_) => {
            h.execute("DROP TRIGGER p06_fail", vec![]).await;
        }
        support::Backend::Postgres(_) => {
            h.execute("DROP TRIGGER p06_fail ON grants", vec![]).await;
        }
    }
    let record = authority.read(&context).await.unwrap();
    let owner = Arc::new(authority.claim_process(&context, &record).await.unwrap());
    let store = h.store.clone().with_fleet_signer(FleetSigner::new(Arc::new(
        Ed25519KeyPair::from_seed(&[support::ISSUER_SEED; 32]).unwrap(),
    )));
    store
        .bind_ownership(owner.clone(), &context.issuer_key_id)
        .unwrap();
    let f = Fixture {
        h,
        store,
        admin,
        authority,
        context,
        owner,
    };
    f.store
        .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    assert_invalidated(&f).await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_ri03_prepared_intent_fences_all_http_and_clones_after_restart() {
    let mut f = Fixture::new().await;
    let status = f
        .store
        .prepare_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    assert_eq!(status.phase, "prepared");
    f.owner.quiesce().await.unwrap();
    f.h.restart_server().await;
    assert!(f.h.store.recovery_required());
    for method in [
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
    ] {
        for path in [
            "/api/v3/capabilities",
            "/api/v3/admin/session",
            "/api/v3/node/poll",
            "/api/v2/agents/token",
            "/api/v2/secret/request",
            "/api/v2/exchange/request",
            "/input/",
            "/assets/P06_DUMMY.js",
            "/P06_DUMMY",
            "/healthz/",
            "/%68ealthz",
        ] {
            let response =
                f.h.request(
                    method,
                    path,
                    &[("cookie", f.h.admin.cookies.as_str())],
                    None,
                )
                .await;
            assert_eq!(response.status, 503, "{method} {path}");
        }
    }
    assert_eq!(f.h.request("GET", "/healthz", &[], None).await.status, 200);
    let ready = f.h.request("GET", "/readyz", &[], None).await;
    assert_eq!(ready.status, 503);
    assert_eq!(ready.body["reason"], "recovery_required");
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
            .await,
        1
    );
    assert_eq!(
        f.h.store.recovery_status().await.unwrap().unwrap().phase,
        "prepared"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_ri04_invalid_input_and_lost_holder_cannot_invalidate_or_guess_epoch() {
    let f = Fixture::new().await;
    if let Ok(url) = std::env::var("P06_TEST_CONTROLLER_AUTHORITY_PROBE_URL") {
        let probe = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        for sql in [
            "SELECT version FROM blindpass_authority.authority_layout",
            "UPDATE blindpass_authority.recovery_authority SET epoch=1",
            "SELECT * FROM blindpass_authority.reserve_recovery('P06_DUMMY','P06_DUMMY','P06_DUMMY',1,1)",
        ] {
            assert!(
                sqlx::query(sql).execute(&probe).await.is_err(),
                "controller role cannot access independent authority"
            );
        }
        probe.close().await;
    }

    for id in ["", "P06 DUMMY INVALID", "../P06_DUMMY"] {
        assert!(f.store.prepare_recovery(&f.owner, id).await.is_err());
    }
    let unbound = Store::connect("sqlite::memory:")
        .await
        .unwrap()
        .with_fleet_signer(FleetSigner::new(Arc::new(
            Ed25519KeyPair::from_seed(&[support::ISSUER_SEED; 32]).unwrap(),
        )));
    assert!(
        unbound
            .prepare_recovery(&f.owner, "P06_DUMMY_RECOVERY")
            .await
            .is_err()
    );
    assert!(!unbound.recovery_required());
    unbound.close().await;
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM controller_recoveries", vec![])
            .await,
        0
    );
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1").bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    assert!(
        f.store
            .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
            .await
            .is_err()
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT issuer_epoch FROM controller_meta WHERE id=1",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
            .await,
        1
    );
    f.close().await;
    for phase in ["fenced", "active"] {
        let f = Fixture::with_phase(phase).await;
        f.owner.check().await.unwrap();
        assert!(!f.owner.is_fenced(), "live {phase} holder");
        assert!(
            f.store
                .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
                .await
                .is_err()
        );
        assert!(!f.store.recovery_required());
        assert_eq!(
            f.h.scalar_i64("SELECT COUNT(*) FROM controller_recoveries", vec![])
                .await,
            0
        );
        assert_eq!(
            f.h.scalar_i64(
                "SELECT issuer_epoch FROM controller_meta WHERE id=1",
                vec![]
            )
            .await,
            1
        );
        assert_eq!(
            f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
                .await,
            1
        );
        f.close().await;
    }
    for epoch in [10_i64, 11] {
        let f = Fixture::new().await;
        f.h.execute(
            "UPDATE controller_meta SET issuer_epoch=? WHERE id=1",
            vec![epoch.into()],
        )
        .await;
        assert!(
            f.store
                .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
                .await
                .is_err()
        );
        assert_eq!(
            f.h.scalar_i64(
                "SELECT issuer_epoch FROM controller_meta WHERE id=1",
                vec![]
            )
            .await,
            epoch
        );
        assert_eq!(
            f.h.scalar_i64("SELECT COUNT(*) FROM controller_recoveries", vec![])
                .await,
            0
        );
        assert_eq!(
            f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
                .await,
            1
        );
        f.close().await;
    }
}

#[tokio::test]
async fn p06_ri05_schema16_authenticated_backup_still_verifies_without_activation() {
    use blindpass_controller::backup::{
        Backend, capture_sqlite, encrypt_bundle, initialize_recovery_key, verify_backup,
        write_archive,
    };
    let directory = support::TestDirectory::new();
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let source = directory.file("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["root-secret", "agent-jwt-secret", "issuer-key"] {
        let p = source.join(name);
        std::fs::write(&p, [b'D'; 32]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let url = format!("sqlite://{}", directory.file("old.db").display());
    let store = Store::connect(&url).await.unwrap();
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    // Form an actual schema16 database, with all its required tables/columns.
    for table in [
        "controller_recovery_reviews",
        "controller_recovery_operations",
        "controller_recovery_nodes",
        "controller_recoveries",
    ] {
        sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE controller_meta SET schema_version=16 WHERE id=1")
        .execute(&pool)
        .await
        .unwrap();
    let snapshot = capture_sqlite(&store, &source.join("database.sqlite"))
        .await
        .unwrap();
    assert_eq!(snapshot.schema_version, 16);
    let tar = directory.file("bundle.tar");
    write_archive(&source, &tar, Backend::Sqlite, &snapshot).unwrap();
    let key = directory.file("recovery.pem");
    initialize_recovery_key(&key).unwrap();
    let work = directory.file("work");
    std::fs::create_dir(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).unwrap();
    let encrypted = directory.file("backup.bpbackup");
    encrypt_bundle(&tar, &encrypted, &key, &work).unwrap();
    let verified = verify_backup(&encrypted, &key, &work).await.unwrap();
    assert_eq!(verified.snapshot.schema_version, 16);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT CAST(schema_version AS BIGINT) FROM controller_meta WHERE id=1"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        16
    );

    store.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_ri05_damaged_or_future_schema_is_refused_without_repair() {
    for fault in ["table", "version"] {
        let f = Fixture::new().await;
        if fault == "table" {
            f.h.execute("DROP TABLE controller_recovery_reviews", vec![])
                .await;
        } else {
            f.h.execute(
                "UPDATE controller_meta SET schema_version=? WHERE id=1",
                vec![Bind::Int(SCHEMA_VERSION + 1)],
            )
            .await;
        }
        let error = f
            .store
            .prepare_recovery(&f.owner, "P06_DUMMY_RECOVERY")
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "controller schema version is unsupported"
        );
        assert_eq!(
            f.h.scalar_i64("SELECT COUNT(*) FROM controller_recoveries", vec![])
                .await,
            0
        );
        assert_eq!(
            f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
                .await,
            1
        );
        assert!(Store::connect(&f.h.database_url).await.is_err());
        assert!(
            Store::connect_existing(&f.h.database_url, 2000)
                .await
                .is_err()
        );
        assert_eq!(
            f.h.scalar_i64(
                "SELECT CAST(schema_version AS BIGINT) FROM controller_meta WHERE id=1",
                vec![]
            )
            .await,
            SCHEMA_VERSION + i64::from(fault == "version")
        );
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_ri06_authority_loss_cancels_write_locked_recovery_and_keeps_intent() {
    use std::time::Duration;
    let f = Fixture::new().await;
    f.store
        .prepare_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    enum Lock {
        Sqlite(sqlx::pool::PoolConnection<sqlx::Sqlite>),
        Postgres(sqlx::Transaction<'static, sqlx::Postgres>),
    }
    let lock = match &f.h.backend {
        support::Backend::Sqlite(pool) => {
            let mut connection = pool.acquire().await.unwrap();
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut *connection)
                .await
                .unwrap();
            Lock::Sqlite(connection)
        }
        support::Backend::Postgres(pool) => {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("UPDATE grants SET status=status WHERE id='P06_GRANT_0'")
                .execute(&mut *tx)
                .await
                .unwrap();
            Lock::Postgres(tx)
        }
    };
    let mut task = tokio::spawn({
        let store = f.store.clone();
        let owner = f.owner.clone();
        async move {
            store
                .invalidate_recovery(&owner, "P06_DUMMY_RECOVERY")
                .await
        }
    });
    if let support::Backend::Postgres(pool) = &f.h.backend {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting:i64=sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND wait_event_type='Lock' AND query LIKE '%UPDATE grants SET status=%'")
                    .fetch_one(pool).await.unwrap();
                if waiting>0 {break;}
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
    } else {
        // The real SQLite write lock keeps the admitted replay/write future
        // pending. This is not a claim about its exact statement position.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut task)
                .await
                .is_err()
        );
    }
    let monitor = f.owner.spawn_monitor();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1")
        .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    assert!(f.owner.is_fenced());
    assert!(f.owner.has_uncertain_database_work());
    monitor.await.unwrap();
    match lock {
        Lock::Sqlite(mut connection) => {
            sqlx::query("ROLLBACK")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        Lock::Postgres(tx) => tx.rollback().await.unwrap(),
    }
    f.store.close().await;
    // Read only after the owned Store pool's queued work/transaction drained.
    assert_eq!(
        f.h.scalar_i64(
            "SELECT issuer_epoch FROM controller_meta WHERE id=1",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
            .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM operations WHERE version=1", vec![])
            .await,
        10
    );
    assert_eq!(f.h.scalar_i64("SELECT COUNT(*) FROM controller_recoveries WHERE phase='prepared' AND summary_json IS NULL",vec![]).await,1);
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM controller_recovery_operations",
            vec![]
        )
        .await,
        0
    );
    f.close().await;
}

async fn decide_all(f: &Fixture, pick: impl Fn(&RecoveryReviewItem) -> &'static str) {
    for item in f.store.recovery_review_items(&f.owner).await.unwrap() {
        let key = ReviewKey {
            category: item.category.clone(),
            subject_id: item.subject_id.clone(),
            related_id: item.related_id.clone(),
        };
        f.store
            .decide_recovery_review(&f.owner, &key, pick(&item), "operator_dummy", "reviewed")
            .await
            .unwrap();
    }
}

async fn trust_node(f: &Fixture) {
    sqlx::query("INSERT INTO blindpass_authority.broker_trust (tenant_id,issuer_key_id,node_id,key_version,signing_public,recipient_public,state,revision) VALUES ($1,$2,'P06_NODE',1,$3,$4,'active',1)")
        .bind(&f.context.tenant_id).bind(&f.context.issuer_key_id)
        .bind(base64_url_encode(&[31; 32])).bind(base64_url_encode(&[33; 32]))
        .execute(&f.admin).await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_rv01_every_quarantined_item_needs_a_decision_and_refusals_never_fence() {
    let f = Fixture::new().await;
    f.store
        .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    let items = f.store.recovery_review_items(&f.owner).await.unwrap();
    let count = |category: &str| items.iter().filter(|i| i.category == category).count();
    assert_eq!(count("operation"), 10);
    assert_eq!(
        count("operator"),
        3,
        "two fixtures and the harness administrator"
    );
    for category in [
        "agent",
        "workload",
        "legacy_policy",
        "fleet_policy",
        "source_binding",
        "node_key_rotation",
    ] {
        assert_eq!(count(category), 1, "{category}");
    }
    assert!(items.iter().all(|i| i.decision.is_none()));
    let status = f.store.recovery_activation_status(&f.owner).await.unwrap();
    assert_eq!(status.items as usize, items.len());
    assert_eq!(status.undecided as usize, items.len());
    assert!(!status.activation_permitted);
    for gap in [
        "source_stop_missing",
        "review_incomplete",
        "review_undecided",
    ] {
        assert!(status.gaps.contains(&gap.to_string()), "{gap}");
    }
    // Refusals are answers, not lost holders.
    let unknown = ReviewKey {
        category: "operation".into(),
        subject_id: "P06_NO_SUCH_OPERATION".into(),
        related_id: String::new(),
    };
    assert!(
        f.store
            .decide_recovery_review(&f.owner, &unknown, "accept", "operator_dummy", "")
            .await
            .is_err()
    );
    let known = ReviewKey {
        subject_id: "P06_OP_0".into(),
        ..unknown.clone()
    };
    assert!(
        f.store
            .decide_recovery_review(&f.owner, &known, "maybe", "operator_dummy", "")
            .await
            .is_err()
    );
    assert!(
        f.store
            .decide_recovery_review(&f.owner, &known, "accept", "bad operator", "")
            .await
            .is_err()
    );
    assert!(
        f.store
            .complete_recovery_review(&f.owner, "operator_dummy")
            .await
            .is_err()
    );
    assert!(
        !f.owner.is_fenced(),
        "a refusal must not fence the controller"
    );
    f.store
        .decide_recovery_review(&f.owner, &known, "reject", "operator_dummy", "x")
        .await
        .unwrap();
    f.store
        .decide_recovery_review(&f.owner, &known, "revoke", "operator_two", "changed")
        .await
        .unwrap();
    let after = f.store.recovery_review_items(&f.owner).await.unwrap();
    let decided = after.iter().find(|i| i.subject_id == "P06_OP_0").unwrap();
    assert_eq!(decided.decision.as_deref(), Some("revoke"));
    assert_eq!(decided.operator_id.as_deref(), Some("operator_two"));
    assert!(
        f.store
            .complete_recovery_review(&f.owner, "operator_dummy")
            .await
            .is_err()
    );
    assert!(!f.owner.is_fenced());
    assert_invalidated(&f).await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_rv02_completion_reenables_only_accepted_invalidated_accounts_and_is_final() {
    let f = Fixture::new().await;
    f.store
        .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    decide_all(&f, |item| match item.category.as_str() {
        "operator" => "accept",
        _ => "reject",
    })
    .await;
    let done = f
        .store
        .complete_recovery_review(&f.owner, "operator_dummy")
        .await
        .unwrap();
    assert_eq!(done.items, 19);
    assert_eq!(
        done.operators_enabled, 2,
        "the harness administrator and P06_OPERATOR; the viewer was disabled before the snapshot"
    );
    assert_eq!(done.nodes_revoked, 0);
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM operators WHERE id='P06_OPERATOR' AND disabled_at IS NULL",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM operators WHERE id='P06_VIEWER' AND disabled_at=42",
            vec![]
        )
        .await,
        1
    );
    // Rejected operations, grants and agents stay invalidated: acceptance never revives them.
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM operations WHERE status='uncertain'",
            vec![]
        )
        .await,
        10
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM agents WHERE status='revoked'", vec![])
            .await,
        1
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM grants WHERE status='issued' OR status='delivered'",
            vec![]
        )
        .await,
        0
    );
    let status = f.store.recovery_activation_status(&f.owner).await.unwrap();
    assert_eq!(status.gaps, ["source_stop_missing"]);
    let key = ReviewKey {
        category: "operation".into(),
        subject_id: "P06_OP_1".into(),
        related_id: String::new(),
    };
    assert!(
        f.store
            .decide_recovery_review(&f.owner, &key, "accept", "operator_dummy", "late")
            .await
            .is_err()
    );
    assert!(!f.owner.is_fenced());
    f.close().await;
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_rv03_an_unreported_node_blocks_completion_until_waived_and_is_then_revoked_locally() {
    let f = Fixture::new().await;
    trust_node(&f).await;
    f.store
        .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    decide_all(&f, |_| "reject").await;
    let status = f.store.recovery_activation_status(&f.owner).await.unwrap();
    assert!(status.gaps.contains(&"node_uncovered".to_string()));
    assert_eq!(status.nodes.len(), 1);
    assert!(status.nodes[0].receipt.is_none() && !status.nodes[0].waived);
    assert!(
        f.store
            .complete_recovery_review(&f.owner, "operator_dummy")
            .await
            .is_err()
    );
    assert!(!f.owner.is_fenced());
    assert!(
        f.store
            .waive_recovery_node(&f.owner, "P06_NO_NODE", "operator_dummy", "x")
            .await
            .is_err()
    );
    assert!(!f.owner.is_fenced());
    f.store
        .waive_recovery_node(&f.owner, "P06_NODE", "operator_dummy", "hardware lost")
        .await
        .unwrap();
    let status = f.store.recovery_activation_status(&f.owner).await.unwrap();
    assert!(status.nodes[0].waived && status.nodes[0].revoked);
    assert!(!status.gaps.contains(&"node_uncovered".to_string()));
    let done = f
        .store
        .complete_recovery_review(&f.owner, "operator_dummy")
        .await
        .unwrap();
    assert_eq!(done.nodes_revoked, 1);
    assert_eq!(f.h.scalar_i64("SELECT COUNT(*) FROM nodes WHERE id='P06_NODE' AND status='revoked' AND revoked_by='operator_dummy'", vec![]).await, 1);
    f.close().await;
}

async fn reopen_active(f: &Fixture) -> (Arc<ProcessOwnership>, Store) {
    let record = f.authority.read(&f.context).await.unwrap();
    assert_eq!(record.phase, "active");
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    let store = Store::connect_existing_owned(
        &f.h.database_url,
        5000,
        owner.clone(),
        &f.context.issuer_key_id,
    )
    .await
    .unwrap();
    (owner, store)
}

#[tokio::test]
#[ignore = "requires disposable separate controller/authority databases"]
async fn p06_rv04_only_protected_activation_releases_the_recovery_latch() {
    // Protected path: review complete, source stop attested, activate_recovery.
    let f = Fixture::new().await;
    f.store
        .invalidate_recovery(&f.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    decide_all(&f, |_| "reject").await;
    f.store
        .complete_recovery_review(&f.owner, "operator_dummy")
        .await
        .unwrap();
    f.owner.quiesce().await.unwrap();
    sqlx::query("SELECT blindpass_authority.attest_source_stop($1,$2,$3,'host_dummy','admin_dummy','stopped')")
        .bind(&f.context.tenant_id).bind(&f.context.issuer_key_id).bind(&f.context.owner_id)
        .execute(&f.admin).await.unwrap();
    let revision = f.authority.read(&f.context).await.unwrap().revision as i64;
    sqlx::query("SELECT * FROM blindpass_authority.activate_recovery($1,$2,$3,$4)")
        .bind(&f.context.tenant_id)
        .bind(&f.context.issuer_key_id)
        .bind(&f.context.owner_id)
        .bind(revision)
        .execute(&f.admin)
        .await
        .unwrap();
    let (owner, store) = reopen_active(&f).await;
    assert!(
        !store.recovery_required(),
        "protected activation concludes the recovery"
    );
    assert!(owner.is_active());
    store.close().await;
    owner.quiesce().await.unwrap();

    // Bypass: fence the recovering record and activate it with the ordinary script.
    let g = Fixture::new().await;
    g.store
        .invalidate_recovery(&g.owner, "P06_DUMMY_RECOVERY")
        .await
        .unwrap();
    g.owner.quiesce().await.unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1 AND phase IN ('active','recovering')")
        .bind(&g.context.tenant_id).execute(&g.admin).await.unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1 AND phase IN ('fenced','active')")
        .bind(&g.context.tenant_id).execute(&g.admin).await.unwrap();
    let (owner, store) = reopen_active(&g).await;
    assert!(
        store.recovery_required(),
        "an unreviewed record stays latched"
    );
    store.close().await;
    owner.quiesce().await.unwrap();
    for fixture in [f, g] {
        fixture.store.close().await;
        match &fixture.h.backend {
            support::Backend::Sqlite(p) => p.close().await,
            support::Backend::Postgres(p) => p.close().await,
        }
        fixture.authority.close().await;
        fixture.admin.close().await;
    }
}
