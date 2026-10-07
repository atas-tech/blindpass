// SPDX-License-Identifier: AGPL-3.0-only
//! An actual encrypted destination stage, not source-stop/activation proof.
mod support;
use blindpass_controller::{
    backup::{Backend, capture_sqlite, encrypt_bundle, initialize_recovery_key, write_archive},
    recovery_authority::{Authority, AuthorityContext},
    store::Store,
};
use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};
use sqlx::{PgPool, SqlitePool};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
    time::Instant,
};

struct Fixture {
    root: support::TestDirectory,
    archive: std::path::PathBuf,
    tenant: String,
    context: AuthorityContext,
    admin: PgPool,
    authority: Authority,
    clock: i64,
}
impl Fixture {
    async fn with_current_broker() -> Self {
        use blindpass_controller::recovery_authority::{BrokerTrustDraft, BrokerTrustState};
        use std::sync::Arc;
        let issuer = format!(
            "ed25519-{}",
            base64_url_encode(Ed25519KeyPair::from_seed(&[71; 32]).unwrap().public_key())
        );
        let f = Self::with_options(
            blindpass_controller::store::SCHEMA_VERSION,
            Some((7, "active", &issuer)),
            0,
        )
        .await;
        let record = f.authority.read(&f.context).await.unwrap();
        let active = Arc::new(
            f.authority
                .claim_process(&f.context, &record)
                .await
                .unwrap(),
        );
        active
            .publish_broker_trust(
                0,
                &BrokerTrustDraft {
                    node_id: "P06_DUMMY_NODE".into(),
                    key_version: 1,
                    signing_public: base64_url_encode(
                        Ed25519KeyPair::from_seed(&[41; 32]).unwrap().public_key(),
                    ),
                    recipient_public: base64_url_encode(&[42; 32]),
                    state: BrokerTrustState::Active,
                    pending: None,
                },
            )
            .await
            .unwrap();
        active.quiesce().await.unwrap();
        drop(active);
        sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1")
            .bind(&f.context.tenant_id).execute(&f.admin).await.unwrap();
        let fenced = f.authority.read(&f.context).await.unwrap();
        assert_eq!(
            f.authority
                .reserve_recovery(&f.context, fenced.revision, 7)
                .await
                .unwrap()
                .epoch,
            8
        );
        f
    }

    async fn new() -> Self {
        Self::with_schema(blindpass_controller::store::SCHEMA_VERSION).await
    }
    async fn with_schema(schema: i64) -> Self {
        Self::with_options(schema, None, 0).await
    }
    async fn with_options(
        schema: i64,
        authority_override: Option<(i64, &str, &str)>,
        audit_rows: i64,
    ) -> Self {
        let root = support::TestDirectory::new();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let members = root.file("members");
        fs::create_dir(&members).unwrap();
        fs::set_permissions(&members, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, byte) in [
            ("root-secret", 65),
            ("agent-jwt-secret", 74),
            ("issuer-key", 71),
        ] {
            private(&members.join(name), &[byte; 32]);
        }
        let store = Store::connect(&format!(
            "sqlite://{}?mode=rwc",
            root.file("source.db").display()
        ))
        .await
        .unwrap();
        let tenant = store.tenant_id().to_owned();
        store
            .create_agent_with_id(
                "00000000-0000-4000-8000-000000000601",
                "dummy",
                "dummy",
                None,
                "P06_DUMMY_HASH",
            )
            .await
            .unwrap();
        let request = store
            .create_secret_request(
                "00000000-0000-4000-8000-000000000601",
                "dummy",
                "dummy",
                "dummy",
                60,
            )
            .await
            .unwrap();
        assert!(
            store
                .submit_secret_request(
                    &request,
                    "00000000-0000-4000-8000-000000000601",
                    "P06_DUMMY_ENC",
                    "P06_DUMMY_CIPHERTEXT",
                    60
                )
                .await
                .unwrap()
        );
        let pool = SqlitePool::connect(&format!("sqlite://{}", root.file("source.db").display()))
            .await
            .unwrap();
        sqlx::query("INSERT INTO operators (id,username,display_name,password_hash,role,created_at) VALUES ('P06_DUMMY_OPERATOR','dummy','dummy','P06_DUMMY_HASH','operator',1)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO bootstrap_tokens (token_hash,expires_at) VALUES ('P06_DUMMY_BOOTSTRAP',9999999999999)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO nodes (id,tenant_id,name,signing_pub,recipient_pub,key_version,status,protocol_version,capabilities_json,created_at) VALUES ('P06_DUMMY_NODE',?,'dummy','P06_DUMMY_SIGNING','P06_DUMMY_RECIPIENT',1,'active','1','{}',1)").bind(&tenant).execute(&pool).await.unwrap();
        for sql in [
            "INSERT INTO workloads (id,tenant_id,node_id,name,unit,account,consumption_mode,local_ceiling_seconds,registration_version,status,created_by,created_at) VALUES ('P06_DUMMY_WORKLOAD',?,'P06_DUMMY_NODE','dummy','dummy.service','dummy','file',60,1,'active','dummy',1)",
            "INSERT INTO exchanges (id,tenant_id,requester_agent_id,requester_public_key,secret_name,purpose,fulfiller_hint,policy_decision_json,policy_hash,status,created_at,expires_at,enc,ciphertext) VALUES ('P06_DUMMY_EXCHANGE',?,'dummy','dummy','dummy','dummy','dummy','{}','dummy','submitted',1,9999999999999,'P06_DUMMY_ENC','P06_DUMMY_CIPHERTEXT')",
            "INSERT INTO approvals (reference,tenant_id,requester_agent_id,secret_name,purpose,fulfiller_hint,reason,approver_ids_json,approver_rings_json,status,created_at,expires_at) VALUES ('P06_DUMMY_APPROVAL',?,'dummy','dummy','dummy','dummy','dummy','[]','[]','approved',1,9999999999999)",
            "INSERT INTO enrollment_requests (id,tenant_id,token_hash,created_by,created_at,expires_at,status) VALUES ('P06_DUMMY_ENROLL',?,'P06_DUMMY_HASH','dummy',1,9999999999999,'submitted')",
            "INSERT INTO policies (tenant_id,version,document_json,source,updated_at) VALUES (?,1,'{}','dummy',1)",
            "INSERT INTO fleet_policies (tenant_id,version,document_json,updated_at,updated_by) VALUES (?,1,'{}',1,'dummy')",
            "INSERT INTO node_challenges (id,tenant_id,node_id,nonce_hash,key_version,issuer_epoch,protocol_version,capabilities_json,capabilities_hash,created_at,expires_at) VALUES ('P06_DUMMY_CHALLENGE',?,'P06_DUMMY_NODE','P06_DUMMY_NONCE',1,1,'3','{}','P06_DUMMY_HASH',1,9999999999999)",
            "INSERT INTO fleet_source_bindings (tenant_id,node_id,resource_id,source_unit,credential,version,updated_at,updated_by) VALUES (?,'P06_DUMMY_NODE','P06_DUMMY_RESOURCE','dummy.service','dummy',1,1,'dummy')",
            "INSERT INTO idempotency_keys (tenant_id,actor_id,operation,key_hash,request_hash,response_json,created_at,expires_at) VALUES (?,'dummy','dummy','P06_DUMMY_HASH','P06_DUMMY_HASH','{}',1,9999999999999)",
            "INSERT INTO operations (id,tenant_id,workload_id,node_id,invocation_id,action,mode,requested_by,purpose,policy_version,decision,status,idempotency_key,request_hash,created_at,expires_at) VALUES ('P06_DUMMY_OPERATION',?,'P06_DUMMY_WORKLOAD','P06_DUMMY_NODE','dummy','dummy','file','dummy','dummy',1,'allow','completed','P06_DUMMY_IDEMPOTENCY','P06_DUMMY_HASH',1,9999999999999)",
            "INSERT INTO grants (id,tenant_id,operation_id,node_id,workload_id,invocation_id,account,resource_id,recipient_key_id,policy_version,request_use_id,unit,action,mode,audience,issuer_epoch,issued_at,expires_at,body_json,signature,status,created_at) VALUES ('P06_DUMMY_GRANT',?,'P06_DUMMY_OPERATION','P06_DUMMY_NODE','P06_DUMMY_WORKLOAD','dummy','dummy','P06_DUMMY_RESOURCE','dummy',1,'dummy','dummy.service','dummy','file','dummy',1,1,9999999999999,'{}','P06_DUMMY_SIGNATURE','issued',1)",
            "INSERT INTO operation_approvals (id,tenant_id,operation_ids_json,requester_summary_json,verified_identity_json,rule_id,status,expires_at,idempotency_key,created_at) VALUES ('P06_DUMMY_FLEET_APPROVAL',?,'[]','{}','{}','dummy','pending',9999999999999,'P06_DUMMY_APPROVAL_IDEMPOTENCY',1)",
            "INSERT INTO fleet_provisioning_offers (id,tenant_id,node_id,operation_id,grant_id,source_binding_version,offer_json,issued_at,expires_at,created_at) VALUES ('P06_DUMMY_OFFER',?,'P06_DUMMY_NODE','P06_DUMMY_OPERATION','P06_DUMMY_GRANT',1,'{}',1,9999999999999,1)",
            "INSERT INTO fleet_provisioning_links (id,tenant_id,node_id,operation_id,grant_id,offer_id,operator_id,idempotency_hash,expires_at,created_at) VALUES ('P06_DUMMY_LINK',?,'P06_DUMMY_NODE','P06_DUMMY_OPERATION','P06_DUMMY_GRANT','P06_DUMMY_OFFER','dummy','P06_DUMMY_HASH',9999999999999,1)",
        ] {
            sqlx::query(sql).bind(&tenant).execute(&pool).await.unwrap();
        }
        for sql in [
            "INSERT INTO node_sessions (id,node_id,nonce_hash,token_hash,created_at,expires_at) VALUES ('P06_DUMMY_SESSION','P06_DUMMY_NODE','P06_DUMMY_NONCE','P06_DUMMY_HASH',1,9999999999999)",
            "INSERT INTO node_inbox (node_id,seq,envelope_json,created_at) VALUES ('P06_DUMMY_NODE',1,'{}',1)",
            "INSERT INTO operator_sessions (id,operator_id,refresh_hash,csrf_secret,kind,created_at,expires_at,family_id,last_seen_at) VALUES ('P06_DUMMY_OPERATOR_SESSION','P06_DUMMY_OPERATOR','P06_DUMMY_HASH','P06_DUMMY_CSRF','browser',1,9999999999999,'P06_DUMMY_FAMILY',1)",
        ] {
            sqlx::query(sql).execute(&pool).await.unwrap();
        }
        sqlx::query(
            "UPDATE operations SET grant_id='P06_DUMMY_GRANT' WHERE id='P06_DUMMY_OPERATION'",
        )
        .execute(&pool)
        .await
        .unwrap();
        if audit_rows > 0 {
            let mut tx = pool.begin().await.unwrap();
            for row in 0..audit_rows {
                sqlx::query("INSERT INTO audit_events (id,tenant_id,actor_type,action,target_type,metadata_json,created_at) VALUES (?,?,'dummy','dummy','dummy','{}',1)")
                    .bind(format!("P06_DUMMY_AUDIT_{row}")).bind(&tenant).execute(&mut *tx).await.unwrap();
            }
            tx.commit().await.unwrap();
        }
        if schema < 19 {
            for table in ["controller_recovery_intents", "controller_recovery_reports"] {
                sqlx::query(&format!("DROP TABLE {table}"))
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        }
        if schema < 18 {
            sqlx::query("DROP TABLE controller_recovery_snapshots")
                .execute(&pool)
                .await
                .unwrap();
        }
        if schema == 16 {
            for table in [
                "controller_recovery_reviews",
                "controller_recovery_operations",
                "controller_recovery_nodes",
                "controller_recoveries",
            ] {
                sqlx::query(&format!("DROP TABLE {table}"))
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        }
        if schema != blindpass_controller::store::SCHEMA_VERSION {
            sqlx::query("UPDATE controller_meta SET schema_version=? WHERE id=1")
                .bind(schema)
                .execute(&pool)
                .await
                .unwrap();
        }
        let clock = sqlx::query_scalar("SELECT last_observed_ms FROM controller_clock WHERE id=1")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        let snapshot = capture_sqlite(&store, &members.join("database.sqlite"))
            .await
            .unwrap();
        write_archive(
            &members,
            &root.file("bundle.tar"),
            Backend::Sqlite,
            &snapshot,
        )
        .unwrap();
        initialize_recovery_key(&root.file("recovery.pem")).unwrap();
        let archive = root.file("archive.bpbackup");
        encrypt_bundle(
            &root.file("bundle.tar"),
            &archive,
            &root.file("recovery.pem"),
            &root.0,
        )
        .unwrap();
        store.close().await;
        let context = AuthorityContext {
            tenant_id: tenant.clone(),
            issuer_key_id: format!(
                "ed25519-{}",
                base64_url_encode(Ed25519KeyPair::from_seed(&[71; 32]).unwrap().public_key())
            ),
            owner_id: "P06_DUMMY_OWNER".into(),
        };
        let admin = PgPool::connect(&std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").unwrap())
            .await
            .unwrap();
        let (epoch, phase, issuer) =
            authority_override.unwrap_or((7, "fenced", &context.issuer_key_id));
        sqlx::query("INSERT INTO blindpass_authority.recovery_authority (tenant_id,issuer_key_id,owner_id,epoch,revision,phase) VALUES ($1,$2,$3,$4,1,$5)")
            .bind(&context.tenant_id).bind(issuer).bind(&context.owner_id).bind(epoch).bind(phase).execute(&admin).await.unwrap();
        let authority =
            Authority::connect_existing(&std::env::var("P06_TEST_AUTHORITY_URL").unwrap())
                .await
                .unwrap();
        if authority_override.is_none() {
            let record = authority.reserve_recovery(&context, 1, 7).await.unwrap();
            assert_eq!(record.epoch, 8);
        }
        private(
            &root.file("authority-url"),
            std::env::var("P06_TEST_AUTHORITY_URL").unwrap().as_bytes(),
        );
        Self {
            root,
            archive,
            tenant,
            context,
            admin,
            authority,
            clock,
        }
    }
    async fn assert_production_fenced(&self) {
        let target = self.root.file("destination");
        let db = target.join("data/controller.db");
        private(
            &self.root.file("restored-database-url"),
            format!("sqlite://{}?mode=rw", db.display()).as_bytes(),
        );
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut command = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
        command
            .env_clear()
            .arg("serve")
            .env("BLINDPASS_LISTEN", address.to_string())
            .env("BLINDPASS_PUBLIC_URL", "https://restore.p06.invalid")
            .env("BLINDPASS_UI_BASE_URL", "https://restore.p06.invalid")
            .env(
                "BLINDPASS_ROOT_SECRET_FILE",
                target.join("keys/root-secret"),
            )
            .env(
                "BLINDPASS_AGENT_JWT_SECRET_FILE",
                target.join("keys/agent-jwt-secret"),
            )
            .env("BLINDPASS_ISSUER_KEY_FILE", target.join("keys/issuer-key"))
            .env(
                "BLINDPASS_DATABASE_URL_FILE",
                self.root.file("restored-database-url"),
            )
            .env(
                "BLINDPASS_AUTHORITY_URL_FILE",
                self.root.file("authority-url"),
            )
            .env("BLINDPASS_CONTROLLER_TENANT_ID", &self.tenant)
            .env("BLINDPASS_CONTROLLER_OWNER_ID", &self.context.owner_id)
            .env(
                "BLINDPASS_ADMIN_SOCKET_PATH",
                self.root.file("restore-admin.sock"),
            )
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = OwnedChild(Some(command.spawn().unwrap()));
        let started = Instant::now();
        loop {
            assert!(
                child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "restored production controller stopped before diagnostics"
            );
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            assert!(
                started.elapsed().as_secs() < 8,
                "restored production listener failed to start"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            support::raw_request(address, "GET", "/healthz", &[], None)
                .await
                .status,
            200
        );
        let ready = support::raw_request(address, "GET", "/readyz", &[], None).await;
        assert_eq!(ready.status, 503);
        assert!(ready.body.to_string().contains("recovery_required"));
        assert_eq!(
            support::raw_request(address, "GET", "/api/auth/me", &[], None)
                .await
                .status,
            503
        );
        assert!(
            Command::new("/bin/kill")
                .args(["-TERM", &child.0.as_ref().unwrap().id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let started = Instant::now();
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                started.elapsed().as_secs() < 5,
                "fenced restored controller failed to stop"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let out = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "fenced restored controller shutdown failed"
        );
    }
    fn args(&self) -> Vec<String> {
        vec![
            "restore".into(),
            "--archive".into(),
            self.archive.display().to_string(),
            "--recovery-key-file".into(),
            self.root.file("recovery.pem").display().to_string(),
            "--destination".into(),
            self.root.file("destination").display().to_string(),
            "--authority-url-file".into(),
            self.root.file("authority-url").display().to_string(),
            "--tenant-id".into(),
            self.tenant.clone(),
            "--owner-id".into(),
            self.context.owner_id.clone(),
            "--recovery-id".into(),
            "P06_DUMMY_RESTORE".into(),
        ]
    }
    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
        c.env_clear().args(self.args());
        c
    }
    fn run(&self) -> Output {
        self.command().output().unwrap()
    }
    fn run_with(&self, flag: &str, value: &str) -> Output {
        let mut args = self.args();
        let index = args.iter().position(|s| s == flag).unwrap();
        args[index + 1] = value.into();
        Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
            .env_clear()
            .args(args)
            .output()
            .unwrap()
    }
    fn refused(&self, out: Output) {
        assert!(!out.status.success(), "unsafe restore was accepted");
        assert!(out.stdout.is_empty(), "restore refusal disclosed output");
        assert!(
            out.stderr == b"blindpass-controller: authenticated fenced restore refused\n",
            "restore refusal was not static"
        );
        assert!(
            !self.root.file("destination").exists(),
            "refused restore published state"
        );
    }
    async fn close(self) {
        self.authority.close().await;
        self.admin.close().await;
    }
}
struct OwnedChild(Option<std::process::Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(c) = self.0.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
fn private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
async fn number(path: &Path, sql: &str) -> i64 {
    let p = SqlitePool::connect(&format!("sqlite://{}?mode=ro", path.display()))
        .await
        .unwrap();
    let n = sqlx::query_scalar(sql).fetch_one(&p).await.unwrap();
    p.close().await;
    n
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08a_authenticated_snapshot_scope_survives_restore_and_restart() {
    for schema in [16, 17, 18] {
        let f = Fixture::with_schema(schema).await;
        let manifest = blindpass_controller::backup::verify_backup(
            &f.archive,
            &f.root.file("recovery.pem"),
            &f.root.0,
        )
        .await
        .unwrap();
        let digest = base64_url_encode(
            &blindpass_core::custody::sha256(&serde_json::to_vec(&manifest).unwrap()).unwrap(),
        );
        let original = fs::read(&f.archive).unwrap();
        assert!(f.run().status.success(), "authenticated restore failed");
        let db = f.root.file("destination/data/controller.db");
        assert_eq!(
            number(&db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='controller_recovery_snapshots'").await,
            1,
            "authenticated backup context must persist before destination publication"
        );
        async fn scope(path: &Path) -> (i64, i64, String, i64, String, i64) {
            let pool = SqlitePool::connect(&format!("sqlite://{}?mode=ro", path.display()))
                .await
                .unwrap();
            let row = sqlx::query_as("SELECT s.snapshot_epoch,s.snapshot_time_ms,s.backup_digest,r.prepared_at,r.phase,r.target_epoch FROM controller_recovery_snapshots s JOIN controller_recoveries r USING(recovery_id) WHERE r.recovery_id='P06_DUMMY_RESTORE'")
                .fetch_one(&pool).await.unwrap();
            pool.close().await;
            row
        }
        let before = scope(&db).await;
        assert_eq!(before.0 as u64, manifest.snapshot.recovery_generation);
        assert_eq!(before.1, manifest.snapshot.clock_ms);
        assert_eq!(before.2, digest);
        assert!(
            before.3 >= before.1,
            "local fence predates authenticated backup"
        );
        assert_eq!(before.4, "invalidated");
        assert_eq!(before.5, 8);
        f.assert_production_fenced().await;
        assert_eq!(scope(&db).await, before);
        assert_eq!(fs::read(&f.archive).unwrap(), original);
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08b_missing_tampered_and_unbound_snapshot_scope_is_refused() {
    use blindpass_controller::store::FleetSigner;
    use std::sync::Arc;
    for fault in [
        "missing",
        "epoch",
        "time",
        "digest",
        "signature",
        "context",
        "unbound",
        "wrong_holder",
    ] {
        let f = Fixture::new().await;
        assert!(f.run().status.success(), "authenticated restore failed");
        let record = f.authority.read(&f.context).await.unwrap();
        let owner = Arc::new(
            f.authority
                .claim_process(&f.context, &record)
                .await
                .unwrap(),
        );
        let url = format!(
            "sqlite://{}?mode=rw",
            f.root.file("destination/data/controller.db").display()
        );
        let signer = FleetSigner::new(Arc::new(Ed25519KeyPair::from_seed(&[71; 32]).unwrap()));
        let store =
            Store::connect_existing_owned(&url, 5000, owner.clone(), &f.context.issuer_key_id)
                .await
                .unwrap()
                .with_fleet_signer(signer.clone());
        let before = store.recovery_receipt_scope(&owner).await.unwrap();
        assert_eq!(before.recovery_id, "P06_DUMMY_RESTORE");
        if fault == "unbound" {
            let unbound = Store::connect_existing(&url, 5000)
                .await
                .unwrap()
                .with_fleet_signer(signer);
            assert!(unbound.recovery_receipt_scope(&owner).await.is_err());
            unbound.close().await;
            assert_eq!(store.recovery_receipt_scope(&owner).await.unwrap(), before);
        } else if fault == "wrong_holder" {
            let other = Fixture::new().await;
            let record = other.authority.read(&other.context).await.unwrap();
            let wrong = Arc::new(
                other
                    .authority
                    .claim_process(&other.context, &record)
                    .await
                    .unwrap(),
            );
            assert!(store.recovery_receipt_scope(&wrong).await.is_err());
            assert_eq!(store.recovery_receipt_scope(&owner).await.unwrap(), before);
            wrong.quiesce().await.unwrap();
            drop(wrong);
            other.close().await;
        } else {
            let sql = match fault {
                "missing" => "DELETE FROM controller_recovery_snapshots",
                "epoch" => {
                    "UPDATE controller_recovery_snapshots SET snapshot_epoch=snapshot_epoch+1"
                }
                "time" => {
                    "UPDATE controller_recovery_snapshots SET snapshot_time_ms=snapshot_time_ms+1"
                }
                "digest" => {
                    "UPDATE controller_recovery_snapshots SET backup_digest='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"
                }
                "signature" => {
                    "UPDATE controller_recovery_snapshots SET signature='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"
                }
                "context" => "UPDATE controller_recoveries SET owner_id='P06_DUMMY_OTHER_OWNER'",
                _ => unreachable!(),
            };
            let pool = SqlitePool::connect(&url).await.unwrap();
            sqlx::query(sql).execute(&pool).await.unwrap();
            pool.close().await;
            assert!(
                store.recovery_receipt_scope(&owner).await.is_err(),
                "tampered {fault} supplied authenticated collection scope"
            );
        }
        assert!(store.recovery_required());
        assert!(owner.begin_operation().is_err());
        owner.quiesce().await.unwrap();
        store.close().await;
        drop(owner);
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08c_scoped_store_collection_uses_protected_keys_and_keeps_quarantine() {
    use blindpass_controller::{recovery_authority::RecoveryReceiptState, store::FleetSigner};
    use std::sync::Arc;
    let f = Fixture::with_current_broker().await;
    assert!(f.run().status.success());
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    let url = format!(
        "sqlite://{}?mode=rw",
        f.root.file("destination/data/controller.db").display()
    );
    let store = Store::connect_existing_owned(&url, 5000, owner.clone(), &f.context.issuer_key_id)
        .await
        .unwrap()
        .with_fleet_signer(FleetSigner::new(Arc::new(
            Ed25519KeyPair::from_seed(&[71; 32]).unwrap(),
        )));
    let challenge = store
        .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
        .await
        .expect("signed local scope must admit protected recovering collection");
    assert_eq!(
        challenge.scope,
        store.recovery_receipt_scope(&owner).await.unwrap()
    );
    let page = scoped_page(&challenge);
    let signer = Ed25519KeyPair::from_seed(&[41; 32]).unwrap();
    let signature = signer.sign(&page.signing_message().unwrap()).unwrap();
    let forged = Ed25519KeyPair::from_seed(&[43; 32])
        .unwrap()
        .sign(&page.signing_message().unwrap())
        .unwrap();
    assert!(
        store
            .stage_recovery_report(&owner, &page, &forged)
            .await
            .is_err()
    );
    assert_eq!(
        store
            .stage_recovery_report(&owner, &page, &signature)
            .await
            .unwrap()
            .next_page,
        1
    );
    assert_eq!(
        store
            .stage_recovery_report(&owner, &page, &signature)
            .await
            .unwrap()
            .next_page,
        1
    );
    let receipt = store
        .finish_recovery_report(&owner, "P06_DUMMY_NODE")
        .await
        .unwrap();
    assert_eq!(receipt.state, RecoveryReceiptState::Covered);
    assert!(receipt.consumed);
    assert!(
        store
            .finish_recovery_report(&owner, "P06_DUMMY_NODE")
            .await
            .is_err()
    );
    let db = f.root.file("destination/data/controller.db");
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM controller_recovery_nodes WHERE state='quarantined'"
        )
        .await,
        1
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM operations WHERE status='uncertain'"
        )
        .await,
        1
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM grants WHERE status='revoked'").await,
        1
    );
    assert!(owner.begin_operation().is_err());
    assert!(store.recovery_required());
    owner.quiesce().await.unwrap();
    store.close().await;
    drop(owner);
    f.assert_production_fenced().await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08c_protected_foreign_snapshot_scope_refuses_before_page_mutation() {
    use blindpass_controller::store::FleetSigner;
    use std::sync::Arc;
    for fault in ["time", "digest"] {
        let f = Fixture::with_current_broker().await;
        assert!(f.run().status.success());
        let record = f.authority.read(&f.context).await.unwrap();
        let owner = Arc::new(
            f.authority
                .claim_process(&f.context, &record)
                .await
                .unwrap(),
        );
        let url = format!(
            "sqlite://{}?mode=rw",
            f.root.file("destination/data/controller.db").display()
        );
        let store =
            Store::connect_existing_owned(&url, 5000, owner.clone(), &f.context.issuer_key_id)
                .await
                .unwrap()
                .with_fleet_signer(FleetSigner::new(Arc::new(
                    Ed25519KeyPair::from_seed(&[71; 32]).unwrap(),
                )));
        let expected = store.recovery_receipt_scope(&owner).await.unwrap();
        let mut foreign = expected.clone();
        if fault == "time" {
            foreign.snapshot_time_ms += 1;
        } else {
            foreign.backup_digest = base64_url_encode(&[44; 32]);
        }
        let challenge = owner
            .open_recovery_challenge(&foreign, "P06_DUMMY_NODE", 1)
            .await
            .unwrap();
        let page = scoped_page(&challenge);
        let signature = Ed25519KeyPair::from_seed(&[41; 32])
            .unwrap()
            .sign(&page.signing_message().unwrap())
            .unwrap();
        assert!(
            store
                .stage_recovery_report(&owner, &page, &signature)
                .await
                .is_err(),
            "foreign {fault} challenge admitted through local signed archive scope"
        );
        let progress: (i64, bool) = sqlx::query_as("SELECT next_page,consumed FROM blindpass_authority.recovery_challenges WHERE tenant_id=$1 AND recovery_id=$2 AND node_id='P06_DUMMY_NODE'")
            .bind(&f.context.tenant_id).bind(&expected.recovery_id).fetch_one(&f.admin).await.unwrap();
        assert_eq!(progress.0, 0, "foreign scope page mutated before refusal");
        assert!(!progress.1);
        let retained = owner
            .recovery_challenge(&expected.recovery_id, "P06_DUMMY_NODE")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.next_page, 0);
        assert!(!retained.consumed);
        assert_eq!(retained.scope, foreign);
        assert!(store.recovery_required());
        owner.quiesce().await.unwrap();
        store.close().await;
        drop(owner);
        f.close().await;
    }
}

fn scoped_page(
    challenge: &blindpass_controller::recovery_authority::RecoveryChallenge,
) -> blindpass_core::recovery::pages::ReportPage {
    use blindpass_core::recovery::pages::{IntentRecord, PageDigest, ReportManifest, ReportPage};
    let records = vec![IntentRecord {
        grant_id: "P06_DUMMY_GRANT".into(),
        operation_id: Some("P06_DUMMY_OPERATION".into()),
        issuer_epoch: Some(1),
        expires_at_ms: 9999999999999,
    }];
    let mut manifest = ReportManifest {
        identity: challenge.identity.clone(),
        report_id: base64_url_encode(&[45; 32]),
        observed_issuer_epoch: 7,
        coverage: blindpass_core::recovery::pages::HistoryCoverage {
            history_id: Some(base64_url_encode(&[46; 32])),
            pruned_through_ms: 0,
            unmapped_records: 0,
        },
        total_records: 1,
        records_digest: base64_url_encode(&[0; 32]),
    };
    let mut digest = PageDigest::new(&manifest).unwrap();
    for record in &records {
        digest.push(record).unwrap();
    }
    manifest.records_digest = digest.finish().unwrap();
    ReportPage {
        manifest,
        page_index: 0,
        records,
    }
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08c_scoped_refusals_cannot_replace_challenge_or_consume_nonce() {
    use blindpass_controller::store::FleetSigner;
    use std::sync::Arc;
    let f = Fixture::with_current_broker().await;
    assert!(f.run().status.success());
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    let url = format!(
        "sqlite://{}?mode=rw",
        f.root.file("destination/data/controller.db").display()
    );
    let store = Store::connect_existing_owned(&url, 5000, owner.clone(), &f.context.issuer_key_id)
        .await
        .unwrap()
        .with_fleet_signer(FleetSigner::new(Arc::new(
            Ed25519KeyPair::from_seed(&[71; 32]).unwrap(),
        )));
    assert!(
        store
            .open_recovery_report(&owner, "P06_DUMMY_UNKNOWN", 1)
            .await
            .is_err()
    );
    assert!(
        store
            .open_recovery_report(&owner, "P06_DUMMY_NODE", 2)
            .await
            .is_err()
    );
    let challenge = store
        .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
        .await
        .unwrap();
    let original = scoped_page(&challenge);
    let signer = Ed25519KeyPair::from_seed(&[41; 32]).unwrap();
    for fault in ["recovery", "generation", "nonce", "node", "gap"] {
        let mut page = original.clone();
        match fault {
            "recovery" => page.manifest.identity.recovery_id = "P06_DUMMY_OTHER_RECOVERY".into(),
            "generation" => page.manifest.identity.recovery_generation += 1,
            "nonce" => page.manifest.identity.challenge = base64_url_encode(&[51; 32]),
            "node" => page.manifest.identity.node_id = "P06_DUMMY_UNKNOWN".into(),
            "gap" => page.page_index = 1,
            _ => unreachable!(),
        }
        // A gap cannot be encoded as a valid one-page report; use the original
        // signature to ensure the collector rejects it rather than truncates.
        let signature = if fault == "gap" {
            signer.sign(&original.signing_message().unwrap()).unwrap()
        } else {
            signer.sign(&page.signing_message().unwrap()).unwrap()
        };
        assert!(
            store
                .stage_recovery_report(&owner, &page, &signature)
                .await
                .is_err(),
            "scoped {fault} report admitted"
        );
        let retained = owner
            .recovery_challenge(&challenge.scope.recovery_id, "P06_DUMMY_NODE")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.next_page, 0);
        assert!(!retained.consumed);
    }
    assert!(
        store
            .finish_recovery_report(&owner, "P06_DUMMY_NODE")
            .await
            .is_err()
    );
    assert_eq!(
        store
            .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
            .await
            .unwrap(),
        challenge
    );
    assert!(store.recovery_required());
    owner.quiesce().await.unwrap();
    store.close().await;
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08c_actual_scoped_stage_socket_loss_preserves_uncertainty() {
    use blindpass_controller::store::FleetSigner;
    use std::{sync::Arc, time::Duration};
    let f = Fixture::with_current_broker().await;
    assert!(f.run().status.success());
    let runtime = PgPool::connect(&std::env::var("P06_TEST_AUTHORITY_URL").unwrap())
        .await
        .unwrap();
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&runtime)
        .await
        .unwrap();
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    let url = format!(
        "sqlite://{}?mode=rw",
        f.root.file("destination/data/controller.db").display()
    );
    let store = Store::connect_existing_owned(&url, 5000, owner.clone(), &f.context.issuer_key_id)
        .await
        .unwrap()
        .with_fleet_signer(FleetSigner::new(Arc::new(
            Ed25519KeyPair::from_seed(&[71; 32]).unwrap(),
        )));
    let challenge = store
        .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
        .await
        .unwrap();
    let page = scoped_page(&challenge);
    let signature = Ed25519KeyPair::from_seed(&[41; 32])
        .unwrap()
        .sign(&page.signing_message().unwrap())
        .unwrap();
    let mut blocker = f.admin.begin().await.unwrap();
    sqlx::query("SELECT tenant_id FROM blindpass_authority.recovery_challenges WHERE tenant_id=$1 AND recovery_id=$2 FOR UPDATE")
        .bind(&f.context.tenant_id).bind(&challenge.scope.recovery_id).execute(&mut *blocker).await.unwrap();
    let writer = {
        let store = store.clone();
        let owner = owner.clone();
        tokio::spawn(async move { store.stage_recovery_report(&owner, &page, &signature).await })
    };
    tokio::time::timeout(Duration::from_secs(2), async { loop {
        let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND a.usename=$1 AND NOT l.granted AND l.locktype='transactionid')")
            .bind(&role).fetch_one(&runtime).await.unwrap();
        if blocked { break; } tokio::time::sleep(Duration::from_millis(10)).await;
    }}).await.expect("actual scoped stage must reach its authority lock wait");
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=$1 AND usename=$2 AND datname=current_database()")
        .bind(owner.backend_pid()).bind(&role).fetch_one(&runtime).await.unwrap();
    assert!(terminated);
    assert!(owner.check().await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_secs(3), writer)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(owner.is_fenced());
    assert!(owner.has_uncertain_database_work());
    assert!(owner.quiesce().await.is_err());
    assert!(
        store
            .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
            .await
            .is_err()
    );
    blocker.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(4), async { loop {
        let running: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND a.usename=$1 AND l.relation='blindpass_authority.recovery_challenges'::regclass)")
            .bind(&role).fetch_one(&f.admin).await.unwrap();
        if !running { break; } tokio::time::sleep(Duration::from_millis(10)).await;
    }}).await.expect("owned uncertain scoped server work must end before inspection");
    let retained: (String, bool, i64) = sqlx::query_as("SELECT nonce,consumed,next_page FROM blindpass_authority.recovery_challenges WHERE tenant_id=$1 AND recovery_id=$2")
        .bind(&f.context.tenant_id).bind(&challenge.scope.recovery_id).fetch_one(&f.admin).await.unwrap();
    assert_eq!(retained.0, challenge.identity.challenge);
    assert!(!retained.1);
    assert!((0..=1).contains(&retained.2));
    assert!(owner.has_uncertain_database_work());
    store.close().await;
    drop(owner);
    runtime.close().await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_st01_actual_authenticated_restore_publishes_only_fenced_invalidated_state() {
    let f = Fixture::new().await;
    let before = fs::read(&f.archive).unwrap();
    let started = Instant::now();
    let out = f.run();
    assert!(
        out.status.success(),
        "authenticated fenced restore command failed"
    );
    assert!(
        started.elapsed().as_secs() < 60,
        "restore stage exceeded its actual process bound"
    );
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["phase"], "recovery_required");
    assert_eq!(summary["activation_permitted"], false);
    assert_eq!(summary["target_epoch"], 8);
    let target = f.root.file("destination");
    for p in [
        &target,
        target.join("keys").as_path(),
        target.join("data").as_path(),
    ] {
        assert_eq!(
            fs::metadata(p).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }
    for name in ["root-secret", "agent-jwt-secret", "issuer-key"] {
        let file = target.join("keys").join(name);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(
            fs::read(file).unwrap() == fs::read(f.root.file("members").join(name)).unwrap(),
            "restored key changed"
        );
    }
    let db = target.join("data/controller.db");
    assert_eq!(
        number(&db, "SELECT issuer_epoch FROM controller_meta WHERE id=1").await,
        8
    );
    assert_eq!(
        number(
            &db,
            "SELECT last_observed_ms FROM controller_clock WHERE id=1"
        )
        .await,
        f.clock
    );
    assert_eq!(number(&db, "SELECT COUNT(*) FROM secret_requests").await, 0);
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM bootstrap_tokens").await,
        0
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM agents WHERE status='revoked' AND key_version=2"
        )
        .await,
        1
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM operators WHERE disabled_at IS NOT NULL AND role='operator'"
        )
        .await,
        1
    );
    assert_eq!(number(&db,"SELECT COUNT(*) FROM controller_recoveries WHERE phase='invalidated' AND target_epoch=8").await,1);
    assert!(
        fs::read(&f.archive).unwrap() == before,
        "source encrypted archive changed"
    );
    assert_eq!(
        f.authority.read(&f.context).await.unwrap().phase,
        "recovering"
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM controller_recovery_nodes WHERE state='quarantined'"
        )
        .await,
        1
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM nodes WHERE status='active'").await,
        1
    );
    for table in [
        "exchanges",
        "approvals",
        "enrollment_requests",
        "operation_approvals",
        "operator_sessions",
        "node_sessions",
        "node_challenges",
        "idempotency_keys",
        "node_inbox",
        "fleet_provisioning_links",
        "fleet_provisioning_offers",
    ] {
        assert_eq!(
            number(&db, &format!("SELECT COUNT(*) FROM {table}")).await,
            0,
            "transient table survived restore: {table}"
        );
    }
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM operations WHERE status='uncertain' AND version=2"
        )
        .await,
        1
    );
    assert_eq!(number(&db,"SELECT COUNT(*) FROM controller_recovery_operations WHERE state='uncertain' AND snapshot_status='completed'").await,1);
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM grant_tombstones WHERE retain_until=9007199254740991"
        )
        .await,
        1
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM controller_recovery_reviews WHERE state='quarantined'"
        )
        .await,
        6
    );
    f.assert_production_fenced().await;
    f.close().await;
}

/// P06-D29 (ADR 0013): a split-custody archive restores only with the offline
/// recipient key and the pinned signer, stages decrypted material on tmpfs only
/// and leaves no key material behind on any refusal.
#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_d29_r01_split_custody_restore_uses_tmpfs_staging_and_leaves_no_residue() {
    use blindpass_controller::backup::{
        KeyRole, SealKeys, encrypt_bundle_with, initialize_role_credentials,
    };
    let f = Fixture::new().await;
    let file = |name: &str| f.root.file(name);
    for (role, key, certificate) in [
        (KeyRole::Signing, "signing.pem", "signing-certificate.pem"),
        (
            KeyRole::Recipient,
            "recipient.pem",
            "recipient-certificate.pem",
        ),
        (
            KeyRole::Signing,
            "other-signing.pem",
            "other-signing-certificate.pem",
        ),
    ] {
        initialize_role_credentials(role, &file(key), &file(certificate)).unwrap();
    }
    let split = file("split.bpbackup");
    encrypt_bundle_with(
        &file("bundle.tar"),
        &split,
        &SealKeys::Split {
            signing_credential: &file("signing.pem"),
            recipient_certificate: &file("recipient-certificate.pem"),
        },
        &f.root.0,
    )
    .unwrap();
    let digest = blindpass_controller::backup::archive_sha256(&split, &f.root.0).unwrap();
    let staging = std::path::PathBuf::from(format!("/dev/shm/p06-d29-r01-{}", std::process::id()));
    let args = |key: &str, signer: &str, extra: &[(&str, &str)]| -> Vec<String> {
        let mut args = f.args();
        let at = args.iter().position(|a| a == "--archive").unwrap();
        args[at + 1] = split.display().to_string();
        let at = args
            .iter()
            .position(|a| a == "--recovery-key-file")
            .unwrap();
        args.splice(
            at..=at + 1,
            [
                "--recipient-key-file".to_owned(),
                file(key).display().to_string(),
                "--signing-certificate-file".into(),
                file(signer).display().to_string(),
                "--staging-directory".into(),
                staging.display().to_string(),
            ],
        );
        for (flag, value) in extra {
            args.extend([(*flag).to_owned(), (*value).to_owned()]);
        }
        args
    };
    let run = |args: Vec<String>| {
        Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
            .env_clear()
            .args(args)
            .output()
            .unwrap()
    };
    let residue = |when: &str| {
        assert!(
            !staging.exists() || fs::read_dir(&staging).unwrap().count() == 0,
            "tmpfs staging kept decrypted material {when}"
        );
    };
    // The backup host's own credential, the wrong signer, a legacy credential next
    // to the split pair and a wrong digest pin each refuse and publish nothing.
    f.refused(run(args("signing.pem", "signing-certificate.pem", &[])));
    residue("after the host credential was refused");
    f.refused(run(args(
        "recipient.pem",
        "other-signing-certificate.pem",
        &[],
    )));
    residue("after the wrong signer was refused");
    let bad_digest = "0".repeat(64);
    f.refused(run(args(
        "recipient.pem",
        "signing-certificate.pem",
        &[("--expected-archive-sha256", &bad_digest)],
    )));
    f.refused(run(args(
        "recipient.pem",
        "signing-certificate.pem",
        &[(
            "--recovery-key-file",
            file("recovery.pem").to_str().unwrap(),
        )],
    )));
    // Persistent-disk staging is refused before anything is decrypted.
    let disk = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("p06-d29-r01-disk-{}", std::process::id()));
    let mut on_disk = args("recipient.pem", "signing-certificate.pem", &[]);
    let at = on_disk
        .iter()
        .position(|a| a == "--staging-directory")
        .unwrap();
    on_disk[at + 1] = disk.display().to_string();
    f.refused(run(on_disk));
    assert!(
        !disk.exists(),
        "a refused disk staging directory was created"
    );
    // The offline recipient key, the pinned signer and the recorded digest restore it.
    let out = run(args(
        "recipient.pem",
        "signing-certificate.pem",
        &[("--expected-archive-sha256", &digest)],
    ));
    assert!(out.status.success(), "split-custody restore failed");
    let target = f.root.file("destination");
    for name in ["root-secret", "agent-jwt-secret", "issuer-key"] {
        assert_eq!(
            fs::read(target.join("keys").join(name)).unwrap(),
            fs::read(f.root.file("members").join(name)).unwrap(),
            "{name} not restored"
        );
    }
    assert!(target.join("data/controller.db").exists());
    residue("after a successful restore");
    let _ = fs::remove_dir(&staging);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_st02_authenticated_input_context_and_authority_refusals_publish_nothing() {
    let f = Fixture::new().await;
    let original = fs::read(&f.archive).unwrap();
    let mut corrupted = original.clone();
    let offset = corrupted.len() / 2;
    corrupted[offset] ^= 1;
    private(&f.root.file("corrupted.bpbackup"), &corrupted);
    f.refused(f.run_with(
        "--archive",
        f.root.file("corrupted.bpbackup").to_str().unwrap(),
    ));
    // Valid CMS authentication around an unsafe USTAR name must still refuse.
    let mut unsafe_tar = fs::read(f.root.file("bundle.tar")).unwrap();
    unsafe_tar[..100].fill(0);
    unsafe_tar[..16].copy_from_slice(b"../manifest.json");
    unsafe_tar[148..156].fill(b' ');
    let checksum: u64 = unsafe_tar[..512].iter().map(|b| u64::from(*b)).sum();
    unsafe_tar[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    private(&f.root.file("unsafe.tar"), &unsafe_tar);
    encrypt_bundle(
        &f.root.file("unsafe.tar"),
        &f.root.file("unsafe.bpbackup"),
        &f.root.file("recovery.pem"),
        &f.root.0,
    )
    .unwrap();
    f.refused(f.run_with(
        "--archive",
        f.root.file("unsafe.bpbackup").to_str().unwrap(),
    ));
    initialize_recovery_key(&f.root.file("wrong-recipient.pem")).unwrap();
    f.refused(f.run_with(
        "--recovery-key-file",
        f.root.file("wrong-recipient.pem").to_str().unwrap(),
    ));
    f.refused(f.run_with("--tenant-id", "P06_DUMMY_WRONG_TENANT"));
    f.refused(f.run_with("--owner-id", "P06_DUMMY_WRONG_OWNER"));
    f.refused(f.run_with(
        "--authority-url-file",
        f.root.file("missing").to_str().unwrap(),
    ));
    private(
        &f.root.file("administrator-url"),
        std::env::var("P06_TEST_AUTHORITY_ADMIN_URL")
            .unwrap()
            .as_bytes(),
    );
    f.refused(f.run_with(
        "--authority-url-file",
        f.root.file("administrator-url").to_str().unwrap(),
    ));
    private(
        &f.root.file("unreachable-url"),
        b"postgresql://P06_DUMMY_USER:P06_DUMMY_PASSWORD@127.0.0.1:1/P06_DUMMY_DATABASE",
    );
    let started = Instant::now();
    f.refused(f.run_with(
        "--authority-url-file",
        f.root.file("unreachable-url").to_str().unwrap(),
    ));
    assert!(started.elapsed().as_secs() < 5);
    assert!(
        fs::read(&f.archive).unwrap() == original,
        "source archive changed on refusal"
    );
    assert_eq!(
        fs::read_dir(&f.root.0)
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .starts_with(".backup-"))
            .count(),
        0
    );
    f.close().await;
    // Fresh protected contexts exercise invalid candidates without bypassing
    // the authority's anti-rollback/immutable-identity triggers.
    for (epoch, phase) in [(1, "recovering"), (8, "active"), (8, "fenced")] {
        let f = Fixture::with_options(
            17,
            Some((
                epoch,
                phase,
                &format!(
                    "ed25519-{}",
                    base64_url_encode(Ed25519KeyPair::from_seed(&[71; 32]).unwrap().public_key())
                ),
            )),
            0,
        )
        .await;
        f.refused(f.run());
        f.close().await;
    }
    let f = Fixture::with_options(17, Some((8, "recovering", "P06_DUMMY_WRONG_KEY")), 0).await;
    f.refused(f.run());
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_st03_private_destination_and_credential_custody_preserve_existing_state() {
    use blindpass_core::deployment::Directory;
    use std::os::unix::fs::{MetadataExt, symlink};
    let f = Fixture::new().await;
    let target = f.root.file("destination");
    fs::create_dir(&target).unwrap();
    let inode = fs::metadata(&target).unwrap().ino();
    let out = f.run();
    assert!(!out.status.success());
    assert_eq!(fs::metadata(&target).unwrap().ino(), inode);
    fs::remove_dir(&target).unwrap();
    private(&target, b"P06_DUMMY_PRESERVED_STATE");
    let out = f.run();
    assert!(!out.status.success());
    assert_eq!(fs::read(&target).unwrap(), b"P06_DUMMY_PRESERVED_STATE");
    fs::remove_file(&target).unwrap();
    symlink("missing", &target).unwrap();
    let out = f.run();
    assert!(!out.status.success());
    assert!(
        fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fs::remove_file(&target).unwrap();
    let parent = Directory::open_private(&f.root.0).unwrap();
    parent.lock(true).unwrap();
    f.refused(f.run());
    drop(parent);
    fs::set_permissions(&f.root.0, fs::Permissions::from_mode(0o755)).unwrap();
    f.refused(f.run());
    fs::set_permissions(&f.root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let credential = f.root.file("authority-url");
    fs::hard_link(&credential, f.root.file("linked-credential")).unwrap();
    f.refused(f.run());
    fs::remove_file(f.root.file("linked-credential")).unwrap();
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o644)).unwrap();
    f.refused(f.run());
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&f.root.0, f.root.file("linked-parent")).unwrap();
    let out = f.run_with(
        "--destination",
        f.root.file("linked-parent/destination").to_str().unwrap(),
    );
    f.refused(out);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_st04_live_competing_recovery_holder_prevents_publication() {
    let f = Fixture::new().await;
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = f
        .authority
        .claim_process(&f.context, &record)
        .await
        .unwrap();
    let started = Instant::now();
    f.refused(f.run());
    assert!(started.elapsed().as_secs() < 5);
    owner.check().await.unwrap();
    owner.quiesce().await.unwrap();
    assert!(
        f.run().status.success(),
        "restore remained blocked after genuine holder release"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_st06_authenticated_schema16_forward_migration_retains_original_archive() {
    let f = Fixture::with_schema(16).await;
    let original = fs::read(&f.archive).unwrap();
    assert!(
        f.run().status.success(),
        "authenticated isolated schema16 restore failed"
    );
    let db = f.root.file("destination/data/controller.db");
    assert_eq!(
        number(&db, "SELECT schema_version FROM controller_meta WHERE id=1").await,
        blindpass_controller::store::SCHEMA_VERSION
    );
    assert_eq!(
        number(&db, "SELECT issuer_epoch FROM controller_meta WHERE id=1").await,
        8
    );
    assert_eq!(
        number(
            &db,
            "SELECT last_observed_ms FROM controller_clock WHERE id=1"
        )
        .await,
        f.clock
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM controller_recoveries WHERE phase='invalidated'"
        )
        .await,
        1
    );
    assert!(
        fs::read(&f.archive).unwrap() == original,
        "pre-upgrade encrypted backup changed"
    );
    assert_eq!(
        number(
            &f.root.file("source.db"),
            "SELECT schema_version FROM controller_meta WHERE id=1"
        )
        .await,
        16
    );
    f.close().await;
    let future_schema = format!(
        "UPDATE controller_meta SET schema_version={} WHERE id=1",
        blindpass_controller::store::SCHEMA_VERSION + 1
    );
    for damage in [
        future_schema.as_str(),
        "DROP TABLE controller_clock",
        "UPDATE controller_meta SET tenant_id='P06_DUMMY_OTHER_TENANT' WHERE id=1",
        "UPDATE controller_meta SET issuer_epoch=2 WHERE id=1",
    ] {
        let f = Fixture::new().await;
        let original = fs::read(&f.archive).unwrap();
        let members = f.root.file("members");
        let db = members.join("database.sqlite");
        let snapshot = blindpass_controller::backup::inspect_sqlite(&db)
            .await
            .unwrap();
        let pool = SqlitePool::connect(&format!("sqlite://{}?mode=rw", db.display()))
            .await
            .unwrap();
        sqlx::query(damage).execute(&pool).await.unwrap();
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        // A valid authenticated archive and member digests do not excuse
        // unsupported schema, lost state or unequal snapshot identity/epoch.
        write_archive(
            &members,
            &f.root.file("damaged.tar"),
            Backend::Sqlite,
            &snapshot,
        )
        .unwrap();
        encrypt_bundle(
            &f.root.file("damaged.tar"),
            &f.root.file("damaged.bpbackup"),
            &f.root.file("recovery.pem"),
            &f.root.0,
        )
        .unwrap();
        f.refused(f.run_with(
            "--archive",
            f.root.file("damaged.bpbackup").to_str().unwrap(),
        ));
        assert!(fs::read(&f.archive).unwrap() == original);
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority and util-linux prlimit"]
async fn p06_st07_actual_restore_with_10000_audit_rows_and_512mib_process_limit() {
    let f = Fixture::with_options(17, None, 10000).await;
    let started = Instant::now();
    let out = Command::new("/usr/bin/prlimit")
        .env_clear()
        .env("TOKIO_WORKER_THREADS", "2")
        .args([
            "--as=536870912",
            "--",
            env!("CARGO_BIN_EXE_blindpass-controller"),
        ])
        .args(f.args())
        .output()
        .unwrap();
    assert!(out.status.success(), "512 MiB address-space restore failed");
    assert!(started.elapsed().as_secs() < 60);
    assert_eq!(
        number(
            &f.root.file("destination/data/controller.db"),
            "SELECT COUNT(*) FROM audit_events WHERE actor_type='dummy'"
        )
        .await,
        10000
    );
    println!(
        "st07_process_address_space_bytes=536870912 tokio_worker_threads=2 audit_rows=10000 restore_seconds={:.3}",
        started.elapsed().as_secs_f64()
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority and built colocated CLI"]
async fn p06_st08_colocated_cli_forwards_real_fenced_restore_and_refuses_overwrite() {
    let f = Fixture::new().await;
    let cli = Path::new(env!("CARGO_BIN_EXE_blindpass-controller")).with_file_name("blindpass");
    assert!(
        cli.is_file(),
        "build the actual colocated CLI before this gate"
    );
    let mut command = Command::new(&cli);
    command.env_clear().args(f.args());
    if !cfg!(feature = "p02-test-failpoints") {
        // A normal binary must ignore every dedicated crash-build hook.
        command
            .env("BLINDPASS_TEST_MODE", "1")
            .env("BLINDPASS_TEST_FAILPOINT", "restore_before_publish");
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "colocated restore command failed");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["phase"], "recovery_required");
    assert_eq!(summary["activation_permitted"], false);
    let before = fs::read(f.root.file("destination/restore.json")).unwrap();
    let out = Command::new(&cli)
        .env_clear()
        .args(f.args())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(fs::read(f.root.file("destination/restore.json")).unwrap() == before);
    f.close().await;
}

#[cfg(feature = "p02-test-failpoints")]
#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority and dedicated crash-test feature"]
async fn p06_st05_crashes_leave_private_fenced_staging_and_preserve_source_archive() {
    use blindpass_core::deployment::Directory;
    for failpoint in [
        "restore_after_extract",
        "restore_after_invalidate",
        "restore_before_publish",
    ] {
        let f = Fixture::new().await;
        let original = fs::read(&f.archive).unwrap();
        // ADR 0013: decrypted material is staged on tmpfs, never in the persistent root.
        let memory = std::path::PathBuf::from(format!(
            "/dev/shm/p06-st05-{}-{failpoint}",
            std::process::id()
        ));
        let out = f
            .command()
            .args(["--staging-directory", memory.to_str().unwrap()])
            .env("BLINDPASS_TEST_MODE", "1")
            .env("BLINDPASS_TEST_FAILPOINT", failpoint)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(86),
            "dedicated restore crash did not fire"
        );
        assert!(out.stdout.is_empty());
        assert!(!f.root.file("destination").exists());
        let stages: Vec<_> = fs::read_dir(&f.root.0)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with(".backup-")
            })
            .collect();
        assert!(!stages.is_empty(), "crash residue was not identifiable");
        let mut pending = stages;
        let mut fenced_database = false;
        while let Some(path) = pending.pop() {
            let m = fs::symlink_metadata(&path).unwrap();
            assert!(!m.file_type().is_symlink());
            if m.is_dir() {
                assert_eq!(m.permissions().mode() & 0o7777, 0o700);
                pending.extend(fs::read_dir(path).unwrap().map(|e| e.unwrap().path()));
            } else {
                assert_eq!(m.permissions().mode() & 0o7777, 0o600);
                let is_key = ["root-secret", "agent-jwt-secret", "issuer-key"]
                    .contains(&path.file_name().unwrap().to_str().unwrap());
                // Keys reach persistent disk only in the last step before publication.
                assert!(
                    !is_key || failpoint == "restore_before_publish",
                    "controller key persisted on disk at {failpoint}"
                );
                if path.file_name().unwrap() == "controller.db"
                    && failpoint != "restore_after_extract"
                {
                    assert_eq!(number(&path,"SELECT COUNT(*) FROM controller_recoveries WHERE phase='invalidated' AND target_epoch=8").await,1);
                    fenced_database = true;
                }
            }
        }
        assert!(failpoint == "restore_after_extract" || fenced_database);
        assert!(fs::read(&f.archive).unwrap() == original);
        // The killed process cannot clean its tmpfs stage; the same explicit cleanup
        // command removes it, and nothing of it ever reached the persistent root.
        let memory_residue = |count: usize| {
            assert_eq!(
                fs::read_dir(&memory)
                    .unwrap()
                    .filter(|e| e
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_str()
                        .unwrap()
                        .starts_with(".backup-"))
                    .count(),
                count
            );
        };
        memory_residue(1);
        let wiped = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
            .env_clear()
            .args([
                "backup",
                "cleanup",
                "--work-directory",
                memory.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(wiped.status.success(), "tmpfs residue cleanup failed");
        memory_residue(0);
        fs::remove_dir(&memory).unwrap();
        let custody = Directory::open_private(&f.root.0).unwrap();
        custody.lock(true).unwrap();
        let cleanup = || {
            Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
                .env_clear()
                .args([
                    "backup",
                    "cleanup",
                    "--work-directory",
                    f.root.0.to_str().unwrap(),
                ])
                .output()
                .unwrap()
        };
        assert!(
            !cleanup().status.success(),
            "cleanup ignored active custody"
        );
        drop(custody);
        assert!(
            cleanup().status.success(),
            "explicit residue cleanup failed"
        );
        assert_eq!(
            fs::read_dir(&f.root.0)
                .unwrap()
                .filter(|e| e
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with(".backup-"))
                .count(),
            0
        );
        assert!(
            f.run().status.success(),
            "clean retry after interrupted staging failed"
        );
        println!(
            "st05_failpoint={failpoint} source_preserved=true private_residue=true destination_absent=true explicit_cleanup=true retry_fenced=true"
        );
        f.close().await;
    }
}

#[cfg(feature = "p02-test-failpoints")]
#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority and dedicated fault-test feature"]
async fn p06_st04_lost_external_socket_before_publication_refuses_destination() {
    let f = Fixture::new().await;
    let original = fs::read(&f.archive).unwrap();
    let mut command = f.command();
    let child = command
        .env("BLINDPASS_TEST_MODE", "1")
        .env("BLINDPASS_TEST_FAILPOINT", "restore_pause_before_publish")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = OwnedChild(Some(child));
    let pid = child.0.as_ref().unwrap().id();
    let started = Instant::now();
    loop {
        assert!(
            child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "restore stopped before fault barrier"
        );
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        if status
            .lines()
            .any(|s| s.starts_with("State:") && s.contains('T'))
        {
            break;
        }
        assert!(
            started.elapsed().as_secs() < 8,
            "restore did not reach publication fault barrier"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // Only this disposable database has a recovering holder. Its exact live
    // backend must be independently observed before terminating that socket.
    let probe = PgPool::connect(&std::env::var("P06_TEST_AUTHORITY_URL").unwrap())
        .await
        .unwrap();
    let backends:Vec<i32>=sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND state='idle in transaction' AND query LIKE 'SELECT pg_backend_pid() FROM blindpass_authority.recovery_authority AS ledger%'")
        .fetch_all(&probe).await.unwrap();
    assert_eq!(
        backends.len(),
        1,
        "could not identify the owned recovery socket"
    );
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(backends[0])
        .fetch_one(&probe)
        .await
        .unwrap();
    probe.close().await;
    assert!(terminated);
    assert!(
        Command::new("/bin/kill")
            .args(["-CONT", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let started = Instant::now();
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(
            started.elapsed().as_secs() < 5,
            "lost-proof restore failed to refuse within bound"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    f.refused(child.0.take().unwrap().wait_with_output().unwrap());
    assert!(fs::read(&f.archive).unwrap() == original);
    assert_eq!(
        fs::read_dir(&f.root.0)
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .starts_with(".backup-"))
            .count(),
        0
    );
    println!(
        "st04_owned_authority_socket_terminated=true destination_absent=true static_refusal=true source_preserved=true"
    );
    f.close().await;
}

async fn application_fixture() -> (
    Fixture,
    Store,
    std::sync::Arc<blindpass_controller::recovery_authority::ProcessOwnership>,
) {
    use blindpass_controller::store::FleetSigner;
    use std::sync::Arc;
    let f = Fixture::with_current_broker().await;
    assert!(f.run().status.success());
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    let url = format!(
        "sqlite://{}?mode=rw",
        f.root.file("destination/data/controller.db").display()
    );
    let store = Store::connect_existing_owned(&url, 5000, owner.clone(), &f.context.issuer_key_id)
        .await
        .unwrap()
        .with_fleet_signer(FleetSigner::new(Arc::new(
            Ed25519KeyPair::from_seed(&[71; 32]).unwrap(),
        )));
    (f, store, owner)
}

async fn cover_application_records(
    store: &Store,
    owner: &std::sync::Arc<blindpass_controller::recovery_authority::ProcessOwnership>,
    records: Vec<blindpass_core::recovery::pages::IntentRecord>,
) -> blindpass_controller::recovery_authority::RecoveryChallenge {
    use blindpass_core::recovery::pages::{PageDigest, RECORDS_PER_PAGE, ReportPage};
    let challenge = store
        .open_recovery_report(owner, "P06_DUMMY_NODE", 1)
        .await
        .unwrap();
    let mut manifest = scoped_page(&challenge).manifest;
    manifest.total_records = records.len() as u64;
    manifest.coverage.unmapped_records = records
        .iter()
        .filter(|record| record.operation_id.is_none())
        .count() as u64;
    let mut digest = PageDigest::new(&manifest).unwrap();
    for record in &records {
        digest.push(record).unwrap();
    }
    manifest.records_digest = digest.finish().unwrap();
    for (index, records) in records.chunks(RECORDS_PER_PAGE as usize).enumerate() {
        let page = ReportPage {
            manifest: manifest.clone(),
            page_index: index as u64,
            records: records.to_vec(),
        };
        let signature = Ed25519KeyPair::from_seed(&[41; 32])
            .unwrap()
            .sign(&page.signing_message().unwrap())
            .unwrap();
        store
            .stage_recovery_report(owner, &page, &signature)
            .await
            .unwrap();
    }
    store
        .finish_recovery_report(owner, "P06_DUMMY_NODE")
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08d_application_exact_mapping_is_durable_and_never_admits() {
    let (f, store, owner) = application_fixture().await;
    let challenge = store
        .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
        .await
        .unwrap();
    cover_application_records(&store, &owner, scoped_page(&challenge).records).await;
    let summary = store
        .apply_recovery_report(&owner, "P06_DUMMY_NODE")
        .await
        .expect("covered receipt must reverify and apply exact local quarantine metadata");
    assert_eq!(
        (
            summary.matched,
            summary.unknown,
            summary.conflicting,
            summary.unmapped
        ),
        (1, 0, 0, 0)
    );
    assert_eq!(
        store
            .apply_recovery_report(&owner, "P06_DUMMY_NODE")
            .await
            .unwrap(),
        summary
    );
    let db = f.root.file("destination/data/controller.db");
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM controller_recovery_intents WHERE mapping='matched'"
        )
        .await,
        1
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM controller_recovery_reports WHERE state='quarantined'"
        )
        .await,
        1
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM grants WHERE status='revoked'").await,
        1
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM operations WHERE status='uncertain'"
        )
        .await,
        1
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM controller_recovery_nodes WHERE state='quarantined'"
        )
        .await,
        1
    );
    assert!(owner.begin_operation().is_err());
    owner.quiesce().await.unwrap();
    store.close().await;
    drop(owner);
    f.assert_production_fenced().await;
    // Reacquisition independently resumes the already consumed authority nonce.
    use blindpass_controller::store::FleetSigner;
    use std::sync::Arc;
    let record = f.authority.read(&f.context).await.unwrap();
    let owner = Arc::new(
        f.authority
            .claim_process(&f.context, &record)
            .await
            .unwrap(),
    );
    let store = Store::connect_existing_owned(
        &format!("sqlite://{}?mode=rw", db.display()),
        5000,
        owner.clone(),
        &f.context.issuer_key_id,
    )
    .await
    .unwrap()
    .with_fleet_signer(FleetSigner::new(Arc::new(
        Ed25519KeyPair::from_seed(&[71; 32]).unwrap(),
    )));
    assert_eq!(
        store
            .apply_recovery_report(&owner, "P06_DUMMY_NODE")
            .await
            .unwrap(),
        summary
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM controller_recovery_intents").await,
        1
    );
    owner.quiesce().await.unwrap();
    store.close().await;
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08d_application_conflicting_and_unknown_records_stay_metadata() {
    for fault in ["node", "operation", "epoch", "expiry", "unknown"] {
        let (f, store, owner) = application_fixture().await;
        let db = f.root.file("destination/data/controller.db");
        let challenge = store
            .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
            .await
            .unwrap();
        let mut records = scoped_page(&challenge).records;
        match fault {
            "node" => {
                let p = SqlitePool::connect(&format!("sqlite://{}", db.display()))
                    .await
                    .unwrap();
                sqlx::query("INSERT INTO nodes (id,tenant_id,name,signing_pub,recipient_pub,key_version,status,protocol_version,capabilities_json,created_at) VALUES ('P06_DUMMY_OTHER_NODE',?,'dummy','dummy','dummy',1,'revoked','1','{}',1)").bind(&f.tenant).execute(&p).await.unwrap();
                sqlx::query("UPDATE grants SET node_id='P06_DUMMY_OTHER_NODE'")
                    .execute(&p)
                    .await
                    .unwrap();
                p.close().await;
            }
            "operation" => records[0].operation_id = Some("P06_DUMMY_OTHER_OPERATION".into()),
            "epoch" => records[0].issuer_epoch = Some(2),
            "expiry" => records[0].expires_at_ms -= 1,
            "unknown" => records[0].grant_id = "P06_DUMMY_POST_BACKUP_GRANT".into(),
            _ => unreachable!(),
        }
        cover_application_records(&store, &owner, records).await;
        let summary = store
            .apply_recovery_report(&owner, "P06_DUMMY_NODE")
            .await
            .unwrap();
        assert_eq!(summary.matched, 0, "{fault} admitted exact mapping");
        assert_eq!(summary.unknown, u64::from(fault == "unknown"));
        assert_eq!(summary.conflicting, u64::from(fault != "unknown"));
        assert_eq!(number(&db, "SELECT COUNT(*) FROM grants").await, 1);
        assert_eq!(
            number(
                &db,
                "SELECT COUNT(*) FROM operations WHERE status='uncertain'"
            )
            .await,
            1
        );
        assert!(owner.begin_operation().is_err());
        owner.quiesce().await.unwrap();
        store.close().await;
        drop(owner);
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08d_application_reverifies_late_page_before_any_local_commit() {
    use blindpass_core::recovery::pages::IntentRecord;
    let (f, store, owner) = application_fixture().await;
    let challenge = store
        .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
        .await
        .unwrap();
    let mut records = scoped_page(&challenge).records;
    for index in 0..128 {
        records.push(IntentRecord {
            grant_id: format!("Z_DUMMY_UNKNOWN_{index:03}"),
            operation_id: Some("Z_DUMMY_OPERATION".into()),
            issuer_epoch: Some(1),
            expires_at_ms: 9999999999999,
        });
    }
    let receipt = cover_application_records(&store, &owner, records).await;
    assert!(receipt.consumed);
    assert_eq!(receipt.next_page, 2);
    // Administrator fixture fault only: runtime cannot mutate protected receipts.
    let mut tx = f.admin.begin().await.unwrap();
    sqlx::query("ALTER TABLE blindpass_authority.recovery_pages DISABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_pages SET signature=$1 WHERE tenant_id=$2 AND recovery_id=$3 AND page_index=1")
        .bind(base64_url_encode(&[44;64])).bind(&f.tenant).bind(&receipt.scope.recovery_id).execute(&mut *tx).await.unwrap();
    sqlx::query("ALTER TABLE blindpass_authority.recovery_pages ENABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        store
            .apply_recovery_report(&owner, "P06_DUMMY_NODE")
            .await
            .is_err(),
        "tampered covered page admitted local application"
    );
    let db = f.root.file("destination/data/controller.db");
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM controller_recovery_intents").await,
        0,
        "earlier valid page committed before late verification"
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM controller_recovery_reports").await,
        0
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM grants WHERE status='revoked'").await,
        1
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM operations WHERE status='uncertain'"
        )
        .await,
        1
    );
    assert!(owner.begin_operation().is_err());
    // Reverification conflict performs no external mutation.
    assert!(!owner.has_uncertain_database_work());
    if !owner.is_fenced() {
        owner.quiesce().await.unwrap();
    }
    store.close().await;
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08d_application_final_transaction_fault_rolls_back_but_retains_uncertainty() {
    let (f, store, owner) = application_fixture().await;
    let challenge = store
        .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
        .await
        .unwrap();
    let receipt = cover_application_records(&store, &owner, scoped_page(&challenge).records).await;
    let db = f.root.file("destination/data/controller.db");
    let local = SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER application_final_fault BEFORE UPDATE ON controller_recovery_reports BEGIN SELECT RAISE(ABORT,'P06_DUMMY_FINAL_FAULT'); END")
        .execute(&local).await.unwrap();
    assert!(
        store
            .apply_recovery_report(&owner, "P06_DUMMY_NODE")
            .await
            .is_err()
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM controller_recovery_intents").await,
        0
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM controller_recovery_reports").await,
        0
    );
    let retained:(bool,String)=sqlx::query_as("SELECT consumed,nonce FROM blindpass_authority.recovery_challenges WHERE tenant_id=$1 AND recovery_id=$2 AND node_id='P06_DUMMY_NODE'")
        .bind(&f.tenant).bind(&receipt.scope.recovery_id).fetch_one(&f.admin).await.unwrap();
    assert!(retained.0);
    assert_eq!(retained.1, receipt.identity.challenge);
    assert!(owner.is_fenced());
    assert!(owner.has_uncertain_database_work());
    assert!(owner.quiesce().await.is_err());
    assert!(owner.begin_operation().is_err());
    assert!(
        store
            .apply_recovery_report(&owner, "P06_DUMMY_NODE")
            .await
            .is_err()
    );
    local.close().await;
    store.close().await;
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority and controller"]
async fn p06_rc08d_application_postgres_local_fixture_maps_and_rolls_back() {
    use blindpass_controller::store::FleetSigner;
    use sqlx::Row;
    use std::sync::Arc;
    for fault in [false, true] {
        let (f, sqlite_store, owner) = application_fixture().await;
        let challenge = sqlite_store
            .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
            .await
            .unwrap();
        cover_application_records(&sqlite_store, &owner, scoped_page(&challenge).records).await;
        let source = SqlitePool::connect(&format!(
            "sqlite://{}",
            f.root.file("destination/data/controller.db").display()
        ))
        .await
        .unwrap();
        // Manually populated PG local fixture from selected authenticated SQLite
        // stage metadata. This is not PostgreSQL archive restore evidence.
        let parent =
            std::env::var("P02_TEST_POSTGRES_URL").expect("disposable PG controller URL required");
        let admin = PgPool::connect(&parent).await.unwrap();
        let schema = format!(
            "p06_application_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let separator = if parent.contains('?') { '&' } else { '?' };
        let url = format!("{parent}{separator}options=-c%20search_path%3D{schema}");
        let initialize = Store::connect(&url).await.unwrap();
        initialize.close().await;
        let pool = PgPool::connect(&url).await.unwrap();
        for table in [
            "controller_meta",
            "controller_clock",
            "nodes",
            "workloads",
            "operations",
            "grants",
            "controller_recoveries",
            "controller_recovery_snapshots",
            "controller_recovery_nodes",
            "controller_recovery_operations",
        ] {
            let columns = sqlx::query(&format!("PRAGMA table_info({table})"))
                .fetch_all(&source)
                .await
                .unwrap();
            let fields = columns
                .iter()
                .map(|row| {
                    let name: String = row.get("name");
                    format!("'{name}',\"{name}\"")
                })
                .collect::<Vec<_>>()
                .join(",");
            let rows: Vec<String> =
                sqlx::query_scalar(&format!("SELECT json_object({fields}) FROM {table}"))
                    .fetch_all(&source)
                    .await
                    .unwrap();
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&pool)
                .await
                .unwrap();
            for row in rows {
                sqlx::query(&format!(
                    "INSERT INTO {table} SELECT * FROM json_populate_record(NULL::{table},$1::json)"
                ))
                .bind(row)
                .execute(&pool)
                .await
                .unwrap();
            }
        }
        if fault {
            sqlx::raw_sql("CREATE FUNCTION application_final_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'P06_DUMMY_FINAL_FAULT'; END $$; CREATE TRIGGER application_final_fault BEFORE UPDATE ON controller_recovery_reports FOR EACH ROW EXECUTE FUNCTION application_final_fault();")
                .execute(&pool).await.unwrap();
        }
        let store =
            Store::connect_existing_owned(&url, 5000, owner.clone(), &f.context.issuer_key_id)
                .await
                .unwrap()
                .with_fleet_signer(FleetSigner::new(Arc::new(
                    Ed25519KeyPair::from_seed(&[71; 32]).unwrap(),
                )));
        let result = store.apply_recovery_report(&owner, "P06_DUMMY_NODE").await;
        if fault {
            assert!(result.is_err());
            assert!(owner.is_fenced());
            assert!(owner.has_uncertain_database_work());
            assert!(owner.quiesce().await.is_err());
        } else {
            let summary = result.unwrap();
            assert_eq!(summary.matched, 1);
            assert_eq!(
                store
                    .apply_recovery_report(&owner, "P06_DUMMY_NODE")
                    .await
                    .unwrap(),
                summary
            );
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM controller_recovery_intents")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, i64::from(!fault));
        for sql in [
            "SELECT COUNT(*) FROM grants WHERE status='revoked'",
            "SELECT COUNT(*) FROM operations WHERE status='uncertain'",
            "SELECT COUNT(*) FROM controller_recovery_nodes WHERE state='quarantined'",
        ] {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(sql)
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
                1
            );
        }
        assert!(owner.begin_operation().is_err());
        store.close().await;
        sqlite_store.close().await;
        source.close().await;
        pool.close().await;
        if !fault {
            owner.quiesce().await.unwrap();
        }
        drop(owner);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc08d_application_incomplete_rebase_and_damaged_marker_refuse() {
    for fault in [
        "collecting",
        "unmapped",
        "higher",
        "marker",
        "controller_epoch",
    ] {
        let (f, store, owner) = application_fixture().await;
        let challenge = store
            .open_recovery_report(&owner, "P06_DUMMY_NODE", 1)
            .await
            .unwrap();
        let db = f.root.file("destination/data/controller.db");
        let mut committed = 0;
        if fault == "unmapped" {
            let mut records = scoped_page(&challenge).records;
            records[0].operation_id = None;
            records[0].issuer_epoch = None;
            let receipt = cover_application_records(&store, &owner, records).await;
            assert!(!receipt.consumed);
            assert_eq!(
                receipt.state,
                blindpass_controller::recovery_authority::RecoveryReceiptState::Incomplete
            );
        } else if fault == "higher" {
            use blindpass_core::recovery::pages::PageDigest;
            let mut page = scoped_page(&challenge);
            page.manifest.observed_issuer_epoch = challenge.identity.recovery_generation;
            let mut digest = PageDigest::new(&page.manifest).unwrap();
            for record in &page.records {
                digest.push(record).unwrap();
            }
            page.manifest.records_digest = digest.finish().unwrap();
            let signature = Ed25519KeyPair::from_seed(&[41; 32])
                .unwrap()
                .sign(&page.signing_message().unwrap())
                .unwrap();
            store
                .stage_recovery_report(&owner, &page, &signature)
                .await
                .unwrap();
            let receipt = store
                .finish_recovery_report(&owner, "P06_DUMMY_NODE")
                .await
                .unwrap();
            assert!(!receipt.consumed);
            assert_eq!(
                receipt.state,
                blindpass_controller::recovery_authority::RecoveryReceiptState::RebaseRequired
            );
        } else if fault == "controller_epoch" {
            cover_application_records(&store, &owner, scoped_page(&challenge).records).await;
            let pool = SqlitePool::connect(&format!("sqlite://{}", db.display()))
                .await
                .unwrap();
            sqlx::query("UPDATE controller_meta SET issuer_epoch=issuer_epoch+1 WHERE id=1")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        } else if fault == "marker" {
            cover_application_records(&store, &owner, scoped_page(&challenge).records).await;
            assert_eq!(
                store
                    .apply_recovery_report(&owner, "P06_DUMMY_NODE")
                    .await
                    .unwrap()
                    .matched,
                1
            );
            let pool = SqlitePool::connect(&format!("sqlite://{}", db.display()))
                .await
                .unwrap();
            sqlx::query("UPDATE controller_recovery_reports SET matched=99")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
            committed = 1;
        }
        assert!(
            store
                .apply_recovery_report(&owner, "P06_DUMMY_NODE")
                .await
                .is_err(),
            "{fault} became application proof"
        );
        assert_eq!(
            number(&db, "SELECT COUNT(*) FROM controller_recovery_intents").await,
            committed
        );
        assert_eq!(
            number(&db, "SELECT COUNT(*) FROM controller_recovery_reports").await,
            committed
        );
        if fault == "marker" {
            assert_eq!(
                number(&db, "SELECT matched FROM controller_recovery_reports").await,
                99
            );
        }
        assert_eq!(
            number(&db, "SELECT COUNT(*) FROM grants WHERE status='revoked'").await,
            1
        );
        assert_eq!(
            number(
                &db,
                "SELECT COUNT(*) FROM operations WHERE status='uncertain'"
            )
            .await,
            1
        );
        assert!(owner.begin_operation().is_err());
        assert!(!owner.has_uncertain_database_work());
        store.close().await;
        drop(owner);
        f.close().await;
    }
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc09_rr01_signed_request_derives_protected_identity_and_frontier() {
    use blindpass_core::recovery::pages::{IntentRecord, PageDigest, ReportPage};
    let (f, store, owner) = application_fixture().await;
    let nonce = base64_url_encode(&[91; 32]);
    let signed = store
        .recovery_report_request(&owner, "P06_DUMMY_NODE", 1, &nonce)
        .await
        .expect("recovering holder must sign only the protected request identity and frontier");
    signed
        .verify(Ed25519KeyPair::from_seed(&[71; 32]).unwrap().public_key())
        .unwrap();
    let challenge = owner
        .recovery_challenge("P06_DUMMY_RESTORE", "P06_DUMMY_NODE")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signed.request.identity, challenge.identity);
    assert_eq!(signed.request.broker_challenge, nonce);
    assert_eq!(signed.request.page_index, 0);
    assert!(signed.request.report_id.is_none());
    let retry = store
        .recovery_report_request(&owner, "P06_DUMMY_NODE", 1, &nonce)
        .await
        .unwrap();
    assert_eq!(retry, signed);
    let mut page = scoped_page(&challenge);
    for index in 0..128 {
        page.records.push(IntentRecord {
            grant_id: format!("Z_DUMMY_UNKNOWN_{index:03}"),
            operation_id: Some("Z_DUMMY_OPERATION".into()),
            issuer_epoch: Some(1),
            expires_at_ms: 9999999999999,
        });
    }
    page.manifest.total_records = 129;
    let mut digest = PageDigest::new(&page.manifest).unwrap();
    for record in &page.records {
        digest.push(record).unwrap();
    }
    page.manifest.records_digest = digest.finish().unwrap();
    let second = ReportPage {
        manifest: page.manifest.clone(),
        page_index: 1,
        records: page.records.split_off(128),
    };
    let signer = Ed25519KeyPair::from_seed(&[41; 32]).unwrap();
    store
        .stage_recovery_report(
            &owner,
            &page,
            &signer.sign(&page.signing_message().unwrap()).unwrap(),
        )
        .await
        .unwrap();
    let next = store
        .recovery_report_request(&owner, "P06_DUMMY_NODE", 1, &nonce)
        .await
        .unwrap();
    next.verify(Ed25519KeyPair::from_seed(&[71; 32]).unwrap().public_key())
        .unwrap();
    assert_eq!(next.request.identity, challenge.identity);
    assert_eq!(next.request.page_index, 1);
    assert_eq!(
        next.request.report_id,
        Some(page.manifest.report_id.clone())
    );
    store
        .stage_recovery_report(
            &owner,
            &second,
            &signer.sign(&second.signing_message().unwrap()).unwrap(),
        )
        .await
        .unwrap();
    assert!(
        store
            .recovery_report_request(&owner, "P06_DUMMY_NODE", 1, &nonce)
            .await
            .is_err()
    );
    store
        .finish_recovery_report(&owner, "P06_DUMMY_NODE")
        .await
        .unwrap();
    assert!(
        store
            .recovery_report_request(&owner, "P06_DUMMY_NODE", 1, &nonce)
            .await
            .is_err()
    );
    assert!(owner.begin_operation().is_err());
    owner.quiesce().await.unwrap();
    store.close().await;
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc09_rr01_bad_nonce_and_unknown_version_refuse_before_nonce_mutation() {
    let (f, store, owner) = application_fixture().await;
    let valid = base64_url_encode(&[91; 32]);
    for nonce in [
        "".to_owned(),
        "x".into(),
        format!("{valid}="),
        format!("{valid}\n"),
    ] {
        assert!(
            store
                .recovery_report_request(&owner, "P06_DUMMY_NODE", 1, &nonce)
                .await
                .is_err()
        );
        assert!(
            owner
                .recovery_challenge("P06_DUMMY_RESTORE", "P06_DUMMY_NODE")
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        store
            .recovery_report_request(&owner, "P06_DUMMY_NODE", 2, &valid)
            .await
            .is_err()
    );
    assert!(
        owner
            .recovery_challenge("P06_DUMMY_RESTORE", "P06_DUMMY_NODE")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .recovery_report_request(&owner, "P06_DUMMY_UNKNOWN", 1, &valid)
            .await
            .is_err()
    );
    assert!(
        owner
            .recovery_challenge("P06_DUMMY_RESTORE", "P06_DUMMY_UNKNOWN")
            .await
            .unwrap()
            .is_none()
    );
    assert!(!owner.is_fenced());
    assert!(!owner.has_uncertain_database_work());
    owner.quiesce().await.unwrap();
    store.close().await;
    drop(owner);
    f.close().await;
}

struct RecoveryHttpFixture {
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RecoveryHttpFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn recovery_http_fixture(
    f: &Fixture,
    store: Store,
    owner: std::sync::Arc<blindpass_controller::recovery_authority::ProcessOwnership>,
) -> RecoveryHttpFixture {
    use axum::serve::ListenerExt;
    use blindpass_controller::{app::build_app_with_ownership, config::Config};
    let target = f.root.file("destination");
    let url = f.root.file("http-fixture-url");
    private(
        &url,
        format!(
            "sqlite://{}?mode=rw",
            target.join("data/controller.db").display()
        )
        .as_bytes(),
    );
    let values = vec![
        (
            "BLINDPASS_PUBLIC_URL".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
        ),
        (
            "BLINDPASS_UI_BASE_URL".to_owned(),
            "http://127.0.0.1:5175".to_owned(),
        ),
        ("BLINDPASS_TEST_MODE".to_owned(), "1".to_owned()),
        ("BLINDPASS_LISTEN".to_owned(), "127.0.0.1:0".to_owned()),
        (
            "BLINDPASS_DATABASE_URL_FILE".to_owned(),
            url.display().to_string(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
            target.join("keys/root-secret").display().to_string(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE".to_owned(),
            target.join("keys/agent-jwt-secret").display().to_string(),
        ),
        (
            "BLINDPASS_ISSUER_KEY_FILE".to_owned(),
            target.join("keys/issuer-key").display().to_string(),
        ),
    ];
    let config = Config::from_variables(values).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = build_app_with_ownership(config, Some(store), owner.clone());
    let task = tokio::spawn(async move {
        axum::serve(
            blindpass_controller::owned_transport::OwnedListener::new(listener, Some(owner))
                .tap_io(|_| {}),
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    RecoveryHttpFixture { address, task }
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc09_rr03_slow_recovery_bodies_release_their_slot_within_the_deadline() {
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (f, store, owner) = application_fixture().await;
    let server = recovery_http_fixture(&f, store.clone(), owner.clone()).await;
    // Four callers announce a body and never send it: they hold every slot.
    let mut slow = Vec::new();
    for _ in 0..4 {
        let mut stream = tokio::net::TcpStream::connect(server.address)
            .await
            .unwrap();
        stream
            .write_all(
                b"POST /api/recovery/request HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{",
            )
            .await
            .unwrap();
        slow.push(stream);
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let headers = [("content-type", "application/json")];
    let request = json!({"version":1,"node_id":"P06_DUMMY_NODE","node_key_version":1,"broker_challenge":base64_url_encode(&[91;32])});
    let busy = support::raw_request(
        server.address,
        "POST",
        "/api/recovery/request",
        &headers,
        Some(&request),
    )
    .await;
    assert_eq!(busy.status, 429, "stalled bodies must hold the slots");
    // The deadline frees them; the stalled connections are closed by the server.
    tokio::time::sleep(std::time::Duration::from_secs(17)).await;
    for stream in &mut slow {
        let mut sink = [0_u8; 512];
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut sink))
            .await
            .expect("stalled connection must be answered or closed");
        let _ = read;
    }
    let after = support::raw_request(
        server.address,
        "POST",
        "/api/recovery/request",
        &headers,
        Some(&request),
    )
    .await;
    assert_eq!(after.status, 200, "slots must be free after the deadline");
    drop(slow);
    drop(server);
    owner.quiesce().await.unwrap();
    store.close().await;
    drop(owner);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires separate disposable restricted PostgreSQL authority"]
async fn p06_rc09_rr02_http_recovery_metadata_is_scoped_and_terminal_retry_is_idempotent() {
    use blindpass_core::canon::canonicalize_value;
    use blindpass_core::recovery::pages::SignedReportRequest;
    use serde_json::json;
    let (f, store, owner) = application_fixture().await;
    let server = recovery_http_fixture(&f, store.clone(), owner.clone()).await;
    let headers = [("content-type", "application/json")];
    let request = json!({"version":1,"node_id":"P06_DUMMY_NODE","node_key_version":1,"broker_challenge":base64_url_encode(&[91;32])});
    let response = support::raw_request(
        server.address,
        "POST",
        "/api/recovery/request",
        &headers,
        Some(&request),
    )
    .await;
    assert_eq!(
        response.status, 200,
        "dedicated recovering request must reach typed signer"
    );
    let signed = SignedReportRequest::from_json(&response.body.to_string()).unwrap();
    signed
        .verify(Ed25519KeyPair::from_seed(&[71; 32]).unwrap().public_key())
        .unwrap();
    let challenge = owner
        .recovery_challenge("P06_DUMMY_RESTORE", "P06_DUMMY_NODE")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signed.request.identity, challenge.identity);
    let page = scoped_page(&challenge);
    let body: serde_json::Value =
        serde_json::from_slice(&canonicalize_value(&page.to_value().unwrap()).unwrap()).unwrap();
    let signature = Ed25519KeyPair::from_seed(&[41; 32])
        .unwrap()
        .sign(&page.signing_message().unwrap())
        .unwrap();
    let envelope = json!({"body":body,"broker_signature":base64_url_encode(&signature)});
    let mut forged = envelope.clone();
    forged["broker_signature"] = json!(base64_url_encode(&[42; 64]));
    assert_eq!(
        support::raw_request(
            server.address,
            "POST",
            "/api/recovery/page",
            &headers,
            Some(&forged)
        )
        .await
        .status,
        400
    );
    assert_eq!(
        owner
            .recovery_challenge("P06_DUMMY_RESTORE", "P06_DUMMY_NODE")
            .await
            .unwrap()
            .unwrap()
            .next_page,
        0
    );
    let complete = support::raw_request(
        server.address,
        "POST",
        "/api/recovery/page",
        &headers,
        Some(&envelope),
    )
    .await;
    assert_eq!(complete.status, 200);
    assert_eq!(complete.body["state"], "covered");
    assert_eq!(complete.body["activation_permitted"], false);
    assert_eq!(complete.body["application"]["matched"], 1);
    let replay = support::raw_request(
        server.address,
        "POST",
        "/api/recovery/page",
        &headers,
        Some(&envelope),
    )
    .await;
    assert_eq!(replay.status, 200);
    assert_eq!(replay.body, complete.body);
    assert_eq!(
        support::raw_request(
            server.address,
            "POST",
            "/api/recovery/page",
            &headers,
            Some(&forged)
        )
        .await
        .status,
        400
    );
    let resumed = support::raw_request(
        server.address,
        "POST",
        "/api/recovery/request",
        &headers,
        Some(&request),
    )
    .await;
    assert_eq!(resumed.status, 200);
    assert_eq!(resumed.body, complete.body);
    for path in [
        "/api/v3/capabilities",
        "/api/auth/me",
        "/api/v3/admin/nodes",
        "/api/v3/nodes/session/challenge",
        "/",
    ] {
        assert_eq!(
            support::raw_request(server.address, "GET", path, &[], None)
                .await
                .status,
            503,
            "ordinary route {path} reopened"
        );
    }
    let db = f.root.file("destination/data/controller.db");
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM controller_recovery_intents").await,
        1
    );
    assert_eq!(
        number(&db, "SELECT COUNT(*) FROM grants WHERE status='revoked'").await,
        1
    );
    assert_eq!(
        number(
            &db,
            "SELECT COUNT(*) FROM operations WHERE status='uncertain'"
        )
        .await,
        1
    );
    drop(server);
    owner.quiesce().await.unwrap();
    store.close().await;
    drop(owner);
    f.close().await;
}
