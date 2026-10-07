// SPDX-License-Identifier: AGPL-3.0-only
//! P06 PostgreSQL full restore (ADR 0011). A real encrypted PostgreSQL archive is
//! restored by the actual command into an empty target database under a
//! separate restricted authority. Publication stays fenced; nothing here is
//! source-stop or activation proof. These tests need the pinned toolkit, so they
//! run in the controller test image through the authority driver
//! (`recovery-authority-postgres.py --test-target restore_postgres`).
mod pg_fixture;
mod support;
use blindpass_controller::recovery_authority::{Authority, AuthorityContext};
use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};
use pg_fixture::*;
use sqlx::PgPool;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};

const REFUSAL: &[u8] = b"blindpass-controller: authenticated fenced restore refused\n";
const EMPTY_SCHEMA_REFUSAL: &[u8] = b"blindpass-controller: PostgreSQL restore target holds an empty schema: drop it first (docs/deploy/recovery-stage.md)\n";

struct Fixture {
    deployment: Deployment,
    archive: PathBuf,
    tenant: String,
    context: AuthorityContext,
    admin: PgPool,
    authority: Authority,
    target: PgPool,
}
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
impl Fixture {
    async fn new() -> Self {
        Self::with_options(true, None, None).await
    }
    /// `reserve` moves the authority record to recovering; `target_override`
    /// replaces the restore target URL.
    async fn with_options(
        reserve: bool,
        target_override: Option<String>,
        schema_version: Option<i64>,
    ) -> Self {
        let deployment = Deployment::with_schema("controller");
        deployment.source.admin_in(
            "blindpass",
            "GRANT ALL ON ALL TABLES IN SCHEMA controller TO ctl",
        );
        if let Some(version) = schema_version {
            // Shape the source as an older schema, as a pre-upgrade backup captures it.
            for (introduced, table) in [
                (20, "cross_fulfillment_payloads"),
                (20, "cross_fulfillments"),
                (19, "controller_recovery_intents"),
                (19, "controller_recovery_reports"),
                (18, "controller_recovery_snapshots"),
                (17, "controller_recovery_reviews"),
                (17, "controller_recovery_operations"),
                (17, "controller_recovery_nodes"),
                (17, "controller_recoveries"),
            ] {
                if introduced > version {
                    let dropped = deployment.source.admin_in(
                        "blindpass",
                        &format!("DROP TABLE controller.{table} CASCADE"),
                    );
                    assert!(dropped.status.success());
                }
            }
            let labelled = deployment.source.admin_in(
                "blindpass",
                &format!(
                    "UPDATE controller.controller_meta SET schema_version={version} WHERE id=1"
                ),
            );
            assert!(labelled.status.success());
        }
        let tenant = deployment.rows("SELECT tenant_id FROM controller.controller_meta");
        let out = deployment.work.file("out");
        private_dir(&out);
        let created = deployment.create(&out);
        assert!(
            created.status.success(),
            "source backup failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );
        let summary: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
        let archive = out.join(summary["backup"].as_str().unwrap());
        let seed = fs::read(deployment.keys.join("issuer-key")).unwrap();
        let key_id = format!(
            "ed25519-{}",
            base64_url_encode(Ed25519KeyPair::from_seed(&seed).unwrap().public_key())
        );
        let context = AuthorityContext {
            tenant_id: tenant.clone(),
            issuer_key_id: key_id.clone(),
            owner_id: "P06_DUMMY_RP_OWNER".into(),
        };
        let admin = PgPool::connect(&std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").unwrap())
            .await
            .unwrap();
        sqlx::query("INSERT INTO blindpass_authority.recovery_authority (tenant_id,issuer_key_id,owner_id,epoch,revision,phase) VALUES ($1,$2,$3,7,1,'fenced')")
            .bind(&tenant).bind(&key_id).bind(&context.owner_id).execute(&admin).await.unwrap();
        let authority =
            Authority::connect_existing(&std::env::var("P06_TEST_AUTHORITY_URL").unwrap())
                .await
                .unwrap();
        if reserve {
            assert_eq!(
                authority
                    .reserve_recovery(&context, 1, 7)
                    .await
                    .unwrap()
                    .epoch,
                8
            );
        }
        write_private(
            &deployment.work.file("authority-url"),
            std::env::var("P06_TEST_AUTHORITY_URL").unwrap().as_bytes(),
        );
        let target_url = target_override
            .unwrap_or_else(|| std::env::var("P06_TEST_RESTORE_TARGET_URL").unwrap());
        write_private(&deployment.work.file("target-url"), target_url.as_bytes());
        let target = PgPool::connect(&std::env::var("P06_TEST_RESTORE_TARGET_URL").unwrap())
            .await
            .unwrap();
        // Every case starts from an empty target database.
        sqlx::query("DROP SCHEMA IF EXISTS controller CASCADE")
            .execute(&target)
            .await
            .unwrap();
        Self {
            deployment,
            archive,
            tenant,
            context,
            admin,
            authority,
            target,
        }
    }
    fn destination(&self) -> PathBuf {
        self.deployment.work.file("destination")
    }
    fn args(&self) -> Vec<String> {
        let path = |name: &str| self.deployment.work.file(name).display().to_string();
        vec![
            "restore".into(),
            "--archive".into(),
            self.archive.display().to_string(),
            "--recovery-key-file".into(),
            path("recovery.pem"),
            "--destination".into(),
            self.destination().display().to_string(),
            "--database-url-file".into(),
            path("target-url"),
            "--authority-url-file".into(),
            path("authority-url"),
            "--tenant-id".into(),
            self.tenant.clone(),
            "--owner-id".into(),
            self.context.owner_id.clone(),
            "--recovery-id".into(),
            "P06_DUMMY_RP_RESTORE".into(),
        ]
    }
    fn run_args(&self, args: Vec<String>) -> Output {
        Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
            .env_clear()
            .args(args)
            .output()
            .unwrap()
    }
    fn run(&self) -> Output {
        self.run_args(self.args())
    }
    fn with_flag(&self, flag: &str, value: &str) -> Vec<String> {
        let mut args = self.args();
        let index = args.iter().position(|s| s == flag).unwrap();
        args[index + 1] = value.into();
        args
    }
    async fn target_number(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.target)
            .await
            .unwrap()
    }
    async fn target_has_controller_schema(&self) -> bool {
        self.target_number("SELECT COUNT(*) FROM pg_namespace WHERE nspname='controller'")
            .await
            == 1
    }
    fn refused(&self, out: Output) {
        assert!(!out.status.success(), "unsafe restore was accepted");
        assert!(out.stdout.is_empty(), "restore refusal disclosed output");
        assert!(out.stderr == REFUSAL, "restore refusal was not static");
        assert!(
            !self.destination().exists(),
            "refused restore published keys"
        );
    }
    async fn close(self) {
        self.authority.close().await;
        self.admin.close().await;
        self.target.close().await;
    }
}

fn target_password() -> String {
    let url = std::env::var("P06_TEST_RESTORE_TARGET_URL").unwrap();
    url.split_once("://")
        .unwrap()
        .1
        .split_once('@')
        .unwrap()
        .0
        .split_once(':')
        .unwrap()
        .1
        .to_owned()
}

async fn assert_serving_fenced(f: &Fixture) {
    let destination = f.destination();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut child = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .env_clear()
        .arg("serve")
        .env("BLINDPASS_LISTEN", address.to_string())
        .env("BLINDPASS_PUBLIC_URL", "https://restore.p06.invalid")
        .env("BLINDPASS_UI_BASE_URL", "https://restore.p06.invalid")
        .env(
            "BLINDPASS_ROOT_SECRET_FILE",
            destination.join("keys/root-secret"),
        )
        .env(
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            destination.join("keys/agent-jwt-secret"),
        )
        .env(
            "BLINDPASS_ISSUER_KEY_FILE",
            destination.join("keys/issuer-key"),
        )
        .env(
            "BLINDPASS_DATABASE_URL_FILE",
            f.deployment.work.file("target-url"),
        )
        .env(
            "BLINDPASS_AUTHORITY_URL_FILE",
            f.deployment.work.file("authority-url"),
        )
        .env("BLINDPASS_CONTROLLER_TENANT_ID", &f.tenant)
        .env("BLINDPASS_CONTROLLER_OWNER_ID", &f.context.owner_id)
        .env(
            "BLINDPASS_ADMIN_SOCKET_PATH",
            f.deployment.work.file("restore-admin.sock"),
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "restored production controller stopped before diagnostics"
        );
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        assert!(
            started.elapsed().as_secs() < 15,
            "restored production listener failed to start"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
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
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(
            started.elapsed().as_secs() < 10,
            "fenced restored controller failed to stop"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
#[ignore = "requires the pinned toolkit image and a separate disposable restricted PostgreSQL authority"]
async fn p06_rp01_actual_restore_of_a_postgresql_archive_publishes_only_fenced_invalidated_state() {
    let f = Fixture::new().await;
    let before = fs::read(&f.archive).unwrap();
    let password = target_password();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = watch_for_bytes(stop.clone(), password.clone().into_bytes());
    let started = Instant::now();
    let out = f.run();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let exposed = watcher.join().unwrap();
    assert!(
        out.status.success(),
        "PostgreSQL restore failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(started.elapsed().as_secs() < 120);
    assert!(
        !exposed,
        "target credential appeared in a process argument or environment"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&password));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&password));
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["phase"], "recovery_required");
    assert_eq!(summary["activation_permitted"], false);
    assert_eq!(summary["backend"], "postgres");
    assert_eq!(summary["target_epoch"], 8);
    let destination = f.destination();
    for path in [destination.clone(), destination.join("keys")] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }
    assert!(
        !destination.join("data").exists(),
        "PostgreSQL restore must not stage a database directory"
    );
    for name in ["root-secret", "agent-jwt-secret", "issuer-key"] {
        let file = destination.join("keys").join(name);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(
            fs::read(&file).unwrap() == fs::read(f.deployment.keys.join(name)).unwrap(),
            "restored key changed"
        );
    }
    assert_eq!(
        f.target_number("SELECT issuer_epoch::bigint FROM controller.controller_meta WHERE id=1")
            .await,
        8
    );
    assert_eq!(
        f.target_number(
            "SELECT COUNT(*) FROM controller.controller_recoveries WHERE phase='invalidated' AND target_epoch=8"
        )
        .await,
        1
    );
    for table in [
        "bootstrap_tokens",
        "secret_requests",
        "operator_sessions",
        "node_sessions",
    ] {
        assert_eq!(
            f.target_number(&format!("SELECT COUNT(*) FROM controller.{table}"))
                .await,
            0,
            "transient table survived restore: {table}"
        );
    }
    assert!(
        fs::read(&f.archive).unwrap() == before,
        "source encrypted archive changed"
    );
    assert_eq!(
        f.authority.read(&f.context).await.unwrap().phase,
        "recovering"
    );
    assert_serving_fenced(&f).await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires the pinned toolkit image and a separate disposable restricted PostgreSQL authority"]
async fn p06_rp02_context_authority_and_target_refusals_publish_and_change_nothing() {
    // Unrecovering authority, wrong tenant, wrong key, existing destination.
    let f = Fixture::new().await;
    f.refused(f.run_args(f.with_flag("--tenant-id", "P06_DUMMY_OTHER_TENANT")));
    f.refused(f.run_args(f.with_flag(
        "--recovery-key-file",
        &f.deployment.work.file("absent.pem").display().to_string(),
    )));
    assert!(!f.target_has_controller_schema().await);
    fs::create_dir(f.destination()).unwrap();
    let out = f.run();
    assert!(!out.status.success() && out.stdout.is_empty() && out.stderr == REFUSAL);
    assert!(!f.target_has_controller_schema().await);
    fs::remove_dir(f.destination()).unwrap();
    // A PostgreSQL archive refuses the SQLite argument form and the reverse.
    let mut sqlite_form = f.args();
    let index = sqlite_form
        .iter()
        .position(|s| s == "--database-url-file")
        .unwrap();
    sqlite_form.drain(index..index + 2);
    f.refused(f.run_args(sqlite_form));
    assert!(!f.target_has_controller_schema().await);
    f.close().await;

    let fenced = Fixture::with_options(false, None, None).await;
    fenced.refused(fenced.run());
    assert!(!fenced.target_has_controller_schema().await);
    fenced.close().await;
}

#[tokio::test]
#[ignore = "requires the pinned toolkit image and a separate disposable restricted PostgreSQL authority"]
async fn p06_rp03_a_non_empty_target_is_refused_and_never_modified() {
    let f = Fixture::new().await;
    sqlx::query("CREATE SCHEMA controller")
        .execute(&f.target)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE controller.p06_existing (id integer primary key, note text not null)",
    )
    .execute(&f.target)
    .await
    .unwrap();
    sqlx::query("INSERT INTO controller.p06_existing VALUES (1, 'P06_DUMMY_EXISTING')")
        .execute(&f.target)
        .await
        .unwrap();
    f.refused(f.run());
    assert_eq!(
        f.target_number(
            "SELECT COUNT(*) FROM controller.p06_existing WHERE note='P06_DUMMY_EXISTING'"
        )
        .await,
        1
    );
    assert_eq!(
        f.target_number("SELECT COUNT(*) FROM pg_tables WHERE schemaname='controller'")
            .await,
        1
    );
    sqlx::query("DROP SCHEMA controller CASCADE")
        .execute(&f.target)
        .await
        .unwrap();
    // Objects in `public` also make the target non-empty.
    sqlx::query("CREATE TABLE public.p06_existing_public (id integer)")
        .execute(&f.target)
        .await
        .unwrap();
    f.refused(f.run());
    assert!(!f.target_has_controller_schema().await);
    sqlx::query("DROP TABLE public.p06_existing_public")
        .execute(&f.target)
        .await
        .unwrap();
    f.close().await;
}

#[tokio::test]
#[ignore = "requires the pinned toolkit image and a separate disposable restricted PostgreSQL authority"]
async fn p06_rp06_an_empty_init_schema_is_refused_with_a_distinct_fixed_reason() {
    // The shipped Compose init hook leaves an empty `controller` schema. Restore still
    // never merges into or replaces it, but tells the operator exactly what to drop.
    let f = Fixture::new().await;
    sqlx::query("CREATE SCHEMA controller")
        .execute(&f.target)
        .await
        .unwrap();
    let out = f.run();
    assert!(
        !out.status.success(),
        "restore into an existing schema was accepted"
    );
    assert!(out.stdout.is_empty(), "restore refusal disclosed output");
    assert_eq!(
        out.stderr, EMPTY_SCHEMA_REFUSAL,
        "empty-schema refusal was not the fixed reason"
    );
    assert!(!f.destination().exists(), "refused restore published keys");
    assert_eq!(
        f.target_number("SELECT COUNT(*) FROM pg_namespace WHERE nspname='controller'")
            .await,
        1,
        "the operator's schema was removed or replaced"
    );
    // A schema holding anything stays the generic refusal (RP03 covers tables); an empty
    // schema next to another occupied one is not "only an empty schema".
    sqlx::query("CREATE SCHEMA p06_other_empty")
        .execute(&f.target)
        .await
        .unwrap();
    f.refused(f.run());
    sqlx::query("DROP SCHEMA p06_other_empty")
        .execute(&f.target)
        .await
        .unwrap();
    sqlx::query("DROP SCHEMA controller")
        .execute(&f.target)
        .await
        .unwrap();
    f.close().await;
}

#[tokio::test]
#[ignore = "requires the pinned toolkit image and a separate disposable restricted PostgreSQL authority"]
async fn p06_rp04_a_failure_after_the_database_restore_removes_only_the_restored_schema() {
    // The target URL resolves another schema, so the restored store cannot be
    // opened. The restored `controller` schema was created by this command and
    // is removed; nothing is published.
    let url = std::env::var("P06_TEST_RESTORE_TARGET_URL").unwrap();
    let f = Fixture::with_options(
        true,
        Some(format!("{url}?options=-c%20search_path%3Dp06_other")),
        None,
    )
    .await;
    f.refused(f.run());
    assert!(
        !f.target_has_controller_schema().await,
        "a failed restore left its schema behind"
    );
    assert_eq!(
        f.authority.read(&f.context).await.unwrap().phase,
        "recovering"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires the pinned toolkit image and a separate disposable restricted PostgreSQL authority"]
async fn p06_rp05_a_pre_upgrade_archive_restores_forward_into_an_empty_target() {
    // The rollback path of a PostgreSQL upgrade: the schema-17 archive restores
    // into an empty database, is brought forward there and stays fenced.
    let f = Fixture::with_options(true, None, Some(17)).await;
    let out = f.run();
    assert!(
        out.status.success(),
        "older-schema restore failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        f.target_number("SELECT schema_version::bigint FROM controller.controller_meta WHERE id=1")
            .await,
        blindpass_controller::store::SCHEMA_VERSION
    );
    assert_eq!(
        f.target_number(
            "SELECT COUNT(*) FROM controller.controller_recoveries WHERE phase='invalidated' AND target_epoch=8"
        )
        .await,
        1
    );
    assert_eq!(
        f.target_number("SELECT COUNT(*) FROM pg_tables WHERE schemaname='controller' AND tablename IN ('controller_recovery_intents','controller_recovery_reports','controller_recovery_snapshots')")
            .await,
        3,
        "forward migration did not create the newer tables"
    );
    assert_serving_fenced(&f).await;
    f.close().await;
}
