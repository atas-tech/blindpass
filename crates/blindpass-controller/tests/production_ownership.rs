// SPDX-License-Identifier: AGPL-3.0-only
//! Actual production commands with private disposable authority/controller state.
//! Fixture administration is not a restore, source-stop proof or unfence workflow.
mod support;

use blindpass_controller::store::Store;
use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};
use serde_json::{Value, json};
use sqlx::{PgPool, SqlitePool};
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use support::{TestDirectory, raw_request, unique};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct ChildProcess(Option<Child>);
impl ChildProcess {
    fn spawn(f: &Fixture, command: &str) -> Self {
        Self(Some(
            f.command(command)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }
    fn spawn_args(f: &Fixture, args: &[&str]) -> Self {
        let mut command = f.command(args[0]);
        command.args(&args[1..]);
        Self(Some(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }
    async fn finish(mut self, must_refuse: bool) -> Output {
        let start = Instant::now();
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none()
            && start.elapsed() < Duration::from_secs(8)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let timed_out = self.0.as_mut().unwrap().try_wait().unwrap().is_none();
        if timed_out {
            self.0.as_mut().unwrap().kill().unwrap();
        }
        let out = self.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            !timed_out,
            "production command did not terminate within fixture bound"
        );
        assert_eq!(
            !out.status.success(),
            must_refuse,
            "unexpected production command result: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }
    async fn ready(&mut self, address: SocketAddr, status: u16) {
        let start = Instant::now();
        loop {
            assert!(
                self.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "production serve stopped before readiness"
            );
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                let response = raw_request(address, "GET", "/readyz", &[], None).await;
                assert_eq!(response.status, status);
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(8),
                "production listener did not start"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn finish_shutdown(mut self) {
        // The caller already proved actual exit within five seconds. Unknown
        // background database completion must be a specifically classified
        // refusal, never success or permission to activate another source.
        assert!(self.0.as_mut().unwrap().try_wait().unwrap().is_some());
        let out = self.0.take().unwrap().wait_with_output().unwrap();
        if out.status.success() {
            assert!(
                out.stderr.is_empty(),
                "successful shutdown emitted an unexpected error"
            );
            println!("production_shutdown=local_drain_completed");
        } else {
            assert_eq!(out.status.code(), Some(1), "unexpected shutdown exit");
            assert_eq!(
                std::str::from_utf8(&out.stderr).unwrap().trim(),
                "blindpass-controller: controller shutdown did not drain within bound",
                "shutdown failed outside its classified local-drain refusal"
            );
            println!("production_shutdown=local_drain_refused");
        }
    }
}
impl Drop for ChildProcess {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Fixture {
    directory: TestDirectory,
    values: BTreeMap<String, String>,
    url: String,
    tenant: String,
    issuer: String,
    address: SocketAddr,
    pg: bool,
}
impl Fixture {
    async fn new(initialized: bool, pg: bool) -> Self {
        let directory = TestDirectory::new();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let tenant = unique("P06_DUMMY_PW");
        let url = if pg {
            let parent = std::env::var("P02_TEST_POSTGRES_URL").expect("owned controller fixture");
            let schema = unique("p06_pw").replace('-', "_");
            let pool = PgPool::connect(&parent)
                .await
                .unwrap_or_else(|_| panic!("private controller fixture unavailable"));
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
            format!(
                "{parent}{}options=-c%20search_path%3D{schema}",
                if parent.contains('?') { '&' } else { '?' }
            )
        } else {
            format!(
                "sqlite://{}?mode=rwc",
                directory.file("controller.db").display()
            )
        };
        for (name, bytes) in [
            ("root-secret", vec![b'R'; 32]),
            ("agent-jwt-secret", vec![b'A'; 32]),
            ("issuer-key", vec![b'I'; 32]),
            ("database-url", url.as_bytes().to_vec()),
        ] {
            fs::write(directory.file(name), bytes).unwrap();
            fs::set_permissions(directory.file(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let issuer = format!(
            "ed25519-{}",
            base64_url_encode(Ed25519KeyPair::from_seed(&[b'I'; 32]).unwrap().public_key())
        );
        let values = BTreeMap::from([
            ("BLINDPASS_LISTEN".into(), address.to_string()),
            (
                "BLINDPASS_PUBLIC_URL".into(),
                "https://controller.pw.invalid".into(),
            ),
            (
                "BLINDPASS_UI_BASE_URL".into(),
                "https://controller.pw.invalid".into(),
            ),
            (
                "BLINDPASS_ROOT_SECRET_FILE".into(),
                directory.file("root-secret").display().to_string(),
            ),
            (
                "BLINDPASS_AGENT_JWT_SECRET_FILE".into(),
                directory.file("agent-jwt-secret").display().to_string(),
            ),
            (
                "BLINDPASS_ISSUER_KEY_FILE".into(),
                directory.file("issuer-key").display().to_string(),
            ),
            (
                "BLINDPASS_DATABASE_URL_FILE".into(),
                directory.file("database-url").display().to_string(),
            ),
            (
                "BLINDPASS_ADMIN_SOCKET_PATH".into(),
                directory.file("admin.sock").display().to_string(),
            ),
        ]);
        let mut f = Self {
            directory,
            values,
            url,
            tenant,
            issuer,
            address,
            pg,
        };
        if initialized {
            let store = Store::connect(&f.url).await.unwrap();
            f.tenant = store.tenant_id().to_owned();
            store.close().await;
        }
        f
    }
    fn private(&self, name: &str, bytes: &[u8]) {
        fs::write(self.directory.file(name), bytes).unwrap();
        fs::set_permissions(self.directory.file(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn command(&self, command: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
        c.env_clear().envs(&self.values).arg(command);
        c
    }
    async fn authority(&mut self, phase: &str) -> PgPool {
        let admin = PgPool::connect(
            &std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").expect("owned authority administrator"),
        )
        .await
        .unwrap_or_else(|_| panic!("private authority fixture unavailable"));
        sqlx::query("INSERT INTO blindpass_authority.recovery_authority (tenant_id,issuer_key_id,owner_id,epoch,revision,phase) VALUES ($1,$2,'P06_DUMMY_OWNER',1,1,$3)").bind(&self.tenant).bind(&self.issuer).bind(phase).execute(&admin).await.unwrap();
        self.private(
            "authority-url",
            std::env::var("P06_TEST_AUTHORITY_URL")
                .expect("owned authority runtime")
                .as_bytes(),
        );
        self.values.insert(
            "BLINDPASS_AUTHORITY_URL_FILE".into(),
            self.directory.file("authority-url").display().to_string(),
        );
        self.values
            .insert("BLINDPASS_CONTROLLER_TENANT_ID".into(), self.tenant.clone());
        self.values.insert(
            "BLINDPASS_CONTROLLER_OWNER_ID".into(),
            "P06_DUMMY_OWNER".into(),
        );
        admin
    }
    async fn clone_store(&self) -> Self {
        let mut clone = Self::new(self.pg, self.pg).await;
        if self.pg {
            // Copy the complete quiescent initialized fixture, without invoking
            // the separately unapproved PostgreSQL dump/restore toolkit.
            let source_schema = self.url.rsplit("%3D").next().unwrap();
            let target_schema = clone.url.rsplit("%3D").next().unwrap();
            assert!(
                [source_schema, target_schema]
                    .iter()
                    .all(|name| name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            );
            let pool = PgPool::connect(&self.url).await.unwrap();
            let tables: Vec<String> = sqlx::query_scalar(
                "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname=$1 ORDER BY tablename",
            )
            .bind(source_schema)
            .fetch_all(&pool)
            .await
            .unwrap();
            assert!(
                tables
                    .iter()
                    .all(|name| name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            );
            let targets = tables
                .iter()
                .map(|table| format!("\"{target_schema}\".\"{table}\""))
                .collect::<Vec<_>>()
                .join(",");
            sqlx::query(&format!("TRUNCATE {targets} CASCADE"))
                .execute(&pool)
                .await
                .unwrap();
            // The pristine fixture has only metadata/clock/default-policy rows.
            // All other tables are still copied; no cross-row live broker or
            // provider recovery is inferred from this controlled snapshot.
            for table in &tables {
                sqlx::query(&format!("INSERT INTO \"{target_schema}\".\"{table}\" SELECT * FROM \"{source_schema}\".\"{table}\"")).execute(&pool).await.unwrap();
            }
            pool.close().await;
        } else {
            // No issuer has started yet, but pool close alone need not erase
            // a WAL. Take a complete consistent fixture snapshot instead of
            // copying only the main file or assuming its WAL is already empty.
            let pool = SqlitePool::connect(&self.url).await.unwrap();
            sqlx::query("VACUUM INTO ?")
                .bind(clone.directory.file("controller.db").display().to_string())
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
            fs::set_permissions(
                clone.directory.file("controller.db"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        clone.tenant = self.tenant.clone();
        clone
    }

    async fn sql(&self, statement: &str) {
        if self.pg {
            let p = PgPool::connect(&self.url).await.unwrap();
            sqlx::query(statement).execute(&p).await.unwrap();
            p.close().await;
        } else {
            let p = SqlitePool::connect(&self.url).await.unwrap();
            sqlx::query(statement).execute(&p).await.unwrap();
            p.close().await;
        }
    }
    async fn number(&self, statement: &str) -> i64 {
        if self.pg {
            let p = PgPool::connect(&self.url).await.unwrap();
            let n = sqlx::query_scalar(statement).fetch_one(&p).await.unwrap();
            p.close().await;
            n
        } else {
            let p = SqlitePool::connect(&self.url).await.unwrap();
            let n = sqlx::query_scalar(statement).fetch_one(&p).await.unwrap();
            p.close().await;
            n
        }
    }
    async fn admin(&self, command: &str) -> Value {
        let mut stream = tokio::net::UnixStream::connect(self.directory.file("admin.sock"))
            .await
            .unwrap();
        let mut request = json!({"command":command}).to_string().into_bytes();
        request.push(b'\n');
        stream.write_all(&request).await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        serde_json::from_slice(&reply)
            .unwrap_or_else(|_| panic!("invalid private administration response"))
    }
}

#[tokio::test]
async fn p06_pw01_missing_production_authority_refuses_configuration_and_writes() {
    let f = Fixture::new(false, false).await;
    for command in ["check-config", "serve", "migrate", "reconcile-clock"] {
        let out = ChildProcess::spawn(&f, command).finish(true).await;
        let diagnostic = String::from_utf8_lossy(&out.stderr);
        assert!(
            diagnostic.contains("BLINDPASS_AUTHORITY_URL_FILE"),
            "missing mandatory authority diagnostic"
        );
        assert!(!f.directory.file("controller.db").exists());
        assert!(!f.directory.file("admin.sock").exists());
    }
}

#[tokio::test]
async fn p06_pw01_inline_partial_unsafe_and_invalid_authority_configuration_refuses_without_echo() {
    for kind in ["inline", "partial", "unsafe", "url", "owner", "tenant"] {
        let mut f = Fixture::new(false, false).await;
        let canary = "P06-DUMMY-PW-CREDENTIAL";
        f.private(
            "authority-url",
            format!("postgres://pw:{canary}@127.0.0.1:9/pw").as_bytes(),
        );
        f.values.insert(
            "BLINDPASS_AUTHORITY_URL_FILE".into(),
            f.directory.file("authority-url").display().to_string(),
        );
        f.values
            .insert("BLINDPASS_CONTROLLER_TENANT_ID".into(), f.tenant.clone());
        f.values.insert(
            "BLINDPASS_CONTROLLER_OWNER_ID".into(),
            "P06_DUMMY_OWNER".into(),
        );
        match kind {
            "inline" => {
                f.values
                    .insert("BLINDPASS_AUTHORITY_URL".into(), canary.into());
            }
            "partial" => {
                f.values.remove("BLINDPASS_CONTROLLER_OWNER_ID");
            }
            "unsafe" => {
                fs::set_permissions(
                    f.directory.file("authority-url"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            "url" => f.private(
                "authority-url",
                format!("postgres://pw:{canary}@127.0.0.1:9/pw?P06_DUMMY_UNKNOWN=secret")
                    .as_bytes(),
            ),
            "owner" => {
                f.values.insert(
                    "BLINDPASS_CONTROLLER_OWNER_ID".into(),
                    format!("bad/{canary}"),
                );
            }
            "tenant" => {
                f.values.insert(
                    "BLINDPASS_CONTROLLER_TENANT_ID".into(),
                    format!("bad/{canary}"),
                );
            }
            _ => unreachable!(),
        }
        let out = ChildProcess::spawn(&f, "check-config").finish(true).await;
        let diagnostic = String::from_utf8_lossy(&out.stderr);
        assert!(!diagnostic.contains(canary));
        assert!(!diagnostic.contains("postgres://"));
        assert!(!f.directory.file("controller.db").exists());
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_pw02_actual_production_excludes_second_store_and_same_revision_restart() {
    let pg = support::postgres_selected();
    let mut f = Fixture::new(true, pg).await;
    let admin = f.authority("active").await;
    let mut second = f.clone_store().await;
    let mut first = ChildProcess::spawn(&f, "serve");
    first.ready(f.address, 200).await;
    assert_eq!(
        raw_request(f.address, "POST", "/api/v3/admin/test/seed", &[], None)
            .await
            .status,
        404,
        "owned production must not expose the test seed route"
    );
    second.private(
        "authority-url",
        std::env::var("P06_TEST_AUTHORITY_URL").unwrap().as_bytes(),
    );
    for key in [
        "BLINDPASS_AUTHORITY_URL_FILE",
        "BLINDPASS_CONTROLLER_TENANT_ID",
        "BLINDPASS_CONTROLLER_OWNER_ID",
    ] {
        second.values.insert(
            key.into(),
            if key == "BLINDPASS_AUTHORITY_URL_FILE" {
                second.directory.file("authority-url").display().to_string()
            } else {
                f.values[key].clone()
            },
        );
    }
    ChildProcess::spawn(&second, "serve").finish(true).await;
    assert_eq!(
        raw_request(f.address, "GET", "/readyz", &[], None)
            .await
            .status,
        200
    );
    drop(first);
    ChildProcess::spawn(&f, "serve").finish(true).await;
    sqlx::query(
        "UPDATE blindpass_authority.recovery_authority SET revision=revision+1 WHERE tenant_id=$1",
    )
    .bind(&f.tenant)
    .execute(&admin)
    .await
    .unwrap();
    let mut restarted = ChildProcess::spawn(&f, "serve");
    restarted.ready(f.address, 200).await;
    drop(restarted);
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_pw03_actual_production_http_and_local_admin_share_authority_loss() {
    let mut f = Fixture::new(true, support::postgres_selected()).await;
    let admin = f.authority("active").await;
    let setup = Store::connect_existing(&f.url, 2000).await.unwrap();
    let seeded = blindpass_controller::seed::seed_fixture(
        &setup,
        blindpass_controller::seed::SeedRequest {
            agents: vec!["p06-pw-requester".into()],
            policy: None,
            rotated_agents: vec![],
            revoked_agents: vec![],
            local_admin: false,
        },
    )
    .await
    .unwrap();
    setup.close().await;
    let mut child = ChildProcess::spawn(&f, "serve");
    child.ready(f.address, 200).await;
    let minted = raw_request(
        f.address,
        "POST",
        "/api/v2/agents/token",
        &[(
            "x-agent-api-key",
            seeded.agents["p06-pw-requester"].as_str(),
        )],
        None,
    )
    .await;
    assert_eq!(minted.status, 200);
    let bearer = format!(
        "Bearer {}",
        minted.body["access_token"]
            .as_str()
            .expect("private minted token")
    );
    let request = json!({"public_key":"AQIDBA==","description":"P06 production guard dummy"});
    let created = raw_request(
        f.address,
        "POST",
        "/api/v2/secret/request",
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
        ],
        Some(&request),
    )
    .await;
    assert_eq!(created.status, 201);
    drop(created);
    let initial = f.admin("bootstrap-token").await;
    assert!(initial["bootstrap_token"].is_string());
    drop(initial);
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1").bind(&f.tenant).execute(&admin).await.unwrap();
    let start = Instant::now();
    loop {
        assert!(
            child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "fencing stopped diagnostic service"
        );
        // A transport accepted before the latch may close while observing
        // loss. Require a fresh diagnostic 503, then all ordinary denials.
        if transition_readiness(f.address).await == Some(503) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "actual production did not fence after authority loss"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for path in [
        "/api/v2/agents/token",
        "/api/v3/node/session/challenge",
        "/api/v3/capabilities",
        "/app",
        "/unknown",
    ] {
        assert_eq!(
            raw_request(
                f.address,
                "POST",
                path,
                &[("content-type", "application/json")],
                Some(&json!({}))
            )
            .await
            .status,
            503
        );
    }
    assert_eq!(
        raw_request(f.address, "GET", "/healthz", &[], None)
            .await
            .status,
        200
    );
    let denied = f.admin("bootstrap-token").await;
    assert!(denied["error"].is_string());
    assert!(!denied["bootstrap_token"].is_string());
    assert_eq!(f.number("SELECT count(*) FROM bootstrap_tokens").await, 1);
    assert_eq!(
        raw_request(
            f.address,
            "POST",
            "/api/v2/secret/request",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json")
            ],
            Some(&request)
        )
        .await
        .status,
        503
    );
    assert_eq!(f.number("SELECT count(*) FROM secret_requests").await, 1);

    drop(child);
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_pw04_fenced_and_recovering_production_start_without_clock_writes() {
    for phase in ["fenced", "recovering"] {
        let mut f = Fixture::new(true, support::postgres_selected()).await;
        let admin = f.authority(phase).await;
        let before = f
            .number("SELECT last_observed_ms FROM controller_clock WHERE id=1")
            .await;
        let mut child = ChildProcess::spawn(&f, "serve");
        child.ready(f.address, 503).await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            f.number("SELECT last_observed_ms FROM controller_clock WHERE id=1")
                .await,
            before,
            "nonactive startup/clock task wrote controller state"
        );
        assert_eq!(
            raw_request(f.address, "GET", "/healthz", &[], None)
                .await
                .status,
            200
        );
        assert!(f.admin("bootstrap-token").await["error"].is_string());
        drop(child);
        admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_pw04_actual_startup_refuses_changed_context_before_clock_write() {
    for update in [
        "issuer_epoch=2",
        "schema_version=999",
        "tenant_id='P06_DUMMY_OTHER'",
    ] {
        let mut f = Fixture::new(true, support::postgres_selected()).await;
        let admin = f.authority("active").await;
        f.sql(&format!("UPDATE controller_meta SET {update} WHERE id=1"))
            .await;
        let before = f
            .number("SELECT last_observed_ms FROM controller_clock WHERE id=1")
            .await;
        ChildProcess::spawn(&f, "serve").finish(true).await;
        assert_eq!(
            f.number("SELECT last_observed_ms FROM controller_clock WHERE id=1")
                .await,
            before
        );
        assert!(!f.directory.file("admin.sock").exists());
        admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_pw05_production_initialization_and_clock_maintenance_require_fenced_owner() {
    let mut f = Fixture::new(false, support::postgres_selected()).await;
    let admin = f.authority("fenced").await;
    ChildProcess::spawn(&f, "migrate").finish(false).await;
    assert_eq!(
        f.number("SELECT issuer_epoch FROM controller_meta WHERE id=1")
            .await,
        1
    );
    let matching = if f.pg {
        let p = PgPool::connect(&f.url).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM controller_meta WHERE tenant_id=$1")
            .bind(&f.tenant)
            .fetch_one(&p)
            .await
            .unwrap();
        p.close().await;
        n
    } else {
        let p = SqlitePool::connect(&f.url).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM controller_meta WHERE tenant_id=?")
            .bind(&f.tenant)
            .fetch_one(&p)
            .await
            .unwrap();
        p.close().await;
        n
    };
    assert_eq!(
        matching, 1,
        "production initialization replaced the explicitly chosen tenant"
    );
    f.sql("UPDATE controller_clock SET last_observed_ms=4000000000000000000 WHERE id=1")
        .await;
    let out = ChildProcess::spawn(&f, "reconcile-clock")
        .finish(false)
        .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["regression_detected"],
        true
    );
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1").bind(&f.tenant).execute(&admin).await.unwrap();
    f.sql("UPDATE controller_clock SET last_observed_ms=4000000000000000000 WHERE id=1")
        .await;
    for command in ["reconcile-clock", "migrate"] {
        ChildProcess::spawn(&f, command).finish(true).await;
    }
    assert_eq!(
        f.number("SELECT last_observed_ms FROM controller_clock WHERE id=1")
            .await,
        4000000000000000000
    );
    f.sql("UPDATE controller_meta SET schema_version=16 WHERE id=1")
        .await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1").bind(&f.tenant).execute(&admin).await.unwrap();
    ChildProcess::spawn(&f, "migrate").finish(true).await;
    assert_eq!(
        f.number("SELECT CAST(schema_version AS BIGINT) FROM controller_meta WHERE id=1")
            .await,
        16
    );
    admin.close().await;
}

#[tokio::test]
async fn p06_pw06_unbound_production_builder_refuses_ordinary_routes_and_readiness() {
    struct AppTask(tokio::task::JoinHandle<()>);
    impl Drop for AppTask {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let f = Fixture::new(true, false).await;
    let config = blindpass_controller::config::Config::from_variables(f.values.clone()).unwrap();
    let store = Store::connect_existing(&f.url, 2000).await.unwrap();
    let before = f
        .number("SELECT last_observed_ms FROM controller_clock WHERE id=1")
        .await;
    let listener = tokio::net::TcpListener::bind(f.address).await.unwrap();
    let app = blindpass_controller::app::build_app(config, Some(store.clone()));
    let server = AppTask(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    }));
    for path in ["/readyz", "/api/v3/capabilities", "/app", "/unknown"] {
        assert_eq!(
            raw_request(f.address, "GET", path, &[], None).await.status,
            503,
            "unbound production builder accepted ordinary access"
        );
    }
    assert_eq!(
        raw_request(f.address, "GET", "/healthz", &[], None)
            .await
            .status,
        200
    );
    assert_eq!(
        f.number("SELECT last_observed_ms FROM controller_clock WHERE id=1")
            .await,
        before
    );
    drop(server);
    store.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_pw05_clock_maintenance_cancels_on_loss_of_its_fenced_guard() {
    let mut f = Fixture::new(true, support::postgres_selected()).await;
    let admin = f.authority("fenced").await;
    f.sql("UPDATE controller_clock SET last_observed_ms=4000000000000000000 WHERE id=1")
        .await;
    let pg_pool;
    let sqlite_pool;
    let mut pg_lock = None;
    let mut sqlite_lock = None;
    if f.pg {
        pg_pool = PgPool::connect(&f.url).await.unwrap();
        let mut transaction = pg_pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM controller_clock WHERE id=1 FOR UPDATE")
            .execute(&mut *transaction)
            .await
            .unwrap();
        pg_lock = Some(transaction);
        sqlite_pool = None;
    } else {
        let pool = SqlitePool::connect(&f.url).await.unwrap();
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("UPDATE controller_clock SET last_observed_ms=last_observed_ms WHERE id=1")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlite_lock = Some(transaction);
        sqlite_pool = Some(pool);
        pg_pool = PgPool::connect(&std::env::var("P06_TEST_AUTHORITY_URL").unwrap())
            .await
            .unwrap();
    }
    let mut child = ChildProcess::spawn(&f, "reconcile-clock");
    let started = Instant::now();
    if f.pg {
        loop {
            let waiting:i64=sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND wait_event_type='Lock' AND query LIKE 'SELECT last_observed_ms, fenced_at, boot_id FROM controller_clock WHERE id = 1 FOR UPDATE%'").fetch_one(&pg_pool).await.unwrap();
            if waiting > 0 {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "owned clock SELECT did not reach the observed PostgreSQL row lock"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    } else {
        // Observe the held transaction in this driver's isolated authority DB.
        // A competing claim can win the lock first and make the very child it
        // observes fail startup. This read does not claim SQLite SQL position.
        loop {
            assert!(
                child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "clock maintenance exited before held-guard observation"
            );
            let held: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() AND a.usename=current_user AND a.state='idle in transaction' AND l.relation='blindpass_authority.process_guard'::regclass AND l.mode='RowShareLock' AND l.granted")
                .fetch_one(&pg_pool).await.unwrap();
            if held > 0 {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "clock maintenance did not acquire its protected guard"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    sqlx::query(
        "UPDATE blindpass_authority.recovery_authority SET revision=revision+1 WHERE tenant_id=$1",
    )
    .bind(&f.tenant)
    .execute(&admin)
    .await
    .unwrap();
    child.finish(true).await;
    if let Some(lock) = pg_lock {
        lock.rollback().await.unwrap();
    }
    if let Some(lock) = sqlite_lock {
        lock.rollback().await.unwrap();
    }
    if let Some(pool) = sqlite_pool {
        pool.close().await;
    }
    pg_pool.close().await;
    assert_eq!(
        f.number("SELECT last_observed_ms FROM controller_clock WHERE id=1")
            .await,
        4000000000000000000
    );
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_pw05_existing_foreign_objects_are_not_pristine_initialization() {
    for object in ["table", "view"] {
        let mut f = Fixture::new(false, support::postgres_selected()).await;
        let admin = f.authority("fenced").await;
        f.sql(if object == "table" {
            "CREATE TABLE sqliteXdummy(id INTEGER)"
        } else {
            "CREATE VIEW p06_dummy_view AS SELECT 1 AS id"
        })
        .await;
        ChildProcess::spawn(&f, "migrate").finish(true).await;
        let metadata = if f.pg {
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='controller_meta'"
        } else {
            "SELECT COUNT(*) FROM sqlite_master WHERE name='controller_meta'"
        };
        assert_eq!(
            f.number(metadata).await,
            0,
            "production initialized metadata in a nonpristine database"
        );
        admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_pw05_lost_state_of_a_previously_active_epoch_is_not_pristine_initialization() {
    // Administrator fencing keeps the epoch. An empty database under a ledger
    // that has ever been active is lost state, never a new controller.
    let mut f = Fixture::new(false, support::postgres_selected()).await;
    let admin = f.authority("fenced").await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1").bind(&f.tenant).execute(&admin).await.unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1").bind(&f.tenant).execute(&admin).await.unwrap();
    ChildProcess::spawn(&f, "migrate").finish(true).await;
    let metadata = if f.pg {
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='controller_meta'"
    } else {
        "SELECT COUNT(*) FROM sqlite_master WHERE name='controller_meta'"
    };
    assert_eq!(
        f.number(metadata).await,
        0,
        "production recreated a controller under a previously active epoch"
    );
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_qf01_sigterm_closes_admitted_incomplete_http_body_within_five_seconds() {
    let mut f = Fixture::new(true, support::postgres_selected()).await;
    let admin = f.authority("active").await;
    let mut child = ChildProcess::spawn(&f, "serve");
    child.ready(f.address, 200).await;
    let mut stream = tokio::net::TcpStream::connect(f.address).await.unwrap();
    stream.write_all(b"POST /api/v2/secret/request HTTP/1.1\r\nHost: controller.pw.invalid\r\nContent-Type: application/json\r\nContent-Length: 200\r\nExpect: 100-continue\r\nConnection: keep-alive\r\n\r\n").await.unwrap();
    let mut interim = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !interim.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            interim.push(byte[0]);
            assert!(interim.len() < 1024);
        }
    })
    .await
    .unwrap();
    assert!(
        interim.starts_with(b"HTTP/1.1 100 Continue"),
        "body was not admitted before shutdown"
    );
    stream.write_all(b"{\"").await.unwrap();
    assert_eq!(f.number("SELECT count(*) FROM secret_requests").await, 0);
    let pid = child.0.as_ref().unwrap().id().to_string();
    assert!(
        Command::new("/usr/bin/kill")
            .args(["-TERM", "--", &pid])
            .status()
            .unwrap()
            .success()
    );
    let started = Instant::now();
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none()
        && started.elapsed() < Duration::from_secs(5)
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        child.0.as_mut().unwrap().try_wait().unwrap().is_some(),
        "SIGTERM waited for an incomplete admitted HTTP body beyond five seconds"
    );
    child.finish_shutdown();
    assert_eq!(f.number("SELECT count(*) FROM secret_requests").await, 0);
    drop(stream);
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_qf04_trusted_tls_pending_body_stops_and_wrong_hostname_refuses() {
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    let mut f = Fixture::new(true, support::postgres_selected()).await;
    let certificate = f.directory.file("tls-certificate.pem");
    let key = f.directory.file("tls-private.pem");
    let output = Command::new("/usr/bin/openssl")
        .env_clear()
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=controller.pw.invalid",
            "-addext",
            "subjectAltName=DNS:controller.pw.invalid",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&certificate)
        .output()
        .unwrap();
    assert!(output.status.success(), "dummy TLS key creation failed");
    for path in [&certificate, &key] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    f.values.insert(
        "BLINDPASS_TLS_CERT_FILE".into(),
        certificate.display().to_string(),
    );
    f.values
        .insert("BLINDPASS_TLS_KEY_FILE".into(), key.display().to_string());
    let admin = f.authority("active").await;
    let mut child = ChildProcess::spawn(&f, "serve");
    let started = Instant::now();
    loop {
        assert!(child.0.as_mut().unwrap().try_wait().unwrap().is_none());
        if tokio::net::TcpStream::connect(f.address).await.is_ok() {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(8));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&fs::read(&certificate).unwrap()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = ClientConfig::builder_with_provider(std::sync::Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let wrong = connector
        .connect(
            ServerName::try_from("wrong.p06.invalid").unwrap(),
            tokio::net::TcpStream::connect(f.address).await.unwrap(),
        )
        .await;
    assert!(wrong.is_err(), "TLS hostname validation was bypassed");
    let mut probe = connector
        .connect(
            ServerName::try_from("controller.pw.invalid").unwrap(),
            tokio::net::TcpStream::connect(f.address).await.unwrap(),
        )
        .await
        .unwrap();
    probe
        .write_all(
            b"GET /readyz HTTP/1.1\r\nHost: controller.pw.invalid\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut readiness = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), probe.read_to_end(&mut readiness))
        .await
        .unwrap()
        .unwrap();
    assert!(readiness.starts_with(b"HTTP/1.1 200"));
    drop(probe);
    let mut stream = connector
        .connect(
            ServerName::try_from("controller.pw.invalid").unwrap(),
            tokio::net::TcpStream::connect(f.address).await.unwrap(),
        )
        .await
        .unwrap();
    stream.write_all(b"POST /api/v2/secret/request HTTP/1.1\r\nHost: controller.pw.invalid\r\nContent-Type: application/json\r\nContent-Length: 200\r\nExpect: 100-continue\r\nConnection: keep-alive\r\n\r\n").await.unwrap();
    let mut interim = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !interim.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            interim.push(byte[0]);
            assert!(interim.len() < 1024);
        }
    })
    .await
    .unwrap();
    assert!(interim.starts_with(b"HTTP/1.1 100 Continue"));
    stream.write_all(b"{\"").await.unwrap();
    let pid = child.0.as_ref().unwrap().id().to_string();
    assert!(
        Command::new("/usr/bin/kill")
            .args(["-TERM", "--", &pid])
            .status()
            .unwrap()
            .success()
    );
    let started = Instant::now();
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none()
        && started.elapsed() < Duration::from_secs(5)
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        child.0.as_mut().unwrap().try_wait().unwrap().is_some(),
        "TLS pending body exceeded the shutdown bound"
    );
    child.finish_shutdown();
    assert_eq!(f.number("SELECT count(*) FROM secret_requests").await, 0);
    drop(stream);
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_qf05_sigterm_closes_an_accepted_partial_admin_client_without_issuing() {
    let mut f = Fixture::new(true, support::postgres_selected()).await;
    let admin = f.authority("active").await;
    let mut child = ChildProcess::spawn(&f, "serve");
    child.ready(f.address, 200).await;
    let pid = child.0.as_ref().unwrap().id();
    let path = f.directory.file("admin.sock");
    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client
        .write_all(b"{\"command\":\"bootstrap-token\"")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let fds: std::collections::HashSet<String> = fs::read_dir(format!("/proc/{pid}/fd"))
                .unwrap()
                .filter_map(|entry| {
                    fs::read_link(entry.ok()?.path())
                        .ok()?
                        .to_str()
                        .map(str::to_owned)
                })
                .collect();
            let unix = fs::read_to_string(format!("/proc/{pid}/net/unix")).unwrap();
            if unix.lines().skip(1).any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.len() > 7
                    && fields[5] == "03"
                    && fields[7] == path.to_str().unwrap()
                    && fds.contains(&format!("socket:[{}]", fields[6]))
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("production admin client was not accepted");
    assert_eq!(f.number("SELECT COUNT(*) FROM bootstrap_tokens").await, 0);
    assert!(
        Command::new("/usr/bin/kill")
            .args(["-TERM", "--", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let started = Instant::now();
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none()
        && started.elapsed() < Duration::from_secs(5)
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        child.0.as_mut().unwrap().try_wait().unwrap().is_some(),
        "admin client outlived the shutdown bound"
    );
    child.finish_shutdown();
    let _ = client.write_all(b"}\n").await;
    let mut byte = [0];
    let reply = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await;
    assert!(
        matches!(reply, Ok(Ok(0)) | Ok(Err(_))),
        "stopped controller delivered an admin credential"
    );
    assert_eq!(f.number("SELECT COUNT(*) FROM bootstrap_tokens").await, 0);
    drop(client);
    admin.close().await;
}

async fn transition_readiness(address: SocketAddr) -> Option<u16> {
    tokio::time::timeout(Duration::from_secs(4), async {
        let mut stream = tokio::net::TcpStream::connect(address).await.ok()?;
        stream
            .write_all(
                b"GET /readyz HTTP/1.1\r\nHost: controller.pw.invalid\r\nConnection: close\r\n\r\n",
            )
            .await
            .ok()?;
        let mut reply = Vec::new();
        if stream.read_to_end(&mut reply).await.is_err() || reply.is_empty() {
            return None;
        }
        assert!(reply.len() < 4096, "unexpected diagnostic response size");
        let text = std::str::from_utf8(&reply).expect("invalid diagnostic response");
        assert!(text.starts_with("HTTP/1.1 "), "invalid diagnostic protocol");
        Some(text.split_whitespace().nth(1).unwrap().parse().unwrap())
    })
    .await
    .expect("diagnostic transition exceeded its request bound")
}

// ---- Slice 7: locked upgrade with an automatic verified pre-upgrade backup ----

/// Tables introduced after each schema version, newest first, so an initialized
/// current database can be turned into a genuine older-schema database.
const NEWER_TABLES: &[(i64, &str)] = &[
    (20, "cross_fulfillment_payloads"),
    (20, "cross_fulfillments"),
    (19, "controller_recovery_intents"),
    (19, "controller_recovery_reports"),
    (18, "controller_recovery_snapshots"),
    (17, "controller_recovery_reviews"),
    (17, "controller_recovery_operations"),
    (17, "controller_recovery_nodes"),
    (17, "controller_recoveries"),
];

struct Upgrade {
    f: Fixture,
    admin: PgPool,
    backups: std::path::PathBuf,
    key: std::path::PathBuf,
}
impl Upgrade {
    /// An initialized SQLite controller labelled and shaped as schema `version`,
    /// under a fenced authority record, with a recovery key and backup root.
    async fn new(version: i64) -> Self {
        Self::with_backend(version, false).await
    }
    async fn with_backend(version: i64, pg: bool) -> Self {
        let mut f = Fixture::new(true, pg).await;
        f.values.insert(
            "BLINDPASS_KEYS_DIR".into(),
            f.directory.0.display().to_string(),
        );
        let admin = f.authority("fenced").await;
        f.sql("UPDATE controller_clock SET last_observed_ms=last_observed_ms")
            .await;
        f.sql("INSERT INTO operators (id, username, display_name, password_hash, role, created_at) VALUES ('P06_DUMMY_UP_CANARY','up-canary','Canary','x','viewer',1)")
            .await;
        for (introduced, table) in NEWER_TABLES {
            if *introduced > version {
                let cascade = if pg { " CASCADE" } else { "" };
                f.sql(&format!("DROP TABLE {table}{cascade}")).await;
            }
        }
        f.sql(&format!(
            "UPDATE controller_meta SET schema_version={version} WHERE id=1"
        ))
        .await;
        let key = f.directory.file("recovery.pem");
        blindpass_controller::backup::initialize_recovery_key(&key).unwrap();
        let backups = f.directory.file("backups");
        Self {
            f,
            admin,
            backups,
            key,
        }
    }
    fn args(&self) -> Vec<String> {
        vec![
            "migrate".into(),
            "--pre-upgrade-backup-dir".into(),
            self.backups.display().to_string(),
            "--recovery-key-file".into(),
            self.key.display().to_string(),
        ]
    }
    async fn migrate(&self, must_refuse: bool) -> Output {
        let args = self.args();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        ChildProcess::spawn_args(&self.f, &refs)
            .finish(must_refuse)
            .await
    }
    fn backup_dirs(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.backups) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with("pre-upgrade-"))
            .collect();
        names.sort();
        names
    }
    async fn version(&self) -> i64 {
        self.f
            .number("SELECT CAST(schema_version AS BIGINT) FROM controller_meta WHERE id=1")
            .await
    }
    async fn close(self) {
        self.admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up01_schema16_upgrade_takes_a_verified_backup_then_migrates() {
    let u = Upgrade::new(16).await;
    let tenant = u.f.tenant.clone();
    let out = u.migrate(false).await;
    assert_eq!(
        u.version().await,
        blindpass_controller::store::SCHEMA_VERSION
    );
    assert_eq!(
        u.f.number("SELECT issuer_epoch FROM controller_meta WHERE id=1")
            .await,
        1
    );
    assert_eq!(
        u.f.number("SELECT COUNT(*) FROM operators WHERE id='P06_DUMMY_UP_CANARY'")
            .await,
        1,
        "upgrade lost existing state"
    );
    let dirs = u.backup_dirs();
    assert_eq!(dirs.len(), 1, "exactly one pre-upgrade backup expected");
    assert!(
        dirs[0].ends_with("-v16"),
        "backup name must record the source schema"
    );
    let archives: Vec<_> = fs::read_dir(u.backups.join(&dirs[0]))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bpbackup"))
        .collect();
    assert_eq!(archives.len(), 1);
    let work = u.f.directory.file("verify-work");
    fs::create_dir(&work).unwrap();
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    let manifest = blindpass_controller::backup::verify_backup(&archives[0], &u.key, &work)
        .await
        .unwrap();
    assert_eq!(manifest.snapshot.schema_version, 16);
    assert_eq!(manifest.snapshot.tenant_id, tenant);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("upgrade summary");
    let summary: Value = serde_json::from_str(line).unwrap();
    assert_eq!(summary["from_schema"], 16);
    assert_eq!(
        summary["to_schema"],
        blindpass_controller::store::SCHEMA_VERSION
    );
    assert!(
        !stdout.contains(u.backups.to_str().unwrap()),
        "summary must not echo paths"
    );
    u.close().await;
}

/// A database genuinely created by a previous release binary (not rewound from
/// the current schema) upgrades through the locked, backed-up path. The binary is
/// built from an earlier commit and named by `P06_TEST_PREVIOUS_RELEASE_CONTROLLER`.
#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver and a previous-release binary"]
async fn p06_up16_database_created_by_a_previous_release_upgrades() {
    let Ok(previous) = std::env::var("P06_TEST_PREVIOUS_RELEASE_CONTROLLER") else {
        // The binary is built from an earlier commit and is never vendored, so the
        // default driver run cannot supply it. This is a skip, not a pass.
        eprintln!(
            "P06-UP16 SKIPPED: set P06_TEST_PREVIOUS_RELEASE_CONTROLLER to a previous-release controller binary"
        );
        return;
    };
    upgrade_from_release_chain(&[previous]).await;
}

/// A database created by the oldest release in `P06_TEST_RELEASE_CHAIN` (colon
/// separated binaries, oldest first) and migrated by each later release in turn
/// upgrades through the current locked, backed-up path.
#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver and release binaries"]
async fn p06_up17_database_walked_through_several_releases_upgrades() {
    let Ok(chain) = std::env::var("P06_TEST_RELEASE_CHAIN") else {
        eprintln!(
            "P06-UP17 SKIPPED: set P06_TEST_RELEASE_CHAIN to colon-separated release binaries, oldest first"
        );
        return;
    };
    let chain: Vec<String> = chain.split(':').map(str::to_owned).collect();
    assert!(chain.len() >= 2, "a chain needs at least two releases");
    upgrade_from_release_chain(&chain).await;
}

async fn f_count_origin(u: &Upgrade) -> i64 {
    u.f.number("SELECT COUNT(*) FROM operators WHERE id='P06_DUMMY_UP_CHAIN_ORIGIN'")
        .await
}

async fn upgrade_from_release_chain(chain: &[String]) {
    let mut f = Fixture::new(false, false).await;
    f.values.insert(
        "BLINDPASS_KEYS_DIR".into(),
        f.directory.0.display().to_string(),
    );
    // The oldest release initializes the database itself; each later release
    // migrates it one step, in order, and the schema must never move backwards.
    let mut seen = 0_i64;
    for (step, release) in chain.iter().enumerate() {
        let run = Command::new(release)
            .env_clear()
            .envs(&f.values)
            .arg("migrate")
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "release {step} could not {}: {}",
            if step == 0 { "initialize" } else { "migrate" },
            String::from_utf8_lossy(&run.stderr)
        );
        let now = f
            .number("SELECT CAST(schema_version AS BIGINT) FROM controller_meta WHERE id=1")
            .await;
        assert!(
            now > seen || (step == 0 && now > 0),
            "release {step} did not advance the schema ({seen} -> {now})"
        );
        if step == 0 {
            f.sql("INSERT INTO operators (id, username, display_name, password_hash, role, created_at) VALUES ('P06_DUMMY_UP_CHAIN_ORIGIN','up-origin','Origin','x','viewer',1)")
                .await;
        }
        seen = now;
        eprintln!("P06-UP17 release {step} left schema {now}");
    }
    let from = f
        .number("SELECT CAST(schema_version AS BIGINT) FROM controller_meta WHERE id=1")
        .await;
    assert!(
        from < blindpass_controller::store::SCHEMA_VERSION,
        "previous release must be older than this tree (schema {from})"
    );
    f.tenant = {
        let p = SqlitePool::connect(&f.url).await.unwrap();
        let tenant: String = sqlx::query_scalar("SELECT tenant_id FROM controller_meta WHERE id=1")
            .fetch_one(&p)
            .await
            .unwrap();
        p.close().await;
        tenant
    };
    f.sql("INSERT INTO operators (id, username, display_name, password_hash, role, created_at) VALUES ('P06_DUMMY_UP_CANARY','up-canary','Canary','x','viewer',1)")
        .await;
    let admin = f.authority("fenced").await;
    let key = f.directory.file("recovery.pem");
    blindpass_controller::backup::initialize_recovery_key(&key).unwrap();
    let u = Upgrade {
        backups: f.directory.file("backups"),
        f,
        admin,
        key,
    };
    // Without the backup arguments the current binary refuses and changes nothing.
    ChildProcess::spawn(&u.f, "migrate").finish(true).await;
    assert_eq!(u.version().await, from);
    let out = u.migrate(false).await;
    assert_eq!(
        u.version().await,
        blindpass_controller::store::SCHEMA_VERSION
    );
    assert_eq!(
        u.f.number("SELECT COUNT(*) FROM operators WHERE id='P06_DUMMY_UP_CANARY'")
            .await,
        1,
        "upgrade lost state created under the previous release"
    );
    if chain.len() > 1 {
        assert_eq!(
            f_count_origin(&u).await,
            1,
            "upgrade lost state created under the oldest release"
        );
    }
    let dirs = u.backup_dirs();
    assert_eq!(dirs.len(), 1);
    assert!(dirs[0].ends_with(&format!("-v{from}")), "{dirs:?}");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = stdout.lines().find(|l| l.starts_with('{')).unwrap();
    let summary: Value = serde_json::from_str(line).unwrap();
    assert_eq!(summary["from_schema"], from);
    assert_eq!(summary["backup_taken"], true);
    u.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up02_older_schema_without_backup_arguments_refuses_unchanged() {
    let u = Upgrade::new(17).await;
    ChildProcess::spawn(&u.f, "migrate").finish(true).await;
    assert_eq!(u.version().await, 17);
    assert!(u.backup_dirs().is_empty());
    u.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up03_unusable_recovery_key_or_backup_root_refuses_before_any_change() {
    let u = Upgrade::new(16).await;
    // A recovery key readable by others is unsafe custody.
    fs::set_permissions(&u.key, fs::Permissions::from_mode(0o644)).unwrap();
    u.migrate(true).await;
    assert_eq!(u.version().await, 16);
    fs::set_permissions(&u.key, fs::Permissions::from_mode(0o600)).unwrap();
    // A backup root that is a symlink is refused too.
    let _ = fs::remove_dir_all(&u.backups);
    std::os::unix::fs::symlink(u.f.directory.file("elsewhere"), &u.backups).unwrap();
    u.migrate(true).await;
    assert_eq!(u.version().await, 16);
    // A missing recovery key.
    fs::remove_file(&u.backups).unwrap();
    fs::remove_file(&u.key).unwrap();
    u.migrate(true).await;
    assert_eq!(u.version().await, 16);
    assert!(
        u.backup_dirs().is_empty(),
        "failed backups must leave no published backup"
    );
    u.close().await;
}

/// P06-D29: the upgrade host holds a signing credential and only the recipient
/// certificate; the pre-upgrade backup opens only with the offline recipient key.
#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up17_split_custody_pre_upgrade_backup_needs_the_offline_recipient_key() {
    use blindpass_controller::backup::{
        KeyRole, OpenKeys, initialize_role_credentials, verify_backup_with,
    };
    let u = Upgrade::new(16).await;
    let signing = u.f.directory.file("signing.pem");
    let signing_cert = u.f.directory.file("signing-certificate.pem");
    let recipient = u.f.directory.file("recipient.pem");
    let recipient_cert = u.f.directory.file("recipient-certificate.pem");
    initialize_role_credentials(KeyRole::Signing, &signing, &signing_cert).unwrap();
    initialize_role_credentials(KeyRole::Recipient, &recipient, &recipient_cert).unwrap();
    let split_args = |recipient_file: &std::path::Path| -> Vec<String> {
        vec![
            "migrate".into(),
            "--pre-upgrade-backup-dir".into(),
            u.backups.display().to_string(),
            "--signing-credential-file".into(),
            signing.display().to_string(),
            "--recipient-certificate-file".into(),
            recipient_file.display().to_string(),
        ]
    };
    // The recipient credential (private key) on the backup host is refused.
    let refused = split_args(&recipient);
    let refs: Vec<&str> = refused.iter().map(String::as_str).collect();
    ChildProcess::spawn_args(&u.f, &refs).finish(true).await;
    assert_eq!(u.version().await, 16, "refused upgrade changed the schema");
    assert!(u.backup_dirs().is_empty());
    let accepted = split_args(&recipient_cert);
    let refs: Vec<&str> = accepted.iter().map(String::as_str).collect();
    ChildProcess::spawn_args(&u.f, &refs).finish(false).await;
    assert_eq!(
        u.version().await,
        blindpass_controller::store::SCHEMA_VERSION
    );
    let dirs = u.backup_dirs();
    assert_eq!(dirs.len(), 1);
    let archive = fs::read_dir(u.backups.join(&dirs[0]))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "bpbackup"))
        .unwrap();
    let work = u.f.directory.file("verify-work");
    fs::create_dir(&work).unwrap();
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    let manifest = verify_backup_with(
        &archive,
        &OpenKeys::Split {
            recipient_key: &recipient,
            signing_certificate: &signing_cert,
        },
        &work,
    )
    .await
    .unwrap();
    assert_eq!(manifest.snapshot.schema_version, 16);
    assert_eq!(manifest.snapshot.tenant_id, u.f.tenant);
    // Nothing the upgrade host held opens the archive.
    assert!(
        verify_backup_with(&archive, &OpenKeys::Single(&signing), &work)
            .await
            .is_err()
    );
    assert!(
        verify_backup_with(
            &archive,
            &OpenKeys::Split {
                recipient_key: &signing,
                signing_certificate: &signing_cert,
            },
            &work,
        )
        .await
        .is_err()
    );
    u.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up04_future_and_unsupported_schemas_refuse_without_a_backup() {
    for version in [blindpass_controller::store::SCHEMA_VERSION + 1, 15] {
        let u = Upgrade::new(blindpass_controller::store::SCHEMA_VERSION).await;
        u.f.sql(&format!(
            "UPDATE controller_meta SET schema_version={version} WHERE id=1"
        ))
        .await;
        u.migrate(true).await;
        assert_eq!(u.version().await, version);
        assert!(
            u.backup_dirs().is_empty(),
            "refusal must not publish a backup"
        );
        u.close().await;
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up05_retention_keeps_the_three_newest_pre_upgrade_backups_only() {
    let u = Upgrade::new(16).await;
    fs::create_dir(&u.backups).unwrap();
    fs::set_permissions(&u.backups, fs::Permissions::from_mode(0o700)).unwrap();
    for stamp in [1u64, 2, 3, 4] {
        let dir = u.backups.join(format!("pre-upgrade-{stamp:013}-v16"));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("controller-backup-old.bpbackup"), b"old").unwrap();
    }
    // Names that do not match the exact pattern, and a link, are never touched.
    fs::create_dir(u.backups.join("pre-upgrade-keep-me")).unwrap();
    fs::create_dir(u.backups.join("operator-notes")).unwrap();
    std::os::unix::fs::symlink(
        u.f.directory.file("elsewhere"),
        u.backups.join("pre-upgrade-0000000000000-v16"),
    )
    .unwrap();
    u.migrate(false).await;
    let kept: Vec<String> = u
        .backup_dirs()
        .into_iter()
        .filter(|n| n != "pre-upgrade-keep-me" && n != "pre-upgrade-0000000000000-v16")
        .collect();
    assert_eq!(kept.len(), 3, "retention must keep exactly three: {kept:?}");
    assert!(
        kept.iter()
            .all(|n| n != "pre-upgrade-0000000000001-v16" && n != "pre-upgrade-0000000000002-v16")
    );
    assert!(u.backups.join("operator-notes").is_dir());
    assert!(u.backups.join("pre-upgrade-keep-me").is_dir());
    assert!(
        fs::symlink_metadata(u.backups.join("pre-upgrade-0000000000000-v16"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    u.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up06_current_schema_makes_no_backup_and_repeats_idempotently() {
    let u = Upgrade::new(blindpass_controller::store::SCHEMA_VERSION).await;
    u.migrate(false).await;
    assert!(
        u.backup_dirs().is_empty(),
        "a current schema needs no pre-upgrade backup"
    );
    assert_eq!(
        u.f.number("SELECT COUNT(*) FROM operators WHERE id='P06_DUMMY_UP_CANARY'")
            .await,
        1
    );
    u.close().await;
    let u = Upgrade::new(16).await;
    u.migrate(false).await;
    let first = u.backup_dirs();
    u.migrate(false).await;
    assert_eq!(
        u.backup_dirs(),
        first,
        "a completed upgrade must not take another backup"
    );
    u.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up07_interrupted_upgrade_is_repeatable() {
    // Newer tables from an interrupted attempt exist while the version marker
    // still names the old schema; the rerun backs up, completes and verifies.
    let u = Upgrade::new(blindpass_controller::store::SCHEMA_VERSION).await;
    u.f.sql("UPDATE controller_meta SET schema_version=16 WHERE id=1")
        .await;
    u.migrate(false).await;
    assert_eq!(
        u.version().await,
        blindpass_controller::store::SCHEMA_VERSION
    );
    assert_eq!(u.backup_dirs().len(), 1);
    u.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_up08_upgrade_needs_the_fenced_owner_and_never_runs_active() {
    let u = Upgrade::new(16).await;
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&u.f.tenant)
        .execute(&u.admin)
        .await
        .unwrap();
    u.migrate(true).await;
    assert_eq!(u.version().await, 16);
    assert!(u.backup_dirs().is_empty());
    u.close().await;
}

/// Found by the actual relay rehearsal: production `serve` claimed ownership and then
/// closed the authority pool the owner shares, so every later broker-trust read or
/// publish (node approval, rotation, revocation) failed and fenced the controller.
#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_rr_claimed_serving_owner_keeps_a_working_authority_pool() {
    use blindpass_controller::recovery_authority::{BrokerTrustDraft, BrokerTrustState};
    let mut f = Fixture::new(true, false).await;
    let admin = f.authority("active").await;
    let config = blindpass_controller::config::Config::from_variables(f.values.clone()).unwrap();
    let session = blindpass_controller::ownership_session::claim_ownership(&config, false)
        .await
        .unwrap()
        .expect("authority-backed ownership");
    assert!(session.owner.is_active());
    let node = "nd_p06_dummy_node";
    assert!(session.owner.broker_trust(node).await.unwrap().is_none());
    let published = session
        .owner
        .publish_broker_trust(
            0,
            &BrokerTrustDraft {
                node_id: node.into(),
                key_version: 1,
                signing_public: base64_url_encode(&[7; 32]),
                recipient_public: base64_url_encode(&[8; 32]),
                state: BrokerTrustState::Active,
                pending: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(published.identity.node_id, node);
    assert!(session.owner.broker_trust(node).await.unwrap().is_some());
    assert!(
        !session.owner.is_fenced(),
        "a working serving owner must not fence itself"
    );
    session.owner.quiesce().await.unwrap();
    drop(session);
    admin.close().await;
}

/// The pinned PostgreSQL toolkit exists only in the controller image.
fn pg_toolkit_present() -> bool {
    std::path::Path::new("/usr/lib/postgresql/16/bin/pg_dump").exists()
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver with --controller-backend postgres"]
async fn p06_up10_postgresql_older_schema_refuses_when_the_pinned_toolkit_is_absent() {
    if !support::postgres_selected() || pg_toolkit_present() {
        // Applies only to a PostgreSQL controller run on a host without the
        // pinned toolkit; the image run executes UP13 and UP14 instead.
        eprintln!("p06_up10 not applicable: SQLite backend or toolkit present");
        return;
    }
    let u = Upgrade::with_backend(16, true).await;
    u.migrate(true).await;
    assert_eq!(u.version().await, 16);
    assert!(u.backup_dirs().is_empty());
    u.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver in the pinned-toolkit image"]
async fn p06_up13_postgresql_older_schema_takes_a_verified_backup_then_migrates() {
    if !support::postgres_selected() || !pg_toolkit_present() {
        eprintln!("p06_up13 not applicable: needs the PostgreSQL backend and the pinned toolkit");
        return;
    }
    let u = Upgrade::with_backend(16, true).await;
    let tenant = u.f.tenant.clone();
    let out = u.migrate(false).await;
    assert_eq!(
        u.version().await,
        blindpass_controller::store::SCHEMA_VERSION
    );
    assert_eq!(
        u.f.number("SELECT COUNT(*) FROM operators WHERE id='P06_DUMMY_UP_CANARY'")
            .await,
        1,
        "upgrade lost existing state"
    );
    let dirs = u.backup_dirs();
    assert_eq!(dirs.len(), 1, "exactly one pre-upgrade backup expected");
    assert!(dirs[0].ends_with("-v16"));
    let archives: Vec<_> = fs::read_dir(u.backups.join(&dirs[0]))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bpbackup"))
        .collect();
    assert_eq!(archives.len(), 1);
    let work = u.f.directory.file("verify-work");
    fs::create_dir(&work).unwrap();
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    let manifest = blindpass_controller::backup::verify_backup(&archives[0], &u.key, &work)
        .await
        .unwrap();
    assert_eq!(manifest.snapshot.schema_version, 16);
    assert_eq!(manifest.snapshot.tenant_id, tenant);
    assert_eq!(
        manifest.backend,
        blindpass_controller::backup::Backend::Postgres
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let summary: Value = serde_json::from_str(
        stdout
            .lines()
            .find(|l| l.starts_with('{'))
            .expect("summary"),
    )
    .unwrap();
    assert_eq!(summary["from_schema"], 16);
    assert_eq!(summary["backup_taken"], true);
    u.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver in the pinned-toolkit image"]
async fn p06_up14_postgresql_failed_backup_refuses_before_any_change() {
    if !support::postgres_selected() || !pg_toolkit_present() {
        eprintln!("p06_up14 not applicable: needs the PostgreSQL backend and the pinned toolkit");
        return;
    }
    let u = Upgrade::with_backend(17, true).await;
    // Unsafe key custody, then a missing key: no migration, no published backup.
    fs::set_permissions(&u.key, fs::Permissions::from_mode(0o644)).unwrap();
    u.migrate(true).await;
    assert_eq!(u.version().await, 17);
    fs::remove_file(&u.key).unwrap();
    u.migrate(true).await;
    assert_eq!(u.version().await, 17);
    assert!(u.backup_dirs().is_empty());
    // Without backup arguments an older PostgreSQL schema is refused as well.
    ChildProcess::spawn(&u.f, "migrate").finish(true).await;
    assert_eq!(u.version().await, 17);
    u.close().await;
}

// ---- Slice 8: planned same-owner handoff (P06-D28) ----
//
// The source is fenced, exported (authenticated archive plus a persisted
// retirement marker) and imported under the SAME owner and unchanged epoch. The
// authority record stays fenced until the operator's ordinary activation.

struct Handoff {
    f: Fixture,
    admin: PgPool,
    key: std::path::PathBuf,
    out: std::path::PathBuf,
}

impl Handoff {
    async fn new() -> Self {
        Self::with_backend(false).await
    }
    async fn with_backend(pg: bool) -> Self {
        let mut f = Fixture::new(true, pg).await;
        f.values.insert(
            "BLINDPASS_KEYS_DIR".into(),
            f.directory.0.display().to_string(),
        );
        let admin = f.authority("fenced").await;
        f.sql("INSERT INTO operators (id, username, display_name, password_hash, role, created_at) VALUES ('P06_DUMMY_HO_CANARY','ho-canary','Canary','x','viewer',1)")
            .await;
        let key = f.directory.file("recovery.pem");
        blindpass_controller::backup::initialize_recovery_key(&key).unwrap();
        let out = f.directory.file("handoff-out");
        Self { f, admin, key, out }
    }
    async fn record(&self) -> (i64, i64, String) {
        sqlx::query_as("SELECT epoch, revision, phase FROM blindpass_authority.recovery_authority WHERE tenant_id=$1")
            .bind(&self.f.tenant)
            .fetch_one(&self.admin)
            .await
            .unwrap()
    }
    /// What `authority-activate.sql` does to a fenced or active record.
    async fn activate(&self) {
        let n = sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active', revision=revision+1 WHERE tenant_id=$1 AND phase IN ('fenced','active')")
            .bind(&self.f.tenant)
            .execute(&self.admin)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(n, 1);
    }
    /// What `authority-fence.sql` does to an active record.
    async fn fence(&self) {
        let n = sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced', revision=revision+1 WHERE tenant_id=$1 AND phase='active'")
            .bind(&self.f.tenant)
            .execute(&self.admin)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(n, 1);
    }
    fn export_args(&self, id: &str) -> Vec<String> {
        [
            "handoff",
            "export",
            "--output",
            self.out.to_str().unwrap(),
            "--recovery-key-file",
            self.key.to_str().unwrap(),
            "--handoff-id",
            id,
        ]
        .map(String::from)
        .to_vec()
    }
    async fn run(fixture: &Fixture, args: Vec<String>, must_refuse: bool) -> Output {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        ChildProcess::spawn_args(fixture, &refs)
            .finish(must_refuse)
            .await
    }
    async fn export(&self, id: &str, must_refuse: bool) -> Output {
        Self::run(&self.f, self.export_args(id), must_refuse).await
    }
    fn json_line(out: &Output) -> Value {
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        serde_json::from_str(
            stdout
                .lines()
                .find(|l| l.starts_with('{'))
                .unwrap_or_else(|| panic!("no JSON summary in: {stdout}")),
        )
        .unwrap()
    }
    fn destination_root(&self) -> std::path::PathBuf {
        self.f.directory.file("destination")
    }
    fn import_args(&self, receipt: &Value, root: &std::path::Path) -> Vec<String> {
        let name = |key: &str| self.out.join(receipt[key].as_str().unwrap());
        [
            "handoff".to_owned(),
            "import".into(),
            "--archive".into(),
            name("archive").display().to_string(),
            "--receipt".into(),
            name("receipt").display().to_string(),
            "--recovery-key-file".into(),
            self.key.display().to_string(),
            "--destination".into(),
            root.display().to_string(),
            "--authority-url-file".into(),
            self.f.directory.file("authority-url").display().to_string(),
            "--tenant-id".into(),
            self.f.tenant.clone(),
            "--owner-id".into(),
            "P06_DUMMY_OWNER".into(),
        ]
        .to_vec()
    }
    async fn import(&self, receipt: &Value, must_refuse: bool) -> Output {
        Self::run(
            &self.f,
            self.import_args(receipt, &self.destination_root()),
            must_refuse,
        )
        .await
    }
    fn source_marker(&self) -> std::path::PathBuf {
        self.f.directory.file("handoff-marker.json")
    }
    /// Environment of a controller that runs from the imported destination root.
    fn destination_fixture(&self) -> Fixture {
        let root = self.destination_root();
        let scratch = TestDirectory::new();
        let url = format!(
            "sqlite://{}?mode=rw",
            root.join("data/controller.db").display()
        );
        fs::write(scratch.file("database-url"), url.as_bytes()).unwrap();
        fs::set_permissions(
            scratch.file("database-url"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut values = self.f.values.clone();
        for (variable, name) in [
            ("BLINDPASS_ROOT_SECRET_FILE", "root-secret"),
            ("BLINDPASS_AGENT_JWT_SECRET_FILE", "agent-jwt-secret"),
            ("BLINDPASS_ISSUER_KEY_FILE", "issuer-key"),
        ] {
            values.insert(
                variable.into(),
                root.join("keys").join(name).display().to_string(),
            );
        }
        values.insert(
            "BLINDPASS_KEYS_DIR".into(),
            root.join("keys").display().to_string(),
        );
        values.insert(
            "BLINDPASS_DATABASE_URL_FILE".into(),
            scratch.file("database-url").display().to_string(),
        );
        values.insert(
            "BLINDPASS_ADMIN_SOCKET_PATH".into(),
            scratch.file("admin.sock").display().to_string(),
        );
        values.insert("BLINDPASS_LISTEN".into(), address.to_string());
        Fixture {
            directory: scratch,
            values,
            url,
            tenant: self.f.tenant.clone(),
            issuer: self.f.issuer.clone(),
            address,
            pg: false,
        }
    }
    async fn close(self) {
        self.admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_ho01_fenced_handoff_moves_state_under_the_same_owner_and_retires_the_source() {
    let h = Handoff::new().await;
    let before = h.record().await;
    assert_eq!(before.2, "fenced");
    let exported = Handoff::json_line(&h.export("ho_one", false).await);
    assert_eq!(exported["handoff"], "exported");
    assert_eq!(exported["handoff_id"], "ho_one");
    assert_eq!(exported["epoch"], before.0);
    assert_eq!(exported["revision"], before.1);
    // Exporting touches neither the authority record nor the source state.
    assert_eq!(h.record().await, before);
    let marker: Value = serde_json::from_slice(&fs::read(h.source_marker()).unwrap()).unwrap();
    assert_eq!(marker["role"], "source");
    assert_eq!(marker["handoff_id"], "ho_one");
    assert_eq!(
        fs::metadata(h.source_marker())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // A retired source refuses maintenance, even under its still-fenced record.
    let refused = ChildProcess::spawn(&h.f, "migrate").finish(true).await;
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("retired"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    h.import(&exported, false).await;
    let root = h.destination_root();
    for name in ["root-secret", "agent-jwt-secret", "issuer-key"] {
        assert_eq!(
            fs::read(root.join("keys").join(name)).unwrap(),
            fs::read(h.f.directory.file(name)).unwrap(),
            "{name} must be the source's key"
        );
        assert_eq!(
            fs::metadata(root.join("keys").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    // An import is not a restore: the record is untouched and still fenced.
    assert_eq!(h.record().await, before);
    let dest_marker: Value =
        serde_json::from_slice(&fs::read(root.join("data/handoff-marker.json")).unwrap()).unwrap();
    assert_eq!(dest_marker["role"], "destination");
    let destination = h.destination_fixture();
    assert_eq!(
        destination
            .number("SELECT COUNT(*) FROM operators WHERE id='P06_DUMMY_HO_CANARY'")
            .await,
        1,
        "state did not move"
    );
    assert_eq!(
        destination
            .number("SELECT issuer_epoch FROM controller_meta WHERE id=1")
            .await,
        before.0
    );
    assert_eq!(
        destination
            .number("SELECT COUNT(*) FROM controller_recoveries")
            .await,
        0,
        "a handoff must not create recovery state"
    );
    h.activate().await;
    let mut serving = ChildProcess::spawn(&destination, "serve");
    serving.ready(destination.address, 200).await;
    assert!(
        !root.join("data/handoff-marker.json").exists(),
        "a successful first start consumes the destination marker"
    );
    assert_eq!(
        destination
            .number("SELECT COUNT(*) FROM operators WHERE id='P06_DUMMY_HO_CANARY'")
            .await,
        1
    );
    drop(serving);
    h.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_ho02_import_refuses_every_mismatch_and_leaves_no_destination() {
    let h = Handoff::new().await;
    let exported = Handoff::json_line(&h.export("ho_two", false).await);
    let before = h.record().await;
    let root = h.destination_root();
    let args = h.import_args(&exported, &root);
    let with = |flag: &str, value: &str| -> Vec<String> {
        let mut args = args.clone();
        let at = args.iter().position(|a| a == flag).unwrap();
        args[at + 1] = value.to_owned();
        args
    };
    // Wrong tenant, wrong owner.
    for refused in [
        with("--tenant-id", "P06_DUMMY_OTHER_TENANT"),
        with("--owner-id", "P06_DUMMY_OTHER_OWNER"),
    ] {
        Handoff::run(&h.f, refused, true).await;
        assert!(!root.exists());
    }
    // A tampered archive is refused by its digest, and a forged receipt that
    // carries the tampered digest is still refused by the authenticated archive.
    let archive = h.out.join(exported["archive"].as_str().unwrap());
    let mut bytes = fs::read(&archive).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x55;
    let tampered_name = "tampered.bpbackup";
    fs::write(h.out.join(tampered_name), &bytes).unwrap();
    fs::set_permissions(h.out.join(tampered_name), fs::Permissions::from_mode(0o600)).unwrap();
    let mut tampered = exported.clone();
    tampered["archive"] = json!(tampered_name);
    Handoff::run(&h.f, h.import_args(&tampered, &root), true).await;
    assert!(!root.exists());
    let digest: String = blindpass_core::custody::sha256(&bytes)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let receipt_path = h.out.join(exported["receipt"].as_str().unwrap());
    let mut forged: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    forged["archive_sha256"] = json!(digest);
    forged["archive"] = json!(tampered_name);
    fs::write(h.out.join("forged-receipt.json"), forged.to_string()).unwrap();
    fs::set_permissions(
        h.out.join("forged-receipt.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut forged_args = h.import_args(&tampered, &root);
    let at = forged_args.iter().position(|a| a == "--receipt").unwrap();
    forged_args[at + 1] = h.out.join("forged-receipt.json").display().to_string();
    Handoff::run(&h.f, forged_args, true).await;
    assert!(!root.exists());
    // An existing destination is never touched.
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("keep"), b"P06_DUMMY_KEEP").unwrap();
    Handoff::run(&h.f, args.clone(), true).await;
    assert_eq!(fs::read(root.join("keep")).unwrap(), b"P06_DUMMY_KEEP");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    fs::remove_dir_all(&root).unwrap();
    assert_eq!(
        h.record().await,
        before,
        "refusals must not touch authority"
    );
    // A record that moved on (activated, then fenced again) no longer matches the
    // exported revision, and an active record is never an import target.
    h.activate().await;
    Handoff::run(&h.f, args.clone(), true).await;
    assert!(!root.exists());
    h.fence().await;
    Handoff::run(&h.f, args.clone(), true).await;
    assert!(!root.exists());
    h.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_ho03_abort_resumes_the_source_only_before_anything_activated() {
    let h = Handoff::new().await;
    let abort = |id: &str| -> Vec<String> {
        ["handoff", "abort", "--handoff-id", id]
            .map(String::from)
            .to_vec()
    };
    let exported = Handoff::json_line(&h.export("ho_three", false).await);
    // Wrong id or no marker: refused, marker retained.
    Handoff::run(&h.f, abort("ho_other"), true).await;
    assert!(h.source_marker().exists());
    // The destination exists but was never activated: abort is allowed and the
    // source resumes under an ordinary activation.
    h.import(&exported, false).await;
    let out = Handoff::run(&h.f, abort("ho_three"), false).await;
    assert_eq!(Handoff::json_line(&out)["handoff"], "aborted");
    assert!(!h.source_marker().exists());
    let (_, revision, phase) = h.record().await;
    assert_eq!(phase, "fenced");
    assert_eq!(revision, exported["revision"].as_i64().unwrap());
    // Abort without a marker is refused (nothing to abort).
    Handoff::run(&h.f, abort("ho_three"), true).await;
    h.activate().await;
    let mut source = ChildProcess::spawn(&h.f, "serve");
    source.ready(h.f.address, 200).await;
    drop(source);
    // Once an activation happened after export, abort is refused for good.
    h.fence().await;
    let second = Handoff::json_line(&h.export("ho_three_b", false).await);
    assert_eq!(second["revision"].as_i64().unwrap(), h.record().await.1);
    h.activate().await;
    Handoff::run(&h.f, abort("ho_three_b"), true).await;
    assert!(h.source_marker().exists());
    h.fence().await;
    Handoff::run(&h.f, abort("ho_three_b"), true).await;
    assert!(
        h.source_marker().exists(),
        "rollback after activation is restore-only"
    );
    h.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_ho04_a_stale_destination_cannot_start_after_the_source_resumed() {
    let h = Handoff::new().await;
    let exported = Handoff::json_line(&h.export("ho_four", false).await);
    h.import(&exported, false).await;
    let abort = ["handoff", "abort", "--handoff-id", "ho_four"].map(String::from);
    Handoff::run(&h.f, abort.to_vec(), false).await;
    // The source resumes and consumes the first activation.
    h.activate().await;
    let mut source = ChildProcess::spawn(&h.f, "serve");
    source.ready(h.f.address, 200).await;
    drop(source);
    // The stale destination now needs a later activation and must refuse it.
    h.fence().await;
    h.activate().await;
    let destination = h.destination_fixture();
    let before = fs::read(h.destination_root().join("data/controller.db")).unwrap();
    let out = ChildProcess::spawn(&destination, "serve")
        .finish(true)
        .await;
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("handoff_stale"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        h.destination_root()
            .join("data/handoff-marker.json")
            .exists()
    );
    assert_eq!(
        fs::read(h.destination_root().join("data/controller.db")).unwrap(),
        before,
        "a refused destination must not be written"
    );
    h.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_ho05_export_is_repeatable_and_refuses_unsafe_starts_without_a_marker() {
    let h = Handoff::new().await;
    // An active record is never exported from, and leaves nothing behind.
    h.activate().await;
    h.export("ho_five", true).await;
    assert!(!h.source_marker().exists());
    assert!(!h.out.exists() || fs::read_dir(&h.out).unwrap().count() == 0);
    h.fence().await;
    // Unusable custody refuses before any marker.
    fs::set_permissions(&h.key, fs::Permissions::from_mode(0o644)).unwrap();
    h.export("ho_five", true).await;
    assert!(!h.source_marker().exists());
    fs::set_permissions(&h.key, fs::Permissions::from_mode(0o600)).unwrap();
    // The same id repeats to the same receipt; another id is refused while the
    // first handoff is open.
    let first = Handoff::json_line(&h.export("ho_five", false).await);
    let again = Handoff::json_line(&h.export("ho_five", false).await);
    assert_eq!(first, again);
    let archives = fs::read_dir(&h.out)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".bpbackup")
        })
        .count();
    assert_eq!(archives, 1, "a repeat must reuse the exported archive");
    h.export("ho_six", true).await;
    h.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver with --controller-backend postgres"]
async fn p06_ho07_a_postgresql_controller_has_nothing_to_hand_off() {
    if !support::postgres_selected() {
        eprintln!("p06_ho07 not applicable: SQLite backend");
        return;
    }
    let h = Handoff::with_backend(true).await;
    h.export("ho_seven", true).await;
    assert!(!h.source_marker().exists());
    assert!(!h.out.exists() || fs::read_dir(&h.out).unwrap().count() == 0);
    // The refusal changed nothing in the authority.
    let (_, revision, phase) = h.record().await;
    assert_eq!((revision, phase.as_str()), (1, "fenced"));
    h.close().await;
}

/// P06-D29: export seals with a signing credential and the recipient certificate
/// only; import opens with the offline recipient key and stages decrypted keys on
/// tmpfs, never on the persistent disk.
#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_ho08_split_custody_handoff_stages_decrypted_material_on_tmpfs_only() {
    use blindpass_controller::backup::{KeyRole, initialize_role_credentials};
    let h = Handoff::new().await;
    let file = |name: &str| h.f.directory.file(name);
    initialize_role_credentials(
        KeyRole::Signing,
        &file("signing.pem"),
        &file("signing-certificate.pem"),
    )
    .unwrap();
    initialize_role_credentials(
        KeyRole::Recipient,
        &file("recipient.pem"),
        &file("recipient-certificate.pem"),
    )
    .unwrap();
    initialize_role_credentials(
        KeyRole::Signing,
        &file("other-signing.pem"),
        &file("other-signing-certificate.pem"),
    )
    .unwrap();
    let export = |recipient_file: &str| -> Vec<String> {
        [
            "handoff",
            "export",
            "--output",
            h.out.to_str().unwrap(),
            "--signing-credential-file",
            file("signing.pem").to_str().unwrap(),
            "--recipient-certificate-file",
            file(recipient_file).to_str().unwrap(),
            "--handoff-id",
            "ho_eight",
        ]
        .map(String::from)
        .to_vec()
    };
    // A recipient file that still holds the private key is refused: no archive,
    // no retirement marker.
    Handoff::run(&h.f, export("recipient.pem"), true).await;
    assert!(!h.source_marker().exists());
    assert!(!h.out.exists() || fs::read_dir(&h.out).unwrap().count() == 0);
    // Mixing both credential models is refused.
    let mut mixed = export("recipient-certificate.pem");
    mixed.extend(["--recovery-key-file".into(), h.key.display().to_string()]);
    Handoff::run(&h.f, mixed, true).await;
    assert!(!h.source_marker().exists());
    let exported =
        Handoff::json_line(&Handoff::run(&h.f, export("recipient-certificate.pem"), false).await);
    assert_eq!(exported["handoff"], "exported");
    let staging = std::path::PathBuf::from(format!("/dev/shm/p06-ho08-{}", std::process::id()));
    let disk = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("p06-ho08-disk-{}", std::process::id()));
    let import = |key: &str, signer: &str, staging: &std::path::Path, root: &std::path::Path| {
        let mut args = h.import_args(&exported, root);
        let index = args
            .iter()
            .position(|a| a == "--recovery-key-file")
            .unwrap();
        args.splice(
            index..=index + 1,
            [
                "--recipient-key-file".to_owned(),
                file(key).display().to_string(),
                "--signing-certificate-file".into(),
                file(signer).display().to_string(),
                "--staging-directory".into(),
                staging.display().to_string(),
            ],
        );
        args
    };
    let root = h.destination_root();
    // The host's own credential and the wrong signer never open the archive.
    for (key, signer) in [
        ("signing.pem", "signing-certificate.pem"),
        ("recipient.pem", "other-signing-certificate.pem"),
    ] {
        Handoff::run(&h.f, import(key, signer, &staging, &root), true).await;
        assert!(!root.exists(), "refused import published state");
        assert!(
            !staging.exists() || fs::read_dir(&staging).unwrap().count() == 0,
            "refused import left decrypted material in staging"
        );
    }
    // A persistent-disk staging directory is refused outright.
    Handoff::run(
        &h.f,
        import("recipient.pem", "signing-certificate.pem", &disk, &root),
        true,
    )
    .await;
    assert!(!root.exists());
    assert!(
        !disk.exists(),
        "a refused disk directory must not be created"
    );
    // A corrupted or wrong digest pin is refused before decryption.
    let mut pinned = import("recipient.pem", "signing-certificate.pem", &staging, &root);
    pinned.extend(["--expected-archive-sha256".into(), "0".repeat(64)]);
    Handoff::run(&h.f, pinned, true).await;
    assert!(!root.exists());
    // The offline recipient key and the pinned signer import it.
    let mut good = import("recipient.pem", "signing-certificate.pem", &staging, &root);
    good.extend([
        "--expected-archive-sha256".into(),
        exported["archive_sha256"].as_str().unwrap().to_owned(),
    ]);
    Handoff::run(&h.f, good, false).await;
    for name in ["root-secret", "agent-jwt-secret", "issuer-key"] {
        assert_eq!(
            fs::read(root.join("keys").join(name)).unwrap(),
            fs::read(h.f.directory.file(name)).unwrap(),
            "{name} must be the source's key"
        );
    }
    assert!(
        !staging.exists() || fs::read_dir(&staging).unwrap().count() == 0,
        "decrypted keys remained in tmpfs staging after import"
    );
    let _ = fs::remove_dir(&staging);
    h.close().await;
}

#[cfg(feature = "p02-test-failpoints")]
#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver and the failpoint build"]
async fn p06_ho06_interrupted_export_and_import_repeat_safely() {
    let mut h = Handoff::new().await;
    h.f.values.insert("BLINDPASS_TEST_MODE".into(), "1".into());
    h.f.values.insert(
        "BLINDPASS_TEST_FAILPOINT".into(),
        "handoff_export_after_archive".into(),
    );
    let died = h.export("ho_seven", true).await;
    assert_eq!(died.status.code(), Some(86));
    assert!(
        !h.source_marker().exists(),
        "no marker before the archive is sealed"
    );
    h.f.values.remove("BLINDPASS_TEST_FAILPOINT");
    let exported = Handoff::json_line(&h.export("ho_seven", false).await);
    assert!(h.source_marker().exists());
    let mut args = h.import_args(&exported, &h.destination_root());
    h.f.values.insert(
        "BLINDPASS_TEST_FAILPOINT".into(),
        "handoff_import_before_publish".into(),
    );
    let died = Handoff::run(&h.f, args.clone(), true).await;
    assert_eq!(died.status.code(), Some(86));
    assert!(
        !h.destination_root().exists(),
        "no destination before publication"
    );
    h.f.values.remove("BLINDPASS_TEST_FAILPOINT");
    args = h.import_args(&exported, &h.destination_root());
    Handoff::run(&h.f, args, false).await;
    assert!(h.destination_root().join("data/controller.db").exists());
    h.close().await;
}
