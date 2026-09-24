// SPDX-License-Identifier: AGPL-3.0-only

use axum::Router;
use blindpass_controller::{
    app::build_app,
    config::Config,
    store::{ApprovalRecord, Store},
};
use blindpass_core::custody::sha256;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blindpass-admin-session-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create admin session test directory");
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

async fn request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> HttpResponse {
    let body = body.map(Value::to_string).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(&body);

    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect local HTTP test server");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send HTTP request");
    stream.flush().await.expect("flush HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read HTTP response");
    let response = String::from_utf8(response).expect("HTTP response is UTF-8");
    let (header_text, body_text) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("HTTP response header separator missing: {response:?}"));
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("HTTP status code");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let body = if body_text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body_text).expect("response body is JSON")
    };
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn cookie_header(response: &HttpResponse, name: &str) -> String {
    response
        .headers
        .iter()
        .filter(|(header, _)| header == "set-cookie")
        .find_map(|(_, value)| {
            let pair = value.split(';').next()?;
            let (cookie_name, cookie_value) = pair.split_once('=')?;
            (cookie_name == name).then(|| format!("{name}={cookie_value}"))
        })
        .expect("expected response cookie")
}

fn token_hash(token: &str) -> String {
    sha256(token.as_bytes())
        .expect("sha256 token")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn approval_record(reference: &str, approver_ids: Vec<String>) -> ApprovalRecord {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_millis() as i64;
    ApprovalRecord {
        approval_reference: reference.to_owned(),
        requester_id: "payments/ring/blue".to_owned(),
        workspace_id: "tenant-fixture".to_owned(),
        secret_name: "db.token".to_owned(),
        purpose: "local approval route test".to_owned(),
        fulfiller_hint: "billing/ring/green".to_owned(),
        rule_id: Some("requires-admin".to_owned()),
        reason: "approval is required".to_owned(),
        requester_ring: Some("payments".to_owned()),
        fulfiller_ring: Some("billing".to_owned()),
        approver_ids,
        approver_rings: Vec::new(),
        status: "pending".to_owned(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 60_000,
        decided_at_ms: None,
        decided_by: None,
    }
}

#[tokio::test]
async fn bootstrap_login_refresh_csrf_and_replay_are_enforced_over_http() {
    let directory = TestDirectory::new();
    let (database_url, postgres_schema): (String, Option<(PgPool, String)>) =
        if std::env::var("P02_TEST_BACKEND").as_deref() == Ok("postgres") {
            let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
                .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                .expect("P02_TEST_POSTGRES_URL or CONTRACT_DATABASE_URL is required");
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos();
            let schema = format!("p02_admin_{}_{nonce}", std::process::id());
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&parent_url)
                .await
                .expect("connect PostgreSQL admin HTTP fixture");
            sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                .execute(&pool)
                .await
                .expect("create isolated PostgreSQL admin schema");
            let separator = if parent_url.contains('?') { '&' } else { '?' };
            (
                format!("{parent_url}{separator}options=-c%20search_path%3D{schema}"),
                Some((pool, schema)),
            )
        } else {
            assert!(
                matches!(
                    std::env::var("P02_TEST_BACKEND").as_deref(),
                    Ok("sqlite") | Err(_)
                ),
                "unknown P02_TEST_BACKEND"
            );
            let database_path = directory.file("controller.db");
            (
                format!("sqlite://{}?mode=rwc", database_path.display()),
                None,
            )
        };
    let credentials = [
        ("database.url", database_url.clone()),
        ("root.secret", "R".repeat(32)),
        ("agent.secret", "A".repeat(32)),
    ];
    for (name, value) in credentials {
        let path = directory.file(name);
        std::fs::write(&path, value).expect("write test credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("protect test credential");
    }
    let config = Config::from_variables([
        ("BLINDPASS_LISTEN", "127.0.0.1:0"),
        ("BLINDPASS_PUBLIC_URL", "http://127.0.0.1:8080"),
        ("BLINDPASS_UI_BASE_URL", "http://127.0.0.1:5175"),
        (
            "BLINDPASS_DATABASE_URL_FILE",
            directory.file("database.url").to_str().unwrap(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE",
            directory.file("root.secret").to_str().unwrap(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            directory.file("agent.secret").to_str().unwrap(),
        ),
    ])
    .expect("valid local test config");
    let store = Store::connect(&database_url)
        .await
        .expect("connect admin HTTP test database");
    let bootstrap_token = "test-bootstrap-token-with-more-than-32-bytes";
    assert!(
        store
            .issue_bootstrap_token(&token_hash(bootstrap_token), 900)
            .await
            .expect("issue bootstrap token")
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local HTTP test listener");
    let address = listener.local_addr().expect("resolve test address");
    let app: Router = build_app(config, Some(store.clone()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let health = request(address, "GET", "/healthz", &[], None).await;
    assert_eq!(health.status, 200);

    let bootstrap_body = json!({
        "username": "admin",
        "password": "bootstrap-password-long-enough",
        "display_name": "Local Admin"
    });
    let missing_capability = request(
        address,
        "POST",
        "/api/v3/admin/bootstrap",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:5175"),
        ],
        Some(&bootstrap_body),
    )
    .await;
    assert_eq!(missing_capability.status, 401);

    let foreign_origin = request(
        address,
        "POST",
        "/api/v3/admin/bootstrap",
        &[
            ("content-type", "application/json"),
            ("origin", "http://foreign.example"),
            ("x-blindpass-bootstrap-token", bootstrap_token),
        ],
        Some(&bootstrap_body),
    )
    .await;
    assert_eq!(foreign_origin.status, 403);

    let bootstrap_headers = [
        ("content-type", "application/json"),
        ("origin", "http://127.0.0.1:5175"),
        ("x-blindpass-bootstrap-token", bootstrap_token),
    ];
    let (first_bootstrap, second_bootstrap) = tokio::join!(
        request(
            address,
            "POST",
            "/api/v3/admin/bootstrap",
            &bootstrap_headers,
            Some(&bootstrap_body),
        ),
        request(
            address,
            "POST",
            "/api/v3/admin/bootstrap",
            &bootstrap_headers,
            Some(&bootstrap_body),
        )
    );
    let mut bootstrap_statuses = [first_bootstrap.status, second_bootstrap.status];
    bootstrap_statuses.sort_unstable();
    assert_eq!(bootstrap_statuses, [201, 409]);
    let bootstrap = if first_bootstrap.status == 201 {
        first_bootstrap
    } else {
        second_bootstrap
    };

    let replay_bootstrap = request(
        address,
        "POST",
        "/api/v3/admin/bootstrap",
        &bootstrap_headers,
        Some(&bootstrap_body),
    )
    .await;
    assert_eq!(replay_bootstrap.status, 409);
    let csrf = bootstrap.body["csrf_token"].as_str().unwrap();
    let admin_id = bootstrap.body["operator"]["id"].as_str().unwrap();
    let session_cookie = cookie_header(&bootstrap, "bp_session");
    let csrf_cookie = cookie_header(&bootstrap, "bp_csrf");
    let refresh_cookie = cookie_header(&bootstrap, "bp_refresh");
    assert!(bootstrap.headers.iter().any(|(name, value)| {
        name == "set-cookie"
            && value.starts_with("bp_session=")
            && value.contains("Path=/;")
            && value.contains("HttpOnly")
            && value.contains("SameSite=Strict")
    }));
    assert!(bootstrap.headers.iter().any(|(name, value)| {
        name == "set-cookie"
            && value.starts_with("bp_refresh=")
            && value.contains("Path=/api/v3/admin/session/refresh;")
            && value.contains("HttpOnly")
    }));

    let forged_csrf = request(
        address,
        "POST",
        "/api/v3/admin/session/logout",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; bp_csrf=forged")),
            ("x-csrf-token", "forged"),
        ],
        None,
    )
    .await;
    assert_eq!(forged_csrf.status, 403);

    let current = request(
        address,
        "GET",
        "/api/v3/admin/session",
        &[("cookie", &format!("{session_cookie}; {csrf_cookie}"))],
        None,
    )
    .await;
    assert_eq!(current.status, 200);
    assert_eq!(current.body["operator"]["role"], "admin");

    let operator_list = request(
        address,
        "GET",
        "/api/v3/admin/operators",
        &[("cookie", &format!("{session_cookie}; {csrf_cookie}"))],
        None,
    )
    .await;
    assert_eq!(operator_list.status, 200);
    assert_eq!(operator_list.body["items"].as_array().unwrap().len(), 1);

    let final_admin_delete = request(
        address,
        "DELETE",
        &format!("/api/v3/admin/operators/{admin_id}"),
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
        ],
        None,
    )
    .await;
    assert_eq!(final_admin_delete.status, 409);

    let final_admin_demote = request(
        address,
        "PATCH",
        &format!("/api/v3/admin/operators/{admin_id}"),
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
        ],
        Some(&json!({"role":"viewer"})),
    )
    .await;
    assert_eq!(final_admin_demote.status, 409);

    let create_viewer = request(
        address,
        "POST",
        "/api/v3/admin/operators",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
        ],
        Some(&json!({
            "username": "viewer",
            "display_name": "Local Viewer",
            "role": "viewer",
            "password": "viewer-password-long-enough"
        })),
    )
    .await;
    assert_eq!(create_viewer.status, 201);
    let viewer_id = create_viewer.body["id"].as_str().unwrap();

    let create_operator = request(
        address,
        "POST",
        "/api/v3/admin/operators",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
        ],
        Some(&json!({
            "username": "operator",
            "display_name": "Local Operator",
            "role": "operator",
            "password": "operator-password-long-enough"
        })),
    )
    .await;
    assert_eq!(create_operator.status, 201);
    let operator_id = create_operator.body["id"].as_str().unwrap();

    let create_agent = request(
        address,
        "POST",
        "/api/v3/admin/agents",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
        ],
        Some(&json!({
            "agent_id": "payments/ring/blue",
            "display_name": "Payments Blue"
        })),
    )
    .await;
    assert_eq!(create_agent.status, 201);
    let agent_id = create_agent.body["agent"]["id"].as_str().unwrap();
    let initial_agent_key = create_agent.body["bootstrap_api_key"].as_str().unwrap();
    assert!(
        create_agent.body["agent"]["created_at"]
            .as_str()
            .unwrap()
            .contains('T')
    );

    let agent_list = request(
        address,
        "GET",
        "/api/v3/admin/agents",
        &[("cookie", &format!("{session_cookie}; {csrf_cookie}"))],
        None,
    )
    .await;
    assert_eq!(agent_list.status, 200);
    assert_eq!(agent_list.body["items"].as_array().unwrap().len(), 1);
    assert!(
        agent_list
            .body
            .to_string()
            .find(initial_agent_key)
            .is_none()
    );

    let rotate_agent = request(
        address,
        "POST",
        &format!("/api/v3/admin/agents/{agent_id}/rotate-key"),
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
        ],
        None,
    )
    .await;
    assert_eq!(rotate_agent.status, 200);
    assert_ne!(rotate_agent.body["bootstrap_api_key"], initial_agent_key);

    let revoke_agent = request(
        address,
        "DELETE",
        &format!("/api/v3/admin/agents/{agent_id}"),
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
        ],
        None,
    )
    .await;
    assert_eq!(revoke_agent.status, 200);
    assert_eq!(revoke_agent.body["status"], "revoked");

    let policy_document = json!({
        "secret_registry":[
            {"secretName":"db.token","classification":"sensitive"}
        ],
        "exchange_policy":[
            {"ruleId":"allow-payments","secretName":"db.token","requesterIds":["payments/ring/blue"],"fulfillerIds":["billing/ring/green"],"mode":"allow"}
        ]
    });
    let validate_policy = request(
        address,
        "POST",
        "/api/v3/admin/policy/validate",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
        ],
        Some(&policy_document),
    )
    .await;
    assert_eq!(validate_policy.status, 200);
    assert_eq!(validate_policy.body["valid"], true);

    let replace_policy = request(
        address,
        "PUT",
        "/api/v3/admin/policy",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("if-match", "1"),
            ("content-type", "application/json"),
        ],
        Some(&policy_document),
    )
    .await;
    assert_eq!(replace_policy.status, 200);
    assert_eq!(replace_policy.body["version"], 2);

    let stale_policy = request(
        address,
        "PUT",
        "/api/v3/admin/policy",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("if-match", "1"),
            ("content-type", "application/json"),
        ],
        Some(&policy_document),
    )
    .await;
    assert_eq!(stale_policy.status, 409);

    let unassigned = approval_record("apr_unassigned_local", Vec::new());
    store
        .create_approval(&unassigned)
        .await
        .expect("create unassigned approval");
    let assigned = approval_record("apr_assigned_local", vec![admin_id.to_owned()]);
    store
        .create_approval(&assigned)
        .await
        .expect("create assigned approval");

    let approvals = request(
        address,
        "GET",
        "/api/v3/admin/approvals?status=pending&limit=1",
        &[("cookie", &format!("{session_cookie}; {csrf_cookie}"))],
        None,
    )
    .await;
    assert_eq!(approvals.status, 200);
    assert_eq!(approvals.body["items"].as_array().unwrap().len(), 1);
    assert!(approvals.body["next_cursor"].is_string());

    let approval_count = request(
        address,
        "GET",
        "/api/v3/admin/approvals/count",
        &[("cookie", &format!("{session_cookie}; {csrf_cookie}"))],
        None,
    )
    .await;
    assert_eq!(approval_count.status, 200);
    assert_eq!(approval_count.body["count"], 2);

    let unassigned_decision = request(
        address,
        "POST",
        "/api/v3/admin/approvals/apr_unassigned_local/approve",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("idempotency-key", "unassigned-approval-key-0001"),
            ("content-type", "application/json"),
        ],
        Some(&json!({"expected_status":"pending"})),
    )
    .await;
    assert_eq!(unassigned_decision.status, 403);

    let approval_reference = assigned.approval_reference.as_str();
    let approval_detail = request(
        address,
        "GET",
        &format!("/api/v3/admin/approvals/{approval_reference}"),
        &[("cookie", &format!("{session_cookie}; {csrf_cookie}"))],
        None,
    )
    .await;
    assert_eq!(approval_detail.status, 200);
    assert_eq!(approval_detail.body["secret_name"], "db.token");
    assert!(approval_detail.body.get("approver_ids").is_none());

    let raw_idempotency_key = "approval-idempotency-key-0001";
    let approve = request(
        address,
        "POST",
        &format!("/api/v3/admin/approvals/{approval_reference}/approve"),
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("idempotency-key", raw_idempotency_key),
            ("content-type", "application/json"),
        ],
        Some(&json!({"expected_status":"pending"})),
    )
    .await;
    assert_eq!(approve.status, 200);
    assert_eq!(approve.body["status"], "approved");

    let approve_replay = request(
        address,
        "POST",
        &format!("/api/v3/admin/approvals/{approval_reference}/approve"),
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("idempotency-key", raw_idempotency_key),
            ("content-type", "application/json"),
        ],
        Some(&json!({"expected_status":"pending"})),
    )
    .await;
    assert_eq!(approve_replay.status, 200);
    assert_eq!(approve_replay.body, approve.body);

    let changed_decision = request(
        address,
        "POST",
        &format!("/api/v3/admin/approvals/{approval_reference}/reject"),
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
            ("idempotency-key", raw_idempotency_key),
            ("content-type", "application/json"),
        ],
        Some(&json!({"expected_status":"pending"})),
    )
    .await;
    assert_eq!(changed_decision.status, 409);

    let audit = request(
        address,
        "GET",
        "/api/v3/admin/audit?limit=10",
        &[("cookie", &format!("{session_cookie}; {csrf_cookie}"))],
        None,
    )
    .await;
    assert_eq!(audit.status, 200);
    let audit_text = audit.body.to_string();
    assert!(audit_text.contains("approval_decided"));
    assert!(!audit_text.contains(raw_idempotency_key));
    let pending_after_decision = request(
        address,
        "GET",
        "/api/v3/admin/approvals/count",
        &[("cookie", &format!("{session_cookie}; {csrf_cookie}"))],
        None,
    )
    .await;
    assert_eq!(pending_after_decision.body["count"], 1);

    let operator_approval = approval_record("apr_assigned_operator", vec![operator_id.to_owned()]);
    store
        .create_approval(&operator_approval)
        .await
        .expect("create operator-assigned approval");
    let operator_login = request(
        address,
        "POST",
        "/api/v3/admin/session/login",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", "bp_csrf=operator-pre-session"),
            ("x-csrf-token", "operator-pre-session"),
        ],
        Some(&json!({
            "username": "operator",
            "password": "operator-password-long-enough"
        })),
    )
    .await;
    assert_eq!(operator_login.status, 200);
    let operator_session = cookie_header(&operator_login, "bp_session");
    let operator_csrf = cookie_header(&operator_login, "bp_csrf");
    let operator_cookies = format!("{operator_session}; {operator_csrf}");
    let operator_agent_denied = request(
        address,
        "GET",
        "/api/v3/admin/agents",
        &[("cookie", &operator_cookies)],
        None,
    )
    .await;
    assert_eq!(operator_agent_denied.status, 403);
    let operator_approve = request(
        address,
        "POST",
        "/api/v3/admin/approvals/apr_assigned_operator/approve",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &operator_cookies),
            (
                "x-csrf-token",
                operator_login.body["csrf_token"].as_str().unwrap(),
            ),
            ("idempotency-key", "operator-approval-key-0001"),
            ("content-type", "application/json"),
        ],
        Some(&json!({"expected_status":"pending"})),
    )
    .await;
    assert_eq!(operator_approve.status, 200);
    assert_eq!(operator_approve.body["status"], "approved");

    let raced_approval = approval_record("apr_admin_http_race", vec![admin_id.to_owned()]);
    store
        .create_approval(&raced_approval)
        .await
        .expect("create approval for HTTP decision race");
    let admin_cookies = format!("{session_cookie}; {csrf_cookie}");
    let decision_body = json!({"expected_status":"pending"});
    let approve_headers = [
        ("origin", "http://127.0.0.1:5175"),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("idempotency-key", "admin-race-approve-key-0001"),
        ("content-type", "application/json"),
    ];
    let reject_headers = [
        ("origin", "http://127.0.0.1:5175"),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("idempotency-key", "admin-race-reject-key-0001"),
        ("content-type", "application/json"),
    ];
    let (raced_approve, raced_reject) = tokio::join!(
        request(
            address,
            "POST",
            "/api/v3/admin/approvals/apr_admin_http_race/approve",
            &approve_headers,
            Some(&decision_body),
        ),
        request(
            address,
            "POST",
            "/api/v3/admin/approvals/apr_admin_http_race/reject",
            &reject_headers,
            Some(&decision_body),
        )
    );
    let mut decision_statuses = [raced_approve.status, raced_reject.status];
    decision_statuses.sort_unstable();
    assert_eq!(decision_statuses, [200, 409]);
    let raced_detail = request(
        address,
        "GET",
        "/api/v3/admin/approvals/apr_admin_http_race",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(raced_detail.status, 200);
    assert!(matches!(
        raced_detail.body["status"].as_str(),
        Some("approved" | "rejected")
    ));

    let foreign_login = request(
        address,
        "POST",
        "/api/v3/admin/session/login",
        &[
            ("content-type", "application/json"),
            ("origin", "http://foreign.example"),
            ("cookie", "bp_csrf=foreign-pre-session"),
            ("x-csrf-token", "foreign-pre-session"),
        ],
        Some(&json!({
            "username": "viewer",
            "password": "viewer-password-long-enough"
        })),
    )
    .await;
    assert_eq!(foreign_login.status, 403);

    let viewer_login = request(
        address,
        "POST",
        "/api/v3/admin/session/login",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", "bp_csrf=viewer-pre-session"),
            ("x-csrf-token", "viewer-pre-session"),
        ],
        Some(&json!({
            "username": "viewer",
            "password": "viewer-password-long-enough"
        })),
    )
    .await;
    assert_eq!(viewer_login.status, 200);
    let viewer_operators = request(
        address,
        "GET",
        "/api/v3/admin/operators",
        &[(
            "cookie",
            &format!(
                "{}; {}",
                cookie_header(&viewer_login, "bp_session"),
                cookie_header(&viewer_login, "bp_csrf")
            ),
        )],
        None,
    )
    .await;
    assert_eq!(viewer_operators.status, 403);

    let reset_password = request(
        address,
        "POST",
        &format!("/api/v3/admin/operators/{viewer_id}/reset-password"),
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &format!("{session_cookie}; {csrf_cookie}")),
            ("x-csrf-token", csrf),
        ],
        None,
    )
    .await;
    assert_eq!(reset_password.status, 200);
    assert!(
        reset_password.body["temporary_password"]
            .as_str()
            .unwrap()
            .len()
            >= 32
    );

    let login = request(
        address,
        "POST",
        "/api/v3/admin/session/login",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", "bp_csrf=pre-session-nonce"),
            ("x-csrf-token", "pre-session-nonce"),
        ],
        Some(&json!({
            "username": "admin",
            "password": "bootstrap-password-long-enough"
        })),
    )
    .await;
    assert_eq!(login.status, 200);
    let login_csrf = login.body["csrf_token"].as_str().unwrap();
    let login_csrf_cookie = cookie_header(&login, "bp_csrf");
    let old_refresh_cookie = cookie_header(&login, "bp_refresh");

    let refresh = request(
        address,
        "POST",
        "/api/v3/admin/session/refresh",
        &[
            ("origin", "http://127.0.0.1:5175"),
            (
                "cookie",
                &format!("{old_refresh_cookie}; {login_csrf_cookie}"),
            ),
            ("x-csrf-token", login_csrf),
        ],
        None,
    )
    .await;
    assert_eq!(refresh.status, 200);
    let next_session_cookie = cookie_header(&refresh, "bp_session");

    let replay = request(
        address,
        "POST",
        "/api/v3/admin/session/refresh",
        &[
            ("origin", "http://127.0.0.1:5175"),
            (
                "cookie",
                &format!("{old_refresh_cookie}; {login_csrf_cookie}"),
            ),
            ("x-csrf-token", login_csrf),
        ],
        None,
    )
    .await;
    assert_eq!(replay.status, 401);
    let revoked = request(
        address,
        "GET",
        "/api/v3/admin/session",
        &[(
            "cookie",
            &format!("{next_session_cookie}; {login_csrf_cookie}"),
        )],
        None,
    )
    .await;
    assert_eq!(revoked.status, 401);
    assert!(!csrf.is_empty());
    assert!(!refresh_cookie.is_empty());

    server.abort();
    let _ = server.await;
    drop(store);
    if let Some((pool, schema)) = postgres_schema {
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .expect("drop isolated PostgreSQL admin schema");
        pool.close().await;
    }
}

#[tokio::test]
async fn forced_password_change_blocks_administration_until_completed() {
    let directory = TestDirectory::new();
    let (database_url, postgres_schema): (String, Option<(PgPool, String)>) =
        if std::env::var("P02_TEST_BACKEND").as_deref() == Ok("postgres") {
            let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
                .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                .expect("P02_TEST_POSTGRES_URL or CONTRACT_DATABASE_URL is required");
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos();
            let schema = format!("p02_forced_{}_{nonce}", std::process::id());
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&parent_url)
                .await
                .expect("connect PostgreSQL forced-change fixture");
            sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                .execute(&pool)
                .await
                .expect("create isolated PostgreSQL schema");
            let separator = if parent_url.contains('?') { '&' } else { '?' };
            (
                format!("{parent_url}{separator}options=-c%20search_path%3D{schema}"),
                Some((pool, schema)),
            )
        } else {
            let database_path = directory.file("controller.db");
            (
                format!("sqlite://{}?mode=rwc", database_path.display()),
                None,
            )
        };
    for (name, value) in [
        ("database.url", database_url.clone()),
        ("root.secret", "R".repeat(32)),
        ("agent.secret", "A".repeat(32)),
    ] {
        let path = directory.file(name);
        std::fs::write(&path, value).expect("write test credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("protect test credential");
    }
    let config = Config::from_variables([
        ("BLINDPASS_LISTEN", "127.0.0.1:0"),
        ("BLINDPASS_PUBLIC_URL", "http://127.0.0.1:8080"),
        ("BLINDPASS_UI_BASE_URL", "http://127.0.0.1:5175"),
        (
            "BLINDPASS_DATABASE_URL_FILE",
            directory.file("database.url").to_str().unwrap(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE",
            directory.file("root.secret").to_str().unwrap(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            directory.file("agent.secret").to_str().unwrap(),
        ),
    ])
    .expect("valid local test config");
    let store = Store::connect(&database_url)
        .await
        .expect("connect forced-change test database");
    let seeded = blindpass_controller::seed::seed_fixture(
        &store,
        &[b'A'; 32],
        blindpass_controller::seed::SeedRequest {
            agents: vec!["fixture-agent".to_owned()],
            policy: None,
            rotated_agents: Vec::new(),
            revoked_agents: Vec::new(),
            local_admin: true,
        },
    )
    .await
    .expect("seed a local administrator with a temporary password");
    let local_admin = seeded.local_admin.expect("seeded local administrator");
    let temporary_password = local_admin.temporary_password.clone();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local HTTP test listener");
    let address = listener.local_addr().expect("resolve test address");
    let app: Router = build_app(config, Some(store.clone()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let login = request(
        address,
        "POST",
        "/api/v3/admin/session/login",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", "bp_csrf=pre-session-token"),
            ("x-csrf-token", "pre-session-token"),
        ],
        Some(&json!({"username": local_admin.username, "password": temporary_password})),
    )
    .await;
    assert_eq!(
        login.status, 200,
        "temporary password login: {:?}",
        login.body
    );
    assert_eq!(login.body["must_change_password"], true);
    let csrf = login.body["csrf_token"].as_str().unwrap().to_owned();
    let session_cookie = cookie_header(&login, "bp_session");
    let csrf_cookie = cookie_header(&login, "bp_csrf");
    let cookies = format!("{session_cookie}; {csrf_cookie}");

    let current = request(
        address,
        "GET",
        "/api/v3/admin/session",
        &[("cookie", &cookies)],
        None,
    )
    .await;
    assert_eq!(current.status, 200);
    assert_eq!(current.body["must_change_password"], true);

    for (method, path, body) in [
        ("GET", "/api/v3/admin/agents", None),
        ("GET", "/api/v3/admin/audit", None),
        ("GET", "/api/v3/admin/policy", None),
        (
            "POST",
            "/api/v3/admin/operators",
            Some(json!({
                "username": "viewer",
                "display_name": "Local Viewer",
                "role": "viewer",
                "password": "viewer-password-long-enough"
            })),
        ),
    ] {
        let blocked = request(
            address,
            method,
            path,
            &[
                ("origin", "http://127.0.0.1:5175"),
                ("cookie", &cookies),
                ("x-csrf-token", &csrf),
                ("content-type", "application/json"),
            ],
            body.as_ref(),
        )
        .await;
        assert_eq!(
            blocked.status, 403,
            "{method} {path} must be blocked until the temporary password is changed: {:?}",
            blocked.body
        );
        assert_eq!(blocked.body["error"], "password_change_required");
    }
    assert!(
        store
            .list_local_operators()
            .await
            .expect("list operators")
            .iter()
            .all(|operator| operator.username != "viewer"),
        "blocked administration must not mutate state"
    );

    let changed = request(
        address,
        "POST",
        "/api/v3/admin/session/change-password",
        &[
            ("origin", "http://127.0.0.1:5175"),
            ("cookie", &cookies),
            ("x-csrf-token", &csrf),
            ("content-type", "application/json"),
        ],
        Some(&json!({
            "current_password": temporary_password,
            "new_password": "rotated-password-long-enough"
        })),
    )
    .await;
    assert_eq!(changed.status, 204, "password change: {:?}", changed.body);

    let agents = request(
        address,
        "GET",
        "/api/v3/admin/agents",
        &[("cookie", &cookies)],
        None,
    )
    .await;
    assert_eq!(
        agents.status, 200,
        "administration resumes: {:?}",
        agents.body
    );
    let current = request(
        address,
        "GET",
        "/api/v3/admin/session",
        &[("cookie", &cookies)],
        None,
    )
    .await;
    assert_eq!(current.status, 200);
    assert_eq!(current.body["must_change_password"], false);

    server.abort();
    let _ = server.await;
    drop(store);
    if let Some((pool, schema)) = postgres_schema {
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .expect("drop isolated PostgreSQL schema");
        pool.close().await;
    }
}
