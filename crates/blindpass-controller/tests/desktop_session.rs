// SPDX-License-Identifier: AGPL-3.0-only

//! P04-D3: the desktop approval app's session transport. A desktop login
//! returns a bearer access token and a refresh token in JSON and sets no
//! cookie; the bearer reaches only session read/refresh/logout and the
//! unified approval routes; refresh rotates and a replay revokes the family;
//! logout, password change, role change and removal end it on the server.

mod support;

use serde_json::{Value, json};
use support::{FleetNode, Harness, ORIGIN, OperationSpec, Operator};

struct Desktop {
    access: String,
    refresh: String,
    body: Value,
}

fn password(username: &str) -> String {
    format!("{username}-test-password-long")
}

async fn desktop_login(harness: &Harness, username: &str, password: &str) -> support::HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[("content-type", "application/json")],
            Some(&json!({"username":username,"password":password,"kind":"desktop"})),
        )
        .await
}

async fn desktop(harness: &Harness, username: &str) -> Desktop {
    let login = desktop_login(harness, username, &password(username)).await;
    assert_eq!(login.status, 200, "{}", login.body);
    Desktop {
        access: login.body["access_token"].as_str().unwrap().to_owned(),
        refresh: login.body["refresh_token"].as_str().unwrap().to_owned(),
        body: login.body,
    }
}

async fn bearer(
    harness: &Harness,
    method: &str,
    path: &str,
    access: &str,
    extra: &[(&str, &str)],
    body: Option<&Value>,
) -> support::HttpResponse {
    let authorization = format!("Bearer {access}");
    let mut headers = vec![
        ("authorization", authorization.as_str()),
        ("content-type", "application/json"),
    ];
    headers.extend_from_slice(extra);
    harness.request(method, path, &headers, body).await
}

async fn refresh(harness: &Harness, token: &str) -> support::HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[("content-type", "application/json")],
            Some(&json!({"kind":"desktop","refresh_token":token})),
        )
        .await
}

fn has_header(response: &support::HttpResponse, name: &str) -> bool {
    response.headers.iter().any(|(header, _)| header == name)
}

async fn session_kinds(harness: &Harness) -> Vec<Option<String>> {
    harness
        .strings(
            "SELECT kind FROM operator_sessions WHERE revoked_at IS NULL ORDER BY kind",
            vec![],
        )
        .await
}

#[tokio::test]
async fn desktop_login_returns_bearer_credentials_and_sets_no_cookie() {
    let harness = Harness::start().await;
    harness.create_operator("desk-approver", "operator").await;
    let login = desktop_login(&harness, "desk-approver", &password("desk-approver")).await;
    assert_eq!(login.status, 200, "{}", login.body);
    assert!(
        !has_header(&login, "set-cookie"),
        "desktop login sets no cookie"
    );
    assert_eq!(
        login
            .headers
            .iter()
            .find(|(name, _)| name == "cache-control")
            .map(|(_, value)| value.as_str()),
        Some("no-store")
    );
    let body = &login.body;
    assert_eq!(body["operator"]["username"], "desk-approver");
    assert_eq!(body["operator"]["role"], "operator");
    assert!(
        body.get("csrf_token").is_none(),
        "no CSRF value for a bearer session"
    );
    let access = body["access_token"].as_str().unwrap();
    let refresh = body["refresh_token"].as_str().unwrap();
    assert!(access.len() >= 32 && refresh.len() >= 32 && access != refresh);
    let now = harness.now_ms().await;
    let expires_at = body["expires_at"].as_i64().unwrap();
    assert!(
        expires_at > now && expires_at <= now + 20 * 60 * 1_000 + 5_000,
        "the access token lasts at most 20 minutes: {expires_at} vs {now}"
    );
    let stored_refresh = harness
        .scalar_i64(
            "SELECT COUNT(*) FROM operator_sessions WHERE kind = 'desktop' AND refresh_hash = ?",
            vec![support::Bind::Text(refresh.to_owned())],
        )
        .await;
    assert_eq!(
        stored_refresh, 0,
        "only a hash of the refresh token is stored"
    );
    let read = bearer(&harness, "GET", "/api/v3/admin/session", access, &[], None).await;
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(read.body["kind"], "desktop");
    assert_eq!(read.body["operator"]["username"], "desk-approver");
    assert!(read.body.get("csrf_token").is_none());
}

#[tokio::test]
async fn desktop_login_refuses_browser_origins_and_temporary_passwords() {
    let harness = Harness::start().await;
    let operator = harness.create_operator("desk-origin", "operator").await;
    let from_page = harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[("content-type", "application/json"), ("origin", ORIGIN)],
            Some(&json!({"username":"desk-origin","password":password("desk-origin"),"kind":"desktop"})),
        )
        .await;
    assert_eq!(from_page.status, 403, "{}", from_page.body);
    assert_eq!(from_page.body["error"], "desktop_origin_denied");

    let wrong = desktop_login(&harness, "desk-origin", "not-the-password-at-all").await;
    assert_eq!(wrong.status, 401, "{}", wrong.body);
    assert_eq!(wrong.body["error"], "invalid_credentials");

    let unknown_kind = harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[("content-type", "application/json")],
            Some(&json!({"username":"desk-origin","password":password("desk-origin"),"kind":"kiosk"})),
        )
        .await;
    assert_eq!(unknown_kind.status, 400, "{}", unknown_kind.body);

    let reset = harness
        .call(
            &harness.admin,
            "POST",
            &format!("/api/v3/admin/operators/{}/reset-password", operator.id),
            &[],
            Some(&json!({})),
        )
        .await;
    assert_eq!(reset.status, 200, "{}", reset.body);
    let temporary = reset.body["temporary_password"].as_str().unwrap();
    let before = session_kinds(&harness).await;
    let refused = desktop_login(&harness, "desk-origin", temporary).await;
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(refused.body["error"], "password_change_required");
    assert_eq!(
        session_kinds(&harness).await,
        before,
        "no session was created"
    );
    assert!(!before.contains(&Some("desktop".to_owned())));
}

#[tokio::test]
async fn desktop_bearer_reaches_only_session_and_approval_routes() {
    let harness = Harness::start().await;
    harness.create_operator("desk-scope", "admin").await;
    let session = desktop(&harness, "desk-scope").await;
    for path in ["/api/v3/approvals", "/api/v3/approvals/count"] {
        let allowed = bearer(&harness, "GET", path, &session.access, &[], None).await;
        assert_eq!(allowed.status, 200, "{path}: {}", allowed.body);
    }
    // An administrator's desktop session still cannot administer.
    for path in [
        "/api/v3/admin/operators",
        "/api/v3/admin/approvals",
        "/api/v3/admin/audit",
        "/api/v3/admin/policy",
        "/api/v3/admin/agents",
        "/api/v3/nodes",
        "/api/v3/grants",
        "/api/v3/operations",
        "/api/v3/policies",
        "/api/v3/workloads",
    ] {
        let denied = bearer(&harness, "GET", path, &session.access, &[], None).await;
        assert_eq!(
            denied.status, 401,
            "{path} must not accept a desktop bearer: {}",
            denied.body
        );
    }
    // The access token is not a browser cookie, and a page cannot use it.
    let as_cookie = harness
        .request(
            "GET",
            "/api/v3/approvals",
            &[("cookie", &format!("bp_session={}", session.access))],
            None,
        )
        .await;
    assert_eq!(as_cookie.status, 401, "{}", as_cookie.body);
    let from_page = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        &session.access,
        &[("origin", ORIGIN)],
        None,
    )
    .await;
    assert_eq!(
        from_page.status, 401,
        "a page cannot use a desktop bearer: {}",
        from_page.body
    );
    // A browser session is not a desktop bearer either.
    let browser_id = harness.admin.cookies.split(';').next().unwrap().trim();
    let browser_id = browser_id.strip_prefix("bp_session=").unwrap();
    let browser_as_bearer =
        bearer(&harness, "GET", "/api/v3/approvals", browser_id, &[], None).await;
    assert_eq!(browser_as_bearer.status, 401, "{}", browser_as_bearer.body);
    let garbage = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        "not-a-session",
        &[],
        None,
    )
    .await;
    assert_eq!(garbage.status, 401, "{}", garbage.body);
}

#[tokio::test]
async fn desktop_refresh_rotates_and_a_replay_revokes_the_family() {
    let harness = Harness::start().await;
    harness.create_operator("desk-rotate", "operator").await;
    let first = desktop(&harness, "desk-rotate").await;
    let rotated = refresh(&harness, &first.refresh).await;
    assert_eq!(rotated.status, 200, "{}", rotated.body);
    assert!(!has_header(&rotated, "set-cookie"));
    let next_access = rotated.body["access_token"].as_str().unwrap().to_owned();
    let next_refresh = rotated.body["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(next_access, first.access);
    assert_ne!(next_refresh, first.refresh);
    let old = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        &first.access,
        &[],
        None,
    )
    .await;
    assert_eq!(
        old.status, 401,
        "rotation retires the previous access token"
    );
    let new = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        &next_access,
        &[],
        None,
    )
    .await;
    assert_eq!(new.status, 200, "{}", new.body);

    // The desktop refresh token is not a browser refresh cookie.
    let as_cookie = harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[
                ("origin", ORIGIN),
                ("cookie", &format!("bp_refresh={next_refresh}; bp_csrf=x")),
                ("x-csrf-token", "x"),
            ],
            None,
        )
        .await;
    assert_eq!(as_cookie.status, 401, "{}", as_cookie.body);
    let from_page = harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[("content-type", "application/json"), ("origin", ORIGIN)],
            Some(&json!({"kind":"desktop","refresh_token":next_refresh})),
        )
        .await;
    // With an Origin the request is a browser refresh, which reads only the
    // cookie: a body token is ignored and nothing rotates.
    assert_eq!(from_page.status, 401, "{}", from_page.body);
    assert_eq!(from_page.body["error"], "refresh_required");

    let replay = refresh(&harness, &first.refresh).await;
    assert_eq!(replay.status, 401, "{}", replay.body);
    assert_eq!(replay.body["error"], "refresh_invalid");
    let after_replay = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        &next_access,
        &[],
        None,
    )
    .await;
    assert_eq!(
        after_replay.status, 401,
        "a replay revokes the whole family"
    );
    let successor = refresh(&harness, &next_refresh).await;
    assert_eq!(successor.status, 401, "{}", successor.body);

    let malformed = harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[("content-type", "application/json")],
            Some(&json!({"kind":"desktop"})),
        )
        .await;
    assert_eq!(malformed.status, 403, "{}", malformed.body);
}

#[tokio::test]
async fn desktop_access_tokens_expire_twenty_minutes_after_rotation() {
    let harness = Harness::start().await;
    harness.create_operator("desk-age", "operator").await;
    let session = desktop(&harness, "desk-age").await;
    harness
        .execute(
            "UPDATE operator_sessions SET created_at = created_at - 1260000 WHERE kind = 'desktop'",
            vec![],
        )
        .await;
    let stale = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        &session.access,
        &[],
        None,
    )
    .await;
    assert_eq!(stale.status, 401, "{}", stale.body);
    // The refresh token still rotates into a fresh access token.
    let rotated = refresh(&harness, &session.refresh).await;
    assert_eq!(rotated.status, 200, "{}", rotated.body);
    let fresh = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        rotated.body["access_token"].as_str().unwrap(),
        &[],
        None,
    )
    .await;
    assert_eq!(fresh.status, 200, "{}", fresh.body);
}

#[tokio::test]
async fn desktop_logout_revokes_on_the_server() {
    let harness = Harness::start().await;
    harness.create_operator("desk-logout", "operator").await;
    let session = desktop(&harness, "desk-logout").await;
    let from_page = bearer(
        &harness,
        "POST",
        "/api/v3/admin/session/logout",
        &session.access,
        &[("origin", ORIGIN)],
        None,
    )
    .await;
    assert_eq!(from_page.status, 401, "{}", from_page.body);
    let logout = bearer(
        &harness,
        "POST",
        "/api/v3/admin/session/logout",
        &session.access,
        &[],
        None,
    )
    .await;
    assert_eq!(logout.status, 204, "{}", logout.body);
    assert!(!has_header(&logout, "set-cookie"));
    let after = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        &session.access,
        &[],
        None,
    )
    .await;
    assert_eq!(after.status, 401);
    let refreshed = refresh(&harness, &session.refresh).await;
    assert_eq!(refreshed.status, 401, "{}", refreshed.body);
    let again = bearer(
        &harness,
        "POST",
        "/api/v3/admin/session/logout",
        &session.access,
        &[],
        None,
    )
    .await;
    assert_eq!(again.status, 401);
    // The browser admin session is untouched.
    assert_eq!(
        harness
            .get(&harness.admin, "/api/v3/admin/session")
            .await
            .status,
        200
    );
}

fn approval_rule(approvers: &[&str]) -> Value {
    json!([{
        "id":"approve-noop-file","action":"noop.marker","mode":"file",
        "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120,
        "approver_ids":approvers
    }])
}

struct Fleet {
    harness: Harness,
    node: FleetNode,
    workload: Value,
    requester: Operator,
}

async fn fleet() -> Fleet {
    let harness = Harness::start().await;
    let node = harness.online_node("desktop-node", 71).await;
    let requester = harness.create_operator("desk-requester", "operator").await;
    harness.create_operator("desk-approver", "operator").await;
    let policy = harness
        .set_policy(approval_rule(&["desk-approver", "desk-requester"]))
        .await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    let workload = harness
        .create_workload(
            &node.id,
            "desktop-worker",
            "desktop.service",
            "desktop",
            "file",
        )
        .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
    Fleet {
        harness,
        node,
        workload: workload.body,
        requester,
    }
}

impl Fleet {
    async fn pending(&self, event_key: &str) -> String {
        let created = self
            .harness
            .request_operation(
                &self.requester,
                &self.node,
                &self.workload,
                &OperationSpec::new(event_key),
            )
            .await;
        assert_eq!(created.status, 201, "{}", created.body);
        created.body["approval_id"].as_str().unwrap().to_owned()
    }
}

async fn decide(
    harness: &Harness,
    access: &str,
    approval_id: &str,
    verb: &str,
    idempotency: Option<&str>,
) -> support::HttpResponse {
    let detail = bearer(
        harness,
        "GET",
        &format!("/api/v3/approvals/{approval_id}"),
        access,
        &[],
        None,
    )
    .await;
    assert_eq!(detail.status, 200, "{}", detail.body);
    let version = detail.body["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let mut extra = vec![("if-match", if_match.as_str())];
    if let Some(key) = idempotency {
        extra.push(("idempotency-key", key));
    }
    bearer(
        harness,
        "POST",
        &format!("/api/v3/approvals/{approval_id}/{verb}"),
        access,
        &extra,
        Some(&json!({
            "expected_status":"pending",
            "expected_version":version,
            "operation_ids":detail.body["operation_ids"]
        })),
    )
    .await
}

#[tokio::test]
async fn desktop_sessions_decide_named_approvals_without_csrf() {
    let fleet = fleet().await;
    let harness = &fleet.harness;
    let approval = fleet.pending("desktop-decide-1").await;
    let approver = desktop(harness, "desk-approver").await;
    assert_eq!(approver.body["operator"]["role"], "operator");
    let listed = bearer(
        harness,
        "GET",
        "/api/v3/approvals?status=pending",
        &approver.access,
        &[],
        None,
    )
    .await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert!(
        listed.body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == approval.as_str())
    );

    let no_key = decide(harness, &approver.access, &approval, "approve", None).await;
    assert_eq!(no_key.status, 400, "{}", no_key.body);
    let requester = desktop(harness, "desk-requester").await;
    let own = decide(
        harness,
        &requester.access,
        &approval,
        "approve",
        Some("desktop-self-approval-key"),
    )
    .await;
    assert_eq!(own.status, 403, "{}", own.body);
    assert_eq!(own.body["error"], "self_approval_denied");

    let approved = decide(
        harness,
        &approver.access,
        &approval,
        "approve",
        Some("desktop-approve-key-0001"),
    )
    .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    assert_eq!(approved.body["status"], "approved");
    let decided_by = harness
        .strings(
            "SELECT decided_by FROM operation_approvals WHERE id = ?",
            vec![support::Bind::Text(approval.clone())],
        )
        .await;
    let approver_id = harness
        .store
        .operator_by_username("desk-approver")
        .await
        .unwrap()
        .unwrap()
        .id;
    assert_eq!(decided_by, vec![Some(approver_id)]);
}

#[tokio::test]
async fn password_change_role_change_and_removal_end_desktop_access() {
    let harness = Harness::start().await;
    let operator = harness.create_operator("desk-life", "operator").await;
    let session = desktop(&harness, "desk-life").await;

    let viewer = harness
        .call(
            &harness.admin,
            "PATCH",
            &format!("/api/v3/admin/operators/{}", operator.id),
            &[],
            Some(&json!({"role":"viewer"})),
        )
        .await;
    assert_eq!(viewer.status, 200, "{}", viewer.body);
    let as_viewer = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        &session.access,
        &[],
        None,
    )
    .await;
    assert_eq!(as_viewer.status, 403, "{}", as_viewer.body);
    let restored = harness
        .call(
            &harness.admin,
            "PATCH",
            &format!("/api/v3/admin/operators/{}", operator.id),
            &[],
            Some(&json!({"role":"operator"})),
        )
        .await;
    assert_eq!(restored.status, 200, "{}", restored.body);

    let changed = harness
        .call(
            &operator,
            "POST",
            "/api/v3/admin/session/change-password",
            &[],
            Some(&json!({
                "current_password":password("desk-life"),
                "new_password":"desk-life-a-new-long-password"
            })),
        )
        .await;
    assert_eq!(changed.status, 204, "{}", changed.body);
    let after_change = bearer(
        &harness,
        "GET",
        "/api/v3/approvals",
        &session.access,
        &[],
        None,
    )
    .await;
    assert_eq!(after_change.status, 401, "{}", after_change.body);
    assert_eq!(refresh(&harness, &session.refresh).await.status, 401);

    let again = desktop_login(&harness, "desk-life", "desk-life-a-new-long-password").await;
    assert_eq!(again.status, 200, "{}", again.body);
    let access = again.body["access_token"].as_str().unwrap();
    let removed = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!("/api/v3/admin/operators/{}", operator.id),
            &[],
            None,
        )
        .await;
    assert_eq!(removed.status, 204, "{}", removed.body);
    let after_removal = bearer(&harness, "GET", "/api/v3/approvals", access, &[], None).await;
    assert_eq!(after_removal.status, 401, "{}", after_removal.body);
}
