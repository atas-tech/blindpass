// SPDX-License-Identifier: AGPL-3.0-only

//! P07 slice 7 (cold-operator dry run, steps 31 and 37): the local administration
//! socket must let an operator who only knows a USERNAME recover a locked account,
//! and must let them find operators without reading the database. Requests are
//! sent over the real socket in the exact shape `blindpass admin reset-password`
//! and `blindpass admin operators list` send. SQLite by default; PostgreSQL with
//! `P02_TEST_BACKEND=postgres` and `P02_TEST_POSTGRES_URL`.

mod support;

use serde_json::{Value, json};
use support::{Bind, Harness, ORIGIN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROXY: (&str, &str) = ("BLINDPASS_TRUST_PROXY", "127.0.0.0/8,::1/128");
const WRONG: &str = "p07-ao-dummy-wrong-password";

struct Socket {
    path: std::path::PathBuf,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Socket {
    fn serve(harness: &Harness) -> Self {
        let path = harness.directory.file("admin.sock");
        let bound = blindpass_controller::admin_socket::bind_admin_socket(&path)
            .expect("bind admin socket");
        let server = tokio::spawn(blindpass_controller::admin_socket::serve_admin_socket(
            bound,
            harness.store.clone(),
        ));
        Self { path, server }
    }

    async fn call(&self, request: &Value) -> Value {
        let mut client = tokio::net::UnixStream::connect(&self.path)
            .await
            .expect("connect admin socket");
        client
            .write_all(format!("{request}\n").as_bytes())
            .await
            .expect("write admin command");
        client.shutdown().await.expect("finish admin command");
        let mut answer = Vec::new();
        client
            .read_to_end(&mut answer)
            .await
            .expect("read admin answer");
        serde_json::from_slice(&answer).expect("JSON admin answer")
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn login(
    harness: &Harness,
    username: &str,
    password: &str,
    ip: &str,
) -> support::HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[
                ("content-type", "application/json"),
                ("origin", ORIGIN),
                ("cookie", "bp_csrf=p07-ao-pre-session"),
                ("x-csrf-token", "p07-ao-pre-session"),
                ("x-forwarded-for", ip),
            ],
            Some(&json!({"username":username,"password":password})),
        )
        .await
}

#[tokio::test]
async fn p07_ao01_reset_password_accepts_the_username_or_the_id() {
    let harness = Harness::start_with(&[PROXY]).await;
    let socket = Socket::serve(&harness);
    let alice = harness.create_operator("ao01-Alice", "operator").await;

    // The operator only knows what the console shows: the username, any case, and
    // stray whitespace from a copy-paste.
    for reference in ["ao01-Alice", "AO01-ALICE", "  ao01-alice \n"] {
        let answer = socket
            .call(&json!({"command":"reset-password","id":reference}))
            .await;
        assert!(
            answer["temporary_password"].as_str().is_some(),
            "reference {reference:?}: {answer}"
        );
        assert_eq!(answer["must_change_password"], true);
    }
    // The id still works, exactly as before.
    let answer = socket
        .call(&json!({"command":"reset-password","id":alice.id}))
        .await;
    assert!(answer["temporary_password"].as_str().is_some(), "{answer}");

    // Nothing matches: a distinct, specific error that is not a credential oracle.
    let missing = socket
        .call(&json!({"command":"reset-password","id":"ao01-nobody"}))
        .await;
    assert_eq!(missing["error"], "operator_not_found", "{missing}");
    // Characters no operator name or id can contain are refused before any lookup.
    let invalid = socket
        .call(&json!({"command":"reset-password","id":"ao01 alice; drop"}))
        .await;
    assert_eq!(invalid["error"], "invalid_operator_id", "{invalid}");
}

#[tokio::test]
async fn p07_ao02_an_ambiguous_case_insensitive_username_is_refused_not_guessed() {
    let harness = Harness::start_with(&[PROXY]).await;
    let socket = Socket::serve(&harness);
    harness.create_operator("ao02-Casey", "operator").await;
    // Usernames are unique case-sensitively, so a case variant can exist.
    let second = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/admin/operators",
            &[],
            Some(&json!({
                "username":"ao02-casey","display_name":"second","role":"viewer",
                "password":"ao02-second-password-long"
            })),
        )
        .await;
    assert_eq!(second.status, 201, "{}", second.body);

    // An exact-case name is unambiguous even though a case variant exists.
    let exact = socket
        .call(&json!({"command":"reset-password","id":"ao02-Casey"}))
        .await;
    assert!(exact["temporary_password"].as_str().is_some(), "{exact}");
    // A third spelling matches both case-insensitively: refuse, point at the id.
    let ambiguous = socket
        .call(&json!({"command":"reset-password","id":"AO02-CASEY"}))
        .await;
    assert_eq!(ambiguous["error"], "operator_ambiguous", "{ambiguous}");
}

#[tokio::test]
async fn p07_ao03_a_disabled_operator_is_reported_as_disabled() {
    let harness = Harness::start_with(&[PROXY]).await;
    let socket = Socket::serve(&harness);
    harness.create_operator("ao03-dora", "operator").await;
    harness
        .execute(
            "UPDATE operators SET disabled_at = ? WHERE username = ?",
            vec![Bind::from(1_i64), Bind::from("ao03-dora")],
        )
        .await;
    let answer = socket
        .call(&json!({"command":"reset-password","id":"ao03-dora"}))
        .await;
    assert_eq!(answer["error"], "operator_disabled", "{answer}");
}

#[tokio::test]
async fn p07_ao04_operators_list_shows_ids_roles_and_lock_state_without_secrets() {
    let harness = Harness::start_with(&[PROXY]).await;
    let socket = Socket::serve(&harness);
    let viewer = harness.create_operator("ao04-viewer", "viewer").await;
    let before = socket.call(&json!({"command":"operators-list"})).await;
    let listed = before["operators"].as_array().expect("operators array");
    assert_eq!(listed.len(), 2, "{before}");
    let row = listed
        .iter()
        .find(|row| row["username"] == "ao04-viewer")
        .expect("viewer listed");
    assert_eq!(row["id"], viewer.id.as_str());
    assert_eq!(row["role"], "viewer");
    assert_eq!(row["disabled"], false);
    assert_eq!(row["must_change_password"], false);
    assert_eq!(row["account_locked_seconds"], 0);
    assert_eq!(row["source_locks"], 0);
    let text = before.to_string();
    for forbidden in ["password", "hash", "csrf", "refresh", "token"] {
        assert!(
            !text
                .to_ascii_lowercase()
                .contains(&format!("\"{forbidden}")),
            "listing exposes a {forbidden} field: {text}"
        );
    }

    // Ten failures from one source lock that (account, source) pair only.
    for _ in 0..10 {
        let failed = login(&harness, "ao04-viewer", WRONG, "203.0.113.41").await;
        assert_eq!(failed.status, 401, "{}", failed.body);
    }
    let after = socket.call(&json!({"command":"operators-list"})).await;
    let row = after["operators"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["username"] == "ao04-viewer")
        .unwrap()
        .clone();
    assert_eq!(row["source_locks"], 1, "{after}");
    assert_eq!(row["account_locked_seconds"], 0, "{after}");

    // Fifty failures across addresses lock the account for everyone.
    for index in 0..50 {
        let ip = format!("198.51.100.{}", index + 1);
        let failed = login(&harness, "ao04-viewer", WRONG, &ip).await;
        assert!(
            matches!(failed.status, 401 | 423),
            "{} {}",
            failed.status,
            failed.body
        );
    }
    let locked = socket.call(&json!({"command":"operators-list"})).await;
    let row = locked["operators"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["username"] == "ao04-viewer")
        .unwrap()
        .clone();
    assert!(
        row["account_locked_seconds"].as_u64().unwrap() > 0,
        "{locked}"
    );
}

/// The exact case the dry run hit (steps 31 and 37): the only administrator is
/// locked out, has no signed-in session and knows only the username.
#[tokio::test]
async fn p07_ao05_a_locked_sole_administrator_is_recovered_by_username_over_the_real_socket() {
    let mut harness = Harness::start_with(&[PROXY]).await;
    let socket = Socket::serve(&harness);
    let admin = harness.admin.username.clone();
    let admins = harness
        .scalar_i64(
            "SELECT COUNT(*) FROM operators WHERE role = ?",
            vec![Bind::from("admin")],
        )
        .await;
    assert_eq!(admins, 1, "the scenario needs exactly one administrator");

    // Account-wide lock from many addresses, then the right password is refused.
    for index in 0..50 {
        let ip = format!("198.51.100.{}", index + 1);
        let failed = login(&harness, &admin, WRONG, &ip).await;
        assert!(matches!(failed.status, 401 | 423), "{}", failed.body);
    }
    let blocked = login(&harness, &admin, "p07-ao05-correct-guess", "203.0.113.50").await;
    assert_eq!(blocked.status, 423, "{}", blocked.body);
    assert!(
        blocked
            .headers
            .iter()
            .any(|(name, _)| name == "retry-after"),
        "a lock carries Retry-After"
    );

    // Recovery needs no id, no session and no database access.
    let reset = socket
        .call(&json!({"command":"reset-password","id":admin.to_uppercase()}))
        .await;
    let temporary = reset["temporary_password"]
        .as_str()
        .unwrap_or_else(|| panic!("reset failed: {reset}"))
        .to_owned();

    // The lock is gone; the temporary password signs in and the change is forced.
    let back = login(&harness, &admin, &temporary, "203.0.113.50").await;
    assert_eq!(back.status, 200, "{}", back.body);
    let id = harness.admin.id.clone();
    let session = harness.login(&id, &admin, &temporary).await;
    let gated = harness.get(&session, "/api/v3/admin/operators").await;
    assert_eq!(gated.status, 403, "{}", gated.body);
    assert_eq!(gated.body["error"], "password_change_required");
    let changed = harness
        .call(
            &session,
            "POST",
            "/api/v3/admin/session/change-password",
            &[],
            Some(&json!({
                "current_password": temporary,
                "new_password": "p07-ao05-rotated-password-long"
            })),
        )
        .await;
    assert!(
        changed.status == 200 || changed.status == 204,
        "{} {}",
        changed.status,
        changed.body
    );
    harness.restart_server().await;
}
