// SPDX-License-Identifier: AGPL-3.0-only

//! P07-D4 / P07-I02 / pilot S05: operator login abuse limits on actual HTTP.
//! Failures-only counting, per-account lockout with `423 locked`, per-IP
//! failure ceiling, uniform behaviour for unknown accounts, bounded state and
//! recovery through the local reset path. SQLite by default; PostgreSQL with
//! `P02_TEST_BACKEND=postgres` and `P02_TEST_POSTGRES_URL`.

mod support;

use serde_json::{Value, json};
use support::{Bind, Harness, HttpResponse, ORIGIN, TestDirectory};

const PROXY: (&str, &str) = ("BLINDPASS_TRUST_PROXY", "127.0.0.0/8,::1/128");
const WRONG: &str = "p07-dummy-wrong-password-canary";

fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

async fn attempt(harness: &Harness, username: &str, password: &str, ip: &str) -> HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[
                ("content-type", "application/json"),
                ("origin", ORIGIN),
                ("cookie", "bp_csrf=p07-pre-session"),
                ("x-csrf-token", "p07-pre-session"),
                ("x-forwarded-for", ip),
            ],
            Some(&json!({"username":username,"password":password})),
        )
        .await
}

async fn desktop_attempt(
    harness: &Harness,
    username: &str,
    password: &str,
    ip: &str,
) -> HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[
                ("content-type", "application/json"),
                ("x-forwarded-for", ip),
            ],
            Some(&json!({"kind":"desktop","username":username,"password":password})),
        )
        .await
}

fn password_for(username: &str) -> String {
    format!("{username}-test-password-long")
}

/// Fail `count` times from one address.
async fn fail_from(harness: &Harness, username: &str, count: usize, ip: &str) {
    for index in 0..count {
        let response = attempt(harness, username, WRONG, ip).await;
        assert_eq!(response.status, 401, "failure {index}: {}", response.body);
    }
}

/// Fail `count` times, each from its own documentation-range address.
async fn fail_from_distinct_ips(harness: &Harness, username: &str, count: usize, base: u8) {
    for index in 0..count {
        let ip = format!("198.51.{base}.{}", index + 1);
        let response = attempt(harness, username, WRONG, &ip).await;
        assert_eq!(response.status, 401, "failure {index}: {}", response.body);
    }
}

/// Account-level limiter rows (everything but the per-address ceiling).
async fn account_rows(harness: &Harness) -> i64 {
    let mut total = 0;
    for prefix in ["fail", "lock", "src", "slock"] {
        total += rows(harness, &format!("operator-login-{prefix}:%")).await;
    }
    total
}

async fn rows(harness: &Harness, pattern: &str) -> i64 {
    harness
        .scalar_i64(
            "SELECT COUNT(*) FROM rate_windows WHERE key LIKE ?",
            vec![Bind::from(pattern)],
        )
        .await
}

#[tokio::test]
async fn p07_ll01_a_guesser_locks_only_its_own_address_never_the_operator() {
    let harness = Harness::start_with(&[PROXY]).await;
    let alice = harness.create_operator("ll01-alice", "operator").await;
    let sessions = harness
        .scalar_i64(
            "SELECT COUNT(*) FROM operator_sessions WHERE operator_id = ?",
            vec![Bind::from(alice.id.as_str())],
        )
        .await;

    fail_from(&harness, "ll01-alice", 10, "198.51.100.10").await;
    let locked = attempt(
        &harness,
        "ll01-alice",
        &password_for("ll01-alice"),
        "198.51.100.10",
    )
    .await;
    assert_eq!(locked.status, 423, "{}", locked.body);
    assert_eq!(locked.body["error"], "locked");
    let retry_after = locked.body["retry_after"].as_u64().expect("retry_after");
    assert!((1..=900).contains(&retry_after), "{retry_after}");
    assert_eq!(
        header(&locked, "retry-after"),
        Some(retry_after.to_string().as_str())
    );
    let after = harness
        .scalar_i64(
            "SELECT COUNT(*) FROM operator_sessions WHERE operator_id = ?",
            vec![Bind::from(alice.id.as_str())],
        )
        .await;
    assert_eq!(
        after, sessions,
        "a locked attempt must not create a session"
    );

    // The operator signs in from another address while the guesser is locked.
    let elsewhere = attempt(
        &harness,
        "ll01-alice",
        &password_for("ll01-alice"),
        "203.0.113.11",
    )
    .await;
    assert_eq!(elsewhere.status, 200, "{}", elsewhere.body);
    // Another account is unaffected from the locked address too.
    let bob = harness.create_operator("ll01-bob", "viewer").await;
    let bob_login = attempt(
        &harness,
        "ll01-bob",
        &password_for("ll01-bob"),
        "198.51.100.10",
    )
    .await;
    assert_eq!(bob_login.status, 200, "{}", bob_login.body);
    assert_eq!(bob.username, "ll01-bob");
}

#[tokio::test]
async fn p07_ll02_guessing_spread_over_addresses_locks_the_account_for_everyone() {
    let harness =
        Harness::start_with(&[PROXY, ("BLINDPASS_LOGIN_ACCOUNT_TOTAL_FAILURES", "12")]).await;
    harness.create_operator("ll02-alice", "operator").await;
    fail_from_distinct_ips(&harness, "ll02-alice", 11, 2).await;
    let still_open = attempt(
        &harness,
        "ll02-alice",
        &password_for("ll02-alice"),
        "203.0.113.20",
    )
    .await;
    assert_eq!(still_open.status, 200, "{}", still_open.body);
    // That success cleared the account counter; spend the whole total again.
    fail_from_distinct_ips(&harness, "ll02-alice", 12, 22).await;
    let locked = attempt(
        &harness,
        "ll02-alice",
        &password_for("ll02-alice"),
        "203.0.113.21",
    )
    .await;
    assert_eq!(locked.status, 423, "{}", locked.body);
    assert_eq!(locked.body["error"], "locked");
}

#[tokio::test]
async fn p07_ll03_lock_expires_and_success_clears_counters() {
    let harness = Harness::start_with(&[PROXY]).await;
    harness.create_operator("ll03-alice", "operator").await;
    fail_from(&harness, "ll03-alice", 10, "203.0.113.30").await;
    assert_eq!(
        attempt(
            &harness,
            "ll03-alice",
            &password_for("ll03-alice"),
            "203.0.113.30"
        )
        .await
        .status,
        423
    );
    harness
        .execute(
            "UPDATE rate_windows SET expires_at = 0 WHERE key LIKE 'operator-login-%'",
            vec![],
        )
        .await;
    let ok = attempt(
        &harness,
        "ll03-alice",
        &password_for("ll03-alice"),
        "203.0.113.30",
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    for prefix in ["fail", "src", "slock", "lock"] {
        assert_eq!(
            rows(&harness, &format!("operator-login-{prefix}:%")).await,
            0,
            "{prefix} rows after a successful sign-in"
        );
    }
}

#[tokio::test]
async fn p07_ll04_failures_below_the_limit_do_not_accumulate_across_a_success() {
    let harness = Harness::start_with(&[PROXY]).await;
    harness.create_operator("ll04-alice", "operator").await;
    fail_from(&harness, "ll04-alice", 9, "203.0.113.40").await;
    let ok = attempt(
        &harness,
        "ll04-alice",
        &password_for("ll04-alice"),
        "203.0.113.40",
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    fail_from(&harness, "ll04-alice", 9, "203.0.113.40").await;
    let again = attempt(
        &harness,
        "ll04-alice",
        &password_for("ll04-alice"),
        "203.0.113.40",
    )
    .await;
    assert_eq!(again.status, 200, "{}", again.body);
}

#[tokio::test]
async fn p07_ll05_successful_logins_are_never_limited() {
    let harness = Harness::start_with(&[PROXY]).await;
    harness.create_operator("ll05-alice", "operator").await;
    for index in 0..12 {
        let response = attempt(
            &harness,
            "ll05-alice",
            &password_for("ll05-alice"),
            "203.0.113.50",
        )
        .await;
        assert_eq!(response.status, 200, "login {index}: {}", response.body);
    }
}

#[tokio::test]
async fn p07_ll06_unknown_accounts_answer_like_known_ones_and_lock_alike() {
    let harness = Harness::start_with(&[PROXY]).await;
    harness.create_operator("ll06-alice", "operator").await;
    let known = attempt(&harness, "ll06-alice", WRONG, "203.0.113.60").await;
    let unknown = attempt(&harness, "ll06-nobody", WRONG, "203.0.113.60").await;
    assert_eq!(known.status, 401);
    assert_eq!(unknown.status, 401);
    assert_eq!(known.body, unknown.body);
    let names = |response: &HttpResponse| {
        let mut names = response
            .headers
            .iter()
            .map(|(name, _)| name.clone())
            .filter(|name| name != "date")
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    assert_eq!(names(&known), names(&unknown));

    fail_from(&harness, "ll06-nobody", 10, "203.0.113.61").await;
    let locked_unknown = attempt(&harness, "ll06-nobody", WRONG, "203.0.113.61").await;
    assert_eq!(locked_unknown.status, 423, "{}", locked_unknown.body);
    fail_from(&harness, "ll06-alice", 10, "203.0.113.62").await;
    let locked_known = attempt(&harness, "ll06-alice", WRONG, "203.0.113.62").await;
    assert_eq!(locked_known.status, 423, "{}", locked_known.body);
    let keys = |response: &HttpResponse| {
        let mut keys = response
            .body
            .as_object()
            .expect("object body")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        keys
    };
    assert_eq!(keys(&locked_known), keys(&locked_unknown));
}

#[tokio::test]
async fn p07_ll07_per_ip_failure_ceiling_is_separate_from_the_account_lock() {
    let harness = Harness::start_with(&[PROXY, ("BLINDPASS_LOGIN_IP_FAILURES", "5")]).await;
    harness.create_operator("ll07-alice", "operator").await;
    for index in 0..5 {
        let response = attempt(
            &harness,
            &format!("ll07-ghost-{index}"),
            WRONG,
            "203.0.113.70",
        )
        .await;
        assert_eq!(response.status, 401, "{}", response.body);
    }
    let limited = attempt(
        &harness,
        "ll07-alice",
        &password_for("ll07-alice"),
        "203.0.113.70",
    )
    .await;
    assert_eq!(limited.status, 429, "{}", limited.body);
    assert_eq!(limited.body["error"], "login_rate_limited");
    assert!(header(&limited, "retry-after").is_some());
    let elsewhere = attempt(
        &harness,
        "ll07-alice",
        &password_for("ll07-alice"),
        "203.0.113.71",
    )
    .await;
    assert_eq!(elsewhere.status, 200, "{}", elsewhere.body);
}

#[tokio::test]
async fn p07_ll08_every_reset_path_clears_the_lock() {
    let mut harness = Harness::start_with(&[PROXY]).await;
    let alice = harness.create_operator("ll08-alice", "operator").await;

    // 1. Administrator over HTTP.
    fail_from(&harness, "ll08-alice", 10, "203.0.113.80").await;
    assert_eq!(
        attempt(
            &harness,
            "ll08-alice",
            &password_for("ll08-alice"),
            "203.0.113.80"
        )
        .await
        .status,
        423
    );
    let reset = harness
        .call(
            &harness.admin,
            "POST",
            &format!("/api/v3/admin/operators/{}/reset-password", alice.id),
            &[],
            None,
        )
        .await;
    assert_eq!(reset.status, 200, "{}", reset.body);
    let temporary = reset.body["temporary_password"]
        .as_str()
        .unwrap()
        .to_owned();
    let back = attempt(&harness, "ll08-alice", &temporary, "203.0.113.80").await;
    assert_eq!(back.status, 200, "{}", back.body);
    assert_eq!(account_rows(&harness).await, 0);

    // 2. The local admin socket, the transport of `blindpass admin
    //    reset-password` (the CLI sends this exact command).
    fail_from(&harness, "ll08-alice", 10, "203.0.113.80").await;
    assert_eq!(
        attempt(&harness, "ll08-alice", &temporary, "203.0.113.80")
            .await
            .status,
        423
    );
    let socket_path = harness.directory.file("admin.sock");
    let bound = blindpass_controller::admin_socket::bind_admin_socket(&socket_path)
        .expect("bind admin socket");
    let server = tokio::spawn(blindpass_controller::admin_socket::serve_admin_socket(
        bound,
        harness.store.clone(),
    ));
    let mut client = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("connect admin socket");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    client
        .write_all(
            format!(
                "{{\"command\":\"reset-password\",\"id\":\"{}\"}}\n",
                alice.id
            )
            .as_bytes(),
        )
        .await
        .expect("write reset command");
    client.shutdown().await.expect("finish command");
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).await.expect("read reset");
    let answer: Value = serde_json::from_slice(&answer).expect("JSON answer");
    let temporary = answer["temporary_password"]
        .as_str()
        .expect("temporary password");
    assert_eq!(account_rows(&harness).await, 0);
    let back = attempt(&harness, "ll08-alice", temporary, "203.0.113.80").await;
    assert_eq!(back.status, 200, "{}", back.body);
    server.abort();
    let _ = server.await;
    harness.restart_server().await;
}

#[tokio::test]
async fn p07_ll09_desktop_and_browser_logins_share_the_lock() {
    let harness = Harness::start_with(&[PROXY]).await;
    harness.create_operator("ll09-alice", "operator").await;
    for index in 0..10 {
        let response = desktop_attempt(&harness, "ll09-alice", WRONG, "198.51.100.9").await;
        assert_eq!(response.status, 401, "failure {index}: {}", response.body);
    }
    let desktop = desktop_attempt(
        &harness,
        "ll09-alice",
        &password_for("ll09-alice"),
        "198.51.100.9",
    )
    .await;
    assert_eq!(desktop.status, 423, "{}", desktop.body);
    assert_eq!(desktop.body["error"], "locked");
    assert!(desktop.body["retry_after"].as_u64().is_some());
    let browser = attempt(
        &harness,
        "ll09-alice",
        &password_for("ll09-alice"),
        "198.51.100.9",
    )
    .await;
    assert_eq!(browser.status, 423, "{}", browser.body);
}

#[tokio::test]
async fn p07_ll10_limits_are_configurable_and_enumerated_in_capabilities() {
    let harness = Harness::start_with(&[
        PROXY,
        ("BLINDPASS_LOGIN_ACCOUNT_FAILURES", "3"),
        ("BLINDPASS_LOGIN_ACCOUNT_TOTAL_FAILURES", "9"),
        ("BLINDPASS_LOGIN_IP_FAILURES", "7"),
        ("BLINDPASS_LOGIN_WINDOW_SECONDS", "120"),
        ("BLINDPASS_LOGIN_LOCKOUT_SECONDS", "60"),
    ])
    .await;
    let capabilities = harness
        .request("GET", "/api/v3/capabilities", &[], None)
        .await;
    assert_eq!(capabilities.status, 200);
    assert_eq!(
        capabilities.body["limits"]["login"],
        json!({
            "account_failures": 3,
            "account_total_failures": 9,
            "ip_failures": 7,
            "window_seconds": 120,
            "lockout_seconds": 60
        })
    );
    harness.create_operator("ll10-alice", "operator").await;
    fail_from(&harness, "ll10-alice", 3, "203.0.113.100").await;
    let locked = attempt(
        &harness,
        "ll10-alice",
        &password_for("ll10-alice"),
        "203.0.113.100",
    )
    .await;
    assert_eq!(locked.status, 423, "{}", locked.body);
    assert!(locked.body["retry_after"].as_u64().unwrap() <= 60);
}

#[tokio::test]
async fn p07_ll11_default_limits_are_published() {
    let harness = Harness::start().await;
    let capabilities = harness
        .request("GET", "/api/v3/capabilities", &[], None)
        .await;
    assert_eq!(
        capabilities.body["limits"]["login"],
        json!({
            "account_failures": 10,
            "account_total_failures": 50,
            "ip_failures": 30,
            "window_seconds": 900,
            "lockout_seconds": 900
        })
    );
}

#[test]
fn p07_ll12_out_of_range_login_settings_are_refused_at_startup() {
    let directory = TestDirectory::new();
    for (name, value) in [
        (
            "database.url",
            "sqlite:///tmp/unused.db?mode=rwc".to_owned(),
        ),
        ("root.secret", "R".repeat(32)),
        ("agent.secret", "A".repeat(32)),
        ("issuer.seed", "I".repeat(32)),
    ] {
        let path = directory.file(name);
        std::fs::write(&path, value).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let base = |extra: (&str, &str)| {
        blindpass_controller::config::Config::from_variables([
            ("BLINDPASS_TEST_MODE", "1"),
            ("BLINDPASS_LISTEN", "127.0.0.1:0"),
            ("BLINDPASS_PUBLIC_URL", "http://127.0.0.1:8080"),
            ("BLINDPASS_UI_BASE_URL", ORIGIN),
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
            (
                "BLINDPASS_ISSUER_KEY_FILE",
                directory.file("issuer.seed").to_str().unwrap(),
            ),
            extra,
        ])
    };
    assert!(base(("BLINDPASS_LOGIN_ACCOUNT_FAILURES", "10")).is_ok());
    for (name, value) in [
        ("BLINDPASS_LOGIN_ACCOUNT_FAILURES", "0"),
        ("BLINDPASS_LOGIN_ACCOUNT_FAILURES", "100001"),
        ("BLINDPASS_LOGIN_ACCOUNT_FAILURES", "ten"),
        // The account-wide total may not undercut the per-source limit.
        ("BLINDPASS_LOGIN_ACCOUNT_FAILURES", "60"),
        ("BLINDPASS_LOGIN_ACCOUNT_TOTAL_FAILURES", "0"),
        ("BLINDPASS_LOGIN_ACCOUNT_TOTAL_FAILURES", "5"),
        ("BLINDPASS_LOGIN_IP_FAILURES", "0"),
        ("BLINDPASS_LOGIN_WINDOW_SECONDS", "0"),
        ("BLINDPASS_LOGIN_WINDOW_SECONDS", "999999999"),
        ("BLINDPASS_LOGIN_LOCKOUT_SECONDS", "0"),
        ("BLINDPASS_LOGIN_TRACKED_ACCOUNTS", "1"),
        ("BLINDPASS_BOOTSTRAP_FAILURES_PER_PEER", "0"),
        ("BLINDPASS_BOOTSTRAP_FAILURES_GLOBAL", "0"),
    ] {
        assert!(base((name, value)).is_err(), "{name}={value} was accepted");
    }
}

#[tokio::test]
async fn p07_ll13_unknown_account_state_is_bounded_and_known_accounts_still_lock() {
    let harness = Harness::start_with(&[
        PROXY,
        ("BLINDPASS_LOGIN_TRACKED_ACCOUNTS", "16"),
        ("BLINDPASS_LOGIN_IP_FAILURES", "1000"),
    ])
    .await;
    harness.create_operator("ll13-alice", "operator").await;
    for index in 0..40 {
        let response = attempt(
            &harness,
            &format!("ll13-ghost-{index}"),
            WRONG,
            &format!("192.0.2.{}", index + 1),
        )
        .await;
        assert_eq!(response.status, 401, "{}", response.body);
    }
    assert!(rows(&harness, "operator-login-src:%").await <= 16);
    assert!(rows(&harness, "operator-login-fail:%").await <= 16);
    fail_from(&harness, "ll13-alice", 10, "203.0.113.130").await;
    assert_eq!(
        attempt(
            &harness,
            "ll13-alice",
            &password_for("ll13-alice"),
            "203.0.113.130"
        )
        .await
        .status,
        423
    );
}

#[tokio::test]
async fn p07_ll14_limiter_state_and_responses_carry_no_credentials() {
    let harness = Harness::start_with(&[PROXY]).await;
    harness.create_operator("ll14-alice", "operator").await;
    let mut seen: Vec<Value> = Vec::new();
    for index in 0..11 {
        let response = attempt(&harness, "ll14-alice", WRONG, "198.18.0.14").await;
        seen.push(json!({"index":index,"body":response.body,"headers":response.headers}));
    }
    let transcript = serde_json::to_string(&seen).unwrap();
    assert!(!transcript.contains(WRONG));
    assert!(!transcript.contains("ll14-alice"));
    let keys = harness
        .strings("SELECT key FROM rate_windows", vec![])
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert!(!keys.is_empty());
    for key in keys {
        assert!(!key.contains("ll14-alice"), "{key}");
        assert!(!key.contains(WRONG), "{key}");
        assert!(!key.contains("198.18.0.14") || key.starts_with("operator-login-ipfail:"));
    }
}

/// N-04: an unknown username must cost the same Argon2 work as a real one.
#[tokio::test]
async fn p07_ll15_unknown_and_known_accounts_take_comparable_time() {
    use std::time::Instant;
    let harness = Harness::start_with(&[PROXY, ("BLINDPASS_LOGIN_IP_FAILURES", "1000")]).await;
    harness.create_operator("ll15-alice", "operator").await;
    // Warm the dummy hash and connections; discard.
    attempt(&harness, "ll15-warm", WRONG, "192.0.2.200").await;
    attempt(&harness, "ll15-alice", WRONG, "192.0.2.201").await;
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for index in 0..5 {
        let start = Instant::now();
        let response = attempt(
            &harness,
            "ll15-alice",
            WRONG,
            &format!("192.0.2.{}", 10 + index),
        )
        .await;
        known.push(start.elapsed());
        assert_eq!(response.status, 401);
        let start = Instant::now();
        let response = attempt(
            &harness,
            &format!("ll15-nobody-{index}"),
            WRONG,
            &format!("192.0.2.{}", 30 + index),
        )
        .await;
        unknown.push(start.elapsed());
        assert_eq!(response.status, 401);
    }
    known.sort();
    unknown.sort();
    let (known, unknown) = (known[2], unknown[2]);
    assert!(
        unknown * 2 >= known,
        "unknown username answered in {unknown:?} against {known:?} for a real one"
    );
}
