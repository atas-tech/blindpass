// SPDX-License-Identifier: AGPL-3.0-only

//! P07 / pilot S02: every authentication secret the controller accepts
//! (bootstrap token, operator password, browser session and refresh cookies,
//! desktop access and refresh tokens) is stored only as a verifier, and a
//! refused credential is answered without echoing the presented value or any
//! stored verifier. The double-submit CSRF value is the one secret kept as
//! issued (the session read serves it back); the test pins that it is never a
//! bearer secret. SQLite by default; PostgreSQL with `P02_TEST_BACKEND=postgres`.

mod support;

use blindpass_core::custody::sha256;
use serde_json::json;
use support::{Harness, HttpResponse, ORIGIN};

const TOKEN: &str = "p07-s02-bootstrap-token-with-more-than-32-bytes";
const PASSWORD: &str = "p07-s02-operator-password-long";

fn digest(text: &str) -> String {
    sha256(text.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn cookie_value(response: &HttpResponse, name: &str) -> String {
    response
        .headers
        .iter()
        .filter(|(header, _)| header == "set-cookie")
        .find_map(|(_, value)| {
            let pair = value.split(';').next()?;
            let (cookie_name, cookie_value) = pair.split_once('=')?;
            (cookie_name == name).then(|| cookie_value.to_owned())
        })
        .unwrap_or_else(|| panic!("{name} cookie missing"))
}

async fn browser_login(harness: &Harness, username: &str) -> HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[
                ("content-type", "application/json"),
                ("origin", ORIGIN),
                ("cookie", "bp_csrf=p07-s02-pre-session"),
                ("x-csrf-token", "p07-s02-pre-session"),
            ],
            Some(&json!({"username":username,"password":PASSWORD})),
        )
        .await
}

async fn browser_refresh(harness: &Harness, refresh: &str, csrf: &str) -> HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[
                ("origin", ORIGIN),
                ("cookie", &format!("bp_refresh={refresh}; bp_csrf={csrf}")),
                ("x-csrf-token", csrf),
            ],
            None,
        )
        .await
}

async fn desktop_refresh(harness: &Harness, token: &str) -> HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[("content-type", "application/json")],
            Some(&json!({"kind":"desktop","refresh_token":token})),
        )
        .await
}

/// Nothing a client could replay appears in the response, headers or body.
fn assert_echoes_nothing(response: &HttpResponse, secrets: &[String], stored: &[String]) {
    let text = format!("{:?} {}", response.headers, response.body);
    for secret in secrets.iter().chain(stored) {
        assert!(
            !text.contains(secret.as_str()),
            "a refusal echoed a credential or verifier: {text}"
        );
    }
}

#[tokio::test]
async fn p07_at01_only_verifiers_are_stored_and_refusals_echo_nothing() {
    let harness = Harness::start_unbootstrapped(&[]).await;
    assert!(
        harness
            .store
            .issue_bootstrap_token(&digest(TOKEN), 900)
            .await
            .expect("issue bootstrap token")
    );
    let created = harness
        .request(
            "POST",
            "/api/v3/admin/bootstrap",
            &[
                ("content-type", "application/json"),
                ("origin", ORIGIN),
                ("x-blindpass-bootstrap-token", TOKEN),
            ],
            Some(&json!({
                "username":"at01-admin",
                "display_name":"S02 Admin",
                "password":PASSWORD
            })),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);

    // Browser: sign in, then rotate the refresh cookie once.
    let login = browser_login(&harness, "at01-admin").await;
    assert_eq!(login.status, 200, "{}", login.body);
    let first_session = cookie_value(&login, "bp_session");
    let first_refresh = cookie_value(&login, "bp_refresh");
    let first_csrf = login.body["csrf_token"].as_str().unwrap().to_owned();
    let rotated = browser_refresh(&harness, &first_refresh, &first_csrf).await;
    assert_eq!(rotated.status, 200, "{}", rotated.body);
    let second_session = cookie_value(&rotated, "bp_session");
    let second_refresh = cookie_value(&rotated, "bp_refresh");
    let second_csrf = rotated.body["csrf_token"].as_str().unwrap().to_owned();

    // Desktop: sign in, then rotate once.
    let desktop = harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[("content-type", "application/json")],
            Some(&json!({"kind":"desktop","username":"at01-admin","password":PASSWORD})),
        )
        .await;
    assert_eq!(desktop.status, 200, "{}", desktop.body);
    let desktop_access = desktop.body["access_token"].as_str().unwrap().to_owned();
    let desktop_refresh_token = desktop.body["refresh_token"].as_str().unwrap().to_owned();
    let desktop_rotated = desktop_refresh(&harness, &desktop_refresh_token).await;
    assert_eq!(desktop_rotated.status, 200, "{}", desktop_rotated.body);
    let desktop_access_2 = desktop_rotated.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let desktop_refresh_2 = desktop_rotated.body["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let secrets: Vec<String> = [
        TOKEN,
        PASSWORD,
        &first_session,
        &first_refresh,
        &second_session,
        &second_refresh,
        &desktop_access,
        &desktop_refresh_token,
        &desktop_access_2,
        &desktop_refresh_2,
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect();

    let bootstrap_rows = harness
        .strings("SELECT token_hash FROM bootstrap_tokens", vec![])
        .await;
    let password_rows = harness
        .strings("SELECT password_hash FROM operators", vec![])
        .await;
    let session_rows = harness
        .strings("SELECT id FROM operator_sessions", vec![])
        .await;
    let refresh_rows = harness
        .strings("SELECT refresh_hash FROM operator_sessions", vec![])
        .await;
    let csrf_rows = harness
        .strings("SELECT csrf_secret FROM operator_sessions", vec![])
        .await;
    let stored: Vec<String> = bootstrap_rows
        .iter()
        .chain(&password_rows)
        .chain(&session_rows)
        .chain(&refresh_rows)
        .flatten()
        .cloned()
        .collect();

    // No stored verifier contains, or equals, a credential a client holds.
    for secret in &secrets {
        for value in &stored {
            assert!(
                !value.contains(secret.as_str()),
                "a credential is stored as issued"
            );
        }
    }
    // The verifiers are the expected one-way forms.
    assert_eq!(
        bootstrap_rows,
        vec![Some(digest(TOKEN))],
        "bootstrap token verifier"
    );
    assert!(
        password_rows
            .iter()
            .flatten()
            .all(|hash| hash.starts_with("$argon2")),
        "operator passwords are Argon2 hashes: {password_rows:?}"
    );
    for bearer in [
        &first_session,
        &second_session,
        &desktop_access,
        &desktop_access_2,
    ] {
        assert!(
            session_rows.contains(&Some(digest(bearer))),
            "a session identifier is stored other than as its digest"
        );
    }
    for bearer in [
        &first_refresh,
        &second_refresh,
        &desktop_refresh_token,
        &desktop_refresh_2,
    ] {
        assert!(
            refresh_rows.contains(&Some(digest(bearer))),
            "a refresh token is stored other than as its digest"
        );
    }
    // The CSRF double-submit value is stored as issued, so it must never also
    // be something that authenticates by itself.
    for csrf in csrf_rows.iter().flatten() {
        assert!(!secrets.contains(csrf) && !stored.contains(csrf));
    }
    assert!(
        csrf_rows.contains(&Some(first_csrf.clone()))
            || csrf_rows.contains(&Some(second_csrf.clone()))
    );

    // Refusals: a replayed (already rotated) refresh cookie, an unknown
    // well-formed token and a desktop replay answer without echoing anything.
    let replay = browser_refresh(&harness, &first_refresh, &first_csrf).await;
    assert_eq!(replay.status, 401, "{}", replay.body);
    assert_echoes_nothing(&replay, &secrets, &stored);
    let unknown = "A".repeat(43);
    let unknown_refresh = browser_refresh(&harness, &unknown, &first_csrf).await;
    assert_eq!(unknown_refresh.status, 401, "{}", unknown_refresh.body);
    assert_echoes_nothing(&unknown_refresh, &secrets, &stored);
    assert!(!format!("{}", unknown_refresh.body).contains(&unknown));
    let desktop_replay = desktop_refresh(&harness, &desktop_refresh_token).await;
    assert_eq!(desktop_replay.status, 401, "{}", desktop_replay.body);
    assert_echoes_nothing(&desktop_replay, &secrets, &stored);
    // The browser replay revoked its family, so the newest refresh cookie is dead too.
    let after = browser_refresh(&harness, &second_refresh, &second_csrf).await;
    assert_eq!(after.status, 401, "{}", after.body);
    // The desktop replay revoked the desktop family likewise.
    let desktop_after = desktop_refresh(&harness, &desktop_refresh_2).await;
    assert_eq!(desktop_after.status, 401, "{}", desktop_after.body);
}

#[tokio::test]
async fn p07_at02_bootstrap_token_is_single_use_and_expires() {
    let harness = Harness::start_unbootstrapped(&[]).await;
    assert!(
        harness
            .store
            .issue_bootstrap_token(&digest(TOKEN), 900)
            .await
            .unwrap()
    );
    let expiry = harness
        .scalar_i64("SELECT expires_at FROM bootstrap_tokens", vec![])
        .await;
    let now = harness.now_ms().await;
    assert!(
        (now..=now + 901_000).contains(&expiry),
        "bootstrap token lives {} ms",
        expiry - now
    );
    let body = json!({"username":"at02-admin","display_name":"S02","password":PASSWORD});
    let headers = [
        ("content-type", "application/json"),
        ("origin", ORIGIN),
        ("x-blindpass-bootstrap-token", TOKEN),
    ];
    let first = harness
        .request("POST", "/api/v3/admin/bootstrap", &headers, Some(&body))
        .await;
    assert_eq!(first.status, 201, "{}", first.body);
    let again = harness
        .request("POST", "/api/v3/admin/bootstrap", &headers, Some(&body))
        .await;
    assert_eq!(again.status, 409, "{}", again.body);
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM bootstrap_tokens WHERE used_at IS NULL",
                vec![]
            )
            .await,
        0
    );
}
