// SPDX-License-Identifier: AGPL-3.0-only

//! P07 / N-05: an operator session has an absolute lifetime from sign-in.
//! Refresh rotation used to restart the 30-day TTL each time, so only the 12 h
//! idle rule bounded a session that kept refreshing. The cap is read from the
//! family's first row, so rotation can never extend it, for browser and desktop
//! sessions alike. SQLite by default; PostgreSQL with `P02_TEST_BACKEND=postgres`.

mod support;

use serde_json::{Value, json};
use support::{Bind, Harness, HttpResponse, ORIGIN};

const ABSOLUTE_SECONDS: i64 = 3_600;
const ABSOLUTE: (&str, &str) = ("BLINDPASS_SESSION_ABSOLUTE_SECONDS", "3600");

fn cookie(response: &HttpResponse, name: &str) -> String {
    response
        .headers
        .iter()
        .filter(|(header, _)| header == "set-cookie")
        .find_map(|(_, value)| {
            let pair = value.split(';').next()?;
            let (cookie_name, cookie_value) = pair.split_once('=')?;
            (cookie_name == name).then(|| format!("{name}={cookie_value}"))
        })
        .expect("response cookie")
}

async fn browser_login(harness: &Harness, username: &str) -> HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[
                ("content-type", "application/json"),
                ("origin", ORIGIN),
                ("cookie", "bp_csrf=p07-pre-session"),
                ("x-csrf-token", "p07-pre-session"),
            ],
            Some(&json!({"username":username,"password":format!("{username}-test-password-long")})),
        )
        .await
}

async fn browser_refresh(harness: &Harness, login: &HttpResponse) -> HttpResponse {
    let csrf = login.body["csrf_token"].as_str().unwrap();
    harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[
                ("origin", ORIGIN),
                (
                    "cookie",
                    &format!(
                        "{}; {}",
                        cookie(login, "bp_refresh"),
                        cookie(login, "bp_csrf")
                    ),
                ),
                ("x-csrf-token", csrf),
            ],
            None,
        )
        .await
}

/// Move every session of the operator `seconds` into the past, as though that
/// much time had passed since sign-in.
async fn age_sessions(harness: &Harness, operator_id: &str, seconds: i64) {
    let milliseconds = seconds * 1_000;
    harness
        .execute(
            "UPDATE operator_sessions SET created_at = created_at - ?,
             expires_at = expires_at - ?, last_seen_at = last_seen_at - ?
             WHERE operator_id = ?",
            vec![
                Bind::Int(milliseconds),
                Bind::Int(milliseconds),
                Bind::Int(milliseconds),
                Bind::from(operator_id),
            ],
        )
        .await;
}

/// Latest expiry and first sign-in time of the family that holds the
/// operator's newest session row.
async fn newest_expiry_and_family_start(harness: &Harness, operator_id: &str) -> (i64, i64) {
    const FAMILY: &str = "family_id = (SELECT family_id FROM operator_sessions
        WHERE operator_id = ? ORDER BY created_at DESC LIMIT 1)";
    let expiry = harness
        .scalar_i64(
            &format!("SELECT MAX(expires_at) FROM operator_sessions WHERE {FAMILY}"),
            vec![Bind::from(operator_id)],
        )
        .await;
    let started = harness
        .scalar_i64(
            &format!("SELECT MIN(created_at) FROM operator_sessions WHERE {FAMILY}"),
            vec![Bind::from(operator_id)],
        )
        .await;
    (expiry, started)
}

#[tokio::test]
async fn p07_sl01_sign_in_is_capped_by_the_absolute_lifetime() {
    let harness = Harness::start_with(&[ABSOLUTE]).await;
    let alice = harness.create_operator("sl01-alice", "operator").await;
    let (expiry, started) = newest_expiry_and_family_start(&harness, &alice.id).await;
    // The sign-in row reads the clock twice (created, expires); allow one second.
    assert!(
        expiry - started <= ABSOLUTE_SECONDS * 1_000 + 1_000,
        "a fresh session lives {} ms, past the {ABSOLUTE_SECONDS} s cap",
        expiry - started
    );
}

#[tokio::test]
async fn p07_sl02_refresh_never_extends_a_browser_session_past_the_cap() {
    let harness = Harness::start_with(&[ABSOLUTE]).await;
    let alice = harness.create_operator("sl02-alice", "operator").await;
    let login = browser_login(&harness, "sl02-alice").await;
    assert_eq!(login.status, 200, "{}", login.body);

    // Fifty minutes later a refresh still works but only until the cap.
    age_sessions(&harness, &alice.id, 3_000).await;
    let refreshed = browser_refresh(&harness, &login).await;
    assert_eq!(refreshed.status, 200, "{}", refreshed.body);
    let (expiry, started) = newest_expiry_and_family_start(&harness, &alice.id).await;
    assert!(
        expiry - started <= ABSOLUTE_SECONDS * 1_000,
        "the rotated session lives until {} ms after sign-in, past the cap",
        expiry - started
    );
    let reported = refreshed.body["expires_at"].as_i64().expect("expires_at");
    assert!(reported <= started + ABSOLUTE_SECONDS * 1_000);

    // After the cap even a fresh refresh credential is refused.
    age_sessions(&harness, &alice.id, 700).await;
    let late = browser_refresh(&harness, &refreshed).await;
    assert_eq!(late.status, 401, "{}", late.body);
    let read = harness
        .request(
            "GET",
            "/api/v3/admin/session",
            &[(
                "cookie",
                &format!(
                    "{}; {}",
                    cookie(&refreshed, "bp_session"),
                    cookie(&refreshed, "bp_csrf")
                ),
            )],
            None,
        )
        .await;
    assert_eq!(read.status, 401, "{}", read.body);
}

#[tokio::test]
async fn p07_sl03_the_desktop_family_has_the_same_cap() {
    let harness = Harness::start_with(&[ABSOLUTE]).await;
    let alice = harness.create_operator("sl03-alice", "operator").await;
    let login = harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[("content-type", "application/json")],
            Some(&json!({
                "kind":"desktop",
                "username":"sl03-alice",
                "password":"sl03-alice-test-password-long"
            })),
        )
        .await;
    assert_eq!(login.status, 200, "{}", login.body);
    let refresh_token = login.body["refresh_token"].as_str().unwrap().to_owned();
    age_sessions(&harness, &alice.id, 3_000).await;
    let refreshed = harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[("content-type", "application/json")],
            Some(&json!({"kind":"desktop","refresh_token":refresh_token})),
        )
        .await;
    assert_eq!(refreshed.status, 200, "{}", refreshed.body);
    let (expiry, started) = newest_expiry_and_family_start(&harness, &alice.id).await;
    assert!(expiry - started <= ABSOLUTE_SECONDS * 1_000);
    age_sessions(&harness, &alice.id, 700).await;
    let next = refreshed.body["refresh_token"].as_str().unwrap().to_owned();
    let late = harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[("content-type", "application/json")],
            Some(&json!({"kind":"desktop","refresh_token":next})),
        )
        .await;
    assert_eq!(late.status, 401, "{}", late.body);
}

#[tokio::test]
async fn p07_sl04_the_default_cap_is_seven_days_and_published() {
    let harness = Harness::start().await;
    let capabilities = harness
        .request("GET", "/api/v3/capabilities", &[], None)
        .await;
    let session: &Value = &capabilities.body["limits"]["session"];
    assert_eq!(
        *session,
        json!({"absolute_seconds": 604_800, "idle_seconds": 43_200})
    );
    let alice = harness.create_operator("sl04-alice", "operator").await;
    let (expiry, started) = newest_expiry_and_family_start(&harness, &alice.id).await;
    assert!(expiry - started <= 604_800 * 1_000 + 1_000);
}
