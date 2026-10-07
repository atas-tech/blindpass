// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use blindpass_controller::store::Store;
use serde_json::json;
use support::{Backend, Bind, Harness, raw_request};

#[tokio::test]
async fn login_attempts_are_bounded_before_password_verification() {
    let harness = Harness::start().await;
    let mut statuses = Vec::new();
    for _ in 0..11 {
        let response = harness
            .request(
                "POST",
                "/api/v3/admin/session/login",
                &[("content-type", "application/json")],
                Some(&json!({
                    "kind":"desktop",
                    "username":harness.admin.username,
                    "password":"incorrect-dummy-password"
                })),
            )
            .await;
        statuses.push(response.status);
    }
    // P07-D4: ten failures from one address lock that account/source pair, so
    // the eleventh attempt is refused as locked (423) before any hashing; the
    // old shared 10-per-minute bucket answered 429 here.
    assert_eq!(
        statuses,
        [401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 423]
    );
}

#[tokio::test]
async fn a_database_session_identifier_cannot_authenticate() {
    let harness = Harness::start().await;
    let ids = harness
        .strings(
            "SELECT id FROM operator_sessions WHERE operator_id = ? AND kind = 'browser' AND revoked_at IS NULL",
            vec![Bind::Text(harness.admin.id.clone())],
        )
        .await;
    let stored_id = ids[0].as_ref().unwrap();
    assert!(!harness.admin.cookies.contains(stored_id));
    let stolen_cookie = format!("bp_session={stored_id}");
    let response = raw_request(
        harness.address,
        "GET",
        "/api/v3/admin/session",
        &[("cookie", &stolen_cookie)],
        None,
    )
    .await;
    assert_eq!(response.status, 401);
    assert_eq!(
        harness
            .get(&harness.admin, "/api/v3/admin/session")
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn a_database_desktop_identifier_cannot_authenticate_as_bearer() {
    let harness = Harness::start().await;
    let login = harness
        .request(
            "POST",
            "/api/v3/admin/session/login",
            &[("content-type", "application/json")],
            Some(&json!({
                "kind":"desktop",
                "username":harness.admin.username,
                "password":format!("{}-test-password-long", harness.admin.username)
            })),
        )
        .await;
    assert_eq!(login.status, 200, "{}", login.body);
    let access_token = login.body["access_token"].as_str().unwrap();
    let ids = harness
        .strings(
            "SELECT id FROM operator_sessions WHERE operator_id = ? AND kind = 'desktop' AND revoked_at IS NULL",
            vec![Bind::Text(harness.admin.id.clone())],
        )
        .await;
    let stored_id = ids[0].as_ref().unwrap();
    assert_ne!(access_token, stored_id);
    let stolen_bearer = format!("Bearer {stored_id}");
    let response = harness
        .request(
            "GET",
            "/api/v3/admin/session",
            &[("authorization", &stolen_bearer)],
            None,
        )
        .await;
    assert_eq!(response.status, 401);
    let bearer = format!("Bearer {access_token}");
    assert_eq!(
        harness
            .request(
                "GET",
                "/api/v3/admin/session",
                &[("authorization", &bearer)],
                None,
            )
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn upgrading_a_version_13_database_expires_old_sessions() {
    let harness = Harness::start().await;
    harness
        .execute(
            "UPDATE operator_sessions SET id = ? WHERE operator_id = ? AND kind = 'browser'",
            vec![
                Bind::Text("legacy-session-canary".to_owned()),
                Bind::Text(harness.admin.id.clone()),
            ],
        )
        .await;
    harness
        .execute("UPDATE controller_meta SET schema_version = 13", vec![])
        .await;
    let upgraded = Store::connect(&harness.database_url).await.unwrap();
    assert_eq!(
        harness
            .scalar_i64("SELECT COUNT(*) FROM operator_sessions", vec![])
            .await,
        0
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT CAST(schema_version AS BIGINT) FROM controller_meta",
                vec![]
            )
            .await,
        blindpass_controller::store::SCHEMA_VERSION
    );
    assert!(
        upgraded
            .operator_by_id(&harness.admin.id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn idle_node_poll_does_not_repeatedly_write_its_session() {
    let harness = Harness::start().await;
    let node = harness.online_node("idle-poll-node", 79).await;
    harness
        .execute(
            "CREATE TABLE review_poll_writes (count BIGINT NOT NULL)",
            vec![],
        )
        .await;
    harness
        .execute("INSERT INTO review_poll_writes VALUES (0)", vec![])
        .await;
    if matches!(&harness.backend, Backend::Postgres(_)) {
        harness
            .execute(
                "CREATE FUNCTION review_count_poll_writes() RETURNS trigger AS $$ \
                 BEGIN UPDATE review_poll_writes SET count = count + 1; RETURN NEW; END; \
                 $$ LANGUAGE plpgsql",
                vec![],
            )
            .await;
        harness
            .execute(
                "CREATE TRIGGER review_count AFTER UPDATE OF delivered_seq ON node_sessions \
                 FOR EACH ROW EXECUTE FUNCTION review_count_poll_writes()",
                vec![],
            )
            .await;
    } else {
        harness
            .execute(
                "CREATE TRIGGER review_count AFTER UPDATE OF delivered_seq ON node_sessions \
                 BEGIN UPDATE review_poll_writes SET count = count + 1; END",
                vec![],
            )
            .await;
    }
    let timed = tokio::time::timeout(
        std::time::Duration::from_millis(2_250),
        harness.poll(&node.bearer, &json!({})),
    )
    .await;
    assert!(timed.is_err());
    let writes = harness
        .scalar_i64("SELECT count FROM review_poll_writes", vec![])
        .await;
    assert!(writes <= 1, "empty poll wrote its session {writes} times");
}

#[tokio::test]
async fn idle_poll_still_checks_that_its_session_exists() {
    let harness = Harness::start().await;
    let node = harness.online_node("removed-poll-session", 80).await;
    let poll_body = json!({});
    let (response, _) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(harness.poll(&node.bearer, &poll_body), async {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            harness
                .execute(
                    "DELETE FROM node_sessions WHERE node_id = ?",
                    vec![Bind::Text(node.id.clone())],
                )
                .await;
        })
    })
    .await
    .expect("removed session must end the idle poll promptly");
    assert_eq!(response.status, 503);
}
