// SPDX-License-Identifier: AGPL-3.0-only
//! P05-I02/I03/I04: actual signed browser intent -> approval/operation/grant.
//! No private helper or browser runtime is executed by this HTTP suite.
mod support;
use blindpass_core::fleet::{Grant, OperationCancellation, SignedEnvelope};
use serde_json::{Value, json};
use support::{FleetNode, Harness, signed_event};

async fn setup(decision: &str, seed: u8) -> (Harness, FleetNode, Value) {
    let h = Harness::start().await;
    let node = h.online_node("browser-intent", seed).await;
    let policy = json!([{"id":"intent-rule","action":"browser.session","mode":"browser_session",
        "decision":decision,"approval_required":decision=="pending_approval","max_ttl_seconds":60,
        "approver_ids":if decision=="pending_approval" {json!([h.admin.username])} else {json!([])}}]);
    assert_eq!(h.set_policy(policy).await.status, 200);
    let workload = h
        .create_workload(
            &node.id,
            "intent-worker",
            "intent-worker.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    assert_eq!(workload.status, 201);
    (h, node, workload.body)
}
async fn intent(h: &Harness, node: &FleetNode, workload: &Value, key: &str, ttl: u64) -> Value {
    signed_event(
        &node.id,
        &node.keys.signing,
        key,
        "operation_request",
        json!({
        "request_version":2,"node_id":node.id,"workload_id":workload["id"],"unit":workload["unit"],"account":workload["account"],
        "action":"browser.session","mode":"browser_session","purpose":"read approved report",
        "resource_id":"report-primary","invocation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ttl_seconds":ttl,"observed_at_ms":h.now_ms().await}),
    )
}
async fn operation(h: &Harness) -> Value {
    let reply = h.get(&h.admin, "/api/v3/operations").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let items = reply.body["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "one operation must be created from the broker intent"
    );
    items[0].clone()
}
async fn grants(h: &Harness, node: &FleetNode) -> Vec<Value> {
    h.inbox(&node.id)
        .await
        .into_iter()
        .filter(|e| e["kind"] == "grant")
        .collect()
}
fn verify(h: &Harness, value: &Value) {
    assert!(
        SignedEnvelope::from_json(&value.to_string())
            .unwrap()
            .verify(h.issuer.public_key(), &h.issuer_key_id, 1)
            .unwrap()
    );
}
async fn install_failure(h: &Harness, table: &str) {
    assert!(
        [
            "node_events",
            "operations",
            "operation_approvals",
            "audit_events",
            "grants",
            "node_inbox"
        ]
        .contains(&table)
    );
    if matches!(h.backend, support::Backend::Postgres(_)) {
        h.execute("CREATE FUNCTION p05_intent_write_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'P05 dummy storage failure'; END $$",vec![]).await;
        h.execute(&format!("CREATE TRIGGER p05_intent_write_failure BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION p05_intent_write_failure()"),vec![]).await;
    } else {
        h.execute(&format!("CREATE TRIGGER p05_intent_write_failure BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'P05 dummy storage failure'); END"),vec![]).await;
    }
}
async fn remove_failure(h: &Harness, table: &str) {
    if matches!(h.backend, support::Backend::Postgres(_)) {
        h.execute(
            &format!("DROP TRIGGER p05_intent_write_failure ON {table}"),
            vec![],
        )
        .await;
        h.execute("DROP FUNCTION p05_intent_write_failure()", vec![])
            .await;
    } else {
        let support::Backend::Sqlite(pool) = &h.backend else {
            unreachable!()
        };
        sqlx::query("DROP TRIGGER p05_intent_write_failure")
            .persistent(false)
            .execute(pool)
            .await
            .expect("drop disposable SQLite trigger");
        assert_eq!(h.scalar_i64("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='p05_intent_write_failure'",vec![]).await,0);
    }
}

#[tokio::test]
async fn intent_creates_workload_approval_without_human_create_and_replay_is_stable() {
    let (h, node, w) = setup("pending_approval", 131).await;
    let event = intent(&h, &node, &w, "event_auto_approval_00000001", 120).await;
    let posted = h.post_events(&node.bearer, &event).await;
    assert_eq!(posted.status, 200, "{}", posted.body);
    let op = operation(&h).await;
    assert_eq!(op["status"], "awaiting_approval");
    assert!(grants(&h, &node).await.is_empty());
    let approval = op["approval_id"].as_str().unwrap();
    let detail = h
        .get(&h.admin, &format!("/api/v3/approvals/{approval}"))
        .await;
    assert_eq!(detail.status, 200);
    assert_eq!(
        detail.body["requester_summary"]["requester_type"],
        "workload"
    );
    assert_eq!(detail.body["requester_summary"]["workload_id"], w["id"]);
    assert!(detail.body["requester_summary"]["operator_id"].is_null());
    let outsider = h.create_operator("intent-outsider", "operator").await;
    assert_eq!(
        h.decide(&outsider, approval, "approve", "intent-outsider-000001")
            .await
            .status,
        403
    );
    let node_approval = h
        .request(
            "POST",
            &format!("/api/v3/approvals/{approval}/approve"),
            &[
                ("authorization", &node.bearer),
                ("content-type", "application/json"),
            ],
            Some(&json!({"expected_status":"pending","expected_version":1})),
        )
        .await;
    assert_eq!(node_approval.status, 401);
    assert_eq!(
        h.decide(&h.admin, approval, "approve", "intent-approved-000001")
            .await
            .status,
        200
    );
    let issued = grants(&h, &node).await;
    assert_eq!(issued.len(), 1);
    verify(&h, &issued[0]);
    let grant = Grant::from_value(
        SignedEnvelope::from_json(&issued[0].to_string())
            .unwrap()
            .body(),
    )
    .unwrap();
    assert_eq!(grant.operation_id, op["id"]);
    assert_eq!(
        grant.request_event_key.as_deref(),
        Some("event_auto_approval_00000001")
    );
    assert_eq!(grant.expires_at_ms - grant.issued_at_ms, 60_000);
    assert_eq!(
        h.post_events(&node.bearer, &event).await.body["duplicates"],
        1
    );
    assert_eq!(operation(&h).await["id"], op["id"]);
    assert_eq!(grants(&h, &node).await, issued);
    let manual = json!({"workload_id":w["id"],"action":"browser.session","mode":"browser_session","purpose":"read approved report","resource_id":"report-primary","invocation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ttl_seconds":120,"broker_event_key":"event_auto_approval_00000001"});
    assert_eq!(
        h.call(
            &h.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "intent-manual-claim-00001")],
            Some(&manual)
        )
        .await
        .status,
        409
    );
}

#[tokio::test]
async fn intent_allow_concurrent_replays_issue_one_original_signed_grant() {
    let (h, node, w) = setup("allow", 132).await;
    let event = intent(&h, &node, &w, "event_auto_allow_00000001", 120).await;
    let (a, b, c) = tokio::join!(
        h.post_events(&node.bearer, &event),
        h.post_events(&node.bearer, &event),
        h.post_events(&node.bearer, &event)
    );
    for reply in [a, b, c] {
        assert_eq!(reply.status, 200, "{}", reply.body);
    }
    let op = operation(&h).await;
    assert_eq!(op["status"], "granted");
    let issued = grants(&h, &node).await;
    assert_eq!(issued.len(), 1);
    verify(&h, &issued[0]);
    assert_eq!(
        h.scalar_i64(
            "SELECT COUNT(*) FROM node_events WHERE kind='operation_request'",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        h.scalar_i64(
            "SELECT COUNT(*) FROM audit_events WHERE action='fleet.operation_requested'",
            vec![]
        )
        .await,
        1
    );
    assert_eq!(
        h.post_events(&node.bearer, &event).await.body["duplicates"],
        1
    );
    assert_eq!(grants(&h, &node).await, issued);
}

#[tokio::test]
async fn intent_deny_commits_signed_closure_without_grant_and_replays_once() {
    let (h, node, w) = setup("deny", 133).await;
    let event = intent(&h, &node, &w, "event_auto_deny_00000001", 60).await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 200);
    assert_eq!(operation(&h).await["status"], "denied");
    assert!(grants(&h, &node).await.is_empty());
    let closures = h
        .inbox(&node.id)
        .await
        .into_iter()
        .filter(|e| e["kind"] == "operation_closed")
        .collect::<Vec<_>>();
    assert_eq!(closures.len(), 1);
    verify(&h, &closures[0]);
    assert_eq!(closures[0]["body"]["status"], "denied");
    assert_eq!(
        h.post_events(&node.bearer, &event).await.body["duplicates"],
        1
    );
    assert_eq!(
        h.inbox(&node.id)
            .await
            .into_iter()
            .filter(|e| e["kind"] == "operation_closed")
            .count(),
        1
    );
}

#[tokio::test]
async fn intent_invalid_signed_bindings_versions_and_fields_create_no_authority() {
    let (h, node, w) = setup("allow", 134).await;
    for (i, (field, value)) in [
        ("request_version", json!(3)),
        ("request_version", json!(null)),
        ("node_id", json!("different-node")),
        ("unit", json!("another.service")),
        ("account", json!("uid:1002")),
        ("workload_id", json!("missing-workload")),
        ("invocation_id", json!("bad-invocation")),
        ("mode", json!("file")),
        ("action", json!("noop.marker")),
        ("ttl_seconds", json!(121)),
        ("ttl_seconds", json!(0)),
        ("observed_at_ms", json!(1)),
        ("observed_at_ms", json!(h.now_ms().await + 120_000)),
        ("purpose", json!("invalid\nmetadata")),
        ("source_password", json!("DUMMY_AUTO_PRIVATE_CANARY")),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("event_auto_invalid_{i:08}");
        let mut body = intent(&h, &node, &w, &key, 60).await["events"][0]["body"].clone();
        body[field] = value;
        let reply = h
            .post_events(
                &node.bearer,
                &signed_event(
                    &node.id,
                    &node.keys.signing,
                    &key,
                    "operation_request",
                    body,
                ),
            )
            .await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(
            reply.body["discarded"].as_array().unwrap().len(),
            1,
            "{field}: {}",
            reply.body
        );
        assert_eq!(reply.body["accepted"], 0);
        assert!(!reply.body.to_string().contains("DUMMY_AUTO_PRIVATE_CANARY"));
    }
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM operations", vec![])
            .await,
        0
    );
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM node_events", vec![])
            .await,
        0
    );
    assert!(grants(&h, &node).await.is_empty());
}

#[tokio::test]
async fn intent_event_operation_approval_and_audit_failure_roll_back_together() {
    let (h, node, w) = setup("pending_approval", 135).await;
    let event = intent(&h, &node, &w, "event_auto_atomic_00000001", 60).await;
    for table in [
        "node_events",
        "operations",
        "operation_approvals",
        "audit_events",
    ] {
        install_failure(&h, table).await;
        let reply = h.post_events(&node.bearer, &event).await;
        assert_eq!(reply.status, 503, "{table}: {}", reply.body);
        for name in ["node_events", "operations", "operation_approvals", "grants"] {
            assert_eq!(
                h.scalar_i64(&format!("SELECT COUNT(*) FROM {name}"), vec![])
                    .await,
                0,
                "{table} rolled back {name}"
            );
        }
        assert_eq!(
            h.scalar_i64(
                "SELECT COUNT(*) FROM audit_events WHERE action='fleet.operation_requested'",
                vec![]
            )
            .await,
            0
        );
        remove_failure(&h, table).await;
    }
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 200);
    assert_eq!(operation(&h).await["status"], "awaiting_approval");
}

#[tokio::test]
async fn intent_grant_failure_is_unacked_and_exact_replay_recovers_original_request() {
    let (h, node, w) = setup("allow", 136).await;
    let event = intent(&h, &node, &w, "event_auto_grant_retry_00000001", 60).await;
    install_failure(&h, "grants").await;
    let reply = h.post_events(&node.bearer, &event).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert!(reply.body["ack"].is_null());
    let first = operation(&h).await;
    assert_eq!(first["status"], "requested");
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM node_events", vec![])
            .await,
        1
    );
    assert!(grants(&h, &node).await.is_empty());
    remove_failure(&h, "grants").await;
    let reply = h.post_events(&node.bearer, &event).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body["duplicates"], 1);
    let op = operation(&h).await;
    assert_eq!(op["id"], first["id"]);
    assert_eq!(op["created_at"], first["created_at"]);
    assert_eq!(op["status"], "granted");
    assert_eq!(grants(&h, &node).await.len(), 1);
}

#[tokio::test]
async fn intent_request_cancel_batch_and_expired_failed_issuance_never_renew_authority() {
    let (h, node, w) = setup("allow", 137).await;
    let key = "event_auto_cancel_00000001";
    let request = intent(&h, &node, &w, key, 60).await;
    let c = OperationCancellation {
        node_id: node.id.clone(),
        workload_id: w["id"].as_str().unwrap().into(),
        invocation_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        request_event_key: key.into(),
    };
    let body: Value = serde_json::from_str(
        &String::from_utf8(
            blindpass_core::canon::canonicalize_value(&c.to_value().unwrap()).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let cancel = signed_event(
        &node.id,
        &node.keys.signing,
        &c.event_key().unwrap(),
        "operation_cancel",
        body,
    );
    let batch = json!({"events":[request["events"][0], cancel["events"][0]]});
    assert_eq!(h.post_events(&node.bearer, &batch).await.status, 200);
    assert_eq!(operation(&h).await["status"], "revoked");
    let issued = grants(&h, &node).await;
    assert_eq!(issued.len(), 1);
    assert_eq!(
        h.post_events(&node.bearer, &request).await.body["duplicates"],
        1
    );
    assert_eq!(grants(&h, &node).await, issued);
    assert_eq!(
        h.scalar_i64(
            "SELECT COUNT(*) FROM grants WHERE status <> 'revoked'",
            vec![]
        )
        .await,
        0
    );

    let (h, node, w) = setup("allow", 138).await;
    let event = intent(&h, &node, &w, "event_auto_expired_retry_00000001", 1).await;
    install_failure(&h, "grants").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 503);
    let first = operation(&h).await;
    remove_failure(&h, "grants").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let retry = h.post_events(&node.bearer, &event).await;
    assert_eq!(retry.status, 200, "{}", retry.body);
    assert_eq!(operation(&h).await["id"], first["id"]);
    assert!(grants(&h, &node).await.is_empty());
    assert!(
        h.inbox(&node.id)
            .await
            .iter()
            .any(|e| e["kind"] == "operation_closed" && e["body"]["status"] == "expired")
    );
}

#[tokio::test]
async fn intent_policy_change_after_failed_issuance_closes_original_request() {
    let (h, node, w) = setup("allow", 139).await;
    let event = intent(&h, &node, &w, "event_auto_policy_changed_00000001", 60).await;
    install_failure(&h, "grants").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 503);
    let original = operation(&h).await;
    remove_failure(&h, "grants").await;
    assert_eq!(h.set_policy(json!([{"id":"intent-rule","action":"browser.session","mode":"browser_session","decision":"deny","approval_required":false,"max_ttl_seconds":60,"approver_ids":[]}])).await.status,200);
    let replay = h.post_events(&node.bearer, &event).await;
    assert_eq!(replay.status, 200, "{}", replay.body);
    assert_eq!(replay.body["duplicates"], 1);
    let op = operation(&h).await;
    assert_eq!(op["id"], original["id"]);
    assert_eq!(op["status"], "denied");
    assert!(grants(&h, &node).await.is_empty());
    let closures = h
        .inbox(&node.id)
        .await
        .into_iter()
        .filter(|e| e["kind"] == "operation_closed" && e["body"]["status"] == "denied")
        .collect::<Vec<_>>();
    assert_eq!(closures.len(), 1);
    verify(&h, &closures[0]);
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 200);
    assert_eq!(
        h.inbox(&node.id)
            .await
            .into_iter()
            .filter(|e| e["kind"] == "operation_closed" && e["body"]["status"] == "denied")
            .count(),
        1
    );
}

#[tokio::test]
async fn intent_cancellation_after_failed_issuance_prevents_recovery_grant() {
    let (h, node, w) = setup("allow", 140).await;
    let key = "event_auto_failed_cancel_00000001";
    let event = intent(&h, &node, &w, key, 60).await;
    install_failure(&h, "grants").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 503);
    let original = operation(&h).await;
    remove_failure(&h, "grants").await;
    let c = OperationCancellation {
        node_id: node.id.clone(),
        workload_id: w["id"].as_str().unwrap().into(),
        invocation_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        request_event_key: key.into(),
    };
    let body: Value = serde_json::from_str(
        &String::from_utf8(
            blindpass_core::canon::canonicalize_value(&c.to_value().unwrap()).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        h.post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                &c.event_key().unwrap(),
                "operation_cancel",
                body
            )
        )
        .await
        .status,
        200
    );
    let replay = h.post_events(&node.bearer, &event).await;
    assert_eq!(replay.status, 200, "{}", replay.body);
    assert_eq!(replay.body["duplicates"], 1);
    assert_eq!(operation(&h).await["id"], original["id"]);
    assert_eq!(operation(&h).await["status"], "cancelled");
    assert!(grants(&h, &node).await.is_empty());
}

#[tokio::test]
async fn intent_missing_original_receipt_or_operation_cannot_reconstruct_authority() {
    let (h, node, w) = setup("allow", 141).await;
    let event = intent(&h, &node, &w, "event_auto_missing_receipt_00000001", 60).await;
    install_failure(&h, "grants").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 503);
    remove_failure(&h, "grants").await;
    assert_eq!(h.execute("DELETE FROM node_events", vec![]).await, 1);
    let retry = h.post_events(&node.bearer, &event).await;
    assert_eq!(retry.status, 503, "{}", retry.body);
    assert!(grants(&h, &node).await.is_empty());
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM node_events", vec![])
            .await,
        0
    );

    let (h, node, w) = setup("pending_approval", 142).await;
    let event = intent(&h, &node, &w, "event_auto_missing_operation_00000001", 60).await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 200);
    assert_eq!(h.execute("DELETE FROM operations", vec![]).await, 1);
    let retry = h.post_events(&node.bearer, &event).await;
    assert_eq!(retry.status, 503, "{}", retry.body);
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM operations", vec![])
            .await,
        0
    );
    assert!(grants(&h, &node).await.is_empty());
}

#[tokio::test]
async fn intent_denial_closure_failure_rolls_back_new_and_recovery_transitions() {
    let (h, node, w) = setup("deny", 143).await;
    let event = intent(&h, &node, &w, "event_auto_deny_atomic_00000001", 60).await;
    install_failure(&h, "node_inbox").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 503);
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM operations", vec![])
            .await,
        0
    );
    assert_eq!(
        h.scalar_i64("SELECT COUNT(*) FROM node_events", vec![])
            .await,
        0
    );
    assert_eq!(
        h.scalar_i64(
            "SELECT COUNT(*) FROM audit_events WHERE action='fleet.operation_requested'",
            vec![]
        )
        .await,
        0
    );
    remove_failure(&h, "node_inbox").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 200);
    assert_eq!(operation(&h).await["status"], "denied");

    let (h, node, w) = setup("allow", 144).await;
    let event = intent(&h, &node, &w, "event_auto_recovery_atomic_00000001", 60).await;
    install_failure(&h, "grants").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 503);
    remove_failure(&h, "grants").await;
    let original = operation(&h).await;
    assert_eq!(h.set_policy(json!([{"id":"intent-rule","action":"browser.session","mode":"browser_session","decision":"deny","approval_required":false,"max_ttl_seconds":60,"approver_ids":[]}])).await.status,200);
    install_failure(&h, "node_inbox").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 503);
    assert_eq!(operation(&h).await["status"], "requested");
    assert_eq!(
        h.scalar_i64(
            "SELECT COUNT(*) FROM audit_events WHERE action='fleet.operation_denied'",
            vec![]
        )
        .await,
        0
    );
    remove_failure(&h, "node_inbox").await;
    assert_eq!(h.post_events(&node.bearer, &event).await.status, 200);
    assert_eq!(operation(&h).await["id"], original["id"]);
    assert_eq!(operation(&h).await["status"], "denied");
    assert!(grants(&h, &node).await.is_empty());
    assert_eq!(
        h.scalar_i64(
            "SELECT COUNT(*) FROM audit_events WHERE action='fleet.operation_denied'",
            vec![]
        )
        .await,
        1
    );
}
