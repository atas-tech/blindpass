// SPDX-License-Identifier: AGPL-3.0-only

//! P03 node event ingestion and revocation accuracy (review C4, C10, C18).

mod support;

use serde_json::{Value, json};
use support::{FleetNode, Harness, OperationSpec, signed_event, signed_events};

fn allow_rules() -> Value {
    json!([{
        "id":"allow-noop-file","action":"noop.marker","mode":"file",
        "decision":"allow","approval_required":false,"max_ttl_seconds":120
    }])
}

async fn granted_operation(
    harness: &Harness,
    node: &FleetNode,
    workload: &Value,
    event_key: &str,
) -> Value {
    let created = harness
        .request_operation(
            &harness.admin,
            node,
            workload,
            &OperationSpec::new(event_key),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(created.body["status"], "granted", "{}", created.body);
    created.body
}

fn result_body(operation: &Value, status: &str, observed_at_ms: i64) -> Value {
    json!({
        "grant_id":operation["grant_id"],
        "operation_id":operation["id"],
        "status":status,
        "result_code": if status == "completed" { "marker_created" } else { "result_uncertain" },
        "observed_at_ms":observed_at_ms
    })
}

async fn operation(harness: &Harness, id: &Value) -> Value {
    let response = harness
        .get(
            &harness.admin,
            &format!("/api/v3/operations/{}", id.as_str().unwrap()),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    response.body
}

async fn grant(harness: &Harness, id: &Value) -> Value {
    let response = harness
        .get(
            &harness.admin,
            &format!("/api/v3/grants/{}", id.as_str().unwrap()),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    response.body
}

async fn fleet(harness: &Harness) -> (FleetNode, Value) {
    let node = harness.online_node("events-node", 51).await;
    assert_eq!(harness.set_policy(allow_rules()).await.status, 200);
    let workload = harness
        .create_workload(
            &node.id,
            "events-worker",
            "events.service",
            "events",
            "file",
        )
        .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
    (node, workload.body)
}

#[tokio::test]
async fn events_bind_to_the_authenticated_node() {
    let harness = Harness::start().await;
    let (node, workload) = fleet(&harness).await;
    let other = harness.online_node("events-other", 53).await;
    let now_ms = harness.now_ms().await;

    // An operation request claiming another node is rejected at ingestion
    // and never recorded. Its broker signature is valid, so it is
    // acknowledged as discarded rather than blocking the broker queue.
    let forged = signed_event(
        &node.id,
        &node.keys.signing,
        "forged-node-claim-0001",
        "operation_request",
        json!({
            "node_id": other.id, "workload_id": workload["id"], "unit": "events.service",
            "account": "events", "invocation_id": "invocation-1", "action": "noop.marker",
            "mode": "file", "purpose": "forged", "resource_id": "marker-a",
            "ttl_seconds": 60, "observed_at_ms": now_ms
        }),
    );
    let response = harness.post_events(&node.bearer, &forged).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        discarded_keys(&response.body),
        vec!["forged-node-claim-0001"]
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM node_events WHERE idempotency_key = ?",
                vec!["forged-node-claim-0001".into()],
            )
            .await,
        0
    );

    // A genuinely node-A-signed event replayed on node B's session fails the
    // signature binding.
    let signed_by_a = signed_event(
        &node.id,
        &node.keys.signing,
        "cross-session-0001",
        "audit",
        json!({"action":"audit_overflow","node_id":node.id,"observed_at_ms":now_ms}),
    );
    let response = harness.post_events(&other.bearer, &signed_by_a).await;
    assert_eq!(response.status, 400, "{}", response.body);

    // An operation result for another node's grant is rejected, discarded
    // and changes nothing.
    let operation = granted_operation(&harness, &node, &workload, "cross-grant-op-0001").await;
    let result = signed_event(
        &other.id,
        &other.keys.signing,
        "cross-grant-result-0001",
        "operation_result",
        result_body(&operation, "completed", now_ms),
    );
    let response = harness.post_events(&other.bearer, &result).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        discarded_keys(&response.body),
        vec!["cross-grant-result-0001"]
    );
    assert_eq!(operation_status(&harness, &operation).await, "granted");
}

fn discarded_keys(body: &Value) -> Vec<String> {
    let acknowledged = body["ack"]["body"]["event_keys"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    body["discarded"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let key = entry["idempotency_key"].as_str().unwrap().to_owned();
            assert!(
                acknowledged.iter().any(|acked| acked == &key),
                "a discarded event must be acknowledged: {body}"
            );
            key
        })
        .collect()
}

async fn operation_status(harness: &Harness, operation: &Value) -> String {
    operation_value(harness, operation).await["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn operation_value(harness: &Harness, operation: &Value) -> Value {
    self::operation(harness, &operation["id"]).await
}

#[tokio::test]
async fn event_batches_are_applied_then_recorded_and_partially_acknowledged() {
    let harness = Harness::start().await;
    let (node, _) = fleet(&harness).await;
    let now_ms = harness.now_ms().await;
    let overflow = json!({"action":"audit_overflow","node_id":node.id,"observed_at_ms":now_ms});
    let batch = signed_events(
        &node.id,
        &node.keys.signing,
        &[
            ("batch-valid-0001", "audit", overflow.clone()),
            (
                "batch-invalid-0001",
                "audit",
                json!({"action":"audit_overflow","node_id":"nd_other","observed_at_ms":now_ms}),
            ),
            ("batch-after-0001", "audit", overflow.clone()),
        ],
    );
    let response = harness.post_events(&node.bearer, &batch).await;
    assert_eq!(response.status, 200, "{}", response.body);
    // A correctly signed event that can never apply is audited, discarded
    // and acknowledged, so it cannot stall the broker queue behind it.
    assert_eq!(response.body["accepted"], 2);
    assert_eq!(
        response.body["ack"]["body"]["event_keys"],
        json!(["batch-valid-0001", "batch-invalid-0001", "batch-after-0001"])
    );
    assert_eq!(discarded_keys(&response.body), vec!["batch-invalid-0001"]);
    assert_eq!(response.body["discarded"][0]["error"], "invalid_node_event");
    assert!(response.body["rejected"].is_null(), "{}", response.body);
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'node_event_rejected'
                 AND actor_id = ? AND target_id = ?",
                vec![node.id.as_str().into(), "batch-invalid-0001".into()],
            )
            .await,
        1
    );
    for (key, expected) in [
        ("batch-valid-0001", 1),
        ("batch-invalid-0001", 0),
        ("batch-after-0001", 1),
    ] {
        assert_eq!(
            harness
                .scalar_i64(
                    "SELECT COUNT(*) FROM node_events WHERE idempotency_key = ?",
                    vec![key.into()],
                )
                .await,
            expected,
            "{key}"
        );
    }

    // An exact duplicate short-circuits and is acknowledged again.
    let duplicate = signed_event(
        &node.id,
        &node.keys.signing,
        "batch-valid-0001",
        "audit",
        overflow.clone(),
    );
    let response = harness.post_events(&node.bearer, &duplicate).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["duplicates"], 1);
    assert_eq!(
        response.body["ack"]["body"]["event_keys"],
        json!(["batch-valid-0001"])
    );

    // A signed event that can never apply is discarded again on retry.
    let invalid_first = signed_event(
        &node.id,
        &node.keys.signing,
        "batch-invalid-0002",
        "audit",
        json!({"action":"unknown_action","node_id":node.id,"observed_at_ms":now_ms}),
    );
    for _ in 0..2 {
        let response = harness.post_events(&node.bearer, &invalid_first).await;
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(discarded_keys(&response.body), vec!["batch-invalid-0002"]);
    }
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'node_event_rejected'
                 AND target_id = ?",
                vec!["batch-invalid-0002".into()],
            )
            .await,
        1
    );

    // A batch whose first event has an invalid broker signature is a plain
    // 400 with nothing recorded or acknowledged: a relay cannot use a
    // corrupted copy to make the controller acknowledge a genuine event.
    let mut forged_signature = signed_event(
        &node.id,
        &node.keys.signing,
        "batch-forged-0001",
        "audit",
        overflow.clone(),
    );
    forged_signature["events"][0]["body"]["observed_at_ms"] = json!(now_ms + 1);
    let response = harness.post_events(&node.bearer, &forged_signature).await;
    assert_eq!(response.status, 400, "{}", response.body);
    assert!(response.body.get("ack").is_none(), "{}", response.body);

    // Store failures are 503, not validation errors.
    harness
        .execute(
            "ALTER TABLE node_events RENAME TO node_events_unavailable",
            vec![],
        )
        .await;
    let unavailable = signed_event(
        &node.id,
        &node.keys.signing,
        "batch-store-0001",
        "audit",
        overflow,
    );
    let response = harness.post_events(&node.bearer, &unavailable).await;
    assert_eq!(response.status, 503, "{}", response.body);
    harness
        .execute(
            "ALTER TABLE node_events_unavailable RENAME TO node_events",
            vec![],
        )
        .await;
}

#[tokio::test]
async fn grant_and_operation_states_follow_broker_evidence() {
    let harness = Harness::start().await;
    let (node, workload) = fleet(&harness).await;
    let operation = granted_operation(&harness, &node, &workload, "state-operation-0001").await;
    assert_eq!(
        grant(&harness, &operation["grant_id"]).await["status"],
        "issued"
    );

    let polled = harness.poll(&node.bearer, &json!({})).await;
    assert_eq!(polled.status, 200, "{}", polled.body);
    assert_eq!(
        grant(&harness, &operation["grant_id"]).await["status"],
        "delivered"
    );

    let now_ms = harness.now_ms().await;
    let uncertain = signed_event(
        &node.id,
        &node.keys.signing,
        "state-result-uncertain-0001",
        "operation_result",
        result_body(&operation, "uncertain", now_ms),
    );
    let response = harness.post_events(&node.bearer, &uncertain).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let current = operation_value(&harness, &operation).await;
    assert_eq!(current["status"], "executing");
    assert_eq!(current["result"]["result_code"], "result_uncertain");
    assert_eq!(
        grant(&harness, &operation["grant_id"]).await["status"],
        "consumed"
    );

    let completed = signed_event(
        &node.id,
        &node.keys.signing,
        "state-result-completed-0001",
        "operation_result",
        result_body(&operation, "completed", now_ms + 1),
    );
    let response = harness.post_events(&node.bearer, &completed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let current = operation_value(&harness, &operation).await;
    assert_eq!(current["status"], "completed");
    assert_eq!(current["result"]["result_code"], "marker_created");
}

#[tokio::test]
async fn revocation_outcomes_distinguish_consumed_grants() {
    let harness = Harness::start().await;
    let (node, workload) = fleet(&harness).await;
    let other = harness.online_node("events-outcome-other", 55).await;

    // Revoked after the broker consumed it: the late completion is kept and
    // the operation records the typed revocation result.
    let consumed = granted_operation(&harness, &node, &workload, "outcome-operation-0001").await;
    let revoked = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!("/api/v3/grants/{}", consumed["grant_id"].as_str().unwrap()),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(revoked.body["status"], "grant_revoked");
    let revoked_grant = grant(&harness, &consumed["grant_id"]).await;
    assert_eq!(revoked_grant["revoked_by"], harness.admin.id);
    assert!(revoked_grant["broker_revocation_outcome"].is_null());

    let now_ms = harness.now_ms().await;
    let late = signed_event(
        &node.id,
        &node.keys.signing,
        "outcome-late-result-0001",
        "operation_result",
        result_body(&consumed, "completed", now_ms),
    );
    let response = harness.post_events(&node.bearer, &late).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let current = operation_value(&harness, &consumed).await;
    assert_eq!(current["status"], "revoked");
    assert_eq!(
        current["result"]["revocation_result"],
        "grant_revoked_after_consumption"
    );
    assert_eq!(current["result"]["result_code"], "marker_created");
    assert!(grant(&harness, &consumed["grant_id"]).await["consumed_at"].is_i64());

    let applied_key = format!(
        "grant_revocation_applied_{}",
        consumed["grant_id"].as_str().unwrap()
    );
    let applied = signed_event(
        &node.id,
        &node.keys.signing,
        &applied_key,
        "audit",
        json!({
            "action":"grant_revocation_applied","node_id":node.id,
            "grant_id":consumed["grant_id"],"outcome":"already_consumed","observed_at_ms":now_ms
        }),
    );
    let response = harness.post_events(&node.bearer, &applied).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        grant(&harness, &consumed["grant_id"]).await["broker_revocation_outcome"],
        "already_consumed"
    );
    let again = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!("/api/v3/grants/{}", consumed["grant_id"].as_str().unwrap()),
            &[],
            None,
        )
        .await;
    assert_eq!(again.status, 200, "{}", again.body);
    assert_eq!(again.body["status"], "grant_revoked_after_consumption");

    // Revoked before consumption, acknowledged by the broker.
    let unconsumed = granted_operation(&harness, &node, &workload, "outcome-operation-0002").await;
    let revoked = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!(
                "/api/v3/grants/{}",
                unconsumed["grant_id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    let body = json!({
        "action":"grant_revocation_applied","node_id":node.id,
        "grant_id":unconsumed["grant_id"],"outcome":"revoked_before_consumption",
        "observed_at_ms":now_ms
    });
    let key = format!(
        "grant_revocation_applied_{}",
        unconsumed["grant_id"].as_str().unwrap()
    );
    // Another node cannot report on this node's grant; its signed report is
    // discarded and changes nothing.
    let mut foreign = body.clone();
    foreign["node_id"] = json!(other.id);
    let response = harness
        .post_events(
            &other.bearer,
            &signed_event(&other.id, &other.keys.signing, &key, "audit", foreign),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(discarded_keys(&response.body), vec![key.clone()]);
    assert!(grant(&harness, &unconsumed["grant_id"]).await["broker_revocation_outcome"].is_null());
    let response = harness
        .post_events(
            &node.bearer,
            &signed_event(&node.id, &node.keys.signing, &key, "audit", body),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    let current = grant(&harness, &unconsumed["grant_id"]).await;
    assert_eq!(
        current["broker_revocation_outcome"],
        "revoked_before_consumption"
    );
    assert!(current["consumed_at"].is_null());
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'grant_revocation_applied'",
                vec![],
            )
            .await,
        2
    );

    // An acknowledgement for a grant that was never revoked is rejected.
    let active = granted_operation(&harness, &node, &workload, "outcome-operation-0003").await;
    let key = format!(
        "grant_revocation_applied_{}",
        active["grant_id"].as_str().unwrap()
    );
    let response = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                &key,
                "audit",
                json!({
                    "action":"grant_revocation_applied","node_id":node.id,
                    "grant_id":active["grant_id"],"outcome":"not_received","observed_at_ms":now_ms
                }),
            ),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(discarded_keys(&response.body), vec![key]);
    assert_eq!(
        grant(&harness, &active["grant_id"]).await["status"],
        "issued",
        "a discarded acknowledgement never revokes a grant"
    );
}

#[tokio::test]
async fn stale_broker_evidence_is_reported_as_stale_not_as_a_mismatch() {
    // A request the broker observed during a long controller outage cannot be
    // approved afterwards. The operator must see that the evidence aged out,
    // distinctly from forged or mismatched fields.
    let harness = Harness::start().await;
    let (node, workload) = fleet(&harness).await;
    let observed_at_ms = harness.now_ms().await - 61_000;
    let body = json!({
        "node_id": node.id,
        "workload_id": workload["id"],
        "unit": workload["unit"],
        "account": workload["account"],
        "invocation_id": "invocation-1",
        "action": "noop.marker",
        "mode": workload["consumption_mode"],
        "purpose": "queued during outage",
        "resource_id": "marker-a",
        "ttl_seconds": 60,
        "observed_at_ms": observed_at_ms
    });
    let events = signed_event(
        &node.id,
        &node.keys.signing,
        "stale-evidence-request-0001",
        "operation_request",
        body,
    );
    assert_eq!(harness.post_events(&node.bearer, &events).await.status, 200);
    let input = json!({
        "workload_id": workload["id"],
        "action": "noop.marker",
        "mode": workload["consumption_mode"],
        "purpose": "queued during outage",
        "resource_id": "marker-a",
        "invocation_id": "invocation-1",
        "ttl_seconds": 60,
        "broker_event_key": "stale-evidence-request-0001"
    });
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "idem-stale-evidence-request-0001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 409, "{}", created.body);
    assert_eq!(created.body["error"], "broker_evidence_stale");
}

#[tokio::test]
async fn a_retried_node_revocation_acknowledgement_still_finalizes_the_revocation() {
    let harness = Harness::start().await;
    let node = harness.online_node("finalize-node", 71).await;
    let revoked = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!("/api/v3/nodes/{}", node.id),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);

    // An earlier attempt committed its audit row, then failed before the
    // revocation was finalized. The broker retries the same signed event.
    let observed_at_ms = harness.now_ms().await;
    let event_key = "node-revocation-ack-retry-0001";
    let canonical_body = format!(
        r#"{{"action":"node_revocation_applied","node_id":"{}","observed_at_ms":{observed_at_ms}}}"#,
        node.id
    );
    harness
        .execute(
            "INSERT INTO audit_events
               (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
             VALUES (?, (SELECT tenant_id FROM nodes WHERE id = ?), 'node', ?, 'node_revocation_applied', 'node', ?, ?, ?)",
            vec![
                format!("aud_{}_{event_key}", node.id).into(),
                node.id.as_str().into(),
                node.id.as_str().into(),
                node.id.as_str().into(),
                canonical_body.into(),
                observed_at_ms.into(),
            ],
        )
        .await;
    let response = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                event_key,
                "audit",
                json!({
                    "action":"node_revocation_applied",
                    "node_id":node.id,
                    "observed_at_ms":observed_at_ms
                }),
            ),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM node_revocation_queue WHERE node_id = ?",
                vec![node.id.as_str().into()],
            )
            .await,
        0,
        "the retried acknowledgement must finalize the revocation"
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM node_sessions WHERE node_id = ? AND revoked_at IS NULL",
                vec![node.id.as_str().into()],
            )
            .await,
        0,
        "the revoked node's channel sessions must close"
    );
    let detail = harness
        .get(&harness.admin, &format!("/api/v3/nodes/{}", node.id))
        .await;
    assert_eq!(detail.body["revocation_pending"], false, "{}", detail.body);
}
