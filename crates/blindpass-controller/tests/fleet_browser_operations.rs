// SPDX-License-Identifier: AGPL-3.0-only
//! P05-I02: real HTTP authorization and controller-signed browser grant contract.
//! This suite does not establish helper, namespace or full client execution.
mod support;

use blindpass_core::fleet::{ConsumptionMode, Grant, SignedEnvelope};
use serde_json::{Value, json};
use support::{FleetNode, Harness, OperationSpec, signed_event};

fn rules(decision: &str, approvers: &[&str], ttl: u64) -> Value {
    json!([{"id":"browser-report","action":"browser.session","mode":"browser_session",
        "decision":decision,"approval_required":decision=="pending_approval",
        "max_ttl_seconds":ttl,"approver_ids":approvers}])
}

#[tokio::test]
async fn consumed_browser_operation_keeps_website_lifetime_independent_of_grant_expiry() {
    let harness = Harness::start().await;
    let node = harness
        .online_node("browser-independent-deadline", 123)
        .await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-independent",
            "browser-independent.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let input = evidence(
        &harness,
        &node,
        &workload.body,
        "event_browser_independent_request_1",
        1,
    )
    .await;
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-independent-expiry-01")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201);
    let result = json!({"grant_id":created.body["grant_id"],"operation_id":created.body["id"],"status":"uncertain","result_code":"result_uncertain","observed_at_ms":harness.now_ms().await});
    assert_eq!(
        harness
            .post_events(
                &node.bearer,
                &signed_event(
                    &node.id,
                    &node.keys.signing,
                    "event_browser_independent_intent_1",
                    "operation_result",
                    result
                )
            )
            .await
            .body["accepted"],
        1
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    harness.store.expire_fleet_state().await.unwrap();
    let operation = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/operations/{}",
                created.body["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(operation.body["status"], "executing");
    let late = json!({"grant_id":created.body["grant_id"],"operation_id":created.body["id"],"status":"completed","result_code":"browser_session_closed","observed_at_ms":harness.now_ms().await});
    assert_eq!(
        harness
            .post_events(
                &node.bearer,
                &signed_event(
                    &node.id,
                    &node.keys.signing,
                    "event_browser_independent_closed_1",
                    "operation_result",
                    late
                )
            )
            .await
            .body["accepted"],
        1
    );
}

#[tokio::test]
async fn browser_closure_result_cannot_complete_a_native_marker_grant() {
    let harness = Harness::start().await;
    let node = harness.online_node("native-result-substitution", 124).await;
    assert_eq!(harness.set_policy(json!([{"id":"native-marker","action":"noop.marker","mode":"file","decision":"allow","approval_required":false,"max_ttl_seconds":120}])).await.status, 200);
    let workload = harness
        .create_workload(
            &node.id,
            "native-marker",
            "native-marker.service",
            "uid:1001",
            "file",
        )
        .await;
    let created = harness
        .request_operation(
            &harness.admin,
            &node,
            &workload.body,
            &OperationSpec::new("event_native_browser_close_bound_1"),
        )
        .await;
    assert_eq!(created.status, 201);
    let result = json!({"grant_id":created.body["grant_id"],"operation_id":created.body["id"],"status":"completed","result_code":"browser_session_closed","observed_at_ms":harness.now_ms().await});
    let denied = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                "event_native_browser_close_denied_1",
                "operation_result",
                result,
            ),
        )
        .await;
    assert_eq!(denied.body["accepted"], 0);
    assert_eq!(denied.body["discarded"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn browser_completion_uses_a_distinct_event_after_provisional_ack_and_is_monotonic() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-async-result", 121).await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-async",
            "browser-async.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let input = evidence(
        &harness,
        &node,
        &workload.body,
        "event_browser_async_request_0001",
        120,
    )
    .await;
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-async-result-0001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let mut body = json!({"grant_id":created.body["grant_id"], "operation_id":created.body["id"], "status":"uncertain", "result_code":"result_uncertain", "observed_at_ms":harness.now_ms().await});
    let intent = signed_event(
        &node.id,
        &node.keys.signing,
        "event_browser_async_intent_0001",
        "operation_result",
        body.clone(),
    );
    let accepted = harness.post_events(&node.bearer, &intent).await;
    assert_eq!(accepted.body["accepted"], 1);
    let path = format!(
        "/api/v3/operations/{}",
        created.body["id"].as_str().unwrap()
    );
    assert_eq!(
        harness
            .call(&harness.admin, "GET", &path, &[], None)
            .await
            .body["status"],
        "executing"
    );
    body["status"] = json!("completed");
    body["result_code"] = json!("browser_session_closed");
    let completion = signed_event(
        &node.id,
        &node.keys.signing,
        "event_browser_async_closed_0001",
        "operation_result",
        body,
    );
    for attempt in 0..2 {
        let reply = harness.post_events(&node.bearer, &completion).await;
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.body["accepted"],
            usize::from(attempt == 0),
            "{}",
            reply.body
        );
        assert_eq!(reply.body["duplicates"], usize::from(attempt == 1));
    }
    let completed = harness.call(&harness.admin, "GET", &path, &[], None).await;
    assert_eq!(completed.body["status"], "completed");
    assert_eq!(
        completed.body["result"]["result_code"],
        "browser_session_closed"
    );
    let replay = harness.post_events(&node.bearer, &intent).await;
    assert_eq!(replay.body["duplicates"], 1);
    let late_body = json!({"grant_id":created.body["grant_id"], "operation_id":created.body["id"], "status":"uncertain", "result_code":"result_uncertain", "observed_at_ms":harness.now_ms().await});
    let late = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                "event_browser_async_late_0001",
                "operation_result",
                late_body,
            ),
        )
        .await;
    assert_eq!(late.body["accepted"], 1);
    assert_eq!(
        harness
            .call(&harness.admin, "GET", &path, &[], None)
            .await
            .body["version"],
        completed.body["version"]
    );
}

#[tokio::test]
async fn native_marker_result_cannot_complete_a_browser_grant() {
    let harness = Harness::start().await;
    let node = harness
        .online_node("browser-result-substitution", 122)
        .await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-result",
            "browser-result.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let input = evidence(
        &harness,
        &node,
        &workload.body,
        "event_browser_result_request_001",
        120,
    )
    .await;
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-result-bound-0001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201);
    let body = json!({"grant_id":created.body["grant_id"], "operation_id":created.body["id"], "status":"completed", "result_code":"marker_created", "observed_at_ms":harness.now_ms().await});
    let rejected = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                "event_browser_result_substitute_001",
                "operation_result",
                body,
            ),
        )
        .await;
    assert_eq!(rejected.status, 200);
    assert_eq!(rejected.body["accepted"], 0, "{}", rejected.body);
    assert_eq!(rejected.body["discarded"].as_array().unwrap().len(), 1);
    let operation = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/operations/{}",
                created.body["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(operation.body["status"], "granted");
}
async fn evidence(
    harness: &Harness,
    node: &FleetNode,
    workload: &Value,
    key: &str,
    ttl: u64,
) -> Value {
    let input = json!({"workload_id":workload["id"],"action":"browser.session","mode":"browser_session",
        "purpose":"read the approved report","resource_id":"report-primary",
        "invocation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ttl_seconds":ttl,"broker_event_key":key});
    let event = json!({"node_id":node.id,"workload_id":workload["id"],"unit":workload["unit"],
        "account":workload["account"],"action":input["action"],"mode":input["mode"],
        "purpose":input["purpose"],"resource_id":input["resource_id"],"invocation_id":input["invocation_id"],
        "ttl_seconds":ttl,"observed_at_ms":harness.now_ms().await});
    let posted = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                key,
                "operation_request",
                event,
            ),
        )
        .await;
    assert_eq!(posted.status, 200, "{}", posted.body);
    input
}

#[tokio::test]
async fn browser_operation_approval_issues_one_signed_request_bound_grant() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-node", 111).await;
    let requester = harness
        .create_operator("browser-requester", "operator")
        .await;
    let approver = harness
        .create_operator("browser-approver", "operator")
        .await;
    let policy = harness
        .set_policy(rules(
            "pending_approval",
            &[&approver.username, &requester.username],
            120,
        ))
        .await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    let workload = harness
        .create_workload(
            &node.id,
            "browser-worker",
            "browser-agent.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
    let key = "event_browser_approval_00000001";
    let input = evidence(&harness, &node, &workload.body, key, 120).await;
    let created = harness
        .call(
            &requester,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-operation-idem-0001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(created.body["status"], "awaiting_approval");
    assert!(
        !harness
            .inbox(&node.id)
            .await
            .iter()
            .any(|envelope| envelope["kind"] == "grant")
    );
    let approval = created.body["approval_id"].as_str().unwrap();
    let denied = harness
        .decide(&requester, approval, "approve", "browser-self-denied-0001")
        .await;
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(denied.body["error"], "self_approval_denied");
    let approved = harness
        .decide(&approver, approval, "approve", "browser-approval-idem-0001")
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    let replay = harness
        .call(
            &requester,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-operation-idem-0001")],
            Some(&input),
        )
        .await;
    assert_eq!(replay.status, 200, "{}", replay.body);
    assert_eq!(replay.body["id"], created.body["id"]);
    let grants = harness
        .inbox(&node.id)
        .await
        .into_iter()
        .filter(|envelope| envelope["kind"] == "grant")
        .collect::<Vec<_>>();
    assert_eq!(grants.len(), 1);
    let signed = SignedEnvelope::from_json(&grants[0].to_string()).unwrap();
    assert!(
        signed
            .verify(harness.issuer.public_key(), &harness.issuer_key_id, 1)
            .unwrap()
    );
    let grant = Grant::from_value(signed.body()).unwrap();
    assert_eq!(grant.mode, ConsumptionMode::BrowserSession);
    assert_eq!(grant.action, "browser.session");
    assert_eq!(grant.request_event_key.as_deref(), Some(key));
    assert_eq!(grant.resource_id, "report-primary");
    assert_eq!(grant.operation_id, created.body["id"]);
    assert_eq!(grant.expires_at_ms - grant.issued_at_ms, 120_000);
}

#[tokio::test]
async fn browser_policy_rejects_mode_substitution_and_deadline_extension() {
    let harness = Harness::start().await;
    for mut rule in [rules("allow", &[], 121), rules("allow", &[], 120)] {
        if rule[0]["max_ttl_seconds"] == 120 {
            rule[0]["mode"] = json!("file");
        }
        let denied = harness.set_policy(rule).await;
        assert_eq!(denied.status, 400, "{}", denied.body);
    }
    let allowed = harness.set_policy(rules("allow", &[], 120)).await;
    assert_eq!(allowed.status, 200, "{}", allowed.body);
}

#[tokio::test]
async fn browser_operation_rejects_evidence_substitution_and_excessive_ttl() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-denials", 112).await;
    let policy = harness.set_policy(rules("allow", &[], 120)).await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    let workload = harness
        .create_workload(
            &node.id,
            "browser-worker",
            "browser-agent.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
    let input = evidence(
        &harness,
        &node,
        &workload.body,
        "event_browser_denials_00000001",
        120,
    )
    .await;
    for (index, field, next, status) in [
        (0, "resource_id", json!("report-isolation"), 409),
        (1, "mode", json!("file"), 400),
        (2, "ttl_seconds", json!(121), 400),
    ] {
        let mut changed = input.clone();
        changed[field] = next;
        let idempotency = format!("browser-denied-input-{index:04}");
        let denied = harness
            .call(
                &harness.admin,
                "POST",
                "/api/v3/operations",
                &[("idempotency-key", &idempotency)],
                Some(&changed),
            )
            .await;
        assert_eq!(denied.status, status, "{}", denied.body);
    }
    assert!(
        !harness
            .inbox(&node.id)
            .await
            .iter()
            .any(|envelope| envelope["kind"] == "grant")
    );
}

async fn cancel_evidence(
    harness: &Harness,
    node: &FleetNode,
    workload: &Value,
    request_key: &str,
) -> support::HttpResponse {
    let cancellation = blindpass_core::fleet::OperationCancellation {
        node_id: node.id.clone(),
        workload_id: workload["id"].as_str().unwrap().into(),
        invocation_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        request_event_key: request_key.into(),
    };
    let body: Value = serde_json::from_slice(
        &blindpass_core::canon::canonicalize_value(&cancellation.to_value().unwrap()).unwrap(),
    )
    .unwrap();
    harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                &cancellation.event_key().unwrap(),
                "operation_cancel",
                body,
            ),
        )
        .await
}

#[tokio::test]
async fn browser_cancellation_before_creation_prevents_late_approval() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-cancel-first", 117).await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-cancel",
            "browser-cancel.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    assert_eq!(workload.status, 201);
    let key = "event_browser_cancel_first_000001";
    let input = evidence(&harness, &node, &workload.body, key, 120).await;
    let cancelled = cancel_evidence(&harness, &node, &workload.body, key).await;
    assert_eq!(cancelled.status, 200, "{}", cancelled.body);
    assert_eq!(cancelled.body["accepted"], 1);
    assert_eq!(cancelled.body["discarded"], json!([]));
    let replay = cancel_evidence(&harness, &node, &workload.body, key).await;
    assert_eq!(replay.status, 200, "{}", replay.body);
    assert_eq!(replay.body["duplicates"], 1);
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-cancelled-create-0001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 409, "{}", created.body);
    assert!(
        !harness
            .inbox(&node.id)
            .await
            .iter()
            .any(|envelope| envelope["kind"] == "grant")
    );
}

#[tokio::test]
async fn browser_cancellation_revokes_a_grant_and_signs_one_closure() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-cancel-grant", 118).await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-cancel",
            "browser-cancel.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    assert_eq!(workload.status, 201);
    let key = "event_browser_cancel_grant_000001";
    let input = evidence(&harness, &node, &workload.body, key, 120).await;
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-cancel-granted-0001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let cancelled = cancel_evidence(&harness, &node, &workload.body, key).await;
    assert_eq!(cancelled.status, 200, "{}", cancelled.body);
    assert_eq!(cancelled.body["accepted"], 1);
    assert_eq!(cancelled.body["discarded"], json!([]));
    assert_eq!(
        cancel_evidence(&harness, &node, &workload.body, key)
            .await
            .status,
        200
    );
    let inbox = harness.inbox(&node.id).await;
    let closures = inbox
        .iter()
        .filter(|e| e["kind"] == "operation_closed" && e["body"]["request_event_key"] == key)
        .collect::<Vec<_>>();
    assert_eq!(closures.len(), 1);
    assert_eq!(closures[0]["body"]["status"], "cancelled");
    let revocations = inbox
        .iter()
        .filter(|e| e["kind"] == "revocation" && e["body"]["grant_id"] == created.body["grant_id"])
        .collect::<Vec<_>>();
    assert_eq!(revocations.len(), 1);
    for envelope in [closures[0], revocations[0]] {
        assert!(
            SignedEnvelope::from_json(&envelope.to_string())
                .unwrap()
                .verify(harness.issuer.public_key(), &harness.issuer_key_id, 1)
                .unwrap()
        );
    }
    let operation = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/operations/{}",
                created.body["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(operation.status, 200);
    assert_eq!(operation.body["status"], "revoked");
    assert!(operation.body["result"]["revocation_result"].is_null());
}

#[tokio::test]
async fn browser_cancellation_withdraws_consumed_unconfirmed_authority() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-cancel-consumed", 119).await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-consumed",
            "browser-consumed.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let key = "event_browser_cancel_consumed_001";
    let input = evidence(&harness, &node, &workload.body, key, 120).await;
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-consumed-cancel-0001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201);
    let result = json!({"grant_id":created.body["grant_id"],"operation_id":created.body["id"],
        "status":"uncertain","result_code":"result_uncertain","observed_at_ms":harness.now_ms().await});
    let consumed = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                "event_browser_consumption_000001",
                "operation_result",
                result,
            ),
        )
        .await;
    assert_eq!(consumed.status, 200);
    assert_eq!(consumed.body["accepted"], 1);
    let cancelled = cancel_evidence(&harness, &node, &workload.body, key).await;
    assert_eq!(cancelled.status, 200);
    assert_eq!(cancelled.body["accepted"], 1);
    let operation = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/operations/{}",
                created.body["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(operation.body["status"], "revoked");
    assert_eq!(
        operation.body["result"]["revocation_result"],
        "grant_revoked_after_consumption"
    );
    assert_eq!(operation.body["result"]["result_code"], "result_uncertain");
    let grant = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/grants/{}",
                created.body["grant_id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(grant.body["status"], "revoked");
    assert!(harness.inbox(&node.id).await.iter().any(|e| e["kind"] == "revocation" && e["body"]["grant_id"] == created.body["grant_id"]));

    // Confirmed cleanup can arrive after cancellation. It records cleanup
    // evidence without restoring the withdrawn operation or grant authority.
    let closed = json!({"grant_id":created.body["grant_id"],"operation_id":created.body["id"],
        "status":"completed","result_code":"browser_session_closed","observed_at_ms":harness.now_ms().await});
    let reply = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                "event_browser_closed_after_cancel_0001",
                "operation_result",
                closed,
            ),
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["accepted"], 1);
    let final_operation = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/operations/{}",
                created.body["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(final_operation.body["status"], "revoked");
    assert_eq!(
        final_operation.body["result"]["result_code"],
        "browser_session_closed"
    );
    assert_eq!(
        final_operation.body["result"]["revocation_result"],
        "grant_revoked_after_consumption"
    );
    let late_uncertain = json!({"grant_id":created.body["grant_id"],"operation_id":created.body["id"],
        "status":"uncertain","result_code":"result_uncertain","observed_at_ms":harness.now_ms().await});
    let reply = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                "event_browser_late_uncertain_after_cleanup_0001",
                "operation_result",
                late_uncertain,
            ),
        )
        .await;
    assert_eq!(reply.body["accepted"], 1);
    let unchanged = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/operations/{}",
                created.body["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(unchanged.body["status"], "revoked");
    assert_eq!(unchanged.body["result"], final_operation.body["result"]);
    assert_eq!(unchanged.body["version"], final_operation.body["version"]);
}

#[tokio::test]
async fn browser_cancellation_removes_only_its_approval_group_member() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-cancel-group", 120).await;
    let approver = harness
        .create_operator("browser-group-approver", "operator")
        .await;
    assert_eq!(
        harness
            .set_policy(rules("pending_approval", &[&approver.username], 120))
            .await
            .status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-group",
            "browser-group.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let mut members = Vec::new();
    for index in 0..2 {
        let key = format!("event_browser_group_cancel_{index:06}");
        let input = evidence(&harness, &node, &workload.body, &key, 120).await;
        let created = harness
            .call(
                &harness.admin,
                "POST",
                "/api/v3/operations",
                &[(
                    "idempotency-key",
                    &format!("browser-group-cancel-{index:06}"),
                )],
                Some(&input),
            )
            .await;
        assert_eq!(created.status, 201);
        members.push((key, created.body));
    }
    assert_eq!(members[0].1["approval_id"], members[1].1["approval_id"]);
    let cancelled = cancel_evidence(&harness, &node, &workload.body, &members[0].0).await;
    assert_eq!(cancelled.status, 200);
    assert_eq!(cancelled.body["accepted"], 1);
    let decision = harness
        .decide(
            &approver,
            members[1].1["approval_id"].as_str().unwrap(),
            "approve",
            "browser-group-decision-0001",
        )
        .await;
    assert_eq!(decision.status, 200, "{}", decision.body);
    let grants = harness
        .inbox(&node.id)
        .await
        .into_iter()
        .filter(|e| e["kind"] == "grant")
        .collect::<Vec<_>>();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["body"]["request_event_key"], members[1].0);
    let first = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/operations/{}",
                members[0].1["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(first.body["status"], "cancelled");
}

#[tokio::test]
async fn browser_cancellation_rejects_signed_owner_substitution() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-cancel-wrong-owner", 121).await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-owner",
            "browser-owner.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let key = "event_browser_wrong_cancel_00001";
    let input = evidence(&harness, &node, &workload.body, key, 120).await;
    let cancellation = blindpass_core::fleet::OperationCancellation {
        node_id: node.id.clone(),
        workload_id: workload.body["id"].as_str().unwrap().into(),
        invocation_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        request_event_key: key.into(),
    };
    let body: Value = serde_json::from_slice(
        &blindpass_core::canon::canonicalize_value(&cancellation.to_value().unwrap()).unwrap(),
    )
    .unwrap();
    let rejected = harness
        .post_events(
            &node.bearer,
            &signed_event(
                &node.id,
                &node.keys.signing,
                &cancellation.event_key().unwrap(),
                "operation_cancel",
                body,
            ),
        )
        .await;
    assert_eq!(rejected.status, 200);
    assert_eq!(rejected.body["accepted"], 0);
    assert_eq!(rejected.body["discarded"].as_array().unwrap().len(), 1);
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-wrong-cancel-create-001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    // Correct cancellation still applies after the rejected signed event.
    let cancelled = cancel_evidence(&harness, &node, &workload.body, key).await;
    assert_eq!(cancelled.status, 200);
    assert_eq!(cancelled.body["accepted"], 1);
}

#[tokio::test]
async fn browser_cancellation_races_operation_creation_without_live_authority() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-cancel-create-race", 122).await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-race",
            "browser-race.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let key = "event_browser_cancel_race_000001";
    let input = evidence(&harness, &node, &workload.body, key, 120).await;
    let (created, cancelled) = tokio::join!(
        harness.call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-cancel-race-create-0001")],
            Some(&input)
        ),
        cancel_evidence(&harness, &node, &workload.body, key)
    );
    assert!(matches!(created.status, 201 | 409), "{}", created.body);
    assert_eq!(cancelled.status, 200, "{}", cancelled.body);
    assert_eq!(cancelled.body["accepted"], 1);
    for envelope in harness
        .inbox(&node.id)
        .await
        .into_iter()
        .filter(|e| e["kind"] == "grant")
    {
        let grant = harness
            .call(
                &harness.admin,
                "GET",
                &format!(
                    "/api/v3/grants/{}",
                    envelope["body"]["id"].as_str().unwrap()
                ),
                &[],
                None,
            )
            .await;
        assert_eq!(grant.status, 200);
        assert_eq!(grant.body["status"], "revoked");
    }
}

#[tokio::test]
async fn browser_cancellation_rolls_back_every_transition_on_storage_failure() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-cancel-storage", 123).await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-storage",
            "browser-storage.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let key = "event_browser_cancel_storage_001";
    let input = evidence(&harness, &node, &workload.body, key, 120).await;
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-cancel-storage-create-001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201);
    let postgres = matches!(harness.backend, support::Backend::Postgres(_));
    if postgres {
        harness.execute("CREATE FUNCTION p05_cancel_write_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind = 'operation_cancel' THEN RAISE EXCEPTION 'P05 dummy storage failure'; END IF; RETURN NEW; END $$", vec![]).await;
        harness.execute("CREATE TRIGGER p05_cancel_write_failure BEFORE INSERT ON node_events FOR EACH ROW EXECUTE FUNCTION p05_cancel_write_failure()", vec![]).await;
    } else {
        harness.execute("CREATE TRIGGER p05_cancel_write_failure BEFORE INSERT ON node_events WHEN NEW.kind = 'operation_cancel' BEGIN SELECT RAISE(ABORT, 'P05 dummy storage failure'); END", vec![]).await;
    }
    let failed = cancel_evidence(&harness, &node, &workload.body, key).await;
    assert_eq!(failed.status, 503, "{}", failed.body);
    let operation = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/operations/{}",
                created.body["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(operation.body["status"], "granted");
    assert_eq!(
        harness
            .scalar_i64("SELECT COUNT(*) FROM grant_tombstones", vec![])
            .await,
        0
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM node_events WHERE kind = 'operation_cancel'",
                vec![]
            )
            .await,
        0
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'fleet.workload_cancelled'",
                vec![]
            )
            .await,
        0
    );
    assert!(
        !harness
            .inbox(&node.id)
            .await
            .iter()
            .any(|e| e["kind"] == "revocation" || e["kind"] == "operation_closed")
    );
    if postgres {
        harness
            .execute(
                "DROP TRIGGER p05_cancel_write_failure ON node_events",
                vec![],
            )
            .await;
        harness
            .execute("DROP FUNCTION p05_cancel_write_failure()", vec![])
            .await;
    } else {
        harness
            .execute("DROP TRIGGER p05_cancel_write_failure", vec![])
            .await;
    }
    let succeeded = cancel_evidence(&harness, &node, &workload.body, key).await;
    assert_eq!(succeeded.status, 200);
    assert_eq!(succeeded.body["accepted"], 1);
    assert_eq!(
        harness
            .scalar_i64("SELECT COUNT(*) FROM grant_tombstones", vec![])
            .await,
        1
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'fleet.workload_cancelled'",
                vec![]
            )
            .await,
        1
    );
}

#[tokio::test]
async fn browser_cancellation_after_grant_expiry_still_signs_revocation() {
    let harness = Harness::start().await;
    let node = harness.online_node("browser-cancel-expired", 124).await;
    assert_eq!(
        harness.set_policy(rules("allow", &[], 120)).await.status,
        200
    );
    let workload = harness
        .create_workload(
            &node.id,
            "browser-expired",
            "browser-expired.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    let key = "event_browser_cancel_expired_001";
    let input = evidence(&harness, &node, &workload.body, key, 1).await;
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "browser-cancel-expired-create-001")],
            Some(&input),
        )
        .await;
    assert_eq!(created.status, 201);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let cancelled = cancel_evidence(&harness, &node, &workload.body, key).await;
    assert_eq!(cancelled.status, 200);
    assert_eq!(cancelled.body["accepted"], 1);
    let grant = harness
        .call(
            &harness.admin,
            "GET",
            &format!(
                "/api/v3/grants/{}",
                created.body["grant_id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(grant.body["status"], "revoked");
    assert!(harness.inbox(&node.id).await.iter().any(|e| e["kind"] == "revocation" && e["body"]["grant_id"] == created.body["grant_id"]));
}
