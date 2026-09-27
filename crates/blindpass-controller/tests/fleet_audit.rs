// SPDX-License-Identifier: AGPL-3.0-only

//! P03 operator audit trail for fleet actions (review C2).

mod support;

use serde_json::{Value, json};
use support::{Harness, OperationSpec, Operator};

async fn audit_events(harness: &Harness, operator: &Operator) -> Vec<Value> {
    let mut events = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let path = match &cursor {
            Some(cursor) => format!("/api/v3/admin/audit?limit=100&cursor={cursor}"),
            None => "/api/v3/admin/audit?limit=100".to_owned(),
        };
        let page = harness.get(operator, &path).await;
        assert_eq!(page.status, 200, "{}", page.body);
        events.extend(page.body["items"].as_array().unwrap().iter().cloned());
        match page.body["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return events,
        }
    }
}

fn find<'a>(events: &'a [Value], event: &str, resource: &str) -> &'a Value {
    events
        .iter()
        .find(|item| item["event"] == event && item["resource_id"] == resource)
        .unwrap_or_else(|| panic!("missing audit {event} for {resource}"))
}

#[tokio::test]
async fn fleet_operator_actions_are_audited_without_secrets() {
    let harness = Harness::start().await;
    let admin = harness.admin.clone();
    let requester = harness.create_operator("audit-requester", "operator").await;
    let approver = harness.create_operator("audit-approver", "operator").await;

    // Enrollment created, submitted and approved; a second one rejected.
    let created = harness
        .call(
            &admin,
            "POST",
            "/api/v3/enrollments",
            &[],
            Some(&json!({"name":"audit-node"})),
        )
        .await;
    let token = created.body["token"].as_str().unwrap().to_owned();
    let enrollment_id = created.body["id"].as_str().unwrap().to_owned();
    let keys = support::NodeKeys::from_seed(111);
    harness
        .request(
            "POST",
            "/api/v3/node/enroll",
            &[("content-type", "application/json")],
            Some(&keys.submission(&token)),
        )
        .await;
    let detail = harness
        .get(&admin, &format!("/api/v3/enrollments/{enrollment_id}"))
        .await;
    let approved = harness
        .call(
            &admin,
            "POST",
            &format!("/api/v3/enrollments/{enrollment_id}/approve"),
            &[],
            Some(&json!({"expected_fingerprint":keys.fingerprint(),"expected_version":detail.body["version"]})),
        )
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    let node_id = approved.body["id"].as_str().unwrap().to_owned();
    let rejected_keys = support::NodeKeys::from_seed(113);
    let second = harness
        .call(
            &admin,
            "POST",
            "/api/v3/enrollments",
            &[],
            Some(&json!({"name":"audit-reject"})),
        )
        .await;
    let second_id = second.body["id"].as_str().unwrap().to_owned();
    harness
        .request(
            "POST",
            "/api/v3/node/enroll",
            &[("content-type", "application/json")],
            Some(&rejected_keys.submission(second.body["token"].as_str().unwrap())),
        )
        .await;
    let second_detail = harness
        .get(&admin, &format!("/api/v3/enrollments/{second_id}"))
        .await;
    let rejected = harness
        .call(
            &admin,
            "POST",
            &format!("/api/v3/enrollments/{second_id}/reject"),
            &[],
            Some(&json!({"expected_fingerprint":rejected_keys.fingerprint(),
                "expected_version":second_detail.body["version"]})),
        )
        .await;
    assert_eq!(rejected.status, 200, "{}", rejected.body);

    // Policy, workloads, operations, approval decisions and revocations.
    let bearer = harness.open_session(&node_id, 1, &keys).await;
    harness.touch_node(&node_id).await;
    let node = support::FleetNode {
        id: node_id.clone(),
        keys,
        bearer,
    };
    let policy = harness
        .set_policy(json!([
            {"id":"allow-noop-file","action":"noop.marker","mode":"file",
             "decision":"allow","approval_required":false,"max_ttl_seconds":120},
            {"id":"approve-noop-socket","action":"noop.marker","mode":"socket",
             "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120,
             "approver_ids":["audit-approver"]}
        ]))
        .await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    let file = harness
        .create_workload(
            &node_id,
            "audit-file",
            "audit-file.service",
            "audit",
            "file",
        )
        .await
        .body;
    let socket = harness
        .create_workload(
            &node_id,
            "audit-socket",
            "audit-socket.service",
            "audit",
            "socket",
        )
        .await
        .body;
    let version = file["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let updated = harness
        .call(
            &admin,
            "PATCH",
            &format!("/api/v3/workloads/{}", file["id"].as_str().unwrap()),
            &[("if-match", if_match.as_str())],
            Some(&json!({"expected_version":version,"local_ceiling_seconds":200})),
        )
        .await;
    assert_eq!(updated.status, 200, "{}", updated.body);
    let granted = harness
        .request_operation(
            &requester,
            &node,
            &file,
            &OperationSpec::new("audit-operation-0001"),
        )
        .await
        .body;
    let awaiting = harness
        .request_operation(
            &requester,
            &node,
            &socket,
            &OperationSpec::new("audit-operation-0002"),
        )
        .await
        .body;
    let denied = harness
        .decide(
            &requester,
            awaiting["approval_id"].as_str().unwrap(),
            "approve",
            "audit-self-idem-0001",
        )
        .await;
    assert_eq!(denied.status, 403, "{}", denied.body);
    let decided = harness
        .decide(
            &approver,
            awaiting["approval_id"].as_str().unwrap(),
            "reject",
            "audit-reject-idem-0001",
        )
        .await;
    assert_eq!(decided.status, 200, "{}", decided.body);
    let dismissed = harness
        .request_operation(
            &requester,
            &node,
            &socket,
            &OperationSpec::new("audit-operation-0003"),
        )
        .await
        .body;
    let cancelled = harness
        .call(
            &requester,
            "DELETE",
            &format!("/api/v3/operations/{}", dismissed["id"].as_str().unwrap()),
            &[],
            None,
        )
        .await;
    assert_eq!(cancelled.status, 200, "{}", cancelled.body);
    let grant_id = granted["grant_id"].as_str().unwrap().to_owned();
    let revoked = harness
        .call(
            &requester,
            "DELETE",
            &format!("/api/v3/grants/{grant_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    let workload_revoked = harness
        .call(
            &admin,
            "DELETE",
            &format!("/api/v3/workloads/{}", socket["id"].as_str().unwrap()),
            &[],
            None,
        )
        .await;
    assert_eq!(workload_revoked.status, 200, "{}", workload_revoked.body);
    let rotated = harness
        .call(
            &admin,
            "POST",
            &format!("/api/v3/nodes/{node_id}/rotate-key"),
            &[],
            Some(&rotation_body(&node_id)),
        )
        .await;
    let node_revoked = harness
        .call(
            &admin,
            "DELETE",
            &format!("/api/v3/nodes/{node_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(node_revoked.status, 200, "{}", node_revoked.body);

    let events = audit_events(&harness, &admin).await;
    let expectations = [
        (
            "fleet.enrollment_created",
            enrollment_id.as_str(),
            &admin,
            "created",
        ),
        (
            "fleet.enrollment_approved",
            enrollment_id.as_str(),
            &admin,
            "approved",
        ),
        (
            "fleet.enrollment_rejected",
            second_id.as_str(),
            &admin,
            "rejected",
        ),
        (
            "fleet.workload_created",
            file["id"].as_str().unwrap(),
            &admin,
            "created",
        ),
        (
            "fleet.workload_updated",
            file["id"].as_str().unwrap(),
            &admin,
            "updated",
        ),
        (
            "fleet.workload_revoked",
            socket["id"].as_str().unwrap(),
            &admin,
            "revoked",
        ),
        (
            "fleet.operation_requested",
            granted["id"].as_str().unwrap(),
            &requester,
            "granted",
        ),
        (
            "fleet.approval_decided",
            awaiting["approval_id"].as_str().unwrap(),
            &approver,
            "rejected",
        ),
        (
            "fleet.operation_cancelled",
            dismissed["id"].as_str().unwrap(),
            &requester,
            "cancelled",
        ),
        (
            "fleet.grant_revoked",
            grant_id.as_str(),
            &requester,
            "grant_revoked",
        ),
        ("fleet.node_revoked", node_id.as_str(), &admin, "revoked"),
    ];
    for (event, resource, actor, outcome) in expectations {
        let item = find(&events, event, resource);
        assert_eq!(item["actor_id"], actor.id, "{event}");
        assert_eq!(item["metadata"]["outcome"], outcome, "{event}");
    }
    let self_denied = events
        .iter()
        .find(|item| {
            item["event"] == "fleet.approval_decided"
                && item["metadata"]["outcome"] == "approval_scope_denied"
        })
        .expect("denied decision audited");
    assert_eq!(self_denied["actor_id"], requester.id);
    assert!(
        events
            .iter()
            .any(|item| item["event"] == "fleet.policy_replaced" && item["actor_id"] == admin.id)
    );
    assert_eq!(rotated.status, 202, "{}", rotated.body);
    {
        find(&events, "fleet.node_key_rotation_staged", &node_id);
    }
    // Enrollment tokens and signed documents never enter audit metadata.
    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains(&token));
    assert!(!serialized.contains("\"sig\""));

    // Who revoked grants and nodes is recorded on the rows.
    let grant = harness
        .get(&admin, &format!("/api/v3/grants/{grant_id}"))
        .await;
    assert_eq!(grant.body["revoked_by"], requester.id);
    assert_eq!(
        harness
            .strings(
                "SELECT revoked_by FROM nodes WHERE id = ?",
                vec![node_id.as_str().into()]
            )
            .await
            .remove(0)
            .as_deref(),
        Some(admin.id.as_str())
    );
}

fn rotation_body(node_id: &str) -> Value {
    let keys = support::NodeKeys::from_seed(115);
    let _ = node_id;
    json!({
        "expected_key_version": 1,
        "expected_fingerprint": keys.fingerprint(),
        "signing_pub": blindpass_core::signing::base64_url_encode(keys.signing.public_key()),
        "recipient_pub": blindpass_core::signing::base64_url_encode(keys.recipient.public_key())
    })
}
