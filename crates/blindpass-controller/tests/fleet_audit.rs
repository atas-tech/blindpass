// SPDX-License-Identifier: AGPL-3.0-only

//! P03 operator audit trail for fleet actions (review C2).
//!
//! Every state-changing fleet action writes its audit row in the same
//! database transaction as the change (pilot O02: no silent loss of
//! security-relevant decisions). The rollback test forces the audit insert
//! to fail inside the store transaction with a test-only trigger on
//! `audit_events` (SQLite `RAISE(ABORT)`, or a PL/pgSQL trigger in the
//! harness's isolated PostgreSQL schema) and checks that the action answers
//! 503 and leaves its state and node inbox unchanged.

mod support;

use serde_json::{Value, json};
use support::{Backend, Harness, HttpResponse, OperationSpec, Operator};

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

/// Operator fleet actions audited in the same transaction as their change.
const FLEET_ACTIONS: [&str; 13] = [
    "fleet.enrollment_created",
    "fleet.enrollment_approved",
    "fleet.enrollment_rejected",
    "fleet.node_revoked",
    "fleet.node_key_rotation_staged",
    "fleet.workload_created",
    "fleet.workload_updated",
    "fleet.workload_revoked",
    "fleet.policy_replaced",
    "fleet.operation_requested",
    "fleet.operation_cancelled",
    "fleet.approval_decided",
    "fleet.grant_revoked",
];

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
        // Recorded in the request transaction, before the allowed
        // operation's grant is issued.
        (
            "fleet.operation_requested",
            granted["id"].as_str().unwrap(),
            &requester,
            "requested",
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
        // Exactly one row per successful action; the approval group also
        // carries the requester's denied attempt.
        let rows = events
            .iter()
            .filter(|item| item["event"] == event && item["resource_id"] == resource)
            .count();
        let expected = if event == "fleet.approval_decided" {
            2
        } else {
            1
        };
        assert_eq!(rows, expected, "{event} rows for {resource}");
    }
    let counts = FLEET_ACTIONS
        .iter()
        .map(|action| {
            let count = events
                .iter()
                .filter(|item| item["event"] == *action)
                .count();
            (*action, count)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        counts,
        vec![
            ("fleet.enrollment_created", 2),
            ("fleet.enrollment_approved", 1),
            ("fleet.enrollment_rejected", 1),
            ("fleet.node_revoked", 1),
            ("fleet.node_key_rotation_staged", 1),
            ("fleet.workload_created", 2),
            ("fleet.workload_updated", 1),
            ("fleet.workload_revoked", 1),
            ("fleet.policy_replaced", 1),
            ("fleet.operation_requested", 3),
            ("fleet.operation_cancelled", 1),
            ("fleet.approval_decided", 2),
            ("fleet.grant_revoked", 1),
        ]
    );
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

/// Create a test-only table of blocked audit actions and a trigger that
/// makes any `audit_events` insert for a blocked action fail.
async fn install_audit_block(harness: &Harness) {
    harness
        .execute(
            "CREATE TABLE test_audit_block (action TEXT PRIMARY KEY)",
            vec![],
        )
        .await;
    match harness.backend {
        Backend::Sqlite(_) => {
            harness
                .execute(
                    "CREATE TRIGGER test_audit_block_insert BEFORE INSERT ON audit_events
                     WHEN EXISTS (SELECT 1 FROM test_audit_block WHERE action = NEW.action)
                     BEGIN SELECT RAISE(ABORT, 'test audit insert blocked'); END",
                    vec![],
                )
                .await;
        }
        Backend::Postgres(_) => {
            harness
                .execute(
                    "CREATE FUNCTION test_audit_block_raise() RETURNS trigger
                     LANGUAGE plpgsql AS $$
                     BEGIN
                       IF EXISTS (SELECT 1 FROM test_audit_block WHERE action = NEW.action) THEN
                         RAISE EXCEPTION 'test audit insert blocked';
                       END IF;
                       RETURN NEW;
                     END
                     $$",
                    vec![],
                )
                .await;
            harness
                .execute(
                    "CREATE TRIGGER test_audit_block_insert BEFORE INSERT ON audit_events
                     FOR EACH ROW EXECUTE FUNCTION test_audit_block_raise()",
                    vec![],
                )
                .await;
        }
    }
}

async fn block_audit(harness: &Harness, action: &str) {
    harness
        .execute(
            "INSERT INTO test_audit_block (action) VALUES (?)",
            vec![action.into()],
        )
        .await;
}

async fn unblock_audit(harness: &Harness) {
    harness
        .execute("DELETE FROM test_audit_block", vec![])
        .await;
}

async fn count(harness: &Harness, sql: &str, binds: Vec<support::Bind>) -> i64 {
    harness.scalar_i64(sql, binds).await
}

async fn audit_rows(harness: &Harness, action: &str) -> i64 {
    count(
        harness,
        "SELECT COUNT(*) FROM audit_events WHERE action = ?",
        vec![action.into()],
    )
    .await
}

async fn column(harness: &Harness, sql: &str, id: &str) -> String {
    harness
        .strings(sql, vec![id.into()])
        .await
        .remove(0)
        .expect("column value")
}

fn assert_rolled_back(response: &HttpResponse, action: &str) {
    assert_eq!(response.status, 503, "{action}: {}", response.body);
    assert_eq!(response.body["error"], "not_ready", "{action}");
}

#[tokio::test]
async fn failed_audit_insert_fails_fleet_actions_and_commits_nothing() {
    let harness = Harness::start().await;
    install_audit_block(&harness).await;
    let admin = harness.admin.clone();
    let requester = harness
        .create_operator("rollback-requester", "operator")
        .await;
    let approver = harness
        .create_operator("rollback-approver", "operator")
        .await;

    // Enrollment creation: no enrollment row, no token handed out.
    block_audit(&harness, "fleet.enrollment_created").await;
    let enrollment = json!({"name":"rollback-node"});
    let blocked = harness
        .call(
            &admin,
            "POST",
            "/api/v3/enrollments",
            &[],
            Some(&enrollment),
        )
        .await;
    assert_rolled_back(&blocked, "enrollment_created");
    assert!(blocked.body.get("token").is_none());
    assert_eq!(
        count(&harness, "SELECT COUNT(*) FROM enrollment_requests", vec![]).await,
        0
    );
    unblock_audit(&harness).await;
    let created = harness
        .call(
            &admin,
            "POST",
            "/api/v3/enrollments",
            &[],
            Some(&enrollment),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let enrollment_id = created.body["id"].as_str().unwrap().to_owned();
    let keys = support::NodeKeys::from_seed(121);
    let submitted = harness
        .request(
            "POST",
            "/api/v3/node/enroll",
            &[("content-type", "application/json")],
            Some(&keys.submission(created.body["token"].as_str().unwrap())),
        )
        .await;
    assert!(submitted.status < 300, "{}", submitted.body);

    // Enrollment approval: the enrollment stays submitted, no node exists.
    let detail = harness
        .get(&admin, &format!("/api/v3/enrollments/{enrollment_id}"))
        .await;
    let decision = json!({"expected_fingerprint":keys.fingerprint(),
        "expected_version":detail.body["version"]});
    let approve_path = format!("/api/v3/enrollments/{enrollment_id}/approve");
    block_audit(&harness, "fleet.enrollment_approved").await;
    let blocked = harness
        .call(&admin, "POST", &approve_path, &[], Some(&decision))
        .await;
    assert_rolled_back(&blocked, "enrollment_approved");
    assert_eq!(
        column(
            &harness,
            "SELECT status FROM enrollment_requests WHERE id = ?",
            &enrollment_id
        )
        .await,
        "submitted"
    );
    assert_eq!(
        count(&harness, "SELECT COUNT(*) FROM nodes", vec![]).await,
        0
    );
    unblock_audit(&harness).await;
    let approved = harness
        .call(&admin, "POST", &approve_path, &[], Some(&decision))
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    let node_id = approved.body["id"].as_str().unwrap().to_owned();

    // Enrollment rejection: the second enrollment stays submitted.
    let second = harness
        .call(
            &admin,
            "POST",
            "/api/v3/enrollments",
            &[],
            Some(&json!({"name":"rollback-reject"})),
        )
        .await;
    let second_id = second.body["id"].as_str().unwrap().to_owned();
    let rejected_keys = support::NodeKeys::from_seed(123);
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
    block_audit(&harness, "fleet.enrollment_rejected").await;
    let blocked = harness
        .call(
            &admin,
            "POST",
            &format!("/api/v3/enrollments/{second_id}/reject"),
            &[],
            Some(&json!({"expected_fingerprint":rejected_keys.fingerprint(),
                "expected_version":second_detail.body["version"]})),
        )
        .await;
    assert_rolled_back(&blocked, "enrollment_rejected");
    assert_eq!(
        column(
            &harness,
            "SELECT status FROM enrollment_requests WHERE id = ?",
            &second_id
        )
        .await,
        "submitted"
    );
    unblock_audit(&harness).await;

    // Policy replacement: version and node inbox unchanged.
    let bearer = harness.open_session(&node_id, 1, &keys).await;
    harness.touch_node(&node_id).await;
    let node = support::FleetNode {
        id: node_id.clone(),
        keys,
        bearer,
    };
    let rules = json!([
        {"id":"allow-noop-file","action":"noop.marker","mode":"file",
         "decision":"allow","approval_required":false,"max_ttl_seconds":120},
        {"id":"approve-noop-socket","action":"noop.marker","mode":"socket",
         "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120,
         "approver_ids":["rollback-approver"]}
    ]);
    let policy_version = harness.get(&admin, "/api/v3/policies").await.body["version"].clone();
    let inbox = harness.inbox(&node_id).await.len();
    block_audit(&harness, "fleet.policy_replaced").await;
    let blocked = harness.set_policy(rules.clone()).await;
    assert_rolled_back(&blocked, "policy_replaced");
    assert_eq!(
        harness.get(&admin, "/api/v3/policies").await.body["version"],
        policy_version
    );
    assert_eq!(harness.inbox(&node_id).await.len(), inbox);
    unblock_audit(&harness).await;
    let policy = harness.set_policy(rules).await;
    assert_eq!(policy.status, 200, "{}", policy.body);

    // Workload creation: no workload row and no queued registration.
    let inbox = harness.inbox(&node_id).await.len();
    block_audit(&harness, "fleet.workload_created").await;
    let blocked = harness
        .create_workload(
            &node_id,
            "rollback-file",
            "rollback-file.service",
            "audit",
            "file",
        )
        .await;
    assert_rolled_back(&blocked, "workload_created");
    assert_eq!(
        count(&harness, "SELECT COUNT(*) FROM workloads", vec![]).await,
        0
    );
    assert_eq!(harness.inbox(&node_id).await.len(), inbox);
    unblock_audit(&harness).await;
    let file = harness
        .create_workload(
            &node_id,
            "rollback-file",
            "rollback-file.service",
            "audit",
            "file",
        )
        .await;
    assert_eq!(file.status, 201, "{}", file.body);
    let file = file.body;
    let socket = harness
        .create_workload(
            &node_id,
            "rollback-socket",
            "rollback-socket.service",
            "audit",
            "socket",
        )
        .await
        .body;

    // Workload update: registration and version unchanged.
    let file_path = format!("/api/v3/workloads/{}", file["id"].as_str().unwrap());
    let version = file["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let inbox = harness.inbox(&node_id).await.len();
    block_audit(&harness, "fleet.workload_updated").await;
    let blocked = harness
        .call(
            &admin,
            "PATCH",
            &file_path,
            &[("if-match", if_match.as_str())],
            Some(&json!({"expected_version":version,"local_ceiling_seconds":200})),
        )
        .await;
    assert_rolled_back(&blocked, "workload_updated");
    let current = harness.get(&admin, &file_path).await.body;
    assert_eq!(current["version"], version);
    assert_eq!(
        current["local_ceiling_seconds"],
        file["local_ceiling_seconds"]
    );
    assert_eq!(harness.inbox(&node_id).await.len(), inbox);
    unblock_audit(&harness).await;

    // Operation request: no operation row; the same request then succeeds.
    let input = harness
        .broker_request(&node, &file, &OperationSpec::new("rollback-operation-0001"))
        .await;
    let idempotency = [("idempotency-key", "idem-rollback-operation-0001")];
    block_audit(&harness, "fleet.operation_requested").await;
    let blocked = harness
        .call(
            &requester,
            "POST",
            "/api/v3/operations",
            &idempotency,
            Some(&input),
        )
        .await;
    assert_rolled_back(&blocked, "operation_requested");
    assert_eq!(
        count(&harness, "SELECT COUNT(*) FROM operations", vec![]).await,
        0
    );
    unblock_audit(&harness).await;
    let granted = harness
        .call(
            &requester,
            "POST",
            "/api/v3/operations",
            &idempotency,
            Some(&input),
        )
        .await;
    assert_eq!(granted.status, 201, "{}", granted.body);
    let grant_id = granted.body["grant_id"].as_str().unwrap().to_owned();

    // Approval decisions: denied attempts are durable too, so a blocked
    // audit insert answers 503 instead of 403; the approval stays pending.
    let awaiting = harness
        .request_operation(
            &requester,
            &node,
            &socket,
            &OperationSpec::new("rollback-operation-0002"),
        )
        .await
        .body;
    let approval_id = awaiting["approval_id"].as_str().unwrap().to_owned();
    block_audit(&harness, "fleet.approval_decided").await;
    let blocked_denial = harness
        .decide(
            &requester,
            &approval_id,
            "approve",
            "rollback-self-idem-0001",
        )
        .await;
    assert_rolled_back(&blocked_denial, "approval_scope_denied");
    let blocked = harness
        .decide(
            &approver,
            &approval_id,
            "approve",
            "rollback-approve-idem-0001",
        )
        .await;
    assert_rolled_back(&blocked, "approval_decided");
    assert_eq!(
        column(
            &harness,
            "SELECT status FROM operation_approvals WHERE id = ?",
            &approval_id
        )
        .await,
        "pending"
    );
    assert_eq!(
        column(
            &harness,
            "SELECT status FROM operations WHERE id = ?",
            awaiting["id"].as_str().unwrap()
        )
        .await,
        "awaiting_approval"
    );
    unblock_audit(&harness).await;
    let denied = harness
        .decide(
            &requester,
            &approval_id,
            "approve",
            "rollback-self-idem-0001",
        )
        .await;
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(audit_rows(&harness, "fleet.approval_decided").await, 1);

    // Cancelling an awaiting operation: it stays awaiting approval.
    let dismissed = harness
        .request_operation(
            &requester,
            &node,
            &socket,
            &OperationSpec::new("rollback-operation-0003"),
        )
        .await
        .body;
    let dismissed_id = dismissed["id"].as_str().unwrap().to_owned();
    block_audit(&harness, "fleet.operation_cancelled").await;
    let blocked = harness
        .call(
            &requester,
            "DELETE",
            &format!("/api/v3/operations/{dismissed_id}"),
            &[],
            None,
        )
        .await;
    assert_rolled_back(&blocked, "operation_cancelled");
    assert_eq!(
        column(
            &harness,
            "SELECT status FROM operations WHERE id = ?",
            &dismissed_id
        )
        .await,
        "awaiting_approval"
    );
    unblock_audit(&harness).await;

    // Grant revocation: the grant stays issued, with no tombstone queued.
    let grant_status = column(
        &harness,
        "SELECT status FROM grants WHERE id = ?",
        &grant_id,
    )
    .await;
    assert!(
        matches!(grant_status.as_str(), "issued" | "delivered"),
        "{grant_status}"
    );
    let inbox = harness.inbox(&node_id).await.len();
    block_audit(&harness, "fleet.grant_revoked").await;
    let blocked = harness
        .call(
            &requester,
            "DELETE",
            &format!("/api/v3/grants/{grant_id}"),
            &[],
            None,
        )
        .await;
    assert_rolled_back(&blocked, "grant_revoked");
    assert_eq!(
        column(
            &harness,
            "SELECT status FROM grants WHERE id = ?",
            &grant_id
        )
        .await,
        grant_status
    );
    assert_eq!(
        count(
            &harness,
            "SELECT COUNT(*) FROM grant_tombstones WHERE grant_id = ?",
            vec![grant_id.as_str().into()]
        )
        .await,
        0
    );
    assert_eq!(harness.inbox(&node_id).await.len(), inbox);
    unblock_audit(&harness).await;

    // Workload revocation: the workload stays active.
    let socket_id = socket["id"].as_str().unwrap().to_owned();
    block_audit(&harness, "fleet.workload_revoked").await;
    let blocked = harness
        .call(
            &admin,
            "DELETE",
            &format!("/api/v3/workloads/{socket_id}"),
            &[],
            None,
        )
        .await;
    assert_rolled_back(&blocked, "workload_revoked");
    assert_eq!(
        column(
            &harness,
            "SELECT status FROM workloads WHERE id = ?",
            &socket_id
        )
        .await,
        "active"
    );
    unblock_audit(&harness).await;

    // Key rotation: nothing staged, nothing queued.
    let node_path = format!("/api/v3/nodes/{node_id}");
    let inbox = harness.inbox(&node_id).await.len();
    block_audit(&harness, "fleet.node_key_rotation_staged").await;
    let blocked = harness
        .call(
            &admin,
            "POST",
            &format!("{node_path}/rotate-key"),
            &[],
            Some(&rotation_body(&node_id)),
        )
        .await;
    assert_rolled_back(&blocked, "node_key_rotation_staged");
    let current = harness.get(&admin, &node_path).await.body;
    assert_eq!(current["rotation_pending"], false);
    assert_eq!(current["key_version"], 1);
    assert_eq!(harness.inbox(&node_id).await.len(), inbox);
    unblock_audit(&harness).await;

    // Node revocation: the node and its grant stay active.
    block_audit(&harness, "fleet.node_revoked").await;
    let blocked = harness.call(&admin, "DELETE", &node_path, &[], None).await;
    assert_rolled_back(&blocked, "node_revoked");
    assert_eq!(
        column(&harness, "SELECT status FROM nodes WHERE id = ?", &node_id).await,
        "active"
    );
    assert_eq!(
        column(
            &harness,
            "SELECT status FROM grants WHERE id = ?",
            &grant_id
        )
        .await,
        grant_status
    );
    unblock_audit(&harness).await;
    let revoked = harness.call(&admin, "DELETE", &node_path, &[], None).await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);

    // Blocked attempts left no audit rows; each committed action left one.
    for (action, expected) in [
        ("fleet.enrollment_created", 2),
        ("fleet.enrollment_approved", 1),
        ("fleet.enrollment_rejected", 0),
        ("fleet.policy_replaced", 1),
        ("fleet.workload_created", 2),
        ("fleet.workload_updated", 0),
        ("fleet.operation_requested", 3),
        ("fleet.approval_decided", 1),
        ("fleet.operation_cancelled", 0),
        ("fleet.grant_revoked", 0),
        ("fleet.workload_revoked", 0),
        ("fleet.node_key_rotation_staged", 0),
        ("fleet.node_revoked", 1),
    ] {
        assert_eq!(audit_rows(&harness, action).await, expected, "{action}");
    }
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
