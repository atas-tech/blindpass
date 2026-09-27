// SPDX-License-Identifier: AGPL-3.0-only

//! P03 fleet route authorization matrix (review C18): viewer, operator and
//! admin sessions on every /api/v3 fleet route; node and agent bearer tokens
//! are not operator credentials; caller-supplied operator ids are refused.

mod support;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use support::{Harness, OperationSpec, Operator};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Access {
    /// Any authenticated role.
    AnyRole,
    /// Administrator or operator.
    Operators,
    /// Administrator only.
    Admin,
}

fn routes() -> Vec<(&'static str, &'static str, Access, Option<Value>)> {
    vec![
        ("GET", "/api/v3/enrollments", Access::AnyRole, None),
        (
            "POST",
            "/api/v3/enrollments",
            Access::Admin,
            Some(json!({"name":"matrix-node"})),
        ),
        (
            "GET",
            "/api/v3/enrollments/enr_missing",
            Access::AnyRole,
            None,
        ),
        (
            "POST",
            "/api/v3/enrollments/enr_missing/approve",
            Access::Admin,
            Some(json!({"expected_fingerprint":"0".repeat(64),"expected_version":1})),
        ),
        (
            "POST",
            "/api/v3/enrollments/enr_missing/reject",
            Access::Admin,
            Some(json!({"expected_fingerprint":"0".repeat(64),"expected_version":1})),
        ),
        ("GET", "/api/v3/nodes", Access::AnyRole, None),
        ("GET", "/api/v3/nodes/nd_missing", Access::AnyRole, None),
        ("DELETE", "/api/v3/nodes/nd_missing", Access::Admin, None),
        (
            "POST",
            "/api/v3/nodes/nd_missing/rotate-key",
            Access::Admin,
            Some(
                json!({"expected_key_version":1,"expected_fingerprint":"0".repeat(64),
                "signing_pub":"AAAA","recipient_pub":"AAAA"}),
            ),
        ),
        ("GET", "/api/v3/workloads", Access::AnyRole, None),
        (
            "POST",
            "/api/v3/workloads",
            Access::Admin,
            Some(
                json!({"node_id":"nd_missing","name":"matrix","unit":"matrix.service",
                "account":"matrix","consumption_mode":"file","local_ceiling_seconds":60}),
            ),
        ),
        ("GET", "/api/v3/workloads/wl_missing", Access::AnyRole, None),
        (
            "PATCH",
            "/api/v3/workloads/wl_missing",
            Access::Admin,
            Some(json!({"expected_version":1,"local_ceiling_seconds":60})),
        ),
        (
            "DELETE",
            "/api/v3/workloads/wl_missing",
            Access::Admin,
            None,
        ),
        ("GET", "/api/v3/policies", Access::AnyRole, None),
        (
            "PUT",
            "/api/v3/policies",
            Access::Admin,
            Some(json!({"expected_version":999,"rules":[]})),
        ),
        ("GET", "/api/v3/operations", Access::Operators, None),
        (
            "POST",
            "/api/v3/operations",
            Access::Operators,
            Some(
                json!({"workload_id":"wl_missing","action":"noop.marker","mode":"file",
                "purpose":"matrix","resource_id":"marker","invocation_id":"invocation",
                "ttl_seconds":60,"broker_event_key":"matrix-event-key-0001"}),
            ),
        ),
        (
            "GET",
            "/api/v3/operations/op_missing",
            Access::Operators,
            None,
        ),
        (
            "DELETE",
            "/api/v3/operations/op_missing",
            Access::Operators,
            None,
        ),
        ("GET", "/api/v3/grants", Access::Operators, None),
        ("GET", "/api/v3/grants/gr_missing", Access::Operators, None),
        (
            "DELETE",
            "/api/v3/grants/gr_missing",
            Access::Operators,
            None,
        ),
        ("GET", "/api/v3/approvals", Access::Operators, None),
        ("GET", "/api/v3/approvals/count", Access::Operators, None),
        (
            "GET",
            "/api/v3/approvals/oa_missing",
            Access::Operators,
            None,
        ),
        (
            "POST",
            "/api/v3/approvals/oa_missing/approve",
            Access::Operators,
            Some(
                json!({"expected_status":"pending","expected_version":1,"operation_ids":["op_missing"]}),
            ),
        ),
        (
            "POST",
            "/api/v3/approvals/oa_missing/reject",
            Access::Operators,
            Some(
                json!({"expected_status":"pending","expected_version":1,"operation_ids":["op_missing"]}),
            ),
        ),
    ]
}

fn allowed(access: Access, role: &str) -> bool {
    match access {
        Access::AnyRole => true,
        Access::Operators => matches!(role, "admin" | "operator"),
        Access::Admin => role == "admin",
    }
}

const EXTRA: [(&str, &str); 2] = [
    ("idempotency-key", "matrix-idempotency-key-0001"),
    ("if-match", "\"1\""),
];

#[tokio::test]
async fn every_fleet_route_enforces_its_role() {
    let harness = Harness::start().await;
    let viewer = harness.create_operator("matrix-viewer", "viewer").await;
    let operator = harness.create_operator("matrix-operator", "operator").await;
    let sessions: [(&str, &Operator); 3] = [
        ("viewer", &viewer),
        ("operator", &operator),
        ("admin", &harness.admin),
    ];
    for (method, path, access, body) in routes() {
        for (role, session) in sessions {
            let response = harness
                .call(session, method, path, &EXTRA, body.as_ref())
                .await;
            if allowed(access, role) {
                assert!(
                    !matches!(response.status, 401 | 403),
                    "{role} {method} {path} must be allowed: {} {}",
                    response.status,
                    response.body
                );
            } else {
                assert_eq!(
                    response.status, 403,
                    "{role} {method} {path} must be denied: {}",
                    response.body
                );
                assert_eq!(
                    response.body["error"], "role_denied",
                    "{role} {method} {path}"
                );
            }
        }
        let anonymous = harness
            .request(
                method,
                path,
                &[
                    ("content-type", "application/json"),
                    ("origin", support::ORIGIN),
                ],
                body.as_ref(),
            )
            .await;
        assert_eq!(anonymous.status, 401, "anonymous {method} {path}");
    }
}

#[tokio::test]
async fn bearer_tokens_are_not_operator_credentials() {
    let harness = Harness::start().await;
    let node = harness.online_node("matrix-bearer-node", 121).await;
    let now = u64::try_from(harness.now_ms().await / 1_000).unwrap();
    let agent_jwt = encode(
        &Header::new(Algorithm::HS256),
        &json!({"sub":"agent-1","iss":"blindpass-controller","aud":"blindpass-agent",
            "iat":now,"exp":now + 600,"role":"admin"}),
        &EncodingKey::from_secret("A".repeat(32).as_bytes()),
    )
    .unwrap();
    let credentials = [
        node.bearer.clone(),
        format!("Bearer {agent_jwt}"),
        "Bearer ak_legacy_agent_key_0000000000000000".to_owned(),
    ];
    for (method, path, _, body) in routes() {
        for credential in &credentials {
            let response = harness
                .request(
                    method,
                    path,
                    &[
                        ("authorization", credential.as_str()),
                        ("content-type", "application/json"),
                        ("origin", support::ORIGIN),
                        ("idempotency-key", "matrix-idempotency-key-0001"),
                        ("if-match", "\"1\""),
                    ],
                    body.as_ref(),
                )
                .await;
            assert_eq!(response.status, 401, "{method} {path}: {}", response.body);
        }
    }
}

#[tokio::test]
async fn caller_supplied_operator_ids_are_refused() {
    let harness = Harness::start().await;
    let node = harness.online_node("matrix-body-node", 123).await;
    let operator = harness
        .create_operator("matrix-body-operator", "operator")
        .await;
    let policy = harness
        .set_policy(json!([
            {"id":"approve-noop-file","action":"noop.marker","mode":"file",
             "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120,
             "approver_ids":["fleet-admin"]}
        ]))
        .await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    let workload = harness
        .create_workload(
            &node.id,
            "matrix-body",
            "matrix-body.service",
            "matrix",
            "file",
        )
        .await
        .body;

    // An operation body naming a requester is refused and creates nothing.
    let mut input = harness
        .broker_request(
            &node,
            &workload,
            &OperationSpec::new("matrix-body-operation-0001"),
        )
        .await;
    input["requested_by"] = json!(harness.admin.id);
    let forged = harness
        .call(
            &operator,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "idem-matrix-body-operation-0001")],
            Some(&input),
        )
        .await;
    assert!(matches!(forged.status, 400 | 422), "{}", forged.body);
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM operations WHERE broker_event_key = ?",
                vec!["matrix-body-operation-0001".into()],
            )
            .await,
        0
    );

    // The session operator is the recorded requester.
    let created = harness
        .request_operation(
            &operator,
            &node,
            &workload,
            &OperationSpec::new("matrix-body-operation-0002"),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let requester = harness
        .strings(
            "SELECT requested_by FROM operations WHERE id = ?",
            vec![created.body["id"].as_str().unwrap().into()],
        )
        .await
        .remove(0);
    assert_eq!(requester.as_deref(), Some(operator.id.as_str()));

    // A decision body naming a decider is refused.
    let approval_id = created.body["approval_id"].as_str().unwrap();
    let detail = harness
        .get(&harness.admin, &format!("/api/v3/approvals/{approval_id}"))
        .await;
    let version = detail.body["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let forged_decision = harness
        .call(
            &harness.admin,
            "POST",
            &format!("/api/v3/approvals/{approval_id}/approve"),
            &[
                ("idempotency-key", "matrix-decision-idem-0001"),
                ("if-match", if_match.as_str()),
            ],
            Some(
                &json!({"expected_status":"pending","expected_version":version,
                "operation_ids":detail.body["operation_ids"],"decided_by":operator.id}),
            ),
        )
        .await;
    assert!(
        matches!(forged_decision.status, 400 | 422),
        "{}",
        forged_decision.body
    );
    // Workload registration cannot name its creator either.
    let forged_workload = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/workloads",
            &[],
            Some(
                &json!({"node_id":node.id,"name":"matrix-forged","unit":"matrix-forged.service",
                "account":"matrix","consumption_mode":"file","local_ceiling_seconds":60,
                "created_by":operator.id}),
            ),
        )
        .await;
    assert!(
        matches!(forged_workload.status, 400 | 422),
        "{}",
        forged_workload.body
    );
}
