// SPDX-License-Identifier: AGPL-3.0-only

//! P03 registry integrity: workload unit uniqueness and authority
//! retirement, node re-enrollment and expired enrollments (review C8, C11,
//! C13).

mod support;

use serde_json::{Value, json};
use support::{FleetNode, Harness, NodeKeys, OperationSpec};

fn rules() -> Value {
    json!([
        {"id":"allow-noop-file","action":"noop.marker","mode":"file",
         "decision":"allow","approval_required":false,"max_ttl_seconds":120},
        {"id":"approve-noop-socket","action":"noop.marker","mode":"socket",
         "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120,
         "approver_ids":["registry-approver"]}
    ])
}

async fn setup(harness: &Harness, seed: u8) -> FleetNode {
    let node = harness.online_node("registry-node", seed).await;
    let policy = harness.set_policy(rules()).await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    node
}

async fn get(harness: &Harness, path: String) -> Value {
    let response = harness.get(&harness.admin, &path).await;
    assert_eq!(response.status, 200, "{}", response.body);
    response.body
}

async fn patch_workload(harness: &Harness, workload: &Value, change: Value) -> Value {
    let current = get(
        harness,
        format!("/api/v3/workloads/{}", workload["id"].as_str().unwrap()),
    )
    .await;
    let version = current["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let mut body = change;
    body["expected_version"] = json!(version);
    let response = harness
        .call(
            &harness.admin,
            "PATCH",
            &format!("/api/v3/workloads/{}", workload["id"].as_str().unwrap()),
            &[("if-match", if_match.as_str())],
            Some(&body),
        )
        .await;
    json!({"status": response.status, "body": response.body})
}

#[tokio::test]
async fn one_active_workload_per_node_unit() {
    let harness = Harness::start().await;
    let node = setup(&harness, 81).await;
    let first = harness
        .create_workload(&node.id, "unit-a", "shared.service", "shared", "file")
        .await;
    assert_eq!(first.status, 201, "{}", first.body);
    let duplicate = harness
        .create_workload(&node.id, "unit-b", "shared.service", "other", "socket")
        .await;
    assert_eq!(duplicate.status, 409, "{}", duplicate.body);
    assert_eq!(duplicate.body["error"], "workload_unit_conflict");
    let other = harness
        .create_workload(&node.id, "unit-c", "other.service", "other", "file")
        .await;
    assert_eq!(other.status, 201, "{}", other.body);
    let remap = patch_workload(&harness, &other.body, json!({"unit":"shared.service"})).await;
    assert_eq!(remap["status"], 409, "{remap}");
    assert_eq!(remap["body"]["error"], "workload_unit_conflict");

    let revoked = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!("/api/v3/workloads/{}", first.body["id"].as_str().unwrap()),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    let replacement = harness
        .create_workload(&node.id, "unit-d", "shared.service", "shared", "file")
        .await;
    assert_eq!(replacement.status, 201, "{}", replacement.body);
}

#[tokio::test]
async fn workload_revocation_and_remap_retire_its_authority() {
    let harness = Harness::start().await;
    let node = setup(&harness, 83).await;
    let approver = harness
        .create_operator("registry-approver", "operator")
        .await;
    let _ = approver;
    let file_workload = harness
        .create_workload(
            &node.id,
            "retire-file",
            "retire-file.service",
            "retire",
            "file",
        )
        .await
        .body;
    let socket_workload = harness
        .create_workload(
            &node.id,
            "retire-socket",
            "retire-socket.service",
            "retire",
            "socket",
        )
        .await
        .body;

    // Revocation: the granted operation's grant is revoked with a signed
    // policy revocation; the awaiting operation is cancelled and closed.
    let granted = harness
        .request_operation(
            &harness.admin,
            &node,
            &file_workload,
            &OperationSpec::new("retire-operation-0001"),
        )
        .await;
    assert_eq!(granted.body["status"], "granted", "{}", granted.body);
    let revoked = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!(
                "/api/v3/workloads/{}",
                file_workload["id"].as_str().unwrap()
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    let grant = get(
        &harness,
        format!(
            "/api/v3/grants/{}",
            granted.body["grant_id"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(grant["status"], "revoked");
    assert_eq!(grant["revoked_by"], harness.admin.id);
    let operation = get(
        &harness,
        format!(
            "/api/v3/operations/{}",
            granted.body["id"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(operation["status"], "revoked");
    assert_eq!(operation["result"]["reason"], "workload_revoked");
    let inbox = harness.inbox(&node.id).await;
    let revocation = inbox
        .iter()
        .find(|envelope| {
            envelope["kind"] == "revocation" && envelope["body"]["grant_id"] == grant["id"]
        })
        .expect("signed revocation queued");
    assert_eq!(revocation["body"]["reason"], "policy");
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM grant_tombstones WHERE grant_id = ? AND envelope_json IS NOT NULL",
                vec![grant["id"].as_str().unwrap().into()],
            )
            .await,
        1
    );

    // Remap: an account change retires authority; the pending approval
    // group for the old identity ends.
    let awaiting = harness
        .request_operation(
            &harness.admin,
            &node,
            &socket_workload,
            &OperationSpec::new("retire-operation-0002"),
        )
        .await;
    assert_eq!(
        awaiting.body["status"], "awaiting_approval",
        "{}",
        awaiting.body
    );
    let ceiling_only = patch_workload(
        &harness,
        &socket_workload,
        json!({"local_ceiling_seconds": 200}),
    )
    .await;
    assert_eq!(ceiling_only["status"], 200, "{ceiling_only}");
    let still = get(
        &harness,
        format!(
            "/api/v3/operations/{}",
            awaiting.body["id"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(still["status"], "awaiting_approval");
    let remapped =
        patch_workload(&harness, &socket_workload, json!({"account":"retire-new"})).await;
    assert_eq!(remapped["status"], 200, "{remapped}");
    let cancelled = get(
        &harness,
        format!(
            "/api/v3/operations/{}",
            awaiting.body["id"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(cancelled["status"], "cancelled");
    assert_eq!(cancelled["result"]["reason"], "workload_changed");
    let approval = get(
        &harness,
        format!(
            "/api/v3/approvals/{}",
            awaiting.body["approval_id"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(approval["status"], "expired");
    let inbox = harness.inbox(&node.id).await;
    assert!(inbox.iter().any(|envelope| {
        envelope["kind"] == "operation_closed"
            && envelope["body"]["operation_id"] == awaiting.body["id"]
            && envelope["body"]["status"] == "cancelled"
    }));
}

#[tokio::test]
async fn revoked_node_names_can_be_enrolled_again_with_new_keys() {
    let harness = Harness::start().await;
    let old_keys = NodeKeys::from_seed(85);
    let old_id = harness.enroll_node("reuse-node", &old_keys).await;

    // While active, the name stays unique.
    let active_duplicate = enroll_expecting(&harness, "reuse-node", &NodeKeys::from_seed(87)).await;
    assert_eq!(active_duplicate["status"], 409, "{active_duplicate}");

    let revoked = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!("/api/v3/nodes/{old_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);

    // The revoked node's keys cannot come back under a new enrollment.
    let reused = enroll_expecting(&harness, "reuse-node", &old_keys).await;
    assert_eq!(reused["status"], 409, "{reused}");
    assert_eq!(reused["body"]["error"], "enrollment_key_reused");

    let new_keys = NodeKeys::from_seed(89);
    let new_id = harness.enroll_node("reuse-node", &new_keys).await;
    assert_ne!(new_id, old_id);
    let new_node = get(&harness, format!("/api/v3/nodes/{new_id}")).await;
    assert_eq!(new_node["name"], "reuse-node");

    // The old signing key cannot open a session for the new node.
    let challenge = harness.session_challenge(&new_id, 1).await;
    assert_eq!(challenge.status, 200, "{}", challenge.body);
    let forged = harness
        .session_authenticate(&new_id, 1, &old_keys, &challenge.body)
        .await;
    assert_eq!(forged.status, 401, "{}", forged.body);
    harness.open_session(&new_id, 1, &new_keys).await;
}

/// Create and submit an enrollment, then try to approve it.
async fn enroll_expecting(harness: &Harness, name: &str, keys: &NodeKeys) -> Value {
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/enrollments",
            &[],
            Some(&json!({"name":name})),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let id = created.body["id"].as_str().unwrap();
    let submitted = harness
        .request(
            "POST",
            "/api/v3/node/enroll",
            &[("content-type", "application/json")],
            Some(&keys.submission(created.body["token"].as_str().unwrap())),
        )
        .await;
    assert_eq!(submitted.status, 201, "{}", submitted.body);
    let detail = get(harness, format!("/api/v3/enrollments/{id}")).await;
    let approved = harness
        .call(
            &harness.admin,
            "POST",
            &format!("/api/v3/enrollments/{id}/approve"),
            &[],
            Some(&json!({
                "expected_fingerprint":keys.fingerprint(),
                "expected_version":detail["version"]
            })),
        )
        .await;
    json!({"status": approved.status, "body": approved.body, "id": id})
}

#[tokio::test]
async fn expired_submitted_enrollments_cannot_be_approved() {
    let harness = Harness::start().await;
    let keys = NodeKeys::from_seed(91);
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/enrollments",
            &[],
            Some(&json!({"name":"late-node"})),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let id = created.body["id"].as_str().unwrap();
    let submitted = harness
        .request(
            "POST",
            "/api/v3/node/enroll",
            &[("content-type", "application/json")],
            Some(&keys.submission(created.body["token"].as_str().unwrap())),
        )
        .await;
    assert_eq!(submitted.status, 201, "{}", submitted.body);
    harness
        .execute(
            "UPDATE enrollment_requests SET expires_at = ? WHERE id = ?",
            vec![(harness.now_ms().await - 1).into(), id.into()],
        )
        .await;
    let detail = get(&harness, format!("/api/v3/enrollments/{id}")).await;
    assert_eq!(detail["status"], "expired");
    let approved = harness
        .call(
            &harness.admin,
            "POST",
            &format!("/api/v3/enrollments/{id}/approve"),
            &[],
            Some(&json!({
                "expected_fingerprint":keys.fingerprint(),
                "expected_version":detail["version"]
            })),
        )
        .await;
    assert_eq!(approved.status, 410, "{}", approved.body);
    assert_eq!(approved.body["error"], "enrollment_expired");
}
