// SPDX-License-Identifier: AGPL-3.0-only

//! P03 fleet authority under a fenced controller clock (review C14),
//! mirroring the P02 clock fence tests in store_transitions.rs.

mod support;

use blindpass_controller::store::Store;
use blindpass_core::clock::{ClockError, ClockSample, ClockSource, SystemClock};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use support::{FleetNode, Harness, NodeKeys, OperationSpec, Operator};

struct ManualClock(Mutex<ClockSample>);

impl ClockSource for ManualClock {
    fn sample(&self) -> Result<ClockSample, ClockError> {
        Ok(self.0.lock().expect("manual clock lock").clone())
    }
}

fn rules(approver: &str) -> Value {
    json!([
        {"id":"allow-noop-file","action":"noop.marker","mode":"file",
         "decision":"allow","approval_required":false,"max_ttl_seconds":120},
        {"id":"approve-noop-socket","action":"noop.marker","mode":"socket",
         "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120,
         "approver_ids":[approver]}
    ])
}

struct FleetState {
    node: FleetNode,
    approver: Operator,
    granted: Value,
    awaiting: Value,
    enrollment_id: String,
    enrollment_keys: NodeKeys,
}

/// Pending approval, issued grant, submitted enrollment and a live session.
async fn fleet_state(harness: &Harness) -> FleetState {
    let node = harness.online_node("clock-node", 101).await;
    let approver = harness.create_operator("clock-approver", "operator").await;
    assert_eq!(
        harness.set_policy(rules(&approver.username)).await.status,
        200
    );
    let file = harness
        .create_workload(
            &node.id,
            "clock-file",
            "clock-file.service",
            "clock",
            "file",
        )
        .await
        .body;
    let socket = harness
        .create_workload(
            &node.id,
            "clock-socket",
            "clock-socket.service",
            "clock",
            "socket",
        )
        .await
        .body;
    let granted = harness
        .request_operation(
            &harness.admin,
            &node,
            &file,
            &OperationSpec::new("clock-operation-0001"),
        )
        .await
        .body;
    assert_eq!(granted["status"], "granted", "{granted}");
    let awaiting = harness
        .request_operation(
            &harness.admin,
            &node,
            &socket,
            &OperationSpec::new("clock-operation-0002"),
        )
        .await
        .body;
    assert_eq!(awaiting["status"], "awaiting_approval", "{awaiting}");
    let created = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/enrollments",
            &[],
            Some(&json!({"name":"clock-late"})),
        )
        .await;
    let enrollment_keys = NodeKeys::from_seed(103);
    let submitted = harness
        .request(
            "POST",
            "/api/v3/node/enroll",
            &[("content-type", "application/json")],
            Some(&enrollment_keys.submission(created.body["token"].as_str().unwrap())),
        )
        .await;
    assert_eq!(submitted.status, 201, "{}", submitted.body);
    FleetState {
        node,
        approver,
        granted,
        awaiting,
        enrollment_id: created.body["id"].as_str().unwrap().to_owned(),
        enrollment_keys,
    }
}

async fn status_of(harness: &Harness, table: &str, id: &str) -> String {
    harness
        .strings(
            &format!("SELECT status FROM {table} WHERE id = ?"),
            vec![id.into()],
        )
        .await
        .remove(0)
        .unwrap()
}

#[tokio::test]
async fn fenced_clock_refuses_fleet_authority_issuance() {
    let harness = Harness::start().await;
    let state = fleet_state(&harness).await;
    let workload = harness
        .get(
            &harness.admin,
            &format!(
                "/api/v3/workloads/{}",
                state.granted["workload_id"].as_str().unwrap()
            ),
        )
        .await
        .body;
    let input = harness
        .broker_request(
            &state.node,
            &workload,
            &OperationSpec::new("clock-operation-0003"),
        )
        .await;
    let approval = harness
        .get(
            &state.approver,
            &format!(
                "/api/v3/approvals/{}",
                state.awaiting["approval_id"].as_str().unwrap()
            ),
        )
        .await
        .body;
    let enrollment = harness
        .get(
            &harness.admin,
            &format!("/api/v3/enrollments/{}", state.enrollment_id),
        )
        .await
        .body;
    let now_ms = harness.now_ms().await;
    harness
        .execute(
            "UPDATE controller_clock SET fenced_at = ? WHERE id = 1",
            vec![now_ms.into()],
        )
        .await;

    let grant_issue = harness
        .call(
            &harness.admin,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "idem-clock-operation-0003")],
            Some(&input),
        )
        .await;
    // Operator routes refuse at session authentication (the fenced store
    // cannot confirm the session) or at the fenced store call.
    assert!(
        matches!(grant_issue.status, 401 | 503),
        "{}",
        grant_issue.body
    );
    let version = approval["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let decision = harness
        .call(
            &state.approver,
            "POST",
            &format!(
                "/api/v3/approvals/{}/approve",
                approval["id"].as_str().unwrap()
            ),
            &[
                ("idempotency-key", "clock-approve-idem-0001"),
                ("if-match", if_match.as_str()),
            ],
            Some(
                &json!({"expected_status":"pending","expected_version":version,
                "operation_ids":approval["operation_ids"]}),
            ),
        )
        .await;
    assert!(matches!(decision.status, 401 | 503), "{}", decision.body);
    let enrollment_approval = harness
        .call(
            &harness.admin,
            "POST",
            &format!("/api/v3/enrollments/{}/approve", state.enrollment_id),
            &[],
            Some(
                &json!({"expected_fingerprint":state.enrollment_keys.fingerprint(),
                "expected_version":enrollment["version"]}),
            ),
        )
        .await;
    assert!(
        matches!(enrollment_approval.status, 401 | 503),
        "{}",
        enrollment_approval.body
    );
    let session = harness.session_challenge(&state.node.id, 1).await;
    assert_eq!(session.status, 503, "{}", session.body);
    let poll = harness
        .poll(
            &state.node.bearer,
            &json!({"time_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        )
        .await;
    assert_eq!(poll.status, 503, "{}", poll.body);

    // Nothing was issued or decided while fenced.
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM operations WHERE broker_event_key = ?",
                vec!["clock-operation-0003".into()],
            )
            .await,
        0
    );
    assert_eq!(
        status_of(
            &harness,
            "operation_approvals",
            approval["id"].as_str().unwrap()
        )
        .await,
        "pending"
    );
    assert_eq!(
        status_of(&harness, "enrollment_requests", &state.enrollment_id).await,
        "submitted"
    );
}

#[tokio::test]
async fn restart_fence_withdraws_fleet_authority_and_redelivers_after_reconcile() {
    let harness = Harness::start().await;
    let state = fleet_state(&harness).await;
    let grant_id = state.granted["grant_id"].as_str().unwrap().to_owned();

    let mut sample = SystemClock.sample().expect("sample system clock");
    sample.boot_id = Some("simulated-next-boot".to_owned());
    let fenced = Store::connect_with_clock_source(
        &harness.database_url,
        Arc::new(ManualClock(Mutex::new(sample))),
        2_000,
    )
    .await
    .expect("boot change fences instead of trusting fleet authority");
    assert!(!fenced.is_ready().await);
    fenced.close().await;

    assert_eq!(
        status_of(
            &harness,
            "operation_approvals",
            state.awaiting["approval_id"].as_str().unwrap()
        )
        .await,
        "expired"
    );
    assert_eq!(
        status_of(
            &harness,
            "operations",
            state.awaiting["id"].as_str().unwrap()
        )
        .await,
        "denied"
    );
    assert_eq!(
        status_of(
            &harness,
            "operations",
            state.granted["id"].as_str().unwrap()
        )
        .await,
        "revoked"
    );
    assert_eq!(status_of(&harness, "grants", &grant_id).await, "revoked");
    assert_eq!(
        status_of(&harness, "enrollment_requests", &state.enrollment_id).await,
        "expired"
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM node_sessions WHERE node_id = ? AND revoked_at IS NULL",
                vec![state.node.id.as_str().into()],
            )
            .await,
        0
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM grant_tombstones WHERE grant_id = ? AND envelope_json IS NULL",
                vec![grant_id.as_str().into()],
            )
            .await,
        1
    );
    let metadata = harness
        .strings(
            "SELECT metadata_json FROM audit_events WHERE action = 'clock_restart_fence'",
            vec![],
        )
        .await
        .remove(0)
        .unwrap();
    let metadata: Value = serde_json::from_str(&metadata).unwrap();
    assert_eq!(metadata["fleet"]["revoked_grants"], 1);
    assert_eq!(metadata["fleet"]["expired_operation_approvals"], 1);

    let summary = Store::reconcile_clock(&harness.database_url)
        .await
        .expect("operator reconciliation clears the fence");
    assert!(summary.regression_detected);
    assert_eq!(
        summary.fleet.revoked_grants, 0,
        "already withdrawn by the fence"
    );

    // After reconciliation (which revokes operator sessions, as in P02),
    // maintenance signs the withdrawn grant's revocation and queues it.
    let admin = harness
        .login(
            &harness.admin.id,
            "fleet-admin",
            "fleet-admin-test-password-long",
        )
        .await;
    let listed = harness.get(&admin, "/api/v3/grants").await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    let queued = harness
        .inbox(&state.node.id)
        .await
        .into_iter()
        .any(|envelope| {
            envelope["kind"] == "revocation" && envelope["body"]["grant_id"] == grant_id.as_str()
        });
    assert!(
        queued,
        "fence-withdrawn grant revocation is delivered after reconciliation"
    );
}

#[tokio::test]
async fn reconciliation_withdraws_fleet_authority_of_a_fenced_database() {
    let harness = Harness::start().await;
    let state = fleet_state(&harness).await;
    let now_ms = harness.now_ms().await;
    harness
        .execute(
            "UPDATE controller_clock SET fenced_at = ? WHERE id = 1",
            vec![now_ms.into()],
        )
        .await;
    let summary = Store::reconcile_clock(&harness.database_url)
        .await
        .expect("reconcile fenced database");
    assert!(summary.regression_detected);
    assert_eq!(summary.fleet.expired_operation_approvals, 1);
    assert_eq!(summary.fleet.denied_operations, 1);
    assert_eq!(summary.fleet.revoked_grants, 1);
    assert_eq!(summary.fleet.expired_enrollments, 1);
    assert!(summary.fleet.revoked_node_sessions >= 1);
    assert_eq!(
        status_of(
            &harness,
            "grants",
            state.granted["grant_id"].as_str().unwrap()
        )
        .await,
        "revoked"
    );
}
