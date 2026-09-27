// SPDX-License-Identifier: AGPL-3.0-only

//! P03 lifecycle maintenance: revocation redelivery, grant expiry and
//! bounded retention (review C5, C6).

mod support;

use serde_json::{Value, json};
use support::{FleetNode, Harness, OperationSpec, signed_event};

fn allow_rules() -> Value {
    json!([{
        "id":"allow-noop-file","action":"noop.marker","mode":"file",
        "decision":"allow","approval_required":false,"max_ttl_seconds":120
    }])
}

async fn fleet(harness: &Harness, seed: u8) -> (FleetNode, Value) {
    let node = harness.online_node("lifecycle-node", seed).await;
    assert_eq!(harness.set_policy(allow_rules()).await.status, 200);
    let workload = harness
        .create_workload(
            &node.id,
            "lifecycle-worker",
            "lifecycle.service",
            "lifecycle",
            "file",
        )
        .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
    (node, workload.body)
}

async fn granted(harness: &Harness, node: &FleetNode, workload: &Value, key: &str) -> Value {
    let created = harness
        .request_operation(&harness.admin, node, workload, &OperationSpec::new(key))
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(created.body["status"], "granted", "{}", created.body);
    created.body
}

async fn unacked_revocations(harness: &Harness, node_id: &str, grant_id: &str) -> usize {
    harness
        .strings(
            "SELECT envelope_json FROM node_inbox WHERE node_id = ? AND acked_at IS NULL",
            vec![node_id.into()],
        )
        .await
        .into_iter()
        .filter_map(|envelope| serde_json::from_str::<Value>(&envelope.unwrap()).ok())
        .filter(|envelope| {
            envelope["kind"] == "revocation" && envelope["body"]["grant_id"] == grant_id
        })
        .count()
}

#[tokio::test]
async fn unacknowledged_revocations_are_redelivered_on_new_sessions() {
    let harness = Harness::start().await;
    let (node, workload) = fleet(&harness, 71).await;
    let operation = granted(&harness, &node, &workload, "requeue-operation-0001").await;
    let grant_id = operation["grant_id"].as_str().unwrap();
    let revoked = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!("/api/v3/grants/{grant_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(unacked_revocations(&harness, &node.id, grant_id).await, 1);

    // A new session while the copy is still unacknowledged adds nothing.
    let bearer = harness.open_session(&node.id, 1, &node.keys).await;
    assert_eq!(unacked_revocations(&harness, &node.id, grant_id).await, 1);

    // Deliver and acknowledge everything, as a broker that lost its state.
    let polled = harness.poll(&bearer, &json!({})).await;
    let highest = polled.body["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|document| document["seq"].as_i64().unwrap())
        .max()
        .unwrap();
    enqueue_marker(&harness, &node.id).await;
    let acked = harness.poll(&bearer, &json!({"ack_seq": highest})).await;
    assert_eq!(acked.status, 200, "{}", acked.body);
    assert_eq!(unacked_revocations(&harness, &node.id, grant_id).await, 0);

    // Without a broker outcome the signed revocation is pushed again.
    let bearer = harness.open_session(&node.id, 1, &node.keys).await;
    assert_eq!(unacked_revocations(&harness, &node.id, grant_id).await, 1);

    // Once the broker reports the outcome it is not redelivered.
    let now_ms = harness.now_ms().await;
    let applied = signed_event(
        &node.id,
        &node.keys.signing,
        &format!("grant_revocation_applied_{grant_id}"),
        "audit",
        json!({
            "action":"grant_revocation_applied","node_id":node.id,"grant_id":grant_id,
            "outcome":"revoked_before_consumption","observed_at_ms":now_ms
        }),
    );
    assert_eq!(harness.post_events(&bearer, &applied).await.status, 200);
    harness
        .execute(
            "UPDATE node_inbox SET delivered_at = ?, acked_at = ? WHERE node_id = ?",
            vec![now_ms.into(), now_ms.into(), node.id.as_str().into()],
        )
        .await;
    harness.open_session(&node.id, 1, &node.keys).await;
    assert_eq!(unacked_revocations(&harness, &node.id, grant_id).await, 0);
}

async fn enqueue_marker(harness: &Harness, node_id: &str) {
    // A fresh unrelated document keeps the next poll from long-polling.
    let workload = harness
        .create_workload(
            node_id,
            "lifecycle-marker",
            "lifecycle-marker.service",
            "marker",
            "file",
        )
        .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
}

#[tokio::test]
async fn expired_grants_converge_from_listing() {
    let harness = Harness::start().await;
    let (node, workload) = fleet(&harness, 73).await;
    let issued = granted(&harness, &node, &workload, "expiry-operation-0001").await;
    let delivered = granted(&harness, &node, &workload, "expiry-operation-0002").await;
    harness
        .execute(
            "UPDATE grants SET status = 'delivered' WHERE id = ?",
            vec![delivered["grant_id"].as_str().unwrap().into()],
        )
        .await;
    let past = harness.now_ms().await - 1;
    for operation in [&issued, &delivered] {
        harness
            .execute(
                "UPDATE grants SET expires_at = ? WHERE id = ?",
                vec![past.into(), operation["grant_id"].as_str().unwrap().into()],
            )
            .await;
    }
    let listed = harness
        .get(&harness.admin, "/api/v3/grants?status=expired")
        .await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_eq!(listed.body["items"].as_array().unwrap().len(), 2);
    let issued_operation = harness
        .get(
            &harness.admin,
            &format!("/api/v3/operations/{}", issued["id"].as_str().unwrap()),
        )
        .await;
    assert_eq!(issued_operation.body["status"], "failed");
    assert_eq!(issued_operation.body["result"]["reason"], "grant_expired");
    let delivered_operation = harness
        .get(
            &harness.admin,
            &format!("/api/v3/operations/{}", delivered["id"].as_str().unwrap()),
        )
        .await;
    assert_eq!(delivered_operation.body["status"], "uncertain");
    let summary = harness.store.expire_fleet_state().await.unwrap();
    assert_eq!(summary.expired_grants, 0, "expiry is idempotent");
}

#[tokio::test]
async fn retention_is_bounded_and_keeps_live_channel_state() {
    let harness = Harness::start().await;
    let (node, workload) = fleet(&harness, 75).await;
    let operation = granted(&harness, &node, &workload, "prune-operation-0001").await;
    let grant_id = operation["grant_id"].as_str().unwrap();
    let revoked = harness
        .call(
            &harness.admin,
            "DELETE",
            &format!("/api/v3/grants/{grant_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    harness.open_session(&node.id, 1, &node.keys).await;
    let now_ms = harness.now_ms().await;
    let old = now_ms - 8 * 24 * 60 * 60 * 1_000;
    let highest = harness
        .scalar_i64(
            "SELECT MAX(seq) FROM node_inbox WHERE node_id = ?",
            vec![node.id.as_str().into()],
        )
        .await;
    harness
        .execute(
            "UPDATE node_inbox SET delivered_at = ?, acked_at = ? WHERE node_id = ?",
            vec![old.into(), old.into(), node.id.as_str().into()],
        )
        .await;
    harness
        .execute(
            "UPDATE node_events SET received_at = ? WHERE node_id = ?",
            vec![old.into(), node.id.as_str().into()],
        )
        .await;
    harness
        .execute(
            "UPDATE node_sessions SET expires_at = ? WHERE node_id = ?",
            vec![old.into(), node.id.as_str().into()],
        )
        .await;
    harness
        .execute(
            "UPDATE grant_tombstones SET retain_until = ? WHERE grant_id = ?",
            vec![old.into(), grant_id.into()],
        )
        .await;
    let sessions_before = harness
        .scalar_i64(
            "SELECT COUNT(*) FROM node_sessions WHERE node_id = ?",
            vec![node.id.as_str().into()],
        )
        .await;
    assert!(sessions_before >= 2);

    let summary = harness.store.prune_fleet_state().await.unwrap();
    assert!(summary.acknowledged_inbox_rows > 0, "{summary:?}");
    assert!(summary.node_events > 0, "{summary:?}");
    assert_eq!(
        summary.node_sessions as i64,
        sessions_before - 1,
        "{summary:?}"
    );
    assert_eq!(summary.grant_tombstones, 1, "{summary:?}");
    // The highest inbox sequence and the newest session survive.
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT MAX(seq) FROM node_inbox WHERE node_id = ?",
                vec![node.id.as_str().into()],
            )
            .await,
        highest
    );
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM node_sessions WHERE node_id = ?",
                vec![node.id.as_str().into()],
            )
            .await,
        1
    );
    // A new document continues the sequence rather than restarting it.
    enqueue_marker(&harness, &node.id).await;
    assert!(
        harness
            .scalar_i64(
                "SELECT MAX(seq) FROM node_inbox WHERE node_id = ?",
                vec![node.id.as_str().into()],
            )
            .await
            > highest
    );
    let again = harness.store.prune_fleet_state().await.unwrap();
    assert_eq!(again.grant_tombstones + again.node_sessions, 0);
}
