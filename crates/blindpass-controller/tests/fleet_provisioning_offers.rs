// SPDX-License-Identifier: AGPL-3.0-only
//! PV06-C01–C06: real HTTP and durable storage, without an operator input page.
mod support;

use blindpass_controller::store::Store;
use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::fleet::{Grant, SignedEnvelope};
use blindpass_core::provisioning::{BrowserProvisioningBinding, sign_browser_recipient_offer};
use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};
use serde_json::{Value, json};
use support::{Bind, FleetNode, Harness, signed_event};

const SOURCE_UNIT: &str = "blindpass-login@report-primary.service";
const CREDENTIAL: &str = "report-source";

fn binding_path(node: &FleetNode) -> String {
    format!("/api/v3/nodes/{}/source-bindings/report-primary", node.id)
}

async fn set_binding(
    h: &Harness,
    node: &FleetNode,
    version: i64,
    credential: &str,
) -> support::HttpResponse {
    h.call(
        &h.admin,
        "PUT",
        &binding_path(node),
        &[],
        Some(&json!({
            "source_unit": SOURCE_UNIT, "credential": credential, "expected_version": version
        })),
    )
    .await
}

async fn setup(seed: u8) -> (Harness, FleetNode, BrowserProvisioningBinding) {
    let h = Harness::start().await;
    let node = h.online_node("provisioning-offer", seed).await;
    assert_eq!(
        h.set_policy(json!([{"id":"offer-rule","action":"browser.session",
        "mode":"browser_session","decision":"pending_approval","approval_required":true,
        "max_ttl_seconds":60,"approver_ids":[h.admin.username]}]))
            .await
            .status,
        200
    );
    let w = h
        .create_workload(
            &node.id,
            "offer-worker",
            "offer-worker.service",
            "uid:1001",
            "browser_session",
        )
        .await;
    assert_eq!(w.status, 201);
    let intent = signed_event(
        &node.id,
        &node.keys.signing,
        "event_offer_request_00000001",
        "operation_request",
        json!({
            "request_version":2,"node_id":node.id,"workload_id":w.body["id"],"unit":w.body["unit"],"account":w.body["account"],
            "action":"browser.session","mode":"browser_session","purpose":"read approved report",
            "resource_id":"report-primary","invocation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ttl_seconds":60,"observed_at_ms":h.now_ms().await
        }),
    );
    assert_eq!(h.post_events(&node.bearer, &intent).await.status, 200);
    let ops = h.get(&h.admin, "/api/v3/operations").await;
    let approval = ops.body["items"][0]["approval_id"].as_str().unwrap();
    assert_eq!(
        h.decide(&h.admin, approval, "approve", "offer-approved-00000001")
            .await
            .status,
        200
    );
    let issued = h
        .inbox(&node.id)
        .await
        .into_iter()
        .find(|e| e["kind"] == "grant")
        .unwrap();
    let grant = Grant::from_value(
        SignedEnvelope::from_json(&issued.to_string())
            .unwrap()
            .body(),
    )
    .unwrap();
    let now = u64::try_from(h.now_ms().await).unwrap();
    let binding = BrowserProvisioningBinding {
        offer_id: "pv_controller_original_00000001".into(),
        node_key_version: 1,
        source_unit: SOURCE_UNIT.into(),
        credential: CREDENTIAL.into(),
        recipient_public: base64_url_encode(RecipientKeyPair::generate().unwrap().public_key()),
        issued_at_ms: now,
        expires_at_ms: now + 30_000,
        grant,
    };
    (h, node, binding)
}

fn event(node: &FleetNode, binding: &BrowserProvisioningBinding, key: &str) -> Value {
    event_signed_by(node, binding, key, &node.keys.signing)
}
fn event_signed_by(
    node: &FleetNode,
    binding: &BrowserProvisioningBinding,
    key: &str,
    issuer: &Ed25519KeyPair,
) -> Value {
    let offer = sign_browser_recipient_offer(binding, issuer).unwrap();
    signed_event(
        &node.id,
        &node.keys.signing,
        key,
        "recipient_offer",
        serde_json::from_slice(&offer.to_json().unwrap()).unwrap(),
    )
}

fn denied(reply: support::HttpResponse, conflict: bool) {
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["accepted"], 0);
    assert_eq!(reply.body["duplicates"], 0);
    assert_eq!(reply.body["discarded"].as_array().unwrap().len(), 1);
    assert_eq!(
        reply.body["discarded"][0]["error"],
        if conflict {
            "event_idempotency_conflict"
        } else {
            "invalid_node_event"
        }
    );
}

async fn count(h: &Harness, table: &str) -> i64 {
    assert!(["fleet_provisioning_offers", "node_events", "audit_events"].contains(&table));
    let filter = match table {
        "node_events" => " WHERE kind='recipient_offer'",
        "audit_events" => " WHERE action='fleet.recipient_offer_recorded'",
        _ => "",
    };
    h.scalar_i64(&format!("SELECT COUNT(*) FROM {table}{filter}"), vec![])
        .await
}

#[tokio::test]
async fn destination_binding_requires_admin_csrf_valid_identifiers_and_current_version() {
    let h = Harness::start().await;
    let node = h.online_node("source-binding", 151).await;
    let body = json!({"source_unit":SOURCE_UNIT,"credential":CREDENTIAL,"expected_version":0});
    assert_eq!(
        h.request(
            "PUT",
            &binding_path(&node),
            &[("content-type", "application/json")],
            Some(&body)
        )
        .await
        .status,
        401
    );
    let viewer = h.create_operator("offer-viewer", "viewer").await;
    let operator = h.create_operator("offer-operator", "operator").await;
    for actor in [&viewer, &operator] {
        assert_eq!(
            h.call(actor, "PUT", &binding_path(&node), &[], Some(&body))
                .await
                .status,
            403
        );
    }
    assert_eq!(
        h.request(
            "PUT",
            &binding_path(&node),
            &[
                ("cookie", &h.admin.cookies),
                ("content-type", "application/json")
            ],
            Some(&body)
        )
        .await
        .status,
        403
    );
    for (unit, credential) in [
        ("../bad.service", CREDENTIAL),
        ("invalid.socket", CREDENTIAL),
        (SOURCE_UNIT, "../bad"),
        (SOURCE_UNIT, ""),
    ] {
        assert_eq!(
            h.call(
                &h.admin,
                "PUT",
                &binding_path(&node),
                &[],
                Some(&json!({"source_unit":unit,"credential":credential,"expected_version":0}))
            )
            .await
            .status,
            400
        );
    }
    let created = set_binding(&h, &node, 0, CREDENTIAL).await;
    assert_eq!(created.status, 200);
    assert_eq!(created.body["version"], 1);
    assert_eq!(set_binding(&h, &node, 0, "new-source").await.status, 409);
    assert_eq!(
        set_binding(&h, &node, 1, "new-source").await.body["version"],
        2
    );
    let detail = h.get(&h.admin, &binding_path(&node)).await;
    assert_eq!(detail.status, 200);
    assert_eq!(detail.body["credential"], "new-source");
    assert_eq!(detail.body["version"], 2);
    h.execute(
        "UPDATE nodes SET status='revoked' WHERE id=?",
        vec![Bind::Text(node.id.clone())],
    )
    .await;
    assert_eq!(set_binding(&h, &node, 2, CREDENTIAL).await.status, 409);
}

#[tokio::test]
async fn original_offer_and_concurrent_replays_commit_once_and_survive_store_reopen() {
    let (h, node, binding) = setup(152).await;
    assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
    let offered = event(&node, &binding, "event_offer_ingest_00000001");
    let (a, b, c) = tokio::join!(
        h.post_events(&node.bearer, &offered),
        h.post_events(&node.bearer, &offered),
        h.post_events(&node.bearer, &offered)
    );
    for result in [a, b, c] {
        assert_eq!(result.status, 200);
    }
    for table in ["fleet_provisioning_offers", "node_events", "audit_events"] {
        assert_eq!(count(&h, table).await, 1);
    }
    let stored = h
        .strings(
            "SELECT offer_json FROM fleet_provisioning_offers WHERE id=?",
            vec![Bind::Text(binding.offer_id.clone())],
        )
        .await;
    let expected = offered["events"][0]["body"].clone();
    assert_eq!(
        serde_json::from_str::<Value>(stored[0].as_ref().unwrap()).unwrap(),
        expected
    );
    assert_eq!(
        h.post_events(&node.bearer, &offered).await.body["duplicates"],
        1
    );
    let reopened = Store::connect(&h.database_url).await.unwrap();
    assert_eq!(
        reopened
            .source_binding(&node.id, "report-primary")
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        h.strings(
            "SELECT offer_json FROM fleet_provisioning_offers WHERE id=?",
            vec![Bind::Text(binding.offer_id.clone())]
        )
        .await,
        stored
    );
    let mut successor = binding.clone();
    successor.offer_id = "pv_controller_successor_00000001".into();
    successor.recipient_public =
        base64_url_encode(RecipientKeyPair::generate().unwrap().public_key());
    denied(
        h.post_events(
            &node.bearer,
            &event(&node, &successor, "event_offer_successor_000001"),
        )
        .await,
        true,
    );
    denied(
        h.post_events(
            &node.bearer,
            &event(&node, &successor, "event_offer_ingest_00000001"),
        )
        .await,
        true,
    );
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 1);
}

#[tokio::test]
async fn untrusted_inner_offer_and_missing_independent_destination_cannot_claim_authority() {
    let (h, node, binding) = setup(153).await;
    let offered = event(&node, &binding, "event_offer_invalid_00000001");
    denied(h.post_events(&node.bearer, &offered).await, false);
    assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
    let foreign = Ed25519KeyPair::from_seed(&[154; 32]).unwrap();
    denied(
        h.post_events(
            &node.bearer,
            &event_signed_by(&node, &binding, "event_offer_invalid_00000001", &foreign),
        )
        .await,
        false,
    );
    let mut variants = vec![];
    let mut altered = binding.clone();
    altered.credential = "attacker-source".into();
    variants.push(altered);
    let mut altered = binding.clone();
    altered.source_unit = "attacker.service".into();
    variants.push(altered);
    let mut altered = binding.clone();
    altered.grant.policy_version += 1;
    variants.push(altered);
    let mut altered = binding.clone();
    altered.grant.registration_version += 1;
    variants.push(altered);
    let mut altered = binding.clone();
    altered.grant.request_event_key = Some("event_foreign_request_00000001".into());
    variants.push(altered);
    let mut altered = binding.clone();
    altered.issued_at_ms += 10_000;
    altered.expires_at_ms += 10_000;
    variants.push(altered);
    let mut altered = binding.clone();
    altered.issued_at_ms = altered.grant.issued_at_ms;
    altered.expires_at_ms = altered.issued_at_ms + 1;
    variants.push(altered);
    let mut altered = binding.clone();
    altered.node_key_version = 2;
    altered.grant.recipient_key_id = format!("{}-2", node.id);
    variants.push(altered);
    for altered in variants {
        denied(
            h.post_events(
                &node.bearer,
                &event(&node, &altered, "event_offer_invalid_00000001"),
            )
            .await,
            false,
        );
    }
    for table in ["fleet_provisioning_offers", "node_events", "audit_events"] {
        assert_eq!(count(&h, table).await, 0);
    }
    assert_eq!(h.post_events(&node.bearer, &offered).await.status, 200);
}

#[tokio::test]
async fn original_grant_and_current_database_authority_are_required_before_receipt() {
    for (i, sql) in [
        "UPDATE grants SET status='consumed'",
        "UPDATE grants SET status='revoked'",
        "UPDATE grants SET expires_at=issued_at",
        "UPDATE operations SET status='cancelled'",
        "UPDATE workloads SET status='revoked'",
        "UPDATE workloads SET registration_version=registration_version+1",
        "UPDATE fleet_policies SET version=version+1",
        "UPDATE workloads SET unit='replacement.service'",
        "UPDATE controller_meta SET issuer_epoch=issuer_epoch+1",
        "DELETE FROM node_inbox WHERE envelope_json LIKE '%\"kind\":\"grant\"%'",
        "UPDATE fleet_source_bindings SET version=version+1, credential='changed-source'",
    ]
    .into_iter()
    .enumerate()
    {
        let (h, node, binding) = setup(160 + u8::try_from(i).unwrap()).await;
        assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
        h.execute(sql, vec![]).await;
        let reply = h
            .post_events(
                &node.bearer,
                &event(&node, &binding, "event_offer_stale_00000001"),
            )
            .await;
        if sql.contains("issuer_epoch") {
            assert_eq!(reply.status, 401);
        } else {
            denied(reply, false);
        }
        for table in ["fleet_provisioning_offers", "node_events", "audit_events"] {
            assert_eq!(count(&h, table).await, 0);
        }
    }
}

#[tokio::test]
async fn receipt_retry_never_reconstructs_deleted_offer_or_renews_original_expiry() {
    let (h, node, binding) = setup(168).await;
    assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
    let offered = event(&node, &binding, "event_offer_deleted_00000001");
    assert_eq!(h.post_events(&node.bearer, &offered).await.status, 200);
    h.execute("DELETE FROM fleet_provisioning_offers", vec![])
        .await;
    assert_eq!(
        h.post_events(&node.bearer, &offered).await.body["duplicates"],
        1
    );
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 0);
    // Another event cannot use the retained receipt to mint fresh authority.
    denied(
        h.post_events(
            &node.bearer,
            &event(&node, &binding, "event_offer_deleted_00000002"),
        )
        .await,
        true,
    );
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 0);
}

#[tokio::test]
async fn offer_receipt_and_audit_writes_roll_back_and_retry_together() {
    for (i, table) in ["fleet_provisioning_offers", "node_events", "audit_events"]
        .into_iter()
        .enumerate()
    {
        let (h, node, binding) = setup(170 + u8::try_from(i).unwrap()).await;
        assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
        if matches!(h.backend, support::Backend::Postgres(_)) {
            h.execute("CREATE FUNCTION p05_offer_write_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'P05 dummy storage failure'; END $$",vec![]).await;
            h.execute(&format!("CREATE TRIGGER p05_offer_write_failure BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION p05_offer_write_failure()"),vec![]).await;
        } else {
            h.execute(&format!("CREATE TRIGGER p05_offer_write_failure BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'P05 dummy storage failure'); END"),vec![]).await;
        }
        let offered = event(&node, &binding, "event_offer_rollback_00000001");
        assert_eq!(h.post_events(&node.bearer, &offered).await.status, 503);
        for table in ["fleet_provisioning_offers", "node_events", "audit_events"] {
            assert_eq!(count(&h, table).await, 0);
        }
        if matches!(h.backend, support::Backend::Postgres(_)) {
            h.execute(
                &format!("DROP TRIGGER p05_offer_write_failure ON {table}"),
                vec![],
            )
            .await;
            h.execute("DROP FUNCTION p05_offer_write_failure()", vec![])
                .await;
        } else {
            h.execute("DROP TRIGGER p05_offer_write_failure", vec![])
                .await;
        }
        assert_eq!(h.post_events(&node.bearer, &offered).await.status, 200);
        for table in ["fleet_provisioning_offers", "node_events", "audit_events"] {
            assert_eq!(count(&h, table).await, 1);
        }
    }
}

#[tokio::test]
async fn offer_and_destination_authority_are_tenant_scoped() {
    let (h, node, binding) = setup(173).await;
    assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
    h.execute(
        "UPDATE fleet_source_bindings SET tenant_id='foreign-tenant'",
        vec![],
    )
    .await;
    assert!(
        h.store
            .source_binding(&node.id, "report-primary")
            .await
            .unwrap()
            .is_none()
    );
    denied(
        h.post_events(
            &node.bearer,
            &event(&node, &binding, "event_offer_tenant_00000001"),
        )
        .await,
        false,
    );
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 0);
    assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
    h.execute("UPDATE operations SET tenant_id='foreign-tenant'", vec![])
        .await;
    denied(
        h.post_events(
            &node.bearer,
            &event(&node, &binding, "event_offer_tenant_00000002"),
        )
        .await,
        false,
    );
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 0);
}

#[tokio::test]
async fn pending_node_rotation_and_revocation_cannot_receive_new_offers() {
    let (h, node, binding) = setup(174).await;
    assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
    h.execute(
        "INSERT INTO node_revocation_queue (node_id,created_at) VALUES (?,?)",
        vec![Bind::Text(node.id.clone()), Bind::Int(h.now_ms().await)],
    )
    .await;
    denied(
        h.post_events(
            &node.bearer,
            &event(&node, &binding, "event_offer_revoking_00000001"),
        )
        .await,
        false,
    );
    assert_eq!(set_binding(&h, &node, 1, CREDENTIAL).await.status, 409);
    h.execute("DELETE FROM node_revocation_queue", vec![]).await;
    let next = support::NodeKeys::from_seed(175);
    let rotated=h.call(&h.admin,"POST",&format!("/api/v3/nodes/{}/rotate-key",node.id),&[],Some(&json!({
        "expected_key_version":1,"expected_fingerprint":next.fingerprint(),
        "signing_pub":base64_url_encode(next.signing.public_key()),"recipient_pub":base64_url_encode(next.recipient.public_key())
    }))).await;
    assert_eq!(rotated.status, 202);
    // The old session remains valid for reconciliation, but no new offer is admitted.
    let reply = h
        .post_events(
            &node.bearer,
            &event(&node, &binding, "event_offer_rotating_00000001"),
        )
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 0);
    assert_eq!(set_binding(&h, &node, 1, CREDENTIAL).await.status, 409);
}

#[tokio::test]
async fn postgres_lock_wait_cannot_extend_the_original_offer_deadline() {
    let (h, node, mut binding) = setup(176).await;
    assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
    // SQLite serializes writers before clock sampling; exercise the later
    // PostgreSQL workload lock as well. Both branches execute actual admission.
    binding.expires_at_ms = u64::try_from(h.now_ms().await).unwrap() + 250;
    let offered = event(&node, &binding, "event_offer_wait_00000001");
    match &h.backend {
        support::Backend::Postgres(pool) => {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SELECT id FROM workloads WHERE id=$1 FOR UPDATE")
                .bind(&binding.grant.workload_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            let submit = h.post_events(&node.bearer, &offered);
            let unlock = async {
                tokio::time::sleep(std::time::Duration::from_millis(450)).await;
                tx.rollback().await.unwrap();
            };
            let (reply, ()) = tokio::join!(submit, unlock);
            denied(reply, false);
        }
        support::Backend::Sqlite(pool) => {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("UPDATE workloads SET version=version WHERE id=?")
                .bind(&binding.grant.workload_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            let submit = h.post_events(&node.bearer, &offered);
            let unlock = async {
                tokio::time::sleep(std::time::Duration::from_millis(450)).await;
                tx.rollback().await.unwrap();
            };
            let (reply, ()) = tokio::join!(submit, unlock);
            denied(reply, false);
        }
    }
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 0);
    assert_eq!(count(&h, "node_events").await, 0);
}

#[tokio::test]
async fn offer_metadata_is_pruned_in_bounded_batches_without_evicting_live_offers() {
    let (h, node, binding) = setup(177).await;
    assert_eq!(set_binding(&h, &node, 0, CREDENTIAL).await.status, 200);
    assert_eq!(
        h.post_events(
            &node.bearer,
            &event(&node, &binding, "event_offer_retention_00000001")
        )
        .await
        .body["accepted"],
        1
    );
    assert_eq!(
        h.store
            .prune_fleet_state()
            .await
            .unwrap()
            .provisioning_offers,
        0
    );
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 1);
    let now = h.now_ms().await;
    let old = now - 8 * 24 * 60 * 60 * 1000;
    h.execute(
        "UPDATE fleet_provisioning_offers SET issued_at=?,expires_at=?",
        vec![Bind::Int(old - 1), Bind::Int(old)],
    )
    .await;
    assert_eq!(
        h.store
            .prune_fleet_state()
            .await
            .unwrap()
            .provisioning_offers,
        1
    );
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 0);
    assert_eq!(count(&h, "node_events").await, 1);
    assert_eq!(
        h.store
            .prune_fleet_state()
            .await
            .unwrap()
            .provisioning_offers,
        0
    );
}

#[tokio::test]
async fn schema_14_migrates_public_offer_tables_but_damaged_schema_15_fails_closed() {
    let h = Harness::start().await;
    h.execute("DROP TABLE fleet_provisioning_offers", vec![])
        .await;
    h.execute("DROP TABLE fleet_source_bindings", vec![]).await;
    // Reporting current version with missing tables is corruption, not migration.
    assert!(matches!(
        Store::connect(&h.database_url).await,
        Err(blindpass_controller::store::StoreError::UnsupportedSchemaVersion)
    ));
    h.execute(
        "UPDATE controller_meta SET schema_version=14 WHERE id=1",
        vec![],
    )
    .await;
    let reopened = Store::connect(&h.database_url).await.unwrap();
    assert!(
        reopened
            .source_binding("nd_missing", "report-primary")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(count(&h, "fleet_provisioning_offers").await, 0);
    // Version 15 preserves hashed sessions issued at the version 14 boundary.
    assert_eq!(h.get(&h.admin, "/api/v3/admin/session").await.status, 200);
}
