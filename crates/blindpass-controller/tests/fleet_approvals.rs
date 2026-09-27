// SPDX-License-Identifier: AGPL-3.0-only

//! P03 operation approvals: named approvers, self-approval, stable-scope
//! grouping, closures, expiry and paging (review C1, C6, C7, C9, C12, C18,
//! C19).

mod support;

use blindpass_core::fleet::SignedEnvelope;
use serde_json::{Value, json};
use std::collections::HashSet;
use support::{FleetNode, Harness, OperationSpec, Operator};

fn approval_rule(approvers: &[&str]) -> Value {
    json!([{
        "id":"approve-noop-file","action":"noop.marker","mode":"file",
        "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120,
        "approver_ids":approvers
    }])
}

struct Fleet {
    harness: Harness,
    node: FleetNode,
    workload: Value,
    requester: Operator,
    approver: Operator,
}

async fn fleet_with(extra: &[(&str, &str)]) -> Fleet {
    let harness = Harness::start_with(extra).await;
    let node = harness.online_node("approval-node", 61).await;
    let requester = harness.create_operator("fleet-requester", "operator").await;
    let approver = harness.create_operator("fleet-approver", "operator").await;
    let policy = harness
        .set_policy(approval_rule(&[approver.username.as_str()]))
        .await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    let workload = harness
        .create_workload(
            &node.id,
            "approval-worker",
            "approval.service",
            "approval",
            "file",
        )
        .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
    Fleet {
        harness,
        node,
        workload: workload.body,
        requester,
        approver,
    }
}

async fn fleet() -> Fleet {
    fleet_with(&[]).await
}

impl Fleet {
    async fn request(&self, operator: &Operator, event_key: &str) -> Value {
        self.request_on(operator, &self.workload, &OperationSpec::new(event_key))
            .await
    }

    async fn request_on(
        &self,
        operator: &Operator,
        workload: &Value,
        spec: &OperationSpec<'_>,
    ) -> Value {
        let created = self
            .harness
            .request_operation(operator, &self.node, workload, spec)
            .await;
        assert_eq!(created.status, 201, "{}", created.body);
        created.body
    }

    async fn approval(&self, id: &Value) -> Value {
        let response = self
            .harness
            .get(
                &self.approver,
                &format!("/api/v3/approvals/{}", id.as_str().unwrap()),
            )
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
        response.body
    }

    async fn operation(&self, id: &Value) -> Value {
        let response = self
            .harness
            .get(
                &self.approver,
                &format!("/api/v3/operations/{}", id.as_str().unwrap()),
            )
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
        response.body
    }

    /// Signed OperationClosed documents queued for the node, by operation.
    async fn closure(&self, operation_id: &Value) -> Option<Value> {
        let issuer_public = self.harness.issuer.public_key().to_vec();
        self.harness
            .inbox(&self.node.id)
            .await
            .into_iter()
            .filter(|envelope| envelope["kind"] == "operation_closed")
            .find(|envelope| envelope["body"]["operation_id"] == *operation_id)
            .inspect(|envelope| {
                let parsed = SignedEnvelope::from_json(&envelope.to_string()).unwrap();
                assert!(
                    parsed
                        .verify(&issuer_public, &self.harness.issuer_key_id, 1)
                        .unwrap()
                );
            })
            .map(|envelope| envelope["body"].clone())
    }

    async fn pending_count(&self) -> i64 {
        let response = self
            .harness
            .get(&self.approver, "/api/v3/approvals/count")
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
        response.body["count"].as_i64().unwrap()
    }
}

#[tokio::test]
async fn pending_approval_rules_must_name_approvers() {
    let harness = Harness::start().await;
    let missing = harness
        .set_policy(json!([{
            "id":"approve-noop-file","action":"noop.marker","mode":"file",
            "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120
        }]))
        .await;
    assert_eq!(missing.status, 400, "{}", missing.body);
    let empty = harness.set_policy(approval_rule(&[])).await;
    assert_eq!(empty.status, 400, "{}", empty.body);
    let allow_with_approvers = harness
        .set_policy(json!([{
            "id":"allow-noop-file","action":"noop.marker","mode":"file",
            "decision":"allow","approval_required":false,"max_ttl_seconds":120,
            "approver_ids":["fleet-approver"]
        }]))
        .await;
    assert_eq!(
        allow_with_approvers.status, 400,
        "{}",
        allow_with_approvers.body
    );
    let duplicate = harness
        .set_policy(approval_rule(&["a-user", "a-user"]))
        .await;
    assert_eq!(duplicate.status, 400, "{}", duplicate.body);
    let valid = harness
        .set_policy(approval_rule(&["fleet-approver", "op_example-id"]))
        .await;
    assert_eq!(valid.status, 200, "{}", valid.body);
    assert_eq!(
        valid.body["rules"][0]["approver_ids"],
        json!(["fleet-approver", "op_example-id"])
    );
}

#[tokio::test]
async fn only_named_non_requesting_operators_decide() {
    let fleet = fleet().await;
    let harness = &fleet.harness;
    let bystander = harness.create_operator("fleet-bystander", "operator").await;
    // Name the requester by id too, so self-approval is what denies it.
    let policy = harness
        .set_policy(approval_rule(&[
            fleet.approver.username.as_str(),
            fleet.requester.id.as_str(),
        ]))
        .await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    let operation = fleet
        .request(&fleet.requester, "scope-operation-0001")
        .await;
    assert_eq!(operation["status"], "awaiting_approval");
    let approval_id = operation["approval_id"].as_str().unwrap().to_owned();
    let approval = fleet.approval(&operation["approval_id"]).await;
    assert_eq!(
        approval["approver_ids"],
        json!([fleet.approver.username, fleet.requester.id])
    );

    for (operator, error) in [
        (&bystander, "approval_scope_denied"),
        (&harness.admin, "approval_scope_denied"),
        (&fleet.requester, "self_approval_denied"),
    ] {
        let denied = harness
            .decide(operator, &approval_id, "approve", "scope-denied-idem-0001")
            .await;
        assert_eq!(denied.status, 403, "{}", denied.body);
        assert_eq!(denied.body["error"], error);
    }
    assert_eq!(
        fleet.approval(&operation["approval_id"]).await["status"],
        "pending"
    );

    // The named approver decides; the same request replays idempotently.
    let version = approval["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let body = json!({
        "expected_status":"pending","expected_version":version,
        "operation_ids":approval["operation_ids"]
    });
    let path = format!("/api/v3/approvals/{approval_id}/approve");
    let headers = [
        ("idempotency-key", "scope-approve-idem-0001"),
        ("if-match", if_match.as_str()),
    ];
    let approved = harness
        .call(&fleet.approver, "POST", &path, &headers, Some(&body))
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    assert_eq!(approved.body["status"], "approved");
    assert_eq!(approved.body["decided_by"], fleet.approver.id);
    let replay = harness
        .call(&fleet.approver, "POST", &path, &headers, Some(&body))
        .await;
    assert_eq!(replay.status, 200, "{}", replay.body);
    assert_eq!(replay.body["version"], approved.body["version"]);
    let other_key = harness
        .call(
            &fleet.approver,
            "POST",
            &path,
            &[
                ("idempotency-key", "scope-approve-idem-0002"),
                ("if-match", if_match.as_str()),
            ],
            Some(&body),
        )
        .await;
    assert_eq!(other_key.status, 409, "{}", other_key.body);
    assert_eq!(fleet.operation(&operation["id"]).await["status"], "granted");
}

#[tokio::test]
async fn approvals_group_by_stable_scope_and_show_each_member() {
    let fleet = fleet().await;
    let harness = &fleet.harness;
    let second_requester = harness
        .create_operator("fleet-requester-two", "operator")
        .await;
    let first = fleet
        .request_on(
            &fleet.requester,
            &fleet.workload,
            &OperationSpec {
                event_key: "group-operation-0001",
                invocation_id: "invocation-a",
                resource_id: "marker-a",
                purpose: "first purpose",
            },
        )
        .await;
    let before_join = fleet.approval(&first["approval_id"]).await;
    let second = fleet
        .request_on(
            &second_requester,
            &fleet.workload,
            &OperationSpec {
                event_key: "group-operation-0002",
                invocation_id: "invocation-b",
                resource_id: "marker-b",
                purpose: "second purpose",
            },
        )
        .await;
    assert_eq!(first["approval_id"], second["approval_id"]);
    let group = fleet.approval(&first["approval_id"]).await;
    assert_eq!(group["operation_ids"], json!([first["id"], second["id"]]));
    let members = group["operations"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0]["requested_by"], fleet.requester.id);
    assert_eq!(members[0]["invocation_id"], "invocation-a");
    assert_eq!(members[1]["requested_by"], second_requester.id);
    assert_eq!(members[1]["invocation_id"], "invocation-b");
    assert_eq!(members[1]["broker_event_key"], "group-operation-0002");
    assert!(group["verified_identity"].get("invocation_id").is_none());
    assert_eq!(group["verified_identity"]["unit"], "approval.service");

    let approval_id = first["approval_id"].as_str().unwrap();
    let path = format!("/api/v3/approvals/{approval_id}/approve");
    // A subset of the group is rejected.
    let version = group["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let subset = harness
        .call(
            &fleet.approver,
            "POST",
            &path,
            &[
                ("idempotency-key", "group-subset-idem-0001"),
                ("if-match", if_match.as_str()),
            ],
            Some(&json!({
                "expected_status":"pending","expected_version":version,
                "operation_ids":[first["id"]]
            })),
        )
        .await;
    assert_eq!(subset.status, 409, "{}", subset.body);
    // The version observed before the second member joined is stale.
    let old_version = before_join["version"].as_i64().unwrap();
    let old_if_match = format!("\"{old_version}\"");
    let stale = harness
        .call(
            &fleet.approver,
            "POST",
            &path,
            &[
                ("idempotency-key", "group-stale-idem-0001"),
                ("if-match", old_if_match.as_str()),
            ],
            Some(&json!({
                "expected_status":"pending","expected_version":old_version,
                "operation_ids":before_join["operation_ids"]
            })),
        )
        .await;
    assert_eq!(stale.status, 409, "{}", stale.body);

    // A different unit is a different scope and a different group.
    let other_workload = harness
        .create_workload(
            &fleet.node.id,
            "other-worker",
            "other.service",
            "other",
            "file",
        )
        .await;
    assert_eq!(other_workload.status, 201, "{}", other_workload.body);
    let other = fleet
        .request_on(
            &fleet.requester,
            &other_workload.body,
            &OperationSpec::new("group-operation-0003"),
        )
        .await;
    assert_ne!(other["approval_id"], first["approval_id"]);

    // A full group of ten starts a new group; no operation is in two groups.
    let mut ids = vec![first["id"].clone(), second["id"].clone()];
    for index in 4..=12 {
        let key = format!("group-operation-{index:04}");
        let created = fleet.request(&fleet.requester, &key).await;
        ids.push(created["id"].clone());
    }
    let full = fleet.approval(&first["approval_id"]).await;
    assert_eq!(full["operation_ids"].as_array().unwrap().len(), 10);
    let last = fleet.operation(ids.last().unwrap()).await;
    assert_ne!(last["approval_id"], first["approval_id"]);
    for id in &ids {
        assert_eq!(
            harness
                .scalar_i64(
                    "SELECT COUNT(*) FROM operation_approvals WHERE operation_ids_json LIKE ?",
                    vec![format!("%\"{}\"%", id.as_str().unwrap()).into()],
                )
                .await,
            1,
            "{id}"
        );
    }

    let approved = harness
        .decide(
            &fleet.approver,
            approval_id,
            "approve",
            "group-approve-idem-0001",
        )
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    for id in [&first["id"], &second["id"]] {
        assert_eq!(fleet.operation(id).await["status"], "granted");
    }
}

#[tokio::test]
async fn ended_requests_are_closed_to_the_broker() {
    let fleet = fleet().await;
    let harness = &fleet.harness;

    // Rejected.
    let rejected = fleet
        .request(&fleet.requester, "closure-operation-0001")
        .await;
    let response = harness
        .decide(
            &fleet.approver,
            rejected["approval_id"].as_str().unwrap(),
            "reject",
            "closure-reject-idem-0001",
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["status"], "rejected");
    assert_eq!(fleet.operation(&rejected["id"]).await["status"], "denied");
    let closure = fleet
        .closure(&rejected["id"])
        .await
        .expect("rejection closure");
    assert_eq!(closure["status"], "rejected");
    assert_eq!(closure["request_event_key"], "closure-operation-0001");
    assert_eq!(closure["node_id"], fleet.node.id);

    // Cancelled while awaiting approval (dismissed).
    let dismissed = fleet
        .request(&fleet.requester, "closure-operation-0002")
        .await;
    let stays = fleet
        .request(&fleet.requester, "closure-operation-0003")
        .await;
    assert_eq!(dismissed["approval_id"], stays["approval_id"]);
    let group_before = fleet.approval(&dismissed["approval_id"]).await;
    let cancelled = harness
        .call(
            &fleet.requester,
            "DELETE",
            &format!("/api/v3/operations/{}", dismissed["id"].as_str().unwrap()),
            &[],
            None,
        )
        .await;
    assert_eq!(cancelled.status, 200, "{}", cancelled.body);
    assert_eq!(cancelled.body["status"], "cancelled");
    let closure = fleet
        .closure(&dismissed["id"])
        .await
        .expect("cancel closure");
    assert_eq!(closure["status"], "cancelled");
    let group_after = fleet.approval(&dismissed["approval_id"]).await;
    assert_eq!(group_after["operation_ids"], json!([stays["id"]]));
    assert!(group_after["version"].as_i64() > group_before["version"].as_i64());

    // Expired: the list path converges state, count and status filter.
    assert_eq!(fleet.pending_count().await, 1);
    harness
        .execute(
            "UPDATE operation_approvals SET expires_at = ? WHERE id = ?",
            vec![
                (harness.now_ms().await - 1).into(),
                stays["approval_id"].as_str().unwrap().into(),
            ],
        )
        .await;
    let listed = harness
        .get(&fleet.approver, "/api/v3/approvals?status=expired")
        .await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert!(
        listed.body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == stays["approval_id"])
    );
    assert_eq!(fleet.pending_count().await, 0);
    assert_eq!(
        fleet.approval(&stays["approval_id"]).await["status"],
        "expired"
    );
    let expired = fleet.operation(&stays["id"]).await;
    assert_eq!(expired["status"], "denied");
    assert_eq!(expired["result"]["reason"], "approval_expired");
    let closure = fleet.closure(&stays["id"]).await.expect("expiry closure");
    assert_eq!(closure["status"], "expired");

    // Denied by policy at request time.
    let deny = harness
        .set_policy(json!([{
            "id":"deny-noop-file","action":"noop.marker","mode":"file",
            "decision":"deny","approval_required":false,"max_ttl_seconds":120
        }]))
        .await;
    assert_eq!(deny.status, 200, "{}", deny.body);
    let denied = fleet
        .request(&fleet.requester, "closure-operation-0004")
        .await;
    assert_eq!(denied["status"], "denied");
    let closure = fleet.closure(&denied["id"]).await.expect("denial closure");
    assert_eq!(closure["status"], "denied");
}

#[tokio::test]
async fn approval_ttl_follows_configuration() {
    let fleet = fleet_with(&[
        ("BLINDPASS_TEST_MODE", "1"),
        ("BLINDPASS_TEST_APPROVAL_TTL_SECONDS", "45"),
    ])
    .await;
    let operation = fleet.request(&fleet.requester, "ttl-operation-0001").await;
    let approval = fleet.approval(&operation["approval_id"]).await;
    let lifetime =
        approval["expires_at"].as_i64().unwrap() - approval["created_at"].as_i64().unwrap();
    assert!((43_000..=47_000).contains(&lifetime), "{lifetime}");

    let default = fleet_with(&[]).await;
    let operation = default
        .request(&default.requester, "ttl-operation-0002")
        .await;
    let approval = default.approval(&operation["approval_id"]).await;
    let lifetime =
        approval["expires_at"].as_i64().unwrap() - approval["created_at"].as_i64().unwrap();
    assert!((598_000..=602_000).contains(&lifetime), "{lifetime}");
}

#[tokio::test]
async fn purposes_are_display_safe_and_bounded() {
    let fleet = fleet().await;
    let harness = &fleet.harness;
    let cases = [
        ("zero\u{200b}width\u{200f}", "zerowidth"),
        ("bidi\u{202e}override\u{202a}", "bidioverride"),
        ("isolate\u{2066}text\u{2069}\u{2060}", "isolatetext"),
        ("\u{feff}bom", "bom"),
        ("line\u{2028}para\u{2029}", "linepara"),
        ("color \u{1b}[31mred\u{1b}[0m", "color red"),
        ("title\u{1b}]0;spoof\u{7}done", "titledone"),
        ("c1\u{9b}2Jcsi", "c1csi"),
        ("tab\tnewline\n", "tabnewline"),
    ];
    for (index, (purpose, expected)) in cases.iter().enumerate() {
        let key = format!("purpose-operation-{index:04}");
        let operation = fleet
            .request_on(
                &fleet.requester,
                &fleet.workload,
                &OperationSpec {
                    event_key: &key,
                    invocation_id: "invocation-p",
                    resource_id: "marker-p",
                    purpose,
                },
            )
            .await;
        assert_eq!(operation["purpose"], *expected, "{purpose:?}");
    }
    let long = "a".repeat(513);
    let input = harness
        .broker_request(
            &fleet.node,
            &fleet.workload,
            &OperationSpec {
                event_key: "purpose-operation-long",
                invocation_id: "invocation-p",
                resource_id: "marker-p",
                purpose: &long,
            },
        )
        .await;
    let rejected = harness
        .call(
            &fleet.requester,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", "idem-purpose-operation-long")],
            Some(&input),
        )
        .await;
    assert_eq!(rejected.status, 400, "{}", rejected.body);
}

#[tokio::test]
async fn approval_listing_is_complete_across_age_and_paging() {
    let fleet = fleet().await;
    let harness = &fleet.harness;
    let mut expected = HashSet::new();
    for index in 0..3 {
        let workload = harness
            .create_workload(
                &fleet.node.id,
                &format!("paging-worker-{index}"),
                &format!("paging-{index}.service"),
                "paging",
                "file",
            )
            .await;
        assert_eq!(workload.status, 201, "{}", workload.body);
        let key = format!("paging-operation-{index:04}");
        let operation = fleet
            .request_on(&fleet.requester, &workload.body, &OperationSpec::new(&key))
            .await;
        expected.insert(operation["approval_id"].as_str().unwrap().to_owned());
    }
    // An approval older than the ten-minute audit window, still pending.
    let oldest = expected.iter().next().unwrap().clone();
    let now_ms = harness.now_ms().await;
    harness
        .execute(
            "UPDATE operation_approvals SET created_at = ?, expires_at = ? WHERE id = ?",
            vec![
                (now_ms - 11 * 60 * 1_000).into(),
                (now_ms + 60 * 60 * 1_000).into(),
                oldest.as_str().into(),
            ],
        )
        .await;
    assert_eq!(fleet.pending_count().await, 3);

    let first_page = harness
        .get(&fleet.approver, "/api/v3/approvals?status=pending&limit=2")
        .await;
    assert_eq!(first_page.status, 200, "{}", first_page.body);
    assert_eq!(first_page.body["items"][0]["id"], oldest.as_str());
    let cursor = first_page.body["next_cursor"].as_str().unwrap().to_owned();
    // Insert while paging.
    let workload = harness
        .create_workload(
            &fleet.node.id,
            "paging-late",
            "paging-late.service",
            "paging",
            "file",
        )
        .await;
    let late = fleet
        .request_on(
            &fleet.requester,
            &workload.body,
            &OperationSpec::new("paging-operation-late"),
        )
        .await;
    expected.insert(late["approval_id"].as_str().unwrap().to_owned());

    let mut seen = Vec::new();
    for item in first_page.body["items"].as_array().unwrap() {
        seen.push(item["id"].as_str().unwrap().to_owned());
    }
    let mut next = Some(cursor);
    while let Some(cursor) = next {
        let page = harness
            .get(
                &fleet.approver,
                &format!("/api/v3/approvals?status=pending&limit=2&cursor={cursor}"),
            )
            .await;
        assert_eq!(page.status, 200, "{}", page.body);
        for item in page.body["items"].as_array().unwrap() {
            seen.push(item["id"].as_str().unwrap().to_owned());
        }
        next = page.body["next_cursor"].as_str().map(str::to_owned);
    }
    let unique = seen.iter().cloned().collect::<HashSet<_>>();
    assert_eq!(unique.len(), seen.len(), "duplicates: {seen:?}");
    assert_eq!(unique, expected);
}
