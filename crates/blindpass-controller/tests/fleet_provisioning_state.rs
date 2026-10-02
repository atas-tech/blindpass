// SPDX-License-Identifier: AGPL-3.0-only
//! P05-PV06-S (GUI portion): the secret-free `provisioning` state the console
//! reads from the fleet operation list and detail. `can_provide` must come from
//! the same current-authority checks as the link route, so it is true only for
//! the named Source owner while the original offer is live. These cases run over
//! real HTTP and durable storage on SQLite, or on PostgreSQL when
//! `P02_TEST_BACKEND=postgres` and `P02_TEST_POSTGRES_URL` are set. No Source
//! plaintext or recipient private key exists in this file's controller.
mod support;

use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::fleet::{Grant, SignedEnvelope};
use blindpass_core::provisioning::{BrowserProvisioningBinding, sign_browser_recipient_offer};
use blindpass_core::signing::base64_url_encode;
use serde_json::{Value, json};
use std::time::Duration;
use support::{Bind, FleetNode, Harness, HttpResponse, Operator, signed_event};

const UNIT: &str = "blindpass-login@report-primary.service";
const CREDENTIAL: &str = "report-source";
const LINK_KEY: &str = "state-source-link-00000001";
const SOURCE_CANARY: &str = "P05-STATE-SOURCE-CANARY";

struct Fixture {
    h: Harness,
    node: FleetNode,
    owner: Operator,
    binding: BrowserProvisioningBinding,
    recipient: RecipientKeyPair,
    offer: Value,
}

impl Fixture {
    async fn new(seed: u8, approval: bool) -> Self {
        Self::build(seed, approval, 30_000, true).await
    }

    async fn build(seed: u8, approval: bool, ttl_ms: u64, publish: bool) -> Self {
        let h = Harness::start().await;
        let owner = h
            .create_operator(&format!("state-owner-{seed}"), "operator")
            .await;
        let node = h.online_node("state-source", seed).await;
        let rule = json!([{
            "id": "state-rule", "action": "browser.session", "mode": "browser_session",
            "decision": if approval { "pending_approval" } else { "allow" },
            "approval_required": approval, "max_ttl_seconds": 60,
            "approver_ids": if approval { json!([owner.id]) } else { json!([]) }
        }]);
        assert_eq!(h.set_policy(rule).await.status, 200);
        let workload = h
            .create_workload(
                &node.id,
                "state-worker",
                "state-worker.service",
                "uid:1001",
                "browser_session",
            )
            .await;
        assert_eq!(workload.status, 201);
        let request = signed_event(
            &node.id,
            &node.keys.signing,
            "event_state_source_00000001",
            "operation_request",
            json!({
                "request_version": 2, "node_id": node.id, "workload_id": workload.body["id"],
                "unit": workload.body["unit"], "account": workload.body["account"],
                "action": "browser.session", "mode": "browser_session",
                "purpose": "read approved report", "resource_id": "report-primary",
                "invocation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ttl_seconds": 60,
                "observed_at_ms": h.now_ms().await
            }),
        );
        assert_eq!(h.post_events(&node.bearer, &request).await.status, 200);
        let binding_path = format!("/api/v3/nodes/{}/source-bindings/report-primary", node.id);
        let configured = h
            .call(
                &h.admin,
                "PUT",
                &binding_path,
                &[],
                Some(
                    &json!({"source_unit": UNIT, "credential": CREDENTIAL, "expected_version": 0}),
                ),
            )
            .await;
        assert_eq!(configured.status, 200);
        if approval {
            let operations = h.get(&h.admin, "/api/v3/operations").await;
            let id = operations.body["items"][0]["approval_id"].as_str().unwrap();
            let decided = h
                .decide(&owner, id, "approve", "state-owner-approved-000001")
                .await;
            assert_eq!(decided.status, 200);
        }
        let document = h
            .inbox(&node.id)
            .await
            .into_iter()
            .find(|entry| entry["kind"] == "grant")
            .unwrap();
        let grant = Grant::from_value(
            SignedEnvelope::from_json(&document.to_string())
                .unwrap()
                .body(),
        )
        .unwrap();
        let private_key = [seed.wrapping_add(90); 32];
        let recipient = RecipientKeyPair::from_private_key(&private_key).unwrap();
        let now = u64::try_from(h.now_ms().await).unwrap();
        let binding = BrowserProvisioningBinding {
            offer_id: "pv_state_source_original_0000001".into(),
            node_key_version: 1,
            source_unit: UNIT.into(),
            credential: CREDENTIAL.into(),
            recipient_public: base64_url_encode(recipient.public_key()),
            issued_at_ms: now,
            expires_at_ms: now + ttl_ms,
            grant,
        };
        let offer: Value = serde_json::from_slice(
            &sign_browser_recipient_offer(&binding, &node.keys.signing)
                .unwrap()
                .to_json()
                .unwrap(),
        )
        .unwrap();
        let fixture = Self {
            h,
            node,
            owner,
            binding,
            recipient,
            offer,
        };
        if publish {
            assert_eq!(fixture.publish_offer().await.body["accepted"], 1);
        }
        fixture
    }

    async fn publish_offer(&self) -> HttpResponse {
        let event = signed_event(
            &self.node.id,
            &self.node.keys.signing,
            "event_state_offer_00000001",
            "recipient_offer",
            self.offer.clone(),
        );
        self.h.post_events(&self.node.bearer, &event).await
    }

    fn operation_id(&self) -> &str {
        &self.binding.grant.operation_id
    }

    async fn detail_as(&self, actor: &Operator) -> HttpResponse {
        self.h
            .get(
                actor,
                &format!("/api/v3/operations/{}", self.operation_id()),
            )
            .await
    }

    /// The `provisioning` object of the detail read, asserting its exact shape.
    async fn state_as(&self, actor: &Operator) -> Value {
        let reply = self.detail_as(actor).await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        shape(&reply.body["provisioning"])
    }

    async fn list_state_as(&self, actor: &Operator) -> Value {
        let reply = self.h.get(actor, "/api/v3/operations").await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        let item = reply.body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == self.operation_id())
            .expect("the browser operation is listed");
        shape(&item["provisioning"])
    }

    async fn link(&self) -> Value {
        let reply = self
            .h
            .call(
                &self.owner,
                "POST",
                &format!(
                    "/api/v3/admin/operations/{}/provisioning-link",
                    self.operation_id()
                ),
                &[("idempotency-key", LINK_KEY)],
                None,
            )
            .await;
        assert_eq!(reply.status, 201, "{}", reply.body);
        reply.body
    }

    fn sealed(&self, source: &[u8]) -> Value {
        let sealed = RecipientKeyPair::seal(
            self.recipient.public_key(),
            source,
            &self.binding.aad().unwrap(),
        )
        .unwrap();
        json!({
            "enc": base64_url_encode(&sealed.enc),
            "ciphertext": base64_url_encode(&sealed.ciphertext)
        })
    }
}

/// The object must carry exactly the three documented keys.
fn shape(value: &Value) -> Value {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("provisioning must be an object: {value}"));
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["can_provide", "offer_expires_at_ms", "state"]);
    assert!(value["can_provide"].is_boolean());
    value.clone()
}

fn assert_state(value: &Value, state: &str, can_provide: bool, with_expiry: Option<u64>) {
    assert_eq!(value["state"], state, "{value}");
    assert_eq!(value["can_provide"], can_provide, "{value}");
    match with_expiry {
        Some(expiry) => assert_eq!(
            value["offer_expires_at_ms"].as_u64(),
            Some(expiry),
            "{value}"
        ),
        None => assert!(value["offer_expires_at_ms"].is_null(), "{value}"),
    }
}

// ---------------------------------------------------------------- P05-PV06-S11

#[tokio::test]
async fn pv06_s10_state_follows_offer_link_and_submission_for_the_named_owner_only() {
    let f = Fixture::build(141, true, 30_000, false).await;
    let other =
        f.h.create_operator("state-other-operator", "operator")
            .await;
    let admin = f.h.admin.clone();

    // A granted browser operation whose node has not yet published its offer.
    for actor in [&f.owner, &other, &admin] {
        assert_state(&f.state_as(actor).await, "awaiting_offer", false, None);
        assert_state(&f.list_state_as(actor).await, "awaiting_offer", false, None);
    }

    // The signed offer arrives: only the deciding operator may provide.
    assert_eq!(f.publish_offer().await.body["accepted"], 1);
    let expiry = f.binding.expires_at_ms;
    assert_state(
        &f.state_as(&f.owner).await,
        "offer_ready",
        true,
        Some(expiry),
    );
    assert_state(
        &f.list_state_as(&f.owner).await,
        "offer_ready",
        true,
        Some(expiry),
    );
    for actor in [&other, &admin] {
        assert_state(&f.state_as(actor).await, "offer_ready", false, Some(expiry));
        assert_state(
            &f.list_state_as(actor).await,
            "offer_ready",
            false,
            Some(expiry),
        );
    }

    // The owner's link exists; the owner may retry idempotently, nobody else.
    f.link().await;
    assert_state(
        &f.state_as(&f.owner).await,
        "link_issued",
        true,
        Some(expiry),
    );
    assert_state(
        &f.list_state_as(&f.owner).await,
        "link_issued",
        true,
        Some(expiry),
    );
    for actor in [&other, &admin] {
        assert_state(&f.state_as(actor).await, "link_issued", false, Some(expiry));
    }

    // After the first ciphertext commits, nobody may provide again.
    let link = f.link_after_creation().await;
    let submit = format!(
        "/api/v3/fleet/provisioning/{}/submit?sig={}",
        link["id"].as_str().unwrap(),
        link["submit_sig"].as_str().unwrap()
    );
    let accepted =
        f.h.call(
            &f.owner,
            "POST",
            &submit,
            &[],
            Some(&f.sealed(SOURCE_CANARY.as_bytes())),
        )
        .await;
    assert_eq!(accepted.status, 201, "{}", accepted.body);
    for actor in [&f.owner, &other, &admin] {
        assert_state(&f.state_as(actor).await, "submitted", false, None);
        assert_state(&f.list_state_as(actor).await, "submitted", false, None);
    }
}

impl Fixture {
    /// The immutable link, read back with an exact idempotent retry.
    async fn link_after_creation(&self) -> Value {
        let reply = self
            .h
            .call(
                &self.owner,
                "POST",
                &format!(
                    "/api/v3/admin/operations/{}/provisioning-link",
                    self.operation_id()
                ),
                &[("idempotency-key", LINK_KEY)],
                None,
            )
            .await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        reply.body
    }
}

#[tokio::test]
async fn pv06_s11_automatic_allow_names_only_the_destination_administrator() {
    let f = Fixture::new(142, false).await;
    let second = f.h.create_operator("state-second-admin", "admin").await;
    let expiry = f.binding.expires_at_ms;
    let destination_admin = f.h.admin.clone();
    // The operator account in the fixture neither decided nor configured it.
    assert_state(
        &f.state_as(&f.owner).await,
        "offer_ready",
        false,
        Some(expiry),
    );
    assert_state(
        &f.state_as(&second).await,
        "offer_ready",
        false,
        Some(expiry),
    );
    assert_state(
        &f.state_as(&destination_admin).await,
        "offer_ready",
        true,
        Some(expiry),
    );
    assert_state(
        &f.list_state_as(&destination_admin).await,
        "offer_ready",
        true,
        Some(expiry),
    );
}

#[tokio::test]
async fn pv06_s12_viewers_cannot_read_operations_so_they_never_receive_a_state() {
    let f = Fixture::new(143, true).await;
    let viewer = f.h.create_operator("state-viewer", "viewer").await;
    let detail = f.detail_as(&viewer).await;
    assert_eq!(detail.status, 403, "{}", detail.body);
    assert!(detail.body.get("provisioning").is_none());
    let list = f.h.get(&viewer, "/api/v3/operations").await;
    assert_eq!(list.status, 403, "{}", list.body);
    // No session at all is refused before any state is computed.
    let anonymous =
        f.h.request(
            "GET",
            &format!("/api/v3/operations/{}", f.operation_id()),
            &[],
            None,
        )
        .await;
    assert_eq!(anonymous.status, 401);
    // A node bearer cannot read operator state either.
    let node =
        f.h.request(
            "GET",
            &format!("/api/v3/operations/{}", f.operation_id()),
            &[("authorization", f.node.bearer.as_str())],
            None,
        )
        .await;
    assert_eq!(node.status, 401);
}

#[tokio::test]
async fn pv06_s13_operations_without_a_browser_grant_are_not_applicable() {
    let f = Fixture::new(144, true).await;
    // A second browser request for the same workload stays awaiting approval:
    // it has no grant, so there is nothing to provide.
    let second = signed_event(
        &f.node.id,
        &f.node.keys.signing,
        "event_state_second_00000001",
        "operation_request",
        json!({
            "request_version": 2, "node_id": f.node.id,
            "workload_id": f.binding.grant.workload_id,
            "unit": f.binding.grant.unit, "account": f.binding.grant.account,
            "action": "browser.session", "mode": "browser_session",
            "purpose": "read another report", "resource_id": "report-primary",
            "invocation_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ttl_seconds": 60,
            "observed_at_ms": f.h.now_ms().await
        }),
    );
    assert_eq!(f.h.post_events(&f.node.bearer, &second).await.status, 200);
    let list = f.h.get(&f.owner, "/api/v3/operations").await;
    assert_eq!(list.status, 200);
    let items = list.body["items"].as_array().unwrap();
    assert!(items.len() >= 2, "{}", list.body);
    let mut granted = 0;
    let mut waiting = 0;
    for item in items {
        let state = shape(&item["provisioning"]);
        if item["id"] == f.operation_id() {
            granted += 1;
            assert_state(&state, "offer_ready", true, Some(f.binding.expires_at_ms));
        } else {
            waiting += 1;
            assert_eq!(item["grant_id"], Value::Null, "{item}");
            assert_state(&state, "not_applicable", false, None);
        }
    }
    assert_eq!((granted, waiting), (1, items.len() - 1));
}

#[tokio::test]
async fn pv06_s14_every_loss_of_authority_or_deadline_reads_as_expired() {
    // The same mutations the link, metadata and submit routes answer 410 for.
    let cases = [
        "UPDATE grants SET status='consumed'",
        "UPDATE grants SET status='revoked'",
        "UPDATE grants SET status='expired'",
        "UPDATE operations SET status='cancelled'",
        "UPDATE workloads SET registration_version=registration_version+1",
        "UPDATE workloads SET status='revoked'",
        "UPDATE fleet_policies SET version=version+1",
        "UPDATE fleet_source_bindings SET version=version+1",
        "UPDATE fleet_source_bindings SET credential='changed-source'",
        "UPDATE controller_meta SET issuer_epoch=issuer_epoch+1",
        "UPDATE fleet_provisioning_offers SET expires_at=issued_at+1",
        "UPDATE nodes SET status='revoked'",
        "INSERT INTO node_revocation_queue (node_id,created_at) SELECT id,0 FROM nodes",
    ];
    for (index, sql) in cases.into_iter().enumerate() {
        let f = Fixture::new(100 + u8::try_from(index).unwrap(), true).await;
        assert_state(
            &f.state_as(&f.owner).await,
            "offer_ready",
            true,
            Some(f.binding.expires_at_ms),
        );
        f.h.execute(sql, vec![]).await;
        assert_state(&f.state_as(&f.owner).await, "expired", false, None);
        assert_state(&f.list_state_as(&f.owner).await, "expired", false, None);
    }
    // A link that outlives its own deadline is expired too.
    let f = Fixture::new(120, true).await;
    f.link().await;
    f.h.execute(
        "UPDATE fleet_provisioning_links SET expires_at=created_at+1",
        vec![],
    )
    .await;
    assert_state(&f.state_as(&f.owner).await, "expired", false, None);
}

#[tokio::test]
async fn pv06_s15_the_real_offer_deadline_expires_the_state_without_a_sweep() {
    let f = Fixture::build(145, true, 2_000, true).await;
    assert_state(
        &f.state_as(&f.owner).await,
        "offer_ready",
        true,
        Some(f.binding.expires_at_ms),
    );
    let remaining = i64::try_from(f.binding.expires_at_ms).unwrap() - f.h.now_ms().await;
    tokio::time::sleep(Duration::from_millis(
        u64::try_from(remaining.max(0)).unwrap() + 150,
    ))
    .await;
    assert_state(&f.state_as(&f.owner).await, "expired", false, None);
}

#[tokio::test]
async fn pv06_s16_owner_loses_can_provide_when_role_or_session_authority_changes() {
    let f = Fixture::new(146, true).await;
    let expiry = f.binding.expires_at_ms;
    assert_state(
        &f.state_as(&f.owner).await,
        "offer_ready",
        true,
        Some(expiry),
    );
    // The named owner kept the decision but lost the operator role: the
    // operations read itself is refused, so no stale can_provide survives.
    f.h.execute(
        "UPDATE operators SET role='viewer' WHERE id=?",
        vec![Bind::Text(f.owner.id.clone())],
    )
    .await;
    assert_eq!(f.detail_as(&f.owner).await.status, 403);
    f.h.execute(
        "UPDATE operators SET role='operator' WHERE id=?",
        vec![Bind::Text(f.owner.id.clone())],
    )
    .await;
    assert_state(
        &f.state_as(&f.owner).await,
        "offer_ready",
        true,
        Some(expiry),
    );
    // A logged-out session is refused rather than shown a state.
    assert_eq!(
        f.h.call(&f.owner, "POST", "/api/v3/admin/session/logout", &[], None)
            .await
            .status,
        204
    );
    assert_eq!(f.detail_as(&f.owner).await.status, 401);
}

#[tokio::test]
async fn pv06_s17_the_state_never_carries_capabilities_keys_ciphertext_or_links() {
    let f = Fixture::new(147, true).await;
    let link = f.link().await;
    let accepted = {
        let submit = format!(
            "/api/v3/fleet/provisioning/{}/submit?sig={}",
            link["id"].as_str().unwrap(),
            link["submit_sig"].as_str().unwrap()
        );
        let body = f.sealed(SOURCE_CANARY.as_bytes());
        let reply = f.h.call(&f.owner, "POST", &submit, &[], Some(&body)).await;
        assert_eq!(reply.status, 201, "{}", reply.body);
        body
    };
    // Read every state on both endpoints, after the submission and while the
    // offer is merely ready.
    let fresh = Fixture::new(148, true).await;
    let mut forbidden = vec![
        link["id"].as_str().unwrap().to_owned(),
        link["metadata_sig"].as_str().unwrap().to_owned(),
        link["submit_sig"].as_str().unwrap().to_owned(),
        link["input_path"].as_str().unwrap().to_owned(),
        accepted["enc"].as_str().unwrap().to_owned(),
        accepted["ciphertext"].as_str().unwrap().to_owned(),
        f.binding.recipient_public.clone(),
        fresh.binding.recipient_public.clone(),
        f.binding.offer_id.clone(),
        SOURCE_CANARY.to_owned(),
        "metadata_sig".to_owned(),
        "submit_sig".to_owned(),
        "recipient_public".to_owned(),
    ];
    forbidden.sort();
    forbidden.dedup();
    for (fixture, label) in [(&f, "submitted"), (&fresh, "offer_ready")] {
        for reply in [
            fixture.detail_as(&fixture.owner).await,
            fixture.h.get(&fixture.owner, "/api/v3/operations").await,
        ] {
            assert_eq!(reply.status, 200, "{label}");
            let text = reply.body.to_string();
            for needle in &forbidden {
                assert!(
                    !text.contains(needle.as_str()),
                    "{label} read leaked {}",
                    &needle[..needle.len().min(12)]
                );
            }
        }
    }
}
