// SPDX-License-Identifier: AGPL-3.0-only
//! PV06-S01–S09: the scoped operator Source link, metadata and ciphertext
//! submit over real HTTP and durable storage. No Source plaintext or recipient
//! private key ever enters the controller under test; the test plays the
//! browser by sealing a dummy canary to the verified offer.
mod support;

use blindpass_controller::store::{Store, StoreError};
use blindpass_core::canon::parse_json;
use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::fleet::{DocumentKind, Grant, SignedEnvelope};
use blindpass_core::provisioning::{
    BrowserProvisioningBinding, BrowserProvisioningDelivery, sign_browser_recipient_offer,
    verify_browser_recipient_offer,
};
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use blindpass_core::signing::{
    BrowserScope, base64_url_decode, base64_url_encode, sign_browser_payload,
    sign_fleet_provisioning_capability,
};
use serde_json::{Value, json};
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use support::{Backend, Bind, FleetNode, Harness, HttpResponse, Operator, signed_event};

const SOURCE: &[u8] = b"  P05-OPERATOR-SOURCE-CANARY\n";
const CANARY: &str = "P05-OPERATOR-SOURCE-CANARY";
const UNIT: &str = "blindpass-login@report-primary.service";
const CREDENTIAL: &str = "report-source";
const LINK_KEY: &str = "scoped-source-link-00000001";
const ROOT_SECRET: &[u8] = b"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";

struct Fixture {
    h: Harness,
    node: FleetNode,
    owner: Operator,
    binding: BrowserProvisioningBinding,
    recipient: RecipientKeyPair,
    private_key: [u8; 32],
    offer: Value,
}

impl Fixture {
    async fn new(seed: u8, approval: bool) -> Self {
        Self::build(seed, approval, 30_000, true).await
    }

    /// `ttl_ms` is the original offer lifetime; `publish` posts the signed
    /// recipient offer event as the node would after its broker minted it.
    async fn build(seed: u8, approval: bool, ttl_ms: u64, publish: bool) -> Self {
        let h = Harness::start().await;
        let owner = h
            .create_operator(&format!("source-owner-{seed}"), "operator")
            .await;
        let node = h.online_node("scoped-source", seed).await;
        let rule = json!([{
            "id": "source-rule", "action": "browser.session", "mode": "browser_session",
            "decision": if approval { "pending_approval" } else { "allow" },
            "approval_required": approval, "max_ttl_seconds": 60,
            "approver_ids": if approval { json!([owner.id]) } else { json!([]) }
        }]);
        assert_eq!(h.set_policy(rule).await.status, 200);
        let workload = h
            .create_workload(
                &node.id,
                "source-worker",
                "source-worker.service",
                "uid:1001",
                "browser_session",
            )
            .await;
        assert_eq!(workload.status, 201);
        let request = signed_event(
            &node.id,
            &node.keys.signing,
            "event_scoped_source_00000001",
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
        if approval {
            let operations = h.get(&h.admin, "/api/v3/operations").await;
            let id = operations.body["items"][0]["approval_id"].as_str().unwrap();
            let decided = h
                .decide(&owner, id, "approve", "source-owner-approved-00001")
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
            offer_id: "pv_scoped_source_original_000001".into(),
            node_key_version: 1,
            source_unit: UNIT.into(),
            credential: CREDENTIAL.into(),
            recipient_public: base64_url_encode(recipient.public_key()),
            issued_at_ms: now,
            expires_at_ms: now + ttl_ms,
            grant,
        };
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
        let offer = offer_body(&binding, &node.keys.signing);
        let fixture = Self {
            h,
            node,
            owner,
            binding,
            recipient,
            private_key,
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
            "event_scoped_offer_00000001",
            "recipient_offer",
            self.offer.clone(),
        );
        self.h.post_events(&self.node.bearer, &event).await
    }

    fn link_path(&self) -> String {
        format!(
            "/api/v3/admin/operations/{}/provisioning-link",
            self.binding.grant.operation_id
        )
    }

    async fn link_as(&self, actor: &Operator, key: &str) -> HttpResponse {
        self.h
            .call(
                actor,
                "POST",
                &self.link_path(),
                &[("idempotency-key", key)],
                None,
            )
            .await
    }

    async fn link(&self) -> Value {
        let reply = self.link_as(&self.owner, LINK_KEY).await;
        assert_eq!(reply.status, 201, "{}", reply.body);
        reply.body
    }

    fn path(link: &Value, scope: &str) -> String {
        let id = link["id"].as_str().unwrap();
        let signature = link[format!("{scope}_sig")].as_str().unwrap();
        format!("/api/v3/fleet/provisioning/{id}/{scope}?sig={signature}")
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

    async fn submit_as(&self, actor: &Operator, link: &Value, body: &Value) -> HttpResponse {
        self.h
            .call(actor, "POST", &Self::path(link, "submit"), &[], Some(body))
            .await
    }

    async fn submit(&self, link: &Value, body: &Value) -> HttpResponse {
        self.submit_as(&self.owner, link, body).await
    }

    async fn metadata(&self, link: &Value) -> HttpResponse {
        self.h.get(&self.owner, &Self::path(link, "metadata")).await
    }

    async fn delivery(&self) -> Vec<Value> {
        self.h
            .inbox(&self.node.id)
            .await
            .into_iter()
            .filter(|entry| entry["kind"] == "provisioning_delivery")
            .collect()
    }

    async fn rows(&self, table: &str) -> i64 {
        assert!(["fleet_provisioning_links", "fleet_provisioning_receipts"].contains(&table));
        self.h
            .scalar_i64(&format!("SELECT COUNT(*) FROM {table}"), vec![])
            .await
    }

    async fn audits(&self, action: &str) -> i64 {
        self.h
            .scalar_i64(
                "SELECT COUNT(*) FROM audit_events WHERE action=?",
                vec![action.into()],
            )
            .await
    }

    /// Nothing was committed: no receipt, no delivery, no audit event.
    async fn assert_no_submission(&self) {
        assert_eq!(self.rows("fleet_provisioning_receipts").await, 0);
        assert!(self.delivery().await.is_empty());
        assert_eq!(self.audits("fleet.source_submitted").await, 0);
    }

    /// The link capability as the controller would sign it, for forged-expiry
    /// and domain-separation checks.
    fn capability(link: &Value, scope: BrowserScope, expires_secs: u64) -> String {
        sign_fleet_provisioning_capability(
            link["id"].as_str().unwrap(),
            expires_secs,
            scope,
            ROOT_SECRET,
        )
        .unwrap()
    }
}

fn offer_body(binding: &BrowserProvisioningBinding, signer: &Ed25519KeyPair) -> Value {
    serde_json::from_slice(
        &sign_browser_recipient_offer(binding, signer)
            .unwrap()
            .to_json()
            .unwrap(),
    )
    .unwrap()
}

fn seconds(link: &Value) -> u64 {
    link["expires_at_ms"].as_u64().unwrap().div_ceil(1_000)
}

fn private_key_text(key: &[u8; 32]) -> String {
    base64_url_encode(key)
}

fn session_token(operator: &Operator) -> String {
    operator
        .cookies
        .split(';')
        .find_map(|pair| pair.trim().strip_prefix("bp_session="))
        .unwrap()
        .to_owned()
}

// ---------------------------------------------------------------- S01

#[tokio::test]
async fn named_operator_link_is_authorized_immutable_and_scope_bound() {
    let f = Fixture::new(181, true).await;
    let viewer = f.h.create_operator("source-viewer", "viewer").await;
    let outsider = f.h.create_operator("source-outsider", "operator").await;
    for actor in [&f.h.admin, &viewer, &outsider] {
        assert_eq!(f.link_as(actor, LINK_KEY).await.status, 403);
    }
    let node_only = [
        ("authorization", f.node.bearer.as_str()),
        ("idempotency-key", LINK_KEY),
    ];
    assert_eq!(
        f.h.request("POST", &f.link_path(), &node_only, None)
            .await
            .status,
        401
    );
    let no_csrf = [
        ("cookie", f.owner.cookies.as_str()),
        ("idempotency-key", LINK_KEY),
    ];
    assert_eq!(
        f.h.request("POST", &f.link_path(), &no_csrf, None)
            .await
            .status,
        403
    );
    assert_eq!(f.link_as(&f.owner, "short").await.status, 400);
    let unknown = "/api/v3/admin/operations/op_unknown_operation_0001/provisioning-link";
    let missing =
        f.h.call(
            &f.owner,
            "POST",
            unknown,
            &[("idempotency-key", LINK_KEY)],
            None,
        )
        .await;
    assert_eq!(missing.status, 404);
    assert_eq!(f.rows("fleet_provisioning_links").await, 0);

    let link = f.link().await;
    let retry = f.link_as(&f.owner, LINK_KEY).await;
    assert_eq!(retry.status, 200);
    assert!(link == retry.body, "the original link must be immutable");
    assert_eq!(link["operator_id"], f.owner.id);
    assert_eq!(link["operation_id"], f.binding.grant.operation_id);
    assert_eq!(
        link["expires_at_ms"].as_u64(),
        Some(f.binding.expires_at_ms)
    );
    let id = link["id"].as_str().unwrap();
    assert_eq!(id.len(), 64);
    let input = link["input_path"].as_str().unwrap();
    assert!(input.starts_with("/?kind=fleet&id="), "{input}");
    assert!(input.contains(link["metadata_sig"].as_str().unwrap()));
    assert!(input.contains(link["submit_sig"].as_str().unwrap()));
    assert_ne!(link["metadata_sig"], link["submit_sig"]);
    assert_eq!(
        f.link_as(&f.owner, "scoped-source-link-changed-001")
            .await
            .status,
        409
    );
    assert_eq!(f.rows("fleet_provisioning_links").await, 1);
    assert_eq!(f.audits("fleet.provisioning_link_created").await, 1);
    assert!(f.delivery().await.is_empty());
}

#[tokio::test]
async fn link_waits_for_the_published_offer_and_never_before_authority_exists() {
    let f = Fixture::build(183, true, 30_000, false).await;
    let pending = f.link_as(&f.owner, LINK_KEY).await;
    assert_eq!(pending.status, 409);
    assert_eq!(pending.body["error"], "provisioning_offer_pending");
    assert_eq!(f.rows("fleet_provisioning_links").await, 0);
    assert_eq!(f.publish_offer().await.body["accepted"], 1);
    assert_eq!(f.link_as(&f.owner, LINK_KEY).await.status, 201);
}

#[tokio::test]
async fn automatic_allow_uses_independent_destination_administrator_as_named_owner() {
    let f = Fixture::new(198, false).await;
    let second = f.h.create_operator("second-admin", "admin").await;
    assert_eq!(f.link_as(&f.owner, LINK_KEY).await.status, 403);
    assert_eq!(f.link_as(&second, LINK_KEY).await.status, 403);
    let created = f.link_as(&f.h.admin, LINK_KEY).await;
    assert_eq!(created.status, 201);
    assert_eq!(created.body["operator_id"], f.h.admin.id);
    let metadata =
        f.h.get(&f.h.admin, &Fixture::path(&created.body, "metadata"))
            .await;
    assert_eq!(metadata.status, 200);
    // The link names one administrator: another cannot read or submit with it.
    assert_eq!(
        f.h.get(&second, &Fixture::path(&created.body, "metadata"))
            .await
            .status,
        403
    );
    let accepted = f
        .submit_as(&f.h.admin, &created.body, &f.sealed(SOURCE))
        .await;
    assert_eq!(accepted.status, 201);
    assert_eq!(f.delivery().await.len(), 1);
}

// ---------------------------------------------------------------- S02 / S03

#[tokio::test]
async fn metadata_requires_named_cookie_fleet_scope_and_never_consumes_on_read() {
    let f = Fixture::new(182, true).await;
    let link = f.link().await;
    let path = Fixture::path(&link, "metadata");
    for _ in 0..3 {
        let result = f.h.get(&f.owner, &path).await;
        assert_eq!(result.status, 200);
        assert_eq!(result.body["status"], "ready");
    }
    assert_eq!(f.h.request("GET", &path, &[], None).await.status, 401);
    assert_eq!(f.h.get(&f.h.admin, &path).await.status, 403);
    let id = link["id"].as_str().unwrap();
    let bare = format!("/api/v3/fleet/provisioning/{id}/metadata");
    assert_eq!(f.h.get(&f.owner, &bare).await.status, 403);
    let wrong_scope = format!("{bare}?sig={}", link["submit_sig"].as_str().unwrap());
    assert_eq!(f.h.get(&f.owner, &wrong_scope).await.status, 403);
    // A genuine legacy exchange capability (same id, expiry, scope and root)
    // is refused: the fleet capability uses a distinct derived domain.
    let legacy =
        sign_browser_payload(id, seconds(&link), BrowserScope::Metadata, ROOT_SECRET).unwrap();
    assert_eq!(
        f.h.get(&f.owner, &format!("{bare}?sig={legacy}"))
            .await
            .status,
        403
    );
    let legacy_submit =
        sign_browser_payload(id, seconds(&link), BrowserScope::Submit, ROOT_SECRET).unwrap();
    let legacy_path = format!("/api/v3/fleet/provisioning/{id}/submit?sig={legacy_submit}");
    let attempt =
        f.h.call(&f.owner, "POST", &legacy_path, &[], Some(&f.sealed(SOURCE)))
            .await;
    assert_eq!(attempt.status, 403);
    // The controller's capability is exactly the independently derived one.
    let independent = Fixture::capability(&link, BrowserScope::Metadata, seconds(&link));
    assert_eq!(independent, link["metadata_sig"]);
    let foreign = sign_fleet_provisioning_capability(
        id,
        seconds(&link),
        BrowserScope::Metadata,
        b"another-root-secret-32-bytes!!!!",
    )
    .unwrap();
    assert_eq!(
        f.h.get(&f.owner, &format!("{bare}?sig={foreign}"))
            .await
            .status,
        403
    );
    // Reads write nothing: no receipt, delivery or submission audit.
    f.assert_no_submission().await;
    assert_eq!(f.audits("fleet.provisioning_link_created").await, 1);
}

#[tokio::test]
async fn metadata_returns_independently_verified_expected_values_for_the_original_offer() {
    let f = Fixture::new(184, true).await;
    let link = f.link().await;
    let result = f.metadata(&link).await;
    assert_eq!(result.status, 200);
    assert_eq!(result.body["status"], "ready");
    assert_eq!(result.body["offer"], f.offer);
    let expected = &result.body["expected"];
    let mut keys: Vec<_> = expected.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "credential",
            "grant",
            "node_key_version",
            "signing_public",
            "source_unit"
        ]
    );
    assert_eq!(
        expected["signing_public"],
        base64_url_encode(f.node.keys.signing.public_key())
    );
    assert_eq!(expected["source_unit"], UNIT);
    assert_eq!(expected["credential"], CREDENTIAL);
    assert_eq!(expected["node_key_version"], 1);
    let grant = Grant::from_value(&parse_json(&expected["grant"].to_string()).unwrap()).unwrap();
    assert_eq!(grant, f.binding.grant);
    assert!(result.body["server_time_ms"].as_i64().unwrap() > 0);
    assert_eq!(result.body["expires_at_ms"], link["expires_at_ms"]);
    assert_eq!(result.body["summary"]["purpose"], "read approved report");
    // The response verifies exactly as the browser library would verify it.
    let offer = SignedEnvelope::from_json(&result.body["offer"].to_string()).unwrap();
    let verified = verify_browser_recipient_offer(
        &offer,
        &base64_url_decode(expected["signing_public"].as_str().unwrap(), 32).unwrap(),
        &grant,
        expected["node_key_version"].as_u64().unwrap(),
        result.body["server_time_ms"].as_u64().unwrap(),
        expected["source_unit"].as_str().unwrap(),
        expected["credential"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(verified, f.binding);
}

#[tokio::test]
async fn a_stored_offer_that_disagrees_with_independent_state_is_never_served() {
    let f = Fixture::new(185, true).await;
    let link = f.link().await;
    // Replace the stored original offer with one signed by a foreign key and
    // with one for another destination: neither may be presented as trusted.
    let foreign = Ed25519KeyPair::from_seed(&[77; 32]).unwrap();
    let mut other = f.binding.clone();
    other.credential = "attacker-source".into();
    for replacement in [
        offer_body(&f.binding, &foreign),
        offer_body(&other, &f.node.keys.signing),
    ] {
        f.h.execute(
            "UPDATE fleet_provisioning_offers SET offer_json=?",
            vec![Bind::Text(replacement.to_string())],
        )
        .await;
        assert_eq!(f.metadata(&link).await.status, 410);
        assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 410);
    }
    f.assert_no_submission().await;
}

// ---------------------------------------------------------------- S04

#[tokio::test]
async fn invalid_ciphertext_scope_csrf_and_oversize_get_fixed_safe_errors() {
    let f = Fixture::new(186, true).await;
    let link = f.link().await;
    let valid = f.sealed(SOURCE);
    let path = Fixture::path(&link, "submit");
    assert_eq!(f.submit_as(&f.h.admin, &link, &valid).await.status, 403);
    let no_csrf = [
        ("cookie", f.owner.cookies.as_str()),
        ("content-type", "application/json"),
    ];
    assert_eq!(
        f.h.request("POST", &path, &no_csrf, Some(&valid))
            .await
            .status,
        403
    );
    assert_eq!(
        f.h.request(
            "POST",
            &path,
            &[("content-type", "application/json")],
            Some(&valid)
        )
        .await
        .status,
        401
    );
    let wrong = path.replace(
        link["submit_sig"].as_str().unwrap(),
        link["metadata_sig"].as_str().unwrap(),
    );
    assert_eq!(
        f.h.call(&f.owner, "POST", &wrong, &[], Some(&valid))
            .await
            .status,
        403
    );
    let plaintext = std::str::from_utf8(SOURCE).unwrap();
    for bad in [
        json!({"enc": "short", "ciphertext": "invalid"}),
        json!({"enc": valid["enc"], "ciphertext": "A".repeat(100_000)}),
        json!({"enc": valid["enc"], "ciphertext": valid["ciphertext"], "source": plaintext}),
        json!({"enc": plaintext, "ciphertext": valid["ciphertext"]}),
        json!({"enc": 42, "ciphertext": valid["ciphertext"]}),
        json!({"enc": valid["enc"]}),
        json!({"enc": valid["enc"], "ciphertext": ""}),
        json!({"enc": valid["enc"], "ciphertext": format!("{}=", valid["ciphertext"].as_str().unwrap())}),
        json!([plaintext]),
    ] {
        let result = f.submit(&link, &bad).await;
        assert_eq!(result.status, 400, "{bad}");
        assert!(!result.body.to_string().contains(CANARY));
        assert!(
            result.body["error"]
                .as_str()
                .unwrap()
                .starts_with("invalid_")
        );
    }
    let malformed =
        f.h.request(
            "POST",
            &path,
            &[
                ("cookie", f.owner.cookies.as_str()),
                ("origin", support::ORIGIN),
                ("x-csrf-token", f.owner.csrf.as_str()),
                ("content-type", "application/json"),
            ],
            Some(&Value::String(format!("{{\"enc\":\"{CANARY}"))),
        )
        .await;
    assert_eq!(malformed.status, 400);
    assert!(!malformed.body.to_string().contains(CANARY));
    let oversize = json!({"enc": valid["enc"], "ciphertext": "A".repeat(200_000)});
    let refused = f.submit(&link, &oversize).await;
    assert_eq!(refused.status, 413);
    // The controller's global 413 normalization applies to this route too.
    assert_eq!(refused.body["error"], "Payload Too Large");
    assert!(!refused.body.to_string().contains("AAAA"));
    f.assert_no_submission().await;
    assert_eq!(f.submit(&link, &valid).await.status, 201);
}

// ---------------------------------------------------------------- S05

#[tokio::test]
async fn concurrent_encrypted_submit_commits_one_original_receipt_and_signed_delivery() {
    let f = Fixture::new(187, true).await;
    let link = f.link().await;
    let body = f.sealed(SOURCE);
    let (a, b, c) = tokio::join!(
        f.submit(&link, &body),
        f.submit(&link, &body),
        f.submit(&link, &body)
    );
    let mut statuses = [a.status, b.status, c.status];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 200, 201]);
    assert!(
        a.body == b.body && b.body == c.body,
        "the exact receipt must be immutable"
    );
    let documents = f.delivery().await;
    assert_eq!(documents.len(), 1);
    assert_eq!(f.rows("fleet_provisioning_receipts").await, 1);
    assert_eq!(f.audits("fleet.source_submitted").await, 1);
    let envelope = SignedEnvelope::from_json(&documents[0].to_string()).unwrap();
    assert!(
        envelope
            .verify(f.h.issuer.public_key(), &f.h.issuer_key_id, 1)
            .unwrap()
    );
    assert_eq!(envelope.kind(), DocumentKind::ProvisioningDelivery);
    assert_eq!(envelope.epoch(), f.binding.grant.issuer_epoch);
    let delivery = BrowserProvisioningDelivery::from_value(envelope.body()).unwrap();
    assert_eq!(delivery.binding, f.binding);
    let (enc, ciphertext) = delivery.sealed_bytes().unwrap();
    let opened = f
        .recipient
        .open(&enc, &ciphertext, &delivery.binding.aad().unwrap())
        .unwrap();
    assert!(
        opened.as_bytes() == SOURCE,
        "the exact dummy Source must survive encryption"
    );
    let receipt = &a.body;
    assert_eq!(receipt["status"], "submitted");
    assert_eq!(receipt["offer_id"], f.binding.offer_id);
    let stored =
        f.h.strings(
            "SELECT delivery_digest FROM fleet_provisioning_receipts",
            vec![],
        )
        .await;
    assert_eq!(stored[0].as_deref(), receipt["delivery_digest"].as_str());
    // A conflicting ciphertext, a later retry and a metadata read change nothing.
    let changed = f.sealed(b"another dummy Source");
    let conflict = f.submit(&link, &changed).await;
    assert_eq!(conflict.status, 409);
    assert_eq!(conflict.body["error"], "provisioning_ciphertext_conflict");
    assert!(f.delivery().await == documents);
    assert!(f.submit(&link, &body).await.body == a.body);
    assert_eq!(f.metadata(&link).await.body["status"], "submitted");
    assert_eq!(f.rows("fleet_provisioning_receipts").await, 1);
    assert_eq!(f.audits("fleet.source_submitted").await, 1);
}

#[tokio::test]
async fn chained_browser_equivalent_flow_delivers_exact_source_to_the_node_inbox() {
    // Signed browser grant -> offer ingestion -> link -> metadata -> seal in
    // Rust from the metadata response alone -> submit -> signed delivery.
    let f = Fixture::new(188, true).await;
    let link = f.link().await;
    let metadata = f.metadata(&link).await;
    assert_eq!(metadata.status, 200);
    let expected = &metadata.body["expected"];
    let grant = Grant::from_value(&parse_json(&expected["grant"].to_string()).unwrap()).unwrap();
    let offer = SignedEnvelope::from_json(&metadata.body["offer"].to_string()).unwrap();
    let binding = verify_browser_recipient_offer(
        &offer,
        &base64_url_decode(expected["signing_public"].as_str().unwrap(), 32).unwrap(),
        &grant,
        expected["node_key_version"].as_u64().unwrap(),
        metadata.body["server_time_ms"].as_u64().unwrap(),
        expected["source_unit"].as_str().unwrap(),
        expected["credential"].as_str().unwrap(),
    )
    .unwrap();
    let recipient_public = base64_url_decode(&binding.recipient_public, 32).unwrap();
    let sealed =
        RecipientKeyPair::seal(&recipient_public, SOURCE, &binding.aad().unwrap()).unwrap();
    let body = json!({
        "enc": base64_url_encode(&sealed.enc),
        "ciphertext": base64_url_encode(&sealed.ciphertext)
    });
    let submitted = f.submit(&link, &body).await;
    assert_eq!(submitted.status, 201);
    let documents = f.delivery().await;
    assert_eq!(documents.len(), 1);
    let envelope = SignedEnvelope::from_json(&documents[0].to_string()).unwrap();
    // The broker's pin is the controller issuer key and the original epoch.
    assert!(
        envelope
            .verify(
                f.h.issuer.public_key(),
                &f.h.issuer_key_id,
                grant.issuer_epoch
            )
            .unwrap()
    );
    let delivery = BrowserProvisioningDelivery::from_value(envelope.body()).unwrap();
    assert_eq!(delivery.binding, binding);
    assert_eq!(delivery.enc, body["enc"]);
    assert_eq!(delivery.ciphertext, body["ciphertext"]);
    let (enc, ciphertext) = delivery.sealed_bytes().unwrap();
    let opened = RecipientKeyPair::from_private_key(&f.private_key)
        .unwrap()
        .open(&enc, &ciphertext, &delivery.binding.aad().unwrap())
        .unwrap();
    assert!(opened.as_bytes() == SOURCE);
    // The delivery is authenticated to this exact binding: another AAD fails.
    let mut changed = delivery.binding.clone();
    changed.credential = "attacker-source".into();
    assert!(
        f.recipient
            .open(&enc, &ciphertext, &changed.aad().unwrap())
            .is_err()
    );
}

// ---------------------------------------------------------------- S06

#[tokio::test]
async fn receipt_survives_a_real_server_restart_and_never_requeues_after_inbox_loss() {
    let mut f = Fixture::new(189, true).await;
    let link = f.link().await;
    let body = f.sealed(SOURCE);
    let original = f.submit(&link, &body).await;
    assert_eq!(original.status, 201);
    let delivery = f.delivery().await;
    assert_eq!(delivery.len(), 1);
    let signature = delivery[0]["sig"].clone();
    // A new HTTP server over a fresh store connection, not a second handle.
    f.h.restart_server().await;
    let reopened = f.submit(&link, &body).await;
    assert_eq!(reopened.status, 200);
    assert!(
        original.body == reopened.body,
        "the receipt must survive the restart unchanged"
    );
    assert!(f.delivery().await == delivery);
    assert_eq!(f.delivery().await[0]["sig"], signature);
    let again = f.h.get(&f.owner, &Fixture::path(&link, "metadata")).await;
    assert_eq!(again.status, 200);
    assert_eq!(again.body["status"], "submitted");
    assert_eq!(f.link_as(&f.owner, LINK_KEY).await.body["id"], link["id"]);
    // The node acknowledges and the inbox row is pruned; the grant is later
    // consumed. Neither reconstructs a delivery or renews authority.
    f.h.execute(
        "DELETE FROM node_inbox WHERE envelope_json LIKE '%\"kind\":\"provisioning_delivery\"%'",
        vec![],
    )
    .await;
    f.h.execute(
        "UPDATE grants SET status='consumed',consumed_at=issued_at",
        vec![],
    )
    .await;
    f.h.execute("UPDATE operations SET status='executing'", vec![])
        .await;
    let retry = f.submit(&link, &body).await;
    assert_eq!(retry.status, 200);
    assert!(original.body == retry.body);
    assert!(f.delivery().await.is_empty());
    assert_eq!(f.rows("fleet_provisioning_receipts").await, 1);
    assert_eq!(f.metadata(&link).await.body["status"], "submitted");
    assert_eq!(
        f.submit(&link, &f.sealed(b"another dummy")).await.status,
        409
    );
    // A fresh store handle sees the same durable state.
    let store = Store::connect(&f.h.database_url).await.unwrap();
    assert_eq!(store.tenant_id(), f.h.store.tenant_id());
    assert_eq!(f.rows("fleet_provisioning_links").await, 1);
}

async fn failure(f: &Fixture, table: &str, remove: bool) {
    assert!(
        [
            "fleet_provisioning_links",
            "fleet_provisioning_receipts",
            "node_inbox",
            "audit_events"
        ]
        .contains(&table)
    );
    if matches!(f.h.backend, Backend::Postgres(_)) {
        if remove {
            f.h.execute(
                &format!("DROP TRIGGER p05_submit_failure ON {table}"),
                vec![],
            )
            .await;
            f.h.execute("DROP FUNCTION p05_submit_failure()", vec![])
                .await;
        } else {
            f.h.execute(
                "CREATE FUNCTION p05_submit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'P05 dummy storage failure'; END $$",
                vec![],
            )
            .await;
            f.h.execute(
                &format!("CREATE TRIGGER p05_submit_failure BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION p05_submit_failure()"),
                vec![],
            )
            .await;
        }
    } else if remove {
        f.h.execute("DROP TRIGGER p05_submit_failure", vec![]).await;
    } else {
        f.h.execute(
            &format!("CREATE TRIGGER p05_submit_failure BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'P05 dummy storage failure'); END"),
            vec![],
        )
        .await;
    }
}

#[tokio::test]
async fn link_write_failures_roll_back_every_effect_and_retry() {
    for (index, table) in ["fleet_provisioning_links", "audit_events"]
        .into_iter()
        .enumerate()
    {
        let f = Fixture::new(200 + u8::try_from(index).unwrap(), true).await;
        failure(&f, table, false).await;
        assert_eq!(f.link_as(&f.owner, LINK_KEY).await.status, 503);
        assert_eq!(f.rows("fleet_provisioning_links").await, 0);
        assert_eq!(f.audits("fleet.provisioning_link_created").await, 0);
        failure(&f, table, true).await;
        assert_eq!(f.link_as(&f.owner, LINK_KEY).await.status, 201);
        assert_eq!(f.rows("fleet_provisioning_links").await, 1);
    }
}

#[tokio::test]
async fn delivery_write_failures_roll_back_every_effect_and_retry() {
    for (index, table) in ["fleet_provisioning_receipts", "node_inbox", "audit_events"]
        .into_iter()
        .enumerate()
    {
        let f = Fixture::new(203 + u8::try_from(index).unwrap(), true).await;
        let link = f.link().await;
        let body = f.sealed(SOURCE);
        failure(&f, table, false).await;
        assert_eq!(f.submit(&link, &body).await.status, 503, "{table}");
        f.assert_no_submission().await;
        failure(&f, table, true).await;
        assert_eq!(f.submit(&link, &body).await.status, 201);
        assert_eq!(f.rows("fleet_provisioning_receipts").await, 1);
        assert_eq!(f.delivery().await.len(), 1);
        assert_eq!(f.audits("fleet.source_submitted").await, 1);
    }
}

// ---------------------------------------------------------------- S07

#[tokio::test]
async fn current_authority_and_destination_version_gate_metadata_and_fresh_submit() {
    let cases = [
        "UPDATE grants SET status='consumed'",
        "UPDATE grants SET status='revoked'",
        "UPDATE grants SET status='expired'",
        "UPDATE operations SET status='cancelled'",
        "UPDATE operations SET status='executing'",
        "UPDATE workloads SET registration_version=registration_version+1",
        "UPDATE workloads SET status='revoked'",
        "UPDATE workloads SET account='uid:1002'",
        "UPDATE fleet_policies SET version=version+1",
        "UPDATE fleet_source_bindings SET version=version+1",
        "UPDATE fleet_source_bindings SET credential='changed-source'",
        "UPDATE controller_meta SET issuer_epoch=issuer_epoch+1",
        "DELETE FROM node_inbox WHERE envelope_json LIKE '%\"kind\":\"grant\"%'",
        "UPDATE fleet_provisioning_offers SET expires_at=issued_at+1",
        "UPDATE fleet_provisioning_links SET expires_at=created_at+1",
        "UPDATE nodes SET status='revoked'",
        "INSERT INTO node_revocation_queue (node_id,created_at) SELECT id,0 FROM nodes",
    ];
    for (index, sql) in cases.into_iter().enumerate() {
        let f = Fixture::new(100 + u8::try_from(index).unwrap(), true).await;
        let link = f.link().await;
        f.h.execute(sql, vec![]).await;
        assert_eq!(f.metadata(&link).await.status, 410, "{sql}");
        assert_eq!(
            f.submit(&link, &f.sealed(SOURCE)).await.status,
            410,
            "{sql}"
        );
        if !sql.contains("fleet_provisioning_links") {
            assert_eq!(f.link_as(&f.owner, LINK_KEY).await.status, 410, "{sql}");
        }
        f.assert_no_submission().await;
    }
}

#[tokio::test]
async fn node_key_rotation_withdraws_link_authority_for_a_new_key_version() {
    let f = Fixture::new(125, true).await;
    let link = f.link().await;
    let next = support::NodeKeys::from_seed(126);
    let rotated =
        f.h.call(
            &f.h.admin,
            "POST",
            &format!("/api/v3/nodes/{}/rotate-key", f.node.id),
            &[],
            Some(&json!({
                "expected_key_version": 1, "expected_fingerprint": next.fingerprint(),
                "signing_pub": base64_url_encode(next.signing.public_key()),
                "recipient_pub": base64_url_encode(next.recipient.public_key())
            })),
        )
        .await;
    assert_eq!(rotated.status, 202);
    assert_eq!(f.metadata(&link).await.status, 410);
    assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 410);
    f.assert_no_submission().await;
}

#[tokio::test]
async fn operator_session_logout_removal_and_role_change_withdraw_fresh_submission() {
    // Logout.
    let f = Fixture::new(127, true).await;
    let link = f.link().await;
    f.h.execute(
        "UPDATE operators SET role='viewer' WHERE id=?",
        vec![Bind::Text(f.owner.id.clone())],
    )
    .await;
    assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 403);
    assert_eq!(f.metadata(&link).await.status, 403);
    f.h.execute(
        "UPDATE operators SET role='operator' WHERE id=?",
        vec![Bind::Text(f.owner.id.clone())],
    )
    .await;
    assert_eq!(
        f.h.call(&f.owner, "POST", "/api/v3/admin/session/logout", &[], None)
            .await
            .status,
        204
    );
    assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 401);
    assert_eq!(f.metadata(&link).await.status, 401);
    f.assert_no_submission().await;
    // A fresh login of the same named operator may continue.
    let again =
        f.h.login(
            &f.owner.id,
            &f.owner.username,
            &format!("{}-test-password-long", f.owner.username),
        )
        .await;
    assert_eq!(
        f.submit_as(&again, &link, &f.sealed(SOURCE)).await.status,
        201
    );

    // Removal.
    let f = Fixture::new(128, true).await;
    let link = f.link().await;
    let removed =
        f.h.call(
            &f.h.admin,
            "DELETE",
            &format!("/api/v3/admin/operators/{}", f.owner.id),
            &[],
            None,
        )
        .await;
    assert!(
        removed.status == 204 || removed.status == 200,
        "{:?}",
        removed.body
    );
    assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 401);
    assert_eq!(f.metadata(&link).await.status, 401);
    f.assert_no_submission().await;
}

#[tokio::test]
async fn password_change_and_reset_end_older_sessions_before_fresh_submission() {
    let f = Fixture::new(129, true).await;
    let link = f.link().await;
    let password = format!("{}-test-password-long", f.owner.username);
    let second = f.h.login(&f.owner.id, &f.owner.username, &password).await;
    let changed =
        f.h.call(
            &second,
            "POST",
            "/api/v3/admin/session/change-password",
            &[],
            Some(
                &json!({"current_password": password, "new_password": "a-new-long-owner-password"}),
            ),
        )
        .await;
    assert_eq!(changed.status, 204);
    assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 401);
    assert_eq!(f.metadata(&link).await.status, 401);
    f.assert_no_submission().await;
    // An administrator reset forces a new password: the session that was
    // active at the change is withdrawn too.
    let reset =
        f.h.call(
            &f.h.admin,
            "POST",
            &format!("/api/v3/admin/operators/{}/reset-password", f.owner.id),
            &[],
            None,
        )
        .await;
    assert!(
        reset.status == 200 || reset.status == 201,
        "{:?}",
        reset.body
    );
    let denied = f.submit_as(&second, &link, &f.sealed(SOURCE)).await;
    assert!(
        denied.status == 401 || denied.status == 403,
        "{}",
        denied.status
    );
    f.assert_no_submission().await;
}

#[tokio::test]
async fn expired_capability_link_and_offer_deny_without_a_receipt() {
    let f = Fixture::new(130, true).await;
    let link = f.link().await;
    let id = link["id"].as_str().unwrap();
    // A genuine fleet capability whose own expiry passed is gone (410); a
    // forged expired token never learns that (403).
    let expired = Fixture::capability(&link, BrowserScope::Metadata, 1);
    let path = format!("/api/v3/fleet/provisioning/{id}/metadata?sig={expired}");
    assert_eq!(f.h.get(&f.owner, &path).await.status, 410);
    let forged = sign_fleet_provisioning_capability(
        id,
        1,
        BrowserScope::Metadata,
        b"another-root-secret-32-bytes!!!!",
    )
    .unwrap();
    let forged_path = format!("/api/v3/fleet/provisioning/{id}/metadata?sig={forged}");
    assert_eq!(f.h.get(&f.owner, &forged_path).await.status, 403);
    let submit_expired = Fixture::capability(&link, BrowserScope::Submit, 1);
    let submit_path = format!("/api/v3/fleet/provisioning/{id}/submit?sig={submit_expired}");
    let denied =
        f.h.call(&f.owner, "POST", &submit_path, &[], Some(&f.sealed(SOURCE)))
            .await;
    assert_eq!(denied.status, 410);
    f.assert_no_submission().await;
}

#[tokio::test]
async fn real_time_expiry_of_the_original_deadline_denies_metadata_and_submit() {
    let f = Fixture::build(131, true, 2_000, true).await;
    let link = f.link().await;
    assert_eq!(f.metadata(&link).await.status, 200);
    let remaining = link["expires_at_ms"].as_i64().unwrap() - f.h.now_ms().await;
    tokio::time::sleep(Duration::from_millis(
        u64::try_from(remaining.max(0)).unwrap() + 150,
    ))
    .await;
    assert_eq!(f.metadata(&link).await.status, 410);
    assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 410);
    f.assert_no_submission().await;
}

#[tokio::test]
async fn lock_wait_cannot_extend_the_original_link_and_offer_deadline() {
    // The lifetime leaves setup headroom on a loaded host (an expired link
    // would make the wait vacuous) yet keeps the held lock below the store's
    // five second busy timeout, which would deny at the session check instead.
    let f = Fixture::build(132, true, 4_000, true).await;
    let link = f.link().await;
    let body = f.sealed(SOURCE);
    let remaining = link["expires_at_ms"].as_i64().unwrap() - f.h.now_ms().await;
    assert!(
        remaining > 500,
        "the host was too loaded to hold the lock before the deadline: {remaining} ms left"
    );
    let wait = u64::try_from(remaining).unwrap() + 400;
    // SQLite serializes writers before the first clock sample; PostgreSQL
    // waits later, on the authority rows. Both branches run real submission.
    match &f.h.backend {
        Backend::Postgres(pool) => {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SELECT id FROM workloads WHERE id=$1 FOR UPDATE")
                .bind(&f.binding.grant.workload_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            let submit = f.submit(&link, &body);
            let unlock = async {
                tokio::time::sleep(Duration::from_millis(wait)).await;
                tx.rollback().await.unwrap();
            };
            let (reply, ()) = tokio::join!(submit, unlock);
            assert_eq!(reply.status, 410, "{}", reply.body);
        }
        Backend::Sqlite(pool) => {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("UPDATE workloads SET version=version WHERE id=?")
                .bind(&f.binding.grant.workload_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            let submit = f.submit(&link, &body);
            let unlock = async {
                tokio::time::sleep(Duration::from_millis(wait)).await;
                tx.rollback().await.unwrap();
            };
            let (reply, ()) = tokio::join!(submit, unlock);
            assert_eq!(reply.status, 410, "{}", reply.body);
        }
    }
    f.assert_no_submission().await;
}

// ---------------------------------------------------------------- S08

#[tokio::test]
async fn full_64k_source_stays_encrypted_in_the_dedicated_signed_delivery() {
    let f = Fixture::new(133, true).await;
    let link = f.link().await;
    let source = vec![b'z'; 65_536];
    let body = f.sealed(&source);
    assert_eq!(f.submit(&link, &body).await.status, 201);
    let documents = f.delivery().await;
    assert_eq!(documents.len(), 1);
    let encoded = documents[0].to_string();
    assert!(
        encoded.len() > 65_536 && encoded.len() <= 131_072,
        "{}",
        encoded.len()
    );
    let delivery = BrowserProvisioningDelivery::from_value(
        SignedEnvelope::from_json(&encoded).unwrap().body(),
    )
    .unwrap();
    let (enc, ciphertext) = delivery.sealed_bytes().unwrap();
    let opened = f
        .recipient
        .open(&enc, &ciphertext, &delivery.binding.aad().unwrap())
        .unwrap();
    assert!(
        opened.as_bytes() == source.as_slice(),
        "the complete dummy bytes must decrypt exactly"
    );
    // Every other node document keeps the 64 KiB cap.
    for entry in f.h.inbox(&f.node.id).await {
        if entry["kind"] != "provisioning_delivery" {
            assert!(entry.to_string().len() <= 65_536, "{}", entry["kind"]);
        }
    }
    assert_eq!(DocumentKind::Grant.max_document_bytes(), 65_536);
    assert_eq!(
        DocumentKind::ProvisioningDelivery.max_document_bytes(),
        131_072
    );
    // One byte over the Source limit cannot even be sealed into a valid body.
    let oversize = f.sealed(&source);
    let too_long = json!({
        "enc": oversize["enc"],
        "ciphertext": format!("{}AAAA", oversize["ciphertext"].as_str().unwrap())
    });
    assert_eq!(f.submit(&link, &too_long).await.status, 400);
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One process-wide capture. A scoped per-test subscriber is unreliable here:
/// with a single registered dispatcher, tracing evaluates a callsite first hit
/// by another test thread against that thread's (empty) default and caches
/// "never", so the request events would sometimes vanish from the capture.
fn captured_logs() -> LogBuffer {
    static LOGS: OnceLock<LogBuffer> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = LogBuffer::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("this test binary installs the only global subscriber");
        logs
    })
    .clone()
}

async fn stored_text(h: &Harness) -> String {
    match &h.backend {
        Backend::Postgres(_) => {
            let tables = h
                .strings(
                    "SELECT tablename::text FROM pg_tables WHERE schemaname=current_schema()",
                    vec![],
                )
                .await;
            let mut text = String::new();
            for table in tables.into_iter().flatten() {
                for row in h
                    .strings(&format!("SELECT t::text FROM \"{table}\" t"), vec![])
                    .await
                    .into_iter()
                    .flatten()
                {
                    text.push_str(&row);
                    text.push('\n');
                }
            }
            text
        }
        Backend::Sqlite(_) => {
            let database = h.directory.file("controller.db");
            let mut bytes = std::fs::read(&database).unwrap_or_default();
            for suffix in ["-wal", "-shm"] {
                let mut name = database.clone().into_os_string();
                name.push(suffix);
                bytes.extend(std::fs::read(name).unwrap_or_default());
            }
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }
}

#[tokio::test]
async fn source_private_key_link_and_cookie_canaries_never_reach_storage_audit_or_logs() {
    let logs = captured_logs();
    let f = Fixture::new(134, true).await;
    let link = f.link().await;
    let body = f.sealed(SOURCE);
    let replies = [
        f.metadata(&link).await.body.to_string(),
        f.submit(&link, &body).await.body.to_string(),
        f.submit(&link, &body).await.body.to_string(),
        f.submit(&link, &f.sealed(b"another dummy Source"))
            .await
            .body
            .to_string(),
        f.submit(&link, &json!({"enc": CANARY, "ciphertext": CANARY}))
            .await
            .body
            .to_string(),
        f.metadata(&link).await.body.to_string(),
    ];
    let audit = f
        .h
        .strings(
            "SELECT action || ' ' || COALESCE(target_id, '') || ' ' || metadata_json FROM audit_events",
            vec![],
        )
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
    let stored = stored_text(&f.h).await;
    let logged = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    assert!(!logged.is_empty(), "the log capture must observe requests");
    assert!(audit.contains("fleet.source_submitted"));
    assert!(audit.contains("fleet.provisioning_link_created"));
    // The ciphertext digest is the only ciphertext-derived audit field.
    assert!(audit.contains("ciphertext_digest"));
    let private_key = private_key_text(&f.private_key);
    let capabilities = [
        link["metadata_sig"].as_str().unwrap(),
        link["submit_sig"].as_str().unwrap(),
        link["id"].as_str().unwrap(),
    ];
    // Plaintext and the offer private key appear nowhere at all.
    for secret in [CANARY, private_key.as_str()] {
        for (place, text) in [("audit", &audit), ("storage", &stored), ("logs", &logged)] {
            assert!(!text.contains(secret), "{place} leaked a canary");
        }
        for reply in &replies {
            assert!(!reply.contains(secret));
        }
    }
    // Link capabilities, the session token and the CSRF secret are never
    // stored (CSRF is stored by design), audited or logged.
    let session = session_token(&f.owner);
    for secret in capabilities.iter().copied().chain([session.as_str()]) {
        assert!(!audit.contains(secret), "audit leaked a capability");
        assert!(!logged.contains(secret), "logs leaked a capability");
        if secret != capabilities[2] {
            assert!(!stored.contains(secret), "storage leaked a capability");
        }
    }
    assert!(!audit.contains(&f.owner.csrf));
    assert!(!logged.contains(&f.owner.csrf));
}

// ---------------------------------------------------------------- S09

async fn drop_table(h: &Harness, table: &str) {
    h.execute(&format!("DROP TABLE {table}"), vec![]).await;
}

#[tokio::test]
async fn schema_16_migrates_additively_and_keeps_rows_across_a_version_rollback_marker() {
    let f = Fixture::new(135, true).await;
    let link = f.link().await;
    assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 201);
    // Rolling the marker back to 15 and forward again is idempotent and loses
    // no link, receipt, offer, destination or session.
    f.h.execute(
        "UPDATE controller_meta SET schema_version=15 WHERE id=1",
        vec![],
    )
    .await;
    let forward = Store::connect(&f.h.database_url).await.unwrap();
    assert_eq!(f.rows("fleet_provisioning_links").await, 1);
    assert_eq!(f.rows("fleet_provisioning_receipts").await, 1);
    assert!(
        forward
            .source_binding(&f.node.id, "report-primary")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT CAST(schema_version AS BIGINT) FROM controller_meta WHERE id=1",
            vec![]
        )
        .await,
        i64::from(16_u8)
    );
    assert_eq!(f.h.get(&f.owner, "/api/v3/admin/session").await.status, 200);
    // A database that predates version 16 gains the tables and keeps 15 data.
    drop_table(&f.h, "fleet_provisioning_links").await;
    drop_table(&f.h, "fleet_provisioning_receipts").await;
    f.h.execute(
        "UPDATE controller_meta SET schema_version=15 WHERE id=1",
        vec![],
    )
    .await;
    let migrated = Store::connect(&f.h.database_url).await.unwrap();
    assert_eq!(f.rows("fleet_provisioning_links").await, 0);
    assert_eq!(f.rows("fleet_provisioning_receipts").await, 0);
    assert!(
        migrated
            .source_binding(&f.node.id, "report-primary")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM fleet_provisioning_offers", vec![])
            .await,
        1
    );
    // A newer-than-supported marker is refused and changes nothing.
    f.h.execute(
        "UPDATE controller_meta SET schema_version=17 WHERE id=1",
        vec![],
    )
    .await;
    assert!(matches!(
        Store::connect(&f.h.database_url).await,
        Err(StoreError::UnsupportedSchemaVersion)
    ));
}

#[tokio::test]
async fn damaged_provisioning_tables_fail_closed_by_missing_table_and_by_wrong_columns() {
    // (version marker, table, replacement definition)
    let wrong_shape = [
        (16, "fleet_provisioning_links", "(id TEXT PRIMARY KEY)"),
        (
            16,
            "fleet_provisioning_receipts",
            "(link_id TEXT PRIMARY KEY)",
        ),
        (16, "fleet_provisioning_offers", "(id TEXT PRIMARY KEY)"),
        (16, "fleet_source_bindings", "(tenant_id TEXT)"),
        (15, "fleet_provisioning_offers", "(id TEXT PRIMARY KEY)"),
        (15, "fleet_source_bindings", "(tenant_id TEXT)"),
        // A pre-existing wrong 0016 table survives the idempotent migration of
        // a version 15 database; the marker is never advanced over it.
        (
            15,
            "fleet_provisioning_receipts",
            "(link_id TEXT PRIMARY KEY)",
        ),
        (14, "fleet_provisioning_links", "(id TEXT PRIMARY KEY)"),
    ];
    for (version, table, definition) in wrong_shape {
        let h = Harness::start().await;
        h.execute(&format!("DROP TABLE {table}"), vec![]).await;
        h.execute(&format!("CREATE TABLE {table} {definition}"), vec![])
            .await;
        h.execute(
            &format!("UPDATE controller_meta SET schema_version={version} WHERE id=1"),
            vec![],
        )
        .await;
        assert!(
            matches!(
                Store::connect(&h.database_url).await,
                Err(StoreError::UnsupportedSchemaVersion)
            ),
            "{table} at {version} must be refused as damaged"
        );
        assert_eq!(
            h.scalar_i64(
                "SELECT CAST(schema_version AS BIGINT) FROM controller_meta WHERE id=1",
                vec![]
            )
            .await,
            i64::from(version),
            "a damaged database keeps its marker"
        );
    }
    for table in [
        "fleet_provisioning_links",
        "fleet_provisioning_receipts",
        "fleet_provisioning_offers",
        "fleet_source_bindings",
    ] {
        let h = Harness::start().await;
        h.execute(&format!("DROP TABLE {table}"), vec![]).await;
        assert!(
            matches!(
                Store::connect(&h.database_url).await,
                Err(StoreError::UnsupportedSchemaVersion)
            ),
            "a missing {table} at the current version is damage"
        );
    }
}

#[tokio::test]
async fn expired_links_and_receipts_prune_after_seven_days_but_live_ones_are_never_evicted() {
    let f = Fixture::new(136, true).await;
    let link = f.link().await;
    assert_eq!(f.submit(&link, &f.sealed(SOURCE)).await.status, 201);
    let pruned = f.h.store.prune_fleet_state().await.unwrap();
    assert_eq!(
        (pruned.provisioning_links, pruned.provisioning_receipts),
        (0, 0)
    );
    assert_eq!(f.rows("fleet_provisioning_links").await, 1);
    assert_eq!(f.rows("fleet_provisioning_receipts").await, 1);
    // Expired a day ago is still inside the seven day retention window.
    let now = f.h.now_ms().await;
    let day = 24 * 60 * 60 * 1_000;
    f.h.execute(
        "UPDATE fleet_provisioning_links SET created_at=?",
        vec![Bind::Int(now - 2 * day)],
    )
    .await;
    for table in ["fleet_provisioning_links", "fleet_provisioning_receipts"] {
        f.h.execute(
            &format!("UPDATE {table} SET expires_at=?"),
            vec![Bind::Int(now - day)],
        )
        .await;
    }
    let pruned = f.h.store.prune_fleet_state().await.unwrap();
    assert_eq!(
        (pruned.provisioning_links, pruned.provisioning_receipts),
        (0, 0)
    );
    assert_eq!(f.rows("fleet_provisioning_links").await, 1);
    // Eight days past expiry both rows go, in one bounded pass each.
    f.h.execute(
        "UPDATE fleet_provisioning_links SET created_at=?",
        vec![Bind::Int(now - 9 * day)],
    )
    .await;
    for table in ["fleet_provisioning_links", "fleet_provisioning_receipts"] {
        f.h.execute(
            &format!("UPDATE {table} SET expires_at=?"),
            vec![Bind::Int(now - 8 * day)],
        )
        .await;
    }
    let pruned = f.h.store.prune_fleet_state().await.unwrap();
    assert_eq!(
        (pruned.provisioning_links, pruned.provisioning_receipts),
        (1, 1)
    );
    assert_eq!(f.rows("fleet_provisioning_links").await, 0);
    assert_eq!(f.rows("fleet_provisioning_receipts").await, 0);
}
