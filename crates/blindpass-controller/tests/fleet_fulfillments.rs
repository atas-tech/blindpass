// SPDX-License-Identifier: AGPL-3.0-only

//! P10 cross-workload fulfillment on the controller: policy, named approvers,
//! fingerprint-bound approval, verified relay of one-use offers and
//! issuer-signed submissions, expiry, revocation and rollback. The tests play
//! both brokers with the real core protocol; every credential is a dummy.
//! Scenario ids follow the P10 acceptance plan.

mod support;

use blindpass_controller::store::{FleetSigner, Store};
use blindpass_core::canon::{Value as CanonValue, canonicalize_value};
use blindpass_core::custody::EphemeralCustody;
use blindpass_core::fleet::{DocumentKind, SignedEnvelope};
use blindpass_core::fulfillment::{
    FulfillmentAuthorization, FulfillmentDelivery, FulfillmentOffer, FulfillmentResult,
    FulfillmentRevocation, FulfillmentSide, FulfillmentTerms, ResultState, fulfillment_aad,
    fulfillment_info, seal_submit, sign_offer, verify_offer,
};
use blindpass_core::signing::base64_url_encode;
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use support::{FleetNode, Harness, HttpResponse, ISSUER_SEED, Operator, signed_event};

const SECRET: &[u8] = b"DUMMY-P10-CONTROLLER-CREDENTIAL-01";
const ENABLED: &[(&str, &str)] = &[("BLINDPASS_FULFILLMENTS_ENABLED", "1")];

fn plain(value: &CanonValue) -> Value {
    serde_json::from_slice(&canonicalize_value(value).unwrap()).unwrap()
}

fn cross_rule(id: &str, decision: &str, approvers: &[&str], issuer: &Value, recipient: &Value) -> Value {
    let mut rule = json!({
        "id": id,
        "issuer_workload_ids": [issuer["id"]],
        "recipient_workload_ids": [recipient["id"]],
        "decision": decision,
        "max_ttl_seconds": 300,
    });
    if !approvers.is_empty() {
        rule["approver_ids"] = json!(approvers);
    }
    rule
}

struct World {
    h: Harness,
    issuer_node: FleetNode,
    recipient_node: FleetNode,
    issuer_wl: Value,
    recipient_wl: Value,
    requester: Operator,
    approver: Operator,
    counter: std::cell::Cell<u32>,
}

/// One live fulfillment's brokers, as the tests drive them.
struct Flow {
    id: String,
    terms: FulfillmentTerms,
    custody: EphemeralCustody,
    offer_id: String,
    offer: Option<(FulfillmentOffer, SignedEnvelope)>,
}

impl World {
    async fn start(extra: &[(&str, &str)]) -> Self {
        let h = Harness::start_with(extra).await;
        let issuer_node = h.online_node("issuer-node", 71).await;
        let recipient_node = h.online_node("recipient-node", 73).await;
        let requester = h.create_operator("fulfill-requester", "operator").await;
        let approver = h.create_operator("fulfill-approver", "operator").await;
        let issuer = h
            .create_workload(&issuer_node.id, "issuer-app", "issuer-app.service", "issuer", "file")
            .await;
        assert_eq!(issuer.status, 201, "{}", issuer.body);
        let recipient = h
            .create_workload(
                &recipient_node.id,
                "recipient-app",
                "recipient-app.service",
                "recipient",
                "file",
            )
            .await;
        assert_eq!(recipient.status, 201, "{}", recipient.body);
        Self {
            h,
            issuer_node,
            recipient_node,
            issuer_wl: issuer.body,
            recipient_wl: recipient.body,
            requester,
            approver,
            counter: std::cell::Cell::new(0),
        }
    }

    /// A world whose policy asks `approver` to approve the issuer/recipient pair.
    async fn with_approval() -> Self {
        let world = Self::start(ENABLED).await;
        let rule = cross_rule(
            "cross-approve",
            "pending_approval",
            &[world.approver.username.as_str()],
            &world.issuer_wl,
            &world.recipient_wl,
        );
        let set = world.set_cross(json!([rule])).await;
        assert_eq!(set.status, 200, "{}", set.body);
        world
    }

    async fn with_allow() -> Self {
        let world = Self::start(ENABLED).await;
        let rule = cross_rule("cross-allow", "allow", &[], &world.issuer_wl, &world.recipient_wl);
        let set = world.set_cross(json!([rule])).await;
        assert_eq!(set.status, 200, "{}", set.body);
        world
    }

    fn next(&self) -> u32 {
        self.counter.set(self.counter.get() + 1);
        self.counter.get()
    }

    async fn set_cross(&self, cross: Value) -> HttpResponse {
        let current = self.h.get(&self.h.admin, "/api/v3/policies").await;
        assert_eq!(current.status, 200, "{}", current.body);
        let version = current.body["version"].as_i64().unwrap();
        let if_match = format!("\"{version}\"");
        self.h
            .call(
                &self.h.admin,
                "PUT",
                "/api/v3/policies",
                &[("if-match", if_match.as_str())],
                Some(&json!({
                    "expected_version": version,
                    "rules": current.body["rules"],
                    "cross_workload": cross,
                })),
            )
            .await
    }

    fn body_for(&self, purpose: &str) -> Value {
        json!({
            "issuer_workload_id": self.issuer_wl["id"],
            "recipient_workload_id": self.recipient_wl["id"],
            "issuer_credential": "api-token",
            "recipient_credential": "api-token",
            "purpose": purpose,
        })
    }

    async fn create_with(&self, operator: &Operator, key: &str, body: &Value) -> HttpResponse {
        self.h
            .call(
                operator,
                "POST",
                "/api/v3/fulfillments",
                &[("idempotency-key", key)],
                Some(body),
            )
            .await
    }

    async fn create(&self, key: &str) -> HttpResponse {
        self.create_with(&self.requester, key, &self.body_for("rotate the dummy api token"))
            .await
    }

    async fn show(&self, id: &str) -> Value {
        let response = self
            .h
            .get(&self.h.admin, &format!("/api/v3/fulfillments/{id}"))
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
        response.body
    }

    async fn status(&self, id: &str) -> String {
        self.show(id).await["status"].as_str().unwrap().to_owned()
    }

    async fn approve_as(&self, operator: &Operator, id: &str) -> HttpResponse {
        let detail = self.show(id).await;
        self.decide_with(
            operator,
            id,
            "approve",
            detail["version"].as_i64().unwrap(),
            Some((
                detail["issuer"]["fingerprint"].as_str().unwrap().to_owned(),
                detail["recipient"]["fingerprint"].as_str().unwrap().to_owned(),
            )),
        )
        .await
    }

    async fn decide_with(
        &self,
        operator: &Operator,
        id: &str,
        verb: &str,
        version: i64,
        fingerprints: Option<(String, String)>,
    ) -> HttpResponse {
        let if_match = format!("\"{version}\"");
        let mut body = json!({"expected_version": version});
        if let Some((issuer, recipient)) = fingerprints {
            body["issuer_fingerprint"] = json!(issuer);
            body["recipient_fingerprint"] = json!(recipient);
        }
        self.h
            .call(
                operator,
                "POST",
                &format!("/api/v3/fulfillments/{id}/{verb}"),
                &[("if-match", if_match.as_str())],
                Some(&body),
            )
            .await
    }

    /// Create, approve and return the id of an approved fulfillment.
    async fn approved(&self) -> String {
        let created = self.create("idem-approved-0001-aaaa").await;
        assert_eq!(created.status, 201, "{}", created.body);
        let id = created.body["id"].as_str().unwrap().to_owned();
        if created.body["status"] == "approved" {
            return id;
        }
        let approved = self.approve_as(&self.approver, &id).await;
        assert_eq!(approved.status, 200, "{}", approved.body);
        assert_eq!(approved.body["status"], "approved");
        id
    }

    /// Controller documents of one kind queued for a node, signature-checked.
    async fn documents(&self, node: &FleetNode, kind: &str) -> Vec<SignedEnvelope> {
        let public = self.h.issuer.public_key().to_vec();
        self.h
            .inbox(&node.id)
            .await
            .into_iter()
            .filter(|envelope| envelope["kind"] == kind)
            .map(|envelope| {
                let parsed = SignedEnvelope::from_json(&envelope.to_string()).unwrap();
                assert!(parsed.verify(&public, &self.h.issuer_key_id, 1).unwrap());
                parsed
            })
            .collect()
    }

    async fn flow(&self, id: &str) -> Flow {
        let documents = self
            .documents(&self.recipient_node, "fulfillment_authorization")
            .await;
        let authorization = documents
            .iter()
            .map(|envelope| FulfillmentAuthorization::from_value(envelope.body()).unwrap())
            .find(|authorization| authorization.terms.fulfillment_id == id)
            .expect("recipient authorization queued");
        assert_eq!(authorization.side, FulfillmentSide::Recipient);
        assert!(authorization.offer.is_none());
        let n = self.next();
        Flow {
            id: id.to_owned(),
            terms: authorization.terms,
            custody: EphemeralCustody::new(Duration::from_secs(120)),
            offer_id: format!("fo_p10controller{n:08}"),
            offer: None,
        }
    }

    async fn now(&self) -> u64 {
        u64::try_from(self.h.now_ms().await).unwrap()
    }

    async fn post(&self, node: &FleetNode, key: &str, kind: &str, body: Value) -> HttpResponse {
        let events = signed_event(&node.id, &node.keys.signing, key, kind, body);
        let response = self.h.post_events(&node.bearer, &events).await;
        assert_eq!(response.status, 200, "{}", response.body);
        response
    }

    fn offer_for(&self, flow: &mut Flow, now: u64) -> (FulfillmentOffer, SignedEnvelope) {
        let public = flow.custody.provision(&flow.offer_id).unwrap();
        let offer = FulfillmentOffer {
            fulfillment_id: flow.id.clone(),
            terms_digest: flow.terms.digest_hex().unwrap(),
            offer_id: flow.offer_id.clone(),
            node_id: flow.terms.recipient.node_id.clone(),
            node_key_version: flow.terms.recipient.key_version,
            recipient_public: base64_url_encode(&public),
            issued_at_ms: now,
            expires_at_ms: (now + 120_000).min(flow.terms.expires_at_ms),
        };
        let envelope = sign_offer(&offer, &self.recipient_node.keys.signing).unwrap();
        (offer, envelope)
    }

    /// The recipient broker mints its one-use key and sends the signed offer.
    async fn send_offer(&self, flow: &mut Flow, key: &str) -> HttpResponse {
        let now = self.now().await;
        let (offer, envelope) = self.offer_for(flow, now);
        let body: Value = serde_json::from_slice(&envelope.to_json().unwrap()).unwrap();
        flow.offer = Some((offer, envelope));
        self.post(&self.recipient_node, key, "fulfillment_offer", body)
            .await
    }

    /// The issuer broker seals the dummy credential to the offered key.
    fn sealed_submit(&self, flow: &Flow, now: u64) -> SignedEnvelope {
        let (offer, envelope) = flow.offer.as_ref().expect("offer sent");
        let verified = verify_offer(envelope, &flow.terms, now).unwrap();
        assert_eq!(&verified, offer);
        seal_submit(
            &flow.terms,
            &verified,
            SECRET,
            &self.issuer_node.keys.signing,
            now,
        )
        .unwrap()
    }

    async fn send_submit(&self, flow: &Flow, key: &str) -> HttpResponse {
        let now = self.now().await;
        let envelope = self.sealed_submit(flow, now);
        let body: Value = serde_json::from_slice(&envelope.to_json().unwrap()).unwrap();
        self.post(&self.issuer_node, key, "fulfillment_submit", body)
            .await
    }

    async fn send_result(
        &self,
        flow: &Flow,
        key: &str,
        side: FulfillmentSide,
        state: ResultState,
        code: Option<&str>,
    ) -> HttpResponse {
        let node = match side {
            FulfillmentSide::Issuer => &self.issuer_node,
            FulfillmentSide::Recipient => &self.recipient_node,
        };
        let result = FulfillmentResult {
            fulfillment_id: flow.id.clone(),
            terms_digest: flow.terms.digest_hex().unwrap(),
            side,
            state,
            code: code.map(str::to_owned),
            observed_at_ms: self.now().await,
        };
        self.post(node, key, "fulfillment_result", plain(&result.to_value().unwrap()))
            .await
    }

    /// Bring an approved fulfillment to `available`: offer, issuer
    /// authorization, submit and queued delivery.
    async fn to_available(&self, id: &str) -> Flow {
        let mut flow = self.flow(id).await;
        let offered = self.send_offer(&mut flow, "offer-flow-0001-aaaa").await;
        assert_eq!(offered.body["accepted"], 1, "{}", offered.body);
        assert_eq!(self.status(id).await, "offered");
        let submitted = self.send_submit(&flow, "submit-flow-0001-aaaa").await;
        assert_eq!(submitted.body["accepted"], 1, "{}", submitted.body);
        assert_eq!(self.status(id).await, "available");
        flow
    }

    async fn count(&self, sql: &str) -> i64 {
        self.h.scalar_i64(sql, vec![]).await
    }

    fn signing_store(&self) -> Store {
        self.h.store.clone().with_fleet_signer(FleetSigner::new(Arc::new(
            Ed25519KeyPair::from_seed(&[ISSUER_SEED; 32]).unwrap(),
        )))
    }

    async fn expire_now(&self, id: &str) {
        let past = self.h.now_ms().await - 1_000;
        self.h
            .execute(
                "UPDATE cross_fulfillments SET expires_at = ? WHERE id = ?",
                vec![past.into(), id.into()],
            )
            .await;
    }

    async fn revocations(&self, node: &FleetNode) -> Vec<FulfillmentRevocation> {
        self.documents(node, "fulfillment_revocation")
            .await
            .iter()
            .map(|envelope| FulfillmentRevocation::from_value(envelope.body()).unwrap())
            .collect()
    }
}

fn discarded_codes(response: &HttpResponse) -> Vec<String> {
    response.body["discarded"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item["error"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

// ------------------------------------------------------------------ P10-I01

#[tokio::test]
async fn p10_i01_unknown_pair_is_denied_and_nothing_is_queued() {
    let world = World::start(ENABLED).await;
    let denied = world.create("idem-denied-0001-aaaa").await;
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(denied.body["error"], "cross_workload_denied");
    let listed = world
        .h
        .get(&world.h.admin, "/api/v3/fulfillments?status=denied")
        .await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_eq!(listed.body["items"].as_array().unwrap().len(), 1);
    assert_eq!(listed.body["items"][0]["rule_id"], "default_deny");
    for node in [&world.issuer_node, &world.recipient_node] {
        for kind in [
            "fulfillment_authorization",
            "fulfillment_delivery",
            "fulfillment_revocation",
        ] {
            assert!(world.documents(node, kind).await.is_empty(), "{kind}");
        }
    }
    assert_eq!(
        world
            .count(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'fleet.fulfillment_requested'"
            )
            .await,
        1
    );
    // The replayed request answers the same refusal and writes no second row.
    let replay = world.create("idem-denied-0001-aaaa").await;
    assert_eq!(replay.status, 403);
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillments").await, 1);
}

#[tokio::test]
async fn p10_i01_rules_are_ordered_and_a_deny_rule_wins_when_first() {
    let world = World::start(ENABLED).await;
    let deny = cross_rule("cross-deny", "deny", &[], &world.issuer_wl, &world.recipient_wl);
    let allow = cross_rule("cross-allow", "allow", &[], &world.issuer_wl, &world.recipient_wl);
    let set = world.set_cross(json!([deny.clone(), allow.clone()])).await;
    assert_eq!(set.status, 200, "{}", set.body);
    let first_deny = world.create("idem-order-00001-aaaa").await;
    assert_eq!(first_deny.status, 403, "{}", first_deny.body);
    let set = world.set_cross(json!([allow, deny])).await;
    assert_eq!(set.status, 200, "{}", set.body);
    let allowed = world.create("idem-order-00002-aaaa").await;
    assert_eq!(allowed.status, 201, "{}", allowed.body);
    assert_eq!(allowed.body["status"], "approved");
    assert_eq!(allowed.body["rule_id"], "cross-allow");
    assert_eq!(allowed.body["approval"]["status"], "not_required");
    // `allow` issued the recipient authorization without an approver.
    assert_eq!(
        world
            .documents(&world.recipient_node, "fulfillment_authorization")
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn p10_i01_policy_selectors_are_explicit_ids_and_omitted_rules_are_kept() {
    let world = World::start(ENABLED).await;
    let good = cross_rule("cross-allow", "allow", &[], &world.issuer_wl, &world.recipient_wl);
    let mut wildcard = good.clone();
    wildcard["issuer_workload_ids"] = json!(["*"]);
    let mut empty = good.clone();
    empty["recipient_workload_ids"] = json!([]);
    let mut slow = good.clone();
    slow["max_ttl_seconds"] = json!(601);
    let mut pending = good.clone();
    pending["decision"] = json!("pending_approval");
    let mut approvers_on_allow = good.clone();
    approvers_on_allow["approver_ids"] = json!(["someone"]);
    let mut unknown_field = good.clone();
    unknown_field["mode"] = json!("provider_issue");
    let mut duplicate_selector = good.clone();
    duplicate_selector["issuer_workload_ids"] =
        json!([world.issuer_wl["id"], world.issuer_wl["id"]]);
    for (label, rule) in [
        ("wildcard", wildcard),
        ("empty recipients", empty),
        ("ttl above ceiling", slow),
        ("pending without approvers", pending),
        ("approvers on allow", approvers_on_allow),
        ("unknown field", unknown_field),
        ("duplicate selector", duplicate_selector),
    ] {
        let response = world.set_cross(json!([rule])).await;
        assert!(
            matches!(response.status, 400 | 422),
            "{label}: {} {}",
            response.status,
            response.body
        );
    }
    let duplicate_ids = world.set_cross(json!([good.clone(), good.clone()])).await;
    assert_eq!(duplicate_ids.status, 400, "{}", duplicate_ids.body);
    // Nothing invalid was stored: a request is still denied.
    assert_eq!(world.create("idem-select-0001-aaaa").await.status, 403);

    let set = world.set_cross(json!([good.clone()])).await;
    assert_eq!(set.status, 200, "{}", set.body);
    assert_eq!(set.body["cross_workload"].as_array().unwrap().len(), 1);
    // A PUT that omits `cross_workload` leaves the stored rules alone; the
    // existing `rules`-only clients keep working without dropping them.
    let current = world.h.get(&world.h.admin, "/api/v3/policies").await;
    let version = current.body["version"].as_i64().unwrap();
    let if_match = format!("\"{version}\"");
    let kept = world
        .h
        .call(
            &world.h.admin,
            "PUT",
            "/api/v3/policies",
            &[("if-match", if_match.as_str())],
            Some(&json!({"expected_version": version, "rules": []})),
        )
        .await;
    assert_eq!(kept.status, 200, "{}", kept.body);
    assert_eq!(kept.body["cross_workload"], json!([good.clone()]));
    // An explicit empty array removes every rule.
    let cleared = world.set_cross(json!([])).await;
    assert_eq!(cleared.status, 200, "{}", cleared.body);
    assert_eq!(cleared.body["cross_workload"], json!([]));
    assert_eq!(world.create("idem-select-0002-aaaa").await.status, 403);
    // A rule for other workloads never matches this pair.
    let other = json!({
        "id": "other-pair", "issuer_workload_ids": [world.recipient_wl["id"]],
        "recipient_workload_ids": [world.issuer_wl["id"]], "decision": "allow",
        "max_ttl_seconds": 60
    });
    assert_eq!(world.set_cross(json!([other])).await.status, 200);
    assert_eq!(world.create("idem-select-0003-aaaa").await.status, 403);
}

#[tokio::test]
async fn p10_i01_untrusted_fields_cannot_broaden_authority() {
    let world = World::with_allow().await;
    let base = world.body_for("rotate the dummy api token");
    let mut rejected = Vec::new();
    for (name, value) in [
        ("mode", json!("provider_issue")),
        ("node_id", json!(world.issuer_node.id)),
        ("approver_ids", json!(["fulfill-requester"])),
        ("tenant_id", json!("other-tenant")),
        ("recipient_key", json!("AAAA")),
        ("ttl_seconds", json!(600)),
    ] {
        let mut body = base.clone();
        body[name] = value;
        rejected.push((name, world.create_with(&world.requester, "idem-fields-0001-aaaa", &body).await));
    }
    for (name, response) in rejected {
        assert!(matches!(response.status, 400 | 422), "{name}: {}", response.body);
    }
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillments").await, 0);

    for (label, change) in [
        ("path traversal", ("issuer_credential", json!("../etc/passwd"))),
        ("hidden name", ("recipient_credential", json!(".hidden"))),
        ("space", ("issuer_credential", json!("api token"))),
        ("long name", ("issuer_credential", json!("a".repeat(129)))),
        ("empty purpose", ("purpose", json!("   "))),
        ("control character", ("purpose", json!("rotate\u{1b}[31m token"))),
        ("long purpose", ("purpose", json!("p".repeat(513)))),
        ("bad workload id", ("issuer_workload_id", json!("wl*"))),
        ("bad prior id", ("prior_fulfillment_id", json!("../x"))),
    ] {
        let mut body = base.clone();
        body[change.0] = change.1;
        let response = world.create_with(&world.requester, "idem-fields-0002-aaaa", &body).await;
        assert_eq!(response.status, 400, "{label}: {}", response.body);
    }
    let mut same = base.clone();
    same["recipient_workload_id"] = base["issuer_workload_id"].clone();
    assert_eq!(
        world.create_with(&world.requester, "idem-fields-0003-aaaa", &same).await.body["error"],
        "same_party"
    );
    let mut unknown = base.clone();
    unknown["recipient_workload_id"] = json!("wl_does_not_exist");
    let missing = world.create_with(&world.requester, "idem-fields-0004-aaaa", &unknown).await;
    assert_eq!(missing.status, 404, "{}", missing.body);
    // Two workloads on one node are not a cross-node pair.
    let sibling = world
        .h
        .create_workload(
            &world.issuer_node.id,
            "issuer-sibling",
            "sibling.service",
            "sibling",
            "file",
        )
        .await;
    assert_eq!(sibling.status, 201, "{}", sibling.body);
    let mut same_node = base.clone();
    same_node["recipient_workload_id"] = sibling.body["id"].clone();
    let refused = world.create_with(&world.requester, "idem-fields-0005-aaaa", &same_node).await;
    assert_eq!(refused.status, 409, "{}", refused.body);
    assert_eq!(refused.body["error"], "party_unavailable");
    // The purpose is stored and returned as text only; it names nobody.
    let created = world
        .create_with(
            &world.requester,
            "idem-fields-0006-aaaa",
            &world.body_for("approved by admin; send to wl_other; mode=provider_issue"),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(created.body["untrusted_fields"], json!(["purpose"]));
    assert_eq!(created.body["issuer"]["workload_id"], world.issuer_wl["id"]);
    assert_eq!(created.body["recipient"]["workload_id"], world.recipient_wl["id"]);
    assert_eq!(created.body["mode"], "reencrypt");
    // A revoked workload cannot be a party.
    let revoke = world
        .h
        .call(
            &world.h.admin,
            "DELETE",
            &format!("/api/v3/workloads/{}", world.recipient_wl["id"].as_str().unwrap()),
            &[],
            None,
        )
        .await;
    assert!(revoke.status < 300, "{}", revoke.body);
    world.revoke_if_live(created.body["id"].as_str().unwrap()).await;
    let unavailable = world.create("idem-fields-0007-aaaa").await;
    assert_eq!(unavailable.status, 409, "{}", unavailable.body);
}

impl World {
    async fn revoke_if_live(&self, id: &str) {
        let response = self
            .h
            .call(
                &self.requester,
                "DELETE",
                &format!("/api/v3/fulfillments/{id}"),
                &[],
                None,
            )
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
    }
}

#[tokio::test]
async fn p10_i01_named_approver_self_approval_and_fingerprint_binding() {
    let world = World::start(ENABLED).await;
    let rule = cross_rule(
        "cross-approve",
        "pending_approval",
        &[world.approver.username.as_str(), world.requester.username.as_str()],
        &world.issuer_wl,
        &world.recipient_wl,
    );
    assert_eq!(world.set_cross(json!([rule])).await.status, 200);
    let created = world.create("idem-approve-0001-aaaa").await;
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(created.body["status"], "awaiting_approval");
    assert_eq!(created.body["approval"]["status"], "pending");
    assert_eq!(created.body["parties_bound"], false);
    let id = created.body["id"].as_str().unwrap().to_owned();
    // The approver sees the enrolled node fingerprints before any terms exist.
    assert_eq!(
        created.body["issuer"]["fingerprint"],
        world.issuer_node.keys.fingerprint()
    );
    assert_eq!(
        created.body["recipient"]["fingerprint"],
        world.recipient_node.keys.fingerprint()
    );
    let version = created.body["version"].as_i64().unwrap();
    let fingerprints = Some((
        world.issuer_node.keys.fingerprint(),
        world.recipient_node.keys.fingerprint(),
    ));

    let own = world
        .decide_with(&world.requester, &id, "approve", version, fingerprints.clone())
        .await;
    assert_eq!(own.status, 403, "{}", own.body);
    assert_eq!(own.body["error"], "self_approval_denied");
    let unnamed = world
        .decide_with(&world.h.admin, &id, "approve", version, fingerprints.clone())
        .await;
    assert_eq!(unnamed.status, 403, "{}", unnamed.body);
    assert_eq!(unnamed.body["error"], "approval_scope_denied");
    let missing = world.decide_with(&world.approver, &id, "approve", version, None).await;
    assert_eq!(missing.status, 400, "{}", missing.body);
    assert_eq!(missing.body["error"], "fingerprints_required");
    let wrong = world
        .decide_with(
            &world.approver,
            &id,
            "approve",
            version,
            Some((world.recipient_node.keys.fingerprint(), world.issuer_node.keys.fingerprint())),
        )
        .await;
    assert_eq!(wrong.status, 409, "{}", wrong.body);
    assert_eq!(wrong.body["error"], "authorization_changed");
    let stale = world
        .decide_with(&world.approver, &id, "approve", version + 5, fingerprints.clone())
        .await;
    assert!(stale.status >= 400, "{}", stale.body);
    assert_eq!(world.status(&id).await, "awaiting_approval");
    assert!(
        world
            .documents(&world.recipient_node, "fulfillment_authorization")
            .await
            .is_empty()
    );

    let approved = world
        .decide_with(&world.approver, &id, "approve", version, fingerprints.clone())
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    assert_eq!(approved.body["status"], "approved");
    assert_eq!(approved.body["parties_bound"], true);
    assert_eq!(approved.body["approval"]["decided_by"], world.approver.id);
    let documents = world
        .documents(&world.recipient_node, "fulfillment_authorization")
        .await;
    assert_eq!(documents.len(), 1);
    let authorization = FulfillmentAuthorization::from_value(documents[0].body()).unwrap();
    assert_eq!(authorization.side, FulfillmentSide::Recipient);
    assert_eq!(authorization.terms.digest_hex().unwrap(), approved.body["terms_digest"].as_str().unwrap());
    assert_eq!(authorization.terms.issuer.fingerprint, world.issuer_node.keys.fingerprint());
    assert_eq!(authorization.terms.recipient.fingerprint, world.recipient_node.keys.fingerprint());
    assert_eq!(authorization.terms.issuer.node_id, world.issuer_node.id);
    assert_eq!(authorization.terms.recipient.node_id, world.recipient_node.id);
    assert_eq!(authorization.terms.recipient.workload_id, world.recipient_wl["id"].as_str().unwrap());
    assert!(authorization.terms.approval_reference.is_some());
    assert_eq!(authorization.terms.issuer_epoch, 1);
    assert!(authorization.terms.expires_at_ms - authorization.terms.issued_at_ms <= 300_000);
    // Neither the purpose nor the credential bytes are part of the signed terms.
    assert!(!String::from_utf8_lossy(&documents[0].to_json().unwrap()).contains("rotate the dummy"));
    // The issuer gets nothing until the recipient's offer arrives.
    assert!(
        world
            .documents(&world.issuer_node, "fulfillment_authorization")
            .await
            .is_empty()
    );
    // A replayed decision does not queue a second document, and a new
    // decision on a decided fulfillment conflicts.
    let replay = world
        .decide_with(&world.approver, &id, "approve", version, fingerprints.clone())
        .await;
    assert_eq!(replay.status, 200, "{}", replay.body);
    assert_eq!(
        world
            .documents(&world.recipient_node, "fulfillment_authorization")
            .await
            .len(),
        1
    );
    let late = world
        .decide_with(&world.approver, &id, "reject", version + 1, None)
        .await;
    assert_eq!(late.status, 409, "{}", late.body);
    assert!(
        world
            .count(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'fleet.fulfillment_decided'"
            )
            .await
            >= 3,
        "applied and denied decisions are audited"
    );
}

#[tokio::test]
async fn p10_i01_rejection_closes_without_authority() {
    let world = World::with_approval().await;
    let created = world.create("idem-reject-0001-aaaa").await;
    let id = created.body["id"].as_str().unwrap().to_owned();
    let version = created.body["version"].as_i64().unwrap();
    let rejected = world
        .decide_with(&world.approver, &id, "reject", version, None)
        .await;
    assert_eq!(rejected.status, 200, "{}", rejected.body);
    assert_eq!(rejected.body["status"], "denied");
    assert_eq!(rejected.body["approval"]["status"], "rejected");
    assert!(
        world
            .documents(&world.recipient_node, "fulfillment_authorization")
            .await
            .is_empty()
    );
    // The slot is free again.
    let again = world.create("idem-reject-0002-aaaa").await;
    assert_eq!(again.status, 201, "{}", again.body);
}

#[tokio::test]
async fn p10_i01_fulfillment_state_is_unreachable_from_other_modules() {
    // No exchange, grant, operation or provisioning code may read or write the
    // fulfillment tables; the store module is the only reader.
    fn walk(directory: &std::path::Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, hits);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                if text.contains("cross_fulfillment") {
                    hits.push(path.to_string_lossy().into_owned());
                }
            }
        }
    }
    let mut hits = Vec::new();
    walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut hits);
    hits.sort();
    let relative = hits
        .iter()
        .map(|path| path.split("/src/").nth(1).unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        relative,
        vec![
            "store/fulfillments.rs".to_owned(),
            "store/mod.rs".to_owned(),
            "store/recovery.rs".to_owned(),
        ],
        "only the fulfillment store, schema registration and recovery may name the tables"
    );
}

// ------------------------------------------------------------------ P10-I02

#[tokio::test]
async fn p10_i02_round_trip_has_exactly_one_legal_completion() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let mut flow = world.flow(&id).await;
    let offered = world.send_offer(&mut flow, "offer-trip-0001-aaaa").await;
    assert_eq!(offered.body["accepted"], 1, "{}", offered.body);
    assert_eq!(world.status(&id).await, "offered");
    // An exact replay is a duplicate and queues nothing new.
    let replay = world.send_offer_again(&flow, "offer-trip-0001-aaaa").await;
    assert_eq!(replay.body["duplicates"], 1, "{}", replay.body);
    let issuer_documents = world
        .documents(&world.issuer_node, "fulfillment_authorization")
        .await;
    assert_eq!(issuer_documents.len(), 1);
    let issuer_authorization = FulfillmentAuthorization::from_value(issuer_documents[0].body()).unwrap();
    assert_eq!(issuer_authorization.side, FulfillmentSide::Issuer);
    assert_eq!(
        issuer_authorization.offer.as_ref().unwrap().to_json().unwrap(),
        flow.offer.as_ref().unwrap().1.to_json().unwrap(),
        "the issuer is given the recipient broker's own signed offer"
    );

    let submitted = world.send_submit(&flow, "submit-trip-0001-aaaa").await;
    assert_eq!(submitted.body["accepted"], 1, "{}", submitted.body);
    assert_eq!(world.status(&id).await, "available");
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillment_payloads").await, 1);
    let deliveries = world
        .documents(&world.recipient_node, "fulfillment_delivery")
        .await;
    assert_eq!(deliveries.len(), 1);
    let delivery = FulfillmentDelivery::from_value(deliveries[0].body()).unwrap();
    let (offer, submit) = delivery.verify(world.now().await).unwrap();
    let (enc, ciphertext) = submit.sealed_bytes().unwrap();
    let plaintext = flow
        .custody
        .open_once_with_info(
            &offer.offer_id,
            &enc,
            &ciphertext,
            &fulfillment_info(&delivery.terms).unwrap(),
            &fulfillment_aad(&offer).unwrap(),
        )
        .unwrap();
    assert_eq!(plaintext.as_bytes(), SECRET);
    // The one-use key is spent: a second open of the same delivery fails.
    assert!(
        flow.custody
            .open_once_with_info(
                &offer.offer_id,
                &enc,
                &ciphertext,
                &fulfillment_info(&delivery.terms).unwrap(),
                &fulfillment_aad(&offer).unwrap(),
            )
            .is_err()
    );

    // A second submission, even a valid fresh seal, cannot add another delivery.
    let second = world.send_submit(&flow, "submit-trip-0002-aaaa").await;
    assert_eq!(discarded_codes(&second), vec!["invalid_node_event".to_owned()]);
    assert_eq!(
        world
            .documents(&world.recipient_node, "fulfillment_delivery")
            .await
            .len(),
        1
    );
    // The same key with different bytes is a conflict, not a replacement.
    let conflict = world.send_submit(&flow, "submit-trip-0001-aaaa").await;
    assert_eq!(discarded_codes(&conflict), vec!["event_idempotency_conflict".to_owned()]);

    let stored = world
        .send_result(&flow, "result-trip-0001-aaaa", FulfillmentSide::Recipient, ResultState::Stored, None)
        .await;
    assert_eq!(stored.body["accepted"], 1, "{}", stored.body);
    assert_eq!(world.status(&id).await, "recipient_consumed");
    assert_eq!(
        world.count("SELECT COUNT(*) FROM cross_fulfillment_payloads").await,
        0,
        "ciphertext is deleted once the recipient holds the credential"
    );
    let consumed = world
        .send_result(&flow, "result-trip-0002-aaaa", FulfillmentSide::Recipient, ResultState::Consumed, None)
        .await;
    assert_eq!(consumed.body["accepted"], 1, "{}", consumed.body);
    let done = world.show(&id).await;
    assert_eq!(done["status"], "completed");
    assert!(done["completed_at"].is_i64());
    assert_eq!(done["provider_revocation"], "unsupported");
    // A late result for a closed fulfillment is evidence only.
    let late = world
        .send_result(
            &flow,
            "result-trip-0003-aaaa",
            FulfillmentSide::Recipient,
            ResultState::Failed,
            Some("late_report"),
        )
        .await;
    assert_eq!(late.body["accepted"], 1, "{}", late.body);
    assert_eq!(world.status(&id).await, "completed");
    // No revocation was queued for a completed fulfillment.
    assert!(world.revocations(&world.recipient_node).await.is_empty());
    assert!(world.revocations(&world.issuer_node).await.is_empty());
    // The slot is free for the next fulfillment.
    let next = world.create("idem-next-000001-aaaa").await;
    assert_eq!(next.status, 201, "{}", next.body);
}

impl World {
    async fn send_offer_again(&self, flow: &Flow, key: &str) -> HttpResponse {
        let body: Value =
            serde_json::from_slice(&flow.offer.as_ref().unwrap().1.to_json().unwrap()).unwrap();
        self.post(&self.recipient_node, key, "fulfillment_offer", body).await
    }
}

#[tokio::test]
async fn p10_i02_controller_never_holds_plaintext_or_the_credential_name_in_signed_terms() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let flow = world.to_available(&id).await;
    let secret = std::str::from_utf8(SECRET).unwrap();
    let encoded = base64_url_encode(SECRET);
    for (table, column) in [
        ("cross_fulfillments", "terms_json"),
        ("cross_fulfillments", "offer_json"),
        ("cross_fulfillments", "purpose"),
        ("cross_fulfillment_payloads", "submit_json"),
        ("node_events", "body_json"),
        ("node_inbox", "envelope_json"),
        ("audit_events", "metadata_json"),
    ] {
        for needle in [secret, encoded.as_str()] {
            let hits = world
                .count(&format!(
                    "SELECT COUNT(*) FROM {table} WHERE {column} LIKE '%{needle}%'"
                ))
                .await;
            assert_eq!(hits, 0, "{table}.{column} contains plaintext");
        }
    }
    // The stored payload is exactly the issuer-signed envelope.
    let stored = world
        .h
        .strings(
            "SELECT submit_json FROM cross_fulfillment_payloads WHERE fulfillment_id = ?",
            vec![flow.id.clone().into()],
        )
        .await;
    let envelope = SignedEnvelope::from_json(stored[0].as_ref().unwrap()).unwrap();
    assert_eq!(envelope.kind(), DocumentKind::FulfillmentSubmit);
}

#[tokio::test]
async fn p10_i02_offer_substitution_is_discarded_and_nothing_advances() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let mut flow = world.flow(&id).await;
    let now = world.now().await;
    let (offer, valid) = world.offer_for(&mut flow, now);
    let as_body = |envelope: &SignedEnvelope| -> Value {
        serde_json::from_slice(&envelope.to_json().unwrap()).unwrap()
    };

    // Signed by the issuer node's key instead of the recipient node's.
    let wrong_signer = sign_offer(&offer, &world.issuer_node.keys.signing).unwrap();
    // Wrong terms digest, offering another fulfillment's authority.
    let mut other_digest = offer.clone();
    other_digest.terms_digest = "0".repeat(64);
    let wrong_digest = sign_offer(&other_digest, &world.recipient_node.keys.signing).unwrap();
    // Wrong node in the offer body.
    let mut other_node = offer.clone();
    other_node.node_id = world.issuer_node.id.clone();
    let wrong_node = sign_offer(&other_node, &world.recipient_node.keys.signing).unwrap();
    // An offer that expired before it was sent.
    let mut stale = offer.clone();
    stale.issued_at_ms = now - 100_000;
    stale.expires_at_ms = now - 10_000;
    let expired = sign_offer(&stale, &world.recipient_node.keys.signing).unwrap();
    // An offer whose window starts before the terms were issued.
    let mut early = offer.clone();
    early.issued_at_ms = flow.terms.issued_at_ms - 1_000;
    early.expires_at_ms = early.issued_at_ms + 60_000;
    let before_terms = sign_offer(&early, &world.recipient_node.keys.signing).unwrap();
    // An offer from the far future of the controller's clock.
    let mut future = offer.clone();
    future.issued_at_ms = now + 3_600_000;
    future.expires_at_ms = (future.issued_at_ms + 60_000).min(flow.terms.expires_at_ms + 3_600_000);
    let ahead = sign_offer(&future, &world.recipient_node.keys.signing).unwrap();

    let attempts = [
        ("wrong signer", &world.recipient_node, &wrong_signer),
        ("wrong digest", &world.recipient_node, &wrong_digest),
        ("wrong node in body", &world.recipient_node, &wrong_node),
        ("expired", &world.recipient_node, &expired),
        ("before the terms", &world.recipient_node, &before_terms),
        ("from the future", &world.recipient_node, &ahead),
        // A valid offer posted by the issuer node's session is not accepted either.
        ("wrong session", &world.issuer_node, &valid),
    ];
    for (index, (label, node, envelope)) in attempts.into_iter().enumerate() {
        let response = world
            .post(node, &format!("offer-bad-{index:04}-aaaa"), "fulfillment_offer", as_body(envelope))
            .await;
        assert_eq!(
            discarded_codes(&response),
            vec!["invalid_node_event".to_owned()],
            "{label}: {}",
            response.body
        );
        assert_eq!(world.status(&id).await, "approved", "{label}");
    }
    assert!(
        world
            .documents(&world.issuer_node, "fulfillment_authorization")
            .await
            .is_empty()
    );
    // The genuine offer still works afterwards.
    let ok = world
        .post(&world.recipient_node, "offer-good-0001-aaaa", "fulfillment_offer", as_body(&valid))
        .await;
    assert_eq!(ok.body["accepted"], 1, "{}", ok.body);
    // A second offer for the same fulfillment cannot replace the first.
    flow.offer_id = "fo_p10controller99999999".to_owned();
    let (_, second) = world.offer_for(&mut flow, now + 1);
    let replaced = world
        .post(&world.recipient_node, "offer-good-0002-aaaa", "fulfillment_offer", as_body(&second))
        .await;
    assert_eq!(discarded_codes(&replaced), vec!["invalid_node_event".to_owned()]);
    assert_eq!(
        world
            .documents(&world.issuer_node, "fulfillment_authorization")
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn p10_i02_submit_substitution_is_discarded_and_no_delivery_is_queued() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let mut flow = world.flow(&id).await;
    let sent = world.send_offer(&mut flow, "offer-sub-00001-aaaa").await;
    assert_eq!(sent.body["accepted"], 1, "{}", sent.body);
    let now = world.now().await;
    let valid = world.sealed_submit(&flow, now);
    let body_of = |envelope: &SignedEnvelope| -> Value {
        serde_json::from_slice(&envelope.to_json().unwrap()).unwrap()
    };
    let resigned = |field: &str, replacement: Value, key: &Ed25519KeyPair| -> Value {
        let mut body = plain(valid.body());
        body[field] = replacement;
        let canon = blindpass_core::canon::parse_json(&body.to_string()).unwrap();
        let envelope = SignedEnvelope::sign(
            DocumentKind::FulfillmentSubmit,
            canon,
            valid.key_id(),
            valid.epoch(),
            key,
        )
        .unwrap();
        body_of(&envelope)
    };
    let altered = |field: &str, replacement: Value| -> Value {
        let mut json = body_of(&valid);
        json["body"][field] = replacement;
        json
    };
    let issuer_key = &world.issuer_node.keys.signing;
    let attempts = vec![
        // Right body, signed by the recipient node's key.
        ("wrong signer", &world.issuer_node, resigned("offer_id", json!(flow.offer_id), &world.recipient_node.keys.signing)),
        // Another offer id (a different recipient key) under a valid signature.
        ("other offer", &world.issuer_node, resigned("offer_id", json!("fo_p10controller77777777"), issuer_key)),
        // Another terms digest.
        ("other digest", &world.issuer_node, resigned("terms_digest", json!("1".repeat(64)), issuer_key)),
        // Digest that does not match the ciphertext, and a flipped ciphertext:
        // neither can even be re-signed, so the bytes are altered after signing.
        ("ciphertext digest", &world.issuer_node, altered("ciphertext_digest", json!("2".repeat(64)))),
        ("ciphertext", &world.issuer_node, altered("ciphertext", json!("AAAA"))),
        ("enc", &world.issuer_node, altered("enc", json!("AAAA"))),
        // Another fulfillment's id.
        ("other fulfillment", &world.issuer_node, resigned("fulfillment_id", json!("fu_other_0123456789abcdef"), issuer_key)),
        // A valid submission posted by the recipient node's session.
        ("wrong session", &world.recipient_node, body_of(&valid)),
    ];
    for (index, (label, node, body)) in attempts.into_iter().enumerate() {
        let response = world
            .post(node, &format!("submit-bad-{index:03}-aaaa"), "fulfillment_submit", body)
            .await;
        assert_eq!(
            discarded_codes(&response),
            vec!["invalid_node_event".to_owned()],
            "{label}: {}",
            response.body
        );
        assert_eq!(world.status(&id).await, "offered", "{label}");
        assert_eq!(
            world.count("SELECT COUNT(*) FROM cross_fulfillment_payloads").await,
            0,
            "{label}"
        );
    }
    assert!(
        world
            .documents(&world.recipient_node, "fulfillment_delivery")
            .await
            .is_empty()
    );
    // The genuine submission is accepted exactly once afterwards.
    let ok = world
        .post(&world.issuer_node, "submit-good-001-aaaa", "fulfillment_submit", body_of(&valid))
        .await;
    assert_eq!(ok.body["accepted"], 1, "{}", ok.body);
    assert_eq!(world.status(&id).await, "available");
}

#[tokio::test]
async fn p10_i02_recipient_key_rotation_mid_flow_fails_closed() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let mut flow = world.flow(&id).await;
    assert_eq!(world.send_offer(&mut flow, "offer-rot-00001-aaaa").await.body["accepted"], 1);
    world
        .h
        .execute(
            "UPDATE nodes SET key_version = key_version + 1 WHERE id = ?",
            vec![world.recipient_node.id.clone().into()],
        )
        .await;
    let summary = world.signing_store().expire_fulfillments(true).await.unwrap();
    assert_eq!(summary.failed, 1);
    let closed = world.show(&id).await;
    assert_eq!(closed["status"], "failed");
    assert_eq!(closed["failure_code"], "node_key_rotated");
    assert_eq!(closed["provider_revocation"], "unsupported");
    // Both nodes are told, so neither side keeps usable state.
    for node in [&world.issuer_node, &world.recipient_node] {
        let revocations = world.revocations(node).await;
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].fulfillment_id, id);
        assert_eq!(revocations[0].node_id, node.id);
    }
    // The failed one no longer holds the slot, and no new submit lands.
    let late = world.send_submit(&flow, "submit-rot-00001-aaaa").await;
    assert_eq!(discarded_codes(&late), vec!["invalid_node_event".to_owned()]);
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillment_payloads").await, 0);
}

#[tokio::test]
async fn p10_i02_policy_workload_and_node_changes_fail_closed() {
    // Policy edited after approval.
    let world = World::with_approval().await;
    let id = world.approved().await;
    assert_eq!(world.set_cross(json!([])).await.status, 200);
    world.signing_store().expire_fulfillments(true).await.unwrap();
    let closed = world.show(&id).await;
    assert_eq!(closed["status"], "failed");
    assert_eq!(closed["failure_code"], "policy_changed");

    // Recipient workload revoked after approval.
    let world = World::with_approval().await;
    let id = world.approved().await;
    let revoke = world
        .h
        .call(
            &world.h.admin,
            "DELETE",
            &format!("/api/v3/workloads/{}", world.recipient_wl["id"].as_str().unwrap()),
            &[],
            None,
        )
        .await;
    assert!(revoke.status < 300, "{}", revoke.body);
    world.signing_store().expire_fulfillments(true).await.unwrap();
    assert_eq!(world.show(&id).await["failure_code"], "workload_changed");

    // Issuer node revoked after approval.
    let world = World::with_approval().await;
    let id = world.approved().await;
    world
        .h
        .execute(
            "UPDATE nodes SET status = 'revoked' WHERE id = ?",
            vec![world.issuer_node.id.clone().into()],
        )
        .await;
    world.signing_store().expire_fulfillments(true).await.unwrap();
    assert_eq!(world.show(&id).await["failure_code"], "node_revoked");
}

#[tokio::test]
async fn p10_i02_approval_after_policy_change_or_rotation_is_stale() {
    let world = World::with_approval().await;
    let created = world.create("idem-stale-00001-aaaa").await;
    let id = created.body["id"].as_str().unwrap().to_owned();
    let before = world.show(&id).await;
    // The policy changes while the approval is pending.
    let rule = cross_rule(
        "cross-approve-2",
        "pending_approval",
        &[world.approver.username.as_str()],
        &world.issuer_wl,
        &world.recipient_wl,
    );
    assert_eq!(world.set_cross(json!([rule])).await.status, 200);
    let stale = world.approve_as(&world.approver, &id).await;
    assert_eq!(stale.status, 409, "{}", stale.body);
    assert_eq!(stale.body["error"], "authorization_changed");
    assert!(world.documents(&world.recipient_node, "fulfillment_authorization").await.is_empty());
    assert_eq!(before["status"], "awaiting_approval");
}

// ------------------------------------------------------------------ P10-I04

#[tokio::test]
async fn p10_i04_idempotency_single_slot_and_revocation_before_approval() {
    let world = World::with_approval().await;
    let first = world.create("idem-slot-000001-aaaa").await;
    assert_eq!(first.status, 201, "{}", first.body);
    let id = first.body["id"].as_str().unwrap().to_owned();
    let replay = world.create("idem-slot-000001-aaaa").await;
    assert_eq!(replay.status, 200, "{}", replay.body);
    assert_eq!(replay.body["id"], id);
    let different = world
        .create_with(
            &world.requester,
            "idem-slot-000001-aaaa",
            &world.body_for("a different purpose"),
        )
        .await;
    assert_eq!(different.status, 409, "{}", different.body);
    assert_eq!(different.body["error"], "idempotency_conflict");
    let busy = world.create("idem-slot-000002-aaaa").await;
    assert_eq!(busy.status, 409, "{}", busy.body);
    assert_eq!(busy.body["error"], "recipient_busy");
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillments").await, 1);

    // Revoking before approval issues no authority and queues no revocation.
    let revoked = world
        .h
        .call(
            &world.requester,
            "DELETE",
            &format!("/api/v3/fulfillments/{id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(revoked.body["status"], "revoked");
    assert!(revoked.body["delivery_revoked_at"].is_null());
    assert!(world.revocations(&world.recipient_node).await.is_empty());
    // A second revoke is idempotent and the approve now conflicts.
    let again = world
        .h
        .call(&world.requester, "DELETE", &format!("/api/v3/fulfillments/{id}"), &[], None)
        .await;
    assert_eq!(again.status, 200);
    let fingerprints = Some((
        world.issuer_node.keys.fingerprint(),
        world.recipient_node.keys.fingerprint(),
    ));
    let version = revoked.body["version"].as_i64().unwrap();
    let late = world
        .decide_with(&world.approver, &id, "approve", version, fingerprints)
        .await;
    assert_eq!(late.status, 409, "{}", late.body);
    assert_eq!(world.status(&id).await, "revoked");
    assert_eq!(world.create("idem-slot-000003-aaaa").await.status, 201);
    let unknown = world
        .h
        .call(&world.requester, "DELETE", "/api/v3/fulfillments/fu_unknown_0001", &[], None)
        .await;
    assert_eq!(unknown.status, 404);
}

#[tokio::test]
async fn p10_i04_revoking_issued_authority_deletes_payload_and_tells_both_nodes() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let flow = world.to_available(&id).await;
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillment_payloads").await, 1);
    let revoked = world
        .h
        .call(&world.requester, "DELETE", &format!("/api/v3/fulfillments/{id}"), &[], None)
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(revoked.body["status"], "revoked");
    assert_eq!(revoked.body["revocation_reason"], "operator");
    assert!(revoked.body["delivery_revoked_at"].is_i64());
    assert_eq!(revoked.body["provider_revocation"], "unsupported");
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillment_payloads").await, 0);
    for node in [&world.issuer_node, &world.recipient_node] {
        let revocations = world.revocations(node).await;
        assert_eq!(revocations.len(), 1, "{}", node.id);
        assert_eq!(revocations[0].terms_digest, flow.terms.digest_hex().unwrap());
    }
    // A reported result after revocation cannot resurrect it.
    let late = world
        .send_result(&flow, "result-rev-0001-aaaa", FulfillmentSide::Recipient, ResultState::Stored, None)
        .await;
    assert_eq!(late.body["accepted"], 1, "{}", late.body);
    assert_eq!(world.status(&id).await, "revoked");
    let audit = world
        .count("SELECT COUNT(*) FROM audit_events WHERE action = 'fleet.fulfillment_revoked'")
        .await;
    assert_eq!(audit, 1);
}

#[tokio::test]
async fn p10_i04_unreported_delivery_becomes_uncertain_and_holds_the_slot() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let flow = world.to_available(&id).await;
    world.expire_now(&id).await;
    let closed = world.show(&id).await;
    assert_eq!(closed["status"], "uncertain");
    assert_eq!(closed["failure_code"], "no_recipient_result");
    assert_eq!(
        world.count("SELECT COUNT(*) FROM cross_fulfillment_payloads").await,
        0,
        "ciphertext is never re-served after expiry"
    );
    for node in [&world.issuer_node, &world.recipient_node] {
        assert_eq!(world.revocations(node).await.len(), 1);
    }
    // An unreconciled fulfillment keeps the recipient slot.
    let busy = world.create("idem-uncert-0001-aaaa").await;
    assert_eq!(busy.status, 409, "{}", busy.body);
    assert_eq!(busy.body["error"], "recipient_busy");
    // Listing again does not close it twice or add documents.
    assert_eq!(world.show(&id).await["status"], "uncertain");
    assert_eq!(world.revocations(&world.recipient_node).await.len(), 1);
    // The recipient's late "consumed" report proves the unit read it in time.
    let consumed = world
        .send_result(&flow, "result-unc-0002-aaaa", FulfillmentSide::Recipient, ResultState::Consumed, None)
        .await;
    assert_eq!(consumed.body["accepted"], 1, "{}", consumed.body);
    assert_eq!(world.status(&id).await, "completed");
    assert_eq!(world.create("idem-uncert-0002-aaaa").await.status, 201);
}

#[tokio::test]
async fn p10_i04_late_stored_report_closes_an_uncertain_fulfillment_as_expired() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let flow = world.to_available(&id).await;
    world.expire_now(&id).await;
    assert_eq!(world.status(&id).await, "uncertain");
    let stored = world
        .send_result(&flow, "result-unc-0001-aaaa", FulfillmentSide::Recipient, ResultState::Stored, None)
        .await;
    assert_eq!(stored.body["accepted"], 1, "{}", stored.body);
    let closed = world.show(&id).await;
    assert_eq!(closed["status"], "expired");
    assert_eq!(closed["failure_code"], "stored_not_consumed");
    // Revocations were sent when it became uncertain and are not repeated.
    assert_eq!(world.revocations(&world.recipient_node).await.len(), 1);
    assert_eq!(world.create("idem-uncert-0004-aaaa").await.status, 201);
}

#[tokio::test]
async fn p10_i04_operator_can_close_an_uncertain_fulfillment() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    world.to_available(&id).await;
    world.expire_now(&id).await;
    assert_eq!(world.status(&id).await, "uncertain");
    let revoked = world
        .h
        .call(&world.requester, "DELETE", &format!("/api/v3/fulfillments/{id}"), &[], None)
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(revoked.body["status"], "revoked");
    assert_eq!(world.create("idem-uncert-0003-aaaa").await.status, 201);
}

#[tokio::test]
async fn p10_i04_approved_but_never_offered_expires_with_revocation() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    world.expire_now(&id).await;
    let closed = world.show(&id).await;
    assert_eq!(closed["status"], "expired");
    assert!(closed["closed_at"].is_i64());
    assert_eq!(world.revocations(&world.recipient_node).await.len(), 1);
    // A late offer for an expired fulfillment is discarded.
    let mut flow = world.flow(&id).await;
    let late = world.send_offer(&mut flow, "offer-exp-00001-aaaa").await;
    assert_eq!(discarded_codes(&late), vec!["invalid_node_event".to_owned()]);
    // An unapproved request that nobody decides also expires and frees the slot.
    let created = world.create("idem-expire-0001-aaaa").await;
    let pending = created.body["id"].as_str().unwrap().to_owned();
    world.expire_now(&pending).await;
    assert_eq!(world.status(&pending).await, "expired");
    assert_eq!(world.create("idem-expire-0002-aaaa").await.status, 201);
}

#[tokio::test]
async fn p10_i04_a_failed_result_closes_the_fulfillment_for_both_sides() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let mut flow = world.flow(&id).await;
    assert_eq!(world.send_offer(&mut flow, "offer-fail-0001-aaaa").await.body["accepted"], 1);
    let failed = world
        .send_result(
            &flow,
            "result-fail-001-aaaa",
            FulfillmentSide::Issuer,
            ResultState::Failed,
            Some("source_missing"),
        )
        .await;
    assert_eq!(failed.body["accepted"], 1, "{}", failed.body);
    let closed = world.show(&id).await;
    assert_eq!(closed["status"], "failed");
    assert_eq!(closed["failure_code"], "source_missing");
    for node in [&world.issuer_node, &world.recipient_node] {
        assert_eq!(world.revocations(node).await.len(), 1);
    }
    // A result bound to other terms is refused.
    let mut other = world.flow(&id).await;
    other.terms.expires_at_ms += 1;
    let mismatch = world
        .send_result(&other, "result-fail-002-aaaa", FulfillmentSide::Issuer, ResultState::Failed, Some("x"))
        .await;
    assert_eq!(discarded_codes(&mismatch), vec!["invalid_node_event".to_owned()]);
}

// ------------------------------------------------------------------ P10-E02

#[tokio::test]
async fn p10_e02_disabled_feature_stops_issuance_and_revokes_outstanding_authority() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    world.to_available(&id).await;
    let pending_created = {
        // A second pair is impossible (one slot), so use the recipient's slot
        // for the live one and check the sweep result on it.
        id.clone()
    };
    let summary = world.signing_store().expire_fulfillments(false).await.unwrap();
    assert_eq!(summary.revoked, 1);
    let closed = world.show(&pending_created).await;
    assert_eq!(closed["status"], "revoked");
    assert_eq!(closed["revocation_reason"], "feature_disabled");
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillment_payloads").await, 0);
    for node in [&world.issuer_node, &world.recipient_node] {
        assert_eq!(world.revocations(node).await.len(), 1);
    }
    // Idempotent: a second pass closes nothing.
    assert_eq!(world.signing_store().expire_fulfillments(false).await.unwrap().revoked, 0);
}

#[tokio::test]
async fn p10_e02_a_controller_without_the_flag_refuses_everything_and_hides_the_capability() {
    let world = World::start(&[]).await;
    let capabilities = world.h.request("GET", "/api/v3/capabilities", &[], None).await;
    assert_eq!(capabilities.body["features"]["fleet_fulfillments"], false);
    let refused = world.create("idem-off-0000001-aaaa").await;
    assert_eq!(refused.status, 404, "{}", refused.body);
    assert_eq!(refused.body["error"], "fulfillments_disabled");
    // Node events of the new kinds are discarded, never applied.
    let flow_body = json!({
        "fulfillment_id": "fu_0123456789abcdefABCDEF",
        "terms_digest": "a".repeat(64),
        "side": "recipient", "state": "stored", "observed_at_ms": 1
    });
    let response = world
        .post(&world.recipient_node, "result-off-0001-aaaa", "fulfillment_result", flow_body)
        .await;
    assert_eq!(discarded_codes(&response), vec!["invalid_node_event".to_owned()]);
    // Reading still works, so lineage stays inspectable.
    let listed = world.h.get(&world.h.admin, "/api/v3/fulfillments").await;
    assert_eq!(listed.status, 200, "{}", listed.body);

    let enabled = World::start(ENABLED).await;
    let capabilities = enabled.h.request("GET", "/api/v3/capabilities", &[], None).await;
    assert_eq!(capabilities.body["features"]["fleet_fulfillments"], true);
}

#[tokio::test]
async fn p10_e02_roles_and_sessions_gate_every_route() {
    let world = World::with_approval().await;
    let viewer = world.h.create_operator("fulfill-viewer", "viewer").await;
    let anonymous = world.h.request("GET", "/api/v3/fulfillments", &[], None).await;
    assert_eq!(anonymous.status, 401);
    let denied = world.h.get(&viewer, "/api/v3/fulfillments").await;
    assert_eq!(denied.status, 403, "{}", denied.body);
    let create = world
        .create_with(&viewer, "idem-viewer-0001-aaaa", &world.body_for("x"))
        .await;
    assert_eq!(create.status, 403, "{}", create.body);
    let bad_status = world
        .h
        .get(&world.h.admin, "/api/v3/fulfillments?status=bogus")
        .await;
    assert_eq!(bad_status.status, 400);
    let bad_cursor = world
        .h
        .get(&world.h.admin, "/api/v3/fulfillments?cursor=nope")
        .await;
    assert_eq!(bad_cursor.status, 400);
    let missing_key = world
        .h
        .call(
            &world.requester,
            "POST",
            "/api/v3/fulfillments",
            &[],
            Some(&world.body_for("x")),
        )
        .await;
    assert_eq!(missing_key.status, 400);
    assert_eq!(missing_key.body["error"], "idempotency_key_required");
}

#[tokio::test]
async fn p10_i04_terminal_lineage_ages_out_with_audit_retention_and_live_rows_stay() {
    let world = World::with_approval().await;
    let id = world.approved().await;
    let revoked = world
        .h
        .call(&world.requester, "DELETE", &format!("/api/v3/fulfillments/{id}"), &[], None)
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    let live = world.create("idem-prune-000001-aaaa").await;
    assert_eq!(live.status, 201, "{}", live.body);
    // Nothing is old enough yet.
    assert_eq!(world.h.store.prune_fulfillments(1).await.unwrap(), 0);
    let two_days_ago = world.h.now_ms().await - 2 * 86_400_000;
    world
        .h
        .execute(
            "UPDATE cross_fulfillments SET closed_at = ? WHERE id = ?",
            vec![two_days_ago.into(), id.clone().into()],
        )
        .await;
    assert_eq!(world.h.store.prune_fulfillments(1).await.unwrap(), 1);
    assert_eq!(world.count("SELECT COUNT(*) FROM cross_fulfillments").await, 1);
    let remaining = world
        .h
        .get(&world.h.admin, "/api/v3/fulfillments")
        .await;
    assert_eq!(remaining.body["items"].as_array().unwrap().len(), 1);
    assert_eq!(remaining.body["items"][0]["status"], "awaiting_approval");
    assert!(world.h.store.prune_fulfillments(0).await.is_err());
}
