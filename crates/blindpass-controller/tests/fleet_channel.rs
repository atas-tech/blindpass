// SPDX-License-Identifier: AGPL-3.0-only

//! P03 node channel review: stateless session challenges, the node-session
//! JWT key domain and per-session acknowledgement clamping.

mod support;

use blindpass_core::fleet::{DocumentKind, SignedEnvelope, TimeReply};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation, decode, encode};
use serde_json::{Value, json};
use support::{Harness, NodeKeys};

async fn enqueue_time_reply(harness: &Harness, node_id: &str, seq: i64) {
    let now_ms = harness.now_ms().await;
    let body = TimeReply {
        node_id: node_id.to_owned(),
        challenge: format!("inbox-{seq}"),
        challenge_received_at_ms: u64::try_from(now_ms).unwrap(),
        controller_time_ms: u64::try_from(now_ms).unwrap(),
        issuer_epoch: 1,
    }
    .to_value()
    .unwrap();
    let envelope = SignedEnvelope::sign(
        DocumentKind::TimeReply,
        body,
        &harness.issuer_key_id,
        1,
        &harness.issuer,
    )
    .unwrap()
    .to_json()
    .unwrap();
    harness
        .execute(
            "INSERT INTO node_inbox (node_id, seq, envelope_json, created_at) VALUES (?, ?, ?, ?)",
            vec![
                node_id.into(),
                seq.into(),
                String::from_utf8(envelope).unwrap().into(),
                now_ms.into(),
            ],
        )
        .await;
}

fn sequences(response: &Value) -> Vec<i64> {
    response["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|document| document["seq"].as_i64().unwrap())
        .collect()
}

#[tokio::test]
async fn session_challenges_are_stateless_bound_and_one_use() {
    let harness = Harness::start().await;
    let keys = NodeKeys::from_seed(41);
    let node_id = harness.enroll_node("channel-node", &keys).await;

    let pending = harness.session_challenge(&node_id, 1).await;
    assert_eq!(pending.status, 200, "{}", pending.body);
    // An unauthenticated caller can request challenges for a known node id;
    // that must not invalidate the legitimate node's pending challenge.
    for _ in 0..20 {
        let attacker = harness.session_challenge(&node_id, 1).await;
        assert_eq!(attacker.status, 200, "{}", attacker.body);
        assert_ne!(attacker.body["nonce"], pending.body["nonce"]);
    }
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM node_challenges WHERE node_id = ?",
                vec![node_id.as_str().into()],
            )
            .await,
        0,
        "phase one must not write per-node challenge state"
    );

    let authenticated = harness
        .session_authenticate(&node_id, 1, &keys, &pending.body)
        .await;
    assert_eq!(authenticated.status, 200, "{}", authenticated.body);

    // The same signed nonce is one-use.
    let replay = harness
        .session_authenticate(&node_id, 1, &keys, &pending.body)
        .await;
    assert_eq!(replay.status, 401, "{}", replay.body);
    assert_eq!(replay.body["error"], "invalid_node_challenge");

    // A nonce altered in its random or MAC bytes is rejected.
    let fresh = harness.session_challenge(&node_id, 1).await;
    let mut tampered = fresh.body.clone();
    let nonce = fresh.body["nonce"].as_str().unwrap();
    // Position 30 lies inside the MAC tag; a full sextet keeps the nonce
    // canonical base64url so the MAC check, not decoding, rejects it.
    let flipped = if &nonce[30..31] == "A" { "B" } else { "A" };
    tampered["nonce"] = json!(format!("{}{flipped}{}", &nonce[..30], &nonce[31..]));
    let rejected = harness
        .session_authenticate(&node_id, 1, &keys, &tampered)
        .await;
    assert_eq!(rejected.status, 401, "{}", rejected.body);

    // A challenge issued for one node cannot open a session for another,
    // even when signed by the other node's own key.
    let other_keys = NodeKeys::from_seed(43);
    let other_id = harness.enroll_node("channel-other", &other_keys).await;
    let mut crossed = fresh.body.clone();
    crossed["node_id"] = json!(other_id);
    let crossed_response = harness
        .session_authenticate(&other_id, 1, &other_keys, &crossed)
        .await;
    assert_eq!(crossed_response.status, 401, "{}", crossed_response.body);

    // A challenge bound to one key version cannot be used for another.
    let version_mismatch = harness
        .session_authenticate(&node_id, 2, &keys, &fresh.body)
        .await;
    assert_eq!(version_mismatch.status, 401, "{}", version_mismatch.body);
}

#[tokio::test]
async fn node_session_tokens_use_a_derived_key_domain() {
    let harness = Harness::start().await;
    let keys = NodeKeys::from_seed(45);
    let node_id = harness.enroll_node("jwt-node", &keys).await;
    let bearer = harness.open_session(&node_id, 1, &keys).await;
    let token = bearer.strip_prefix("Bearer ").unwrap();

    let agent_secret = "A".repeat(32);
    let derived = jsonwebtoken::crypto::sign(
        b"blindpass:node-session-jwt:v1",
        &EncodingKey::from_secret(agent_secret.as_bytes()),
        Algorithm::HS256,
    )
    .unwrap();
    let derived = blindpass_core::signing::base64_url_decode(&derived, 32).unwrap();
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["blindpass-node"]);
    validation.set_issuer(&["blindpass-controller"]);
    let claims = decode::<Value>(token, &DecodingKey::from_secret(&derived), &validation)
        .expect("node session token verifies under the derived key")
        .claims;
    assert_eq!(claims["node_id"], node_id);
    assert!(
        decode::<Value>(
            token,
            &DecodingKey::from_secret(agent_secret.as_bytes()),
            &validation
        )
        .is_err(),
        "node session token must not verify under the raw agent secret"
    );

    // A token with valid claims signed by the raw agent JWT secret is rejected.
    let forged = encode(
        &jsonwebtoken::Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(agent_secret.as_bytes()),
    )
    .unwrap();
    let forged_poll = harness
        .poll(&format!("Bearer {forged}"), &json!({"health":{}}))
        .await;
    assert_eq!(forged_poll.status, 401, "{}", forged_poll.body);
}

#[tokio::test]
async fn acknowledgements_are_clamped_to_documents_delivered_to_the_session() {
    let harness = Harness::start().await;
    let keys = NodeKeys::from_seed(47);
    let node_id = harness.enroll_node("ack-node", &keys).await;
    let preexisting = harness.inbox(&node_id).await.len() as i64;
    let base = harness
        .scalar_i64(
            "SELECT COALESCE(MAX(seq), 0) FROM node_inbox WHERE node_id = ?",
            vec![node_id.as_str().into()],
        )
        .await;
    enqueue_time_reply(&harness, &node_id, base + 1).await;
    enqueue_time_reply(&harness, &node_id, base + 2).await;

    let first = harness.open_session(&node_id, 1, &keys).await;
    // An acknowledgement beyond anything delivered to this session is
    // clamped and removes nothing.
    let poll = harness
        .poll(&first, &json!({"ack_seq": base + 1_000}))
        .await;
    assert_eq!(poll.status, 200, "{}", poll.body);
    let delivered = sequences(&poll.body);
    assert_eq!(delivered.len() as i64, preexisting + 2);
    assert_eq!(*delivered.last().unwrap(), base + 2);

    enqueue_time_reply(&harness, &node_id, base + 3).await;
    let poll = harness
        .poll(&first, &json!({"ack_seq": base + 1_000}))
        .await;
    assert_eq!(poll.status, 200, "{}", poll.body);
    assert_eq!(sequences(&poll.body), vec![base + 3]);

    // A replacement session (relay reconnect) inherits the delivered
    // high-water mark, so the retained acknowledgement still applies.
    enqueue_time_reply(&harness, &node_id, base + 4).await;
    let second = harness.open_session(&node_id, 1, &keys).await;
    let poll = harness.poll(&second, &json!({"ack_seq": base + 3})).await;
    assert_eq!(poll.status, 200, "{}", poll.body);
    assert_eq!(sequences(&poll.body), vec![base + 4]);
    assert_eq!(
        harness
            .scalar_i64(
                "SELECT COUNT(*) FROM node_inbox WHERE node_id = ? AND acked_at IS NULL",
                vec![node_id.as_str().into()],
            )
            .await,
        1
    );
}
