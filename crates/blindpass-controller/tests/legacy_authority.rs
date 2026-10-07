// SPDX-License-Identifier: AGPL-3.0-only
//! P06-LA01–LA04 isolate cryptographic generation changes with retained state.
//! Fixture epoch writes are not a restore, external reservation or activation.
mod support;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blindpass_controller::seed::{SeedRequest, seed_fixture};
use serde_json::{Value, json};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};
use support::{Backend, Harness, HttpResponse, TestDirectory};

struct Fixture {
    h: Harness,
    keys: BTreeMap<String, String>,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_extra(&[]).await
    }
    async fn with_extra(extra: &[(&str, &str)]) -> Self {
        let h = Harness::start_with(extra).await;
        std::fs::set_permissions(&h.directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let seeded = seed_fixture(&h.store, SeedRequest {
            agents: vec!["p06-requester".into(), "p06-fulfiller".into()],
            rotated_agents: vec![], revoked_agents: vec![], local_admin: false,
            policy: Some(json!({
                "secret_registry":[{"secretName":"p06.dummy", "classification":"dummy"}],
                "exchange_policy":[{"ruleId":"p06-dummy-allow", "secretName":"p06.dummy", "requesterIds":["p06-requester"], "fulfillerIds":["p06-fulfiller"], "mode":"allow"}]
            })),
        }).await.expect("private valid legacy fixture");
        Self {
            h,
            keys: seeded.agents,
        }
    }
    async fn token(&self, actor: &str) -> String {
        let response = self
            .h
            .request(
                "POST",
                "/api/v2/agents/token",
                &[("x-agent-api-key", &self.keys[actor])],
                None,
            )
            .await;
        assert_eq!(response.status, 200, "actual agent mint");
        response.body["access_token"].as_str().unwrap().to_owned()
    }
    async fn epoch(&self, epoch: i64) {
        self.h
            .execute(
                "UPDATE controller_meta SET issuer_epoch=? WHERE id=1",
                vec![epoch.into()],
            )
            .await;
    }
    async fn call(
        &self,
        token: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> HttpResponse {
        self.h
            .request(
                method,
                path,
                &[
                    ("authorization", &format!("Bearer {token}")),
                    ("content-type", "application/json"),
                ],
                body,
            )
            .await
    }
    async fn secret(&self, token: &str) -> Value {
        let r = self
            .call(
                token,
                "POST",
                "/api/v2/secret/request",
                Some(&json!({"public_key":"AQIDBA==","description":"P06 dummy retained request"})),
            )
            .await;
        assert_eq!(r.status, 201, "actual secret request");
        r.body
    }
    async fn exchange(&self, token: &str) -> Value {
        let r=self.call(token,"POST","/api/v2/secret/exchange/request",Some(&json!({"public_key":"AQIDBA==","secret_name":"p06.dummy","purpose":"P06 dummy generation","fulfiller_hint":"p06-fulfiller"}))).await;
        assert_eq!(r.status, 201, "actual allowed exchange");
        r.body
    }
    async fn close(self) {
        self.h.store.close().await;
        match &self.h.backend {
            Backend::Sqlite(p) => p.close().await,
            Backend::Postgres(p) => p.close().await,
        }
    }
}
fn signature(request: &Value, scope: &str) -> String {
    request["secret_url"]
        .as_str()
        .unwrap()
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .filter_map(|q| q.split_once('='))
        .find(|(key, _)| *key == scope)
        .unwrap()
        .1
        .to_owned()
}
fn claims(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

// Independent fixture derivation, checked against the production-minted
// JWT's signature before forging claim failures. No controller key helper is
// imported, so rejection alone cannot hide a wrong test key.
fn context_key(master: &[u8], purpose: &[u8], tenant: &str, epoch: u64) -> Vec<u8> {
    let mut context = b"blindpass:controller-legacy-authority:v1\0".to_vec();
    context.extend_from_slice(purpose);
    context.push(0);
    context.extend_from_slice(&(tenant.len() as u32).to_be_bytes());
    context.extend_from_slice(tenant.as_bytes());
    context.extend_from_slice(&epoch.to_be_bytes());
    let encoded = jsonwebtoken::crypto::sign(
        &context,
        &jsonwebtoken::EncodingKey::from_secret(master),
        jsonwebtoken::Algorithm::HS256,
    )
    .unwrap();
    URL_SAFE_NO_PAD.decode(encoded).unwrap()
}

fn signed_claims(claims: &Value, key: &[u8], kid: Option<&str>) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = kid.map(str::to_owned);
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_secret(key),
    )
    .unwrap()
}

fn verify_fixture_key(token: &str, key: &[u8], audience: &str) {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_issuer(&["sps"]);
    validation.set_audience(&[audience]);
    assert!(
        jsonwebtoken::decode::<Value>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(key),
            &validation
        )
        .is_ok(),
        "independent key must verify actual minted JWT before claim negatives"
    );
}

fn invalid_epoch_claims(original: &Value) -> Vec<Value> {
    let mut absent = original.clone();
    absent.as_object_mut().unwrap().remove("issuer_epoch");
    let mut result = vec![absent];
    for epoch in [
        Value::Null,
        json!(1),
        json!(10),
        json!(9.0),
        json!("9"),
        json!(9_007_199_254_740_992_u64),
    ] {
        let mut claims = original.clone();
        claims["issuer_epoch"] = epoch;
        result.push(claims);
    }
    result
}

#[tokio::test]
#[ignore = "run with owned controller backend through deployment driver"]
async fn p06_la01_agent_jwt_changes_generation_with_retained_keys_rows_and_restart() {
    let mut f = Fixture::new().await;
    let old = f.token("p06-requester").await;
    f.secret(&old).await;
    f.epoch(9).await;
    let refused = f
        .call(
            &old,
            "POST",
            "/api/v2/secret/request",
            Some(&json!({"public_key":"AQIDBA==","description":"P06 stale token"})),
        )
        .await;
    assert_eq!(
        refused.status, 401,
        "stale agent JWT despite retained active credential and master key"
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
            .await,
        1
    );
    let current = f.token("p06-requester").await;
    assert_eq!(claims(&current)["issuer_epoch"], 9);
    let current_key = context_key(&[b'A'; 32], b"agent-jwt", f.h.store.tenant_id(), 9);
    verify_fixture_key(&current, &current_key, "sps-agent");
    for bad in invalid_epoch_claims(&claims(&current)) {
        let forged = signed_claims(&bad, &current_key, None);
        assert_eq!(f.call(&forged, "POST", "/api/v2/secret/request", Some(&json!({"public_key":"AQIDBA==","description":"P06 correctly signed invalid epoch claim"}))).await.status, 401, "valid current MAC cannot mask invalid epoch claim");
    }
    f.secret(&current).await;
    f.h.restart_server().await;
    f.secret(&current).await;
    assert_eq!(
        f.call(
            &old,
            "GET",
            &format!("/api/v2/secret/status/{}", "a".repeat(64)),
            None
        )
        .await
        .status,
        401
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "run with owned controller backend through deployment driver"]
async fn p06_la02_every_browser_scope_changes_key_while_retained_request_stays_pending() {
    let f = Fixture::new().await;
    let old = f.token("p06-requester").await;
    let retained = f.secret(&old).await;
    let id = retained["request_id"].as_str().unwrap();
    let metadata = signature(&retained, "metadata_sig");
    let submit = signature(&retained, "submit_sig");
    let status =
        f.h.request(
            "POST",
            &format!("/api/v2/secret/browser-status/{id}/capability?sig={metadata}"),
            &[],
            None,
        )
        .await;
    assert_eq!(status.status, 200);
    let status_sig = status.body["status_sig"].as_str().unwrap();
    assert_eq!(
        f.h.request(
            "GET",
            &format!("/api/v2/secret/metadata/{id}?sig={metadata}"),
            &[],
            None
        )
        .await
        .status,
        200
    );
    f.epoch(9).await;
    assert_eq!(
        f.h.request(
            "GET",
            &format!("/api/v2/secret/metadata/{id}?sig={metadata}"),
            &[],
            None
        )
        .await
        .status,
        403,
        "retained metadata authority must change key"
    );
    assert_eq!(
        f.h.request(
            "POST",
            &format!("/api/v2/secret/submit/{id}?sig={submit}"),
            &[("content-type", "application/json")],
            Some(&json!({"enc":"AQIDBA==","ciphertext":"AQIDBA=="}))
        )
        .await
        .status,
        403
    );
    assert_eq!(
        f.h.request(
            "POST",
            &format!("/api/v2/secret/browser-status/{id}/capability?sig={metadata}"),
            &[],
            None
        )
        .await
        .status,
        410
    );
    assert_eq!(
        f.h.request(
            "GET",
            &format!("/api/v2/secret/browser-status/{id}?sig={status_sig}"),
            &[],
            None
        )
        .await
        .status,
        410
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM secret_requests WHERE status='pending'",
            vec![]
        )
        .await,
        1
    );
    let current = f.token("p06-requester").await;
    let fresh = f.secret(&current).await;
    let id = fresh["request_id"].as_str().unwrap();
    let metadata = signature(&fresh, "metadata_sig");
    let submit = signature(&fresh, "submit_sig");
    assert_eq!(
        f.h.request(
            "GET",
            &format!("/api/v2/secret/metadata/{id}?sig={metadata}"),
            &[],
            None
        )
        .await
        .status,
        200
    );
    let status =
        f.h.request(
            "POST",
            &format!("/api/v2/secret/browser-status/{id}/capability?sig={metadata}"),
            &[],
            None,
        )
        .await;
    assert_eq!(status.status, 200);
    let status_sig = status.body["status_sig"].as_str().unwrap();
    assert_eq!(
        f.h.request(
            "POST",
            &format!("/api/v2/secret/submit/{id}?sig={submit}"),
            &[("content-type", "application/json")],
            Some(&json!({"enc":"AQIDBA==","ciphertext":"AQIDBA=="}))
        )
        .await
        .status,
        201
    );
    assert_eq!(
        f.h.request(
            "GET",
            &format!("/api/v2/secret/browser-status/{id}?sig={status_sig}"),
            &[],
            None
        )
        .await
        .body["status"],
        "submitted"
    );
    let path = format!("/api/v2/secret/retrieve/{id}");
    assert_eq!(f.call(&current, "GET", &path, None).await.status, 200);
    assert_eq!(f.call(&current, "GET", &path, None).await.status, 410);
    f.close().await;
}

#[tokio::test]
#[ignore = "run with owned controller backend through deployment driver"]
async fn p06_la03_fulfillment_jwt_refuses_old_generation_before_retained_exchange_use() {
    let f = Fixture::new().await;
    let old = f.token("p06-requester").await;
    let retained = f.exchange(&old).await;
    let old_fulfillment = retained["fulfillment_token"].as_str().unwrap();
    f.epoch(9).await;
    let requester = f.token("p06-requester").await;
    let fulfiller = f.token("p06-fulfiller").await;
    let reply = f
        .call(
            &fulfiller,
            "POST",
            "/api/v2/secret/exchange/fulfill",
            Some(&json!({"fulfillment_token":old_fulfillment})),
        )
        .await;
    assert_eq!(
        reply.status, 401,
        "stale fulfillment token with a current agent JWT and retained exchange"
    );
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM exchanges WHERE status='pending'",
            vec![]
        )
        .await,
        1
    );
    let fresh = f.exchange(&requester).await;
    let token = fresh["fulfillment_token"].as_str().unwrap();
    let id = fresh["exchange_id"].as_str().unwrap();
    assert_eq!(claims(token)["issuer_epoch"], 9);
    let current_root = context_key(&[b'R'; 32], b"root", f.h.store.tenant_id(), 9);
    let fulfillment_key =
        blindpass_core::signing::derive_secret(&current_root, "agent-fulfillment").unwrap();
    verify_fixture_key(token, fulfillment_key.as_bytes(), "agent-fulfill");
    for bad in invalid_epoch_claims(&claims(token)) {
        let forged = signed_claims(&bad, fulfillment_key.as_bytes(), None);
        assert_eq!(
            f.call(
                &fulfiller,
                "POST",
                "/api/v2/secret/exchange/fulfill",
                Some(&json!({"fulfillment_token":forged}))
            )
            .await
            .status,
            401,
            "valid fulfillment MAC cannot mask invalid epoch claim"
        );
    }
    assert_eq!(
        f.h.scalar_i64(
            "SELECT COUNT(*) FROM exchanges WHERE status='pending'",
            vec![]
        )
        .await,
        2
    );
    assert_eq!(
        f.call(
            &fulfiller,
            "POST",
            "/api/v2/secret/exchange/fulfill",
            Some(&json!({"fulfillment_token":token}))
        )
        .await
        .status,
        200
    );
    assert_eq!(
        f.call(
            &fulfiller,
            "POST",
            &format!("/api/v2/secret/exchange/submit/{id}"),
            Some(&json!({"enc":"AQIDBA==","ciphertext":"AQIDBA=="}))
        )
        .await
        .status,
        201
    );
    let path = format!("/api/v2/secret/exchange/retrieve/{id}");
    assert_eq!(f.call(&requester, "GET", &path, None).await.status, 200);
    assert_eq!(f.call(&requester, "GET", &path, None).await.status, 410);
    f.close().await;
}

#[tokio::test]
#[ignore = "run with owned controller backend through deployment driver"]
async fn p06_la04_unsafe_epoch_and_symmetric_provider_cannot_supply_legacy_authority() {
    let directory = TestDirectory::new();
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let jwks = directory.file("dummy.jwks");
    std::fs::write(&jwks,json!({"keys":[{"kty":"oct","alg":"HS256","kid":"P06_DUMMY","k":URL_SAFE_NO_PAD.encode("A".repeat(32))}]}).to_string()).unwrap();
    std::fs::set_permissions(&jwks, std::fs::Permissions::from_mode(0o600)).unwrap();
    let providers =
        json!([{"name":"P06_DUMMY","jwks_file":jwks,"issuer":"sps","audience":"sps-agent"}])
            .to_string();
    let f = Fixture::with_extra(&[("BLINDPASS_AGENT_AUTH_PROVIDERS_JSON", &providers)]).await;
    let old = f.token("p06-requester").await;
    let kid_token = signed_claims(&claims(&old), &[b'A'; 32], Some("P06_DUMMY"));
    let probe_path = format!("/api/v2/secret/status/{}", "a".repeat(64));
    assert_eq!(
        f.call(&kid_token, "GET", &probe_path, None).await.status,
        410,
        "live baseline local JWT before generation change"
    );
    f.epoch(9).await;
    assert_eq!(
        f.call(&kid_token, "GET", &probe_path, None).await.status,
        401,
        "known external symmetric JWK cannot re-admit a stale local JWT"
    );
    assert_eq!(
        f.call(
            &old,
            "GET",
            &format!("/api/v2/secret/status/{}", "a".repeat(64)),
            None
        )
        .await
        .status,
        401
    );
    let current = f.token("p06-requester").await;
    for epoch in [0_i64, 9_007_199_254_740_992] {
        f.epoch(epoch).await;
        assert_eq!(
            f.h.request(
                "POST",
                "/api/v2/agents/token",
                &[("x-agent-api-key", &f.keys["p06-requester"])],
                None
            )
            .await
            .status,
            503,
            "unsafe authority cannot mint"
        );
        assert_eq!(
            f.call(
                &current,
                "POST",
                "/api/v2/secret/request",
                Some(&json!({"public_key":"AQIDBA==","description":"P06 invalid authority"}))
            )
            .await
            .status,
            503,
            "unsafe authority cannot verify or fall back"
        );
    }
    f.epoch(9).await;
    f.h.execute(
        "UPDATE controller_meta SET tenant_id='P06_DUMMY_CHANGED' WHERE id=1",
        vec![],
    )
    .await;
    assert_eq!(
        f.call(
            &current,
            "POST",
            "/api/v2/secret/request",
            Some(&json!({"public_key":"AQIDBA==","description":"P06 changed authority tenant"}))
        )
        .await
        .status,
        503,
        "cached tenant cannot mask changed metadata"
    );
    f.h.execute(
        "UPDATE controller_meta SET tenant_id=? WHERE id=1",
        vec![f.h.store.tenant_id().into()],
    )
    .await;
    if !support::postgres_selected() {
        // SQLite's dynamic types must not be coerced by CAST into a known
        // version. PostgreSQL enforces the column's integer type itself.
        for marker in ["'17suffix'", "17.5"] {
            f.h.execute(
                &format!("UPDATE controller_meta SET schema_version={marker} WHERE id=1"),
                vec![],
            )
            .await;
            assert_eq!(
                f.call(
                    &current,
                    "POST",
                    "/api/v2/secret/request",
                    Some(
                        &json!({"public_key":"AQIDBA==","description":"P06 malformed schema type"})
                    )
                )
                .await
                .status,
                503,
                "SQLite must not coerce malformed schema metadata"
            );
        }
    }
    f.h.execute(
        "UPDATE controller_meta SET schema_version=? WHERE id=1",
        vec![(blindpass_controller::store::SCHEMA_VERSION + 1).into()],
    )
    .await;
    assert_eq!(
        f.call(
            &current,
            "POST",
            "/api/v2/secret/request",
            Some(
                &json!({"public_key":"AQIDBA==","description":"P06 unsupported authority schema"})
            )
        )
        .await
        .status,
        503,
        "cached schema cannot mask changed metadata"
    );
    assert_eq!(
        f.h.scalar_i64("SELECT COUNT(*) FROM secret_requests", vec![])
            .await,
        0
    );
    f.close().await;
}
