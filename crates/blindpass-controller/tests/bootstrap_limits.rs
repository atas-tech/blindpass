// SPDX-License-Identifier: AGPL-3.0-only

//! P07-D4 / P07-I02 / N-01: bootstrap abuse. The bootstrap token is the whole
//! capability (256 bits, stored as a SHA-256), so a guess cannot be tied to a
//! victim token and cannot burn it. These cases pin that, the failure budgets
//! (per peer shard and global, bounded state), that an invalid token never
//! reaches Argon2 and that reissue is the recovery from an exposed token.
//! SQLite by default; PostgreSQL with `P02_TEST_BACKEND=postgres`.

mod support;

use blindpass_core::custody::sha256;
use serde_json::json;
use std::time::{Duration, Instant};
use support::{Bind, Harness, HttpResponse, ORIGIN};

const PROXY: (&str, &str) = ("BLINDPASS_TRUST_PROXY", "127.0.0.0/8,::1/128");
const TOKEN_A: &str = "p07-bootstrap-token-a-with-more-than-32-bytes";
const TOKEN_B: &str = "p07-bootstrap-token-b-with-more-than-32-bytes";

fn digest(text: &str) -> String {
    sha256(text.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn issue(harness: &Harness, token: &str) {
    assert!(
        harness
            .store
            .issue_bootstrap_token(&digest(token), 900)
            .await
            .expect("issue bootstrap token")
    );
}

async fn bootstrap(harness: &Harness, token: &str, username: &str, ip: &str) -> HttpResponse {
    harness
        .request(
            "POST",
            "/api/v3/admin/bootstrap",
            &[
                ("content-type", "application/json"),
                ("origin", ORIGIN),
                ("x-blindpass-bootstrap-token", token),
                ("x-forwarded-for", ip),
            ],
            Some(&json!({
                "username":username,
                "display_name":"Bootstrap Admin",
                "password":"p07-bootstrap-password-long"
            })),
        )
        .await
}

fn shard(ip: &str) -> u8 {
    sha256(ip.as_bytes()).unwrap()[0]
}

/// An address in 198.51.100.0/24 whose peer shard differs from `other`.
fn address_in_another_shard(other: &str) -> String {
    (1..=250)
        .map(|last| format!("198.51.100.{last}"))
        .find(|candidate| shard(candidate) != shard(other))
        .expect("an address in another shard")
}

fn guess(index: usize) -> String {
    format!("p07-wrong-bootstrap-guess-{index:04}-padding-to-pass-length-check")
}

#[tokio::test]
async fn p07_bl01_guesses_cannot_burn_or_block_the_valid_token() {
    let harness = Harness::start_unbootstrapped(&[PROXY]).await;
    issue(&harness, TOKEN_A).await;
    for index in 0..8 {
        let wrong = guess(index);
        let response = bootstrap(&harness, &wrong, "bl01-admin", "203.0.113.10").await;
        assert_eq!(response.status, 409, "{}", response.body);
        // Near-misses of the real token are not special either.
        let near = format!("{}x", &TOKEN_A[..TOKEN_A.len() - 1]);
        let response = bootstrap(&harness, &near, "bl01-admin", "203.0.113.11").await;
        assert_eq!(response.status, 409, "{}", response.body);
    }
    assert!(
        harness
            .store
            .bootstrap_token_usable(&digest(TOKEN_A))
            .await
            .unwrap(),
        "failed guesses must leave the valid token usable"
    );
    let created = bootstrap(&harness, TOKEN_A, "bl01-admin", "203.0.113.12").await;
    assert_eq!(created.status, 201, "{}", created.body);
    let replay = bootstrap(&harness, TOKEN_A, "bl01-second", "203.0.113.12").await;
    assert_eq!(replay.status, 409, "{}", replay.body);
}

#[tokio::test]
async fn p07_bl02_a_spent_peer_budget_never_blocks_the_valid_token() {
    let harness =
        Harness::start_unbootstrapped(&[PROXY, ("BLINDPASS_BOOTSTRAP_FAILURES_PER_PEER", "3")])
            .await;
    issue(&harness, TOKEN_A).await;
    let attacker = "203.0.113.20";
    for index in 0..3 {
        let response = bootstrap(&harness, &guess(index), "bl02-admin", attacker).await;
        assert_eq!(response.status, 409, "{}", response.body);
    }
    let limited = bootstrap(&harness, &guess(99), "bl02-admin", attacker).await;
    assert_eq!(limited.status, 429, "{}", limited.body);
    assert_eq!(limited.body["error"], "bootstrap_rate_limited");
    assert!(limited.body["retry_after"].as_u64().unwrap() >= 1);
    assert!(
        limited
            .headers
            .iter()
            .any(|(name, _)| name == "retry-after")
    );
    // Another peer shard still gets the plain refusal.
    let other = address_in_another_shard(attacker);
    let other_response = bootstrap(&harness, &guess(100), "bl02-admin", &other).await;
    assert_eq!(other_response.status, 409, "{}", other_response.body);
    // The limited peer holds the real token: it is not locked out of setup.
    let created = bootstrap(&harness, TOKEN_A, "bl02-admin", attacker).await;
    assert_eq!(created.status, 201, "{}", created.body);
}

#[tokio::test]
async fn p07_bl03_the_global_budget_covers_many_peers() {
    let harness = Harness::start_unbootstrapped(&[
        PROXY,
        ("BLINDPASS_BOOTSTRAP_FAILURES_PER_PEER", "1000"),
        ("BLINDPASS_BOOTSTRAP_FAILURES_GLOBAL", "4"),
    ])
    .await;
    issue(&harness, TOKEN_A).await;
    for index in 0..4 {
        let ip = format!("203.0.113.{}", 30 + index);
        let response = bootstrap(&harness, &guess(index), "bl03-admin", &ip).await;
        assert_eq!(response.status, 409, "{}", response.body);
    }
    let limited = bootstrap(&harness, &guess(50), "bl03-admin", "198.51.100.77").await;
    assert_eq!(limited.status, 429, "{}", limited.body);
    let created = bootstrap(&harness, TOKEN_A, "bl03-admin", "198.51.100.78").await;
    assert_eq!(created.status, 201, "{}", created.body);
}

#[tokio::test]
async fn p07_bl04_failure_state_is_bounded_by_shards_not_addresses() {
    let harness = Harness::start_unbootstrapped(&[
        PROXY,
        ("BLINDPASS_BOOTSTRAP_FAILURES_PER_PEER", "100000"),
        ("BLINDPASS_BOOTSTRAP_FAILURES_GLOBAL", "1000000"),
    ])
    .await;
    issue(&harness, TOKEN_A).await;
    for index in 0..300 {
        let ip = format!("10.{}.{}.{}", index / 250, index % 250, index % 7);
        let response = bootstrap(&harness, &guess(index), "bl04-admin", &ip).await;
        assert_eq!(response.status, 409, "{}", response.body);
    }
    let rows = harness
        .scalar_i64(
            "SELECT COUNT(*) FROM rate_windows WHERE key LIKE ?",
            vec![Bind::from("bootstrap-fail-%")],
        )
        .await;
    assert!(
        rows <= 257,
        "{rows} bootstrap failure rows for 300 addresses"
    );
    assert!(rows >= 2);
}

#[tokio::test]
async fn p07_bl05_an_invalid_token_never_reaches_password_hashing() {
    let harness = Harness::start_unbootstrapped(&[
        PROXY,
        ("BLINDPASS_BOOTSTRAP_FAILURES_PER_PEER", "100000"),
        ("BLINDPASS_BOOTSTRAP_FAILURES_GLOBAL", "1000000"),
    ])
    .await;
    issue(&harness, TOKEN_A).await;
    let mut invalid = Vec::new();
    for index in 0..5 {
        let start = Instant::now();
        let response = bootstrap(&harness, &guess(index), "bl05-admin", "203.0.113.50").await;
        invalid.push(start.elapsed());
        assert_eq!(response.status, 409);
    }
    invalid.sort();
    let start = Instant::now();
    let created = bootstrap(&harness, TOKEN_A, "bl05-admin", "203.0.113.50").await;
    let valid = start.elapsed();
    assert_eq!(created.status, 201, "{}", created.body);
    assert!(
        invalid[2] * 3 < valid,
        "an invalid token took {:?} against {valid:?} for a hashed bootstrap",
        invalid[2]
    );
}

#[tokio::test]
async fn p07_bl06_reissue_replaces_an_exposed_token_and_expiry_is_enforced() {
    let harness = Harness::start_unbootstrapped(&[PROXY]).await;
    issue(&harness, TOKEN_A).await;
    issue(&harness, TOKEN_B).await;
    let old = bootstrap(&harness, TOKEN_A, "bl06-admin", "203.0.113.60").await;
    assert_eq!(old.status, 409, "reissue must invalidate the earlier token");
    // Expiry is checked in the same statement as use.
    harness
        .execute(
            "UPDATE bootstrap_tokens SET expires_at = 1 WHERE token_hash = ?",
            vec![Bind::from(digest(TOKEN_B))],
        )
        .await;
    let expired = bootstrap(&harness, TOKEN_B, "bl06-admin", "203.0.113.60").await;
    assert_eq!(expired.status, 409, "{}", expired.body);
    issue(&harness, TOKEN_A).await;
    let created = bootstrap(&harness, TOKEN_A, "bl06-admin", "203.0.113.60").await;
    assert_eq!(created.status, 201, "{}", created.body);
    // Setup complete: the capability cannot be issued again.
    assert!(
        !harness
            .store
            .issue_bootstrap_token(&digest(TOKEN_B), 900)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn p07_bl07_a_race_for_one_token_creates_exactly_one_administrator() {
    let harness = Harness::start_unbootstrapped(&[PROXY]).await;
    issue(&harness, TOKEN_A).await;
    let mut attempts = Vec::new();
    for index in 0..8 {
        let address = harness.address;
        attempts.push(tokio::spawn(async move {
            support::raw_request(
                address,
                "POST",
                "/api/v3/admin/bootstrap",
                &[
                    ("content-type", "application/json"),
                    ("origin", ORIGIN),
                    ("x-blindpass-bootstrap-token", TOKEN_A),
                    ("x-forwarded-for", "203.0.113.70"),
                ],
                Some(&json!({
                    "username":format!("bl07-admin-{index}"),
                    "display_name":"Race Admin",
                    "password":"p07-bootstrap-password-long"
                })),
            )
            .await
        }));
    }
    let mut created = 0;
    for attempt in attempts {
        let response = tokio::time::timeout(Duration::from_secs(120), attempt)
            .await
            .expect("race attempt finished")
            .expect("race task");
        assert!(
            matches!(response.status, 201 | 409 | 429),
            "{} {}",
            response.status,
            response.body
        );
        if response.status == 201 {
            created += 1;
        }
    }
    assert_eq!(created, 1);
    let operators = harness
        .scalar_i64("SELECT COUNT(*) FROM operators", vec![])
        .await;
    assert_eq!(operators, 1);
}
