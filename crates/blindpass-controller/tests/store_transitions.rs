// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_controller::store::{
    ApprovalRecord, ExchangePolicyRecord, ExchangeRecord, SecretRequestStatus, Store,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct StoreFixture {
    url: String,
    store: Option<Store>,
    sqlite_dir: Option<PathBuf>,
    postgres_schema: Option<String>,
    admin_pool: Option<PgPool>,
}

impl StoreFixture {
    async fn new() -> Self {
        match std::env::var("P02_TEST_BACKEND")
            .as_deref()
            .unwrap_or("sqlite")
        {
            "sqlite" => {
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock after Unix epoch")
                    .as_nanos();
                let directory = std::env::temp_dir()
                    .join(format!("blindpass-store-{}-{nonce}", std::process::id()));
                std::fs::create_dir_all(&directory).expect("create SQLite fixture directory");
                let url = format!(
                    "sqlite://{}?mode=rwc",
                    directory.join("controller.db").display()
                );
                let store = Store::connect(&url)
                    .await
                    .expect("connect SQLite controller store");
                Self {
                    url,
                    store: Some(store),
                    sqlite_dir: Some(directory),
                    postgres_schema: None,
                    admin_pool: None,
                }
            }
            "postgres" => {
                let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
                    .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                    .expect("P02_TEST_POSTGRES_URL or CONTRACT_DATABASE_URL is required for PostgreSQL tests");
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock after Unix epoch")
                    .as_nanos();
                let schema = format!("p02_store_{}_{}", std::process::id(), nonce);
                let admin_pool = PgPoolOptions::new()
                    .max_connections(2)
                    .connect(&parent_url)
                    .await
                    .expect("connect disposable PostgreSQL fixture");
                sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                    .execute(&admin_pool)
                    .await
                    .expect("create isolated PostgreSQL schema");
                let separator = if parent_url.contains('?') { '&' } else { '?' };
                let url = format!("{parent_url}{separator}options=-c%20search_path%3D{schema}");
                let store = Store::connect(&url)
                    .await
                    .expect("connect PostgreSQL controller store");
                Self {
                    url,
                    store: Some(store),
                    sqlite_dir: None,
                    postgres_schema: Some(schema),
                    admin_pool: Some(admin_pool),
                }
            }
            other => panic!("unknown P02_TEST_BACKEND value: {other}"),
        }
    }

    fn store(&self) -> &Store {
        self.store.as_ref().expect("store is open")
    }

    async fn restart(&mut self) {
        self.store.take();
        self.store = Some(
            Store::connect(&self.url)
                .await
                .expect("reconnect controller store after restart"),
        );
    }

    async fn close(mut self) {
        self.store.take();
        if let (Some(pool), Some(schema)) = (&self.admin_pool, &self.postgres_schema) {
            sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
                .execute(pool)
                .await
                .expect("drop isolated PostgreSQL fixture schema");
            pool.close().await;
        }
        if let Some(directory) = self.sqlite_dir.take() {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

#[tokio::test]
async fn schema_migrations_are_repeatable_and_tenant_identity_is_stable() {
    let fixture = StoreFixture::new().await;
    let tenant = fixture.store().tenant_id().to_owned();
    let second = Store::connect(&fixture.url)
        .await
        .expect("repeat schema migration and initialization");
    assert_eq!(second.tenant_id(), tenant);
    drop(second);
    fixture.close().await;
}

#[tokio::test]
async fn unsupported_schema_version_fails_closed_before_migration() {
    let fixture = StoreFixture::new().await;
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL schema fixture");
        sqlx::query("UPDATE controller_meta SET schema_version = 999 WHERE id = 1")
            .execute(&pool)
            .await
            .expect("set unsupported schema version");
        sqlx::query("DROP TABLE quota_counters")
            .execute(&pool)
            .await
            .expect("remove table to detect an unintended migration");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite schema fixture");
        sqlx::query("UPDATE controller_meta SET schema_version = 999 WHERE id = 1")
            .execute(&pool)
            .await
            .expect("set unsupported schema version");
        sqlx::query("DROP TABLE quota_counters")
            .execute(&pool)
            .await
            .expect("remove table to detect an unintended migration");
        pool.close().await;
    }

    let error = Store::connect(&fixture.url)
        .await
        .err()
        .expect("unsupported schema must prevent startup");
    assert_eq!(
        error.to_string(),
        "controller schema version is unsupported"
    );
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("reopen PostgreSQL schema fixture");
        let recreated: bool =
            sqlx::query_scalar("SELECT to_regclass('quota_counters') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .expect("inspect PostgreSQL schema");
        assert!(!recreated, "unsupported schema must not be migrated");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("reopen SQLite schema fixture");
        let recreated: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'quota_counters')",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect SQLite schema");
        assert_eq!(recreated, 0, "unsupported schema must not be migrated");
        pool.close().await;
    }
    fixture.close().await;
}

#[tokio::test]
async fn conditional_submit_and_consume_allow_one_winner_under_concurrency() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let request_id = store
        .create_secret_request("requester", "public-key", "description", "confirm", 60)
        .await
        .expect("create request");

    let submissions = (0..12).map(|index| {
        let store = store.clone();
        let request_id = request_id.clone();
        tokio::spawn(async move {
            store
                .submit_secret_request(
                    &request_id,
                    "requester",
                    "enc-value",
                    &format!("ciphertext-{index}"),
                    60,
                )
                .await
                .expect("submit concurrently")
        })
    });
    let accepted = futures_join(submissions).await;
    assert_eq!(accepted.iter().filter(|value| **value).count(), 1);
    assert_eq!(
        store
            .request_status(&request_id, "requester")
            .await
            .unwrap(),
        Some(SecretRequestStatus::Submitted)
    );

    let readers = (0..12).map(|_| {
        let store = store.clone();
        let request_id = request_id.clone();
        tokio::spawn(async move {
            store
                .consume_secret_request(&request_id, "requester")
                .await
                .expect("consume concurrently")
        })
    });
    let retrieved = futures_join(readers).await;
    assert_eq!(retrieved.iter().filter(|value| value.is_some()).count(), 1);
    assert!(retrieved.into_iter().flatten().all(|payload| {
        payload.enc == "enc-value" && payload.ciphertext.starts_with("ciphertext-")
    }));
    assert_eq!(
        store
            .request_status(&request_id, "requester")
            .await
            .unwrap(),
        None
    );
    fixture.close().await;
}

#[tokio::test]
async fn expiry_is_enforced_before_sweep_and_after_database_restart() {
    let mut fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let expiring = store
        .create_secret_request("requester", "key-expiring", "short-lived", "code", 1)
        .await
        .expect("create short-lived request");
    assert_eq!(
        store.request_status(&expiring, "requester").await.unwrap(),
        Some(SecretRequestStatus::Pending)
    );
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        store.request_status(&expiring, "requester").await.unwrap(),
        None
    );
    assert!(
        store
            .consume_secret_request(&expiring, "requester")
            .await
            .unwrap()
            .is_none()
    );

    let durable = store
        .create_secret_request("requester", "key-durable", "submitted", "code", 60)
        .await
        .expect("create durable request");
    assert!(
        store
            .submit_secret_request(&durable, "requester", "enc", "ciphertext", 60)
            .await
            .unwrap()
    );
    fixture.restart().await;
    assert_eq!(
        fixture
            .store()
            .request_status(&expiring, "requester")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        fixture
            .store()
            .request_status(&durable, "requester")
            .await
            .unwrap(),
        Some(SecretRequestStatus::Submitted)
    );
    let payload = fixture
        .store()
        .consume_secret_request(&durable, "requester")
        .await
        .unwrap()
        .expect("submitted data persists across restart");
    assert_eq!(payload.ciphertext, "ciphertext");
    fixture.close().await;
}

#[tokio::test]
async fn p02_i03_committed_one_use_retrieval_stays_consumed_after_store_restart() {
    let mut fixture = StoreFixture::new().await;
    let request_id = fixture
        .store()
        .create_secret_request("requester", "key", "restart recovery", "code", 60)
        .await
        .expect("create request");
    assert!(
        fixture
            .store()
            .submit_secret_request(&request_id, "requester", "enc", "ciphertext", 60)
            .await
            .unwrap()
    );

    let payload = fixture
        .store()
        .consume_secret_request(&request_id, "requester")
        .await
        .unwrap()
        .expect("first retrieval commits");
    assert_eq!(payload.enc, "enc");
    assert_eq!(payload.ciphertext, "ciphertext");

    fixture.restart().await;
    assert_eq!(
        fixture
            .store()
            .request_status(&request_id, "requester")
            .await
            .unwrap(),
        None
    );
    assert!(
        fixture
            .store()
            .consume_secret_request(&request_id, "requester")
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn retention_sweep_removes_expired_ciphertext_only_after_grace() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let request_id = store
        .create_secret_request("requester", "key", "sweep", "code", 1)
        .await
        .expect("create short-lived request");
    assert_eq!(store.sweep_expired(1).await.unwrap(), 0);
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert_eq!(
        store
            .request_status(&request_id, "requester")
            .await
            .unwrap(),
        None
    );
    assert_eq!(store.sweep_expired(1).await.unwrap(), 1);
    fixture.close().await;
}

#[tokio::test]
async fn agent_key_rotation_revocation_and_ip_windows_are_atomic() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let agent = store
        .create_agent(
            "contract-agent",
            "Contract Agent",
            Some("blue"),
            "argon2id$old",
        )
        .await
        .expect("create enrolled agent");
    assert_eq!(
        store.agent_by_key_id(&agent.id).await.unwrap(),
        Some(agent.clone())
    );
    let rotated = store
        .replace_agent_api_key_hash("contract-agent", agent.key_version, "argon2id$new")
        .await
        .unwrap()
        .expect("rotate active agent key");
    assert_eq!(rotated.key_version, 2);
    assert_eq!(rotated.api_key_hash, "argon2id$new");
    assert!(
        store
            .replace_agent_api_key_hash("contract-agent", agent.key_version, "argon2id$stale")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.revoke_agent("contract-agent").await.unwrap());
    assert!(!store.revoke_agent("contract-agent").await.unwrap());
    assert_eq!(
        store
            .agent_by_key_id(&agent.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "revoked"
    );

    assert_eq!(
        store
            .consume_rate_limit("token:198.51.100.1", 2, 1_000)
            .await
            .unwrap()
            .count,
        1
    );
    assert_eq!(
        store
            .consume_rate_limit("token:198.51.100.1", 2, 1_000)
            .await
            .unwrap()
            .count,
        2
    );
    assert_eq!(
        store
            .consume_rate_limit("token:198.51.100.1", 2, 1_000)
            .await
            .unwrap()
            .count,
        3
    );
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        store
            .consume_rate_limit("token:198.51.100.1", 2, 1_000)
            .await
            .unwrap()
            .count,
        1
    );
    fixture.close().await;
}

#[tokio::test]
async fn exchange_reservation_submit_and_one_use_retrieval_are_durable_and_atomic() {
    let mut fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let exchange_id = "a".repeat(64);
    let created = store
        .create_exchange(exchange_record(&exchange_id), 60)
        .await
        .expect("create exchange");
    assert_eq!(created.status, "pending");
    assert!(created.expires_at_ms > created.created_at_ms);

    let reservations = (0..12).map(|_| {
        let store = store.clone();
        let exchange_id = exchange_id.clone();
        tokio::spawn(async move {
            store
                .reserve_exchange(&exchange_id, "fulfiller")
                .await
                .unwrap()
        })
    });
    let reserved = futures_join(reservations).await;
    assert_eq!(reserved.iter().filter(|value| value.is_some()).count(), 1);
    assert_eq!(
        reserved.into_iter().flatten().next().unwrap().status,
        "reserved"
    );

    let submitted = store
        .submit_exchange(&exchange_id, "fulfiller", "ZW5j", "Y2lwaGVydGV4dA", 60)
        .await
        .unwrap()
        .expect("submit reserved exchange");
    assert_eq!(submitted.status, "submitted");
    fixture.restart().await;

    let readers = (0..12).map(|_| {
        let store = fixture.store().clone();
        let exchange_id = exchange_id.clone();
        tokio::spawn(async move {
            store
                .consume_exchange(&exchange_id, "requester")
                .await
                .unwrap()
        })
    });
    let retrieved = futures_join(readers).await;
    assert_eq!(retrieved.iter().filter(|value| value.is_some()).count(), 1);
    let payload = retrieved.into_iter().flatten().next().unwrap();
    assert_eq!(payload.enc.as_deref(), Some("ZW5j"));
    assert_eq!(payload.ciphertext.as_deref(), Some("Y2lwaGVydGV4dA"));
    assert!(
        fixture
            .store()
            .get_exchange(&exchange_id)
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn exchange_submit_racing_revocation_never_restores_ciphertext() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let exchange_id = "d".repeat(64);
    store
        .create_exchange(exchange_record(&exchange_id), 60)
        .await
        .expect("create exchange for race");
    store
        .reserve_exchange(&exchange_id, "fulfiller")
        .await
        .expect("reserve exchange")
        .expect("pending exchange is reservable");

    let (submitted, revoked) = tokio::join!(
        store.submit_exchange(&exchange_id, "fulfiller", "ZW5j", "Y2lwaGVydGV4dA", 60),
        store.revoke_exchange(&exchange_id, Some("requester"), 60),
    );
    let _ = submitted.expect("submit race completes");
    assert_eq!(
        revoked
            .expect("revoke race completes")
            .expect("requester can revoke")
            .status,
        "revoked"
    );
    let record = store
        .get_exchange(&exchange_id)
        .await
        .expect("read raced exchange")
        .expect("revocation marker persists");
    assert_eq!(record.status, "revoked");
    assert!(record.enc.is_none());
    assert!(record.ciphertext.is_none());
    assert!(
        store
            .consume_exchange(&exchange_id, "requester")
            .await
            .expect("retrieval after revocation")
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn foreign_tenant_exchange_cannot_be_read_reserved_or_revoked() {
    let fixture = StoreFixture::new().await;
    let exchange_id = "e".repeat(64);
    let insert = format!(
        "INSERT INTO exchanges
         (id, tenant_id, requester_agent_id, requester_public_key, secret_name,
          purpose, fulfiller_hint, policy_decision_json, policy_hash, status,
          created_at, expires_at)
         VALUES ('{exchange_id}', 'foreign-tenant', 'requester', 'public-key',
                 'dummy.secret', 'tenant boundary', 'fulfiller', '{{}}', 'hash',
                 'pending', 0, 4102444800000)"
    );
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL tenant fixture");
        sqlx::query(&insert)
            .execute(&pool)
            .await
            .expect("insert foreign tenant exchange");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite tenant fixture");
        sqlx::query(&insert)
            .execute(&pool)
            .await
            .expect("insert foreign tenant exchange");
        pool.close().await;
    }

    let store = fixture.store();
    assert!(store.get_exchange(&exchange_id).await.unwrap().is_none());
    assert!(
        store
            .reserve_exchange(&exchange_id, "fulfiller")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .revoke_exchange(&exchange_id, Some("requester"), 60)
            .await
            .unwrap()
            .is_none()
    );
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("reopen PostgreSQL tenant fixture");
        let status: String = sqlx::query_scalar("SELECT status FROM exchanges WHERE id = $1")
            .bind(&exchange_id)
            .fetch_one(&pool)
            .await
            .expect("read foreign tenant exchange");
        assert_eq!(status, "pending");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("reopen SQLite tenant fixture");
        let status: String = sqlx::query_scalar("SELECT status FROM exchanges WHERE id = ?")
            .bind(&exchange_id)
            .fetch_one(&pool)
            .await
            .expect("read foreign tenant exchange");
        assert_eq!(status, "pending");
        pool.close().await;
    }
    fixture.close().await;
}

#[tokio::test]
async fn exchange_expiring_while_waiting_for_lock_cannot_be_reserved() {
    let fixture = StoreFixture::new().await;
    let exchange_id = "f".repeat(64);
    fixture
        .store()
        .create_exchange(exchange_record(&exchange_id), 1)
        .await
        .expect("create short-lived exchange");

    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL lock fixture");
        let mut transaction = pool.begin().await.expect("begin row lock transaction");
        sqlx::query("SELECT id FROM exchanges WHERE id = $1 FOR UPDATE")
            .bind(&exchange_id)
            .execute(&mut *transaction)
            .await
            .expect("lock exchange row");
        let store = fixture.store().clone();
        let raced_id = exchange_id.clone();
        let reservation =
            tokio::spawn(async move { store.reserve_exchange(&raced_id, "fulfiller").await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !reservation.is_finished(),
            "reservation must wait on row lock"
        );
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        transaction.commit().await.expect("release row lock");
        assert!(
            reservation
                .await
                .expect("reservation task")
                .expect("reservation query")
                .is_none(),
            "expired exchange must not become reserved after lock release"
        );
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite lock fixture");
        let mut connection = pool
            .acquire()
            .await
            .expect("acquire SQLite lock connection");
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .expect("hold SQLite writer lock");
        let store = fixture.store().clone();
        let raced_id = exchange_id.clone();
        let reservation =
            tokio::spawn(async move { store.reserve_exchange(&raced_id, "fulfiller").await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !reservation.is_finished(),
            "reservation must wait on writer lock"
        );
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .expect("release SQLite writer lock");
        assert!(
            reservation
                .await
                .expect("reservation task")
                .expect("reservation query")
                .is_none(),
            "expired exchange must not become reserved after lock release"
        );
        drop(connection);
        pool.close().await;
    }
    fixture.close().await;
}

#[tokio::test]
async fn exchange_revocation_and_approval_decision_use_expiry_and_compare_and_set() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let exchange_id = "b".repeat(64);
    store
        .create_exchange(exchange_record(&exchange_id), 60)
        .await
        .unwrap();
    let revoked = store
        .revoke_exchange(&exchange_id, Some("requester"), 1)
        .await
        .unwrap()
        .expect("requester revokes exchange");
    assert_eq!(revoked.status, "revoked");
    assert_eq!(
        store
            .revoke_exchange(&exchange_id, Some("requester"), 1)
            .await
            .unwrap()
            .unwrap()
            .status,
        "revoked"
    );
    assert!(
        store
            .revoke_exchange(&exchange_id, Some("other"), 1)
            .await
            .unwrap()
            .is_none()
    );
    let submitted_id = "c".repeat(64);
    store
        .create_exchange(exchange_record(&submitted_id), 60)
        .await
        .unwrap();
    store
        .reserve_exchange(&submitted_id, "fulfiller")
        .await
        .unwrap()
        .unwrap();
    store
        .submit_exchange(&submitted_id, "fulfiller", "ZW5j", "Y2lwaGVydGV4dA", 60)
        .await
        .unwrap()
        .unwrap();
    let revoked_submission = store
        .revoke_exchange(&submitted_id, Some("requester"), 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked_submission.status, "revoked");
    assert!(revoked_submission.enc.is_none());
    assert!(revoked_submission.ciphertext.is_none());

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let approval = ApprovalRecord {
        approval_reference: "apr_aaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        requester_id: "requester".to_owned(),
        workspace_id: store.tenant_id().to_owned(),
        secret_name: "restricted.secret".to_owned(),
        purpose: "test approval".to_owned(),
        fulfiller_hint: "fulfiller".to_owned(),
        rule_id: Some("approval-rule".to_owned()),
        reason: "requires approval".to_owned(),
        requester_ring: None,
        fulfiller_ring: None,
        approver_ids: vec!["approver".to_owned()],
        approver_rings: Vec::new(),
        status: "pending".to_owned(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 60_000,
        decided_at_ms: None,
        decided_by: None,
    };
    store.create_approval(&approval).await.unwrap();
    assert_eq!(store.count_pending_approvals().await.unwrap(), 1);
    assert_eq!(
        store
            .list_approvals(Some("pending"), None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let approval_reference = approval.approval_reference.clone();
    let decisions = (0..8).map(|index| {
        let store = store.clone();
        let approval_reference = approval_reference.clone();
        let status = if index % 2 == 0 {
            "approved"
        } else {
            "rejected"
        };
        tokio::spawn(async move {
            store
                .decide_approval(&approval_reference, status, "approver")
                .await
                .unwrap()
        })
    });
    let decisions = futures_join(decisions).await;
    assert_eq!(decisions.iter().filter(|value| value.is_some()).count(), 1);
    let final_approval = store
        .get_approval(&approval_reference)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        final_approval.status.as_str(),
        "approved" | "rejected"
    ));
    assert_eq!(final_approval.decided_by.as_deref(), Some("approver"));
    assert_eq!(store.count_pending_approvals().await.unwrap(), 0);
    assert_eq!(
        store
            .list_approvals(Some(&final_approval.status), None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    fixture.close().await;
}

#[tokio::test]
async fn bootstrap_serializes_first_admin_creation_and_consumes_setup_tokens_once() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let bootstrap_attempts = (0..8).map(|index| {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .bootstrap_local_operator(
                    &format!("00000000-0000-4000-8000-{index:012}"),
                    "first-admin",
                    "First administrator",
                    "argon2id$fixture-hash",
                )
                .await
                .unwrap()
        })
    });
    assert_eq!(
        futures_join(bootstrap_attempts)
            .await
            .iter()
            .filter(|created| **created)
            .count(),
        1
    );
    assert!(store.has_active_admin().await.unwrap());
    assert!(
        !store
            .issue_bootstrap_token("another-token-hash", 900)
            .await
            .unwrap()
    );
    fixture.close().await;

    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    assert!(
        store
            .issue_bootstrap_token("single-use-hash", 900)
            .await
            .unwrap()
    );
    assert!(
        store
            .bootstrap_operator_with_token(
                "single-use-hash",
                "00000000-0000-4000-8000-000000000001",
                "first-admin",
                "First administrator",
                "argon2id$fixture-hash",
            )
            .await
            .unwrap()
    );
    assert!(
        !store
            .bootstrap_operator_with_token(
                "single-use-hash",
                "00000000-0000-4000-8000-000000000002",
                "second-admin",
                "Second administrator",
                "argon2id$fixture-hash",
            )
            .await
            .unwrap()
    );
    assert!(store.has_active_admin().await.unwrap());
    fixture.close().await;
}

#[tokio::test]
async fn local_browser_sessions_are_operator_bound_idle_checked_and_revocable() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let operator_id = "00000000-0000-4000-8000-000000000011";
    assert!(
        store
            .bootstrap_local_operator(operator_id, "admin", "Local Admin", "password-hash")
            .await
            .unwrap()
    );

    let session = store
        .create_browser_session(operator_id, "refresh-token-hash", 60)
        .await
        .unwrap()
        .expect("active operator receives a browser session");
    let other_session = store
        .create_browser_session(operator_id, "other-refresh-token-hash", 60)
        .await
        .unwrap()
        .expect("active operator can have another browser session");
    assert_eq!(session.operator.id, operator_id);
    assert_eq!(session.operator.role, "admin");
    assert!(!session.csrf_secret.is_empty());
    assert!(
        store
            .touch_browser_session(&session.session_id)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .browser_session_by_id(&session.session_id)
            .await
            .unwrap()
            .unwrap()
            .csrf_secret,
        session.csrf_secret
    );
    assert!(
        store
            .change_operator_password(operator_id, &session.session_id, "new-password-hash")
            .await
            .unwrap()
    );
    assert!(
        store
            .browser_session_by_id(&session.session_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .browser_session_by_id(&other_session.session_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .operator_by_username("admin")
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        "new-password-hash"
    );
    assert!(
        store
            .revoke_browser_session(&session.session_id)
            .await
            .unwrap()
    );
    assert!(
        store
            .browser_session_by_id(&session.session_id)
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn browser_refresh_rotation_and_replay_revoke_the_session_family() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let operator_id = "00000000-0000-4000-8000-000000000012";
    assert!(
        store
            .bootstrap_local_operator(operator_id, "admin", "Local Admin", "password-hash")
            .await
            .unwrap()
    );
    let first = store
        .create_browser_session(operator_id, "first-refresh-hash", 60)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .browser_session_by_refresh_hash("first-refresh-hash")
            .await
            .unwrap()
            .is_some()
    );
    let second = store
        .rotate_browser_session("first-refresh-hash", "second-refresh-hash", 60)
        .await
        .unwrap()
        .expect("first refresh rotation wins");
    assert_eq!(second.operator.id, operator_id);
    assert!(
        store
            .browser_session_by_refresh_hash("first-refresh-hash")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .rotate_browser_session("first-refresh-hash", "replay-refresh-hash", 60)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .browser_session_by_id(&first.session_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .browser_session_by_id(&second.session_id)
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn local_operator_management_preserves_a_final_admin_and_revokes_reset_sessions() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let first_admin = "00000000-0000-4000-8000-000000000013";
    let second_admin = "00000000-0000-4000-8000-000000000014";
    assert!(
        store
            .bootstrap_local_operator(first_admin, "first-admin", "First Admin", "hash-1")
            .await
            .unwrap()
    );
    assert_eq!(
        store.delete_local_operator(first_admin).await.unwrap(),
        Some(false),
        "the final admin cannot be deleted"
    );
    store
        .create_local_operator(
            second_admin,
            "second-admin",
            "Second Admin",
            "admin",
            "hash-2",
        )
        .await
        .unwrap();
    assert_eq!(store.list_local_operators().await.unwrap().len(), 2);
    assert_eq!(
        store
            .update_local_operator(first_admin, "First Admin", "viewer")
            .await
            .unwrap(),
        Some(true),
        "an admin may be demoted when another admin remains"
    );
    assert_eq!(
        store.delete_local_operator(first_admin).await.unwrap(),
        Some(true)
    );
    let session = store
        .create_browser_session(second_admin, "reset-refresh-hash", 60)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .reset_local_operator_password(second_admin, "temporary-password-hash")
            .await
            .unwrap()
    );
    assert!(
        store
            .browser_session_by_id(&session.session_id)
            .await
            .unwrap()
            .is_none()
    );
    let operator = store
        .operator_by_username("second-admin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(operator.password_hash, "temporary-password-hash");
    assert!(operator.must_change_password);
    assert_eq!(store.list_local_operators().await.unwrap().len(), 1);
    assert_eq!(
        store.delete_local_operator(second_admin).await.unwrap(),
        Some(false),
        "password reset does not bypass last-admin protection"
    );
    fixture.close().await;
}

#[tokio::test]
async fn p02_i03_policy_compare_and_set_retry_survives_store_restart() {
    let mut fixture = StoreFixture::new().await;
    let first = r#"{"secret_registry":[],"exchange_policy":[]}"#;
    assert_eq!(
        fixture
            .store()
            .replace_policy_document(1, first, "operator")
            .await
            .unwrap(),
        Some(2)
    );
    fixture.restart().await;
    assert_eq!(
        fixture
            .store()
            .replace_policy_document(1, first, "operator")
            .await
            .unwrap(),
        None,
        "a retry using the stale version cannot duplicate a committed update"
    );
    let stored = fixture.store().policy_document().await.unwrap().unwrap();
    assert_eq!(stored.version, 2);
    assert_eq!(stored.document_json, first);
    assert_eq!(
        fixture
            .store()
            .replace_policy_document(2, first, "operator")
            .await
            .unwrap(),
        Some(3)
    );
    fixture.restart().await;
    assert_eq!(
        fixture
            .store()
            .policy_document()
            .await
            .unwrap()
            .unwrap()
            .version,
        3
    );
    fixture.close().await;
}

#[tokio::test]
async fn approval_decision_is_audited_and_idempotent_by_actor_and_request() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let approval = ApprovalRecord {
        approval_reference: "apr_idempotent_decision".to_owned(),
        requester_id: "requester".to_owned(),
        workspace_id: store.tenant_id().to_owned(),
        secret_name: "restricted.secret".to_owned(),
        purpose: "approval idempotency".to_owned(),
        fulfiller_hint: "fulfiller".to_owned(),
        rule_id: Some("admin-approval".to_owned()),
        reason: "requires approval".to_owned(),
        requester_ring: None,
        fulfiller_ring: None,
        approver_ids: vec!["local-operator".to_owned()],
        approver_rings: Vec::new(),
        status: "pending".to_owned(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 60_000,
        decided_at_ms: None,
        decided_by: None,
    };
    store.create_approval(&approval).await.unwrap();
    let raw_idempotency_key = "local-idempotency-secret";
    let key_hash = blindpass_core::custody::sha256(raw_idempotency_key.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let applied = store
        .decide_approval_idempotent(
            &approval.approval_reference,
            "approved",
            "local-operator",
            &key_hash,
        )
        .await
        .unwrap();
    assert!(matches!(
        applied,
        blindpass_controller::store::ApprovalDecisionOutcome::Applied(_)
    ));
    let replay = store
        .decide_approval_idempotent(
            &approval.approval_reference,
            "approved",
            "local-operator",
            &key_hash,
        )
        .await
        .unwrap();
    assert!(matches!(
        replay,
        blindpass_controller::store::ApprovalDecisionOutcome::Replayed(_)
    ));
    let conflict = store
        .decide_approval_idempotent(
            &approval.approval_reference,
            "rejected",
            "local-operator",
            &key_hash,
        )
        .await
        .unwrap();
    assert_eq!(
        conflict,
        blindpass_controller::store::ApprovalDecisionOutcome::Conflict
    );
    let audit = store.list_audit(10).await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].event_type, "approval_decided");
    assert!(!audit[0].metadata.to_string().contains(raw_idempotency_key));
    fixture.close().await;
}

#[tokio::test]
async fn audit_retention_uses_its_own_day_limit_without_pruning_fresh_events() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    store
        .append_audit(
            "old_event",
            "system",
            None,
            "fixture",
            Some("old"),
            &serde_json::json!({}),
        )
        .await
        .expect("append old audit fixture");
    store
        .append_audit(
            "fresh_event",
            "system",
            None,
            "fixture",
            Some("fresh"),
            &serde_json::json!({}),
        )
        .await
        .expect("append fresh audit fixture");
    let three_days_ago = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as i64
        - 3 * 86_400_000;
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect audit fixture");
        sqlx::query("UPDATE audit_events SET created_at = $1 WHERE target_id = 'old'")
            .bind(three_days_ago)
            .execute(&pool)
            .await
            .expect("age old audit event");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect audit fixture");
        sqlx::query("UPDATE audit_events SET created_at = ? WHERE target_id = 'old'")
            .bind(three_days_ago)
            .execute(&pool)
            .await
            .expect("age old audit event");
        pool.close().await;
    }

    assert_eq!(store.sweep_audit(1).await.expect("sweep old audit"), 1);
    let audit = store.list_audit(10).await.expect("list retained audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].event_type, "fresh_event");
    assert_eq!(store.sweep_audit(1).await.expect("repeat sweep"), 0);
    fixture.close().await;
}

fn exchange_record(exchange_id: &str) -> ExchangeRecord {
    ExchangeRecord {
        exchange_id: exchange_id.to_owned(),
        requester_id: "requester".to_owned(),
        workspace_id: "tenant-fixture".to_owned(),
        requester_public_key: "cHVibGljLWtleQ==".to_owned(),
        secret_name: "stripe.api_key.prod".to_owned(),
        purpose: "store transition test".to_owned(),
        fulfiller_hint: "fulfiller".to_owned(),
        allowed_fulfiller_id: Some("fulfiller".to_owned()),
        fulfilled_by: None,
        policy: ExchangePolicyRecord {
            mode: "allow".to_owned(),
            approval_required: false,
            rule_id: "test-rule".to_owned(),
            reason: "test policy".to_owned(),
            approval_reference: None,
            requester_ring: None,
            fulfiller_ring: None,
            secret_name: "stripe.api_key.prod".to_owned(),
        },
        policy_hash: "policy-hash".to_owned(),
        status: "pending".to_owned(),
        prior_exchange_id: None,
        supersedes_exchange_id: None,
        created_at_ms: 0,
        expires_at_ms: 0,
        enc: None,
        ciphertext: None,
    }
}

async fn futures_join<T>(tasks: impl IntoIterator<Item = tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.expect("concurrent store worker"));
    }
    results
}
