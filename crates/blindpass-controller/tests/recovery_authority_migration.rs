// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_controller::recovery_authority::{
    Authority, AuthorityContext, BrokerTrustDraft, BrokerTrustState,
};
use blindpass_core::signing::base64_url_encode;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
use std::sync::Arc;

async fn migrate(pool: &PgPool, statement: &str) -> bool {
    let mut connection = pool.acquire().await.unwrap();
    let result = sqlx::raw_sql(statement).execute(&mut *connection).await;
    if result.is_err() {
        sqlx::query("ROLLBACK")
            .execute(&mut *connection)
            .await
            .unwrap();
    }
    result.is_ok()
}

#[tokio::test]
#[ignore = "requires its own disposable PostgreSQL authority database"]
async fn p06_pt05_admin_migration_preserves_history_and_refuses_active_or_held_guards() {
    let admin_url = std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").unwrap();
    let runtime_url = std::env::var("P06_TEST_AUTHORITY_URL").unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&admin_url)
        .await
        .unwrap();
    let runtime = PgPoolOptions::new()
        .max_connections(2)
        .connect(&runtime_url)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM blindpass_authority.recovery_authority")
            .fetch_one(&admin)
            .await
            .unwrap(),
        0,
        "migration fixture must have a dedicated database"
    );
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&runtime)
        .await
        .unwrap();
    assert!(
        role.starts_with("p06_authority_")
            && role
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    let migration = include_str!("../../../deploy/controller/recovery-authority-v2-to-v3.sql")
        .replace(":\"runtime_role\"", &format!("\"{role}\""));
    sqlx::raw_sql(include_str!("support/authority-v4-fixture.sql"))
        .execute(&admin)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("support/authority-v3-fixture.sql"))
        .execute(&admin)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("support/authority-v2-fixture.sql"))
        .execute(&admin)
        .await
        .unwrap();
    sqlx::raw_sql(&format!("GRANT EXECUTE ON FUNCTION blindpass_authority.claim_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT), blindpass_authority.register_active_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER) TO \"{role}\""))
        .execute(&admin).await.unwrap();
    let context = AuthorityContext {
        tenant_id: "P06_DUMMY_MIGRATION".into(),
        issuer_key_id: "P06_DUMMY_ISSUER".into(),
        owner_id: "P06_DUMMY_OWNER".into(),
    };
    sqlx::query(
        "INSERT INTO blindpass_authority.recovery_authority VALUES ($1,$2,$3,700,40,'active')",
    )
    .bind(&context.tenant_id)
    .bind(&context.issuer_key_id)
    .bind(&context.owner_id)
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query("INSERT INTO blindpass_authority.active_process VALUES ($1,699,39,123)")
        .bind(&context.tenant_id)
        .execute(&admin)
        .await
        .unwrap();
    assert!(
        Authority::connect_existing(&runtime_url).await.is_err(),
        "startup must not upgrade v2"
    );
    assert!(
        !migrate(&admin, &migration).await,
        "active tenant must refuse migration"
    );
    assert!(
        !migrate(&runtime, &migration).await,
        "runtime role cannot migrate"
    );
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1")
        .bind(&context.tenant_id).execute(&admin).await.unwrap();
    let mut guard = PgConnection::connect(&runtime_url).await.unwrap();
    sqlx::query("BEGIN").execute(&mut guard).await.unwrap();
    let held: (i64, i64, String, i32) =
        sqlx::query_as("SELECT * FROM blindpass_authority.claim_process($1,$2,$3,700,41,'fenced')")
            .bind(&context.tenant_id)
            .bind(&context.issuer_key_id)
            .bind(&context.owner_id)
            .fetch_one(&mut guard)
            .await
            .unwrap();
    assert_eq!(held.0, 700);
    assert!(
        !migrate(&admin, &migration).await,
        "held process guard must refuse migration"
    );
    let version: i64 =
        sqlx::query_scalar("SELECT version FROM blindpass_authority.authority_layout")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(version, 2);
    let before: (i64,i64,String) = sqlx::query_as("SELECT epoch,revision,phase FROM blindpass_authority.recovery_authority WHERE tenant_id=$1")
        .bind(&context.tenant_id).fetch_one(&admin).await.unwrap();
    assert_eq!(before, (700, 41, "fenced".into()));
    sqlx::query("ROLLBACK").execute(&mut guard).await.unwrap();
    guard.close().await.unwrap();
    assert!(migrate(&admin, &migration).await);
    let after: (i64,i64,String) = sqlx::query_as("SELECT epoch,revision,phase FROM blindpass_authority.recovery_authority WHERE tenant_id=$1")
        .bind(&context.tenant_id).fetch_one(&admin).await.unwrap();
    assert_eq!(after, before);
    let historical: (i64,i64,i32,Option<Vec<u8>>) = sqlx::query_as("SELECT epoch,revision,backend_pid,holder_token_sha256 FROM blindpass_authority.active_process WHERE tenant_id=$1")
        .bind(&context.tenant_id).fetch_one(&admin).await.unwrap();
    assert_eq!(
        historical,
        (699, 39, 123, None),
        "historical attempts must not gain invented proof"
    );
    assert!(
        !migrate(&admin, &migration).await,
        "migration is not a reset/replay command"
    );
    assert!(
        Authority::connect_existing(&runtime_url).await.is_err(),
        "startup must not upgrade v3"
    );
    let receipt_migration =
        include_str!("../../../deploy/controller/recovery-authority-v3-to-v4.sql")
            .replace(":\"runtime_role\"", &format!("\"{role}\""));
    sqlx::query("INSERT INTO blindpass_authority.broker_trust (tenant_id,issuer_key_id,node_id,key_version,signing_public,recipient_public,state,revision) VALUES ($1,$2,'P06_DUMMY_PRIOR',1,$3,$4,'revoked',1)")
        .bind(&context.tenant_id).bind(&context.issuer_key_id).bind(base64_url_encode(&[31;32])).bind(base64_url_encode(&[33;32])).execute(&admin).await.unwrap();
    sqlx::query(
        "INSERT INTO blindpass_authority.broker_key_history VALUES ($1,'P06_DUMMY_PRIOR',1,$2,$3)",
    )
    .bind(&context.tenant_id)
    .bind(base64_url_encode(&[31; 32]))
    .bind(base64_url_encode(&[33; 32]))
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&context.tenant_id).execute(&admin).await.unwrap();
    assert!(
        !migrate(&admin, &receipt_migration).await,
        "active v3 tenant must refuse receipt migration"
    );
    assert!(
        !migrate(&runtime, &receipt_migration).await,
        "runtime cannot migrate v3"
    );
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1")
        .bind(&context.tenant_id).execute(&admin).await.unwrap();
    let mut guard = PgConnection::connect(&runtime_url).await.unwrap();
    sqlx::query("BEGIN").execute(&mut guard).await.unwrap();
    let held: (i64, i64, String, i32) = sqlx::query_as(
        "SELECT * FROM blindpass_authority.claim_process($1,$2,$3,700,43,'fenced',$4)",
    )
    .bind(&context.tenant_id)
    .bind(&context.issuer_key_id)
    .bind(&context.owner_id)
    .bind(vec![71_u8; 32])
    .fetch_one(&mut guard)
    .await
    .unwrap();
    assert_eq!(held.1, 43);
    assert!(
        !migrate(&admin, &receipt_migration).await,
        "held v3 guard must refuse receipt migration"
    );
    sqlx::query("ROLLBACK").execute(&mut guard).await.unwrap();
    guard.close().await.unwrap();
    let before:(i64,i64,String)=sqlx::query_as("SELECT epoch,revision,phase FROM blindpass_authority.recovery_authority WHERE tenant_id=$1")
        .bind(&context.tenant_id).fetch_one(&admin).await.unwrap();
    assert!(migrate(&admin, &receipt_migration).await);
    let after:(i64,i64,String)=sqlx::query_as("SELECT epoch,revision,phase FROM blindpass_authority.recovery_authority WHERE tenant_id=$1")
        .bind(&context.tenant_id).fetch_one(&admin).await.unwrap();
    assert_eq!(before, after);
    let prior:(i64,String,String,String,i64)=sqlx::query_as("SELECT key_version,signing_public,recipient_public,state,revision FROM blindpass_authority.broker_trust WHERE tenant_id=$1 AND node_id='P06_DUMMY_PRIOR'")
        .bind(&context.tenant_id).fetch_one(&admin).await.unwrap();
    assert_eq!(
        prior,
        (
            1,
            base64_url_encode(&[31; 32]),
            base64_url_encode(&[33; 32]),
            "revoked".into(),
            1
        )
    );
    let history_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blindpass_authority.broker_key_history WHERE tenant_id=$1",
    )
    .bind(&context.tenant_id)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(history_count, 1);
    assert!(
        !migrate(&admin, &receipt_migration).await,
        "receipt migration cannot replay/reset"
    );
    assert!(
        Authority::connect_existing(&runtime_url).await.is_err(),
        "startup must not upgrade v4"
    );
    let activation_migration =
        include_str!("../../../deploy/controller/recovery-authority-v4-to-v5.sql")
            .replace(":\"runtime_role\"", &format!("\"{role}\""));
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&context.tenant_id).execute(&admin).await.unwrap();
    assert!(
        !migrate(&admin, &activation_migration).await,
        "active v4 tenant must refuse activation migration"
    );
    assert!(
        !migrate(&runtime, &activation_migration).await,
        "runtime cannot migrate v4"
    );
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1")
        .bind(&context.tenant_id).execute(&admin).await.unwrap();
    let mut guard = PgConnection::connect(&runtime_url).await.unwrap();
    sqlx::query("BEGIN").execute(&mut guard).await.unwrap();
    sqlx::query("SELECT * FROM blindpass_authority.claim_process($1,$2,$3,700,45,'fenced',$4)")
        .bind(&context.tenant_id)
        .bind(&context.issuer_key_id)
        .bind(&context.owner_id)
        .bind(vec![72_u8; 32])
        .fetch_one(&mut guard)
        .await
        .unwrap();
    assert!(
        !migrate(&admin, &activation_migration).await,
        "held v4 guard must refuse activation migration"
    );
    sqlx::query("ROLLBACK").execute(&mut guard).await.unwrap();
    guard.close().await.unwrap();
    let before:(i64,i64,String)=sqlx::query_as("SELECT epoch,revision,phase FROM blindpass_authority.recovery_authority WHERE tenant_id=$1")
        .bind(&context.tenant_id).fetch_one(&admin).await.unwrap();
    assert_eq!(before, (700, 45, "fenced".into()));
    assert!(migrate(&admin, &activation_migration).await);
    let after:(i64,i64,String)=sqlx::query_as("SELECT epoch,revision,phase FROM blindpass_authority.recovery_authority WHERE tenant_id=$1")
        .bind(&context.tenant_id).fetch_one(&admin).await.unwrap();
    assert_eq!(before, after);
    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blindpass_authority.broker_trust WHERE tenant_id=$1",
    )
    .bind(&context.tenant_id)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(kept, 1, "migration preserves broker trust");
    for table in [
        "recovery_source_stop",
        "recovery_node_waivers",
        "recovery_review_decisions",
        "recovery_review_complete",
        "recovery_activations",
    ] {
        let rows: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM blindpass_authority.{table}"))
                .fetch_one(&admin)
                .await
                .unwrap();
        assert_eq!(rows, 0, "{table} starts empty");
    }
    assert!(
        !migrate(&admin, &activation_migration).await,
        "activation migration cannot replay/reset"
    );
    let authority = Authority::connect_existing(&runtime_url).await.unwrap();
    sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
        .bind(&context.tenant_id).execute(&admin).await.unwrap();
    let active = authority.read(&context).await.unwrap();
    assert_eq!(active.epoch, 700);
    assert_eq!(active.revision, 46);
    let owner = Arc::new(authority.claim_process(&context, &active).await.unwrap());
    let draft = BrokerTrustDraft {
        node_id: "P06_DUMMY_NODE".into(),
        key_version: 1,
        signing_public: base64_url_encode(&[41; 32]),
        recipient_public: base64_url_encode(&[43; 32]),
        state: BrokerTrustState::Active,
        pending: None,
    };
    let current = owner.publish_broker_trust(0, &draft).await.unwrap();
    assert_eq!(current.identity, draft);
    assert_eq!(
        owner.broker_trust(&draft.node_id).await.unwrap(),
        Some(current)
    );
    owner.quiesce().await.unwrap();
    drop(owner);
    authority.close().await;
    runtime.close().await;
    admin.close().await;
}
