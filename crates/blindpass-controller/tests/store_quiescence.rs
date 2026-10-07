// SPDX-License-Identifier: AGPL-3.0-only
//! Server-side faults, restricted to the wrapper's disposable controller DB.
//! Independent outcome reads do not authorize clearing an uncertain owner.
use blindpass_controller::{
    recovery_authority::{Authority, AuthorityContext, ProcessOwnership},
    store::{FleetSigner, Store},
};
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{sync::Arc, time::Duration};

struct Fixture {
    store: Store,
    observer: PgPool,
    authority_admin: PgPool,
    authority: Authority,
    context: AuthorityContext,
    owner: Arc<ProcessOwnership>,
}

impl Fixture {
    async fn new(recovering: bool) -> Self {
        let url = std::env::var("P02_TEST_POSTGRES_URL").expect("owned controller fixture");
        let base = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!(
            "qf07_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        assert!(
            schema
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&base)
            .await
            .unwrap();
        base.close().await;
        // The fixture wrapper supplies a URL without query options. Never log it.
        assert!(!url.contains('?'));
        let scoped_url = format!("{url}?options=-csearch_path%3D{schema}");
        let observer = PgPoolOptions::new()
            .max_connections(2)
            .connect(&scoped_url)
            .await
            .unwrap();
        let keypair = Arc::new(Ed25519KeyPair::from_seed(&[71; 32]).unwrap());
        let context_key = format!(
            "ed25519-{}",
            blindpass_core::signing::base64_url_encode(keypair.public_key())
        );
        let signer = FleetSigner::new(keypair);
        let store = Store::connect(&scoped_url)
            .await
            .unwrap()
            .with_fleet_signer(signer);
        let context = AuthorityContext {
            tenant_id: store.tenant_id().into(),
            issuer_key_id: context_key,
            owner_id: "P06_DUMMY_OWNER".into(),
        };
        let authority_admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").unwrap())
            .await
            .unwrap();
        let authority =
            Authority::connect_existing(&std::env::var("P06_TEST_AUTHORITY_URL").unwrap())
                .await
                .unwrap();
        sqlx::query("INSERT INTO blindpass_authority.recovery_authority (tenant_id,issuer_key_id,owner_id,epoch,revision,phase) VALUES ($1,$2,$3,1,1,'fenced')")
            .bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id)
            .execute(&authority_admin).await.unwrap();
        let record = if recovering {
            authority.reserve_recovery(&context, 1, 1).await.unwrap()
        } else {
            // Protected administrator fixture setup; not a production activation API.
            sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
                .bind(&context.tenant_id).execute(&authority_admin).await.unwrap();
            authority.read(&context).await.unwrap()
        };
        let owner = Arc::new(authority.claim_process(&context, &record).await.unwrap());
        store
            .bind_ownership(owner.clone(), &context.issuer_key_id)
            .unwrap();
        Self {
            store,
            observer,
            authority_admin,
            authority,
            context,
            owner,
        }
    }

    async fn wait_blocked(&self, commit: bool) -> i32 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let rows: Vec<(i32, String)> = sqlx::query_as("SELECT pid,query FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND state='active' AND wait_event_type='Lock' AND wait_event='advisory'")
                    .fetch_all(&self.observer).await.unwrap();
                if let Some((pid, _)) = rows.into_iter().find(|(_, query)| {
                    if commit { query == "COMMIT" } else { query.contains("INSERT INTO secret_requests") }
                }) { return pid; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("exact owned server command never reached its barrier")
    }

    async fn server_still_blocked(&self, pid: i32) -> bool {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=current_database() AND usename=current_user AND state='active' AND wait_event='advisory' AND xact_start IS NOT NULL)")
            .bind(pid).fetch_one(&self.observer).await.unwrap()
    }

    async fn wait_server_completed(&self, pid: i32) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let active: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=current_database() AND usename=current_user AND (state='active' OR xact_start IS NOT NULL))")
                    .bind(pid).fetch_one(&self.observer).await.unwrap();
                if !active { return; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("owned server command did not complete after barrier release");
    }

    async fn recovery_blocked(&self) -> bool {
        sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='fenced',revision=revision+1 WHERE tenant_id=$1")
            .bind(&self.context.tenant_id).execute(&self.authority_admin).await.unwrap();
        let record = self.authority.read(&self.context).await.unwrap();
        self.authority
            .reserve_recovery(&self.context, record.revision, record.epoch)
            .await
            .is_err()
    }

    async fn close(self) {
        self.store.close().await;
        self.observer.close().await;
        drop(self.store);
        drop(self.owner);
        self.authority.close().await;
        self.authority_admin.close().await;
        // The wrapper drops this entire uniquely named database and roles.
    }
}

async fn blocked_insert(abort: bool) {
    let f = Fixture::new(false).await;
    sqlx::raw_sql("CREATE FUNCTION qf07_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(706,7); RETURN NEW; END $$; CREATE TRIGGER qf07_before_insert BEFORE INSERT ON secret_requests FOR EACH ROW EXECUTE FUNCTION qf07_barrier();")
        .execute(&f.observer).await.unwrap();
    let mut lock = f.observer.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(706,7)")
        .execute(&mut *lock)
        .await
        .unwrap();
    let store = f.store.clone();
    let task = tokio::spawn(async move {
        store
            .create_secret_request("P06_DUMMY", "dummy", "dummy", "dummy", 60)
            .await
    });
    let pid = f.wait_blocked(false).await;
    if abort {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    } else {
        f.owner.fence();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
    assert!(
        f.owner.is_fenced(),
        "abandoning Store work must fence admission"
    );
    assert!(
        f.owner.has_uncertain_database_work(),
        "cancelled Store work did not latch database uncertainty"
    );
    let quiescence_refused = f.owner.quiesce().await.is_err();
    let still_running = f.server_still_blocked(pid).await;
    let reservation_refused = f.recovery_blocked().await;
    sqlx::query("SELECT pg_advisory_unlock(706,7)")
        .execute(&mut *lock)
        .await
        .unwrap();
    drop(lock);
    // Drain the actual driver and then read independent server state. Do not
    // infer rollback from the task result or reset the original ownership latch.
    f.store.close().await;
    f.wait_server_completed(pid).await;
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM secret_requests WHERE requester_agent_id='P06_DUMMY'",
    )
    .fetch_one(&f.observer)
    .await
    .unwrap();
    let remains_uncertain = f.owner.quiesce().await.is_err();
    f.close().await;
    assert!(
        still_running,
        "fault did not leave the owned server transaction blocked"
    );
    assert_eq!(
        rows, 1,
        "observe the late autocommit only after server completion"
    );
    assert!(
        quiescence_refused,
        "cancelled Store work reported local quiescence while PostgreSQL still ran"
    );
    assert!(
        reservation_refused,
        "uncertain Store work released its live authority guard"
    );
    assert!(
        remains_uncertain,
        "a later fixture outcome read silently cleared uncertainty"
    );
}

#[tokio::test]
#[ignore = "requires disposable separate PostgreSQL controller and restricted authority"]
async fn p06_qf07a_cancelled_autocommit_cannot_report_quiescence() {
    blocked_insert(false).await;
}

#[tokio::test]
#[ignore = "requires disposable separate PostgreSQL controller and restricted authority"]
async fn p06_qf07c_aborted_store_task_cannot_release_uncertain_guard() {
    blocked_insert(true).await;
}

#[tokio::test]
#[ignore = "requires disposable separate PostgreSQL controller and restricted authority"]
async fn p06_qf07b_cancelled_commit_may_still_commit_on_server() {
    let f = Fixture::new(true).await;
    sqlx::raw_sql("CREATE FUNCTION qf07_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(706,7); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER qf07_commit AFTER INSERT ON controller_recoveries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION qf07_barrier();")
        .execute(&f.observer).await.unwrap();
    let mut lock = f.observer.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(706,7)")
        .execute(&mut *lock)
        .await
        .unwrap();
    let store = f.store.clone();
    let owner = f.owner.clone();
    let task =
        tokio::spawn(async move { store.prepare_recovery(&owner, "P06_DUMMY_RECOVERY").await });
    let pid = f.wait_blocked(true).await;
    f.owner.fence();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let quiescence_refused = f.owner.quiesce().await.is_err();
    let still_running = f.server_still_blocked(pid).await;
    let reservation_refused = f.recovery_blocked().await;
    sqlx::query("SELECT pg_advisory_unlock(706,7)")
        .execute(&mut *lock)
        .await
        .unwrap();
    drop(lock);
    f.store.close().await;
    f.wait_server_completed(pid).await;
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM controller_recoveries WHERE recovery_id='P06_DUMMY_RECOVERY' AND phase='prepared'")
        .fetch_one(&f.observer).await.unwrap();
    let remains_uncertain = f.owner.quiesce().await.is_err();
    f.close().await;
    assert!(
        still_running,
        "fault never left a real COMMIT transaction blocked"
    );
    assert_eq!(
        rows, 1,
        "lost COMMIT acknowledgement must not be mistaken for rollback"
    );
    assert!(
        quiescence_refused,
        "cancelled COMMIT reported quiescence while the server still ran"
    );
    assert!(
        reservation_refused,
        "ambiguous COMMIT released its live authority guard"
    );
    assert!(
        remains_uncertain,
        "an independent fixture read cleared uncertainty"
    );
}

#[tokio::test]
#[ignore = "requires disposable separate PostgreSQL controller and restricted authority"]
async fn p06_qf07d_completed_store_work_can_drain_normally() {
    let f = Fixture::new(false).await;
    assert!(
        f.store
            .create_secret_request("", "dummy", "dummy", "dummy", 60)
            .await
            .is_err()
    );
    assert!(f.owner.is_active());
    assert!(!f.owner.has_uncertain_database_work());
    f.store
        .create_secret_request("P06_DUMMY", "dummy", "dummy", "dummy", 60)
        .await
        .unwrap();
    f.store.close().await;
    f.owner.quiesce().await.unwrap();
    assert!(!f.recovery_blocked().await);
    f.close().await;
}
