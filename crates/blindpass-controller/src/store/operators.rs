// SPDX-License-Identifier: AGPL-3.0-only

//! Local operator and browser-session state.

use super::{Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError, positive_milliseconds};
use rand::{RngCore, rngs::OsRng};
use sqlx::{Row, postgres::PgRow, sqlite::SqliteRow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalOperator {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
    pub role: String,
    pub must_change_password: bool,
    pub disabled_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSession {
    pub session_id: String,
    pub operator: LocalOperator,
    pub csrf_secret: String,
    pub expires_at_ms: i64,
}

const SESSION_IDLE_MS: i64 = 12 * 60 * 60 * 1_000;

impl Store {
    pub async fn has_active_admin(&self) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query("SELECT EXISTS(SELECT 1 FROM operators WHERE role = 'admin' AND disabled_at IS NULL)")
                    .fetch_one(pool).await.map_err(StoreError::Database)?;
                row.try_get::<i64, _>(0)
                    .map(|value| value != 0)
                    .map_err(StoreError::Database)
            }
            Database::Postgres(pool) => {
                let row = sqlx::query("SELECT EXISTS(SELECT 1 FROM operators WHERE role = 'admin' AND disabled_at IS NULL)")
                    .fetch_one(pool).await.map_err(StoreError::Database)?;
                row.try_get(0).map_err(StoreError::Database)
            }
        }
    }

    pub async fn bootstrap_local_operator(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                if active_admin_exists_sqlite(&mut transaction).await? {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                insert_operator_sqlite(
                    &mut transaction,
                    id,
                    username,
                    display_name,
                    password_hash,
                    true,
                )
                .await?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                if active_admin_exists_postgres(&mut transaction).await? {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                insert_operator_postgres(
                    &mut transaction,
                    id,
                    username,
                    display_name,
                    password_hash,
                    true,
                )
                .await?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    pub async fn issue_bootstrap_token(
        &self,
        token_hash: &str,
        ttl_seconds: u64,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        let ttl_ms = positive_milliseconds(ttl_seconds, "bootstrap token TTL")?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                if active_admin_exists_sqlite(&mut transaction).await? {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let sql = format!(
                    "INSERT INTO bootstrap_tokens (token_hash, expires_at, used_at)
                    VALUES (?, {SQLITE_NOW_MS} + ?, NULL)"
                );
                sqlx::query(&sql)
                    .bind(token_hash)
                    .bind(ttl_ms)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                if active_admin_exists_postgres(&mut transaction).await? {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let sql = format!(
                    "INSERT INTO bootstrap_tokens (token_hash, expires_at, used_at)
                    VALUES ($1, {POSTGRES_NOW_MS} + $2::BIGINT, NULL)"
                );
                sqlx::query(&sql)
                    .bind(token_hash)
                    .bind(ttl_ms)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    pub async fn bootstrap_operator_with_token(
        &self,
        token_hash: &str,
        id: &str,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                if active_admin_exists_sqlite(&mut transaction).await? {
                    return Ok(false);
                }
                let update = format!("UPDATE bootstrap_tokens SET used_at = {SQLITE_NOW_MS}
                    WHERE token_hash = ? AND used_at IS NULL AND expires_at > {SQLITE_NOW_MS} RETURNING token_hash");
                if sqlx::query(&update)
                    .bind(token_hash)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .is_none()
                {
                    return Ok(false);
                }
                insert_operator_sqlite(
                    &mut transaction,
                    id,
                    username,
                    display_name,
                    password_hash,
                    false,
                )
                .await?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                if active_admin_exists_postgres(&mut transaction).await? {
                    return Ok(false);
                }
                let update = format!("UPDATE bootstrap_tokens SET used_at = {POSTGRES_NOW_MS}
                    WHERE token_hash = $1 AND used_at IS NULL AND expires_at > {POSTGRES_NOW_MS} RETURNING token_hash");
                if sqlx::query(&update)
                    .bind(token_hash)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .is_none()
                {
                    return Ok(false);
                }
                insert_operator_postgres(
                    &mut transaction,
                    id,
                    username,
                    display_name,
                    password_hash,
                    false,
                )
                .await?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    pub async fn operator_by_username(
        &self,
        username: &str,
    ) -> Result<Option<LocalOperator>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT id, username, display_name, password_hash, role,
                    must_change_password, disabled_at FROM operators WHERE username = ?",
                )
                .bind(username)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                row.as_ref().map(local_operator_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, username, display_name, password_hash, role,
                    must_change_password, disabled_at FROM operators WHERE username = $1",
                )
                .bind(username)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                row.as_ref().map(local_operator_from_postgres).transpose()
            }
        }
    }

    pub async fn operator_by_id(&self, id: &str) -> Result<Option<LocalOperator>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT id, username, display_name, password_hash, role,
                    must_change_password, disabled_at FROM operators WHERE id = ?",
                )
                .bind(id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                row.as_ref().map(local_operator_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, username, display_name, password_hash, role,
                    must_change_password, disabled_at FROM operators WHERE id = $1",
                )
                .bind(id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                row.as_ref().map(local_operator_from_postgres).transpose()
            }
        }
    }

    pub async fn create_browser_session(
        &self,
        operator_id: &str,
        refresh_hash: &str,
        ttl_seconds: u64,
    ) -> Result<Option<LocalSession>, StoreError> {
        self.checkpoint_clock().await?;
        if refresh_hash.is_empty() {
            return Err(StoreError::InvalidInput("refresh hash"));
        }
        let ttl_ms = positive_milliseconds(ttl_seconds, "refresh TTL")?;
        let session_id = new_uuid();
        let csrf_secret = random_token();
        let created = match &self.database {
            Database::Sqlite(pool) => {
                let insert = format!("INSERT INTO operator_sessions
                    (id, operator_id, refresh_hash, csrf_secret, kind, created_at, expires_at,
                     rotated_from, family_id, last_seen_at)
                    SELECT ?, id, ?, ?, 'browser', {SQLITE_NOW_MS}, {SQLITE_NOW_MS} + ?, NULL, ?, {SQLITE_NOW_MS}
                    FROM operators WHERE id = ? AND disabled_at IS NULL");
                sqlx::query(&insert)
                    .bind(&session_id)
                    .bind(refresh_hash)
                    .bind(&csrf_secret)
                    .bind(ttl_ms)
                    .bind(&session_id)
                    .bind(operator_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected()
            }
            Database::Postgres(pool) => {
                let insert = format!("INSERT INTO operator_sessions
                    (id, operator_id, refresh_hash, csrf_secret, kind, created_at, expires_at,
                     rotated_from, family_id, last_seen_at)
                    SELECT $1, id, $2, $3, 'browser', {POSTGRES_NOW_MS}, {POSTGRES_NOW_MS} + $4::BIGINT, NULL, $5, {POSTGRES_NOW_MS}
                    FROM operators WHERE id = $6 AND disabled_at IS NULL");
                sqlx::query(&insert)
                    .bind(&session_id)
                    .bind(refresh_hash)
                    .bind(&csrf_secret)
                    .bind(ttl_ms)
                    .bind(&session_id)
                    .bind(operator_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected()
            }
        };
        if created != 1 {
            return Ok(None);
        }
        self.browser_session_by_id(&session_id).await
    }

    pub async fn browser_session_by_id(
        &self,
        session_id: &str,
    ) -> Result<Option<LocalSession>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let query = format!(
                    "SELECT s.id, s.csrf_secret, MIN(s.expires_at, s.last_seen_at + {SESSION_IDLE_MS}),
                    o.id, o.username, o.display_name, o.password_hash, o.role,
                    o.must_change_password, o.disabled_at
                    FROM operator_sessions s JOIN operators o ON o.id = s.operator_id
                    WHERE s.id = ? AND s.kind = 'browser' AND s.revoked_at IS NULL
                    AND s.expires_at > {SQLITE_NOW_MS}
                    AND s.last_seen_at + {SESSION_IDLE_MS} > {SQLITE_NOW_MS}
                    AND o.disabled_at IS NULL"
                );
                let row = sqlx::query(&query)
                    .bind(session_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(local_session_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let query = format!(
                    "SELECT s.id, s.csrf_secret, LEAST(s.expires_at, s.last_seen_at + {SESSION_IDLE_MS}),
                    o.id, o.username, o.display_name, o.password_hash, o.role,
                    o.must_change_password, o.disabled_at
                    FROM operator_sessions s JOIN operators o ON o.id = s.operator_id
                    WHERE s.id = $1 AND s.kind = 'browser' AND s.revoked_at IS NULL
                    AND s.expires_at > {POSTGRES_NOW_MS}
                    AND s.last_seen_at + {SESSION_IDLE_MS} > {POSTGRES_NOW_MS}
                    AND o.disabled_at IS NULL"
                );
                let row = sqlx::query(&query)
                    .bind(session_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(local_session_from_postgres).transpose()
            }
        }
    }

    pub async fn browser_session_by_refresh_hash(
        &self,
        refresh_hash: &str,
    ) -> Result<Option<LocalSession>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let query = format!(
                    "SELECT s.id, s.csrf_secret, MIN(s.expires_at, s.last_seen_at + {SESSION_IDLE_MS}),
                    o.id, o.username, o.display_name, o.password_hash, o.role,
                    o.must_change_password, o.disabled_at
                    FROM operator_sessions s JOIN operators o ON o.id = s.operator_id
                    WHERE s.refresh_hash = ? AND s.kind = 'browser' AND s.revoked_at IS NULL
                    AND s.expires_at > {SQLITE_NOW_MS}
                    AND s.last_seen_at + {SESSION_IDLE_MS} > {SQLITE_NOW_MS}
                    AND o.disabled_at IS NULL"
                );
                let row = sqlx::query(&query)
                    .bind(refresh_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(local_session_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let query = format!(
                    "SELECT s.id, s.csrf_secret, LEAST(s.expires_at, s.last_seen_at + {SESSION_IDLE_MS}),
                    o.id, o.username, o.display_name, o.password_hash, o.role,
                    o.must_change_password, o.disabled_at
                    FROM operator_sessions s JOIN operators o ON o.id = s.operator_id
                    WHERE s.refresh_hash = $1 AND s.kind = 'browser' AND s.revoked_at IS NULL
                    AND s.expires_at > {POSTGRES_NOW_MS}
                    AND s.last_seen_at + {SESSION_IDLE_MS} > {POSTGRES_NOW_MS}
                    AND o.disabled_at IS NULL"
                );
                let row = sqlx::query(&query)
                    .bind(refresh_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(local_session_from_postgres).transpose()
            }
        }
    }

    pub async fn browser_session_for_refresh_hash(
        &self,
        refresh_hash: &str,
    ) -> Result<Option<LocalSession>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let query = format!("SELECT s.id, s.csrf_secret, MIN(s.expires_at, s.last_seen_at + {SESSION_IDLE_MS}),
                    o.id, o.username, o.display_name, o.password_hash, o.role,
                    o.must_change_password, o.disabled_at
                    FROM operator_sessions s JOIN operators o ON o.id = s.operator_id
                    WHERE s.refresh_hash = ? AND s.kind = 'browser'");
                let row = sqlx::query(&query)
                    .bind(refresh_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(local_session_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let query = format!("SELECT s.id, s.csrf_secret, LEAST(s.expires_at, s.last_seen_at + {SESSION_IDLE_MS}),
                    o.id, o.username, o.display_name, o.password_hash, o.role,
                    o.must_change_password, o.disabled_at
                    FROM operator_sessions s JOIN operators o ON o.id = s.operator_id
                    WHERE s.refresh_hash = $1 AND s.kind = 'browser'");
                let row = sqlx::query(&query)
                    .bind(refresh_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(local_session_from_postgres).transpose()
            }
        }
    }

    pub async fn rotate_browser_session(
        &self,
        old_refresh_hash: &str,
        new_refresh_hash: &str,
        ttl_seconds: u64,
    ) -> Result<Option<LocalSession>, StoreError> {
        self.checkpoint_clock().await?;
        if new_refresh_hash.is_empty() {
            return Err(StoreError::InvalidInput("refresh hash"));
        }
        let ttl_ms = positive_milliseconds(ttl_seconds, "refresh TTL")?;
        let new_session_id = new_uuid();
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let query = format!(
                    "SELECT id, operator_id, family_id, csrf_secret, revoked_at,
                    expires_at > {SQLITE_NOW_MS},
                    last_seen_at + {SESSION_IDLE_MS} > {SQLITE_NOW_MS}
                    FROM operator_sessions WHERE refresh_hash = ? AND kind = 'browser'"
                );
                let row = sqlx::query(&query)
                    .bind(old_refresh_hash)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let Some(row) = row else {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                };
                let old_session_id: String = row.try_get(0).map_err(StoreError::Database)?;
                let operator_id: String = row.try_get(1).map_err(StoreError::Database)?;
                let family_id: String = row.try_get(2).map_err(StoreError::Database)?;
                let csrf_secret: String = row.try_get(3).map_err(StoreError::Database)?;
                let revoked_at: Option<i64> = row.try_get(4).map_err(StoreError::Database)?;
                let not_expired: i64 = row.try_get(5).map_err(StoreError::Database)?;
                let not_idle: i64 = row.try_get(6).map_err(StoreError::Database)?;
                if revoked_at.is_some() {
                    revoke_session_family_sqlite(&mut transaction, &family_id).await?;
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                if not_expired == 0 || not_idle == 0 {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                let update = format!("UPDATE operator_sessions SET revoked_at = {SQLITE_NOW_MS}, last_seen_at = {SQLITE_NOW_MS}
                    WHERE id = ? AND revoked_at IS NULL AND expires_at > {SQLITE_NOW_MS}
                    AND last_seen_at + {SESSION_IDLE_MS} > {SQLITE_NOW_MS}");
                let changed = sqlx::query(&update)
                    .bind(&old_session_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if changed != 1 {
                    revoke_session_family_sqlite(&mut transaction, &family_id).await?;
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                let insert = format!("INSERT INTO operator_sessions
                    (id, operator_id, refresh_hash, csrf_secret, kind, created_at, expires_at,
                     rotated_from, family_id, last_seen_at)
                    SELECT ?, ?, ?, ?, 'browser', {SQLITE_NOW_MS}, {SQLITE_NOW_MS} + ?, ?, ?, {SQLITE_NOW_MS}
                    WHERE EXISTS (SELECT 1 FROM operators WHERE id = ? AND disabled_at IS NULL)");
                let inserted = sqlx::query(&insert)
                    .bind(&new_session_id)
                    .bind(&operator_id)
                    .bind(new_refresh_hash)
                    .bind(&csrf_secret)
                    .bind(ttl_ms)
                    .bind(&old_session_id)
                    .bind(&family_id)
                    .bind(&operator_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if inserted != 1 {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                transaction.commit().await.map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let query = format!(
                    "SELECT id, operator_id, family_id, csrf_secret, revoked_at,
                    expires_at > {POSTGRES_NOW_MS},
                    last_seen_at + {SESSION_IDLE_MS} > {POSTGRES_NOW_MS}
                    FROM operator_sessions WHERE refresh_hash = $1 AND kind = 'browser' FOR UPDATE"
                );
                let row = sqlx::query(&query)
                    .bind(old_refresh_hash)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let Some(row) = row else {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                };
                let old_session_id: String = row.try_get(0).map_err(StoreError::Database)?;
                let operator_id: String = row.try_get(1).map_err(StoreError::Database)?;
                let family_id: String = row.try_get(2).map_err(StoreError::Database)?;
                let csrf_secret: String = row.try_get(3).map_err(StoreError::Database)?;
                let revoked_at: Option<i64> = row.try_get(4).map_err(StoreError::Database)?;
                let not_expired: bool = row.try_get(5).map_err(StoreError::Database)?;
                let not_idle: bool = row.try_get(6).map_err(StoreError::Database)?;
                if revoked_at.is_some() {
                    revoke_session_family_postgres(&mut transaction, &family_id).await?;
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                if !not_expired || !not_idle {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                let update = format!("UPDATE operator_sessions SET revoked_at = {POSTGRES_NOW_MS}, last_seen_at = {POSTGRES_NOW_MS}
                    WHERE id = $1 AND revoked_at IS NULL AND expires_at > {POSTGRES_NOW_MS}
                    AND last_seen_at + {SESSION_IDLE_MS} > {POSTGRES_NOW_MS}");
                let changed = sqlx::query(&update)
                    .bind(&old_session_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if changed != 1 {
                    revoke_session_family_postgres(&mut transaction, &family_id).await?;
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                let insert = format!("INSERT INTO operator_sessions
                    (id, operator_id, refresh_hash, csrf_secret, kind, created_at, expires_at,
                     rotated_from, family_id, last_seen_at)
                    SELECT $1, $2, $3, $4, 'browser', {POSTGRES_NOW_MS}, {POSTGRES_NOW_MS} + $5::BIGINT, $6, $7, {POSTGRES_NOW_MS}
                    WHERE EXISTS (SELECT 1 FROM operators WHERE id = $8 AND disabled_at IS NULL)");
                let inserted = sqlx::query(&insert)
                    .bind(&new_session_id)
                    .bind(&operator_id)
                    .bind(new_refresh_hash)
                    .bind(&csrf_secret)
                    .bind(ttl_ms)
                    .bind(&old_session_id)
                    .bind(&family_id)
                    .bind(&operator_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if inserted != 1 {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                transaction.commit().await.map_err(StoreError::Database)?;
            }
        }
        self.browser_session_by_id(&new_session_id).await
    }

    pub async fn touch_browser_session(&self, session_id: &str) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        let updated = match &self.database {
            Database::Sqlite(pool) => {
                let query = format!("UPDATE operator_sessions SET last_seen_at = {SQLITE_NOW_MS}
                    WHERE id = ? AND kind = 'browser' AND revoked_at IS NULL
                    AND expires_at > {SQLITE_NOW_MS}
                    AND last_seen_at + {SESSION_IDLE_MS} > {SQLITE_NOW_MS}
                    AND EXISTS (SELECT 1 FROM operators o WHERE o.id = operator_id AND o.disabled_at IS NULL)");
                sqlx::query(&query)
                    .bind(session_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected()
            }
            Database::Postgres(pool) => {
                let query = format!("UPDATE operator_sessions SET last_seen_at = {POSTGRES_NOW_MS}
                    WHERE id = $1 AND kind = 'browser' AND revoked_at IS NULL
                    AND expires_at > {POSTGRES_NOW_MS}
                    AND last_seen_at + {SESSION_IDLE_MS} > {POSTGRES_NOW_MS}
                    AND EXISTS (SELECT 1 FROM operators o WHERE o.id = operator_sessions.operator_id AND o.disabled_at IS NULL)");
                sqlx::query(&query)
                    .bind(session_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected()
            }
        };
        Ok(updated == 1)
    }

    pub async fn revoke_browser_session(&self, session_id: &str) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        let updated = match &self.database {
            Database::Sqlite(pool) => {
                let query = format!(
                    "UPDATE operator_sessions SET revoked_at = {SQLITE_NOW_MS}
                    WHERE id = ? AND kind = 'browser' AND revoked_at IS NULL
                      AND {SQLITE_NOW_MS} IS NOT NULL"
                );
                sqlx::query(&query)
                    .bind(session_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected()
            }
            Database::Postgres(pool) => {
                let query = format!(
                    "UPDATE operator_sessions SET revoked_at = {POSTGRES_NOW_MS}
                    WHERE id = $1 AND kind = 'browser' AND revoked_at IS NULL
                      AND {POSTGRES_NOW_MS} IS NOT NULL"
                );
                sqlx::query(&query)
                    .bind(session_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected()
            }
        };
        Ok(updated == 1)
    }

    pub async fn change_operator_password(
        &self,
        operator_id: &str,
        current_session_id: &str,
        new_password_hash: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        if new_password_hash.is_empty() {
            return Err(StoreError::InvalidInput("password hash"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let updated = sqlx::query(
                    "UPDATE operators SET password_hash = ?,
                    must_change_password = 0 WHERE id = ? AND disabled_at IS NULL",
                )
                .bind(new_password_hash)
                .bind(operator_id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                if updated != 1 {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let sql = format!(
                    "UPDATE operator_sessions SET revoked_at = {SQLITE_NOW_MS}
                    WHERE operator_id = ? AND id <> ? AND revoked_at IS NULL"
                );
                sqlx::query(&sql)
                    .bind(operator_id)
                    .bind(current_session_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let updated = sqlx::query(
                    "UPDATE operators SET password_hash = $1,
                    must_change_password = FALSE WHERE id = $2 AND disabled_at IS NULL",
                )
                .bind(new_password_hash)
                .bind(operator_id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                if updated != 1 {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let sql = format!(
                    "UPDATE operator_sessions SET revoked_at = {POSTGRES_NOW_MS}
                    WHERE operator_id = $1 AND id <> $2 AND revoked_at IS NULL"
                );
                sqlx::query(&sql)
                    .bind(operator_id)
                    .bind(current_session_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    pub async fn list_local_operators(&self) -> Result<Vec<LocalOperator>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT id, username, display_name, password_hash, role,
                    must_change_password, disabled_at FROM operators ORDER BY username, id",
                )
                .fetch_all(pool)
                .await
                .map_err(StoreError::Database)?;
                rows.iter().map(local_operator_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT id, username, display_name, password_hash, role,
                    must_change_password, disabled_at FROM operators ORDER BY username, id",
                )
                .fetch_all(pool)
                .await
                .map_err(StoreError::Database)?;
                rows.iter().map(local_operator_from_postgres).collect()
            }
        }
    }

    pub async fn create_local_operator(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        role: &str,
        password_hash: &str,
    ) -> Result<(), StoreError> {
        self.checkpoint_clock().await?;
        if !matches!(role, "admin" | "operator" | "viewer") {
            return Err(StoreError::InvalidInput("operator role"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let query = format!("INSERT INTO operators
                    (id, username, display_name, password_hash, role, must_change_password, created_at)
                    VALUES (?, ?, ?, ?, ?, 0, {SQLITE_NOW_MS})");
                sqlx::query(&query)
                    .bind(id)
                    .bind(username)
                    .bind(display_name)
                    .bind(password_hash)
                    .bind(role)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let query = format!("INSERT INTO operators
                    (id, username, display_name, password_hash, role, must_change_password, created_at)
                    VALUES ($1, $2, $3, $4, $5, FALSE, {POSTGRES_NOW_MS})");
                sqlx::query(&query)
                    .bind(id)
                    .bind(username)
                    .bind(display_name)
                    .bind(password_hash)
                    .bind(role)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }
        Ok(())
    }

    pub async fn update_local_operator(
        &self,
        id: &str,
        display_name: &str,
        role: &str,
    ) -> Result<Option<bool>, StoreError> {
        self.checkpoint_clock().await?;
        if !matches!(role, "admin" | "operator" | "viewer") {
            return Err(StoreError::InvalidInput("operator role"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let current =
                    sqlx::query("SELECT role FROM operators WHERE id = ? AND disabled_at IS NULL")
                        .bind(id)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                let Some(current) = current else {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                };
                let current_role: String = current.try_get(0).map_err(StoreError::Database)?;
                if current_role == "admin" && role != "admin" {
                    let others = sqlx::query(
                        "SELECT COUNT(*) FROM operators
                        WHERE id <> ? AND role = 'admin' AND disabled_at IS NULL",
                    )
                    .bind(id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .try_get::<i64, _>(0)
                    .map_err(StoreError::Database)?;
                    if others == 0 {
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(Some(false));
                    }
                }
                let updated = sqlx::query(
                    "UPDATE operators SET display_name = ?, role = ?
                    WHERE id = ? AND disabled_at IS NULL",
                )
                .bind(display_name)
                .bind(role)
                .bind(id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok((updated == 1).then_some(true))
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let current = sqlx::query(
                    "SELECT role FROM operators WHERE id = $1 AND disabled_at IS NULL FOR UPDATE",
                )
                .bind(id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                let Some(current) = current else {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                };
                let current_role: String = current.try_get(0).map_err(StoreError::Database)?;
                if current_role == "admin" && role != "admin" {
                    let others = sqlx::query(
                        "SELECT COUNT(*) FROM operators
                        WHERE id <> $1 AND role = 'admin' AND disabled_at IS NULL",
                    )
                    .bind(id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .try_get::<i64, _>(0)
                    .map_err(StoreError::Database)?;
                    if others == 0 {
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(Some(false));
                    }
                }
                let updated = sqlx::query(
                    "UPDATE operators SET display_name = $1, role = $2
                    WHERE id = $3 AND disabled_at IS NULL",
                )
                .bind(display_name)
                .bind(role)
                .bind(id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok((updated == 1).then_some(true))
            }
        }
    }

    pub async fn delete_local_operator(&self, id: &str) -> Result<Option<bool>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let current =
                    sqlx::query("SELECT role FROM operators WHERE id = ? AND disabled_at IS NULL")
                        .bind(id)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                let Some(current) = current else {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                };
                let role: String = current.try_get(0).map_err(StoreError::Database)?;
                if role == "admin" {
                    let others = sqlx::query(
                        "SELECT COUNT(*) FROM operators
                        WHERE id <> ? AND role = 'admin' AND disabled_at IS NULL",
                    )
                    .bind(id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .try_get::<i64, _>(0)
                    .map_err(StoreError::Database)?;
                    if others == 0 {
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(Some(false));
                    }
                }
                let deleted =
                    sqlx::query("DELETE FROM operators WHERE id = ? AND disabled_at IS NULL")
                        .bind(id)
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?
                        .rows_affected();
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok((deleted == 1).then_some(true))
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let current = sqlx::query(
                    "SELECT role FROM operators WHERE id = $1 AND disabled_at IS NULL FOR UPDATE",
                )
                .bind(id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                let Some(current) = current else {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                };
                let role: String = current.try_get(0).map_err(StoreError::Database)?;
                if role == "admin" {
                    let others = sqlx::query(
                        "SELECT COUNT(*) FROM operators
                        WHERE id <> $1 AND role = 'admin' AND disabled_at IS NULL",
                    )
                    .bind(id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .try_get::<i64, _>(0)
                    .map_err(StoreError::Database)?;
                    if others == 0 {
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(Some(false));
                    }
                }
                let deleted =
                    sqlx::query("DELETE FROM operators WHERE id = $1 AND disabled_at IS NULL")
                        .bind(id)
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?
                        .rows_affected();
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok((deleted == 1).then_some(true))
            }
        }
    }

    pub async fn reset_local_operator_password(
        &self,
        id: &str,
        password_hash: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        if password_hash.is_empty() {
            return Err(StoreError::InvalidInput("password hash"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let updated = sqlx::query(
                    "UPDATE operators SET password_hash = ?,
                    must_change_password = 1 WHERE id = ? AND disabled_at IS NULL",
                )
                .bind(password_hash)
                .bind(id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                if updated == 1 {
                    let sql = format!(
                        "UPDATE operator_sessions SET revoked_at = {SQLITE_NOW_MS}
                        WHERE operator_id = ? AND revoked_at IS NULL"
                    );
                    sqlx::query(&sql)
                        .bind(id)
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                }
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(updated == 1)
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let updated = sqlx::query(
                    "UPDATE operators SET password_hash = $1,
                    must_change_password = TRUE WHERE id = $2 AND disabled_at IS NULL",
                )
                .bind(password_hash)
                .bind(id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                if updated == 1 {
                    let sql = format!(
                        "UPDATE operator_sessions SET revoked_at = {POSTGRES_NOW_MS}
                        WHERE operator_id = $1 AND revoked_at IS NULL"
                    );
                    sqlx::query(&sql)
                        .bind(id)
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                }
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(updated == 1)
            }
        }
    }
}

async fn active_admin_exists_sqlite(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "SELECT EXISTS(SELECT 1 FROM operators WHERE role = 'admin' AND disabled_at IS NULL)",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    row.try_get::<i64, _>(0)
        .map(|value| value != 0)
        .map_err(StoreError::Database)
}

async fn active_admin_exists_postgres(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "SELECT EXISTS(SELECT 1 FROM operators WHERE role = 'admin' AND disabled_at IS NULL)",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    row.try_get(0).map_err(StoreError::Database)
}

async fn insert_operator_sqlite(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    username: &str,
    display_name: &str,
    password_hash: &str,
    must_change_password: bool,
) -> Result<(), StoreError> {
    let sql = format!(
        "INSERT INTO operators
        (id, username, display_name, password_hash, role, must_change_password, created_at)
        VALUES (?, ?, ?, ?, 'admin', ?, {SQLITE_NOW_MS})"
    );
    sqlx::query(&sql)
        .bind(id)
        .bind(username)
        .bind(display_name)
        .bind(password_hash)
        .bind(must_change_password)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

async fn insert_operator_postgres(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    username: &str,
    display_name: &str,
    password_hash: &str,
    must_change_password: bool,
) -> Result<(), StoreError> {
    let sql = format!(
        "INSERT INTO operators
        (id, username, display_name, password_hash, role, must_change_password, created_at)
        VALUES ($1, $2, $3, $4, 'admin', $5, {POSTGRES_NOW_MS})"
    );
    sqlx::query(&sql)
        .bind(id)
        .bind(username)
        .bind(display_name)
        .bind(password_hash)
        .bind(must_change_password)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn new_uuid() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let raw = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..]
    )
}

fn local_operator_from_sqlite(row: &SqliteRow) -> Result<LocalOperator, StoreError> {
    Ok(LocalOperator {
        id: row.try_get(0).map_err(StoreError::Database)?,
        username: row.try_get(1).map_err(StoreError::Database)?,
        display_name: row.try_get(2).map_err(StoreError::Database)?,
        password_hash: row.try_get(3).map_err(StoreError::Database)?,
        role: row.try_get(4).map_err(StoreError::Database)?,
        must_change_password: row
            .try_get::<i64, _>(5)
            .map(|value| value != 0)
            .map_err(StoreError::Database)?,
        disabled_at_ms: row.try_get(6).map_err(StoreError::Database)?,
    })
}

fn local_operator_from_postgres(row: &PgRow) -> Result<LocalOperator, StoreError> {
    Ok(LocalOperator {
        id: row.try_get(0).map_err(StoreError::Database)?,
        username: row.try_get(1).map_err(StoreError::Database)?,
        display_name: row.try_get(2).map_err(StoreError::Database)?,
        password_hash: row.try_get(3).map_err(StoreError::Database)?,
        role: row.try_get(4).map_err(StoreError::Database)?,
        must_change_password: row.try_get(5).map_err(StoreError::Database)?,
        disabled_at_ms: row.try_get(6).map_err(StoreError::Database)?,
    })
}

fn local_session_from_sqlite(row: &SqliteRow) -> Result<LocalSession, StoreError> {
    Ok(LocalSession {
        session_id: row.try_get(0).map_err(StoreError::Database)?,
        csrf_secret: row.try_get(1).map_err(StoreError::Database)?,
        expires_at_ms: row.try_get(2).map_err(StoreError::Database)?,
        operator: LocalOperator {
            id: row.try_get(3).map_err(StoreError::Database)?,
            username: row.try_get(4).map_err(StoreError::Database)?,
            display_name: row.try_get(5).map_err(StoreError::Database)?,
            password_hash: row.try_get(6).map_err(StoreError::Database)?,
            role: row.try_get(7).map_err(StoreError::Database)?,
            must_change_password: row
                .try_get::<i64, _>(8)
                .map(|value| value != 0)
                .map_err(StoreError::Database)?,
            disabled_at_ms: row.try_get(9).map_err(StoreError::Database)?,
        },
    })
}

fn local_session_from_postgres(row: &PgRow) -> Result<LocalSession, StoreError> {
    Ok(LocalSession {
        session_id: row.try_get(0).map_err(StoreError::Database)?,
        csrf_secret: row.try_get(1).map_err(StoreError::Database)?,
        expires_at_ms: row.try_get(2).map_err(StoreError::Database)?,
        operator: LocalOperator {
            id: row.try_get(3).map_err(StoreError::Database)?,
            username: row.try_get(4).map_err(StoreError::Database)?,
            display_name: row.try_get(5).map_err(StoreError::Database)?,
            password_hash: row.try_get(6).map_err(StoreError::Database)?,
            role: row.try_get(7).map_err(StoreError::Database)?,
            must_change_password: row.try_get(8).map_err(StoreError::Database)?,
            disabled_at_ms: row.try_get(9).map_err(StoreError::Database)?,
        },
    })
}

async fn revoke_session_family_sqlite(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    family_id: &str,
) -> Result<(), StoreError> {
    let query = format!(
        "UPDATE operator_sessions SET revoked_at = {SQLITE_NOW_MS}
        WHERE family_id = ? AND revoked_at IS NULL"
    );
    sqlx::query(&query)
        .bind(family_id)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

async fn revoke_session_family_postgres(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    family_id: &str,
) -> Result<(), StoreError> {
    let query = format!(
        "UPDATE operator_sessions SET revoked_at = {POSTGRES_NOW_MS}
        WHERE family_id = $1 AND revoked_at IS NULL"
    );
    sqlx::query(&query)
        .bind(family_id)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}
