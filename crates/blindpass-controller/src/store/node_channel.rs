// SPDX-License-Identifier: AGPL-3.0-only

//! Short-lived node challenges, authenticated channel sessions and durable
//! transport inbox/event state.

use super::{Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError, new_uuid};
use sqlx::{Row, postgres::PgRow, sqlite::SqliteRow};

const NODE_CHALLENGE_TTL_MS: i64 = 60_000;
const NODE_SESSION_TTL_MS: i64 = 15 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeChallenge {
    pub id: String,
    pub tenant_id: String,
    pub node_id: String,
    pub key_version: i64,
    pub issuer_epoch: i64,
    pub protocol_version: String,
    pub capabilities_json: String,
    pub capabilities_hash: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEventInsert {
    Inserted,
    Duplicate,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxDocument {
    pub seq: i64,
    pub envelope_json: String,
}

impl Store {
    /// Create a one-use challenge only for an active node whose stored
    /// protocol and capability snapshot exactly match the handshake.
    pub async fn create_node_challenge(
        &self,
        node_id: &str,
        nonce_hash: &str,
        protocol_version: &str,
        capabilities_json: &str,
        capabilities_hash: &str,
    ) -> Result<Option<NodeChallenge>, StoreError> {
        self.checkpoint_clock().await?;
        let id = format!("ch_{}", new_uuid());
        match &self.database {
            Database::Sqlite(pool) => {
                sqlx::query(&format!(
                    "DELETE FROM node_challenges WHERE expires_at <= {SQLITE_NOW_MS}
                       OR consumed_at IS NOT NULL OR (tenant_id = ? AND node_id = ?)"
                ))
                .bind(&self.tenant_id)
                .bind(node_id)
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                let sql = format!(
                    "INSERT INTO node_challenges
                     (id, tenant_id, node_id, nonce_hash, key_version, issuer_epoch,
                      protocol_version, capabilities_json, capabilities_hash, created_at, expires_at, consumed_at)
                     SELECT ?, n.tenant_id, n.id, ?, n.key_version, m.issuer_epoch,
                            n.protocol_version, n.capabilities_json, ?, {SQLITE_NOW_MS},
                            {SQLITE_NOW_MS} + ?, NULL
                     FROM nodes n CROSS JOIN controller_meta m
                     WHERE n.id = ? AND n.tenant_id = ? AND n.status = 'active'
                       AND n.protocol_version = ? AND n.capabilities_json = ? AND m.id = 1"
                );
                let inserted = sqlx::query(&sql)
                    .bind(&id)
                    .bind(nonce_hash)
                    .bind(capabilities_hash)
                    .bind(NODE_CHALLENGE_TTL_MS)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .bind(protocol_version)
                    .bind(capabilities_json)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if inserted != 1 {
                    return Ok(None);
                }
                let sql = format!(
                    "SELECT id, tenant_id, node_id, key_version, issuer_epoch,
                            protocol_version, capabilities_json, capabilities_hash, created_at, expires_at
                     FROM node_challenges WHERE id = ? AND expires_at > {SQLITE_NOW_MS}"
                );
                sqlx::query(&sql)
                    .bind(&id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(challenge_from_sqlite)
                    .transpose()
            }
            Database::Postgres(pool) => {
                sqlx::query(&format!(
                    "DELETE FROM node_challenges WHERE expires_at <= {POSTGRES_NOW_MS}
                       OR consumed_at IS NOT NULL OR (tenant_id = $1 AND node_id = $2)"
                ))
                .bind(&self.tenant_id)
                .bind(node_id)
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                let sql = format!(
                    "INSERT INTO node_challenges
                     (id, tenant_id, node_id, nonce_hash, key_version, issuer_epoch,
                      protocol_version, capabilities_json, capabilities_hash, created_at, expires_at, consumed_at)
                     SELECT $1, n.tenant_id, n.id, $2, n.key_version, m.issuer_epoch,
                            n.protocol_version, n.capabilities_json, $3, {POSTGRES_NOW_MS},
                            {POSTGRES_NOW_MS} + $4::BIGINT, NULL
                     FROM nodes n CROSS JOIN controller_meta m
                     WHERE n.id = $5 AND n.tenant_id = $6 AND n.status = 'active'
                       AND n.protocol_version = $7 AND n.capabilities_json = $8 AND m.id = 1"
                );
                let inserted = sqlx::query(&sql)
                    .bind(&id)
                    .bind(nonce_hash)
                    .bind(capabilities_hash)
                    .bind(NODE_CHALLENGE_TTL_MS)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .bind(protocol_version)
                    .bind(capabilities_json)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if inserted != 1 {
                    return Ok(None);
                }
                let sql = format!(
                    "SELECT id, tenant_id, node_id, key_version, issuer_epoch,
                            protocol_version, capabilities_json, capabilities_hash, created_at, expires_at
                     FROM node_challenges WHERE id = $1 AND expires_at > {POSTGRES_NOW_MS}"
                );
                sqlx::query(&sql)
                    .bind(&id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(challenge_from_postgres)
                    .transpose()
            }
        }
    }

    pub async fn node_challenge(
        &self,
        node_id: &str,
        nonce_hash: &str,
    ) -> Result<Option<NodeChallenge>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT id, tenant_id, node_id, key_version, issuer_epoch,
                            protocol_version, capabilities_json, capabilities_hash, created_at, expires_at
                     FROM node_challenges WHERE tenant_id = ? AND node_id = ? AND nonce_hash = ?
                       AND consumed_at IS NULL AND expires_at > {SQLITE_NOW_MS}"
                );
                sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(node_id)
                    .bind(nonce_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(challenge_from_sqlite)
                    .transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT id, tenant_id, node_id, key_version, issuer_epoch,
                            protocol_version, capabilities_json, capabilities_hash, created_at, expires_at
                     FROM node_challenges WHERE tenant_id = $1 AND node_id = $2 AND nonce_hash = $3
                       AND consumed_at IS NULL AND expires_at > {POSTGRES_NOW_MS}"
                );
                sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(node_id)
                    .bind(nonce_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(challenge_from_postgres)
                    .transpose()
            }
        }
    }

    /// Atomically consume the signed challenge and insert its short-lived
    /// session. A losing concurrent replay observes `false`.
    pub async fn consume_node_challenge(
        &self,
        challenge: &NodeChallenge,
        nonce_hash: &str,
        session_id: &str,
        token_hash: &str,
        expires_at_ms: i64,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        if expires_at_ms <= challenge.created_at_ms
            || expires_at_ms.saturating_sub(challenge.created_at_ms)
                > NODE_SESSION_TTL_MS + NODE_CHALLENGE_TTL_MS
        {
            return Err(StoreError::InvalidInput("node session expiry"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let sql = format!(
                    "UPDATE node_challenges SET consumed_at = {SQLITE_NOW_MS}
                     WHERE id = ? AND tenant_id = ? AND node_id = ? AND nonce_hash = ?
                       AND key_version = ? AND issuer_epoch = ? AND protocol_version = ?
                       AND capabilities_json = ? AND capabilities_hash = ? AND consumed_at IS NULL
                       AND expires_at > {SQLITE_NOW_MS}
                       AND EXISTS (SELECT 1 FROM nodes n WHERE n.id = ? AND n.tenant_id = ?
                         AND n.status = 'active' AND n.key_version = ?
                         AND n.protocol_version = ? AND n.capabilities_json = ?)
                       AND EXISTS (SELECT 1 FROM controller_meta m WHERE m.id = 1 AND m.issuer_epoch = ?)"
                );
                let updated = sqlx::query(&sql)
                    .bind(&challenge.id)
                    .bind(&challenge.tenant_id)
                    .bind(&challenge.node_id)
                    .bind(nonce_hash)
                    .bind(challenge.key_version)
                    .bind(challenge.issuer_epoch)
                    .bind(&challenge.protocol_version)
                    .bind(&challenge.capabilities_json)
                    .bind(&challenge.capabilities_hash)
                    .bind(&challenge.node_id)
                    .bind(&self.tenant_id)
                    .bind(challenge.key_version)
                    .bind(&challenge.protocol_version)
                    .bind(&challenge.capabilities_json)
                    .bind(challenge.issuer_epoch)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if updated != 1 {
                    transaction.rollback().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let sql = format!(
                    "INSERT INTO node_sessions (id, node_id, nonce_hash, token_hash, created_at, expires_at, revoked_at)
                     VALUES (?, ?, ?, ?, {SQLITE_NOW_MS}, ?, NULL)"
                );
                sqlx::query(&sql)
                    .bind(session_id)
                    .bind(&challenge.node_id)
                    .bind(nonce_hash)
                    .bind(token_hash)
                    .bind(expires_at_ms)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let sql = format!(
                    "UPDATE node_challenges SET consumed_at = {POSTGRES_NOW_MS}
                     WHERE id = $1 AND tenant_id = $2 AND node_id = $3 AND nonce_hash = $4
                       AND key_version = $5 AND issuer_epoch = $6 AND protocol_version = $7
                       AND capabilities_json = $9 AND capabilities_hash = $8 AND consumed_at IS NULL
                       AND expires_at > {POSTGRES_NOW_MS}
                       AND EXISTS (SELECT 1 FROM nodes n WHERE n.id = $3 AND n.tenant_id = $2
                         AND n.status = 'active' AND n.key_version = $5
                         AND n.protocol_version = $7 AND n.capabilities_json = $9)
                       AND EXISTS (SELECT 1 FROM controller_meta m WHERE m.id = 1 AND m.issuer_epoch = $6)"
                );
                let updated = sqlx::query(&sql)
                    .bind(&challenge.id)
                    .bind(&challenge.tenant_id)
                    .bind(&challenge.node_id)
                    .bind(nonce_hash)
                    .bind(challenge.key_version)
                    .bind(challenge.issuer_epoch)
                    .bind(&challenge.protocol_version)
                    .bind(&challenge.capabilities_hash)
                    .bind(&challenge.capabilities_json)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if updated != 1 {
                    transaction.rollback().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let sql = format!(
                    "INSERT INTO node_sessions (id, node_id, nonce_hash, token_hash, created_at, expires_at, revoked_at)
                     VALUES ($1, $2, $3, $4, {POSTGRES_NOW_MS}, $5, NULL)"
                );
                sqlx::query(&sql)
                    .bind(session_id)
                    .bind(&challenge.node_id)
                    .bind(nonce_hash)
                    .bind(token_hash)
                    .bind(expires_at_ms)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    /// Validate a node bearer session against both its JWT hash and durable
    /// session row, while updating the authenticated liveness timestamp.
    pub async fn authenticate_node_session(
        &self,
        session_id: &str,
        node_id: &str,
        token_hash: &str,
        key_version: i64,
        issuer_epoch: i64,
        protocol_version: &str,
        poll: bool,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE nodes SET last_seen_at = {SQLITE_NOW_MS},
                       last_poll_at = CASE WHEN ? THEN {SQLITE_NOW_MS} ELSE last_poll_at END
                     WHERE id = ? AND tenant_id = ? AND status = 'active' AND key_version = ?
                       AND protocol_version = ?
                       AND EXISTS (SELECT 1 FROM controller_meta m WHERE m.id = 1 AND m.issuer_epoch = ?)
                       AND EXISTS (SELECT 1 FROM node_sessions s WHERE s.id = ? AND s.node_id = nodes.id
                         AND s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > {SQLITE_NOW_MS})"
                );
                let result = sqlx::query(&sql)
                    .bind(poll)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .bind(key_version)
                    .bind(protocol_version)
                    .bind(issuer_epoch)
                    .bind(session_id)
                    .bind(token_hash)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "UPDATE nodes SET last_seen_at = {POSTGRES_NOW_MS},
                       last_poll_at = CASE WHEN $1 THEN {POSTGRES_NOW_MS} ELSE last_poll_at END
                     WHERE id = $2 AND tenant_id = $3 AND status = 'active' AND key_version = $4
                       AND protocol_version = $5
                       AND EXISTS (SELECT 1 FROM controller_meta m WHERE m.id = 1 AND m.issuer_epoch = $6)
                       AND EXISTS (SELECT 1 FROM node_sessions s WHERE s.id = $7 AND s.node_id = nodes.id
                         AND s.token_hash = $8 AND s.revoked_at IS NULL AND s.expires_at > {POSTGRES_NOW_MS})"
                );
                let result = sqlx::query(&sql)
                    .bind(poll)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .bind(key_version)
                    .bind(protocol_version)
                    .bind(issuer_epoch)
                    .bind(session_id)
                    .bind(token_hash)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    /// Acknowledge only previously delivered inbox rows, mark at most fifty
    /// outstanding rows delivered, and return those rows in sequence order.
    pub async fn poll_node_inbox(
        &self,
        node_id: &str,
        ack_seq: Option<i64>,
    ) -> Result<Vec<InboxDocument>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                if let Some(ack_seq) = ack_seq {
                    let sql = format!(
                        "UPDATE node_inbox SET acked_at = {SQLITE_NOW_MS}
                         WHERE node_id = ? AND seq <= ? AND delivered_at IS NOT NULL AND acked_at IS NULL"
                    );
                    sqlx::query(&sql)
                        .bind(node_id)
                        .bind(ack_seq)
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                }
                let sql = format!(
                    "UPDATE node_inbox SET delivered_at = COALESCE(delivered_at, {SQLITE_NOW_MS})
                     WHERE node_id = ? AND acked_at IS NULL AND seq IN
                       (SELECT seq FROM node_inbox WHERE node_id = ? AND acked_at IS NULL ORDER BY seq LIMIT 50)"
                );
                sqlx::query(&sql)
                    .bind(node_id)
                    .bind(node_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let rows = sqlx::query(
                    "SELECT seq, envelope_json FROM node_inbox WHERE node_id = ? AND acked_at IS NULL ORDER BY seq LIMIT 50",
                )
                .bind(node_id)
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                let documents = rows
                    .iter()
                    .map(|row| {
                        Ok(InboxDocument {
                            seq: row.try_get("seq").map_err(StoreError::Database)?,
                            envelope_json: row
                                .try_get("envelope_json")
                                .map_err(StoreError::Database)?,
                        })
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(documents)
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                if let Some(ack_seq) = ack_seq {
                    let sql = format!(
                        "UPDATE node_inbox SET acked_at = {POSTGRES_NOW_MS}
                         WHERE node_id = $1 AND seq <= $2 AND delivered_at IS NOT NULL AND acked_at IS NULL"
                    );
                    sqlx::query(&sql)
                        .bind(node_id)
                        .bind(ack_seq)
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                }
                let sql = format!(
                    "UPDATE node_inbox SET delivered_at = COALESCE(delivered_at, {POSTGRES_NOW_MS})
                     WHERE (node_id, seq) IN
                       (SELECT node_id, seq FROM node_inbox WHERE node_id = $1 AND acked_at IS NULL ORDER BY seq LIMIT 50)"
                );
                sqlx::query(&sql)
                    .bind(node_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let rows = sqlx::query(
                    "SELECT seq, envelope_json FROM node_inbox WHERE node_id = $1 AND acked_at IS NULL ORDER BY seq LIMIT 50",
                )
                .bind(node_id)
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                let documents = rows
                    .iter()
                    .map(|row| {
                        Ok(InboxDocument {
                            seq: row.try_get("seq").map_err(StoreError::Database)?,
                            envelope_json: row
                                .try_get("envelope_json")
                                .map_err(StoreError::Database)?,
                        })
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(documents)
            }
        }
    }

    pub async fn record_node_event(
        &self,
        id: &str,
        node_id: &str,
        idempotency_key: &str,
        kind: &str,
        body_json: &str,
        body_hash: &str,
    ) -> Result<NodeEventInsert, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT INTO node_events (id, node_id, idempotency_key, kind, body_json, body_hash, received_at)
                     VALUES (?, ?, ?, ?, ?, ?, {SQLITE_NOW_MS})
                     ON CONFLICT(node_id, idempotency_key) DO NOTHING"
                );
                let result = sqlx::query(&sql)
                    .bind(id)
                    .bind(node_id)
                    .bind(idempotency_key)
                    .bind(kind)
                    .bind(body_json)
                    .bind(body_hash)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                if result.rows_affected() == 1 {
                    return Ok(NodeEventInsert::Inserted);
                }
                let existing = sqlx::query_scalar::<_, String>(
                    "SELECT body_hash FROM node_events WHERE node_id = ? AND idempotency_key = ?",
                )
                .bind(node_id)
                .bind(idempotency_key)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(if existing.as_deref() == Some(body_hash) {
                    NodeEventInsert::Duplicate
                } else {
                    NodeEventInsert::Conflict
                })
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO node_events (id, node_id, idempotency_key, kind, body_json, body_hash, received_at)
                     VALUES ($1, $2, $3, $4, $5, $6, {POSTGRES_NOW_MS})
                     ON CONFLICT(node_id, idempotency_key) DO NOTHING"
                );
                let result = sqlx::query(&sql)
                    .bind(id)
                    .bind(node_id)
                    .bind(idempotency_key)
                    .bind(kind)
                    .bind(body_json)
                    .bind(body_hash)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                if result.rows_affected() == 1 {
                    return Ok(NodeEventInsert::Inserted);
                }
                let existing = sqlx::query_scalar::<_, String>(
                    "SELECT body_hash FROM node_events WHERE node_id = $1 AND idempotency_key = $2",
                )
                .bind(node_id)
                .bind(idempotency_key)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(if existing.as_deref() == Some(body_hash) {
                    NodeEventInsert::Duplicate
                } else {
                    NodeEventInsert::Conflict
                })
            }
        }
    }
}

fn challenge_from_sqlite(row: &SqliteRow) -> Result<NodeChallenge, StoreError> {
    Ok(NodeChallenge {
        id: row.try_get("id").map_err(StoreError::Database)?,
        tenant_id: row.try_get("tenant_id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        key_version: row.try_get("key_version").map_err(StoreError::Database)?,
        issuer_epoch: row.try_get("issuer_epoch").map_err(StoreError::Database)?,
        protocol_version: row
            .try_get("protocol_version")
            .map_err(StoreError::Database)?,
        capabilities_json: row
            .try_get("capabilities_json")
            .map_err(StoreError::Database)?,
        capabilities_hash: row
            .try_get("capabilities_hash")
            .map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
    })
}

fn challenge_from_postgres(row: &PgRow) -> Result<NodeChallenge, StoreError> {
    Ok(NodeChallenge {
        id: row.try_get("id").map_err(StoreError::Database)?,
        tenant_id: row.try_get("tenant_id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        key_version: row.try_get("key_version").map_err(StoreError::Database)?,
        issuer_epoch: row.try_get("issuer_epoch").map_err(StoreError::Database)?,
        protocol_version: row
            .try_get("protocol_version")
            .map_err(StoreError::Database)?,
        capabilities_json: row
            .try_get("capabilities_json")
            .map_err(StoreError::Database)?,
        capabilities_hash: row
            .try_get("capabilities_hash")
            .map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
    })
}
