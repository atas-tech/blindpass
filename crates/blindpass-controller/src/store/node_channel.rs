// SPDX-License-Identifier: AGPL-3.0-only

//! Authenticated node channel sessions and durable transport inbox/event
//! state. Session challenges are stateless: the controller authenticates its
//! own nonce, and only a successfully signed nonce is recorded, one use, as
//! part of the session row.

use super::{Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError, pg};
use sqlx::Row;

const NODE_SESSION_TTL_MS: i64 = 15 * 60 * 1_000;
/// Inbox bytes returned by one poll beyond the first document. The node
/// transport bounds a response at 1 MiB, so up to eight 128 KiB Source
/// deliveries must not be answered at once.
const POLL_RESPONSE_BYTES: usize = 512 * 1024;

/// Current node identity facts needed to issue or verify a stateless session
/// challenge. Obtaining it is read-only and cannot disturb another handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSessionContext {
    pub tenant_id: String,
    pub node_id: String,
    pub key_version: i64,
    pub issuer_epoch: i64,
    pub now_ms: i64,
}

/// A verified session handshake ready to be recorded. The nonce hash is
/// unique across sessions, which makes each signed challenge one-use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSessionDraft {
    pub node_id: String,
    pub key_version: i64,
    pub issuer_epoch: i64,
    pub protocol_version: String,
    pub capabilities_json: String,
    pub nonce_hash: String,
    pub challenge_expires_at_ms: i64,
    pub session_id: String,
    pub token_hash: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEventRecord {
    pub id: String,
    pub node_id: String,
    pub idempotency_key: String,
    pub kind: String,
    pub body_json: String,
    pub body_hash: String,
    pub received_at_ms: i64,
}

/// Node rows that may authenticate a channel: active, or revoked with a
/// signed revocation still awaiting broker acknowledgement.
const CHANNEL_NODE_PREDICATE: &str = "n.id = ? AND n.tenant_id = ?
    AND (n.status = 'active' OR (n.status = 'revoked' AND EXISTS (
      SELECT 1 FROM node_revocation_queue q WHERE q.node_id = n.id
    )))
    AND n.protocol_version = ? AND n.capabilities_json = ?
    AND (n.key_version = ? OR EXISTS (
      SELECT 1 FROM node_key_rotations r WHERE r.node_id = n.id AND r.to_key_version = ?
    ))";

impl Store {
    /// Check for undelivered work without acquiring a write lock during an
    /// idle long poll. The delivery transaction rechecks this result.
    pub async fn has_pending_node_inbox(
        &self,
        node_id: &str,
        session_id: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        let sql = "SELECT EXISTS(SELECT 1 FROM node_inbox WHERE node_id = ? AND acked_at IS NULL)
            FROM node_sessions WHERE id = ? AND node_id = ?";
        match &self.database {
            Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(sql)
                .bind(node_id)
                .bind(session_id)
                .bind(node_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
                .map(|value| value != 0)
                .ok_or(StoreError::MissingState("node session")),
            Database::Postgres(pool) => sqlx::query_scalar::<_, bool>(&pg(sql))
                .bind(node_id)
                .bind(session_id)
                .bind(node_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
                .ok_or(StoreError::MissingState("node session")),
        }
    }

    /// Read the facts a stateless challenge binds for a node whose stored
    /// protocol, capabilities and current or staged key version match.
    pub async fn node_session_context(
        &self,
        node_id: &str,
        key_version: i64,
        protocol_version: &str,
        capabilities_json: &str,
    ) -> Result<Option<NodeSessionContext>, StoreError> {
        self.checkpoint_clock().await?;
        let now = match &self.database {
            Database::Sqlite(_) => SQLITE_NOW_MS,
            Database::Postgres(_) => POSTGRES_NOW_MS,
        };
        let sql = format!(
            "SELECT n.tenant_id, n.id, m.issuer_epoch, {now} AS now_ms
             FROM nodes n CROSS JOIN controller_meta m
             WHERE m.id = 1 AND {CHANNEL_NODE_PREDICATE}"
        );
        let row = match &self.database {
            Database::Sqlite(pool) => sqlx::query(&sql)
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(protocol_version)
                .bind(capabilities_json)
                .bind(key_version)
                .bind(key_version)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
                .map(|row| {
                    Ok::<_, StoreError>((
                        row.try_get::<String, _>(0).map_err(StoreError::Database)?,
                        row.try_get::<String, _>(1).map_err(StoreError::Database)?,
                        row.try_get::<i64, _>(2).map_err(StoreError::Database)?,
                        row.try_get::<i64, _>(3).map_err(StoreError::Database)?,
                    ))
                })
                .transpose()?,
            Database::Postgres(pool) => sqlx::query(&pg(&sql))
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(protocol_version)
                .bind(capabilities_json)
                .bind(key_version)
                .bind(key_version)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
                .map(|row| {
                    Ok::<_, StoreError>((
                        row.try_get::<String, _>(0).map_err(StoreError::Database)?,
                        row.try_get::<String, _>(1).map_err(StoreError::Database)?,
                        row.try_get::<i64, _>(2).map_err(StoreError::Database)?,
                        row.try_get::<i64, _>(3).map_err(StoreError::Database)?,
                    ))
                })
                .transpose()?,
        };
        Ok(row.map(
            |(tenant_id, node_id, issuer_epoch, now_ms)| NodeSessionContext {
                tenant_id,
                node_id,
                key_version,
                issuer_epoch,
                now_ms,
            },
        ))
    }

    /// Record a session for a verified signed challenge. The node state,
    /// issuer epoch and challenge deadline are re-checked under the node row
    /// lock, and the unique nonce hash makes a replayed challenge lose.
    /// The session inherits the highest inbox sequence already delivered to
    /// the node so a reconnecting relay can acknowledge what it applied.
    pub async fn create_node_session(&self, draft: &NodeSessionDraft) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        if draft.expires_at_ms <= 0
            || draft
                .expires_at_ms
                .saturating_sub(draft.challenge_expires_at_ms)
                > NODE_SESSION_TTL_MS
        {
            return Err(StoreError::InvalidInput("node session expiry"));
        }
        let (now, lock) = match &self.database {
            Database::Sqlite(_) => (
                SQLITE_NOW_MS,
                "UPDATE nodes SET version = version WHERE id = ? AND tenant_id = ?",
            ),
            Database::Postgres(_) => (
                POSTGRES_NOW_MS,
                "SELECT id FROM nodes WHERE id = ? AND tenant_id = ? FOR UPDATE",
            ),
        };
        let eligible_sql = format!(
            "SELECT COUNT(*) FROM nodes n CROSS JOIN controller_meta m
             WHERE m.id = 1 AND m.issuer_epoch = ? AND ? > {now} AND {CHANNEL_NODE_PREDICATE}"
        );
        let insert_sql = format!(
            "INSERT INTO node_sessions
             (id, node_id, nonce_hash, token_hash, created_at, expires_at, revoked_at, delivered_seq)
             VALUES (?, ?, ?, ?, {now}, ?, NULL,
               COALESCE((SELECT MAX(s.delivered_seq) FROM node_sessions s WHERE s.node_id = ?), 0))
             ON CONFLICT DO NOTHING"
        );
        macro_rules! record_session {
            ($pool:expr, $convert:expr, $tombstones:path) => {{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query(&$convert(lock))
                    .bind(&draft.node_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let eligible: i64 = sqlx::query_scalar(&$convert(&eligible_sql))
                    .bind(draft.issuer_epoch)
                    .bind(draft.challenge_expires_at_ms)
                    .bind(&draft.node_id)
                    .bind(&self.tenant_id)
                    .bind(&draft.protocol_version)
                    .bind(&draft.capabilities_json)
                    .bind(draft.key_version)
                    .bind(draft.key_version)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if eligible != 1 {
                    tx.rollback().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let inserted = sqlx::query(&$convert(&insert_sql))
                    .bind(&draft.session_id)
                    .bind(&draft.node_id)
                    .bind(&draft.nonce_hash)
                    .bind(&draft.token_hash)
                    .bind(draft.expires_at_ms)
                    .bind(&draft.node_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                if inserted != 1 {
                    tx.rollback().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                $tombstones(&mut tx, &self.tenant_id, &draft.node_id).await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => record_session!(
                pool,
                |sql: &str| sql.to_owned(),
                super::fleet_lifecycle::requeue_revocations_sqlite
            ),
            Database::Postgres(pool) => record_session!(
                pool,
                pg,
                super::fleet_lifecycle::requeue_revocations_postgres
            ),
        }
    }

    pub async fn node_signing_public_key(
        &self,
        node_id: &str,
        key_version: i64,
    ) -> Result<Option<String>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => sqlx::query_scalar(
                "SELECT h.signing_pub FROM node_key_history h JOIN nodes n ON n.id = h.node_id
                 WHERE h.node_id = ? AND h.key_version = ? AND h.retired_at IS NULL
                   AND n.tenant_id = ? AND (n.status = 'active' OR (n.status = 'revoked' AND EXISTS (
                     SELECT 1 FROM node_revocation_queue q WHERE q.node_id = n.id
                   )))",
            )
            .bind(node_id)
            .bind(key_version)
            .bind(&self.tenant_id)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database),
            Database::Postgres(pool) => sqlx::query_scalar(
                "SELECT h.signing_pub FROM node_key_history h JOIN nodes n ON n.id = h.node_id
                 WHERE h.node_id = $1 AND h.key_version = $2 AND h.retired_at IS NULL
                   AND n.tenant_id = $3 AND (n.status = 'active' OR (n.status = 'revoked' AND EXISTS (
                     SELECT 1 FROM node_revocation_queue q WHERE q.node_id = n.id
                   )))",
            )
            .bind(node_id)
            .bind(key_version)
            .bind(&self.tenant_id)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database),
        }
    }

    /// Validate a node bearer session against both its JWT hash and durable
    /// session row, while updating the authenticated liveness timestamp.
    #[allow(clippy::too_many_arguments)] // The session predicate binds each token and challenge claim.
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
                     WHERE id = ? AND tenant_id = ?
                       AND (status = 'active' OR (status = 'revoked' AND EXISTS (
                         SELECT 1 FROM node_revocation_queue q WHERE q.node_id = nodes.id
                       ))) AND (key_version = ? OR EXISTS (
                         SELECT 1 FROM node_key_rotations r WHERE r.node_id = nodes.id AND r.to_key_version = ?
                       ))
                       AND protocol_version = ?
                       AND EXISTS (SELECT 1 FROM controller_meta m WHERE m.id = 1 AND
                         (m.issuer_epoch = ? OR (nodes.status = 'revoked' AND ? <= m.issuer_epoch)))
                       AND EXISTS (SELECT 1 FROM node_sessions s WHERE s.id = ? AND s.node_id = nodes.id
                         AND s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > {SQLITE_NOW_MS})"
                );
                let result = sqlx::query(&sql)
                    .bind(poll)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .bind(key_version)
                    .bind(key_version)
                    .bind(protocol_version)
                    .bind(issuer_epoch)
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
                     WHERE id = $2 AND tenant_id = $3
                       AND (status = 'active' OR (status = 'revoked' AND EXISTS (
                         SELECT 1 FROM node_revocation_queue q WHERE q.node_id = nodes.id
                       ))) AND (key_version = $4 OR EXISTS (
                         SELECT 1 FROM node_key_rotations r WHERE r.node_id = nodes.id AND r.to_key_version = $5
                       ))
                       AND protocol_version = $6
                       AND EXISTS (SELECT 1 FROM controller_meta m WHERE m.id = 1 AND
                         (m.issuer_epoch = $7 OR (nodes.status = 'revoked' AND $8 <= m.issuer_epoch)))
                       AND EXISTS (SELECT 1 FROM node_sessions s WHERE s.id = $9 AND s.node_id = nodes.id
                         AND s.token_hash = $10 AND s.revoked_at IS NULL AND s.expires_at > {POSTGRES_NOW_MS})"
                );
                let result = sqlx::query(&sql)
                    .bind(poll)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .bind(key_version)
                    .bind(key_version)
                    .bind(protocol_version)
                    .bind(issuer_epoch)
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

    /// Acknowledge rows at or below the relay's claimed sequence, clamped to
    /// the highest sequence actually delivered to this session (including the
    /// sequence it inherited at creation), mark at most fifty outstanding rows
    /// delivered and return them in order. Delivered grant documents move
    /// their grants from `issued` to `delivered`.
    pub async fn poll_node_inbox(
        &self,
        node_id: &str,
        session_id: &str,
        ack_seq: Option<i64>,
    ) -> Result<Vec<InboxDocument>, StoreError> {
        self.checkpoint_clock().await?;
        let (now, lock) = match &self.database {
            Database::Sqlite(_) => (
                SQLITE_NOW_MS,
                "UPDATE node_sessions SET delivered_seq = delivered_seq
                 WHERE id = ? AND node_id = ? RETURNING delivered_seq",
            ),
            Database::Postgres(_) => (
                POSTGRES_NOW_MS,
                "SELECT delivered_seq FROM node_sessions WHERE id = ? AND node_id = ? FOR UPDATE",
            ),
        };
        let ack_sql = format!(
            "UPDATE node_inbox SET acked_at = {now}
             WHERE node_id = ? AND seq <= ? AND delivered_at IS NOT NULL AND acked_at IS NULL"
        );
        let deliver_sql = format!(
            "UPDATE node_inbox SET delivered_at = COALESCE(delivered_at, {now})
             WHERE node_id = ? AND acked_at IS NULL AND seq IN
               (SELECT seq FROM node_inbox WHERE node_id = ? AND acked_at IS NULL ORDER BY seq LIMIT 50)"
        );
        let select_sql = "SELECT seq, envelope_json FROM node_inbox
             WHERE node_id = ? AND acked_at IS NULL ORDER BY seq LIMIT 50";
        let advance_sql = "UPDATE node_sessions SET delivered_seq = ?
             WHERE id = ? AND node_id = ? AND delivered_seq < ?";
        let delivered_sql = "UPDATE grants SET status = 'delivered'
             WHERE id = ? AND node_id = ? AND tenant_id = ? AND status = 'issued'";
        macro_rules! poll {
            ($pool:expr, $convert:expr) => {{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                let delivered_seq: Option<i64> = sqlx::query_scalar(&$convert(lock))
                    .bind(session_id)
                    .bind(node_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let Some(delivered_seq) = delivered_seq else {
                    tx.rollback().await.map_err(StoreError::Database)?;
                    return Err(StoreError::MissingState("node session"));
                };
                if let Some(ack_seq) = ack_seq {
                    let acknowledged = ack_seq.min(delivered_seq);
                    if acknowledged > 0 {
                        sqlx::query(&$convert(&ack_sql))
                            .bind(node_id)
                            .bind(acknowledged)
                            .execute(&mut *tx)
                            .await
                            .map_err(StoreError::Database)?;
                    }
                }
                sqlx::query(&$convert(&deliver_sql))
                    .bind(node_id)
                    .bind(node_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let rows = sqlx::query(&$convert(select_sql))
                    .bind(node_id)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let mut documents = Vec::with_capacity(rows.len());
                let mut response_bytes = 0_usize;
                for row in &rows {
                    let document = InboxDocument {
                        seq: row.try_get("seq").map_err(StoreError::Database)?,
                        envelope_json: row
                            .try_get("envelope_json")
                            .map_err(StoreError::Database)?,
                    };
                    // Source deliveries may reach 128 KiB; a poll answer must
                    // stay inside the node transport's response bound. Documents
                    // left out stay unacknowledged and arrive on the next poll.
                    response_bytes = response_bytes.saturating_add(document.envelope_json.len());
                    if !documents.is_empty() && response_bytes > POLL_RESPONSE_BYTES {
                        break;
                    }
                    documents.push(document);
                }
                if let Some(highest) = documents.iter().map(|document| document.seq).max() {
                    sqlx::query(&$convert(advance_sql))
                        .bind(highest)
                        .bind(session_id)
                        .bind(node_id)
                        .bind(highest)
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                }
                for grant_id in documents
                    .iter()
                    .filter_map(|document| delivered_grant_id(&document.envelope_json))
                {
                    sqlx::query(&$convert(delivered_sql))
                        .bind(&grant_id)
                        .bind(node_id)
                        .bind(&self.tenant_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(documents)
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => poll!(pool, |sql: &str| sql.to_owned()),
            Database::Postgres(pool) => poll!(pool, pg),
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

    /// Return a previously signature-verified event only when it belongs to
    /// the specified enrolled node. Operation creation uses this to bind
    /// caller-visible requests to broker-authenticated workload evidence.
    pub async fn node_event_by_key(
        &self,
        node_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<NodeEventRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let sql = "SELECT e.id, e.node_id, e.idempotency_key, e.kind, e.body_json, e.body_hash, e.received_at
            FROM node_events e JOIN nodes n ON n.id = e.node_id
            WHERE e.node_id = ? AND e.idempotency_key = ? AND n.tenant_id = ? AND n.status = 'active'";
        match &self.database {
            Database::Sqlite(pool) => sqlx::query(sql)
                .bind(node_id)
                .bind(idempotency_key)
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
                .as_ref()
                .map(node_event_from_sqlite)
                .transpose(),
            Database::Postgres(pool) => {
                let sql = "SELECT e.id, e.node_id, e.idempotency_key, e.kind, e.body_json, e.body_hash, e.received_at
                    FROM node_events e JOIN nodes n ON n.id = e.node_id
                    WHERE e.node_id = $1 AND e.idempotency_key = $2 AND n.tenant_id = $3 AND n.status = 'active'";
                sqlx::query(sql)
                    .bind(node_id)
                    .bind(idempotency_key)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(node_event_from_postgres)
                    .transpose()
            }
        }
    }
}

fn node_event_from_sqlite(row: &sqlx::sqlite::SqliteRow) -> Result<NodeEventRecord, StoreError> {
    Ok(NodeEventRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        idempotency_key: row
            .try_get("idempotency_key")
            .map_err(StoreError::Database)?,
        kind: row.try_get("kind").map_err(StoreError::Database)?,
        body_json: row.try_get("body_json").map_err(StoreError::Database)?,
        body_hash: row.try_get("body_hash").map_err(StoreError::Database)?,
        received_at_ms: row.try_get("received_at").map_err(StoreError::Database)?,
    })
}

fn node_event_from_postgres(row: &sqlx::postgres::PgRow) -> Result<NodeEventRecord, StoreError> {
    Ok(NodeEventRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        idempotency_key: row
            .try_get("idempotency_key")
            .map_err(StoreError::Database)?,
        kind: row.try_get("kind").map_err(StoreError::Database)?,
        body_json: row.try_get("body_json").map_err(StoreError::Database)?,
        body_hash: row.try_get("body_hash").map_err(StoreError::Database)?,
        received_at_ms: row.try_get("received_at").map_err(StoreError::Database)?,
    })
}

impl Store {
    /// Look up a previously recorded event for idempotency, whatever the
    /// node's current state. Ingestion uses it to short-circuit exact
    /// duplicates without re-applying them.
    pub async fn recorded_node_event(
        &self,
        node_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<NodeEventRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let sql = "SELECT e.id, e.node_id, e.idempotency_key, e.kind, e.body_json, e.body_hash, e.received_at
            FROM node_events e JOIN nodes n ON n.id = e.node_id
            WHERE e.node_id = ? AND e.idempotency_key = ? AND n.tenant_id = ?";
        match &self.database {
            Database::Sqlite(pool) => sqlx::query(sql)
                .bind(node_id)
                .bind(idempotency_key)
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
                .as_ref()
                .map(node_event_from_sqlite)
                .transpose(),
            Database::Postgres(pool) => sqlx::query(&pg(sql))
                .bind(node_id)
                .bind(idempotency_key)
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
                .as_ref()
                .map(node_event_from_postgres)
                .transpose(),
        }
    }
}

/// The grant identifier of a signed grant document, if the inbox row is one.
fn delivered_grant_id(envelope_json: &str) -> Option<String> {
    use blindpass_core::fleet::{DocumentKind, Grant, SignedEnvelope};
    let envelope = SignedEnvelope::from_json(envelope_json).ok()?;
    if envelope.kind() != DocumentKind::Grant {
        return None;
    }
    Grant::from_value(envelope.body())
        .ok()
        .map(|grant| grant.id)
}
