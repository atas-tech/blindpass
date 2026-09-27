// SPDX-License-Identifier: AGPL-3.0-only

//! Audit rows written inside the transaction of the state change they record.
//!
//! Security-relevant fleet decisions must not be lost silently (pilot O02):
//! a store function that accepts an [`AuditDraft`] inserts the row before it
//! commits, so a failed audit insert rolls the action back and the route
//! answers 503.

use super::{POSTGRES_NOW_MS, SQLITE_NOW_MS, StoreError, new_hex_id};
use serde_json::{Map, Value, json};
use sqlx::{PgConnection, SqliteConnection};

/// One audit row. Metadata holds the target type, outcome and identifiers
/// only, never tokens, keys, signatures, signed documents or plaintext.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditDraft {
    pub action: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub target_type: String,
    pub target_id: Option<String>,
    pub metadata: Map<String, Value>,
}

impl AuditDraft {
    /// An operator action on one target. `details` must be a JSON object;
    /// its fields are merged after `target_type` and `outcome`.
    pub fn operator(
        operator_id: &str,
        action: &str,
        target_type: &str,
        target_id: &str,
        outcome: &str,
        details: Value,
    ) -> Self {
        let mut metadata = Map::new();
        metadata.insert("target_type".to_owned(), json!(target_type));
        metadata.insert("outcome".to_owned(), json!(outcome));
        if let Value::Object(extra) = details {
            metadata.extend(extra);
        }
        Self {
            action: action.to_owned(),
            actor_type: "operator".to_owned(),
            actor_id: Some(operator_id.to_owned()),
            target_type: target_type.to_owned(),
            target_id: Some(target_id.to_owned()),
            metadata,
        }
    }

    /// Add or replace one metadata field known only inside the transaction.
    #[must_use]
    pub fn with_detail(mut self, name: &str, value: Value) -> Self {
        self.metadata.insert(name.to_owned(), value);
        self
    }

    fn metadata_json(&self) -> Result<String, StoreError> {
        serde_json::to_string(&self.metadata)
            .map_err(|_| StoreError::InvalidInput("audit metadata"))
    }
}

pub(super) async fn insert_audit_sqlite(
    connection: &mut SqliteConnection,
    tenant_id: &str,
    draft: &AuditDraft,
) -> Result<(), StoreError> {
    let sql = format!(
        "INSERT INTO audit_events
         (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, {SQLITE_NOW_MS})"
    );
    sqlx::query(&sql)
        .bind(new_hex_id())
        .bind(tenant_id)
        .bind(&draft.actor_type)
        .bind(draft.actor_id.as_deref())
        .bind(&draft.action)
        .bind(&draft.target_type)
        .bind(draft.target_id.as_deref())
        .bind(draft.metadata_json()?)
        .execute(connection)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn insert_audit_postgres(
    connection: &mut PgConnection,
    tenant_id: &str,
    draft: &AuditDraft,
) -> Result<(), StoreError> {
    let sql = format!(
        "INSERT INTO audit_events
         (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, {POSTGRES_NOW_MS})"
    );
    sqlx::query(&sql)
        .bind(new_hex_id())
        .bind(tenant_id)
        .bind(&draft.actor_type)
        .bind(draft.actor_id.as_deref())
        .bind(&draft.action)
        .bind(&draft.target_type)
        .bind(draft.target_id.as_deref())
        .bind(draft.metadata_json()?)
        .execute(connection)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}
