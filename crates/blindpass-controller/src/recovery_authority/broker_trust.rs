// SPDX-License-Identifier: AGPL-3.0-only

//! Independent current key/revocation records; restored controller rows never
//! create trust. Only the actual active holder can publish transitions.

use super::{AuthorityError, ProcessOwnership, deadline, safe_integer};
use blindpass_core::fleet::is_valid_opaque_id;
use blindpass_core::signing::{base64_url_decode, base64_url_encode};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerTrustState {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBrokerKey {
    pub key_version: u64,
    pub rotation_id: String,
    pub signing_public: String,
    pub recipient_public: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerTrustDraft {
    pub node_id: String,
    pub key_version: u64,
    pub signing_public: String,
    pub recipient_public: String,
    pub state: BrokerTrustState,
    pub pending: Option<PendingBrokerKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerTrustRecord {
    pub tenant_id: String,
    pub issuer_key_id: String,
    pub revision: u64,
    pub identity: BrokerTrustDraft,
}

fn public_key(value: &str) -> bool {
    base64_url_decode(value, 32).is_some_and(|bytes| base64_url_encode(&bytes) == value)
}

impl BrokerTrustDraft {
    fn validate(&self) -> Result<(), AuthorityError> {
        if !is_valid_opaque_id(&self.node_id)
            || !safe_integer(self.key_version)
            || !public_key(&self.signing_public)
            || !public_key(&self.recipient_public)
            || self.pending.as_ref().is_some_and(|pending| {
                self.state != BrokerTrustState::Active
                    || !safe_integer(pending.key_version)
                    || self.key_version.checked_add(1) != Some(pending.key_version)
                    || !is_valid_opaque_id(&pending.rotation_id)
                    || !public_key(&pending.signing_public)
                    || !public_key(&pending.recipient_public)
            })
        {
            return Err(AuthorityError::InvalidInput);
        }
        Ok(())
    }
    fn state_text(&self) -> &'static str {
        match self.state {
            BrokerTrustState::Active => "active",
            BrokerTrustState::Revoked => "revoked",
        }
    }
}

type TrustRow = (
    String,
    i64,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
);
const COLUMNS: &str = "node_id,key_version,signing_public,recipient_public,state,revision,pending_key_version,pending_rotation_id,pending_signing_public,pending_recipient_public";

impl ProcessOwnership {
    fn parse_broker_trust(&self, row: TrustRow) -> Result<BrokerTrustRecord, AuthorityError> {
        let pending = match (row.6, row.7, row.8, row.9) {
            (None, None, None, None) => None,
            (Some(version), Some(rotation_id), Some(signing_public), Some(recipient_public)) => {
                Some(PendingBrokerKey {
                    key_version: u64::try_from(version).map_err(|_| AuthorityError::Unavailable)?,
                    rotation_id,
                    signing_public,
                    recipient_public,
                })
            }
            _ => return Err(AuthorityError::Unavailable),
        };
        let identity = BrokerTrustDraft {
            node_id: row.0,
            key_version: u64::try_from(row.1).map_err(|_| AuthorityError::Unavailable)?,
            signing_public: row.2,
            recipient_public: row.3,
            state: match row.4.as_str() {
                "active" => BrokerTrustState::Active,
                "revoked" => BrokerTrustState::Revoked,
                _ => return Err(AuthorityError::Unavailable),
            },
            pending,
        };
        identity
            .validate()
            .map_err(|_| AuthorityError::Unavailable)?;
        let revision = u64::try_from(row.5).map_err(|_| AuthorityError::Unavailable)?;
        if !safe_integer(revision) {
            return Err(AuthorityError::Unavailable);
        }
        Ok(BrokerTrustRecord {
            tenant_id: self.context.tenant_id.clone(),
            issuer_key_id: self.context.issuer_key_id.clone(),
            revision,
            identity,
        })
    }

    pub async fn broker_trust(
        self: &Arc<Self>,
        node_id: &str,
    ) -> Result<Option<BrokerTrustRecord>, AuthorityError> {
        if !is_valid_opaque_id(node_id) {
            return Err(AuthorityError::InvalidInput);
        }
        self.check().await?;
        let _operation = if self.is_active() {
            self.begin_operation()?
        } else {
            self.begin_recovery_operation()?
        };
        let result=deadline(async {
            tokio::select!{biased;
                _=self.wait_fenced()=>Err(AuthorityError::Unavailable),
                result=async {
                    let row=sqlx::query_as::<_,TrustRow>(&format!("SELECT {COLUMNS} FROM blindpass_authority.broker_trust WHERE tenant_id=$1 AND issuer_key_id=$2 AND node_id=$3"))
                        .bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(node_id)
                        .fetch_optional(&self.pool).await.map_err(|_|AuthorityError::Unavailable)?;
                    row.map(|row|self.parse_broker_trust(row)).transpose()
                }=>result,
            }
        }).await;
        if result.is_err() {
            self.fence();
            return result;
        }
        self.check().await?;
        result
    }

    /// Separate committed write under the held process proof. Ambiguous results
    /// retain the existing irreversible uncertainty latch; no hidden retry.
    pub async fn publish_broker_trust(
        self: &Arc<Self>,
        expected_revision: u64,
        draft: &BrokerTrustDraft,
    ) -> Result<BrokerTrustRecord, AuthorityError> {
        draft.validate()?;
        if expected_revision >= super::MAX_SAFE_INTEGER {
            return Err(AuthorityError::InvalidInput);
        }
        self.check().await?;
        let mut operation = self.begin_operation()?.database_work();
        let result=deadline(async {
            tokio::select!{biased;
                _=self.wait_fenced()=>Err(AuthorityError::Unavailable),
                result=async {
                    let pending=draft.pending.as_ref();
                    let row=sqlx::query_as::<_,TrustRow>(&format!("SELECT {COLUMNS} FROM blindpass_authority.publish_broker_trust($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)"))
                        .bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(&self.context.owner_id)
                        .bind(self.record.epoch as i64).bind(self.record.revision as i64).bind(self.backend_pid).bind(self.process_token.as_bytes())
                        .bind(expected_revision as i64).bind(&draft.node_id).bind(draft.key_version as i64)
                        .bind(&draft.signing_public).bind(&draft.recipient_public).bind(draft.state_text())
                        .bind(pending.map(|key|key.key_version as i64)).bind(pending.map(|key|key.rotation_id.as_str()))
                        .bind(pending.map(|key|key.signing_public.as_str())).bind(pending.map(|key|key.recipient_public.as_str()))
                        .fetch_optional(&self.pool).await.map_err(|error|match &error {
                            sqlx::Error::Database(error) if matches!(error.code().as_deref(),Some("23505"|"23514"|"P0001"|"40001"|"40P01"))=>AuthorityError::Conflict,
                            _=>AuthorityError::Unavailable,
                        })?.ok_or(AuthorityError::Conflict)?;
                    self.parse_broker_trust(row)
                }=>result,
            }
        }).await;
        if result.is_ok() || result == Err(AuthorityError::Conflict) {
            operation.acknowledge();
        }
        if result == Err(AuthorityError::Unavailable) {
            self.fence();
            return result;
        }
        self.check().await?;
        result
    }
}
