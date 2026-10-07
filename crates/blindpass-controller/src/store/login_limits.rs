// SPDX-License-Identifier: AGPL-3.0-only

//! P07-D4 operator sign-in and bootstrap abuse state. Everything lives in
//! `rate_windows`, so expiry is the same database-clock rule as the other
//! windows and the existing sweeper bounds retention. Keys carry a SHA-256
//! of the lower-cased username, never the name or any credential.
//!
//! Two counters bound guessing without handing an attacker a denial of
//! service. The account/source pair locks after the pair limit, so a guesser
//! at one address locks only itself. The account-wide counter locks the
//! account for everyone after the larger total limit, which stops guessing
//! spread over many addresses. A failure counter opens at the first failure
//! and expires with its window; reaching a limit writes a separate lock row
//! that lives for the lockout and resets the counter. A success clears the
//! pair rows and the account counter; a password reset clears everything for
//! the account.

use super::{Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError, database_now_ms};
use crate::config::AbuseLimits;
use blindpass_core::custody::sha256;
use sqlx::Row;

const ACCOUNT_FAIL_PREFIX: &str = "operator-login-fail:";
const ACCOUNT_LOCK_PREFIX: &str = "operator-login-lock:";
const PAIR_FAIL_PREFIX: &str = "operator-login-src:";
const PAIR_LOCK_PREFIX: &str = "operator-login-slock:";
const IP_FAIL_PREFIX: &str = "operator-login-ipfail:";
const BOOTSTRAP_PEER_PREFIX: &str = "bootstrap-fail-peer:";
const BOOTSTRAP_GLOBAL_KEY: &str = "bootstrap-fail-global";
/// Bootstrap tokens live 15 minutes; the failure window matches.
const BOOTSTRAP_WINDOW_MS: u64 = 900_000;

/// Why a sign-in attempt is refused before any password is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginBlock {
    /// The client address used up its failure budget.
    IpLimited { retry_after_seconds: u64 },
    /// The account reached its failure limit and is locked.
    Locked { retry_after_seconds: u64 },
}

/// What an administrator sees about one account's sign-in locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorLockState {
    /// Seconds left on the account-wide lock; 0 when the account is not locked.
    pub account_locked_seconds: u64,
    /// Source addresses currently locked out of this account.
    pub source_locks: u64,
}

/// Stable account key for the sign-in counters: SHA-256 of the lower-cased
/// username, so counters never contain the name.
pub fn login_account_key(username: &str) -> Option<String> {
    sha256(username.trim().to_ascii_lowercase().as_bytes())
        .ok()
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// SQL `LIKE` patterns and exact keys that together cover every limiter row
/// of one account: the reset path deletes them in its own transaction.
pub(super) fn account_row_keys(account_key: &str) -> [String; 4] {
    [
        format!("{ACCOUNT_FAIL_PREFIX}{account_key}"),
        format!("{ACCOUNT_LOCK_PREFIX}{account_key}"),
        format!("{PAIR_FAIL_PREFIX}{account_key}:%"),
        format!("{PAIR_LOCK_PREFIX}{account_key}:%"),
    ]
}

/// Source part of the pair keys: 16 hex characters of SHA-256 of the client
/// address, so the key stays short and carries no address text.
fn source_key(ip: &str) -> Result<String, StoreError> {
    let digest = sha256(ip.as_bytes()).map_err(|_| StoreError::InvalidInput("source"))?;
    Ok(digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn retry_seconds(expires_at: i64, now_ms: i64) -> u64 {
    u64::try_from((expires_at - now_ms).max(0))
        .unwrap_or_default()
        .div_ceil(1_000)
        .max(1)
}

impl Store {
    /// Read-only gate evaluated before the password is verified. The address
    /// ceiling answers first so an exhausted address learns nothing about
    /// which accounts are locked.
    pub async fn login_block(
        &self,
        account_key: &str,
        ip: &str,
        limits: &AbuseLimits,
    ) -> Result<Option<LoginBlock>, StoreError> {
        let source = source_key(ip)?;
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let now_ms = database_now_ms(&self.database).await?;
            if let Some((count, expires_at)) = self
                .live_window(&format!("{IP_FAIL_PREFIX}{ip}"), now_ms)
                .await?
                && count >= i64::from(limits.login_ip_failures)
            {
                return Ok(Some(LoginBlock::IpLimited {
                    retry_after_seconds: retry_seconds(expires_at, now_ms),
                }));
            }
            let mut locked: Option<i64> = None;
            for key in [
                format!("{ACCOUNT_LOCK_PREFIX}{account_key}"),
                format!("{PAIR_LOCK_PREFIX}{account_key}:{source}"),
            ] {
                if let Some((_, expires_at)) = self.live_window(&key, now_ms).await? {
                    locked = Some(locked.map_or(expires_at, |held| held.max(expires_at)));
                }
            }
            Ok(locked.map(|expires_at| LoginBlock::Locked {
                retry_after_seconds: retry_seconds(expires_at, now_ms),
            }))
        })
        .await
    }

    /// Count one failed sign-in against the address, the account/source pair
    /// and the account. Unknown usernames are tracked only while the live
    /// rows are under the state cap; real operators always are, so a flood
    /// of invented names cannot unlock them. Reaching a limit writes the
    /// lock row.
    pub async fn record_login_failure(
        &self,
        account_key: &str,
        account_exists: bool,
        ip: &str,
        limits: &AbuseLimits,
    ) -> Result<(), StoreError> {
        let window_ms = limits.login_window_seconds * 1_000;
        let lockout_ms = limits.login_lockout_seconds * 1_000;
        let source = source_key(ip)?;
        self.consume_rate_limit(
            &format!("{IP_FAIL_PREFIX}{ip}"),
            limits.login_ip_failures,
            window_ms,
        )
        .await?;
        let pair_fail = format!("{PAIR_FAIL_PREFIX}{account_key}:{source}");
        if !account_exists && !self.may_track_unknown(&pair_fail, limits).await? {
            return Ok(());
        }
        let pair = self
            .consume_rate_limit(&pair_fail, limits.login_account_failures, window_ms)
            .await?;
        if pair.count >= i64::from(limits.login_account_failures) {
            self.consume_rate_limit(
                &format!("{PAIR_LOCK_PREFIX}{account_key}:{source}"),
                1,
                lockout_ms,
            )
            .await?;
            self.delete_windows(&[&pair_fail]).await?;
        }
        let total_fail = format!("{ACCOUNT_FAIL_PREFIX}{account_key}");
        let total = self
            .consume_rate_limit(&total_fail, limits.login_account_total_failures, window_ms)
            .await?;
        if total.count >= i64::from(limits.login_account_total_failures) {
            self.consume_rate_limit(
                &format!("{ACCOUNT_LOCK_PREFIX}{account_key}"),
                1,
                lockout_ms,
            )
            .await?;
            self.delete_windows(&[&total_fail]).await?;
        }
        Ok(())
    }

    /// Read-only lock state of one account for `blindpass admin operators list`:
    /// seconds left on the account-wide lock (0 when none) and how many source
    /// addresses are currently locked for it. Nothing is written.
    pub async fn operator_lock_state(
        &self,
        username: &str,
    ) -> Result<OperatorLockState, StoreError> {
        let Some(account_key) = login_account_key(username) else {
            return Err(StoreError::InvalidInput("username"));
        };
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let now_ms = database_now_ms(&self.database).await?;
            let account_locked_seconds = self
                .live_window(&format!("{ACCOUNT_LOCK_PREFIX}{account_key}"), now_ms)
                .await?
                .map_or(0, |(_, expires_at)| retry_seconds(expires_at, now_ms));
            let pattern = format!("{PAIR_LOCK_PREFIX}{account_key}:%");
            let source_locks: i64 = match &self.database {
                Database::Sqlite(pool) => sqlx::query_scalar(
                    "SELECT COUNT(*) FROM rate_windows WHERE key LIKE ? AND expires_at > ?",
                )
                .bind(&pattern)
                .bind(now_ms)
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?,
                Database::Postgres(pool) => sqlx::query_scalar(
                    "SELECT COUNT(*) FROM rate_windows WHERE key LIKE $1 AND expires_at > $2",
                )
                .bind(&pattern)
                .bind(now_ms)
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?,
            };
            Ok(OperatorLockState {
                account_locked_seconds,
                source_locks: u64::try_from(source_locks).unwrap_or_default(),
            })
        })
        .await
    }

    /// A successful sign-in clears the account/source pair and the account
    /// counter. An account-wide lock cannot be present on success.
    pub async fn clear_login_failures(
        &self,
        account_key: &str,
        ip: &str,
    ) -> Result<(), StoreError> {
        let source = source_key(ip)?;
        self.delete_windows(&[
            &format!("{ACCOUNT_FAIL_PREFIX}{account_key}"),
            &format!("{PAIR_FAIL_PREFIX}{account_key}:{source}"),
            &format!("{PAIR_LOCK_PREFIX}{account_key}:{source}"),
        ])
        .await
    }

    /// Count a failed bootstrap attempt against its peer shard and the whole
    /// controller. Returns the retry delay when either budget is spent. State
    /// is bounded: 256 peer shards plus one global row, never one row per
    /// address.
    pub async fn record_bootstrap_failure(
        &self,
        ip: &str,
        limits: &AbuseLimits,
    ) -> Result<Option<u64>, StoreError> {
        let shard = sha256(ip.as_bytes()).map_err(|_| StoreError::InvalidInput("peer"))?[0];
        let peer = self
            .consume_rate_limit(
                &format!("{BOOTSTRAP_PEER_PREFIX}{shard:02x}"),
                limits.bootstrap_failures_per_peer,
                BOOTSTRAP_WINDOW_MS,
            )
            .await?;
        let global = self
            .consume_rate_limit(
                BOOTSTRAP_GLOBAL_KEY,
                limits.bootstrap_failures_global,
                BOOTSTRAP_WINDOW_MS,
            )
            .await?;
        let exceeded = [
            (&peer, limits.bootstrap_failures_per_peer),
            (&global, limits.bootstrap_failures_global),
        ]
        .into_iter()
        .filter(|(window, limit)| window.count > i64::from(*limit))
        .map(|(window, _)| window.retry_after_seconds)
        .max();
        Ok(exceeded)
    }

    /// Whether the pair row for an unknown username may exist: it already
    /// does, or the live pair rows are under the cap. Every row of the other
    /// families belongs to a pair row, so this bounds all of them.
    async fn may_track_unknown(
        &self,
        fail_key: &str,
        limits: &AbuseLimits,
    ) -> Result<bool, StoreError> {
        self.run_owned(async {
            let now_ms = database_now_ms(&self.database).await?;
            if self.live_window(fail_key, now_ms).await?.is_some() {
                return Ok(true);
            }
            let pattern = format!("{PAIR_FAIL_PREFIX}%");
            let count: i64 = match &self.database {
                Database::Sqlite(pool) => sqlx::query_scalar(
                    "SELECT COUNT(*) FROM rate_windows WHERE key LIKE ? AND expires_at > ?",
                )
                .bind(&pattern)
                .bind(now_ms)
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?,
                Database::Postgres(pool) => sqlx::query_scalar(
                    "SELECT COUNT(*) FROM rate_windows WHERE key LIKE $1 AND expires_at > $2",
                )
                .bind(&pattern)
                .bind(now_ms)
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?,
            };
            Ok(count < i64::from(limits.login_tracked_accounts))
        })
        .await
    }

    async fn live_window(&self, key: &str, now_ms: i64) -> Result<Option<(i64, i64)>, StoreError> {
        let row = match &self.database {
            Database::Sqlite(pool) => sqlx::query(
                "SELECT count, expires_at FROM rate_windows WHERE key = ? AND expires_at > ?",
            )
            .bind(key)
            .bind(now_ms)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database)?
            .map(|row| {
                (
                    row.try_get::<i64, _>(0).map_err(StoreError::Database),
                    row.try_get::<i64, _>(1).map_err(StoreError::Database),
                )
            }),
            Database::Postgres(pool) => sqlx::query(
                "SELECT count, expires_at FROM rate_windows WHERE key = $1 AND expires_at > $2",
            )
            .bind(key)
            .bind(now_ms)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database)?
            .map(|row| {
                (
                    row.try_get::<i64, _>(0).map_err(StoreError::Database),
                    row.try_get::<i64, _>(1).map_err(StoreError::Database),
                )
            }),
        };
        row.map(|(count, expires_at)| Ok((count?, expires_at?)))
            .transpose()
    }

    async fn delete_windows(&self, keys: &[&str]) -> Result<(), StoreError> {
        self.run_owned(async {
            for key in keys {
                match &self.database {
                    Database::Sqlite(pool) => {
                        sqlx::query("DELETE FROM rate_windows WHERE key = ?")
                            .bind(*key)
                            .execute(pool)
                            .await
                            .map_err(StoreError::Database)?;
                    }
                    Database::Postgres(pool) => {
                        sqlx::query("DELETE FROM rate_windows WHERE key = $1")
                            .bind(*key)
                            .execute(pool)
                            .await
                            .map_err(StoreError::Database)?;
                    }
                }
            }
            Ok(())
        })
        .await
    }

    /// Whether an unused, unexpired bootstrap token matches. A failed guess
    /// reads only; no row is changed, so a guess cannot burn a valid token.
    pub async fn bootstrap_token_usable(&self, token_hash: &str) -> Result<bool, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let usable: i64 = match &self.database {
                Database::Sqlite(pool) => {
                    let sql = format!(
                        "SELECT COUNT(*) FROM bootstrap_tokens
                         WHERE token_hash = ? AND used_at IS NULL AND expires_at > {SQLITE_NOW_MS}"
                    );
                    sqlx::query_scalar(&sql)
                        .bind(token_hash)
                        .fetch_one(pool)
                        .await
                        .map_err(StoreError::Database)?
                }
                Database::Postgres(pool) => {
                    let sql = format!(
                        "SELECT COUNT(*) FROM bootstrap_tokens
                         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > {POSTGRES_NOW_MS}"
                    );
                    sqlx::query_scalar(&sql)
                        .bind(token_hash)
                        .fetch_one(pool)
                        .await
                        .map_err(StoreError::Database)?
                }
            };
            Ok(usable > 0)
        })
        .await
    }
}
