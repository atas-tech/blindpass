// SPDX-License-Identifier: AGPL-3.0-only

//! Root-only browser reconciliation state. Callers are trusted broker code:
//! authorization, signed time, cookie validation and actual manager/website
//! cleanup must be established before calling these transitions. No password,
//! cookie or browser endpoint belongs in this journal. Opening after restart
//! fences every unfinished operation until explicit reconciliation succeeds
//! or the independent maximum (`release_expired`) elapses.

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const RETENTION_MS: u64 = 86_400_000;
/// Estimated trusted time can step back a little between replies (the grant
/// verifier tolerates 2 s); the journal tolerates 2.5 s and stays monotonic.
const TIME_REGRESSION_TOLERANCE_MS: u64 = 2_500;
/// Browser operation deadline (grant to endpoint delivered).
const OPERATION_DEADLINE_MS: u64 = 120_000;
/// Application session ceiling, independent of activity (see
/// `session_boot_deadline`'s 30 minute check).
const SESSION_CEILING_MS: u64 = 1_800_000;
const RELEASE_MARGIN_MS: u64 = 60_000;
/// Independent maximum: after this much trusted time from reservation no
/// helper unit (RuntimeMaxSec=60s), workload browser unit (RuntimeMaxSec=30min)
/// or application session can still be alive, so an unreconciled record may
/// release its account without a confirmed revoke.
pub(crate) const RELEASE_AFTER_MS: u64 =
    OPERATION_DEADLINE_MS + SESSION_CEILING_MS + RELEASE_MARGIN_MS;
/// An idle prune refreshes the durable high-water mark at most this often.
const HIGH_WATER_PERSIST_INTERVAL_MS: u64 = 600_000;
const MAX_RECORDS: usize = 1_024;
const MAX_BYTES: usize = 1_048_576;
const MAX_TIME: u64 = 9_007_199_254_740_991 - RETENTION_MS;
const NOFOLLOW: i32 = blindpass_core::open_flags::O_NOFOLLOW;
const NONBLOCK: i32 = 0x800;
const DIRECTORY: i32 = blindpass_core::open_flags::O_DIRECTORY;
const FAILURE: &str = "session reconciliation state unavailable";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn geteuid() -> u32;
}
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no pointers or ownership effects.
    unsafe { geteuid() }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionBinding {
    pub node_id: String,
    pub workload_id: String,
    pub operation_id: String,
    pub idempotency_key: String,
    /// Exact original request correlation; old snapshots never infer it from
    /// workload/recipe fields shared by successive requests.
    pub request_event_key: Option<String>,
    pub workload_unit: String,
    pub workload_invocation: String,
    pub resource: String,
    pub recipe_fingerprint: String,
    pub account: String,
}
#[derive(Clone, PartialEq, Eq)]
pub enum RevokeHandle {
    Fixture {
        account: String,
        session_reference: String,
    },
    GrafanaManaged {
        account: String,
        user_id: u32,
        org_id: u32,
    },
}
impl std::fmt::Debug for RevokeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevokeHandle([protected])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionReceipt {
    pub original_deadline_ms: u64,
    pub revoke_handle: RevokeHandle,
    pub browser_unit: String,
    pub browser_invocation: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Reserved,
    Active,
    Revoking,
    BlockedUncertain,
    Closed,
}
impl SessionState {
    fn name(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Revoking => "revoking",
            Self::BlockedUncertain => "blocked_uncertain",
            Self::Closed => "closed",
        }
    }
    fn parse(name: &str) -> Result<Self, &'static str> {
        match name {
            "reserved" => Ok(Self::Reserved),
            "active" => Ok(Self::Active),
            "revoking" => Ok(Self::Revoking),
            "blocked_uncertain" => Ok(Self::BlockedUncertain),
            "closed" => Ok(Self::Closed),
            _ => Err(FAILURE),
        }
    }
}
/// A record closed by the independent maximum without a confirmed revoke.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasedSession {
    pub node_id: String,
    pub idempotency_key: String,
    pub had_original_deadline: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reservation {
    New,
    Existing(SessionState),
}
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub binding: SessionBinding,
    pub state: SessionState,
    pub original_deadline_ms: Option<u64>,
    pub revoke_handle: Option<RevokeHandle>,
    pub browser_unit: Option<String>,
    pub browser_invocation: Option<String>,
    pub helper_unit: Option<String>,
    pub helper_invocation: Option<String>,
    created_at_ms: u64,
    closed_at_ms: Option<u64>,
}
pub struct SessionJournal {
    directory: File,
    _lock: File,
    owner: u32,
    records: BTreeMap<String, SessionRecord>,
    time_high_water_ms: u64,
    persisted_high_water_ms: u64,
    fenced: bool,
    source_alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    source_guards: BTreeMap<String, std::sync::Weak<std::sync::atomic::AtomicBool>>,
    context_guards: BTreeMap<String, std::sync::Weak<std::sync::atomic::AtomicBool>>,
    #[cfg(test)]
    fail_next_persist: bool,
    #[cfg(test)]
    writes: u64,
}
/// Sealed, one-use permission created only after exact helper identity is
/// durable. The duplicate shares the journal's lifetime flock; no journal
/// reference or mutex is retained during private IO.
pub(crate) struct HelperSourcePermit {
    journal_alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    operation_alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _lock: File,
}
impl HelperSourcePermit {
    pub(crate) fn allows_source(&self) -> bool {
        self.journal_alive
            .load(std::sync::atomic::Ordering::Acquire)
            && self
                .operation_alive
                .load(std::sync::atomic::Ordering::Acquire)
    }
}
impl Drop for HelperSourcePermit {
    fn drop(&mut self) {
        self.operation_alive
            .store(false, std::sync::atomic::Ordering::Release);
    }
}
impl Drop for SessionJournal {
    fn drop(&mut self) {
        self.source_alive
            .store(false, std::sync::atomic::Ordering::Release);
    }
}
impl SessionJournal {
    /// The installation must create this root-owned 0700 directory. The
    /// lifetime lock excludes a second broker/reconciler opening the journal.
    pub fn open() -> Result<Self, &'static str> {
        Self::open_at(Path::new("/var/lib/blindpass/broker/sessions"), 0)
    }
    pub(crate) fn open_at(path: &Path, owner: u32) -> Result<Self, &'static str> {
        if effective_uid() != owner {
            return Err(FAILURE);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW | DIRECTORY)
            .open(path)
            .map_err(|_| FAILURE)?;
        let metadata = directory.metadata().map_err(|_| FAILURE)?;
        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
            return Err(FAILURE);
        }
        let base = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(NOFOLLOW | NONBLOCK)
            .open(base.join(".lock"))
            .map_err(|_| FAILURE)?;
        private_file(&lock, owner)?;
        // SAFETY: fd is live; LOCK_EX | LOCK_NB does not wait for another owner.
        if unsafe { flock(lock.as_raw_fd(), 2 | 4) } != 0 {
            return Err(FAILURE);
        }
        let mut journal = Self {
            directory,
            _lock: lock,
            owner,
            records: BTreeMap::new(),
            time_high_water_ms: 0,
            persisted_high_water_ms: 0,
            fenced: false,
            source_alive: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            source_guards: BTreeMap::new(),
            context_guards: BTreeMap::new(),
            #[cfg(test)]
            fail_next_persist: false,
            #[cfg(test)]
            writes: 0,
        };
        match OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW | NONBLOCK)
            .open(base.join("state.json"))
        {
            Ok(file) => {
                private_file(&file, owner)?;
                let mut body = Vec::new();
                file.take((MAX_BYTES + 1) as u64)
                    .read_to_end(&mut body)
                    .map_err(|_| FAILURE)?;
                if body.len() > MAX_BYTES {
                    return Err(FAILURE);
                }
                journal.load(&body)?;
                let mut changed = false;
                for record in journal.records.values_mut() {
                    if record.state != SessionState::Closed
                        && record.state != SessionState::BlockedUncertain
                    {
                        record.state = SessionState::BlockedUncertain;
                        changed = true;
                    }
                }
                if changed {
                    journal.persist()?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => journal.persist()?,
            Err(_) => return Err(FAILURE),
        }
        Ok(journal)
    }
    /// Only New authorizes the coordinator to start its first login. Existing
    /// is a status replay, never permission to retry the external effect.
    pub fn reserve(
        &mut self,
        binding: SessionBinding,
        trusted_time_ms: u64,
    ) -> Result<Reservation, &'static str> {
        let trusted_time_ms = self.effective_time(trusted_time_ms)?;
        validate_binding(&binding)?;
        if let Some(existing) = self.records.get(&binding.operation_id) {
            if existing.binding != binding {
                return Err("session binding conflict");
            }
            let state = existing.state;
            if trusted_time_ms > self.time_high_water_ms {
                self.time_high_water_ms = trusted_time_ms;
                self.persist()?;
            }
            return Ok(Reservation::Existing(state));
        }
        if self.records.len() >= MAX_RECORDS {
            return Err("session journal capacity reached");
        }
        if self.records.values().any(|record| {
            record.binding.idempotency_key == binding.idempotency_key
                || record.state != SessionState::Closed
                    && (record.binding.account == binding.account
                        || record.binding.workload_unit == binding.workload_unit)
        }) {
            return Err("session account or workload unavailable");
        }
        self.records.insert(
            binding.operation_id.clone(),
            SessionRecord {
                binding,
                state: SessionState::Reserved,
                original_deadline_ms: None,
                revoke_handle: None,
                browser_unit: None,
                browser_invocation: None,
                helper_unit: None,
                helper_invocation: None,
                created_at_ms: trusted_time_ms,
                closed_at_ms: None,
            },
        );
        self.time_high_water_ms = trusted_time_ms;
        self.persist()?;
        Ok(Reservation::New)
    }
    /// Trusted Root observation from a held reverse kernel proof, never worker
    /// claims. Persist before sending the source; one operation cannot acquire
    /// a replacement helper invocation, even if the first login reply was lost.
    pub fn record_helper(
        &mut self,
        operation: &str,
        unit: &str,
        invocation: &str,
        trusted_time_ms: u64,
    ) -> Result<(), &'static str> {
        let trusted_time_ms = self.effective_time(trusted_time_ms)?;
        if !crate::runtime_identity::valid_helper_unit(unit) || !valid_invocation(invocation) {
            return Err("session helper binding invalid");
        }
        let record = self
            .records
            .get_mut(operation)
            .ok_or("session operation unavailable")?;
        if record.state != SessionState::Reserved
            || record.helper_unit.is_some()
            || record.revoke_handle.is_some()
            || trusted_time_ms - record.created_at_ms > 120_000
        {
            return Err("session helper is not pending");
        }
        record.helper_unit = Some(unit.into());
        record.helper_invocation = Some(invocation.into());
        self.time_high_water_ms = trusted_time_ms;
        self.persist()
    }
    /// Persist the nonbearer server revocation handle immediately after private
    /// authentication, BEFORE launching or importing into a workload browser.
    pub fn record_login(
        &mut self,
        operation: &str,
        original_deadline_ms: u64,
        handle: RevokeHandle,
        trusted_time_ms: u64,
    ) -> Result<(), &'static str> {
        self.withdraw_helper_source(operation);
        let trusted_time_ms = self.effective_time(trusted_time_ms)?;
        let record = self
            .records
            .get_mut(operation)
            .ok_or("session operation unavailable")?;
        if record.state != SessionState::Reserved
            || record.revoke_handle.is_some()
            || record.helper_unit.is_none()
        {
            return Err("session login is not pending");
        }
        validate_handle(&handle, &record.binding.account)?;
        if original_deadline_ms <= trusted_time_ms
            || original_deadline_ms > MAX_TIME
            || trusted_time_ms - record.created_at_ms > 120_000
            || original_deadline_ms > trusted_time_ms.checked_add(1_800_000).ok_or(FAILURE)?
        {
            return Err("session deadline invalid");
        }
        record.original_deadline_ms = Some(original_deadline_ms);
        record.revoke_handle = Some(handle);
        self.time_high_water_ms = trusted_time_ms;
        self.persist()
    }
    /// The coordinator has already journaled the login handle. These exact
    /// manager identities must be persisted BEFORE importing any cookie.
    pub fn activate(
        &mut self,
        operation: &str,
        receipt: SessionReceipt,
        trusted_time_ms: u64,
    ) -> Result<(), &'static str> {
        let trusted_time_ms = self.effective_time(trusted_time_ms)?;
        let record = self
            .records
            .get_mut(operation)
            .ok_or("session operation unavailable")?;
        if record.state != SessionState::Reserved {
            return Err("session activation is not pending");
        }
        validate_handle(&receipt.revoke_handle, &record.binding.account)?;
        if !valid_unit(&receipt.browser_unit)
            || record.helper_unit.is_none()
            || !valid_invocation(&receipt.browser_invocation)
            || record.original_deadline_ms != Some(receipt.original_deadline_ms)
            || record.revoke_handle.as_ref() != Some(&receipt.revoke_handle)
            || receipt.original_deadline_ms <= trusted_time_ms
            || trusted_time_ms - record.created_at_ms > 120_000
        {
            return Err("session receipt binding invalid");
        }
        record.browser_unit = Some(receipt.browser_unit);
        record.browser_invocation = Some(receipt.browser_invocation);
        record.state = SessionState::Active;
        self.time_high_water_ms = trusted_time_ms;
        self.persist()
    }
    pub fn begin_revoke(
        &mut self,
        operation: &str,
        trusted_time_ms: u64,
    ) -> Result<(), &'static str> {
        self.withdraw_helper_source(operation);
        let trusted_time_ms = self.effective_time(trusted_time_ms)?;
        let record = self
            .records
            .get_mut(operation)
            .ok_or("session operation unavailable")?;
        if record.state == SessionState::Closed {
            return Ok(());
        }
        record.state = SessionState::Revoking;
        self.time_high_water_ms = trusted_time_ms;
        self.persist()
    }
    /// Booleans are trusted reconciler observations, never workload/model
    /// claims. Process termination must include BOTH the private helper and
    /// workload browser, so no late private authentication can recreate a
    /// session after logout. A session deadline alone does not release an account, especially
    /// when the authentication result was lost or an old helper might still run; only confirmed
    /// reconciliation or the independent maximum (`release_expired`) does.
    pub fn reconcile(
        &mut self,
        operation: &str,
        website_revoked: bool,
        verified_processes_terminated: bool,
        trusted_time_ms: u64,
    ) -> Result<(), &'static str> {
        self.withdraw_helper_source(operation);
        let trusted_time_ms = self.effective_time(trusted_time_ms)?;
        let record = self
            .records
            .get_mut(operation)
            .ok_or("session operation unavailable")?;
        if record.state == SessionState::Closed {
            return Ok(());
        }
        if !website_revoked || !verified_processes_terminated {
            record.state = SessionState::BlockedUncertain;
            self.time_high_water_ms = trusted_time_ms;
            self.persist()?;
            return Err("session reconciliation incomplete");
        }
        record.state = SessionState::Closed;
        record.closed_at_ms = Some(trusted_time_ms);
        record.revoke_handle = None;
        record.browser_unit = None;
        record.browser_invocation = None;
        record.helper_unit = None;
        record.helper_invocation = None;
        self.time_high_water_ms = trusted_time_ms;
        self.persist()
    }
    #[must_use]
    pub fn pending(&self) -> Vec<&SessionRecord> {
        self.records
            .values()
            .filter(|record| record.state != SessionState::Closed)
            .collect()
    }
    pub(crate) fn closed_browser_records(&self) -> Vec<&SessionRecord> {
        self.records
            .values()
            .filter(|record| {
                record.state == SessionState::Closed
                    && record.original_deadline_ms.is_some()
                    && record.closed_at_ms.is_some()
            })
            .collect()
    }
    pub(crate) fn guard_context(
        &mut self,
        operation: &str,
        guard: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), &'static str> {
        if self.fenced
            || self.context_guards.contains_key(operation)
            || self
                .records
                .get(operation)
                .is_none_or(|record| record.state != SessionState::Active)
        {
            return Err(FAILURE);
        }
        self.context_guards
            .insert(operation.into(), std::sync::Arc::downgrade(guard));
        Ok(())
    }
    pub(crate) fn availability(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.source_alive)
    }
    pub(crate) fn context_is_active(
        &self,
        grant: &str,
        unit: &str,
        invocation: &str,
        time: u64,
    ) -> bool {
        !self.fenced
            && self.records.values().any(|record| {
                record.binding.idempotency_key == grant
                    && record.state == SessionState::Active
                    && record
                        .original_deadline_ms
                        .is_some_and(|deadline| time < deadline)
                    && record.browser_unit.as_deref() == Some(unit)
                    && record.browser_invocation.as_deref() == Some(invocation)
            })
    }
    pub(crate) fn replay_binding(&self, key: &str) -> Option<(&SessionBinding, SessionState)> {
        self.records
            .values()
            .find(|record| record.binding.idempotency_key == key)
            .map(|record| (&record.binding, record.state))
    }
    /// Only durable confirmed cleanup of a validated website session can
    /// publish browser closure. Failed writes and unfinished intents stay out.
    pub(crate) fn closed_record(&self, key: &str) -> Option<(&SessionBinding, u64)> {
        if self.fenced {
            return None;
        }
        let record = self
            .records
            .values()
            .find(|record| record.binding.idempotency_key == key)?;
        if record.state != SessionState::Closed
            || record.original_deadline_ms.is_none()
            || record.revoke_handle.is_some()
            || record.helper_unit.is_some()
            || record.helper_invocation.is_some()
            || record.browser_unit.is_some()
            || record.browser_invocation.is_some()
        {
            return None;
        }
        Some((&record.binding, record.closed_at_ms?))
    }
    pub(crate) fn helper_source_permit(
        &mut self,
        operation: &str,
        unit: &str,
        invocation: &str,
    ) -> Result<HelperSourcePermit, &'static str> {
        if self.fenced
            || !self.source_alive.load(std::sync::atomic::Ordering::Acquire)
            || self.source_guards.contains_key(operation)
        {
            return Err(FAILURE);
        }
        let record = self.records.get(operation).ok_or(FAILURE)?;
        if record.state != SessionState::Reserved
            || record.revoke_handle.is_some()
            || record.helper_unit.as_deref() != Some(unit)
            || record.helper_invocation.as_deref() != Some(invocation)
        {
            return Err(FAILURE);
        }
        let lock = self._lock.try_clone().map_err(|_| FAILURE)?;
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        self.source_guards
            .insert(operation.into(), std::sync::Arc::downgrade(&active));
        Ok(HelperSourcePermit {
            journal_alive: std::sync::Arc::clone(&self.source_alive),
            operation_alive: active,
            _lock: lock,
        })
    }
    pub(crate) fn withdraw_helper_source(&self, operation: &str) {
        if let Some(guard) = self
            .context_guards
            .get(operation)
            .and_then(std::sync::Weak::upgrade)
        {
            guard.store(false, std::sync::atomic::Ordering::Release);
        }
        if let Some(active) = self
            .source_guards
            .get(operation)
            .and_then(std::sync::Weak::upgrade)
        {
            active.store(false, std::sync::atomic::Ordering::Release);
        }
    }
    /// The supplied time must come from the existing signed controller-time
    /// verifier. Never use the local wall clock to prune replay protection.
    pub fn prune(&mut self, trusted_time_ms: u64) -> Result<usize, &'static str> {
        let trusted_time_ms = self.effective_time(trusted_time_ms)?;
        let before = self.records.len();
        self.records.retain(|_, record| {
            !record
                .closed_at_ms
                .is_some_and(|closed| trusted_time_ms >= closed + RETENTION_MS)
        });
        self.source_guards
            .retain(|operation, _| self.records.contains_key(operation));
        self.context_guards
            .retain(|operation, _| self.records.contains_key(operation));
        let removed = before - self.records.len();
        self.time_high_water_ms = trusted_time_ms;
        // Every other transition persists the mark with its record, and a
        // snapshot's records never exceed its mark, so an idle tick has
        // nothing to make durable. Rewriting every minute only wears the
        // disk and risks fencing for no gain; refresh the durable mark at a
        // bounded interval so a restart does not start from a distant past.
        if removed > 0
            || trusted_time_ms.saturating_sub(self.persisted_high_water_ms)
                >= HIGH_WATER_PERSIST_INTERVAL_MS
        {
            self.persist()?;
        }
        Ok(removed)
    }
    /// Trusted controller time is an estimate that can step back slightly
    /// between replies. A step back within the tolerance is applied as the
    /// high-water mark itself, so recorded times never decrease; a larger step
    /// (or zero/overflow/fence) fails closed. Every transition uses this value.
    fn effective_time(&self, time: u64) -> Result<u64, &'static str> {
        if self.fenced || time == 0 || time > MAX_TIME {
            return Err(FAILURE);
        }
        if time >= self.time_high_water_ms {
            return Ok(time);
        }
        if self.time_high_water_ms - time <= TIME_REGRESSION_TOLERANCE_MS {
            Ok(self.time_high_water_ms)
        } else {
            Err(FAILURE)
        }
    }
    /// Close, without a confirmed revoke, every unfinished record whose
    /// independent maximum has elapsed (`RELEASE_AFTER_MS` of trusted time
    /// from reservation). Helper units (60 s), workload browser units (30 min)
    /// and the application session ceiling (30 min) are all bounded below
    /// that, so nothing the record describes can still be alive; this is the
    /// only way an unrecoverable record (for example after the administrator
    /// edits the recipe) frees its account. Time is signed controller time,
    /// never the local wall clock. Returns the released records so the caller
    /// can publish closures for those that had a durable login.
    pub fn release_expired(
        &mut self,
        trusted_time_ms: u64,
    ) -> Result<Vec<ReleasedSession>, &'static str> {
        let trusted_time_ms = self.effective_time(trusted_time_ms)?;
        let due = self
            .records
            .iter()
            .filter(|(_, record)| {
                record.state != SessionState::Closed
                    && trusted_time_ms >= record.created_at_ms.saturating_add(RELEASE_AFTER_MS)
            })
            .map(|(operation, _)| operation.clone())
            .collect::<Vec<_>>();
        self.time_high_water_ms = trusted_time_ms;
        if due.is_empty() {
            return Ok(Vec::new());
        }
        let mut released = Vec::with_capacity(due.len());
        for operation in due {
            // Withdraw any live source/context authority before closing.
            self.withdraw_helper_source(&operation);
            if let Some(record) = self.records.get_mut(&operation) {
                released.push(ReleasedSession {
                    node_id: record.binding.node_id.clone(),
                    idempotency_key: record.binding.idempotency_key.clone(),
                    had_original_deadline: record.original_deadline_ms.is_some(),
                });
                record.state = SessionState::Closed;
                record.closed_at_ms = Some(trusted_time_ms);
                record.revoke_handle = None;
                record.browser_unit = None;
                record.browser_invocation = None;
                record.helper_unit = None;
                record.helper_invocation = None;
            }
        }
        self.persist()?;
        Ok(released)
    }
    /// A failed write fences the journal for new work. Retry by writing the
    /// current in-memory state as a durable snapshot (it carries whatever the
    /// failed write attempted, which is the conservative direction: an
    /// unfinished record stays unfinished). Success clears the fence. Source
    /// and context permits invalidated by the fence stay invalid: the shared
    /// availability flag is replaced rather than revived.
    pub fn try_unfence(&mut self) -> bool {
        if !self.fenced {
            return true;
        }
        if self.write_snapshot().is_err() {
            return false;
        }
        self.fenced = false;
        self.source_alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        true
    }
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }
    /// Make the next durable write fail, for fence scenarios in other modules.
    #[cfg(test)]
    pub(crate) fn fail_next_write_for_test(&mut self) {
        self.fail_next_persist = true;
    }
    /// The conditions under which `reserve` refuses a new operation, without
    /// side effects. Lets the dispatcher skip a blocked account's candidate
    /// without preparing (and copying source for) it again every tick.
    pub(crate) fn admission_blocked(&self, account: &str, unit: &str, key: &str) -> bool {
        self.records.values().any(|record| {
            record.binding.idempotency_key == key
                || record.state != SessionState::Closed
                    && (record.binding.account == account || record.binding.workload_unit == unit)
        })
    }
    /// Request correlation keys of unfinished records, for owner retention.
    pub(crate) fn unresolved_request_keys(&self) -> std::collections::BTreeSet<String> {
        self.records
            .values()
            .filter(|record| record.state != SessionState::Closed)
            .filter_map(|record| record.binding.request_event_key.clone())
            .collect()
    }
    fn path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{name}",
            self.directory.as_raw_fd()
        ))
    }
    fn persist(&mut self) -> Result<(), &'static str> {
        let result = self.write_snapshot();
        if result.is_err() {
            self.fenced = true;
            self.source_alive
                .store(false, std::sync::atomic::Ordering::Release);
        }
        result
    }
    fn write_snapshot(&mut self) -> Result<(), &'static str> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_persist) {
            return Err(FAILURE);
        }
        #[cfg(test)]
        {
            self.writes += 1;
        }
        let value = object(vec![
            ("version", number(4)),
            ("time_high_water_ms", number(self.time_high_water_ms)),
            (
                "records",
                Value::Array(self.records.values().map(record_value).collect()),
            ),
        ]);
        let body = canonicalize_value(&value).map_err(|_| FAILURE)?;
        if body.len() > MAX_BYTES {
            return Err(FAILURE);
        }
        let temp = self.path(&format!(
            ".state-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(NOFOLLOW)
                .open(&temp)
                .map_err(|_| FAILURE)?;
            private_file(&file, self.owner)?;
            file.write_all(&body).map_err(|_| FAILURE)?;
            file.sync_all().map_err(|_| FAILURE)?;
            fs::rename(&temp, self.path("state.json")).map_err(|_| FAILURE)?;
            self.directory.sync_all().map_err(|_| FAILURE)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        } else {
            self.persisted_high_water_ms = self.time_high_water_ms;
        }
        result
    }
    fn load(&mut self, body: &[u8]) -> Result<(), &'static str> {
        let value =
            parse_json(std::str::from_utf8(body).map_err(|_| FAILURE)?).map_err(|_| FAILURE)?;
        keys(&value, &["version", "time_high_water_ms", "records"])?;
        let version = integer(&value, "version")?;
        if !matches!(version, 2..=4) {
            return Err(FAILURE);
        }
        let high_water = integer(&value, "time_high_water_ms")?;
        if high_water > MAX_TIME {
            return Err(FAILURE);
        }
        let records = value
            .get("records")
            .and_then(Value::as_array)
            .ok_or(FAILURE)?;
        if records.len() > MAX_RECORDS {
            return Err(FAILURE);
        }
        let mut decoded = BTreeMap::new();
        for value in records {
            let record = parse_record(value, high_water, version)?;
            if decoded.values().any(|previous: &SessionRecord| {
                previous.binding.idempotency_key == record.binding.idempotency_key
                    || previous.state != SessionState::Closed
                        && record.state != SessionState::Closed
                        && (previous.binding.account == record.binding.account
                            || previous.binding.workload_unit == record.binding.workload_unit)
            }) {
                return Err(FAILURE);
            }
            if decoded
                .insert(record.binding.operation_id.clone(), record)
                .is_some()
            {
                return Err(FAILURE);
            }
        }
        self.records = decoded;
        self.time_high_water_ms = high_water;
        self.persisted_high_water_ms = high_water;
        Ok(())
    }
}
fn private_file(file: &File, owner: u32) -> Result<(), &'static str> {
    let metadata = file.metadata().map_err(|_| FAILURE)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        Err(FAILURE)
    } else {
        Ok(())
    }
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:.".contains(&byte))
}
fn valid_unit(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.ends_with(".service")
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:.@".contains(&byte))
}
fn valid_invocation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn validate_binding(binding: &SessionBinding) -> Result<(), &'static str> {
    if !valid_id(&binding.node_id)
        || !valid_id(&binding.workload_id)
        || binding.recipe_fingerprint.len() != 64
        || !binding
            .recipe_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !valid_id(&binding.operation_id)
        || !valid_id(&binding.idempotency_key)
        || binding
            .request_event_key
            .as_deref()
            .is_some_and(|key| !blindpass_core::protocol::is_valid_event_key(key))
        || !valid_id(&binding.resource)
        || !valid_id(&binding.account)
        || !valid_unit(&binding.workload_unit)
        || !valid_invocation(&binding.workload_invocation)
    {
        Err("session binding invalid")
    } else {
        Ok(())
    }
}
fn validate_handle(handle: &RevokeHandle, expected: &str) -> Result<(), &'static str> {
    let valid = match handle {
        RevokeHandle::Fixture {
            account,
            session_reference,
        } => account == expected && valid_id(session_reference),
        RevokeHandle::GrafanaManaged {
            account,
            user_id,
            org_id,
        } => account == expected && *user_id > 0 && *org_id > 0,
    };
    if valid {
        Ok(())
    } else {
        Err("session revocation binding invalid")
    }
}
fn object(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn string(value: &str) -> Value {
    Value::String(value.to_owned())
}
fn number(value: u64) -> Value {
    Value::Unsigned(value)
}
fn optional_string(value: &Option<String>) -> Value {
    value.as_deref().map_or(Value::Null, string)
}
fn optional_number(value: Option<u64>) -> Value {
    value.map_or(Value::Null, number)
}
fn handle_value(handle: &RevokeHandle) -> Value {
    match handle {
        RevokeHandle::Fixture {
            account,
            session_reference,
        } => object(vec![
            ("kind", string("fixture")),
            ("account", string(account)),
            ("session_reference", string(session_reference)),
        ]),
        RevokeHandle::GrafanaManaged {
            account,
            user_id,
            org_id,
        } => object(vec![
            ("kind", string("grafana-managed")),
            ("account", string(account)),
            ("user_id", number(u64::from(*user_id))),
            ("org_id", number(u64::from(*org_id))),
        ]),
    }
}
fn record_value(record: &SessionRecord) -> Value {
    let b = &record.binding;
    object(vec![
        (
            "binding",
            object(vec![
                ("node_id", string(&b.node_id)),
                ("workload_id", string(&b.workload_id)),
                ("operation_id", string(&b.operation_id)),
                ("idempotency_key", string(&b.idempotency_key)),
                ("request_event_key", optional_string(&b.request_event_key)),
                ("workload_unit", string(&b.workload_unit)),
                ("workload_invocation", string(&b.workload_invocation)),
                ("resource", string(&b.resource)),
                ("recipe_fingerprint", string(&b.recipe_fingerprint)),
                ("account", string(&b.account)),
            ]),
        ),
        ("state", string(record.state.name())),
        ("created_at_ms", number(record.created_at_ms)),
        ("closed_at_ms", optional_number(record.closed_at_ms)),
        (
            "original_deadline_ms",
            optional_number(record.original_deadline_ms),
        ),
        (
            "revoke_handle",
            record
                .revoke_handle
                .as_ref()
                .map_or(Value::Null, handle_value),
        ),
        ("helper_unit", optional_string(&record.helper_unit)),
        (
            "helper_invocation",
            optional_string(&record.helper_invocation),
        ),
        ("browser_unit", optional_string(&record.browser_unit)),
        (
            "browser_invocation",
            optional_string(&record.browser_invocation),
        ),
    ])
}
fn keys(value: &Value, expected: &[&str]) -> Result<(), &'static str> {
    if value.as_object().is_some_and(|fields| {
        fields.len() == expected.len()
            && fields
                .iter()
                .all(|(key, _)| expected.contains(&key.as_str()))
    }) {
        Ok(())
    } else {
        Err(FAILURE)
    }
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    value.get(key).and_then(Value::as_str).ok_or(FAILURE)
}
fn integer(value: &Value, key: &str) -> Result<u64, &'static str> {
    value.get(key).and_then(Value::as_u64).ok_or(FAILURE)
}
fn nullable_text(value: &Value, key: &str) -> Result<Option<String>, &'static str> {
    match value.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(FAILURE),
    }
}
fn nullable_number(value: &Value, key: &str) -> Result<Option<u64>, &'static str> {
    match value.get(key) {
        Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or(FAILURE),
        _ => Err(FAILURE),
    }
}
fn parse_handle(value: &Value) -> Result<RevokeHandle, &'static str> {
    match text(value, "kind")? {
        "fixture" => {
            keys(value, &["kind", "account", "session_reference"])?;
            Ok(RevokeHandle::Fixture {
                account: text(value, "account")?.into(),
                session_reference: text(value, "session_reference")?.into(),
            })
        }
        "grafana-managed" => {
            keys(value, &["kind", "account", "user_id", "org_id"])?;
            Ok(RevokeHandle::GrafanaManaged {
                account: text(value, "account")?.into(),
                user_id: u32::try_from(integer(value, "user_id")?).map_err(|_| FAILURE)?,
                org_id: u32::try_from(integer(value, "org_id")?).map_err(|_| FAILURE)?,
            })
        }
        _ => Err(FAILURE),
    }
}
fn parse_record(
    value: &Value,
    high_water: u64,
    version: u64,
) -> Result<SessionRecord, &'static str> {
    let mut expected = vec![
        "binding",
        "state",
        "created_at_ms",
        "closed_at_ms",
        "original_deadline_ms",
        "revoke_handle",
        "browser_unit",
        "browser_invocation",
    ];
    if version >= 3 {
        expected.extend(["helper_unit", "helper_invocation"]);
    }
    keys(value, &expected)?;
    let binding = value.get("binding").ok_or(FAILURE)?;
    let mut binding_keys = vec![
        "node_id",
        "workload_id",
        "operation_id",
        "idempotency_key",
        "workload_unit",
        "workload_invocation",
        "resource",
        "recipe_fingerprint",
        "account",
    ];
    if version >= 4 {
        binding_keys.push("request_event_key");
    }
    keys(binding, &binding_keys)?;
    let binding = SessionBinding {
        node_id: text(binding, "node_id")?.into(),
        workload_id: text(binding, "workload_id")?.into(),
        operation_id: text(binding, "operation_id")?.into(),
        idempotency_key: text(binding, "idempotency_key")?.into(),
        request_event_key: if version >= 4 {
            nullable_text(binding, "request_event_key")?
        } else {
            None
        },
        workload_unit: text(binding, "workload_unit")?.into(),
        workload_invocation: text(binding, "workload_invocation")?.into(),
        resource: text(binding, "resource")?.into(),
        recipe_fingerprint: text(binding, "recipe_fingerprint")?.into(),
        account: text(binding, "account")?.into(),
    };
    validate_binding(&binding)?;
    let record = SessionRecord {
        binding,
        state: SessionState::parse(text(value, "state")?)?,
        created_at_ms: integer(value, "created_at_ms")?,
        closed_at_ms: nullable_number(value, "closed_at_ms")?,
        original_deadline_ms: nullable_number(value, "original_deadline_ms")?,
        revoke_handle: match value.get("revoke_handle") {
            Some(Value::Null) => None,
            Some(value) => Some(parse_handle(value)?),
            _ => return Err(FAILURE),
        },
        helper_unit: if version >= 3 {
            nullable_text(value, "helper_unit")?
        } else {
            None
        },
        helper_invocation: if version >= 3 {
            nullable_text(value, "helper_invocation")?
        } else {
            None
        },
        browser_unit: nullable_text(value, "browser_unit")?,
        browser_invocation: nullable_text(value, "browser_invocation")?,
    };
    if record.created_at_ms == 0
        || record.created_at_ms > high_water
        || record
            .original_deadline_ms
            .is_some_and(|deadline| deadline <= record.created_at_ms || deadline > MAX_TIME)
        || record
            .closed_at_ms
            .is_some_and(|time| time < record.created_at_ms || time > high_water)
        || (record.state == SessionState::Closed) != record.closed_at_ms.is_some()
        || record.helper_unit.is_some() != record.helper_invocation.is_some()
        || record
            .helper_unit
            .as_deref()
            .is_some_and(|unit| !crate::runtime_identity::valid_helper_unit(unit))
        || record
            .helper_invocation
            .as_deref()
            .is_some_and(|value| !valid_invocation(value))
        || record.browser_unit.is_some() != record.browser_invocation.is_some()
        || record
            .browser_unit
            .as_deref()
            .is_some_and(|unit| !valid_unit(unit))
        || record
            .browser_invocation
            .as_deref()
            .is_some_and(|invocation| !valid_invocation(invocation))
    {
        return Err(FAILURE);
    }
    if record.state == SessionState::Closed {
        if record.revoke_handle.is_some()
            || record.browser_unit.is_some()
            || record.helper_unit.is_some()
        {
            return Err(FAILURE);
        }
    } else {
        if record.original_deadline_ms.is_some() != record.revoke_handle.is_some()
            || record.browser_unit.is_some() && record.revoke_handle.is_none()
            || version >= 3
                && matches!(record.state, SessionState::Reserved | SessionState::Active)
                && record.revoke_handle.is_some()
                && record.helper_unit.is_none()
        {
            return Err(FAILURE);
        }
        if let Some(handle) = &record.revoke_handle {
            validate_handle(handle, &record.binding.account)?;
        }
        if record.state == SessionState::Active
            && (record.revoke_handle.is_none() || record.browser_unit.is_none())
        {
            return Err(FAILURE);
        }
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "blindpass-session-journal-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn open(&self) -> SessionJournal {
            SessionJournal::open_at(&self.0, effective_uid()).unwrap()
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn binding() -> SessionBinding {
        SessionBinding {
            node_id: "node-a".into(),
            workload_id: "workload-a".into(),
            recipe_fingerprint: "a".repeat(64),
            operation_id: "operation-1".into(),
            idempotency_key: "retry-1".into(),
            request_event_key: None,
            workload_unit: "agent-1.service".into(),
            workload_invocation: "a".repeat(32),
            resource: "report-1".into(),
            account: "primary".into(),
        }
    }
    fn receipt() -> SessionReceipt {
        SessionReceipt {
            original_deadline_ms: 301_000,
            revoke_handle: RevokeHandle::Fixture {
                account: "primary".into(),
                session_reference: "NONBEARER-REFERENCE".into(),
            },
            browser_unit: "blindpass-browser-1.service".into(),
            browser_invocation: "b".repeat(32),
        }
    }
    #[test]
    fn real_browser_template_unit_is_durable_and_reloadable_before_import() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@proof.service",
                &"c".repeat(32),
                1001,
            )
            .unwrap();
        let mut receipt = receipt();
        receipt.browser_unit = "blindpass-browser@0-123-root.service".into();
        journal
            .record_login(
                "operation-1",
                receipt.original_deadline_ms,
                receipt.revoke_handle.clone(),
                1002,
            )
            .unwrap();
        journal
            .activate("operation-1", receipt.clone(), 1003)
            .unwrap();
        assert_eq!(
            journal.pending()[0].browser_unit.as_deref(),
            Some(receipt.browser_unit.as_str())
        );
        drop(journal);
        let journal = dir.open();
        assert_eq!(journal.pending()[0].state, SessionState::BlockedUncertain);
        assert_eq!(
            journal.pending()[0].browser_unit.as_deref(),
            Some(receipt.browser_unit.as_str())
        );
        for wrong in [
            "blindpass-browser@../root.service",
            "blindpass-browser@x;id.service",
            "blindpass-browser@x/y.service",
            "blindpass-browser@x\n.service",
        ] {
            assert!(!valid_unit(wrong));
        }
    }
    #[test]
    fn active_context_permission_is_single_use_and_withdraws_before_failed_revoke() {
        let dir = Directory::new();
        let mut journal = dir.open();
        let guard = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        journal.reserve(binding(), 1000).unwrap();
        assert!(journal.guard_context("operation-1", &guard).is_err());
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@proof.service",
                &"c".repeat(32),
                1001,
            )
            .unwrap();
        let receipt = receipt();
        journal
            .record_login(
                "operation-1",
                receipt.original_deadline_ms,
                receipt.revoke_handle.clone(),
                1002,
            )
            .unwrap();
        journal.activate("operation-1", receipt, 1003).unwrap();
        journal.guard_context("operation-1", &guard).unwrap();
        assert!(journal.guard_context("operation-1", &guard).is_err());
        assert!(guard.load(Ordering::Acquire));
        assert!(journal.begin_revoke("operation-1", 0).is_err());
        assert!(!guard.load(Ordering::Acquire));
    }
    #[test]
    fn detached_helper_permission_is_single_use_bound_and_withdrawn_before_reconciliation() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 10_000).unwrap();
        assert!(
            journal
                .helper_source_permit(
                    "operation-1",
                    "blindpass-login-helper@proof.service",
                    &"c".repeat(32)
                )
                .is_err()
        );
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@proof.service",
                &"c".repeat(32),
                10_001,
            )
            .unwrap();
        assert!(
            journal
                .helper_source_permit(
                    "operation-1",
                    "blindpass-login-helper@other.service",
                    &"c".repeat(32)
                )
                .is_err()
        );
        let permit = journal
            .helper_source_permit(
                "operation-1",
                "blindpass-login-helper@proof.service",
                &"c".repeat(32),
            )
            .unwrap();
        assert!(permit.allows_source());
        assert!(
            journal
                .helper_source_permit(
                    "operation-1",
                    "blindpass-login-helper@proof.service",
                    &"c".repeat(32)
                )
                .is_err()
        );
        // A regression beyond the 2.5 s estimate tolerance is still rejected.
        journal.begin_revoke("operation-1", 7_500).unwrap_err();
        assert!(
            !permit.allows_source(),
            "local withdrawal precedes signed-time persistence checks"
        );
        journal.begin_revoke("operation-1", 10_002).unwrap();
        assert!(!permit.allows_source());
        drop(permit);
        assert!(
            journal
                .helper_source_permit(
                    "operation-1",
                    "blindpass-login-helper@proof.service",
                    &"c".repeat(32)
                )
                .is_err()
        );
    }

    #[test]
    fn detached_helper_permission_retains_file_lock_but_journal_drop_denies_source() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@proof.service",
                &"c".repeat(32),
                1_001,
            )
            .unwrap();
        let permit = journal
            .helper_source_permit(
                "operation-1",
                "blindpass-login-helper@proof.service",
                &"c".repeat(32),
            )
            .unwrap();
        drop(journal);
        assert!(!permit.allows_source());
        assert!(SessionJournal::open_at(&dir.0, effective_uid()).is_err());
        drop(permit);
        let mut restored = dir.open();
        assert_eq!(restored.pending()[0].state, SessionState::BlockedUncertain);
        assert!(
            restored
                .helper_source_permit(
                    "operation-1",
                    "blindpass-login-helper@proof.service",
                    &"c".repeat(32)
                )
                .is_err()
        );
    }

    #[test]
    fn detached_helper_permission_is_invalidated_by_later_persistence_failure() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@proof.service",
                &"c".repeat(32),
                1_001,
            )
            .unwrap();
        let permit = journal
            .helper_source_permit(
                "operation-1",
                "blindpass-login-helper@proof.service",
                &"c".repeat(32),
            )
            .unwrap();
        journal.fail_next_persist = true;
        let mut other = binding();
        other.operation_id = "operation-2".into();
        other.idempotency_key = "retry-2".into();
        other.account = "isolation".into();
        other.workload_unit = "agent-2.service".into();
        assert!(journal.reserve(other, 1_002).is_err());
        assert!(!permit.allows_source());
    }
    #[test]
    fn login_without_durable_helper_identity_is_rejected() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        assert!(
            journal
                .record_login(
                    "operation-1",
                    receipt().original_deadline_ms,
                    receipt().revoke_handle,
                    1_001
                )
                .is_err()
        );
        assert!(journal.pending()[0].revoke_handle.is_none());
    }
    #[test]
    fn helper_identity_is_durable_once_and_lost_login_reply_stays_blocked() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        let unit = "blindpass-login-helper@fixture.service";
        let invocation = "c".repeat(32);
        for (bad_unit, bad_invocation) in [
            ("agent.service", invocation.as_str()),
            ("blindpass-login-helper@.service", invocation.as_str()),
            (unit, "claimed-invocation"),
        ] {
            assert!(
                journal
                    .record_helper("operation-1", bad_unit, bad_invocation, 1_001)
                    .is_err()
            );
        }
        journal
            .record_helper("operation-1", unit, &invocation, 1_001)
            .unwrap();
        assert!(
            journal
                .record_helper("operation-1", unit, &invocation, 1_002)
                .is_err()
        );
        assert!(
            journal
                .record_helper("operation-1", unit, &"d".repeat(32), 1_002)
                .is_err()
        );
        drop(journal);
        let mut restored = dir.open();
        let record = restored.pending()[0];
        assert_eq!(record.helper_unit.as_deref(), Some(unit));
        assert_eq!(
            record.helper_invocation.as_deref(),
            Some(invocation.as_str())
        );
        assert_eq!(record.state, SessionState::BlockedUncertain);
        assert!(record.revoke_handle.is_none());
        assert!(
            restored
                .record_helper("operation-1", unit, &invocation, 1_003)
                .is_err()
        );
        assert_eq!(restored.prune(1_000 + RETENTION_MS).unwrap(), 0);
        restored
            .reconcile("operation-1", true, true, 1_000 + RETENTION_MS)
            .unwrap();
        let record = restored.records.get("operation-1").unwrap();
        assert!(record.helper_unit.is_none() && record.helper_invocation.is_none());
    }
    #[test]
    fn failed_helper_identity_write_fences_delivery_and_preserves_original_intent() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal.fail_next_persist = true;
        assert!(
            journal
                .record_helper(
                    "operation-1",
                    "blindpass-login-helper@fixture.service",
                    &"c".repeat(32),
                    1_001
                )
                .is_err()
        );
        assert!(
            journal
                .record_login(
                    "operation-1",
                    receipt().original_deadline_ms,
                    receipt().revoke_handle,
                    1_002
                )
                .is_err()
        );
        drop(journal);
        let restored = dir.open();
        assert_eq!(restored.pending()[0].state, SessionState::BlockedUncertain);
        assert!(restored.pending()[0].helper_unit.is_none());
    }
    #[test]
    fn legacy_journal_cannot_invent_helper_authority_and_new_fields_are_strict() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                1_001,
            )
            .unwrap();
        journal
            .record_login(
                "operation-1",
                receipt().original_deadline_ms,
                receipt().revoke_handle,
                1_001,
            )
            .unwrap();
        journal.activate("operation-1", receipt(), 1_001).unwrap();
        let high_water = journal.time_high_water_ms;
        let original = record_value(journal.pending()[0]);
        let mut missing = original.clone();
        if let Value::Object(fields) = &mut missing {
            for (key, value) in fields {
                if key.starts_with("helper_") {
                    *value = Value::Null;
                }
            }
        }
        assert!(
            parse_record(&missing, high_water, 4).is_err(),
            "new active state must contain the original helper identity"
        );
        for field in ["helper_unit", "helper_invocation"] {
            let mut malformed = original.clone();
            if let Value::Object(fields) = &mut malformed {
                fields.iter_mut().find(|(key, _)| key == field).unwrap().1 = Value::Null;
            }
            assert!(parse_record(&malformed, high_water, 4).is_err());
        }
        let mut legacy = original;
        if let Value::Object(fields) = &mut legacy {
            fields.retain(|(key, _)| !key.starts_with("helper_"));
            if let Value::Object(binding) = &mut fields
                .iter_mut()
                .find(|(key, _)| key == "binding")
                .unwrap()
                .1
            {
                binding.retain(|(key, _)| key != "request_event_key");
            }
        }
        let snapshot = canonicalize_value(&object(vec![
            ("version", number(2)),
            ("time_high_water_ms", number(high_water)),
            ("records", Value::Array(vec![legacy])),
        ]))
        .unwrap();
        drop(journal);
        fs::write(dir.0.join("state.json"), snapshot).unwrap();
        let mut restored = dir.open();
        assert_eq!(restored.pending()[0].state, SessionState::BlockedUncertain);
        assert!(restored.pending()[0].helper_unit.is_none());
        assert!(
            restored
                .record_helper(
                    "operation-1",
                    "blindpass-login-helper@fixture.service",
                    &"c".repeat(32),
                    1_002
                )
                .is_err()
        );
        drop(restored);
        assert_eq!(
            dir.open().pending()[0].state,
            SessionState::BlockedUncertain
        );
    }
    #[test]
    fn intent_is_durable_and_retry_after_restart_never_authorizes_new_login() {
        let dir = Directory::new();
        let mut journal = dir.open();
        assert_eq!(journal.reserve(binding(), 1_000), Ok(Reservation::New));
        assert_eq!(
            journal.reserve(binding(), 1_000),
            Ok(Reservation::Existing(SessionState::Reserved))
        );
        drop(journal);
        let mut restored = dir.open();
        assert_eq!(
            restored.reserve(binding(), 1_001),
            Ok(Reservation::Existing(SessionState::BlockedUncertain))
        );
        assert_eq!(restored.pending().len(), 1);
        assert!(restored.activate("operation-1", receipt(), 1_001).is_err());
        let body = std::fs::read(dir.0.join("state.json")).unwrap();
        assert!(!body.windows(8).any(|s| s == b"password"));
    }
    #[test]
    fn account_workload_and_idempotency_conflicts_fail_closed() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                1_000,
            )
            .unwrap();
        let mut other = binding();
        other.resource = "other".into();
        assert!(journal.reserve(other, 1_000).is_err());
        let mut other = binding();
        other.operation_id = "operation-2".into();
        other.idempotency_key = "retry-2".into();
        other.workload_unit = "agent-2.service".into();
        assert!(journal.reserve(other.clone(), 1_000).is_err());
        other.account = "isolation".into();
        other.workload_unit = "agent-1.service".into();
        other.workload_invocation = "c".repeat(32);
        assert!(journal.reserve(other, 1_000).is_err());
    }
    #[test]
    fn activation_is_bound_and_reconciliation_requires_both_real_effects() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                1_000,
            )
            .unwrap();
        let mut wrong = receipt();
        wrong.revoke_handle = RevokeHandle::Fixture {
            account: "other".into(),
            session_reference: "reference".into(),
        };
        assert!(journal.activate("operation-1", wrong, 1_001).is_err());
        journal
            .record_login(
                "operation-1",
                receipt().original_deadline_ms,
                receipt().revoke_handle,
                1_001,
            )
            .unwrap();
        journal.activate("operation-1", receipt(), 1_001).unwrap();
        assert_eq!(
            journal.reserve(binding(), 1_002),
            Ok(Reservation::Existing(SessionState::Active))
        );
        journal.begin_revoke("operation-1", 1_003).unwrap();
        assert!(
            journal
                .reconcile("operation-1", false, true, 1_004)
                .is_err()
        );
        assert!(
            journal
                .reconcile("operation-1", true, false, 1_004)
                .is_err()
        );
        drop(journal);
        let mut restored = dir.open();
        assert_eq!(restored.pending()[0].state, SessionState::BlockedUncertain);
        restored
            .reconcile("operation-1", true, true, 1_005)
            .unwrap();
        assert_eq!(
            restored.reserve(binding(), 1_006),
            Ok(Reservation::Existing(SessionState::Closed))
        );
        restored.reserve(binding(), 10_000).unwrap();
        assert!(
            restored
                .prune(10_000 - TIME_REGRESSION_TOLERANCE_MS - 1)
                .is_err()
        );
        assert_eq!(restored.prune(1_005 + RETENTION_MS - 1).unwrap(), 0);
        assert_eq!(restored.prune(1_005 + RETENTION_MS).unwrap(), 1);
    }
    #[test]
    fn expired_known_or_unknown_session_is_still_blocked_without_reconciliation() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                1_000,
            )
            .unwrap();
        journal
            .record_login(
                "operation-1",
                receipt().original_deadline_ms,
                receipt().revoke_handle,
                1_001,
            )
            .unwrap();
        journal.activate("operation-1", receipt(), 1_001).unwrap();
        drop(journal);
        let mut restored = dir.open();
        // The session's own deadline and the 24 h retention never release it.
        assert_eq!(restored.prune(500_000).unwrap(), 0);
        assert!(restored.release_expired(500_000).unwrap().is_empty());
        assert_eq!(
            restored.reserve(binding(), 500_000),
            Ok(Reservation::Existing(SessionState::BlockedUncertain))
        );
        let mut other = binding();
        other.operation_id = "operation-2".into();
        other.idempotency_key = "retry-2".into();
        assert!(restored.reserve(other.clone(), 500_000).is_err());
        // Until the operation deadline, the application ceiling and the margin
        // have all elapsed, the account stays blocked.
        assert!(
            restored
                .release_expired(1_000 + RELEASE_AFTER_MS - 1)
                .unwrap()
                .is_empty()
        );
        assert!(
            restored
                .reserve(other.clone(), 1_000 + RELEASE_AFTER_MS - 1)
                .is_err()
        );
        let released = restored.release_expired(1_000 + RELEASE_AFTER_MS).unwrap();
        assert_eq!(released.len(), 1);
        assert!(released[0].had_original_deadline);
        assert_eq!(released[0].idempotency_key, "retry-1");
        assert!(restored.pending().is_empty());
        assert_eq!(
            restored.reserve(other, 1_000 + RELEASE_AFTER_MS + 1),
            Ok(Reservation::New)
        );
    }
    #[test]
    fn lock_metadata_symlink_hardlink_and_corruption_are_rejected() {
        let dir = Directory::new();
        let journal = dir.open();
        assert!(SessionJournal::open_at(&dir.0, effective_uid()).is_err());
        drop(journal);
        let state = dir.0.join("state.json");
        std::fs::hard_link(&state, dir.0.join("alias")).unwrap();
        assert!(SessionJournal::open_at(&dir.0, effective_uid()).is_err());
        std::fs::remove_file(dir.0.join("alias")).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SessionJournal::open_at(&dir.0, effective_uid()).is_err());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&state, dir.0.join("real")).unwrap();
        symlink("real", &state).unwrap();
        assert!(SessionJournal::open_at(&dir.0, effective_uid()).is_err());
        std::fs::remove_file(&state).unwrap();
        std::fs::rename(dir.0.join("real"), &state).unwrap();
        std::fs::write(&state, b"{\"version\":1,\"version\":1}").unwrap();
        assert!(SessionJournal::open_at(&dir.0, effective_uid()).is_err());
    }
    #[test]
    fn failed_persistence_fences_all_future_actions_and_preserves_durable_intent() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                1_000,
            )
            .unwrap();
        journal
            .record_login(
                "operation-1",
                receipt().original_deadline_ms,
                receipt().revoke_handle,
                1_001,
            )
            .unwrap();
        journal.fail_next_persist = true;
        assert!(journal.activate("operation-1", receipt(), 1_001).is_err());
        assert!(journal.reserve(binding(), 1_002).is_err());
        assert!(journal.reconcile("operation-1", true, true, 1_003).is_err());
        drop(journal);
        let mut restored = dir.open();
        assert_eq!(
            restored.reserve(binding(), 1_004),
            Ok(Reservation::Existing(SessionState::BlockedUncertain))
        );
    }
    #[test]
    fn login_handle_survives_crash_before_browser_and_cannot_be_substituted() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                1_000,
            )
            .unwrap();
        journal
            .record_login(
                "operation-1",
                receipt().original_deadline_ms,
                receipt().revoke_handle,
                1_001,
            )
            .unwrap();
        let mut wrong = receipt();
        wrong.original_deadline_ms += 1;
        assert!(journal.activate("operation-1", wrong, 1_002).is_err());
        assert!(!format!("{:?}", journal.pending()).contains("NONBEARER-REFERENCE"));
        drop(journal);
        let restored = dir.open();
        let record = restored.pending()[0];
        assert_eq!(record.state, SessionState::BlockedUncertain);
        assert!(record.browser_unit.is_none());
        assert_eq!(
            record.revoke_handle.as_ref(),
            Some(&receipt().revoke_handle)
        );
    }
    #[test]
    fn malformed_receipts_and_operation_deadlines_never_activate() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                1_000,
            )
            .unwrap();
        assert!(
            journal.activate("operation-1", receipt(), 1_001).is_err(),
            "login handle must already be durable"
        );
        for deadline in [0, 1_000, 1_802_000, u64::MAX] {
            assert!(
                journal
                    .record_login("operation-1", deadline, receipt().revoke_handle, 1_001)
                    .is_err()
            );
        }
        journal
            .record_login(
                "operation-1",
                receipt().original_deadline_ms,
                receipt().revoke_handle,
                1_001,
            )
            .unwrap();
        let mut wrong = receipt();
        wrong.browser_invocation = "../foreign".into();
        assert!(journal.activate("operation-1", wrong, 1_002).is_err());
        assert!(
            journal.activate("operation-1", receipt(), 121_001).is_err(),
            "120s operation budget"
        );
    }
    #[test]
    fn closed_replays_do_not_extend_retention_and_released_account_can_be_reused() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 1_000).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                1_000,
            )
            .unwrap();
        journal.reconcile("operation-1", true, true, 1_001).unwrap();
        journal.reconcile("operation-1", true, true, 1_500).unwrap();
        let mut next = binding();
        next.operation_id = "operation-2".into();
        next.idempotency_key = "retry-2".into();
        assert_eq!(journal.reserve(next, 1_501), Ok(Reservation::New));
        assert_eq!(journal.prune(1_001 + RETENTION_MS).unwrap(), 1);
        assert_eq!(journal.pending().len(), 1);
    }
    #[test]
    fn unsafe_directory_and_nonregular_state_are_rejected_without_blocking() {
        let dir = Directory::new();
        drop(dir.open());
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SessionJournal::open_at(&dir.0, effective_uid()).is_err());
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = dir.0.join("state.json");
        std::fs::remove_file(&state).unwrap();
        unsafe extern "C" {
            fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
        }
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(state.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is NUL-terminated and valid for this call.
        assert_eq!(unsafe { mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(SessionJournal::open_at(&dir.0, effective_uid()).is_err());
    }

    fn open_reserved_with_helper(journal: &mut SessionJournal, time: u64) {
        journal.reserve(binding(), time).unwrap();
        journal
            .record_helper(
                "operation-1",
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                time,
            )
            .unwrap();
    }
    fn second_binding() -> SessionBinding {
        let mut other = binding();
        other.operation_id = "operation-2".into();
        other.idempotency_key = "retry-2".into();
        other.account = "isolation".into();
        other.workload_unit = "agent-2.service".into();
        other
    }
    #[test]
    fn regression_within_the_estimate_tolerance_is_monotonic_and_larger_steps_fail() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 10_000).unwrap();
        // reserve of a second operation 2.5 s behind is stamped at the mark.
        journal.reserve(second_binding(), 7_500).unwrap();
        assert_eq!(journal.records["operation-2"].created_at_ms, 10_000);
        assert_eq!(journal.time_high_water_ms, 10_000);
        let unit = "blindpass-login-helper@fixture.service";
        // Every transition rejects a step back beyond the tolerance and accepts
        // one within it, never lowering the persisted mark.
        let beyond = 10_000 - TIME_REGRESSION_TOLERANCE_MS - 1;
        let within = 10_000 - TIME_REGRESSION_TOLERANCE_MS;
        assert!(
            journal
                .record_helper("operation-1", unit, &"c".repeat(32), beyond)
                .is_err()
        );
        journal
            .record_helper("operation-1", unit, &"c".repeat(32), within)
            .unwrap();
        assert!(
            journal
                .record_login(
                    "operation-1",
                    receipt().original_deadline_ms,
                    receipt().revoke_handle,
                    beyond
                )
                .is_err()
        );
        journal
            .record_login(
                "operation-1",
                receipt().original_deadline_ms,
                receipt().revoke_handle,
                within + 1,
            )
            .unwrap();
        assert!(journal.activate("operation-1", receipt(), beyond).is_err());
        journal
            .activate("operation-1", receipt(), within + 2)
            .unwrap();
        assert!(journal.begin_revoke("operation-1", beyond).is_err());
        journal.begin_revoke("operation-1", within + 3).unwrap();
        assert!(journal.reserve(binding(), beyond).is_err());
        assert!(
            journal
                .reconcile("operation-1", true, true, beyond)
                .is_err()
        );
        journal
            .reconcile("operation-1", true, true, within + 4)
            .unwrap();
        assert_eq!(journal.records["operation-1"].closed_at_ms, Some(10_000));
        assert!(journal.prune(beyond).is_err());
        assert_eq!(journal.prune(within + 5).unwrap(), 0);
        assert!(journal.release_expired(beyond).is_err());
        assert!(journal.release_expired(within + 6).unwrap().is_empty());
        assert_eq!(journal.time_high_water_ms, 10_000);
        drop(journal);
        let restored = dir.open();
        assert_eq!(restored.time_high_water_ms, 10_000);
        assert_eq!(restored.records["operation-1"].state, SessionState::Closed);
    }
    #[test]
    fn effective_time_rejects_zero_overflow_and_a_fenced_journal() {
        let dir = Directory::new();
        let mut journal = dir.open();
        journal.reserve(binding(), 10_000).unwrap();
        assert!(journal.effective_time(0).is_err());
        assert!(journal.effective_time(MAX_TIME + 1).is_err());
        assert_eq!(journal.effective_time(10_000), Ok(10_000));
        assert_eq!(journal.effective_time(12_000), Ok(12_000));
        journal.fail_next_persist = true;
        assert!(journal.reserve(second_binding(), 10_001).is_err());
        assert!(journal.effective_time(10_002).is_err());
    }
    #[test]
    fn release_expired_closes_only_past_the_bound_and_survives_restart() {
        let dir = Directory::new();
        let mut journal = dir.open();
        open_reserved_with_helper(&mut journal, 1_000);
        // A second operation created later has its own, later bound.
        journal.reserve(second_binding(), 50_000).unwrap();
        assert!(
            journal
                .release_expired(1_000 + RELEASE_AFTER_MS - 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(journal.pending().len(), 2);
        let released = journal.release_expired(1_000 + RELEASE_AFTER_MS).unwrap();
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].idempotency_key, "retry-1");
        assert_eq!(released[0].node_id, "node-a");
        assert!(
            !released[0].had_original_deadline,
            "no login handle was durable for this operation"
        );
        let record = &journal.records["operation-1"];
        assert_eq!(record.state, SessionState::Closed);
        assert_eq!(record.closed_at_ms, Some(1_000 + RELEASE_AFTER_MS));
        assert!(record.revoke_handle.is_none() && record.helper_unit.is_none());
        assert!(record.browser_unit.is_none() && record.browser_invocation.is_none());
        // Idempotent: a closed record is never released again.
        assert!(
            journal
                .release_expired(1_000 + RELEASE_AFTER_MS + 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(journal.pending().len(), 1);
        drop(journal);
        let mut restored = dir.open();
        assert_eq!(restored.records["operation-1"].state, SessionState::Closed);
        let released = restored.release_expired(50_000 + RELEASE_AFTER_MS).unwrap();
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].idempotency_key, "retry-2");
        assert!(restored.pending().is_empty());
    }
    #[test]
    fn released_session_with_a_login_handle_reports_its_deadline_for_closure_publication() {
        let dir = Directory::new();
        let mut journal = dir.open();
        open_reserved_with_helper(&mut journal, 1_000);
        journal
            .record_login(
                "operation-1",
                receipt().original_deadline_ms,
                receipt().revoke_handle,
                1_001,
            )
            .unwrap();
        journal.activate("operation-1", receipt(), 1_002).unwrap();
        let guard = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        journal.guard_context("operation-1", &guard).unwrap();
        let released = journal.release_expired(1_000 + RELEASE_AFTER_MS).unwrap();
        assert_eq!(released.len(), 1);
        assert!(released[0].had_original_deadline);
        assert!(
            !guard.load(Ordering::Acquire),
            "release withdraws any live context authority first"
        );
        let (binding, closed) = journal.closed_record("retry-1").unwrap();
        assert_eq!(binding.operation_id, "operation-1");
        assert_eq!(closed, 1_000 + RELEASE_AFTER_MS);
    }
    #[test]
    fn release_bound_covers_the_operation_deadline_session_ceiling_and_unit_limits() {
        fn seconds(unit: &str, key: &str) -> u64 {
            let line = unit
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .expect("unit sets the key");
            let line = line.trim();
            if let Some(value) = line.strip_suffix("min") {
                value.trim().parse::<u64>().unwrap() * 60
            } else if let Some(value) = line.strip_suffix('s') {
                value.trim().parse::<u64>().unwrap()
            } else {
                panic!("unsupported RuntimeMaxSec unit")
            }
        }
        let helper = include_str!("../../../deploy/native/blindpass-login-helper@.service");
        let browser = include_str!("../../../deploy/native/blindpass-browser@.service");
        let helper_ms = seconds(helper, "RuntimeMaxSec=") * 1_000;
        let browser_ms = seconds(browser, "RuntimeMaxSec=") * 1_000;
        // The helper must be gone before the operation deadline plus its own
        // lifetime, and the browser before its start (<= the operation
        // deadline) plus its lifetime; the website session is capped by the
        // application at 30 minutes from a login made inside the deadline.
        assert!(helper_ms <= 60_000, "helper lifetime assumption changed");
        assert!(
            browser_ms <= 1_800_000,
            "browser lifetime assumption changed"
        );
        assert!(RELEASE_AFTER_MS >= OPERATION_DEADLINE_MS + helper_ms);
        assert!(RELEASE_AFTER_MS >= OPERATION_DEADLINE_MS + browser_ms);
        const {
            assert!(RELEASE_AFTER_MS >= OPERATION_DEADLINE_MS + SESSION_CEILING_MS);
            assert!(
                RELEASE_AFTER_MS == OPERATION_DEADLINE_MS + SESSION_CEILING_MS + RELEASE_MARGIN_MS
            );
        }
    }
    #[test]
    fn unrecoverable_record_is_released_at_the_bound_so_the_account_is_reusable() {
        // An administrator who edits the recipe/catalog and restarts leaves
        // recovery unable to prepare a revocation for the old record; nothing
        // but the independent maximum can free its account.
        let dir = Directory::new();
        let mut journal = dir.open();
        open_reserved_with_helper(&mut journal, 1_000);
        drop(journal);
        let mut restored = dir.open();
        let mut again = binding();
        again.operation_id = "operation-9".into();
        again.idempotency_key = "retry-9".into();
        assert!(restored.reserve(again.clone(), 60_000).is_err());
        assert!(
            restored
                .release_expired(1_000 + RELEASE_AFTER_MS - 1)
                .unwrap()
                .is_empty()
        );
        assert!(
            restored
                .reserve(again.clone(), 1_000 + RELEASE_AFTER_MS - 1)
                .is_err()
        );
        assert_eq!(
            restored
                .release_expired(1_000 + RELEASE_AFTER_MS)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            restored.reserve(again, 1_000 + RELEASE_AFTER_MS),
            Ok(Reservation::New)
        );
    }
    #[test]
    fn idle_prune_does_not_rewrite_the_journal_until_something_changes() {
        let dir = Directory::new();
        let mut journal = dir.open();
        open_reserved_with_helper(&mut journal, 1_000);
        journal.reconcile("operation-1", true, true, 1_001).unwrap();
        let writes = journal.writes;
        for tick in 1..=5 {
            assert_eq!(journal.prune(1_001 + tick * 60_000).unwrap(), 0);
        }
        assert_eq!(journal.writes, writes, "an idle prune never writes");
        assert_eq!(journal.time_high_water_ms, 1_001 + 300_000);
        // A stale durable mark is refreshed at a bounded interval.
        assert_eq!(
            journal
                .prune(1_001 + HIGH_WATER_PERSIST_INTERVAL_MS)
                .unwrap(),
            0
        );
        assert_eq!(journal.writes, writes + 1);
        // A removal always persists.
        assert_eq!(journal.prune(1_001 + RETENTION_MS).unwrap(), 1);
        assert_eq!(journal.writes, writes + 2);
        drop(journal);
        assert!(dir.open().records.is_empty());
    }
    #[test]
    fn fence_is_cleared_by_a_durable_snapshot_and_invalidated_permits_stay_invalid() {
        let dir = Directory::new();
        let mut journal = dir.open();
        open_reserved_with_helper(&mut journal, 1_000);
        let unit = "blindpass-login-helper@fixture.service";
        let permit = journal
            .helper_source_permit("operation-1", unit, &"c".repeat(32))
            .unwrap();
        assert!(journal.try_unfence(), "an unfenced journal is a no-op");
        assert!(permit.allows_source());
        journal.fail_next_persist = true;
        assert!(journal.reserve(second_binding(), 1_002).is_err());
        assert!(journal.is_fenced());
        assert!(!permit.allows_source());
        assert!(journal.begin_revoke("operation-1", 1_003).is_err());
        // The next durable write still failing keeps the fence.
        journal.fail_next_persist = true;
        assert!(!journal.try_unfence());
        assert!(journal.is_fenced());
        assert!(journal.try_unfence());
        assert!(!journal.is_fenced());
        assert!(
            !permit.allows_source(),
            "an invalidated permit never revives"
        );
        assert!(
            journal
                .helper_source_permit("operation-1", unit, &"c".repeat(32))
                .is_err(),
            "the single-use permit is not reissued"
        );
        // New work resumes, with fresh permits for operations not yet armed.
        journal
            .record_helper(
                "operation-2",
                "blindpass-login-helper@second.service",
                &"d".repeat(32),
                1_004,
            )
            .unwrap();
        let fresh = journal
            .helper_source_permit(
                "operation-2",
                "blindpass-login-helper@second.service",
                &"d".repeat(32),
            )
            .unwrap();
        assert!(fresh.allows_source());
        journal.begin_revoke("operation-1", 1_005).unwrap();
        drop(fresh);
        drop(permit);
        drop(journal);
        // The in-memory reservation that failed to persist is durable now and
        // restart treats it like any unfinished intent.
        let restored = dir.open();
        assert_eq!(restored.records.len(), 2);
        assert_eq!(
            restored.records["operation-2"].state,
            SessionState::BlockedUncertain
        );
    }
    #[test]
    fn admission_is_refused_only_for_the_blocked_account_workload_or_replayed_key() {
        let dir = Directory::new();
        let mut journal = dir.open();
        open_reserved_with_helper(&mut journal, 1_000);
        drop(journal);
        let mut restored = dir.open();
        assert_eq!(restored.pending()[0].state, SessionState::BlockedUncertain);
        // Same account, same workload unit and a replayed key are refused.
        assert!(restored.admission_blocked("primary", "other.service", "gr_other"));
        assert!(restored.admission_blocked("other", "agent-1.service", "gr_other"));
        assert!(restored.admission_blocked("other", "other.service", "retry-1"));
        // Another account and workload are not.
        assert!(!restored.admission_blocked("isolation", "agent-2.service", "retry-2"));
        assert_eq!(
            restored.reserve(second_binding(), 1_100),
            Ok(Reservation::New)
        );
        let mut same = binding();
        same.operation_id = "operation-3".into();
        same.idempotency_key = "retry-3".into();
        assert!(restored.reserve(same, 1_101).is_err());
        let keys = restored.unresolved_request_keys();
        assert!(keys.is_empty(), "records carry no request correlation here");
        let mut correlated = second_binding();
        correlated.operation_id = "operation-4".into();
        correlated.idempotency_key = "retry-4".into();
        correlated.account = "third".into();
        correlated.workload_unit = "agent-4.service".into();
        correlated.request_event_key = Some("event_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        restored.reserve(correlated, 1_102).unwrap();
        assert!(
            restored
                .unresolved_request_keys()
                .contains("event_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        restored
            .reconcile("operation-4", true, true, 1_103)
            .unwrap();
        assert!(restored.unresolved_request_keys().is_empty());
    }
}
