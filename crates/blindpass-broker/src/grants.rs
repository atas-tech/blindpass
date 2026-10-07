// SPDX-License-Identifier: AGPL-3.0-only

//! Freshness-bound grant deadlines and durable one-use consumption records.

use blindpass_core::custody::sha256;
use blindpass_core::fleet::{
    ConsumptionMode, Grant, PolicySnapshot, Registration, Revocation, TimeReply, is_valid_opaque_id,
};
use blindpass_core::identity::WorkloadAuthorization;
use blindpass_core::signing::base64_url_encode;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_TIME_REPLY_DELAY_MS: u64 = 35_000;
const MAX_DOCUMENT_AGE_MS: u64 = 60_000;
const CLOCK_ROLLBACK_TOLERANCE_MS: u64 = 2_000;
const GRANT_JOURNAL_MAX_BYTES: u64 = 64 * 1024 * 1024;
const GRANT_JOURNAL_MAX_RECORDS: usize = 1_000_000;
const GRANT_REPLAY_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_RETIRED_GRANTS: usize = 10_000;
const MAX_ACCEPTED_GRANTS: usize = 10_000;
/// A verified grant whose fate is already recorded; redelivery changes nothing.
pub(crate) const GRANT_ALREADY_SETTLED: &str = "grant is already settled";
const PRIVATE_FILE_MODE: u32 = 0o600;
const NO_FOLLOW: i32 = blindpass_core::open_flags::O_NOFOLLOW;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

mod history;
mod report;
use history::ConsumptionHistory;

pub(crate) fn initialize_consumption_history(path: &Path) -> Result<(), &'static str> {
    history::initialize(path)
}

pub(crate) fn bind_consumption_history(
    path: &Path,
    pin: &crate::keys::PinnedIssuer,
) -> Result<(), &'static str> {
    history::bind(path, pin).map(|_| ())
}

pub(crate) fn bind_history_observation(
    path: &Path,
    pin: &crate::keys::PinnedIssuer,
) -> Result<u64, &'static str> {
    history::bind(path, pin)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TimeChallenge {
    value: String,
    sent_at_boottime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedTime {
    /// Controller time signed into the reply; a lower bound on controller
    /// time at receipt. Used for rollback checks, the persisted high-water
    /// mark and journal pruning.
    signed_controller_ms: u64,
    /// Upper bound on controller time at receipt: the signed time plus the
    /// part of the round trip the controller did not account for. Used for
    /// grant deadlines and document age so relay delay cannot add lifetime.
    estimated_controller_ms: u64,
    received_at_boottime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptedGrant {
    grant: Grant,
    deadline_boottime_ms: u64,
    document_hash: [u8; 32],
}

#[derive(Debug, Default)]
pub(crate) struct GrantVerifier {
    pending_time: Option<TimeChallenge>,
    trusted_time: Option<TrustedTime>,
    highest_controller_time_ms: Option<u64>,
    trusted_time_path: Option<PathBuf>,
    accepted: BTreeMap<String, AcceptedGrant>,
    /// The pinned controller issuer epoch. Grants of any other epoch are
    /// neither accepted nor consumable.
    issuer_epoch: Option<u64>,
    retired: BTreeMap<String, ConsumeDenial>,
    retired_order: VecDeque<String>,
    journal: Option<GrantJournal>,
    revocations: Option<RevocationJournal>,
    recovery_challenge: Option<report::PendingChallenge>,
    recovery_snapshot: Option<report::HistorySnapshot>,
}

#[derive(Debug, Default)]
struct GrantJournal {
    path: Option<PathBuf>,
    consumed: BTreeMap<String, u64>,
    /// Immutable correlation from the same durable consume intent. Legacy
    /// records remain unmapped; neither restart nor compaction guesses it.
    bindings: BTreeMap<String, ConsumedBinding>,
    /// Present only when this broker created a durable fresh identity genesis.
    history: Option<ConsumptionHistory>,
    revision: Option<JournalRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JournalRevision {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl JournalRevision {
    fn from_file(file: &File) -> Result<Self, &'static str> {
        let metadata = file
            .metadata()
            .map_err(|_| "grant journal metadata is unavailable")?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

/// Every append, compaction and pin binding shares this private lock inode.
/// Contention denies the current request; it never blocks a control peer.
fn lock_consumption_journal(path: &Path) -> Result<File, &'static str> {
    let file = open_private(&path.with_extension("lock"), true)
        .map_err(|_| "grant journal lock could not be opened safely")?;
    if file
        .metadata()
        .map_err(|_| "grant journal lock is unavailable")?
        .len()
        != 0
    {
        return Err("grant journal lock is malformed");
    }
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    // SAFETY: the owned File supplies a live descriptor; 2|4 is LOCK_EX|LOCK_NB.
    if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 {
        return Err("grant journal is busy");
    }
    Ok(file)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConsumedBinding {
    operation_id: String,
    issuer_epoch: u64,
}

#[derive(Debug, Default)]
struct RevocationJournal {
    path: Option<PathBuf>,
    acknowledged_path: Option<PathBuf>,
    tombstones: BTreeMap<String, u64>,
    /// The first observed result is committed with the tombstone so a
    /// restart can recover an outcome lost from a full queue.
    outcomes: BTreeMap<String, (&'static str, u64)>,
    acknowledged_outcomes: BTreeSet<String>,
    /// Tombstones in force in memory whose journal append has not succeeded.
    unpersisted: BTreeSet<String>,
}

impl GrantVerifier {
    pub(crate) fn with_state_files(
        journal_path: &Path,
        trusted_time_path: &Path,
        revocation_path: &Path,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            highest_controller_time_ms: read_trusted_time(trusted_time_path)?,
            trusted_time_path: Some(trusted_time_path.to_owned()),
            journal: Some(GrantJournal::open(journal_path)?),
            revocations: Some(RevocationJournal::open(revocation_path)?),
            ..Self::default()
        })
    }

    pub(crate) fn begin_time_challenge(&mut self) -> Result<String, &'static str> {
        let sent_at_boottime_ms = boottime_ms()?;
        let mut nonce = [0_u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut nonce))
            .map_err(|_| "time challenge randomness is unavailable")?;
        let value = base64_url_encode(&nonce);
        self.pending_time = Some(TimeChallenge {
            value: value.clone(),
            sent_at_boottime_ms,
        });
        Ok(value)
    }

    pub(crate) fn trusted_controller_time_ms(&self, now_boottime_ms: u64) -> Option<u64> {
        let trusted = self.trusted_time.as_ref().filter(|time| {
            now_boottime_ms.saturating_sub(time.received_at_boottime_ms) <= MAX_TIME_REPLY_DELAY_MS
        })?;
        trusted
            .estimated_controller_ms
            .checked_add(now_boottime_ms.saturating_sub(trusted.received_at_boottime_ms))
    }

    pub(crate) fn accept_time_reply(
        &mut self,
        reply: &TimeReply,
        expected_node_id: &str,
        expected_epoch: u64,
        now_boottime_ms: u64,
    ) -> Result<(), &'static str> {
        let challenge = self
            .pending_time
            .take()
            .ok_or("time reply has no pending broker challenge")?;
        if reply.challenge != challenge.value
            || reply.node_id != expected_node_id
            || reply.issuer_epoch != expected_epoch
        {
            return Err("time reply does not match the pending broker challenge");
        }
        let round_trip_ms = now_boottime_ms
            .checked_sub(challenge.sent_at_boottime_ms)
            .filter(|value| *value <= MAX_TIME_REPLY_DELAY_MS)
            .ok_or("time reply delay is outside the supported bound")?;
        // The controller stamps the reply after its long-poll hold and signs
        // both the arrival and response times. Any part of the round trip it
        // did not hold may have elapsed after the stamp, including delay the
        // relay added, so count it towards controller time.
        let controller_now_ms = reply.controller_time_ms;
        let controller_hold_ms = reply
            .controller_time_ms
            .saturating_sub(reply.challenge_received_at_ms);
        let estimated_controller_ms = controller_now_ms
            .checked_add(round_trip_ms.saturating_sub(controller_hold_ms))
            .ok_or("time reply exceeds the supported clock range")?;
        if let Some(previous) = self.trusted_time.as_ref() {
            let elapsed = now_boottime_ms.saturating_sub(previous.received_at_boottime_ms);
            let minimum_now = previous
                .signed_controller_ms
                .saturating_add(elapsed)
                .saturating_sub(CLOCK_ROLLBACK_TOLERANCE_MS);
            if estimated_controller_ms < minimum_now {
                return Err("controller time moved backwards beyond the accepted tolerance");
            }
        }
        if self.highest_controller_time_ms.is_some_and(|previous| {
            controller_now_ms.saturating_add(CLOCK_ROLLBACK_TOLERANCE_MS) < previous
        }) {
            return Err("controller time moved backwards beyond the persisted high-water mark");
        }
        let highest_controller_time_ms = self
            .highest_controller_time_ms
            .unwrap_or_default()
            .max(controller_now_ms);
        if let Some(path) = self.trusted_time_path.as_deref() {
            write_trusted_time(path, highest_controller_time_ms)?;
        }
        if let Some(journal) = self.journal.as_mut() {
            journal.prune(controller_now_ms)?;
        }
        if let Some(revocations) = self.revocations.as_mut() {
            revocations.prune(controller_now_ms)?;
        }
        let expired = self
            .accepted
            .iter()
            .filter(|(_, accepted)| {
                accepted.grant.expires_at_ms <= estimated_controller_ms
                    || accepted.deadline_boottime_ms <= now_boottime_ms
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            self.accepted.remove(&id);
            self.retire(id, ConsumeDenial::Expired);
        }
        self.highest_controller_time_ms = Some(highest_controller_time_ms);
        self.trusted_time = Some(TrustedTime {
            signed_controller_ms: controller_now_ms,
            estimated_controller_ms,
            received_at_boottime_ms: now_boottime_ms,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // The acceptance check keeps every signed binding explicit.
    pub(crate) fn accept_grant(
        &mut self,
        grant: Grant,
        document: &[u8],
        node_id: &str,
        recipient_key_id: &str,
        policy: &PolicySnapshot,
        registration: &Registration,
        now_boottime_ms: u64,
    ) -> Result<bool, &'static str> {
        let now_controller_ms = self
            .trusted_controller_time_ms(now_boottime_ms)
            .ok_or("grant has no fresh signed controller time proof")?;
        // Settle redeliveries before any binding check. A grant already
        // accepted, consumed, revoked or retired can be redelivered after a
        // session break, a relay restart or a later key, policy or
        // registration change; none of those may block the documents behind it.
        let digest = sha256(document).map_err(|_| "grant digest could not be computed")?;
        if let Some(existing) = self.accepted.get(&grant.id) {
            if existing.document_hash == digest && existing.grant == grant {
                return Ok(false);
            }
            return Err("grant id was reused with different signed content");
        }
        if self.missing_grant_denial(&grant.id) != ConsumeDenial::Unknown {
            return Err(GRANT_ALREADY_SETTLED);
        }
        let remaining_ms = grant
            .expires_at_ms
            .checked_sub(now_controller_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or("grant expired before broker receipt")?;
        if self.issuer_epoch != Some(grant.issuer_epoch) {
            return Err("grant issuer epoch is not the pinned issuer epoch");
        }
        if grant.node_id != node_id
            || grant.recipient_key_id != recipient_key_id
            || grant.registration_version != registration.registration_version
            || grant.policy_version != policy.policy_version
            || registration.policy_version != grant.policy_version
            || grant.local_ceiling_seconds > policy.local_ceiling_seconds
            || grant.local_ceiling_seconds > registration.local_ceiling_seconds
            || registration.status != "active"
            || registration.node_id != grant.node_id
            || registration.workload_id != grant.workload_id
            || registration.unit != grant.unit
            || registration.account != grant.account
            || registration
                .invocation_id
                .as_deref()
                .is_some_and(|expected| expected != grant.invocation_id)
            || registration.consumption_mode != grant.mode
            || grant.audience != "blindpass-node"
            || !policy
                .allowed_actions
                .iter()
                .any(|action| action == &grant.action)
            || !policy.allowed_modes.contains(&grant.mode)
        {
            return Err("grant does not match current broker policy and workload registration");
        }
        if grant.issued_at_ms > now_controller_ms
            || now_controller_ms.saturating_sub(grant.issued_at_ms) > MAX_DOCUMENT_AGE_MS
            || grant.expires_at_ms.saturating_sub(grant.issued_at_ms) > 3_600_000
        {
            return Err("grant is stale or exceeds the broker lifetime maximum");
        }
        // The broker enforces every local ceiling itself, even for a signed
        // grant whose ceiling passed the comparisons above.
        let local_ceiling_ms = grant
            .local_ceiling_seconds
            .min(policy.local_ceiling_seconds)
            .min(registration.local_ceiling_seconds)
            .saturating_mul(1_000);
        let deadline_boottime_ms = now_boottime_ms
            .checked_add(remaining_ms.min(local_ceiling_ms))
            .filter(|deadline| *deadline > now_boottime_ms)
            .ok_or("grant has no safe local lifetime remaining")?;
        if self.accepted.len() >= MAX_ACCEPTED_GRANTS {
            return Err("broker grant capacity reached");
        }
        self.accepted.insert(
            grant.id.clone(),
            AcceptedGrant {
                grant,
                deadline_boottime_ms,
                document_hash: digest,
            },
        );
        Ok(true)
    }

    pub(crate) fn consume(
        &mut self,
        grant_id: &str,
        authorization: &WorkloadAuthorization,
        current_policy_version: u64,
        now_boottime_ms: u64,
    ) -> Result<Grant, ConsumeDenial> {
        let accepted_grant = self.validate_consumption(
            grant_id,
            authorization,
            current_policy_version,
            now_boottime_ms,
        )?;
        let grant_id = accepted_grant.grant.id.clone();
        let consumed_grant = accepted_grant.grant.clone();
        let journal = self.journal.as_mut().ok_or(ConsumeDenial::Unavailable)?;
        journal
            .record_bound_consumption(&consumed_grant)
            .map_err(|_| ConsumeDenial::Unavailable)?;
        let accepted = self
            .accepted
            .remove(&grant_id)
            .ok_or(ConsumeDenial::Consumed)?;
        Ok(accepted.grant)
    }

    pub(crate) fn preview_consumption(
        &self,
        grant_id: &str,
        authorization: &WorkloadAuthorization,
        current_policy_version: u64,
        now_boottime_ms: u64,
    ) -> Result<Grant, ConsumeDenial> {
        self.validate_consumption(
            grant_id,
            authorization,
            current_policy_version,
            now_boottime_ms,
        )
        .map(|accepted| accepted.grant.clone())
    }
    pub(crate) fn preview_consumption_deadline(
        &self,
        grant_id: &str,
        authorization: &WorkloadAuthorization,
        current_policy_version: u64,
        now_boottime_ms: u64,
    ) -> Result<(Grant, u64), ConsumeDenial> {
        self.validate_consumption(
            grant_id,
            authorization,
            current_policy_version,
            now_boottime_ms,
        )
        .map(|accepted| (accepted.grant.clone(), accepted.deadline_boottime_ms))
    }
    /// Resolve only an exact signed browser request correlation. Multiple
    /// grants for the same request fail closed rather than choosing one.
    pub(crate) fn preview_request_grant(
        &self,
        key: &str,
        authorization: &WorkloadAuthorization,
        current_policy_version: u64,
        now_boottime_ms: u64,
    ) -> Option<Grant> {
        let mut candidates = self.accepted.values().filter(|accepted| {
            accepted.grant.request_event_key.as_deref() == Some(key)
                && accepted.grant.mode == ConsumptionMode::BrowserSession
                && accepted.grant.action == "browser.session"
        });
        let first = candidates.next()?;
        if candidates.next().is_some() {
            return None;
        }
        let mut consuming = authorization.clone();
        consuming.operation = format!("consume:{}", first.grant.id);
        self.preview_consumption(
            &first.grant.id,
            &consuming,
            current_policy_version,
            now_boottime_ms,
        )
        .ok()
    }
    pub(crate) fn matches_issuer_epoch(&self, epoch: u64) -> bool {
        self.issuer_epoch == Some(epoch)
    }

    /// Check a consumption request and name the one reason it is denied.
    /// Identity is checked before lifetime so that another workload cannot
    /// learn the state of a grant bound to someone else.
    fn validate_consumption(
        &self,
        grant_id: &str,
        authorization: &WorkloadAuthorization,
        current_policy_version: u64,
        now_boottime_ms: u64,
    ) -> Result<&AcceptedGrant, ConsumeDenial> {
        let Some(accepted) = self.accepted.get(grant_id) else {
            return Err(self.missing_grant_denial(grant_id));
        };
        let grant = &accepted.grant;
        if authorization.node_id != grant.node_id
            || authorization.workload_id != grant.workload_id
            || authorization.unit != grant.unit
            || authorization.invocation_id != grant.invocation_id
            || authorization.operation != format!("consume:{grant_id}")
            || grant.audience != "blindpass-node"
        {
            return Err(ConsumeDenial::IdentityMismatch);
        }
        if self.issuer_epoch != Some(grant.issuer_epoch) {
            return Err(ConsumeDenial::EpochStale);
        }
        if grant.policy_version != current_policy_version {
            return Err(ConsumeDenial::PolicyStale);
        }
        if now_boottime_ms >= accepted.deadline_boottime_ms {
            return Err(ConsumeDenial::Expired);
        }
        Ok(accepted)
    }

    fn missing_grant_denial(&self, grant_id: &str) -> ConsumeDenial {
        if self
            .journal
            .as_ref()
            .is_some_and(|journal| journal.consumed.contains_key(grant_id))
        {
            return ConsumeDenial::Consumed;
        }
        if self
            .revocations
            .as_ref()
            .is_some_and(|journal| journal.tombstones.contains_key(grant_id))
        {
            return ConsumeDenial::Revoked;
        }
        self.retired
            .get(grant_id)
            .copied()
            .unwrap_or(ConsumeDenial::Unknown)
    }

    /// Remember, within a fixed bound, why an accepted grant was dropped so
    /// that a later consumption attempt reports the actual reason. After a
    /// restart the record is gone and the grant reports `grant_unknown`.
    fn retire(&mut self, grant_id: String, reason: ConsumeDenial) {
        if self.retired.insert(grant_id.clone(), reason).is_none() {
            self.retired_order.push_back(grant_id);
        }
        while self.retired_order.len() > MAX_RETIRED_GRANTS {
            if let Some(oldest) = self.retired_order.pop_front() {
                self.retired.remove(&oldest);
            }
        }
    }

    fn retire_where(&mut self, reason: ConsumeDenial, retire: impl Fn(&Grant) -> bool) {
        let ids = self
            .accepted
            .iter()
            .filter(|(_, accepted)| retire(&accepted.grant))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            self.accepted.remove(&id);
            self.retire(id, reason);
        }
    }

    /// Record the pinned issuer epoch. When it advances, every accepted
    /// grant of a lower epoch loses its authority immediately.
    pub(crate) fn observe_issuer_epoch(&mut self, epoch: u64) {
        if self.issuer_epoch.is_some_and(|current| epoch <= current) {
            return;
        }
        self.retire_where(ConsumeDenial::EpochStale, |grant| {
            grant.issuer_epoch < epoch
        });
        self.issuer_epoch = Some(epoch);
    }

    /// Retire every accepted grant bound to a recipient key other than the
    /// node's current one. A signed rotation ends the old key's authority.
    pub(crate) fn retire_other_recipient_keys(&mut self, current_recipient_key_id: &str) {
        self.retire_where(ConsumeDenial::KeyRotated, |grant| {
            grant.recipient_key_id != current_recipient_key_id
        });
    }

    pub(crate) fn revoke_workload(&mut self, workload_id: &str) {
        self.retire_where(ConsumeDenial::RegistrationChanged, |grant| {
            grant.workload_id == workload_id
        });
    }

    /// Apply a signed revocation. The grant loses its authority in memory
    /// before the tombstone is written; a failed write returns an error so
    /// the relay retries, while the revocation stays in force.
    pub(crate) fn revoke(
        &mut self,
        revocation: &Revocation,
        observed_at_ms: u64,
    ) -> Result<(), &'static str> {
        let outcome = self.revocation_outcome(&revocation.grant_id);
        if self.accepted.remove(&revocation.grant_id).is_some() {
            self.retire(revocation.grant_id.clone(), ConsumeDenial::Revoked);
        }
        self.revocations
            .get_or_insert_with(RevocationJournal::default)
            .record(
                &revocation.grant_id,
                revocation.retain_until_ms,
                Some((outcome, observed_at_ms)),
            )
    }

    /// True when a tombstone for the grant is already in force.
    pub(crate) fn has_tombstone(&self, grant_id: &str) -> bool {
        self.revocations
            .as_ref()
            .is_some_and(|journal| journal.tombstones.contains_key(grant_id))
    }

    pub(crate) fn has_recorded_revocation_outcome(&self, grant_id: &str) -> bool {
        self.revocations.as_ref().is_some_and(|journal| {
            journal.outcomes.contains_key(grant_id)
                && !journal.acknowledged_outcomes.contains(grant_id)
        })
    }

    pub(crate) fn acknowledge_revocation_outcome(
        &mut self,
        grant_id: &str,
    ) -> Result<(), &'static str> {
        if let Some(journal) = self.revocations.as_mut() {
            journal.acknowledge_outcome(grant_id)?;
        }
        Ok(())
    }

    pub(crate) fn pending_revocation_outcomes_after(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Vec<(String, &'static str, u64)> {
        self.revocations.as_ref().map_or_else(Vec::new, |journal| {
            use std::ops::Bound::{Excluded, Unbounded};
            let range = match after {
                Some(cursor) => journal
                    .outcomes
                    .range::<str, _>((Excluded(cursor), Unbounded)),
                None => journal.outcomes.range::<str, _>((Unbounded, Unbounded)),
            };
            range
                .filter(|(id, _)| !journal.acknowledged_outcomes.contains(*id))
                .take(limit)
                .map(|(id, (outcome, observed_at_ms))| (id.clone(), *outcome, *observed_at_ms))
                .collect()
        })
    }

    /// What a revocation applied now would change for this grant.
    pub(crate) fn revocation_outcome(&self, grant_id: &str) -> &'static str {
        if let Some((outcome, _)) = self
            .revocations
            .as_ref()
            .and_then(|journal| journal.outcomes.get(grant_id))
        {
            return outcome;
        }
        if self.accepted.contains_key(grant_id) {
            "revoked_before_consumption"
        } else if self
            .journal
            .as_ref()
            .is_some_and(|journal| journal.consumed.contains_key(grant_id))
        {
            "already_consumed"
        } else {
            "not_received"
        }
    }

    pub(crate) fn revocation_observed_at_ms(&self, grant_id: &str) -> Option<u64> {
        self.revocations
            .as_ref()
            .and_then(|journal| journal.outcomes.get(grant_id))
            .map(|(_, observed_at_ms)| *observed_at_ms)
    }

    #[cfg(test)]
    pub(crate) fn is_accepted(&self, grant_id: &str) -> bool {
        self.accepted.contains_key(grant_id)
    }

    /// True while a revocation is in force only in memory.
    pub(crate) fn has_unpersisted_revocations(&self) -> bool {
        self.revocations
            .as_ref()
            .is_some_and(RevocationJournal::has_unpersisted)
    }

    pub(crate) fn retry_revocation_persistence(&mut self) -> Result<(), &'static str> {
        match self.revocations.as_mut() {
            Some(journal) => journal.retry_unpersisted(),
            None => Ok(()),
        }
    }

    pub(crate) fn revoke_stale_policy(&mut self, policy_version: u64) {
        self.retire_where(ConsumeDenial::PolicyStale, |grant| {
            grant.policy_version != policy_version
        });
    }
}

/// Stable reason codes for a denied grant consumption. They name broker
/// state only and never carry secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsumeDenial {
    /// The suspend-aware local deadline has passed.
    Expired,
    /// A signed revocation tombstone exists for the grant.
    Revoked,
    /// The durable consumed journal already contains the grant.
    Consumed,
    /// The grant was never accepted or needs fresh reconciliation, for
    /// example after a broker restart or host reboot.
    Unknown,
    /// Node, workload, unit, invocation or operation differ from the grant.
    IdentityMismatch,
    /// The fleet policy version changed after the grant was issued.
    PolicyStale,
    /// The workload registration changed or was revoked after issue.
    RegistrationChanged,
    /// The pinned issuer epoch advanced past the grant's epoch.
    EpochStale,
    /// A signed node key rotation replaced the recipient key the grant names.
    KeyRotated,
    /// The durable consumption intent could not be recorded.
    Unavailable,
}

impl ConsumeDenial {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 10] = [
        Self::Expired,
        Self::Revoked,
        Self::Consumed,
        Self::Unknown,
        Self::IdentityMismatch,
        Self::PolicyStale,
        Self::RegistrationChanged,
        Self::EpochStale,
        Self::KeyRotated,
        Self::Unavailable,
    ];

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Expired => "grant_expired",
            Self::Revoked => "grant_revoked",
            Self::Consumed => "grant_consumed",
            Self::Unknown => "grant_unknown",
            Self::IdentityMismatch => "grant_identity_mismatch",
            Self::PolicyStale => "grant_policy_stale",
            Self::RegistrationChanged => "grant_registration_changed",
            Self::EpochStale => "grant_epoch_stale",
            Self::KeyRotated => "grant_key_rotated",
            Self::Unavailable => "consumption_unavailable",
        }
    }
}

impl GrantJournal {
    fn open(path: &Path) -> Result<Self, &'static str> {
        let _lock = lock_consumption_journal(path)?;
        Self::read_locked(path)
    }

    fn read_locked(path: &Path) -> Result<Self, &'static str> {
        let mut journal = Self {
            path: Some(path.to_owned()),
            consumed: BTreeMap::new(),
            bindings: BTreeMap::new(),
            history: None,
            revision: None,
        };
        let mut file = match open_private_for_recovery(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(journal),
            Err(_) => return Err("grant journal could not be opened safely"),
        };
        let metadata = file
            .metadata()
            .map_err(|_| "grant journal metadata is unavailable")?;
        if metadata.len() > GRANT_JOURNAL_MAX_BYTES {
            return Err("grant journal exceeds its configured size bound");
        }
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut contents)
            .map_err(|_| "grant journal could not be read")?;
        let has_history = contents
            .split(|byte| *byte == b'\n')
            .any(|line| line.starts_with(b"{\"history_version\":"));
        if has_history
            && (!contents.starts_with(b"{\"history_version\":") || !contents.contains(&b'\n'))
        {
            // A misplaced or newline-less header cannot claim complete
            // coverage. Keep the bytes for recovery review and deny
            // consumption at startup. An unterminated record after a complete
            // header is a never-durable append and is cut by the repair below.
            return Err("grant history is misplaced or its header is torn");
        }
        truncate_torn_tail(&file, &mut contents)
            .map_err(|_| "grant journal torn record could not be truncated")?;
        for (index, line) in contents
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .enumerate()
        {
            if line.starts_with(b"{\"history_version\":") {
                if index != 0 || journal.history.is_some() {
                    return Err("grant history header is misplaced or duplicated");
                }
                journal.history = Some(ConsumptionHistory::parse(line)?);
                continue;
            }
            let (id, expiry, binding) = parse_journal_line(line)?;
            if let Some(existing) = journal.consumed.get(id) {
                if *existing != expiry || journal.bindings.get(id) != binding.as_ref() {
                    return Err("grant journal contains a conflicting replay record");
                }
                continue;
            }
            journal.consumed.insert(id.to_owned(), expiry);
            if let Some(binding) = binding {
                if let Some(history) = &mut journal.history {
                    history.highest_issuer_epoch =
                        history.highest_issuer_epoch.max(binding.issuer_epoch);
                }
                journal.bindings.insert(id.to_owned(), binding);
            }
        }
        if journal.consumed.len() > GRANT_JOURNAL_MAX_RECORDS {
            return Err("grant journal exceeds its record bound");
        }
        if journal
            .history
            .as_ref()
            .is_some_and(|history| !history.is_bound())
            && !journal.consumed.is_empty()
        {
            return Err("unbound grant history contains consumption records");
        }
        journal.revision = Some(JournalRevision::from_file(&file)?);
        Ok(journal)
    }

    /// The caller holds the journal lock. Usually metadata is unchanged;
    /// reload the bounded durable replay map only after another writer or a
    /// pin binding replaced/extended it. This prevents lost consume intents.
    fn synchronize(&mut self) -> Result<(), &'static str> {
        let path = self
            .path
            .as_ref()
            .ok_or("grant journal path is unavailable")?;
        let file = match open_private_for_recovery(path) {
            Ok(file) => file,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && self.revision.is_none() =>
            {
                return Ok(());
            }
            Err(_) => return Err("grant history is unavailable"),
        };
        if self.revision.as_ref() == Some(&JournalRevision::from_file(&file)?) {
            return Ok(());
        }
        let mut current = Self::read_locked(path)?;
        if let Some(previous) = &self.history {
            let history = current
                .history
                .as_mut()
                .ok_or("grant history provenance disappeared")?;
            if history.history_id != previous.history_id
                || history.pruned_through_ms < previous.pruned_through_ms
                || (previous.is_bound() && !history.same_scope(previous))
            {
                return Err("grant history identity or coverage changed");
            }
            // Records only leave through compaction, which advances
            // `pruned_through_ms` past their expiry. A journal that lost any
            // other record this process already saw is an older copy: refuse
            // instead of re-admitting an already consumed grant.
            let pruned_through_ms = history.pruned_through_ms;
            if self.consumed.iter().any(|(id, expires_at_ms)| {
                *expires_at_ms > pruned_through_ms
                    && current.consumed.get(id) != Some(expires_at_ms)
            }) {
                return Err("grant history lost consumption records");
            }
            history.highest_issuer_epoch = history
                .highest_issuer_epoch
                .max(previous.highest_issuer_epoch);
        }
        *self = current;
        Ok(())
    }

    #[cfg(test)]
    fn record_consumption(
        &mut self,
        grant_id: &str,
        expires_at_ms: u64,
    ) -> Result<(), &'static str> {
        self.record(grant_id, expires_at_ms, None, None)
    }

    fn record_bound_consumption(&mut self, grant: &Grant) -> Result<(), &'static str> {
        if !is_valid_opaque_id(&grant.operation_id)
            || !(1..=9_007_199_254_740_991).contains(&grant.issuer_epoch)
        {
            return Err("grant consume correlation is invalid");
        }
        self.record(
            &grant.id,
            grant.expires_at_ms,
            Some(ConsumedBinding {
                operation_id: grant.operation_id.clone(),
                issuer_epoch: grant.issuer_epoch,
            }),
            Some(&grant.node_id),
        )
    }

    fn record(
        &mut self,
        grant_id: &str,
        expires_at_ms: u64,
        binding: Option<ConsumedBinding>,
        node_id: Option<&str>,
    ) -> Result<(), &'static str> {
        let path = self
            .path
            .clone()
            .ok_or("grant journal path is unavailable")?;
        let _lock = lock_consumption_journal(&path)?;
        self.synchronize()?;
        if self
            .history
            .as_ref()
            .is_some_and(|history| !history.is_bound() || node_id != Some(history.node_id.as_str()))
        {
            return Err("grant consumption history has the wrong node scope");
        }
        if self.history.as_ref().is_some_and(|history| {
            binding
                .as_ref()
                .is_none_or(|binding| binding.issuer_epoch != history.highest_issuer_epoch)
        }) {
            return Err("grant consumption epoch does not match the durable issuer pin");
        }
        if !is_valid_opaque_id(grant_id) || expires_at_ms == 0 {
            return Err("grant consumption intent is invalid");
        }
        if self.consumed.contains_key(grant_id) {
            return Err("grant was already consumed");
        }
        if self.consumed.len() >= GRANT_JOURNAL_MAX_RECORDS {
            return Err("grant journal is full; new grant consumption is denied");
        }
        let path = self
            .path
            .as_ref()
            .ok_or("grant journal path is unavailable")?;
        let line = consumption_line(grant_id, expires_at_ms, binding.as_ref());
        let existed = match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err("grant journal could not be inspected safely"),
        };
        let mut file = open_private(path, true)
            .map_err(|_| "grant journal could not be opened for durable append")?;
        let length = file
            .metadata()
            .map_err(|_| "grant journal metadata is unavailable")?
            .len();
        if length.saturating_add(line.len() as u64) > GRANT_JOURNAL_MAX_BYTES {
            return Err("grant journal is full; new grant consumption is denied");
        }
        if file
            .write_all(line.as_bytes())
            .and_then(|()| file.sync_all())
            .is_err()
        {
            // Cut a partial record so the next append starts on a record
            // boundary; startup repairs the tail if this also fails.
            let _ = file.set_len(length).and_then(|()| file.sync_all());
            return Err("grant consumption intent could not be flushed");
        }
        self.consumed.insert(grant_id.to_owned(), expires_at_ms);
        if let Some(binding) = binding {
            if let Some(history) = &mut self.history {
                history.highest_issuer_epoch =
                    history.highest_issuer_epoch.max(binding.issuer_epoch);
            }
            self.bindings.insert(grant_id.to_owned(), binding);
        }
        if !existed {
            let parent = path
                .parent()
                .ok_or("grant journal parent directory is unavailable")?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "grant journal directory could not be synchronized")?;
        }
        self.revision = Some(JournalRevision::from_file(&file)?);
        Ok(())
    }

    fn prune(&mut self, authenticated_time_ms: u64) -> Result<(), &'static str> {
        let path = self
            .path
            .clone()
            .ok_or("grant journal path is unavailable")?;
        let _lock = lock_consumption_journal(&path)?;
        self.synchronize()?;
        let pruned = self
            .consumed
            .iter()
            .filter(|(_, expires_at)| {
                expires_at
                    .checked_add(GRANT_REPLAY_RETENTION_MS)
                    .is_none_or(|retain_until| retain_until > authenticated_time_ms)
            })
            .map(|(id, expires_at)| (id.clone(), *expires_at))
            .collect::<BTreeMap<_, _>>();
        if pruned.len() == self.consumed.len() {
            return Ok(());
        }
        let mut history = self.history.clone();
        if let Some(history) = &mut history {
            let boundary = self
                .consumed
                .iter()
                .filter(|(id, _)| !pruned.contains_key(*id))
                .map(|(_, expiry)| *expiry)
                .max()
                .unwrap_or(0);
            history.pruned_through_ms = history.pruned_through_ms.max(boundary);
        }
        self.rewrite(&pruned, history.as_ref())?;
        self.history = history;
        self.consumed = pruned;
        self.bindings.retain(|id, _| self.consumed.contains_key(id));
        self.revision = Some(JournalRevision::from_file(
            &open_private_for_recovery(&path).map_err(|_| "grant history is unavailable")?,
        )?);
        Ok(())
    }

    fn rewrite(
        &self,
        records: &BTreeMap<String, u64>,
        history: Option<&ConsumptionHistory>,
    ) -> Result<(), &'static str> {
        let header_line = history.map(ConsumptionHistory::line).transpose()?;
        let path = self
            .path
            .as_ref()
            .ok_or("grant journal path is unavailable")?;
        let parent = path
            .parent()
            .ok_or("grant journal parent directory is unavailable")?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".consumed-grants-{}-{sequence}.tmp", process_id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(NO_FOLLOW)
            .open(&temp)
            .map_err(|_| "grant journal compaction file could not be created")?;
        let mut written = 0_u64;
        if let Some(line) = header_line {
            if file.write_all(line.as_bytes()).is_err() {
                let _ = fs::remove_file(&temp);
                return Err("grant journal history could not be written");
            }
            written = line.len() as u64;
        }
        for (id, expires_at) in records {
            let line = consumption_line(id, *expires_at, self.bindings.get(id));
            written = written.saturating_add(line.len() as u64);
            if written > GRANT_JOURNAL_MAX_BYTES {
                let _ = fs::remove_file(&temp);
                return Err("grant journal compaction exceeds its size bound");
            }
            if file.write_all(line.as_bytes()).is_err() {
                let _ = fs::remove_file(&temp);
                return Err("grant journal compaction could not be written");
            }
        }
        if file.sync_all().is_err() || fs::rename(&temp, path).is_err() {
            let _ = fs::remove_file(&temp);
            return Err("grant journal compaction could not be committed");
        }
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "grant journal directory could not be synchronized")?;
        Ok(())
    }
}

impl RevocationJournal {
    fn open(path: &Path) -> Result<Self, &'static str> {
        let mut journal = Self {
            path: Some(path.to_owned()),
            acknowledged_path: Some(path.with_extension("acks")),
            ..Self::default()
        };
        let mut file = match open_private_for_recovery(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                journal.read_acknowledgements()?;
                return Ok(journal);
            }
            Err(_) => return Err("grant revocation journal could not be opened safely"),
        };
        let metadata = file
            .metadata()
            .map_err(|_| "grant revocation journal metadata is unavailable")?;
        if metadata.len() > GRANT_JOURNAL_MAX_BYTES {
            return Err("grant revocation journal exceeds its configured size bound");
        }
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut contents)
            .map_err(|_| "grant revocation journal could not be read")?;
        truncate_torn_tail(&file, &mut contents)
            .map_err(|_| "grant revocation journal torn record could not be truncated")?;
        for line in contents
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let (id, retain_until, outcome) = parse_revocation_line(line)?;
            journal
                .tombstones
                .entry(id.to_owned())
                .and_modify(|previous| *previous = (*previous).max(retain_until))
                .or_insert(retain_until);
            if let Some(outcome) = outcome {
                journal.outcomes.entry(id.to_owned()).or_insert(outcome);
            }
        }
        if journal.tombstones.len() > GRANT_JOURNAL_MAX_RECORDS {
            return Err("grant revocation journal exceeds its record bound");
        }
        journal.read_acknowledgements()?;
        Ok(journal)
    }

    fn read_acknowledgements(&mut self) -> Result<(), &'static str> {
        let path = self
            .acknowledged_path
            .as_ref()
            .ok_or("grant revocation acknowledgement path is unavailable")?;
        let mut file = match open_private_for_recovery(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("grant revocation acknowledgements could not be opened safely"),
        };
        let metadata = file
            .metadata()
            .map_err(|_| "grant revocation acknowledgement metadata is unavailable")?;
        if metadata.len() > GRANT_JOURNAL_MAX_BYTES {
            return Err("grant revocation acknowledgements exceed their size bound");
        }
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut contents)
            .map_err(|_| "grant revocation acknowledgements could not be read")?;
        truncate_torn_tail(&file, &mut contents)
            .map_err(|_| "grant revocation acknowledgement torn record could not be truncated")?;
        for line in contents
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let (id, _, outcome) = parse_revocation_line(line)?;
            if outcome.is_some() {
                return Err("grant revocation acknowledgement is malformed");
            }
            if self.outcomes.contains_key(id) {
                self.acknowledged_outcomes.insert(id.to_owned());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn contains_at(&self, grant_id: &str, controller_time_ms: u64) -> bool {
        self.tombstones
            .get(grant_id)
            .is_some_and(|retain_until| *retain_until > controller_time_ms)
    }

    /// Apply a tombstone in memory first, then make it durable. A failed
    /// write leaves the tombstone in force and marks it unpersisted so the
    /// caller can fence the broker and a later attempt can retry the write.
    fn record(
        &mut self,
        grant_id: &str,
        retain_until_ms: u64,
        outcome: Option<(&'static str, u64)>,
    ) -> Result<(), &'static str> {
        let raises_retention = self
            .tombstones
            .get(grant_id)
            .is_none_or(|existing| *existing < retain_until_ms);
        if !raises_retention && !self.unpersisted.contains(grant_id) {
            return Ok(());
        }
        if !self.tombstones.contains_key(grant_id)
            && let Some(outcome) = outcome
        {
            self.outcomes.insert(grant_id.to_owned(), outcome);
        }
        if raises_retention {
            self.tombstones.insert(grant_id.to_owned(), retain_until_ms);
        }
        self.unpersisted.insert(grant_id.to_owned());
        self.append(grant_id)?;
        self.unpersisted.remove(grant_id);
        Ok(())
    }

    fn has_unpersisted(&self) -> bool {
        !self.unpersisted.is_empty()
    }

    fn acknowledge_outcome(&mut self, grant_id: &str) -> Result<(), &'static str> {
        if !self.outcomes.contains_key(grant_id) || self.acknowledged_outcomes.contains(grant_id) {
            return Ok(());
        }
        if let Some(path) = self.acknowledged_path.as_ref() {
            let retain_until_ms = *self
                .tombstones
                .get(grant_id)
                .ok_or("grant revocation tombstone is unavailable")?;
            let line = revocation_line(grant_id, retain_until_ms, None);
            let existed = match fs::symlink_metadata(path) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(_) => return Err("grant revocation acknowledgements could not be inspected"),
            };
            let mut file = open_private(path, true)
                .map_err(|_| "grant revocation acknowledgements could not be opened")?;
            let length = file
                .metadata()
                .map_err(|_| "grant revocation acknowledgement metadata is unavailable")?
                .len();
            if length.saturating_add(line.len() as u64) > GRANT_JOURNAL_MAX_BYTES {
                return Err("grant revocation acknowledgements are full");
            }
            if file
                .write_all(line.as_bytes())
                .and_then(|()| file.sync_all())
                .is_err()
            {
                let _ = file.set_len(length).and_then(|()| file.sync_all());
                return Err("grant revocation acknowledgement could not be flushed");
            }
            if !existed {
                let parent = path
                    .parent()
                    .ok_or("grant revocation acknowledgement directory is unavailable")?;
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(
                        |_| "grant revocation acknowledgement directory could not be synchronized",
                    )?;
            }
        }
        self.acknowledged_outcomes.insert(grant_id.to_owned());
        Ok(())
    }

    fn retry_unpersisted(&mut self) -> Result<(), &'static str> {
        for grant_id in self.unpersisted.clone() {
            self.append(&grant_id)?;
            self.unpersisted.remove(&grant_id);
        }
        Ok(())
    }

    fn append(&self, grant_id: &str) -> Result<(), &'static str> {
        let retain_until_ms = *self
            .tombstones
            .get(grant_id)
            .ok_or("grant revocation tombstone is unavailable")?;
        if self.tombstones.len() > GRANT_JOURNAL_MAX_RECORDS {
            return Err("grant revocation journal is full; tombstone is not durable");
        }
        let path = self
            .path
            .as_ref()
            .ok_or("grant revocation journal path is unavailable")?;
        let line = revocation_line(
            grant_id,
            retain_until_ms,
            self.outcomes.get(grant_id).copied(),
        );
        let existed = match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err("grant revocation journal could not be inspected safely"),
        };
        let mut file = open_private(path, true)
            .map_err(|_| "grant revocation journal could not be opened for append")?;
        let length = file
            .metadata()
            .map_err(|_| "grant revocation journal metadata is unavailable")?
            .len();
        if length.saturating_add(line.len() as u64) > GRANT_JOURNAL_MAX_BYTES {
            return Err("grant revocation journal is full; tombstone is not durable");
        }
        if file
            .write_all(line.as_bytes())
            .and_then(|()| file.sync_all())
            .is_err()
        {
            let _ = file.set_len(length).and_then(|()| file.sync_all());
            return Err("grant revocation tombstone could not be flushed");
        }
        if !existed {
            let parent = path
                .parent()
                .ok_or("grant revocation journal parent directory is unavailable")?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "grant revocation journal directory could not be synchronized")?;
        }
        Ok(())
    }

    fn prune(&mut self, authenticated_time_ms: u64) -> Result<(), &'static str> {
        let pruned = self
            .tombstones
            .iter()
            .filter(|(_, retain_until)| **retain_until > authenticated_time_ms)
            .map(|(id, retain_until)| (id.clone(), *retain_until))
            .collect::<BTreeMap<_, _>>();
        if pruned.len() == self.tombstones.len() {
            return Ok(());
        }
        self.compact_acknowledgements(&pruned)?;
        let path = self
            .path
            .as_ref()
            .ok_or("grant revocation journal path is unavailable")?;
        let parent = path
            .parent()
            .ok_or("grant revocation journal parent directory is unavailable")?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".revoked-grants-{}-{sequence}.tmp", process_id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(NO_FOLLOW)
            .open(&temp)
            .map_err(|_| "grant revocation compaction file could not be created")?;
        for (id, retain_until) in &pruned {
            let line = revocation_line(id, *retain_until, self.outcomes.get(id).copied());
            if file.write_all(line.as_bytes()).is_err() {
                let _ = fs::remove_file(&temp);
                return Err("grant revocation compaction could not be written");
            }
        }
        if file.sync_all().is_err() || fs::rename(&temp, path).is_err() {
            let _ = fs::remove_file(&temp);
            return Err("grant revocation compaction could not be committed");
        }
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "grant revocation directory could not be synchronized")?;
        // The compacted file holds every retained tombstone, including any
        // whose earlier append failed.
        self.unpersisted.clear();
        self.outcomes.retain(|id, _| pruned.contains_key(id));
        self.acknowledged_outcomes
            .retain(|id| pruned.contains_key(id));
        self.tombstones = pruned;
        Ok(())
    }

    fn compact_acknowledgements(
        &self,
        retained: &BTreeMap<String, u64>,
    ) -> Result<(), &'static str> {
        let Some(path) = self.acknowledged_path.as_ref() else {
            return Ok(());
        };
        if self.acknowledged_outcomes.is_empty() && !path.exists() {
            return Ok(());
        }
        let parent = path
            .parent()
            .ok_or("grant revocation acknowledgement directory is unavailable")?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".revocation-acks-{}-{sequence}.tmp", process_id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(NO_FOLLOW)
            .open(&temp)
            .map_err(|_| "grant revocation acknowledgement compaction could not start")?;
        for id in &self.acknowledged_outcomes {
            if let Some(retain_until_ms) = retained.get(id) {
                let line = revocation_line(id, *retain_until_ms, None);
                if file.write_all(line.as_bytes()).is_err() {
                    let _ = fs::remove_file(&temp);
                    return Err("grant revocation acknowledgement compaction could not be written");
                }
            }
        }
        if file.sync_all().is_err() || fs::rename(&temp, path).is_err() {
            let _ = fs::remove_file(&temp);
            return Err("grant revocation acknowledgement compaction could not be committed");
        }
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "grant revocation acknowledgement directory could not be synchronized")
    }
}

fn read_trusted_time(path: &Path) -> Result<Option<u64>, &'static str> {
    let mut file = match open_private(path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("trusted controller time could not be read safely"),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "trusted controller time metadata is unavailable")?;
    if metadata.len() == 0 || metadata.len() > 32 {
        return Err("trusted controller time file has an invalid size");
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut contents)
        .map_err(|_| "trusted controller time could not be read")?;
    let text =
        std::str::from_utf8(&contents).map_err(|_| "trusted controller time file is malformed")?;
    let value = text
        .strip_suffix('\n')
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0 && format!("{value}\n") == text)
        .ok_or("trusted controller time file is malformed")?;
    Ok(Some(value))
}

fn write_trusted_time(path: &Path, value: u64) -> Result<(), &'static str> {
    let parent = path
        .parent()
        .ok_or("trusted controller time directory is unavailable")?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".trusted-time-{}-{sequence}.tmp", process_id()));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(NO_FOLLOW)
            .open(&temp)?;
        writeln!(file, "{value}")?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
        return Err("trusted controller time could not be persisted");
    }
    Ok(())
}

fn open_private(path: &Path, append: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(append)
        .append(append)
        .create(append);
    options.mode(PRIVATE_FILE_MODE).custom_flags(NO_FOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "grant journal file ownership or mode is unsafe",
        ));
    }
    Ok(file)
}

/// Open an existing journal for startup reading and torn-tail repair. It
/// never creates the file and applies the same ownership and mode checks.
fn open_private_for_recovery(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(NO_FOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "grant journal file ownership or mode is unsafe",
        ));
    }
    Ok(file)
}

/// Every journal record is appended as one line and fsynced before the
/// caller may act on it. A final line without its newline is therefore an
/// append that never became durable, so its effect never ran: cut it off and
/// fsync so later appends start on a record boundary. Complete lines are
/// still parsed strictly by the caller and fail closed when corrupt.
fn truncate_torn_tail(file: &File, contents: &mut Vec<u8>) -> std::io::Result<()> {
    if contents.is_empty() || contents.last() == Some(&b'\n') {
        return Ok(());
    }
    let keep = contents
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    file.set_len(keep as u64)?;
    file.sync_all()?;
    contents.truncate(keep);
    Ok(())
}

fn consumption_line(
    grant_id: &str,
    expires_at_ms: u64,
    binding: Option<&ConsumedBinding>,
) -> String {
    let correlation = binding.map_or(String::new(), |binding| {
        format!(
            ",\"operation_id\":\"{}\",\"issuer_epoch\":{}",
            binding.operation_id, binding.issuer_epoch,
        )
    });
    format!("{{\"grant_id\":\"{grant_id}\",\"expires_at_ms\":{expires_at_ms}{correlation}}}\n")
}

type ParsedConsumption<'a> = (&'a str, u64, Option<ConsumedBinding>);

fn parse_journal_line(line: &[u8]) -> Result<ParsedConsumption<'_>, &'static str> {
    let text = std::str::from_utf8(line).map_err(|_| "grant journal is not UTF-8")?;
    let value = text
        .strip_prefix("{\"grant_id\":\"")
        .and_then(|value| value.strip_suffix('}'))
        .ok_or("grant journal record is malformed")?;
    let (id, expiry) = value
        .split_once("\",\"expires_at_ms\":")
        .ok_or("grant journal record is malformed")?;
    if !is_valid_opaque_id(id) {
        return Err("grant journal id is malformed");
    }
    let (expiry, binding) = match expiry.split_once(",\"operation_id\":\"") {
        Some((expiry, correlation)) => {
            let (operation_id, epoch) = correlation
                .split_once("\",\"issuer_epoch\":")
                .ok_or("grant journal correlation is malformed")?;
            if !is_valid_opaque_id(operation_id) {
                return Err("grant journal correlation is malformed");
            }
            let issuer_epoch = epoch
                .parse::<u64>()
                .ok()
                .filter(|value| {
                    (1..=9_007_199_254_740_991).contains(value) && value.to_string() == epoch
                })
                .ok_or("grant journal epoch is malformed")?;
            (
                expiry,
                Some(ConsumedBinding {
                    operation_id: operation_id.into(),
                    issuer_epoch,
                }),
            )
        }
        None => (expiry, None),
    };
    let expiry = expiry
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == expiry)
        .ok_or("grant journal expiry is malformed")?;
    Ok((id, expiry, binding))
}

fn revocation_line(grant_id: &str, retain_until_ms: u64, outcome: Option<(&str, u64)>) -> String {
    let outcome_field = outcome.map_or(String::new(), |(outcome, observed_at_ms)| {
        format!(",\"outcome\":\"{outcome}\",\"observed_at_ms\":{observed_at_ms}")
    });
    format!(
        "{{\"grant_id\":\"{grant_id}\",\"retain_until_ms\":{retain_until_ms}{outcome_field}}}\n"
    )
}

type ParsedRevocation<'a> = (&'a str, u64, Option<(&'static str, u64)>);

fn parse_revocation_line(line: &[u8]) -> Result<ParsedRevocation<'_>, &'static str> {
    let text = std::str::from_utf8(line).map_err(|_| "grant revocation journal is not UTF-8")?;
    let value = text
        .strip_prefix("{\"grant_id\":\"")
        .and_then(|value| value.strip_suffix('}'))
        .ok_or("grant revocation record is malformed")?;
    let (id, retain_until) = value
        .split_once("\",\"retain_until_ms\":")
        .ok_or("grant revocation record is malformed")?;
    if !is_valid_opaque_id(id) {
        return Err("grant revocation id is malformed");
    }
    let (retain_until, outcome) = match retain_until.split_once(",\"outcome\":\"") {
        Some((retain_until, outcome)) => {
            let (outcome, observed_at_ms) = outcome
                .split_once("\",\"observed_at_ms\":")
                .ok_or("grant revocation observation is malformed")?;
            let observed_at_ms = observed_at_ms
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0 && value.to_string() == observed_at_ms)
                .ok_or("grant revocation observation is malformed")?;
            let outcome = match outcome {
                "revoked_before_consumption" => "revoked_before_consumption",
                "already_consumed" => "already_consumed",
                "not_received" => "not_received",
                _ => return Err("grant revocation outcome is malformed"),
            };
            (retain_until, Some((outcome, observed_at_ms)))
        }
        None => (retain_until, None),
    };
    let retain_until = retain_until
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == retain_until)
        .ok_or("grant revocation retention is malformed")?;
    Ok((id, retain_until, outcome))
}

pub(crate) fn boottime_ms() -> Result<u64, &'static str> {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock_id: i32, value: *mut Timespec) -> i32;
    }
    const CLOCK_BOOTTIME: i32 = 7;
    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: clock_gettime writes one timespec to the valid stack pointer.
    if unsafe { clock_gettime(CLOCK_BOOTTIME, &mut time) } != 0
        || time.seconds < 0
        || !(0..1_000_000_000).contains(&time.nanoseconds)
    {
        return Err("suspend-aware boottime clock is unavailable");
    }
    u64::try_from(time.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|milliseconds| milliseconds.checked_add((time.nanoseconds / 1_000_000) as u64))
        .ok_or("suspend-aware boottime clock overflow")
}

fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no arguments and returns the current effective UID.
    unsafe { geteuid() }
}

fn process_id() -> u32 {
    unsafe extern "C" {
        fn getpid() -> i32;
    }
    // SAFETY: getpid has no arguments and returns the current process ID.
    unsafe { getpid() as u32 }
}

#[cfg(test)]
mod tests {
    use super::{ConsumeDenial, GrantJournal, GrantVerifier, RevocationJournal};
    use blindpass_core::fleet::{ConsumptionMode, Grant, PolicySnapshot, Registration, TimeReply};
    use blindpass_core::identity::WorkloadAuthorization;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("blindpass-grants-{}-{nonce}", process_id()));
        std::fs::create_dir(&dir).unwrap();
        dir.join("consumed.jsonl")
    }

    fn process_id() -> u32 {
        unsafe extern "C" {
            fn getpid() -> i32;
        }
        // SAFETY: getpid has no arguments and returns the current process ID.
        unsafe { getpid() as u32 }
    }

    fn grant() -> Grant {
        Grant {
            id: "gr_0123456789abcdef0123456789abcdef".to_owned(),
            operation_id: "op_0123456789abcdef0123456789abcdef".to_owned(),
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            invocation_id: "invocation-a".to_owned(),
            unit: "worker.service".to_owned(),
            account: "worker".to_owned(),
            resource_id: "marker-a".to_owned(),
            recipient_key_id: "nd_node-a-1".to_owned(),
            registration_version: 1,
            policy_version: 4,
            approval_reference: None,
            request_event_key: None,
            action: "noop.marker".to_owned(),
            mode: ConsumptionMode::File,
            audience: "blindpass-node".to_owned(),
            issuer_epoch: 1,
            issued_at_ms: 1_800_000_000_000,
            expires_at_ms: 1_800_000_060_000,
            local_ceiling_seconds: 60,
        }
    }

    fn registration() -> Registration {
        Registration {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            unit: "worker.service".to_owned(),
            account: "worker".to_owned(),
            invocation_id: None,
            status: "active".to_owned(),
            consumption_mode: ConsumptionMode::File,
            registration_version: 1,
            policy_version: 4,
            local_ceiling_seconds: 60,
        }
    }

    fn policy() -> PolicySnapshot {
        PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        }
    }

    fn verifier(path: &std::path::Path, started_at: u64) -> GrantVerifier {
        let mut verifier = GrantVerifier {
            journal: Some(GrantJournal::open(path).unwrap()),
            issuer_epoch: Some(1),
            ..GrantVerifier::default()
        };
        verifier.pending_time = Some(super::TimeChallenge {
            value: "challenge-a".to_owned(),
            sent_at_boottime_ms: started_at,
        });
        verifier
    }

    #[test]
    fn signed_time_reply_counts_unaccounted_round_trip_as_elapsed_controller_time() {
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        // The controller held the long poll for 2,000 ms before stamping the
        // reply; only the remaining 1,000 ms of the 3,000 ms round trip can
        // have elapsed after the stamp.
        let reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: 1_799_999_998_000,
            controller_time_ms: 1_800_000_000_000,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&reply, "nd_node-a", 1, 4_000)
            .unwrap();
        assert_eq!(
            verifier.trusted_controller_time_ms(4_000),
            Some(reply.controller_time_ms + 1_000)
        );
        assert_eq!(
            verifier.trusted_controller_time_ms(5_000),
            Some(reply.controller_time_ms + 2_000)
        );
        assert_eq!(
            verifier.highest_controller_time_ms,
            Some(reply.controller_time_ms)
        );
        assert!(verifier.pending_time.is_none());
        assert!(
            verifier
                .accept_time_reply(&reply, "nd_node-a", 1, 4_100)
                .is_err()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn relay_held_time_reply_cannot_extend_an_expired_grant() {
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        // The controller answered immediately; the relay then held the signed
        // reply for 34,000 ms before handing it to the broker.
        let stamped_at = 1_800_000_000_000;
        let reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: stamped_at,
            controller_time_ms: stamped_at,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&reply, "nd_node-a", 1, 35_000)
            .unwrap();
        assert_eq!(
            verifier.trusted_controller_time_ms(35_000),
            Some(stamped_at + 34_000)
        );
        let mut grant = grant();
        grant.issued_at_ms = stamped_at - 1_000;
        grant.expires_at_ms = stamped_at + 20_000;
        let error = verifier
            .accept_grant(
                grant,
                b"grant",
                "nd_node-a",
                "nd_node-a-1",
                &policy(),
                &registration(),
                35_000,
            )
            .unwrap_err();
        assert_eq!(error, "grant expired before broker receipt");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_live_grant_stops_authorizing_once_signed_time_is_older_than_its_bound() {
        // Proposed P03-D12: consumption needs signed controller time no older
        // than MAX_TIME_REPLY_DELAY_MS, so an outage longer than that denies a
        // grant whose local deadline has not passed (trusted_time_unavailable).
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        let stamped_at = 1_800_000_000_000;
        let reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: stamped_at,
            controller_time_ms: stamped_at,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&reply, "nd_node-a", 1, 2_000)
            .unwrap();
        let mut grant = grant();
        grant.issued_at_ms = stamped_at;
        grant.expires_at_ms = stamped_at + 600_000;
        assert!(
            verifier
                .accept_grant(
                    grant,
                    b"grant",
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy(),
                    &registration(),
                    2_000,
                )
                .unwrap()
        );
        let deadline = verifier
            .accepted
            .values()
            .next()
            .unwrap()
            .deadline_boottime_ms;
        let bound_end = 2_000 + super::MAX_TIME_REPLY_DELAY_MS;
        assert!(
            deadline > bound_end + 1,
            "the local deadline is still ahead"
        );
        assert!(verifier.trusted_controller_time_ms(bound_end).is_some());
        assert!(verifier.trusted_controller_time_ms(bound_end + 1).is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persisted_time_high_water_rejects_controller_rollback_after_restart() {
        let journal_path = temporary_path();
        let time_path = journal_path.parent().unwrap().join("trusted-time");
        let revocation_path = journal_path.parent().unwrap().join("revoked-grants.jsonl");
        let mut verifier =
            GrantVerifier::with_state_files(&journal_path, &time_path, &revocation_path).unwrap();
        verifier.pending_time = Some(super::TimeChallenge {
            value: "challenge-new".to_owned(),
            sent_at_boottime_ms: 1_000,
        });
        let reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-new".to_owned(),
            challenge_received_at_ms: 1_800_000_000_000,
            controller_time_ms: 1_800_000_000_000,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&reply, "nd_node-a", 1, 2_000)
            .unwrap();

        let mut restarted =
            GrantVerifier::with_state_files(&journal_path, &time_path, &revocation_path).unwrap();
        restarted.pending_time = Some(super::TimeChallenge {
            value: "challenge-after-restart".to_owned(),
            sent_at_boottime_ms: 5_000,
        });
        let rolled_back = TimeReply {
            challenge: "challenge-after-restart".to_owned(),
            challenge_received_at_ms: 1_799_999_000_000,
            controller_time_ms: 1_799_999_000_000,
            ..reply
        };
        assert!(
            restarted
                .accept_time_reply(&rolled_back, "nd_node-a", 1, 6_000)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(journal_path.parent().unwrap());
    }

    #[test]
    fn grants_need_fresh_time_and_are_bound_to_the_current_workload_policy() {
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        let reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: 1_800_000_000_000,
            controller_time_ms: 1_800_000_000_000,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&reply, "nd_node-a", 1, 2_000)
            .unwrap();
        let policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        let grant = grant();
        assert!(
            verifier
                .accept_grant(
                    grant.clone(),
                    b"signed-grant",
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy,
                    &registration(),
                    2_100,
                )
                .unwrap()
        );
        assert!(
            verifier
                .accept_grant(
                    grant.clone(),
                    b"signed-grant",
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy,
                    &registration(),
                    2_200,
                )
                .is_ok_and(|inserted| !inserted)
        );
        let authorization = WorkloadAuthorization {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            unit: "worker.service".to_owned(),
            invocation_id: "invocation-a".to_owned(),
            operation: format!("consume:{}", grant.id),
        };
        let mut wrong_node = authorization.clone();
        wrong_node.node_id = "nd_node-b".to_owned();
        assert!(verifier.consume(&grant.id, &wrong_node, 4, 2_300).is_err());
        let mut wrong_workload = authorization.clone();
        wrong_workload.workload_id = "wl_worker-b".to_owned();
        assert!(
            verifier
                .consume(&grant.id, &wrong_workload, 4, 2_300)
                .is_err()
        );
        let mut wrong_unit = authorization.clone();
        wrong_unit.unit = "other.service".to_owned();
        assert!(verifier.consume(&grant.id, &wrong_unit, 4, 2_300).is_err());
        let mut wrong_invocation = authorization.clone();
        wrong_invocation.invocation_id = "invocation-old".to_owned();
        assert!(
            verifier
                .consume(&grant.id, &wrong_invocation, 4, 2_300)
                .is_err()
        );
        let mut wrong_operation = authorization.clone();
        wrong_operation.operation = "consume:other-grant".to_owned();
        assert!(
            verifier
                .consume(&grant.id, &wrong_operation, 4, 2_300)
                .is_err()
        );
        assert!(
            verifier
                .consume(&grant.id, &authorization, 3, 2_300)
                .is_err()
        );
        verifier
            .consume(&grant.id, &authorization, 4, 2_300)
            .unwrap();
        assert!(
            verifier
                .consume(&grant.id, &authorization, 4, 2_301)
                .is_err()
        );
        let restored = GrantJournal::open(&path).unwrap();
        assert!(restored.consumed.contains_key(&grant.id));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn delayed_grant_receipt_uses_remaining_lifetime_and_boottime_deadline() {
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        let base_controller_time = 1_800_000_000_000;
        // The controller held the 1,000 ms round trip for its whole length,
        // so no unaccounted delay is added to the signed time.
        let time_reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: base_controller_time - 1_000,
            controller_time_ms: base_controller_time,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&time_reply, "nd_node-a", 1, 2_000)
            .unwrap();
        let policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        let grant = grant();

        // Receive the signed grant 20 seconds after the time sample. The
        // broker must retain only the remaining 40 seconds. Advancing the
        // supplied BOOTTIME value below also models time spent suspended.
        assert!(
            verifier
                .accept_grant(
                    grant.clone(),
                    b"signed-delayed-grant",
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy,
                    &registration(),
                    22_000,
                )
                .unwrap()
        );
        assert_eq!(verifier.accepted[&grant.id].deadline_boottime_ms, 62_000);
        let authorization = WorkloadAuthorization {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            unit: "worker.service".to_owned(),
            invocation_id: "invocation-a".to_owned(),
            operation: format!("consume:{}", grant.id),
        };
        assert!(
            verifier
                .preview_consumption(&grant.id, &authorization, 4, 61_999)
                .is_ok()
        );
        assert!(
            verifier
                .preview_consumption(&grant.id, &authorization, 4, 62_000)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn receipt_rejects_grants_delayed_past_expiry_or_document_age() {
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        let issued_at_ms = 1_800_000_000_000;
        let time_reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: issued_at_ms + 60_001,
            controller_time_ms: issued_at_ms + 60_001,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&time_reply, "nd_node-a", 1, 2_000)
            .unwrap();
        let policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        let mut expired = grant();
        expired.expires_at_ms = issued_at_ms + 60_000;
        assert_eq!(
            verifier.accept_grant(
                expired,
                b"signed-expired-grant",
                "nd_node-a",
                "nd_node-a-1",
                &policy,
                &registration(),
                2_100,
            ),
            Err("grant expired before broker receipt")
        );

        let mut stale = grant();
        stale.expires_at_ms = issued_at_ms + 600_000;
        assert_eq!(
            verifier.accept_grant(
                stale,
                b"signed-stale-grant",
                "nd_node-a",
                "nd_node-a-1",
                &policy,
                &registration(),
                2_100,
            ),
            Err("grant is stale or exceeds the broker lifetime maximum")
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A verifier with fresh signed time where controller time equals
    /// `1_800_000_000_000` at boottime 2_000 and the grant fixtures are fresh.
    fn verifier_with_fresh_time(path: &std::path::Path) -> GrantVerifier {
        let mut verifier = verifier(path, 1_000);
        let reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: 1_799_999_999_000,
            controller_time_ms: 1_800_000_000_000,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&reply, "nd_node-a", 1, 2_000)
            .unwrap();
        verifier
    }

    #[test]
    fn grant_deadline_is_clamped_by_the_smallest_local_ceiling() {
        let path = temporary_path();
        let mut verifier = verifier_with_fresh_time(&path);
        // 10 minutes of signed lifetime remain; every ceiling is shorter.
        let mut grant = grant();
        grant.expires_at_ms = grant.issued_at_ms + 600_000;
        grant.local_ceiling_seconds = 20;
        let mut policy = policy();
        policy.local_ceiling_seconds = 30;
        let mut registration = registration();
        registration.local_ceiling_seconds = 45;
        assert!(
            verifier
                .accept_grant(
                    grant.clone(),
                    b"clamped-by-grant",
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy,
                    &registration,
                    2_000,
                )
                .unwrap()
        );
        assert_eq!(verifier.accepted[&grant.id].deadline_boottime_ms, 22_000);

        // The policy and registration ceilings also bound the deadline on
        // their own; the grant ceiling can never exceed either of them.
        let mut second = grant.clone();
        second.id = "gr_1123456789abcdef0123456789abcdef".to_owned();
        second.local_ceiling_seconds = 30;
        policy.local_ceiling_seconds = 30;
        registration.local_ceiling_seconds = 30;
        verifier
            .accept_grant(
                second.clone(),
                b"clamped-by-all",
                "nd_node-a",
                "nd_node-a-1",
                &policy,
                &registration,
                2_000,
            )
            .unwrap();
        assert_eq!(verifier.accepted[&second.id].deadline_boottime_ms, 32_000);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn grant_acceptance_rejects_ceiling_lifetime_and_binding_violations() {
        let path = temporary_path();
        let mut verifier = verifier_with_fresh_time(&path);
        let policy = policy();
        let registration = registration();
        type Mutation = fn(&mut super::Grant, &mut PolicySnapshot, &mut Registration);
        let cases: [(&str, Mutation); 9] = [
            ("grant ceiling above policy ceiling", |grant, policy, _| {
                policy.local_ceiling_seconds = 30;
                grant.local_ceiling_seconds = 31;
            }),
            (
                "grant ceiling above registration ceiling",
                |grant, _, registration| {
                    registration.local_ceiling_seconds = 30;
                    grant.local_ceiling_seconds = 31;
                },
            ),
            (
                "lifetime above one hour with fresh issue time",
                |grant, _, _| {
                    grant.expires_at_ms = grant.issued_at_ms + 3_600_001;
                },
            ),
            ("grant bound to another node", |grant, _, registration| {
                grant.node_id = "nd_node-b".to_owned();
                registration.node_id = "nd_node-b".to_owned();
            }),
            ("recipient key mismatch", |grant, _, _| {
                grant.recipient_key_id = "nd_node-a-2".to_owned();
            }),
            ("action not in policy", |_, policy, _| {
                policy.allowed_actions = vec!["other.action".to_owned()];
            }),
            ("mode not in policy", |_, policy, _| {
                policy.allowed_modes = vec![ConsumptionMode::Socket];
            }),
            ("issued in the future", |grant, _, _| {
                grant.issued_at_ms = 1_800_000_005_000;
                grant.expires_at_ms = 1_800_000_065_000;
            }),
            ("policy version mismatch", |grant, _, _| {
                grant.policy_version = 5;
            }),
        ];
        for (label, mutate) in cases {
            let mut grant = grant();
            let mut policy = policy.clone();
            let mut registration = registration.clone();
            mutate(&mut grant, &mut policy, &mut registration);
            assert!(
                verifier
                    .accept_grant(
                        grant.clone(),
                        label.as_bytes(),
                        "nd_node-a",
                        "nd_node-a-1",
                        &policy,
                        &registration,
                        2_000,
                    )
                    .is_err(),
                "{label} must be rejected"
            );
            assert!(verifier.accepted.is_empty(), "{label} must not be accepted");
        }

        // The same grant id with different signed content is rejected, and
        // the first accepted binding is kept.
        let original = grant();
        verifier
            .accept_grant(
                original.clone(),
                b"original",
                "nd_node-a",
                "nd_node-a-1",
                &policy,
                &registration,
                2_000,
            )
            .unwrap();
        let mut changed = original.clone();
        changed.resource_id = "marker-other".to_owned();
        assert_eq!(
            verifier.accept_grant(
                changed,
                b"changed",
                "nd_node-a",
                "nd_node-a-1",
                &policy,
                &registration,
                2_000,
            ),
            Err("grant id was reused with different signed content")
        );
        assert_eq!(
            verifier.accept_grant(
                original.clone(),
                b"same-body-different-bytes",
                "nd_node-a",
                "nd_node-a-1",
                &policy,
                &registration,
                2_000,
            ),
            Err("grant id was reused with different signed content")
        );
        assert_eq!(verifier.accepted[&original.id].grant, original);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    fn stateful_verifier_with_fresh_time(path: &std::path::Path) -> GrantVerifier {
        let directory = path.parent().unwrap();
        let mut verifier = GrantVerifier::with_state_files(
            path,
            &directory.join("trusted-time"),
            &directory.join("revoked-grants.jsonl"),
        )
        .unwrap();
        verifier.observe_issuer_epoch(1);
        verifier.pending_time = Some(super::TimeChallenge {
            value: "challenge-a".to_owned(),
            sent_at_boottime_ms: 1_000,
        });
        verifier
            .accept_time_reply(
                &TimeReply {
                    node_id: "nd_node-a".to_owned(),
                    challenge: "challenge-a".to_owned(),
                    challenge_received_at_ms: 1_799_999_999_000,
                    controller_time_ms: 1_800_000_000_000,
                    issuer_epoch: 1,
                },
                "nd_node-a",
                1,
                2_000,
            )
            .unwrap();
        verifier
    }

    fn numbered_grant(index: u8) -> Grant {
        let mut grant = grant();
        grant.id = format!("gr_{index:02}23456789abcdef0123456789abcdef");
        grant.operation_id = format!("op_{index:02}23456789abcdef0123456789abcdef");
        grant
    }

    fn accept(verifier: &mut GrantVerifier, grant: &Grant) {
        verifier
            .accept_grant(
                grant.clone(),
                grant.id.as_bytes(),
                "nd_node-a",
                "nd_node-a-1",
                &policy(),
                &registration(),
                2_000,
            )
            .unwrap();
    }

    struct ConsumptionJournalDirectory(PathBuf);

    impl ConsumptionJournalDirectory {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("blindpass-p06-cj-{}-{nonce}", process_id()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for ConsumptionJournalDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn history_pin(epoch: u64) -> crate::keys::PinnedIssuer {
        let public_key = blindpass_core::signing::base64_url_encode(&[9; 32]);
        crate::keys::PinnedIssuer {
            tenant_id: "tenant-a".into(),
            node_id: "nd_node-a".into(),
            epoch,
            key_id: format!("ed25519-{public_key}"),
            public_key,
        }
    }

    #[test]
    fn p06_br01_actual_consume_refreshes_first_pin_and_reopens_original_correlation() {
        let fixture = ConsumptionJournalDirectory::new();
        let identity = crate::keys::NodeIdentity::load_or_create(&fixture.0).unwrap();
        let path = identity.consumed_grant_journal_path();
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        // Match the real first-enrollment ordering: verifier before pinning.
        identity.pin_issuer(history_pin(1)).unwrap();
        let grant = grant();
        accept(&mut verifier, &grant);
        verifier
            .consume(&grant.id, &authorization_for(&grant), 4, 2_200)
            .unwrap();
        let reopened = GrantJournal::open(&path).unwrap();
        let history = reopened.history.unwrap();
        assert_eq!(history.tenant_id, "tenant-a");
        assert_eq!(history.node_id, grant.node_id);
        assert_eq!(history.highest_issuer_epoch, 1);
        assert_eq!(
            reopened.bindings[&grant.id].operation_id,
            grant.operation_id
        );
        assert_eq!(reopened.bindings[&grant.id].issuer_epoch, 1);
        assert_eq!(
            verifier.consume(&grant.id, &authorization_for(&grant), 4, 2_200),
            Err(ConsumeDenial::Consumed)
        );
    }

    #[test]
    fn p06_br04_existing_verifier_cannot_consume_after_durable_pin_advances() {
        let fixture = ConsumptionJournalDirectory::new();
        let identity = crate::keys::NodeIdentity::load_or_create(&fixture.0).unwrap();
        identity.pin_issuer(history_pin(1)).unwrap();
        let path = identity.consumed_grant_journal_path();
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        let grant = grant();
        accept(&mut verifier, &grant);
        // Real PIN_ISSUER publishes the identity pin before acquiring the
        // broker state mutex. An already opened verifier must honor it even
        // during that window, before its in-memory epoch is updated.
        identity.pin_issuer(history_pin(2)).unwrap();
        assert_eq!(
            verifier.consume(&grant.id, &authorization_for(&grant), 4, 2_200),
            Err(ConsumeDenial::Unavailable),
            "stale in-memory epoch authorized an effect after durable fencing"
        );
        assert!(GrantJournal::open(&path).unwrap().consumed.is_empty());
    }

    #[test]
    fn p06_br03_prune_all_retains_monotonic_coverage_and_trusted_epoch() {
        let fixture = ConsumptionJournalDirectory::new();
        let identity = crate::keys::NodeIdentity::load_or_create(&fixture.0).unwrap();
        identity.pin_issuer(history_pin(1)).unwrap();
        let path = identity.consumed_grant_journal_path();
        let mut journal = GrantJournal::open(&path).unwrap();
        let first = journal.history.clone().unwrap();
        let mut expired = grant();
        expired.expires_at_ms = 10;
        journal.record_bound_consumption(&expired).unwrap();
        // A restored controller can propose an epoch below this broker's
        // trusted high-watermark; journal compaction must never erase it.
        identity.pin_issuer(history_pin(7)).unwrap();
        journal
            .prune(super::GRANT_REPLAY_RETENTION_MS + 11)
            .unwrap();
        let mut reopened = GrantJournal::open(&path).unwrap();
        assert!(reopened.consumed.is_empty());
        let history = reopened.history.clone().unwrap();
        assert_eq!(history.history_id, first.history_id);
        assert_eq!(history.pruned_through_ms, 10);
        assert_eq!(history.highest_issuer_epoch, 7);
        reopened.prune(1).unwrap();
        assert_eq!(GrantJournal::open(&path).unwrap().history.unwrap(), history);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
    }

    #[test]
    fn p06_br04_different_tenant_node_or_issuer_cannot_rebind_known_history() {
        let fixture = ConsumptionJournalDirectory::new();
        let identity = crate::keys::NodeIdentity::load_or_create(&fixture.0).unwrap();
        let pin = history_pin(1);
        identity.pin_issuer(pin.clone()).unwrap();
        let before = std::fs::read(identity.consumed_grant_journal_path()).unwrap();
        for (tenant, node, key) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let mut changed = history_pin(2);
            if tenant {
                changed.tenant_id = "other-tenant".into();
            }
            if node {
                changed.node_id = "other-node".into();
            }
            if key {
                changed.public_key = blindpass_core::signing::base64_url_encode(&[10; 32]);
                changed.key_id = format!("ed25519-{}", changed.public_key);
            }
            assert!(identity.pin_issuer(changed).is_err());
            assert_eq!(identity.pinned_issuer().unwrap().as_ref(), Some(&pin));
            assert_eq!(
                std::fs::read(identity.consumed_grant_journal_path()).unwrap(),
                before
            );
        }
    }

    #[test]
    fn p06_br02_provenance_torn_duplicate_or_unbound_history_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = ConsumptionJournalDirectory::new();
        let identity = crate::keys::NodeIdentity::load_or_create(&fixture.0).unwrap();
        let path = identity.consumed_grant_journal_path();
        let genesis = std::fs::read_to_string(&path).unwrap();
        let bound_line = super::consumption_line(
            &grant().id,
            grant().expires_at_ms,
            Some(&super::ConsumedBinding {
                operation_id: grant().operation_id,
                issuer_epoch: 1,
            }),
        );
        for bad in [
            format!("{genesis}{genesis}"),
            format!("{genesis}{bound_line}"),
            // A header torn before its newline cannot claim any coverage.
            genesis.trim_end_matches('\n').to_owned(),
        ] {
            std::fs::write(&path, &bad).unwrap();
            assert!(GrantJournal::open(&path).is_err());
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                bad,
                "failed read altered evidence"
            );
        }
        // An unterminated record after a complete header was never fsynced, so
        // its effect never ran: only that tail is dropped, history is kept.
        std::fs::write(&path, format!("{genesis}{{\"grant_id\":\"torn")).unwrap();
        let reopened = GrantJournal::open(&path).unwrap();
        assert!(reopened.history.is_some());
        assert!(reopened.consumed.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), genesis);
        std::fs::write(&path, &genesis).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(GrantJournal::open(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hardlink = fixture.0.join("linked");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert!(GrantJournal::open(&path).is_err());
    }

    #[test]
    fn p06_br02_genesis_is_published_atomically_and_survives_a_stale_stage() {
        use std::os::unix::fs::MetadataExt;
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        // A crash while staging leaves a partial stage but never a final file.
        std::fs::write(fixture.0.join(".consumed-genesis.tmp"), b"{\"history_vers").unwrap();
        super::initialize_consumption_history(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\"history_version\":") && text.ends_with('\n'));
        assert_eq!(text.matches('\n').count(), 1);
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!((metadata.nlink(), metadata.mode() & 0o777), (1, 0o600));
        assert!(!fixture.0.join(".consumed-genesis.tmp").exists());
        assert!(super::initialize_consumption_history(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert!(GrantJournal::open(&path).unwrap().history.is_some());
    }

    #[test]
    fn p06_br02_a_rolled_back_journal_is_refused_while_legitimate_pruning_is_allowed() {
        use std::os::unix::fs::PermissionsExt;
        let replace = |path: &std::path::Path, text: &str| {
            std::fs::remove_file(path).unwrap();
            std::fs::write(path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        let fixture = ConsumptionJournalDirectory::new();
        let identity = crate::keys::NodeIdentity::load_or_create(&fixture.0).unwrap();
        identity.pin_issuer(history_pin(1)).unwrap();
        let path = identity.consumed_grant_journal_path();
        let bound = std::fs::read_to_string(&path).unwrap();
        let grant_with = |id: &str, expires_at_ms: u64| {
            let mut value = grant();
            value.id = id.to_owned();
            value.expires_at_ms = expires_at_ms;
            value
        };
        let first = grant_with("gr_1123456789abcdef0123456789abcdef", 10_000);
        let mut journal = GrantJournal::open(&path).unwrap();
        journal.record_bound_consumption(&first).unwrap();
        let longer = std::fs::read_to_string(&path).unwrap();
        // An older copy of the same history replaces the journal.
        replace(&path, &bound);
        let second = grant_with("gr_2123456789abcdef0123456789abcdef", 20_000);
        assert!(
            journal.record_bound_consumption(&second).is_err(),
            "a shrunken journal re-opened a consumed grant"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bound);
        // Restoring the longer file is accepted again; real pruning is not rollback.
        replace(&path, &longer);
        journal.record_bound_consumption(&second).unwrap();
        journal
            .prune(10_000 + super::GRANT_REPLAY_RETENTION_MS + 1)
            .unwrap();
        let third = grant_with("gr_3123456789abcdef0123456789abcdef", 30_000);
        journal.record_bound_consumption(&third).unwrap();
        assert!(journal.consumed.contains_key(&second.id));
        assert!(!journal.consumed.contains_key(&first.id));
    }

    #[test]
    fn p06_br02_legacy_rows_never_acquire_guessed_genesis_or_scope() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let original = super::consumption_line("legacy-grant", 1, None);
        std::fs::write(&path, &original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let identity = crate::keys::NodeIdentity::load_or_create(&fixture.0).unwrap();
        identity.pin_issuer(history_pin(1)).unwrap();
        let journal = GrantJournal::open(&path).unwrap();
        assert!(journal.history.is_none());
        assert!(journal.bindings.is_empty());
        assert!(journal.consumed.contains_key("legacy-grant"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn p06_br04_busy_or_unsafe_lock_denies_without_journal_changes() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let mut journal = GrantJournal::open(&path).unwrap();
        let held = super::lock_consumption_journal(&path).unwrap();
        assert!(journal.record_bound_consumption(&grant()).is_err());
        assert!(journal.prune(u64::MAX).is_err());
        assert!(!path.exists());
        drop(held);
        std::fs::set_permissions(
            path.with_extension("lock"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(journal.record_bound_consumption(&grant()).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn p06_br03_stale_compactor_preserves_another_writers_consume_intent() {
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let mut writer = GrantJournal::open(&path).unwrap();
        writer.record_consumption("expired", 1).unwrap();
        let mut compactor = GrantJournal::open(&path).unwrap();
        let retained = grant();
        writer.record_bound_consumption(&retained).unwrap();
        compactor
            .prune(super::GRANT_REPLAY_RETENTION_MS + 2)
            .unwrap();
        let reopened = GrantJournal::open(&path).unwrap();
        assert!(
            reopened.consumed.contains_key(&retained.id),
            "compaction lost durable intent"
        );
        assert_eq!(
            reopened.bindings[&retained.id].operation_id,
            retained.operation_id
        );
    }

    #[test]
    fn p06_br04_stale_writer_cannot_consume_another_writers_grant_again() {
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let mut first = GrantJournal::open(&path).unwrap();
        let mut stale = GrantJournal::open(&path).unwrap();
        first.record_bound_consumption(&grant()).unwrap();
        assert!(
            stale.record_bound_consumption(&grant()).is_err(),
            "same grant consumed twice"
        );
    }

    #[test]
    fn p06_cj01_durable_consumption_contains_exact_signed_correlation() {
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        let grant = grant();
        accept(&mut verifier, &grant);
        assert_eq!(
            verifier
                .consume(&grant.id, &authorization_for(&grant), 4, 2_200)
                .unwrap(),
            grant
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        let value = blindpass_core::canon::parse_json(contents.trim_end()).unwrap();
        assert_eq!(
            value
                .get("operation_id")
                .and_then(blindpass_core::canon::Value::as_str),
            Some(grant.operation_id.as_str())
        );
        assert_eq!(
            value
                .get("issuer_epoch")
                .and_then(blindpass_core::canon::Value::as_u64),
            Some(grant.issuer_epoch)
        );
        assert_eq!(
            value
                .get("grant_id")
                .and_then(blindpass_core::canon::Value::as_str),
            Some(grant.id.as_str())
        );
        assert_eq!(
            value
                .get("expires_at_ms")
                .and_then(blindpass_core::canon::Value::as_u64),
            Some(grant.expires_at_ms)
        );
        drop(verifier);
        let mut restored = stateful_verifier_with_fresh_time(&path);
        assert_eq!(
            restored.consume(&grant.id, &authorization_for(&grant), 4, 2_200),
            Err(ConsumeDenial::Consumed)
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn p06_cj02_legacy_intent_keeps_denial_beside_new_bound_consumption() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let legacy = numbered_grant(1);
        let original = format!(
            "{{\"grant_id\":\"{}\",\"expires_at_ms\":{}}}\n",
            legacy.id, legacy.expires_at_ms
        );
        std::fs::write(&path, &original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        assert_eq!(
            verifier.consume(&legacy.id, &authorization_for(&legacy), 4, 2_200),
            Err(ConsumeDenial::Consumed)
        );
        let current = numbered_grant(2);
        accept(&mut verifier, &current);
        verifier
            .consume(&current.id, &authorization_for(&current), 4, 2_200)
            .unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with(&original));
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        let first = blindpass_core::canon::parse_json(lines[0]).unwrap();
        assert!(first.get("operation_id").is_none());
        assert!(first.get("issuer_epoch").is_none());
        let second = blindpass_core::canon::parse_json(lines[1]).unwrap();
        assert_eq!(
            second
                .get("operation_id")
                .and_then(blindpass_core::canon::Value::as_str),
            Some(current.operation_id.as_str())
        );
        assert!(
            GrantJournal::open(&path)
                .unwrap()
                .consumed
                .contains_key(&current.id)
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn p06_cj03_compaction_preserves_retained_bound_metadata_without_guessing_legacy() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let expired = numbered_grant(1);
        let retained = numbered_grant(2);
        let line = format!(
            "{{\"grant_id\":\"{}\",\"expires_at_ms\":{},\"operation_id\":\"{}\",\"issuer_epoch\":{}}}\n",
            retained.id, retained.expires_at_ms, retained.operation_id, retained.issuer_epoch
        );
        let original = format!(
            "{{\"grant_id\":\"{}\",\"expires_at_ms\":1}}\n{line}",
            expired.id
        );
        std::fs::write(&path, &original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut journal = GrantJournal::open(&path).unwrap();
        journal.prune(super::GRANT_REPLAY_RETENTION_MS + 2).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), line);
        let loaded = GrantJournal::open(&path).unwrap();
        assert!(!loaded.consumed.contains_key(&expired.id));
        assert_eq!(
            loaded.consumed.get(&retained.id),
            Some(&retained.expires_at_ms)
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn p06_cj04_complete_malformed_or_conflicting_correlations_refuse() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let grant = grant();
        let line = format!(
            "{{\"grant_id\":\"{}\",\"expires_at_ms\":{},\"operation_id\":\"{}\",\"issuer_epoch\":{}}}\n",
            grant.id, grant.expires_at_ms, grant.operation_id, grant.issuer_epoch
        );
        let legacy = format!(
            "{{\"grant_id\":\"{}\",\"expires_at_ms\":{}}}\n",
            grant.id, grant.expires_at_ms
        );
        let mut cases = vec![
            line.replace(&grant.operation_id, "../dummy"),
            line.replace("\"issuer_epoch\":1", "\"issuer_epoch\":0"),
            line.replace("\"issuer_epoch\":1", "\"issuer_epoch\":9007199254740992"),
            line.replace("}\n", ",\"extra\":1}\n"),
            line.replace("}\n", ",\"operation_id\":\"op_duplicate\"}\n"),
            format!("{line}{}", line.replace(&grant.operation_id, "op_other")),
            format!(
                "{line}{}",
                line.replace("\"issuer_epoch\":1", "\"issuer_epoch\":2")
            ),
            format!("{legacy}{line}"),
            format!("{line}{legacy}"),
        ];
        cases.push(line.replace(",\"issuer_epoch\":1", ""));
        for malformed in cases {
            std::fs::write(&path, &malformed).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(GrantJournal::open(&path).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), malformed);
        }
        std::fs::write(&path, format!("{line}{line}")).unwrap();
        assert_eq!(GrantJournal::open(&path).unwrap().consumed.len(), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn p06_cj04b_torn_bound_record_retains_only_the_complete_intent() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let first = numbered_grant(1);
        let next = numbered_grant(2);
        let complete = format!(
            "{{\"grant_id\":\"{}\",\"expires_at_ms\":{},\"operation_id\":\"{}\",\"issuer_epoch\":{}}}\n",
            first.id, first.expires_at_ms, first.operation_id, first.issuer_epoch
        );
        let torn = format!(
            "{{\"grant_id\":\"{}\",\"expires_at_ms\":{},\"operation_id\":\"{}\"",
            next.id, next.expires_at_ms, next.operation_id
        );
        std::fs::write(&path, format!("{complete}{torn}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let journal = GrantJournal::open(&path).unwrap();
        assert_eq!(journal.consumed.len(), 1);
        assert!(journal.consumed.contains_key(&first.id));
        assert!(!journal.consumed.contains_key(&next.id));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), complete);
        assert_eq!(GrantJournal::open(&path).unwrap().consumed.len(), 1);
    }

    #[test]
    fn p06_cj05a_unsafe_correlation_denies_before_effect() {
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        let mut invalid = grant();
        invalid.operation_id = "../dummy".into();
        accept(&mut verifier, &invalid);
        assert_eq!(
            verifier.consume(&invalid.id, &authorization_for(&invalid), 4, 2_200),
            Err(ConsumeDenial::Unavailable)
        );
        assert!(!path.exists());
    }

    #[test]
    fn p06_cj05b_hardlinked_intent_denies_append_and_recovery() {
        let fixture = ConsumptionJournalDirectory::new();
        let path = fixture.0.join("consumed.jsonl");
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        let first = numbered_grant(1);
        accept(&mut verifier, &first);
        verifier
            .consume(&first.id, &authorization_for(&first), 4, 2_200)
            .unwrap();
        let contents = std::fs::read(&path).unwrap();
        let alias = path.with_extension("alias");
        std::fs::hard_link(&path, &alias).unwrap();
        let next = numbered_grant(2);
        accept(&mut verifier, &next);
        assert_eq!(
            verifier.consume(&next.id, &authorization_for(&next), 4, 2_200),
            Err(ConsumeDenial::Unavailable)
        );
        assert_eq!(std::fs::read(&path).unwrap(), contents);
        assert_eq!(std::fs::read(&alias).unwrap(), contents);
        assert!(GrantJournal::open(&path).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn registration_change_cannot_reauthorize_a_replayed_grant_after_restart() {
        let path = temporary_path();
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        let grant = grant();
        accept(&mut verifier, &grant);
        verifier.revoke_workload(&grant.workload_id);
        drop(verifier);

        let mut restarted = stateful_verifier_with_fresh_time(&path);
        let mut changed = registration();
        changed.registration_version += 1;
        assert!(
            restarted
                .accept_grant(
                    grant.clone(),
                    grant.id.as_bytes(),
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy(),
                    &changed,
                    2_100,
                )
                .is_err()
        );
        assert!(
            restarted
                .consume(&grant.id, &authorization_for(&grant), 4, 2_200)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn expired_unconsumed_grants_leave_the_accepted_map() {
        let path = temporary_path();
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        let expired_grant = grant();
        accept(&mut verifier, &expired_grant);
        verifier.pending_time = Some(super::TimeChallenge {
            value: "fresh".to_owned(),
            sent_at_boottime_ms: 100_000,
        });
        let later = 1_800_000_100_000;
        verifier
            .accept_time_reply(
                &TimeReply {
                    node_id: "nd_node-a".to_owned(),
                    challenge: "fresh".to_owned(),
                    challenge_received_at_ms: later,
                    controller_time_ms: later,
                    issuer_epoch: 1,
                },
                "nd_node-a",
                1,
                100_001,
            )
            .unwrap();
        assert!(verifier.accepted.is_empty());
        assert_eq!(
            verifier.consume(
                &expired_grant.id,
                &authorization_for(&expired_grant),
                expired_grant.policy_version,
                100_002,
            ),
            Err(ConsumeDenial::Expired)
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn accepted_grants_have_a_fixed_capacity() {
        let path = temporary_path();
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        for index in 0..super::MAX_ACCEPTED_GRANTS {
            let mut next = grant();
            next.id = format!("gr_{index:032x}");
            next.operation_id = format!("op_{index:032x}");
            accept(&mut verifier, &next);
        }
        let mut overflow = grant();
        overflow.id = "gr_ffffffffffffffffffffffffffffffff".to_owned();
        assert_eq!(
            verifier.accept_grant(
                overflow.clone(),
                overflow.id.as_bytes(),
                "nd_node-a",
                "nd_node-a-1",
                &policy(),
                &registration(),
                2_000,
            ),
            Err("broker grant capacity reached")
        );
        assert_eq!(verifier.accepted.len(), super::MAX_ACCEPTED_GRANTS);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    fn authorization_for(grant: &Grant) -> WorkloadAuthorization {
        WorkloadAuthorization {
            node_id: grant.node_id.clone(),
            workload_id: grant.workload_id.clone(),
            unit: grant.unit.clone(),
            invocation_id: grant.invocation_id.clone(),
            operation: format!("consume:{}", grant.id),
        }
    }

    #[test]
    fn consume_denials_name_one_stable_reason_each() {
        use super::ConsumeDenial;
        let path = temporary_path();
        let mut verifier = stateful_verifier_with_fresh_time(&path);

        let unknown = numbered_grant(1);
        assert_eq!(
            verifier.consume(&unknown.id, &authorization_for(&unknown), 4, 2_100),
            Err(ConsumeDenial::Unknown)
        );

        let mismatched = numbered_grant(2);
        accept(&mut verifier, &mismatched);
        for mutate in [
            (|value: &mut WorkloadAuthorization| value.node_id = "nd_node-b".to_owned())
                as fn(&mut WorkloadAuthorization),
            |value| value.workload_id = "wl_worker-b".to_owned(),
            |value| value.unit = "other.service".to_owned(),
            |value| value.invocation_id = "invocation-b".to_owned(),
            |value| value.operation = "consume:gr_other".to_owned(),
        ] {
            let mut authorization = authorization_for(&mismatched);
            mutate(&mut authorization);
            assert_eq!(
                verifier.consume(&mismatched.id, &authorization, 4, 2_100),
                Err(ConsumeDenial::IdentityMismatch)
            );
        }
        // Identity is checked first, so an expired grant bound to another
        // workload still reports only the identity mismatch.
        let mut other = authorization_for(&mismatched);
        other.workload_id = "wl_worker-b".to_owned();
        assert_eq!(
            verifier.consume(&mismatched.id, &other, 4, 999_999),
            Err(ConsumeDenial::IdentityMismatch)
        );

        let expired = numbered_grant(3);
        accept(&mut verifier, &expired);
        let deadline = verifier.accepted[&expired.id].deadline_boottime_ms;
        assert_eq!(
            verifier.consume(&expired.id, &authorization_for(&expired), 4, deadline),
            Err(ConsumeDenial::Expired)
        );

        let stale_policy = numbered_grant(4);
        accept(&mut verifier, &stale_policy);
        assert_eq!(
            verifier.consume(
                &stale_policy.id,
                &authorization_for(&stale_policy),
                5,
                2_100
            ),
            Err(ConsumeDenial::PolicyStale)
        );
        verifier.revoke_stale_policy(5);
        assert_eq!(
            verifier.consume(
                &stale_policy.id,
                &authorization_for(&stale_policy),
                5,
                2_100
            ),
            Err(ConsumeDenial::PolicyStale)
        );

        let consumed = numbered_grant(5);
        accept(&mut verifier, &consumed);
        verifier
            .consume(&consumed.id, &authorization_for(&consumed), 4, 2_100)
            .unwrap();
        assert_eq!(
            verifier.consume(&consumed.id, &authorization_for(&consumed), 4, 2_100),
            Err(ConsumeDenial::Consumed)
        );

        let revoked = numbered_grant(6);
        accept(&mut verifier, &revoked);
        verifier
            .revoke(
                &blindpass_core::fleet::Revocation {
                    grant_id: revoked.id.clone(),
                    node_id: "nd_node-a".to_owned(),
                    reason: "operator".to_owned(),
                    revoked_at_ms: 1_800_000_000_000,
                    retain_until_ms: 1_800_604_800_000,
                    issuer_epoch: 1,
                },
                1_800_000_000_000,
            )
            .unwrap();
        assert_eq!(
            verifier.consume(&revoked.id, &authorization_for(&revoked), 4, 2_100),
            Err(ConsumeDenial::Revoked)
        );

        let reregistered = numbered_grant(7);
        accept(&mut verifier, &reregistered);
        verifier.revoke_workload(&reregistered.workload_id);
        assert_eq!(
            verifier.consume(
                &reregistered.id,
                &authorization_for(&reregistered),
                4,
                2_100
            ),
            Err(ConsumeDenial::RegistrationChanged)
        );

        // A restart forgets in-memory acceptance: the grant needs fresh
        // reconciliation and reports unknown, while durable state survives.
        drop(verifier);
        let restarted = stateful_verifier_with_fresh_time(&path);
        let mut restarted = restarted;
        assert_eq!(
            restarted.consume(&expired.id, &authorization_for(&expired), 4, 2_100),
            Err(ConsumeDenial::Unknown)
        );
        assert_eq!(
            restarted.consume(&consumed.id, &authorization_for(&consumed), 4, 2_100),
            Err(ConsumeDenial::Consumed)
        );
        assert_eq!(
            restarted.consume(&revoked.id, &authorization_for(&revoked), 4, 2_100),
            Err(ConsumeDenial::Revoked)
        );

        let codes = ConsumeDenial::ALL
            .iter()
            .map(|denial| denial.code())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            [
                "grant_expired",
                "grant_revoked",
                "grant_consumed",
                "grant_unknown",
                "grant_identity_mismatch",
                "grant_policy_stale",
                "grant_registration_changed",
                "grant_epoch_stale",
                "grant_key_rotated",
                "consumption_unavailable",
            ]
        );
        for code in codes {
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn issuer_epoch_advance_purges_old_grants_and_consume_requires_the_pinned_epoch() {
        use super::ConsumeDenial;
        let path = temporary_path();
        let mut verifier = stateful_verifier_with_fresh_time(&path);
        let old_epoch = numbered_grant(1);
        accept(&mut verifier, &old_epoch);
        let bypassed = numbered_grant(2);
        accept(&mut verifier, &bypassed);

        verifier.observe_issuer_epoch(2);
        assert!(!verifier.accepted.contains_key(&old_epoch.id));
        assert_eq!(
            verifier.consume(&old_epoch.id, &authorization_for(&old_epoch), 4, 2_100),
            Err(ConsumeDenial::EpochStale)
        );
        // Lower or equal epochs never move the pin back.
        verifier.observe_issuer_epoch(1);
        assert_eq!(verifier.issuer_epoch, Some(2));

        // Even if an old-epoch grant were still held, consumption checks the
        // pinned epoch itself.
        verifier.accepted.insert(
            bypassed.id.clone(),
            super::AcceptedGrant {
                grant: bypassed.clone(),
                deadline_boottime_ms: 60_000,
                document_hash: [0; 32],
            },
        );
        assert_eq!(
            verifier.consume(&bypassed.id, &authorization_for(&bypassed), 4, 2_100),
            Err(ConsumeDenial::EpochStale)
        );

        // A grant of the old epoch is no longer accepted.
        let late = numbered_grant(3);
        assert!(
            verifier
                .accept_grant(
                    late.clone(),
                    late.id.as_bytes(),
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy(),
                    &registration(),
                    2_000,
                )
                .is_err()
        );
        let mut current = numbered_grant(4);
        current.issuer_epoch = 2;
        accept(&mut verifier, &current);
        verifier
            .consume(&current.id, &authorization_for(&current), 4, 2_100)
            .unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn retired_grant_reasons_are_bounded() {
        let mut verifier = GrantVerifier::default();
        for index in 0..super::MAX_RETIRED_GRANTS + 5 {
            verifier.retire(format!("gr_{index}"), super::ConsumeDenial::PolicyStale);
        }
        assert_eq!(verifier.retired.len(), super::MAX_RETIRED_GRANTS);
        assert_eq!(verifier.retired_order.len(), super::MAX_RETIRED_GRANTS);
        assert!(!verifier.retired.contains_key("gr_0"));
        assert!(
            verifier
                .retired
                .contains_key(&format!("gr_{}", super::MAX_RETIRED_GRANTS + 4))
        );
    }

    #[test]
    fn time_reply_after_the_challenge_delay_bound_is_rejected() {
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        let delayed = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: 1_800_000_000_000,
            controller_time_ms: 1_800_000_000_000,
            issuer_epoch: 1,
        };
        assert_eq!(
            verifier.accept_time_reply(&delayed, "nd_node-a", 1, 36_001),
            Err("time reply delay is outside the supported bound")
        );
        assert!(verifier.trusted_time.is_none());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn grant_acceptance_rejects_registration_and_audience_binding_changes() {
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        let time_reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            challenge_received_at_ms: 1_800_000_000_000,
            controller_time_ms: 1_800_000_000_000,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&time_reply, "nd_node-a", 1, 2_000)
            .unwrap();
        let policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        let registration = registration();
        let cases = [
            (
                "wrong audience",
                {
                    let mut value = grant();
                    value.audience = "other-audience".to_owned();
                    value
                },
                registration.clone(),
            ),
            ("different registered node", grant(), {
                let mut value = registration.clone();
                value.node_id = "nd_node-b".to_owned();
                value
            }),
            ("different registered workload", grant(), {
                let mut value = registration.clone();
                value.workload_id = "wl_worker-b".to_owned();
                value
            }),
            ("different registered unit", grant(), {
                let mut value = registration.clone();
                value.unit = "other.service".to_owned();
                value
            }),
            ("different registered invocation", grant(), {
                let mut value = registration.clone();
                value.invocation_id = Some("invocation-other".to_owned());
                value
            }),
            ("different registered account", grant(), {
                let mut value = registration.clone();
                value.account = "other-account".to_owned();
                value
            }),
            ("different registered mode", grant(), {
                let mut value = registration.clone();
                value.consumption_mode = ConsumptionMode::Socket;
                value
            }),
            ("revoked registration", grant(), {
                let mut value = registration.clone();
                value.status = "revoked".to_owned();
                value
            }),
        ];
        for (label, grant, registration) in cases {
            assert!(
                verifier
                    .accept_grant(
                        grant,
                        label.as_bytes(),
                        "nd_node-a",
                        "nd_node-a-1",
                        &policy,
                        &registration,
                        2_100,
                    )
                    .is_err(),
                "{label} must fail the broker's grant binding checks"
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn consumed_grant_intent_survives_crash_before_the_operation_effect() {
        let path = temporary_path();
        let time_path = path.parent().unwrap().join("trusted-time");
        let revocation_path = path.parent().unwrap().join("revoked-grants.jsonl");
        let mut verifier =
            GrantVerifier::with_state_files(&path, &time_path, &revocation_path).unwrap();
        verifier.observe_issuer_epoch(1);
        verifier.pending_time = Some(super::TimeChallenge {
            value: "challenge-before-consume".to_owned(),
            sent_at_boottime_ms: 1_000,
        });
        let first_time = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-before-consume".to_owned(),
            challenge_received_at_ms: 1_800_000_000_000,
            controller_time_ms: 1_800_000_000_000,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&first_time, "nd_node-a", 1, 2_000)
            .unwrap();

        let grant = grant();
        let policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        assert!(
            verifier
                .accept_grant(
                    grant.clone(),
                    b"signed-grant-before-crash",
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy,
                    &registration(),
                    2_100,
                )
                .unwrap()
        );
        let authorization = WorkloadAuthorization {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            unit: "worker.service".to_owned(),
            invocation_id: "invocation-a".to_owned(),
            operation: format!("consume:{}", grant.id),
        };

        // This is the durable boundary: consume writes the one-use intent. A
        // process loss here happens before the caller can create the marker.
        assert_eq!(
            verifier
                .consume(&grant.id, &authorization, policy.policy_version, 2_200)
                .unwrap(),
            grant
        );
        let marker_path = path
            .parent()
            .unwrap()
            .join("ops")
            .join("gr_0123456789abcdef0123456789abcdef.marker");
        assert!(
            !marker_path.exists(),
            "the simulated crash precedes the effect"
        );
        drop(verifier);

        let mut restarted =
            GrantVerifier::with_state_files(&path, &time_path, &revocation_path).unwrap();
        restarted.observe_issuer_epoch(1);
        restarted.pending_time = Some(super::TimeChallenge {
            value: "challenge-after-crash".to_owned(),
            sent_at_boottime_ms: 3_000,
        });
        let fresh_time = TimeReply {
            challenge: "challenge-after-crash".to_owned(),
            challenge_received_at_ms: first_time.controller_time_ms + 100,
            controller_time_ms: first_time.controller_time_ms + 100,
            ..first_time
        };
        restarted
            .accept_time_reply(&fresh_time, "nd_node-a", 1, 4_000)
            .unwrap();
        assert!(
            restarted
                .accept_grant(
                    grant.clone(),
                    b"signed-grant-before-crash",
                    "nd_node-a",
                    "nd_node-a-1",
                    &policy,
                    &registration(),
                    4_100,
                )
                .is_err()
        );
        assert!(
            restarted
                .consume(&grant.id, &authorization, policy.policy_version, 4_200)
                .is_err()
        );
        assert!(
            !marker_path.exists(),
            "replay must not run the operation effect"
        );
        assert!(
            GrantJournal::open(&path)
                .unwrap()
                .consumed
                .contains_key(&grant.id)
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn consumed_intent_is_fsynced_and_survives_broker_restart() {
        let path = temporary_path();
        let mut journal = GrantJournal::open(&path).unwrap();
        journal
            .record_consumption("gr_0123456789abcdef0123456789abcdef", 1_800_000_060_000)
            .unwrap();
        let mut restored = GrantJournal::open(&path).unwrap();
        assert!(
            restored
                .consumed
                .contains_key("gr_0123456789abcdef0123456789abcdef")
        );
        assert!(
            restored
                .record_consumption("gr_0123456789abcdef0123456789abcdef", 1_800_000_060_000)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn revocation_tombstones_survive_restart_until_authenticated_retention_expires() {
        let path = temporary_path();
        let mut journal = RevocationJournal::open(&path).unwrap();
        journal
            .record(
                "gr_0123456789abcdef0123456789abcdef",
                1_800_604_800_000,
                None,
            )
            .unwrap();
        let restored = RevocationJournal::open(&path).unwrap();
        assert!(restored.contains_at("gr_0123456789abcdef0123456789abcdef", 1_800_000_000_000));
        assert!(!restored.contains_at("gr_0123456789abcdef0123456789abcdef", 1_800_700_000_000));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    fn write_private(path: &std::path::Path, contents: &[u8]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(contents).unwrap();
    }

    #[test]
    fn empty_and_torn_consumed_journals_recover_without_losing_durable_intents() {
        let path = temporary_path();
        write_private(&path, b"");
        assert!(GrantJournal::open(&path).unwrap().consumed.is_empty());

        // A crash mid-append leaves an unterminated record. The intent was
        // never fsynced, so its effect never ran: drop only that tail.
        let durable = "{\"grant_id\":\"gr_0123456789abcdef0123456789abcdef\",\"expires_at_ms\":1800000060000}\n";
        let torn = "{\"grant_id\":\"gr_1123456789abcdef01234";
        write_private(&path, format!("{durable}{torn}").as_bytes());
        let mut journal = GrantJournal::open(&path).unwrap();
        assert_eq!(journal.consumed.len(), 1);
        assert!(
            journal
                .consumed
                .contains_key("gr_0123456789abcdef0123456789abcdef")
        );
        assert_eq!(std::fs::read(&path).unwrap(), durable.as_bytes());
        // Appending after recovery produces well-formed records again.
        journal
            .record_consumption("gr_1123456789abcdef0123456789abcdef", 1_800_000_060_000)
            .unwrap();
        assert_eq!(GrantJournal::open(&path).unwrap().consumed.len(), 2);

        // Only an unterminated record at all: the file becomes empty.
        write_private(&path, torn.as_bytes());
        assert!(GrantJournal::open(&path).unwrap().consumed.is_empty());
        assert!(std::fs::read(&path).unwrap().is_empty());

        // A corrupt complete record still fails closed.
        write_private(&path, b"{\"grant_id\":\"gr_bad.id\",\"expires_at_ms\":1}\n");
        assert!(GrantJournal::open(&path).is_err());
        write_private(&path, format!("not-json\n{durable}").as_bytes());
        assert!(GrantJournal::open(&path).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn empty_and_torn_revocation_journals_recover_and_corrupt_records_fail_closed() {
        let path = temporary_path();
        write_private(&path, b"");
        assert!(
            RevocationJournal::open(&path)
                .unwrap()
                .tombstones
                .is_empty()
        );

        let durable = "{\"grant_id\":\"gr_0123456789abcdef0123456789abcdef\",\"retain_until_ms\":1800604800000}\n";
        write_private(&path, format!("{durable}{{\"grant_id\":\"gr_1").as_bytes());
        let journal = RevocationJournal::open(&path).unwrap();
        assert!(journal.contains_at("gr_0123456789abcdef0123456789abcdef", 1_800_000_000_000));
        assert_eq!(journal.tombstones.len(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), durable.as_bytes());

        write_private(&path, format!("{durable}garbage\n").as_bytes());
        assert!(RevocationJournal::open(&path).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn revocation_acknowledgements_prune_with_expired_tombstones() {
        let path = temporary_path();
        let expired = "gr_0123456789abcdef0123456789abcdef";
        let retained = "gr_1123456789abcdef0123456789abcdef";
        let mut journal = RevocationJournal::open(&path).unwrap();
        journal
            .record(expired, 100, Some(("not_received", 1)))
            .unwrap();
        journal
            .record(retained, 200, Some(("not_received", 1)))
            .unwrap();
        journal.acknowledge_outcome(expired).unwrap();
        journal.acknowledge_outcome(retained).unwrap();
        journal.prune(150).unwrap();
        let restored = RevocationJournal::open(&path).unwrap();
        assert!(!restored.tombstones.contains_key(expired));
        assert!(restored.tombstones.contains_key(retained));
        assert_eq!(restored.acknowledged_outcomes.len(), 1);
        assert!(restored.acknowledged_outcomes.contains(retained));
        assert_eq!(
            std::fs::read_to_string(path.with_extension("acks"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
