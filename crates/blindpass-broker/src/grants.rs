// SPDX-License-Identifier: AGPL-3.0-only

//! Freshness-bound grant deadlines and durable one-use consumption records.

use blindpass_core::custody::sha256;
use blindpass_core::fleet::{Grant, PolicySnapshot, Registration, Revocation, TimeReply};
use blindpass_core::identity::WorkloadAuthorization;
use blindpass_core::signing::base64_url_encode;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_TIME_REPLY_DELAY_MS: u64 = 35_000;
const MAX_DOCUMENT_AGE_MS: u64 = 60_000;
const CLOCK_ROLLBACK_TOLERANCE_MS: u64 = 2_000;
const GRANT_JOURNAL_MAX_BYTES: u64 = 64 * 1024 * 1024;
const GRANT_JOURNAL_MAX_RECORDS: usize = 1_000_000;
const GRANT_REPLAY_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
const PRIVATE_FILE_MODE: u32 = 0o600;
const NO_FOLLOW: i32 = 0x20000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
struct TimeChallenge {
    value: String,
    sent_at_boottime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedTime {
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
    journal: Option<GrantJournal>,
    revocations: Option<RevocationJournal>,
}

#[derive(Debug, Default)]
struct GrantJournal {
    path: Option<PathBuf>,
    consumed: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
struct RevocationJournal {
    path: Option<PathBuf>,
    tombstones: BTreeMap<String, u64>,
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
            .filter(|value| *value > 0 && *value <= MAX_TIME_REPLY_DELAY_MS)
            .ok_or("time reply delay is outside the supported bound")?;
        let controller_now_ms = reply
            .controller_time_ms
            .checked_add(round_trip_ms)
            .ok_or("trusted controller time overflow")?;
        if let Some(previous) = self.trusted_time.as_ref() {
            let elapsed = now_boottime_ms.saturating_sub(previous.received_at_boottime_ms);
            let minimum_now = previous
                .estimated_controller_ms
                .saturating_add(elapsed)
                .saturating_sub(CLOCK_ROLLBACK_TOLERANCE_MS);
            if controller_now_ms < minimum_now {
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
        self.highest_controller_time_ms = Some(highest_controller_time_ms);
        self.trusted_time = Some(TrustedTime {
            estimated_controller_ms: controller_now_ms,
            received_at_boottime_ms: now_boottime_ms,
        });
        Ok(())
    }

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
        let trusted = self
            .trusted_time
            .as_ref()
            .filter(|time| {
                now_boottime_ms.saturating_sub(time.received_at_boottime_ms)
                    <= MAX_TIME_REPLY_DELAY_MS
            })
            .ok_or("grant has no fresh signed controller time proof")?;
        if grant.node_id != node_id
            || grant.recipient_key_id != recipient_key_id
            || grant.policy_version != policy.policy_version
            || registration.policy_version != grant.policy_version
            || grant.local_ceiling_seconds > policy.local_ceiling_seconds
            || grant.local_ceiling_seconds > registration.local_ceiling_seconds
            || registration.status != "active"
            || registration.node_id != grant.node_id
            || registration.workload_id != grant.workload_id
            || registration.unit != grant.unit
            || registration.account != grant.account
            || registration.consumption_mode != grant.mode
            || !policy
                .allowed_actions
                .iter()
                .any(|action| action == &grant.action)
            || !policy.allowed_modes.contains(&grant.mode)
        {
            return Err("grant does not match current broker policy and workload registration");
        }
        let now_controller_ms = trusted
            .estimated_controller_ms
            .checked_add(now_boottime_ms.saturating_sub(trusted.received_at_boottime_ms))
            .ok_or("trusted controller time overflow")?;
        let remaining_ms = grant
            .expires_at_ms
            .checked_sub(now_controller_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or("grant expired before broker receipt")?;
        if grant.issued_at_ms > now_controller_ms
            || now_controller_ms.saturating_sub(grant.issued_at_ms) > MAX_DOCUMENT_AGE_MS
            || grant.expires_at_ms.saturating_sub(grant.issued_at_ms) > 3_600_000
        {
            return Err("grant is stale or exceeds the broker lifetime maximum");
        }
        if self
            .revocations
            .as_ref()
            .is_some_and(|journal| journal.contains_at(&grant.id, now_controller_ms))
        {
            return Err("grant has an active revocation tombstone");
        }
        if self
            .journal
            .as_ref()
            .is_some_and(|journal| journal.consumed.contains_key(&grant.id))
        {
            return Err("grant was already consumed");
        }
        let digest = sha256(document).map_err(|_| "grant digest could not be computed")?;
        if let Some(existing) = self.accepted.get(&grant.id) {
            if existing.document_hash == digest && existing.grant == grant {
                return Ok(false);
            }
            return Err("grant id was reused with different signed content");
        }
        let deadline_boottime_ms = now_boottime_ms
            .checked_add(remaining_ms.min(registration.local_ceiling_seconds * 1_000))
            .filter(|deadline| *deadline > now_boottime_ms)
            .ok_or("grant has no safe local lifetime remaining")?;
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
    ) -> Result<Grant, &'static str> {
        let accepted = self
            .accepted
            .get(grant_id)
            .ok_or("grant is unknown or requires fresh reconciliation")?;
        let grant = &accepted.grant;
        if now_boottime_ms >= accepted.deadline_boottime_ms
            || authorization.node_id != grant.node_id
            || authorization.workload_id != grant.workload_id
            || authorization.unit != grant.unit
            || authorization.invocation_id != grant.invocation_id
            || authorization.operation != format!("consume:{grant_id}")
            || grant.policy_version != current_policy_version
            || grant.audience != "blindpass-node"
        {
            return Err("live workload identity does not match the grant");
        }
        let journal = self
            .journal
            .as_mut()
            .ok_or("durable grant journal is unavailable")?;
        journal.record_consumption(&grant.id, grant.expires_at_ms)?;
        let accepted = self
            .accepted
            .remove(grant_id)
            .ok_or("grant was consumed concurrently")?;
        Ok(accepted.grant)
    }

    pub(crate) fn revoke_workload(&mut self, workload_id: &str) {
        self.accepted
            .retain(|_, accepted| accepted.grant.workload_id != workload_id);
    }

    pub(crate) fn revoke(&mut self, revocation: &Revocation) -> Result<(), &'static str> {
        self.revocations
            .as_mut()
            .ok_or("durable grant revocation journal is unavailable")?
            .record(&revocation.grant_id, revocation.retain_until_ms)?;
        self.accepted.remove(&revocation.grant_id);
        Ok(())
    }

    pub(crate) fn revoke_stale_policy(&mut self, policy_version: u64) {
        self.accepted
            .retain(|_, accepted| accepted.grant.policy_version == policy_version);
    }
}

impl GrantJournal {
    fn open(path: &Path) -> Result<Self, &'static str> {
        let mut journal = Self {
            path: Some(path.to_owned()),
            consumed: BTreeMap::new(),
        };
        let mut file = match open_private(path, false) {
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
        if contents.last() != Some(&b'\n') {
            return Err("grant journal ends with an incomplete record");
        }
        for line in contents
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let (id, expiry) = parse_journal_line(line)?;
            if let Some(existing) = journal.consumed.insert(id.to_owned(), expiry)
                && existing != expiry
            {
                return Err("grant journal contains a conflicting replay record");
            }
        }
        if journal.consumed.len() > GRANT_JOURNAL_MAX_RECORDS {
            return Err("grant journal exceeds its record bound");
        }
        Ok(journal)
    }

    fn record_consumption(
        &mut self,
        grant_id: &str,
        expires_at_ms: u64,
    ) -> Result<(), &'static str> {
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
        let line = format!("{{\"grant_id\":\"{grant_id}\",\"expires_at_ms\":{expires_at_ms}}}\n");
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
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| "grant consumption intent could not be flushed")?;
        self.consumed.insert(grant_id.to_owned(), expires_at_ms);
        if !existed {
            let parent = path
                .parent()
                .ok_or("grant journal parent directory is unavailable")?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "grant journal directory could not be synchronized")?;
        }
        Ok(())
    }

    fn prune(&mut self, authenticated_time_ms: u64) -> Result<(), &'static str> {
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
        for (id, expires_at) in &pruned {
            let line = format!("{{\"grant_id\":\"{id}\",\"expires_at_ms\":{expires_at}}}\n");
            if let Err(_) = file.write_all(line.as_bytes()) {
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
        self.consumed = pruned;
        Ok(())
    }
}

impl RevocationJournal {
    fn open(path: &Path) -> Result<Self, &'static str> {
        let mut journal = Self {
            path: Some(path.to_owned()),
            tombstones: BTreeMap::new(),
        };
        let mut file = match open_private(path, false) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(journal),
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
        if !contents.is_empty() && contents.last() != Some(&b'\n') {
            return Err("grant revocation journal ends with an incomplete record");
        }
        for line in contents
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let (id, retain_until) = parse_revocation_line(line)?;
            journal
                .tombstones
                .entry(id.to_owned())
                .and_modify(|previous| *previous = (*previous).max(retain_until))
                .or_insert(retain_until);
        }
        if journal.tombstones.len() > GRANT_JOURNAL_MAX_RECORDS {
            return Err("grant revocation journal exceeds its record bound");
        }
        Ok(journal)
    }

    fn contains_at(&self, grant_id: &str, controller_time_ms: u64) -> bool {
        self.tombstones
            .get(grant_id)
            .is_some_and(|retain_until| *retain_until > controller_time_ms)
    }

    fn record(&mut self, grant_id: &str, retain_until_ms: u64) -> Result<(), &'static str> {
        if let Some(existing) = self.tombstones.get(grant_id)
            && *existing >= retain_until_ms
        {
            return Ok(());
        }
        if self.tombstones.len() >= GRANT_JOURNAL_MAX_RECORDS
            && !self.tombstones.contains_key(grant_id)
        {
            return Err("grant revocation journal is full; revocation is denied");
        }
        let path = self
            .path
            .as_ref()
            .ok_or("grant revocation journal path is unavailable")?;
        let line =
            format!("{{\"grant_id\":\"{grant_id}\",\"retain_until_ms\":{retain_until_ms}}}\n");
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
            return Err("grant revocation journal is full; revocation is denied");
        }
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| "grant revocation tombstone could not be flushed")?;
        self.tombstones.insert(grant_id.to_owned(), retain_until_ms);
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
            let line = format!("{{\"grant_id\":\"{id}\",\"retain_until_ms\":{retain_until}}}\n");
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
        self.tombstones = pruned;
        Ok(())
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
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "grant journal file ownership or mode is unsafe",
        ));
    }
    Ok(file)
}

fn parse_journal_line(line: &[u8]) -> Result<(&str, u64), &'static str> {
    let text = std::str::from_utf8(line).map_err(|_| "grant journal is not UTF-8")?;
    let value = text
        .strip_prefix("{\"grant_id\":\"")
        .and_then(|value| value.strip_suffix('}'))
        .ok_or("grant journal record is malformed")?;
    let (id, expiry) = value
        .split_once("\",\"expires_at_ms\":")
        .ok_or("grant journal record is malformed")?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("grant journal id is malformed");
    }
    let expiry = expiry
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == expiry)
        .ok_or("grant journal expiry is malformed")?;
    Ok((id, expiry))
}

fn parse_revocation_line(line: &[u8]) -> Result<(&str, u64), &'static str> {
    let text = std::str::from_utf8(line).map_err(|_| "grant revocation journal is not UTF-8")?;
    let value = text
        .strip_prefix("{\"grant_id\":\"")
        .and_then(|value| value.strip_suffix('}'))
        .ok_or("grant revocation record is malformed")?;
    let (id, retain_until) = value
        .split_once("\",\"retain_until_ms\":")
        .ok_or("grant revocation record is malformed")?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("grant revocation id is malformed");
    }
    let retain_until = retain_until
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == retain_until)
        .ok_or("grant revocation retention is malformed")?;
    Ok((id, retain_until))
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
    use super::{GrantJournal, GrantVerifier, RevocationJournal};
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
            policy_version: 4,
            approval_reference: None,
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

    fn verifier(path: &std::path::Path, started_at: u64) -> GrantVerifier {
        let mut verifier = GrantVerifier {
            journal: Some(GrantJournal::open(path).unwrap()),
            ..GrantVerifier::default()
        };
        verifier.pending_time = Some(super::TimeChallenge {
            value: "challenge-a".to_owned(),
            sent_at_boottime_ms: started_at,
        });
        verifier
    }

    #[test]
    fn signed_time_reply_consumes_one_challenge_and_subtracts_full_delay() {
        let path = temporary_path();
        let mut verifier = verifier(&path, 1_000);
        let reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge: "challenge-a".to_owned(),
            controller_time_ms: 1_800_000_000_000,
            issuer_epoch: 1,
        };
        verifier
            .accept_time_reply(&reply, "nd_node-a", 1, 4_000)
            .unwrap();
        assert!(verifier.pending_time.is_none());
        assert!(
            verifier
                .accept_time_reply(&reply, "nd_node-a", 1, 4_100)
                .is_err()
        );
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
        let mut wrong_invocation = WorkloadAuthorization {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            unit: "worker.service".to_owned(),
            invocation_id: "invocation-old".to_owned(),
            operation: format!("consume:{}", grant.id),
        };
        assert!(
            verifier
                .consume(&grant.id, &wrong_invocation, 4, 2_300)
                .is_err()
        );
        wrong_invocation.invocation_id = "invocation-a".to_owned();
        assert!(
            verifier
                .consume(&grant.id, &wrong_invocation, 3, 2_300)
                .is_err()
        );
        verifier
            .consume(&grant.id, &wrong_invocation, 4, 2_300)
            .unwrap();
        assert!(
            verifier
                .consume(&grant.id, &wrong_invocation, 4, 2_301)
                .is_err()
        );
        let restored = GrantJournal::open(&path).unwrap();
        assert!(restored.consumed.contains_key(&grant.id));
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
            .record("gr_0123456789abcdef0123456789abcdef", 1_800_604_800_000)
            .unwrap();
        let restored = RevocationJournal::open(&path).unwrap();
        assert!(restored.contains_at("gr_0123456789abcdef0123456789abcdef", 1_800_000_000_000));
        assert!(!restored.contains_at("gr_0123456789abcdef0123456789abcdef", 1_800_700_000_000));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
