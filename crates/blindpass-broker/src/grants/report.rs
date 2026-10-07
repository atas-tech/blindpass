// SPDX-License-Identifier: AGPL-3.0-only

//! Broker-owned immutable metadata export. No caller supplies journal rows.

use super::{
    GrantJournal, GrantVerifier, NO_FOLLOW, PRIVATE_FILE_MODE, TEMP_SEQUENCE, boottime_ms,
    lock_consumption_journal, process_id,
};
use crate::BrokerError;
use crate::keys::{NodeIdentity, PinnedIssuer};
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::recovery::pages::{
    HistoryCoverage, IntentRecord, MAX_PAGE_BYTES, PageDigest, ReportIdentity, ReportManifest,
    ReportPage, SignedReportRequest,
};
use blindpass_core::signing::{base64_url_decode, base64_url_encode};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::Ordering;

const REPORT_LIFETIME_MS: u64 = 30_000;
const MAX_SNAPSHOT_BYTES: u64 = 192 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct PendingChallenge {
    nonce: String,
    pin: PinnedIssuer,
    key_version: u64,
    expires_boottime_ms: u64,
}

#[derive(Debug)]
pub(super) struct HistorySnapshot {
    file: File,
    offsets: Vec<u64>,
    manifest: ReportManifest,
    pin_epoch: u64,
    broker_challenge: String,
    expires_boottime_ms: u64,
}

fn denied() -> BrokerError {
    BrokerError::Configuration("recovery_report_denied")
}

fn random_id() -> Result<String, BrokerError> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| denied())?;
    Ok(base64_url_encode(&bytes))
}

impl GrantVerifier {
    pub(crate) fn begin_recovery_challenge(
        &mut self,
        identity: &NodeIdentity,
    ) -> Result<Value, BrokerError> {
        let pin = identity.pinned_issuer()?.ok_or_else(denied)?;
        let key_version = identity.key_version()?;
        let nonce = random_id()?;
        let expires = boottime_ms()
            .map_err(|_| denied())?
            .checked_add(REPORT_LIFETIME_MS)
            .ok_or_else(denied)?;
        self.recovery_snapshot = None;
        self.recovery_challenge = Some(PendingChallenge {
            nonce: nonce.clone(),
            pin: pin.clone(),
            key_version,
            expires_boottime_ms: expires,
        });
        Ok(Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("broker_challenge".into(), Value::String(nonce)),
            ("tenant_id".into(), Value::String(pin.tenant_id)),
            ("node_id".into(), Value::String(pin.node_id)),
            ("issuer_key_id".into(), Value::String(pin.key_id)),
            ("node_key_version".into(), Value::Unsigned(key_version)),
            ("observed_issuer_epoch".into(), Value::Unsigned(pin.epoch)),
        ]))
    }

    pub(crate) fn recovery_page(
        &mut self,
        signed: &SignedReportRequest,
        identity: &NodeIdentity,
    ) -> Result<Value, BrokerError> {
        let request = &signed.request;
        let pin = identity.pinned_issuer()?.ok_or_else(denied)?;
        let key_version = identity.key_version()?;
        let binding = &request.identity;
        if pin.tenant_id != binding.tenant_id
            || pin.node_id != binding.node_id
            || pin.key_id != binding.issuer_key_id
            || key_version != binding.node_key_version
        {
            return Err(denied());
        }
        let public = base64_url_decode(&pin.public_key, 32).ok_or_else(denied)?;
        signed.verify(&public).map_err(|_| denied())?;
        let now = boottime_ms().map_err(|_| denied())?;
        if self
            .recovery_snapshot
            .as_ref()
            .is_some_and(|snapshot| now >= snapshot.expires_boottime_ms)
        {
            self.recovery_snapshot = None;
        }
        if let Some(snapshot) = &mut self.recovery_snapshot {
            if snapshot.manifest.identity != *binding
                || snapshot.broker_challenge != request.broker_challenge
                || snapshot.pin_epoch != pin.epoch
                || request
                    .report_id
                    .as_ref()
                    .is_some_and(|id| id != &snapshot.manifest.report_id)
                || (request.report_id.is_none() && request.page_index != 0)
            {
                return Err(denied());
            }
            return snapshot.signed_page(request.page_index, identity);
        }
        if request.report_id.is_some() || request.page_index != 0 {
            return Err(denied());
        }
        let pending = self.recovery_challenge.as_ref().ok_or_else(denied)?;
        if now >= pending.expires_boottime_ms
            || pending.nonce != request.broker_challenge
            || pending.pin != pin
            || pending.key_version != key_version
        {
            return Err(denied());
        }
        let expires = pending.expires_boottime_ms;
        // Consume this ephemeral nonce before any durable pin advancement or
        // snapshot IO. Failures leave issuance fenced and require a new nonce.
        self.recovery_challenge = None;
        let (pin, observed) = identity.recovery_pin(binding)?;
        self.observe_issuer_epoch(pin.epoch);
        let journal = self.journal.as_mut().ok_or_else(denied)?;
        let mut snapshot =
            journal.snapshot(binding, &request.broker_challenge, &pin, observed, expires)?;
        let value = snapshot.signed_page(0, identity)?;
        self.recovery_snapshot = Some(snapshot);
        Ok(value)
    }
}

impl GrantJournal {
    fn snapshot(
        &mut self,
        binding: &ReportIdentity,
        broker_challenge: &str,
        pin: &PinnedIssuer,
        original_observed: u64,
        expires: u64,
    ) -> Result<HistorySnapshot, BrokerError> {
        let path = self.path.clone().ok_or_else(denied)?;
        let _lock = lock_consumption_journal(&path).map_err(|_| denied())?;
        self.synchronize().map_err(|_| denied())?;
        if self.history.as_ref().is_some_and(|history| {
            history.tenant_id != pin.tenant_id
                || history.node_id != pin.node_id
                || history.issuer_key_id != pin.key_id
        }) {
            return Err(denied());
        }
        let recorded_epoch = self
            .bindings
            .values()
            .map(|binding| binding.issuer_epoch)
            .max()
            .unwrap_or(0);
        let mut observed = original_observed.max(recorded_epoch);
        if let Some(history) = &self.history {
            // Our own advancement is a fence, not a previous-issued epoch.
            // Any subsequently observed higher value must still be attested.
            if history.highest_issuer_epoch > pin.epoch {
                observed = observed.max(history.highest_issuer_epoch);
            }
        }
        let mut manifest = ReportManifest {
            identity: binding.clone(),
            report_id: random_id()?,
            observed_issuer_epoch: observed,
            coverage: HistoryCoverage {
                history_id: self
                    .history
                    .as_ref()
                    .map(|history| history.history_id.clone()),
                pruned_through_ms: self
                    .history
                    .as_ref()
                    .map_or(0, |history| history.pruned_through_ms),
                unmapped_records: (self.consumed.len() - self.bindings.len()) as u64,
            },
            total_records: self.consumed.len() as u64,
            records_digest: base64_url_encode(&[0; 32]),
        };
        let mut digest = PageDigest::new(&manifest).map_err(|_| denied())?;
        let parent = path.parent().ok_or_else(denied)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".recovery-history-{}-{sequence}.tmp", process_id()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(NO_FOLLOW)
            .open(&temp)
            .map_err(|_| denied())?;
        // Unlink while empty, before writing metadata. Only this owned FD can
        // retain the snapshot; interruption leaves no named plaintext report.
        fs::remove_file(&temp).map_err(|_| denied())?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| denied())?;
        let mut offsets = vec![0];
        let mut written = 0_u64;
        for (index, (grant_id, expires_at)) in self.consumed.iter().enumerate() {
            if boottime_ms().map_err(|_| denied())? >= expires {
                return Err(denied());
            }
            if index > 0 && index % 128 == 0 {
                offsets.push(written);
            }
            let correlation = self.bindings.get(grant_id);
            let record = IntentRecord {
                grant_id: grant_id.clone(),
                expires_at_ms: *expires_at,
                operation_id: correlation.map(|binding| binding.operation_id.clone()),
                issuer_epoch: correlation.map(|binding| binding.issuer_epoch),
            };
            digest.push(&record).map_err(|_| denied())?;
            let mut line = canonicalize_value(&record.to_value().map_err(|_| denied())?)
                .map_err(|_| denied())?;
            line.push(b'\n');
            written = written.checked_add(line.len() as u64).ok_or_else(denied)?;
            if written > MAX_SNAPSHOT_BYTES {
                return Err(denied());
            }
            file.write_all(&line).map_err(|_| denied())?;
        }
        file.sync_all().map_err(|_| denied())?;
        manifest.records_digest = digest.finish().map_err(|_| denied())?;
        Ok(HistorySnapshot {
            file,
            offsets,
            manifest,
            pin_epoch: pin.epoch,
            broker_challenge: broker_challenge.into(),
            expires_boottime_ms: expires,
        })
    }
}

impl HistorySnapshot {
    fn signed_page(&mut self, index: u64, identity: &NodeIdentity) -> Result<Value, BrokerError> {
        if boottime_ms().map_err(|_| denied())? >= self.expires_boottime_ms {
            return Err(denied());
        }
        let offset = *self
            .offsets
            .get(usize::try_from(index).map_err(|_| denied())?)
            .ok_or_else(denied)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| denied())?;
        let expected = self
            .manifest
            .total_records
            .saturating_sub(index * 128)
            .min(128);
        let mut records = Vec::with_capacity(expected as usize);
        let mut reader = BufReader::new(&mut self.file);
        for _ in 0..expected {
            let mut line = Vec::new();
            reader
                .by_ref()
                .take(1_024)
                .read_until(b'\n', &mut line)
                .map_err(|_| denied())?;
            if line.last() != Some(&b'\n') {
                return Err(denied());
            }
            let text = std::str::from_utf8(&line).map_err(|_| denied())?;
            records.push(
                IntentRecord::from_value(&parse_json(text).map_err(|_| denied())?)
                    .map_err(|_| denied())?,
            );
        }
        let page = ReportPage {
            manifest: self.manifest.clone(),
            page_index: index,
            records,
        };
        if boottime_ms().map_err(|_| denied())? >= self.expires_boottime_ms {
            return Err(denied());
        }
        let signature = identity.sign_recovery_page(&page, self.pin_epoch)?;
        if boottime_ms().map_err(|_| denied())? >= self.expires_boottime_ms {
            return Err(denied());
        }
        let value = Value::Object(vec![
            ("body".into(), page.to_value().map_err(|_| denied())?),
            ("broker_signature".into(), Value::String(signature)),
        ]);
        if canonicalize_value(&value).map_err(|_| denied())?.len() > MAX_PAGE_BYTES {
            return Err(denied());
        }
        Ok(value)
    }
}
