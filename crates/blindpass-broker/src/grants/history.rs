// SPDX-License-Identifier: AGPL-3.0-only

//! Durable provenance for consumption metadata. A history marker attests
//! only to journal coverage, never to effect completion or provider cleanup.

use super::{GrantJournal, NO_FOLLOW, PRIVATE_FILE_MODE};
use crate::keys::PinnedIssuer;
use blindpass_core::canon::parse_json;
use blindpass_core::fleet::is_valid_opaque_id;
use blindpass_core::signing::{base64_url_decode, base64_url_encode};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConsumptionHistory {
    pub(super) history_id: String,
    pub(super) tenant_id: String,
    pub(super) node_id: String,
    pub(super) issuer_key_id: String,
    /// Removed records can have effects before their expiry, so this is a
    /// conservative lower bound on coverage, not a claim about their fate.
    pub(super) pruned_through_ms: u64,
    pub(super) highest_issuer_epoch: u64,
}

impl ConsumptionHistory {
    pub(super) fn is_bound(&self) -> bool {
        !self.tenant_id.is_empty()
    }

    pub(super) fn same_scope(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.node_id == other.node_id
            && self.issuer_key_id == other.issuer_key_id
    }

    pub(super) fn parse(line: &[u8]) -> Result<Self, &'static str> {
        if line.len() > 2_047 {
            return Err("grant history header is too large");
        }
        let text = std::str::from_utf8(line).map_err(|_| "grant history header is malformed")?;
        let value = parse_json(text).map_err(|_| "grant history header is malformed")?;
        let fields = value
            .as_object()
            .ok_or("grant history header is malformed")?;
        let expected = [
            "history_version",
            "history_id",
            "tenant_id",
            "node_id",
            "issuer_key_id",
            "pruned_through_ms",
            "highest_issuer_epoch",
        ];
        if fields.len() != expected.len()
            || fields
                .iter()
                .any(|(key, _)| !expected.contains(&key.as_str()))
            || value
                .get("history_version")
                .and_then(|value| value.as_u64())
                != Some(1)
        {
            return Err("grant history header is malformed");
        }
        let text_field = |name| {
            value
                .get(name)
                .and_then(|value| value.as_str())
                .map(str::to_owned)
                .ok_or("grant history header is malformed")
        };
        let number = |name| {
            value
                .get(name)
                .and_then(|value| value.as_u64())
                .ok_or("grant history header is malformed")
        };
        let history = Self {
            history_id: text_field("history_id")?,
            tenant_id: text_field("tenant_id")?,
            node_id: text_field("node_id")?,
            issuer_key_id: text_field("issuer_key_id")?,
            pruned_through_ms: number("pruned_through_ms")?,
            highest_issuer_epoch: number("highest_issuer_epoch")?,
        };
        // Require exactly the broker's fixed format, including integer and
        // base64 spelling. Other complete lines fail closed on startup.
        if history.line()?.trim_end().as_bytes() != line {
            return Err("grant history header is not canonical");
        }
        Ok(history)
    }

    pub(super) fn line(&self) -> Result<String, &'static str> {
        let nonce = base64_url_decode(&self.history_id, 32)
            .filter(|bytes| bytes.len() == 32 && base64_url_encode(bytes) == self.history_id);
        let scope = [&self.tenant_id, &self.node_id, &self.issuer_key_id];
        if nonce.is_none()
            || !(scope.iter().all(|value| value.is_empty())
                || scope.iter().all(|value| is_valid_opaque_id(value)))
            || self.pruned_through_ms > MAX_SAFE_INTEGER
            || self.highest_issuer_epoch > MAX_SAFE_INTEGER
            || (self.is_bound() && self.highest_issuer_epoch == 0)
            || (!self.is_bound() && (self.pruned_through_ms != 0 || self.highest_issuer_epoch != 0))
        {
            return Err("grant history header is malformed");
        }
        Ok(format!(
            "{{\"history_version\":1,\"history_id\":\"{}\",\"tenant_id\":\"{}\",\"node_id\":\"{}\",\"issuer_key_id\":\"{}\",\"pruned_through_ms\":{},\"highest_issuer_epoch\":{}}}\n",
            self.history_id,
            self.tenant_id,
            self.node_id,
            self.issuer_key_id,
            self.pruned_through_ms,
            self.highest_issuer_epoch,
        ))
    }
}

pub(super) fn initialize(path: &Path) -> Result<(), &'static str> {
    let mut nonce = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|_| "grant history randomness is unavailable")?;
    let history = ConsumptionHistory {
        history_id: base64_url_encode(&nonce),
        tenant_id: String::new(),
        node_id: String::new(),
        issuer_key_id: String::new(),
        pruned_through_ms: 0,
        highest_issuer_epoch: 0,
    };
    let line = history.line()?;
    let parent = path.parent().ok_or("grant history parent is unavailable")?;
    // Publish atomically: a crash while writing must never leave a torn
    // header at the final path, which would fail closed forever. The link
    // fails if a journal already exists; the private directory is ours.
    let staged = parent.join(".consumed-genesis.tmp");
    match std::fs::remove_file(&staged) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("grant history genesis could not be staged"),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(NO_FOLLOW)
        .open(&staged)
        .map_err(|_| "grant history genesis could not be created")?;
    let written = file
        .write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "grant history genesis could not be flushed");
    let published = written.and_then(|()| {
        std::fs::hard_link(&staged, path)
            .map_err(|_| "grant history genesis could not be published")
    });
    let _ = std::fs::remove_file(&staged);
    published?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "grant history directory could not be synchronized")
}

pub(super) fn bind(path: &Path, pin: &PinnedIssuer) -> Result<u64, &'static str> {
    let _lock = super::lock_consumption_journal(path)?;
    let journal = GrantJournal::read_locked(path)?;
    let observed = journal
        .history
        .as_ref()
        .map_or(0, |history| history.highest_issuer_epoch)
        .max(
            journal
                .bindings
                .values()
                .map(|binding| binding.issuer_epoch)
                .max()
                .unwrap_or(0),
        );
    let Some(mut history) = journal.history.clone() else {
        // Legacy or missing history remains unknown. Existing one-use
        // consumption stays supported, without an invented recovery proof.
        return Ok(observed);
    };
    if history.is_bound() {
        if history.tenant_id != pin.tenant_id
            || history.node_id != pin.node_id
            || history.issuer_key_id != pin.key_id
        {
            return Err("grant history is bound to another controller scope");
        }
    } else if !journal.consumed.is_empty() {
        return Err("grant history cannot bind after consumption");
    }
    history.tenant_id.clone_from(&pin.tenant_id);
    history.node_id.clone_from(&pin.node_id);
    history.issuer_key_id.clone_from(&pin.key_id);
    history.highest_issuer_epoch = history.highest_issuer_epoch.max(pin.epoch);
    if journal.history.as_ref() == Some(&history) {
        return Ok(observed);
    }
    journal.rewrite(&journal.consumed, Some(&history))?;
    Ok(observed)
}
