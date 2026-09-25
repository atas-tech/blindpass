// SPDX-License-Identifier: AGPL-3.0-only

//! Durable bounded node event queue. The relay stores broker-signed event
//! documents before forwarding them and removes them only after broker-verified
//! controller acknowledgement.

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::signing::base64_url_decode;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_EVENTS: usize = 1_000;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_OUTBOX_BYTES: u64 = MAX_EVENTS as u64 * MAX_EVENT_BYTES as u64;
const PRIVATE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
const O_NOFOLLOW: i32 = 0x20000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeEvent {
    pub idempotency_key: String,
    pub kind: String,
    pub body: Value,
    pub broker_signature: String,
}

impl NodeEvent {
    pub(crate) fn from_value(value: &Value) -> Result<Self, &'static str> {
        let fields = value
            .as_object()
            .filter(|fields| fields.len() == 4)
            .ok_or("node event is malformed")?;
        if fields.iter().any(|(name, _)| {
            !matches!(
                name.as_str(),
                "idempotency_key" | "kind" | "body" | "broker_signature"
            )
        }) {
            return Err("node event fields are malformed");
        }
        let idempotency_key = value
            .get("idempotency_key")
            .and_then(Value::as_str)
            .filter(|key| valid_key(key))
            .ok_or("node event key is malformed")?;
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .filter(|kind| matches!(*kind, "operation_request" | "operation_result" | "audit"))
            .ok_or("node event kind is malformed")?;
        let body = value
            .get("body")
            .filter(|body| body.as_object().is_some())
            .cloned()
            .ok_or("node event body is malformed")?;
        let broker_signature = value
            .get("broker_signature")
            .and_then(Value::as_str)
            .filter(|signature| base64_url_decode(signature, 64).is_some())
            .ok_or("node event signature is malformed")?;
        Ok(Self {
            idempotency_key: idempotency_key.to_owned(),
            kind: kind.to_owned(),
            body,
            broker_signature: broker_signature.to_owned(),
        })
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Object(vec![
            ("body".to_owned(), self.body.clone()),
            (
                "broker_signature".to_owned(),
                Value::String(self.broker_signature.clone()),
            ),
            (
                "idempotency_key".to_owned(),
                Value::String(self.idempotency_key.clone()),
            ),
            ("kind".to_owned(), Value::String(self.kind.clone())),
        ])
    }
}

#[derive(Debug)]
pub(crate) struct Outbox {
    directory: PathBuf,
    events: Vec<NodeEvent>,
}

impl Outbox {
    pub(crate) fn open(directory: &Path) -> Result<Self, &'static str> {
        ensure_directory(directory)?;
        let path = directory.join("outbox.jsonl");
        let events = read_events(&path)?;
        Ok(Self {
            directory: directory.to_owned(),
            events,
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn free_slots(&self) -> usize {
        MAX_EVENTS.saturating_sub(self.events.len())
    }

    pub(crate) fn first_batch(&self, limit: usize) -> Vec<NodeEvent> {
        self.events.iter().take(limit.min(100)).cloned().collect()
    }

    pub(crate) fn insert_batch(&mut self, events: Vec<NodeEvent>) -> Result<(), &'static str> {
        let mut updated = self.events.clone();
        for event in events {
            NodeEvent::from_value(&event.to_value())?;
            let encoded = canonicalize_value(&event.to_value())
                .map_err(|_| "node event could not be encoded")?;
            if encoded.len() > MAX_EVENT_BYTES || !valid_key(&event.idempotency_key) {
                return Err("node event exceeds its configured size bound");
            }
            if let Some(existing) = updated
                .iter()
                .find(|existing| existing.idempotency_key == event.idempotency_key)
            {
                if existing != &event {
                    return Err("node event key was reused with different bytes");
                }
            } else {
                updated.push(event);
            }
        }
        if updated.len() > MAX_EVENTS {
            return Err("node event outbox is full");
        }
        persist_events(&self.directory, &updated)?;
        self.events = updated;
        Ok(())
    }

    pub(crate) fn remove_acked(&mut self, event_keys: &[String]) -> Result<(), &'static str> {
        let acknowledged = event_keys.iter().collect::<HashSet<_>>();
        let updated = self
            .events
            .iter()
            .filter(|event| !acknowledged.contains(&event.idempotency_key))
            .cloned()
            .collect::<Vec<_>>();
        if updated.len() != self.events.len() {
            persist_events(&self.directory, &updated)?;
            self.events = updated;
        }
        Ok(())
    }
}

fn ensure_directory(directory: &Path) -> Result<(), &'static str> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) => validate_directory(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(directory).map_err(|_| "node state directory is unavailable")?;
            fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|_| "node state directory permissions are unsafe")?;
            File::open(
                directory
                    .parent()
                    .ok_or("node state directory is invalid")?,
            )
            .and_then(|parent| parent.sync_all())
            .map_err(|_| "node state directory could not be synchronized")?;
        }
        Err(_) => return Err("node state directory could not be inspected safely"),
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| "node state directory could not be inspected safely")?;
    validate_directory(&metadata)
}

fn validate_directory(metadata: &fs::Metadata) -> Result<(), &'static str> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != DIRECTORY_MODE
    {
        return Err("node state directory ownership or mode is unsafe");
    }
    Ok(())
}

fn read_events(path: &Path) -> Result<Vec<NodeEvent>, &'static str> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("node event outbox could not be opened safely"),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "node event outbox metadata is unavailable")?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != PRIVATE_MODE
        || metadata.len() > MAX_OUTBOX_BYTES
    {
        return Err("node event outbox ownership, mode or size is unsafe");
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut contents)
        .map_err(|_| "node event outbox could not be read")?;
    if !contents.is_empty() && contents.last() != Some(&b'\n') {
        return Err("node event outbox ends with an incomplete record");
    }
    let mut events = Vec::new();
    for line in contents
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > MAX_EVENT_BYTES {
            return Err("node event outbox contains an oversized record");
        }
        let source = std::str::from_utf8(line).map_err(|_| "node event outbox is malformed")?;
        let value = parse_json(source).map_err(|_| "node event outbox is malformed")?;
        events.push(NodeEvent::from_value(&value)?);
        if events.len() > MAX_EVENTS {
            return Err("node event outbox exceeds its event limit");
        }
    }
    Ok(events)
}

fn persist_events(directory: &Path, events: &[NodeEvent]) -> Result<(), &'static str> {
    if events.is_empty() {
        match fs::remove_file(directory.join("outbox.jsonl")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("node event outbox could not be cleared"),
        }
        return File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "node event outbox directory could not be synchronized");
    }
    let mut contents = Vec::new();
    for event in events {
        let line =
            canonicalize_value(&event.to_value()).map_err(|_| "node event could not be encoded")?;
        if line.len() > MAX_EVENT_BYTES {
            return Err("node event exceeds its configured size bound");
        }
        contents.extend_from_slice(&line);
        contents.push(b'\n');
    }
    if contents.len() as u64 > MAX_OUTBOX_BYTES {
        return Err("node event outbox is full");
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(".outbox-{}-{sequence}.tmp", std::process::id()));
    let destination = directory.join("outbox.jsonl");
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_MODE)
            .custom_flags(O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(&contents)?;
        file.sync_all()?;
        fs::rename(&temporary, destination)?;
        File::open(directory)?.sync_all()
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("node event outbox could not be committed");
    }
    Ok(())
}

fn valid_key(value: &str) -> bool {
    value.len() >= 16
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid takes no arguments and returns the calling process uid.
    unsafe { geteuid() }
}

#[cfg(test)]
mod tests {
    use super::{DIRECTORY_MODE, NodeEvent, Outbox, effective_uid};
    use blindpass_core::canon::Value;
    use blindpass_core::signing::base64_url_encode;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("blindpass-node-outbox-{nonce}"));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        path
    }

    fn event(key: &str) -> NodeEvent {
        NodeEvent {
            idempotency_key: key.to_owned(),
            kind: "audit".to_owned(),
            body: Value::Object(vec![("event".to_owned(), Value::String("test".to_owned()))]),
            broker_signature: base64_url_encode(&[7; 64]),
        }
    }

    #[test]
    fn outbox_persists_before_forwarding_and_removes_only_acknowledged_events() {
        let directory = directory();
        let mut outbox = Outbox::open(&directory).unwrap();
        outbox
            .insert_batch(vec![
                event("event-key-00000001"),
                event("event-key-00000002"),
            ])
            .unwrap();
        assert_eq!(outbox.len(), 2);
        drop(outbox);
        let mut restored = Outbox::open(&directory).unwrap();
        assert_eq!(restored.first_batch(10).len(), 2);
        restored
            .remove_acked(&["event-key-00000001".to_owned()])
            .unwrap();
        assert_eq!(
            restored.first_batch(10)[0].idempotency_key,
            "event-key-00000002"
        );
        assert_eq!(
            std::fs::metadata(directory.join("outbox.jsonl"))
                .unwrap()
                .uid(),
            effective_uid()
        );
        assert_eq!(
            std::fs::metadata(directory.join("outbox.jsonl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn outbox_rejects_overflow_and_conflicting_idempotency_keys() {
        let directory = directory();
        let mut outbox = Outbox::open(&directory).unwrap();
        outbox
            .insert_batch(vec![event("event-key-00000001")])
            .unwrap();
        let mut conflicting = event("event-key-00000001");
        conflicting.body = Value::Object(vec![(
            "event".to_owned(),
            Value::String("different".to_owned()),
        )]);
        assert!(outbox.insert_batch(vec![conflicting]).is_err());
        let overflow = (0..1_001)
            .map(|index| event(&format!("event-overflow-{index:08}")))
            .collect();
        assert!(outbox.insert_batch(overflow).is_err());
        assert_eq!(outbox.len(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn outbox_accepts_its_limit_then_stays_bounded_after_overflow() {
        let directory = directory();
        let mut outbox = Outbox::open(&directory).unwrap();
        let full = (0..1_000)
            .map(|index| event(&format!("event-capacity-{index:08}")))
            .collect();
        outbox.insert_batch(full).unwrap();
        assert_eq!(outbox.len(), 1_000);
        assert_eq!(outbox.free_slots(), 0);

        assert_eq!(
            outbox.insert_batch(vec![event("event-capacity-00001000")]),
            Err("node event outbox is full")
        );
        assert_eq!(outbox.len(), 1_000);
        drop(outbox);

        let restored = Outbox::open(&directory).unwrap();
        assert_eq!(restored.len(), 1_000);
        assert_eq!(restored.free_slots(), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
