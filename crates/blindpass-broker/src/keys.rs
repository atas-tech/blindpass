// SPDX-License-Identifier: AGPL-3.0-only

//! Broker-owned node identity and controller pin storage.

use crate::BrokerError;
use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::fleet::SignedEnvelope;
use blindpass_core::fleet::{
    DocumentKind, Registration, enrollment_proof_message, node_key_fingerprint,
    node_session_challenge_message,
};
use blindpass_core::secret::wipe;
use blindpass_core::signing::base64_url_decode;
use blindpass_core::signing::base64_url_encode;
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const PRIVATE_FILE_MODE: u32 = 0o600;
const KEY_DIRECTORY_MODE: u32 = 0o700;
const O_NOFOLLOW: i32 = 0x20000;
static STATE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    pub signing_public: String,
    pub recipient_public: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedIssuer {
    pub tenant_id: String,
    pub node_id: String,
    pub epoch: u64,
    pub key_id: String,
    pub public_key: String,
}

pub struct NodeIdentity {
    signing: Ed25519KeyPair,
    recipient: RecipientKeyPair,
    directory: PathBuf,
    pin: Mutex<Option<PinnedIssuer>>,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeIdentity")
            .field("directory", &self.directory)
            .field("private_keys", &"<redacted>")
            .field("pin", &self.pin)
            .finish()
    }
}

impl NodeIdentity {
    pub fn load_or_create(directory: &Path) -> Result<Self, BrokerError> {
        ensure_key_directory(directory)?;
        let signing_seed = load_or_create_secret(&directory.join("node-signing.seed"), || {
            let key = Ed25519KeyPair::generate()?;
            Ok(key.seed_bytes().to_vec())
        })?;
        let signing_result = Ed25519KeyPair::from_seed(&signing_seed);
        let mut signing_seed = signing_seed;
        wipe(&mut signing_seed);
        let signing = signing_result?;

        let recipient_seed = load_or_create_secret(&directory.join("node-recipient.key"), || {
            let key = RecipientKeyPair::generate()?;
            Ok(key.private_key_bytes().to_vec())
        })?;
        let recipient_result = RecipientKeyPair::from_private_key(&recipient_seed);
        let mut recipient_seed = recipient_seed;
        wipe(&mut recipient_seed);
        let recipient = recipient_result?;

        let pin = read_pin(directory)?;
        Ok(Self {
            signing,
            recipient,
            directory: directory.to_path_buf(),
            pin: Mutex::new(pin),
        })
    }

    #[must_use]
    pub fn consumed_grant_journal_path(&self) -> PathBuf {
        self.directory.join("consumed.jsonl")
    }

    #[must_use]
    pub fn revoked_grant_journal_path(&self) -> PathBuf {
        self.directory.join("revoked-grants.jsonl")
    }

    #[must_use]
    pub fn trusted_time_path(&self) -> PathBuf {
        self.directory.join("trusted-controller-time")
    }

    #[must_use]
    pub fn public_identity(&self) -> Result<PublicIdentity, BrokerError> {
        Ok(PublicIdentity {
            signing_public: base64_url_encode(self.signing.public_key()),
            recipient_public: base64_url_encode(self.recipient.public_key()),
            fingerprint: node_key_fingerprint(
                self.signing.public_key(),
                self.recipient.public_key(),
            )
            .map_err(|_| BrokerError::Configuration("node key fingerprint failed"))?,
        })
    }

    pub fn enrollment_proof(&self, token: &str) -> Result<String, BrokerError> {
        let mut message = enrollment_proof_message(
            token,
            self.signing.public_key(),
            self.recipient.public_key(),
        )
        .map_err(|_| BrokerError::Configuration("invalid enrollment proof request"))?;
        let signature = self.signing.sign(&message);
        wipe(&mut message);
        let signature = signature?;
        Ok(base64_url_encode(&signature))
    }

    pub fn node_challenge_signature(
        &self,
        tenant_id: &str,
        node_id: &str,
        protocol_version: &str,
        nonce: &str,
        capabilities_hash: &str,
        key_version: u64,
        issuer_epoch: u64,
        controller_time_ms: i64,
        expires_at_ms: i64,
    ) -> Result<String, BrokerError> {
        let pin = self.pinned_issuer()?.ok_or(BrokerError::Configuration(
            "controller issuer is not pinned",
        ))?;
        if pin.tenant_id != tenant_id
            || pin.node_id != node_id
            || pin.epoch != issuer_epoch
            || key_version != 1
        {
            return Err(BrokerError::Configuration(
                "node challenge does not match pinned identity",
            ));
        }
        let mut message = node_session_challenge_message(
            tenant_id,
            node_id,
            protocol_version,
            nonce,
            capabilities_hash,
            key_version,
            issuer_epoch,
            controller_time_ms,
            expires_at_ms,
        )
        .map_err(|_| BrokerError::Configuration("invalid node challenge request"))?;
        let signature = self.signing.sign(&message);
        wipe(&mut message);
        Ok(base64_url_encode(&signature?))
    }

    pub fn pin_issuer(&self, candidate: PinnedIssuer) -> Result<(), BrokerError> {
        validate_pin(&candidate)?;
        let mut current = self
            .pin
            .lock()
            .map_err(|_| BrokerError::Configuration("node issuer pin is unavailable"))?;
        if let Some(existing) = current.as_ref() {
            if existing == &candidate {
                return Ok(());
            }
            if existing.node_id != candidate.node_id || candidate.epoch <= existing.epoch {
                return Err(BrokerError::Configuration(
                    "issuer pin change requires the same node and a higher epoch",
                ));
            }
        }
        write_pin(&self.directory, &candidate)?;
        *current = Some(candidate);
        Ok(())
    }

    #[must_use]
    pub fn pinned_issuer(&self) -> Result<Option<PinnedIssuer>, BrokerError> {
        self.pin
            .lock()
            .map(|pin| pin.clone())
            .map_err(|_| BrokerError::Configuration("node issuer pin is unavailable"))
    }

    pub fn verify_controller_document(&self, document: &[u8]) -> Result<String, BrokerError> {
        let pin = self.pinned_issuer()?.ok_or(BrokerError::Configuration(
            "controller issuer is not pinned",
        ))?;
        let public_key = base64_url_decode(&pin.public_key, 32).ok_or(
            BrokerError::Configuration("controller issuer pin is invalid"),
        )?;
        let document = std::str::from_utf8(document)
            .map_err(|_| BrokerError::Configuration("controller document is malformed"))?;
        let envelope = SignedEnvelope::from_json(document)
            .map_err(|_| BrokerError::Configuration("controller document is malformed"))?;
        if !envelope
            .verify(&public_key, &pin.key_id, 1)
            .map_err(|_| BrokerError::Configuration("controller document verification failed"))?
        {
            return Err(BrokerError::Configuration(
                "controller document signature is invalid",
            ));
        }
        if envelope.epoch() < pin.epoch {
            // A delayed document from an older, but correctly signed, epoch
            // can be acknowledged by the channel without restoring authority.
            return Ok("stale_epoch".to_owned());
        }
        if envelope.epoch() > pin.epoch {
            let mut advanced_pin = pin;
            advanced_pin.epoch = envelope.epoch();
            self.pin_issuer(advanced_pin)?;
        }
        Ok(envelope.kind().as_str().to_owned())
    }

    /// Persist the latest verified registration or policy envelope for broker
    /// recovery. The signed bytes remain opaque to the relay and contain no
    /// secret payloads.
    pub fn persist_controller_document(&self, document: &[u8]) -> Result<(), BrokerError> {
        let source = std::str::from_utf8(document)
            .map_err(|_| BrokerError::Configuration("controller document is malformed"))?;
        let envelope = SignedEnvelope::from_json(source)
            .map_err(|_| BrokerError::Configuration("controller document is malformed"))?;
        let file_name = match envelope.kind() {
            DocumentKind::Registration => {
                let registration = Registration::from_value(envelope.body()).map_err(|_| {
                    BrokerError::Configuration("controller registration is malformed")
                })?;
                if !valid_state_component(&registration.workload_id) {
                    return Err(BrokerError::Configuration(
                        "controller registration id is invalid",
                    ));
                }
                format!("fleet-registration-{}.json", registration.workload_id)
            }
            DocumentKind::PolicySnapshot => "fleet-policy.json".to_owned(),
            _ => {
                return Err(BrokerError::Configuration(
                    "controller document is not durable fleet state",
                ));
            }
        };
        atomic_write_private(&self.directory.join(file_name), document)
    }

    /// Return bounded private fleet state documents in deterministic order.
    pub fn persisted_controller_documents(&self) -> Result<Vec<Vec<u8>>, BrokerError> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| BrokerError::Configuration("fleet state filename is invalid"))?;
            if file_name == "fleet-policy.json"
                || (file_name.starts_with("fleet-registration-") && file_name.ends_with(".json"))
            {
                paths.push(entry.path());
            }
        }
        paths.sort();
        paths
            .iter()
            .map(|path| read_private_document(path))
            .collect()
    }
}

fn valid_state_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), BrokerError> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(BrokerError::Configuration(
            "fleet state document size is invalid",
        ));
    }
    let parent = path.parent().ok_or(BrokerError::Configuration(
        "fleet state directory is invalid",
    ))?;
    let sequence = STATE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".fleet-state-{}-{sequence}.tmp",
        std::process::id()
    ));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(BrokerError::Configuration(
            "fleet state document could not be persisted",
        ));
    }
    Ok(())
}

fn read_private_document(path: &Path) -> Result<Vec<u8>, BrokerError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() == 0
        || metadata.len() > 64 * 1024
    {
        return Err(BrokerError::Configuration("fleet state document is unsafe"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn ensure_key_directory(directory: &Path) -> Result<(), BrokerError> {
    fs::create_dir_all(directory)?;
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != effective_uid()
    {
        return Err(BrokerError::Configuration(
            "node key directory must be a real directory owned by the broker",
        ));
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(KEY_DIRECTORY_MODE))?;
    Ok(())
}

fn load_or_create_secret<F>(path: &Path, generate: F) -> Result<Vec<u8>, BrokerError>
where
    F: FnOnce() -> Result<Vec<u8>, BrokerError>,
{
    match read_private_file(path) {
        Ok(bytes) => return Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(BrokerError::Configuration(
                "node private key file is unsafe or unreadable",
            ));
        }
    }
    let mut bytes = generate()?;
    if bytes.len() != 32 {
        wipe(&mut bytes);
        return Err(BrokerError::Configuration(
            "node private key has invalid size",
        ));
    }
    let create_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(O_NOFOLLOW)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()
    })();
    wipe(&mut bytes);
    if create_result.is_err() {
        return Err(BrokerError::Configuration(
            "node private key could not be persisted",
        ));
    }
    File::open(
        path.parent()
            .ok_or(BrokerError::Configuration("node key directory is invalid"))?,
    )?
    .sync_all()?;
    read_private_file(path).map_err(|_| {
        BrokerError::Configuration("persisted node private key is unsafe or unreadable")
    })
}

fn read_private_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() != 32
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe node key file",
        ));
    }
    let mut bytes = Vec::with_capacity(32);
    file.read_to_end(&mut bytes)?;
    if bytes.len() != 32 {
        wipe(&mut bytes);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid node key length",
        ));
    }
    Ok(bytes)
}

fn read_pin(directory: &Path) -> Result<Option<PinnedIssuer>, BrokerError> {
    let path = directory.join("issuer.pin");
    let bytes = match read_metadata_file(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(BrokerError::Configuration(
                "issuer pin file is unsafe or unreadable",
            ));
        }
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| BrokerError::Configuration("issuer pin file is malformed"))?;
    let mut parts = text.split('|');
    let tenant_id = parts.next().unwrap_or_default().to_owned();
    let node_id = parts.next().unwrap_or_default().to_owned();
    let epoch_text = parts.next().unwrap_or_default();
    let epoch = epoch_text
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == epoch_text)
        .ok_or(BrokerError::Configuration("issuer pin file is malformed"))?;
    let pin = PinnedIssuer {
        tenant_id,
        node_id,
        epoch,
        key_id: parts.next().unwrap_or_default().to_owned(),
        public_key: parts.next().unwrap_or_default().to_owned(),
    };
    if parts.next().is_some() {
        return Err(BrokerError::Configuration("issuer pin file is malformed"));
    }
    validate_pin(&pin)?;
    Ok(Some(pin))
}

fn read_metadata_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() > 512
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe issuer pin file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_pin(directory: &Path, pin: &PinnedIssuer) -> Result<(), BrokerError> {
    let content = format!(
        "{}|{}|{}|{}|{}",
        pin.tenant_id, pin.node_id, pin.epoch, pin.key_id, pin.public_key
    );
    let mut content = content.into_bytes();
    let path = directory.join("issuer.pin");
    let temporary = directory.join(format!(".issuer-pin-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(O_NOFOLLOW)
        .open(&temporary)?;
    let result = file.write_all(&content).and_then(|()| file.sync_all());
    wipe(&mut content);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(BrokerError::Configuration(
            "issuer pin could not be persisted",
        ));
    }
    fs::rename(&temporary, &path)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn validate_pin(pin: &PinnedIssuer) -> Result<(), BrokerError> {
    if !valid_identifier(&pin.tenant_id, 128)
        || !valid_identifier(&pin.node_id, 128)
        || pin.epoch == 0
        || !valid_identifier(&pin.key_id, 128)
        || pin.public_key.len() != 43
        || !pin
            .public_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || pin.key_id != format!("ed25519-{}", pin.public_key)
    {
        return Err(BrokerError::Configuration("issuer pin is invalid"));
    }
    Ok(())
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no arguments and returns the current effective UID.
    unsafe { geteuid() }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519KeyPair, NodeIdentity, PinnedIssuer};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "blindpass-node-keys-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        directory
    }

    #[test]
    fn node_keys_are_stable_and_private_files_are_0600() {
        let directory = temporary_directory();
        let first = NodeIdentity::load_or_create(&directory).unwrap();
        let public = first.public_identity().unwrap();
        let second = NodeIdentity::load_or_create(&directory).unwrap();
        assert_eq!(second.public_identity().unwrap(), public);
        assert_eq!(
            std::fs::metadata(directory.join("node-signing.seed"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(directory.join("node-recipient.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn issuer_pin_is_persistent_and_epoch_monotonic() {
        let directory = temporary_directory();
        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let pin = PinnedIssuer {
            tenant_id: "tenant-a".to_owned(),
            node_id: "nd_a".to_owned(),
            epoch: 1,
            public_key: blindpass_core::signing::base64_url_encode(&[9; 32]),
            key_id: format!(
                "ed25519-{}",
                blindpass_core::signing::base64_url_encode(&[9; 32])
            ),
        };
        identity.pin_issuer(pin.clone()).unwrap();
        assert!(
            identity
                .pin_issuer(PinnedIssuer {
                    epoch: 1,
                    key_id: format!(
                        "ed25519-{}",
                        blindpass_core::signing::base64_url_encode(&[10; 32])
                    ),
                    public_key: blindpass_core::signing::base64_url_encode(&[10; 32]),
                    ..pin.clone()
                })
                .is_err()
        );
        drop(identity);
        let loaded = NodeIdentity::load_or_create(&directory).unwrap();
        assert_eq!(loaded.pinned_issuer().unwrap(), Some(pin));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn node_channel_signature_is_limited_to_pinned_node_and_epoch() {
        let directory = temporary_directory();
        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let public = identity.public_identity().unwrap();
        identity
            .pin_issuer(PinnedIssuer {
                tenant_id: "tenant-a".to_owned(),
                node_id: "nd_a".to_owned(),
                epoch: 1,
                key_id: format!(
                    "ed25519-{}",
                    blindpass_core::signing::base64_url_encode(&[9; 32])
                ),
                public_key: blindpass_core::signing::base64_url_encode(&[9; 32]),
            })
            .unwrap();
        let nonce = blindpass_core::signing::base64_url_encode(&[3; 32]);
        let signature = identity
            .node_challenge_signature(
                "tenant-a",
                "nd_a",
                "blindpass-node/1",
                &nonce,
                &"a".repeat(64),
                1,
                1,
                1_800_000_000_000,
                1_800_000_060_000,
            )
            .unwrap();
        let message = blindpass_core::fleet::node_session_challenge_message(
            "tenant-a",
            "nd_a",
            "blindpass-node/1",
            &nonce,
            &"a".repeat(64),
            1,
            1,
            1_800_000_000_000,
            1_800_000_060_000,
        )
        .unwrap();
        let signature = blindpass_core::signing::base64_url_decode(&signature, 64).unwrap();
        let public =
            blindpass_core::signing::base64_url_decode(&public.signing_public, 32).unwrap();
        assert!(blindpass_core::signing::ed25519::verify(&public, &message, &signature).unwrap());
        assert!(
            identity
                .node_challenge_signature(
                    "tenant-b",
                    "nd_a",
                    "blindpass-node/1",
                    &nonce,
                    &"a".repeat(64),
                    1,
                    1,
                    1_800_000_000_000,
                    1_800_000_060_000,
                )
                .is_err()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn verified_controller_documents_advance_the_persisted_epoch() {
        let directory = temporary_directory();
        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let issuer = Ed25519KeyPair::from_seed(&[9; 32]).unwrap();
        let issuer_public = blindpass_core::signing::base64_url_encode(issuer.public_key());
        let issuer_key_id = format!("ed25519-{issuer_public}");
        identity
            .pin_issuer(PinnedIssuer {
                tenant_id: "tenant-a".to_owned(),
                node_id: "nd_a".to_owned(),
                epoch: 1,
                key_id: issuer_key_id.clone(),
                public_key: issuer_public,
            })
            .unwrap();
        let document = blindpass_core::fleet::SignedEnvelope::sign(
            blindpass_core::fleet::DocumentKind::TimeReply,
            blindpass_core::fleet::TimeReply {
                node_id: "nd_a".to_owned(),
                challenge: "challenge-1".to_owned(),
                controller_time_ms: 1_800_000_000_000,
                issuer_epoch: 2,
            }
            .to_value()
            .unwrap(),
            &issuer_key_id,
            2,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            identity.verify_controller_document(&document).unwrap(),
            "time_reply"
        );
        assert_eq!(identity.pinned_issuer().unwrap().unwrap().epoch, 2);

        let stale_document = blindpass_core::fleet::SignedEnvelope::sign(
            blindpass_core::fleet::DocumentKind::TimeReply,
            blindpass_core::fleet::TimeReply {
                node_id: "nd_a".to_owned(),
                challenge: "challenge-2".to_owned(),
                controller_time_ms: 1_800_000_000_000,
                issuer_epoch: 1,
            }
            .to_value()
            .unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            identity
                .verify_controller_document(&stale_document)
                .unwrap(),
            "stale_epoch"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unsafe_node_key_permissions_fail_closed() {
        let directory = temporary_directory();
        let _ = NodeIdentity::load_or_create(&directory).unwrap();
        std::fs::set_permissions(
            directory.join("node-signing.seed"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(NodeIdentity::load_or_create(&directory).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
