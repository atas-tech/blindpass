// SPDX-License-Identifier: AGPL-3.0-only

//! Broker-owned node identity and controller pin storage.

use crate::BrokerError;
use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::fleet::SignedEnvelope;
use blindpass_core::fleet::{
    DocumentKind, NodeKeyRotation, NodeRevocation, Registration, enrollment_proof_message,
    node_event_message, node_key_fingerprint, node_session_challenge_message,
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
const KEY_MATERIAL_BYTES: usize = 137;
const ROTATION_ID_BYTES: usize = 64;
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

struct NodeKeyMaterial {
    signing: Ed25519KeyPair,
    recipient: RecipientKeyPair,
    version: u64,
    last_rotation_id: Option<String>,
}

pub struct NodeIdentity {
    keys: Mutex<NodeKeyMaterial>,
    staged_rotation: Mutex<Option<NodeKeyMaterial>>,
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
        let identity_path = directory.join("node-identity.state");
        let keys = match read_key_material(&identity_path) {
            Ok(keys) => keys,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let keys = load_legacy_key_material(directory)?;
                write_key_material(&identity_path, &keys)?;
                keys
            }
            Err(_) => {
                return Err(BrokerError::Configuration(
                    "node identity state is unsafe or unreadable",
                ));
            }
        };
        // A crash between publishing the canonical state and unlinking a
        // legacy seed must not leave a second copy of either private key.
        remove_legacy_keys(directory)?;
        let staged_rotation = match read_key_material(&directory.join("node-rotation.pending")) {
            Ok(staged) if staged.version == keys.version.saturating_add(1) => Some(staged),
            Ok(stale) if stale.version <= keys.version => {
                drop(stale);
                let _ = fs::remove_file(directory.join("node-rotation.pending"));
                None
            }
            Ok(_) => {
                return Err(BrokerError::Configuration(
                    "staged node key rotation has an invalid version",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => {
                return Err(BrokerError::Configuration(
                    "staged node key rotation is unsafe or unreadable",
                ));
            }
        };
        let pin = read_pin(directory)?;
        Ok(Self {
            keys: Mutex::new(keys),
            staged_rotation: Mutex::new(staged_rotation),
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
    pub fn pending_node_events_path(&self) -> PathBuf {
        self.directory.join("pending-node-events.jsonl")
    }

    pub fn public_identity(&self) -> Result<PublicIdentity, BrokerError> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))?;
        Ok(PublicIdentity {
            signing_public: base64_url_encode(keys.signing.public_key()),
            recipient_public: base64_url_encode(keys.recipient.public_key()),
            fingerprint: node_key_fingerprint(
                keys.signing.public_key(),
                keys.recipient.public_key(),
            )
            .map_err(|_| BrokerError::Configuration("node key fingerprint failed"))?,
        })
    }

    pub fn key_version(&self) -> Result<u64, BrokerError> {
        self.keys
            .lock()
            .map(|keys| keys.version)
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))
    }

    /// Generate and persist a replacement key pair without changing the
    /// active identity. Repeated calls return the same staged public keys.
    pub fn prepare_rotation(&self) -> Result<(u64, PublicIdentity), BrokerError> {
        let active = self
            .keys
            .lock()
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))?;
        let mut staged = self
            .staged_rotation
            .lock()
            .map_err(|_| BrokerError::Configuration("staged node key state is unavailable"))?;
        if staged.is_none() {
            let version = active
                .version
                .checked_add(1)
                .ok_or(BrokerError::Configuration("node key version is exhausted"))?;
            let candidate = NodeKeyMaterial::generate(version)?;
            write_key_material(&self.directory.join("node-rotation.pending"), &candidate)?;
            *staged = Some(candidate);
        }
        let candidate = staged.as_ref().ok_or(BrokerError::Configuration(
            "staged node key state is unavailable",
        ))?;
        Ok((candidate.version, public_identity(candidate)?))
    }

    /// Activate only the exact broker-generated candidate named by a signed
    /// controller rotation document. The active key pair and version are
    /// committed in one atomic state-file replacement.
    pub fn apply_key_rotation(&self, rotation: &NodeKeyRotation) -> Result<(), BrokerError> {
        let pin = self.pinned_issuer()?.ok_or(BrokerError::Configuration(
            "controller issuer is not pinned",
        ))?;
        if rotation.node_id != pin.node_id {
            return Err(BrokerError::Configuration(
                "node key rotation is bound to another node",
            ));
        }
        let mut active = self
            .keys
            .lock()
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))?;
        if active.version == rotation.to_key_version
            && active.last_rotation_id.as_deref() == Some(rotation.rotation_id.as_str())
            && public_identity(&active)?.fingerprint == rotation.fingerprint
        {
            return Ok(());
        }
        let mut staged = self
            .staged_rotation
            .lock()
            .map_err(|_| BrokerError::Configuration("staged node key state is unavailable"))?;
        let candidate = staged.take().ok_or(BrokerError::Configuration(
            "node key rotation was not prepared",
        ))?;
        let candidate_public = public_identity(&candidate)?;
        if rotation.from_key_version != active.version
            || rotation.to_key_version != candidate.version
            || rotation.to_key_version != rotation.from_key_version.saturating_add(1)
            || candidate_public.signing_public != rotation.signing_public
            || candidate_public.recipient_public != rotation.recipient_public
            || candidate_public.fingerprint != rotation.fingerprint
        {
            *staged = Some(candidate);
            return Err(BrokerError::Configuration(
                "node key rotation does not match the prepared identity",
            ));
        }
        let replacement = NodeKeyMaterial {
            last_rotation_id: Some(rotation.rotation_id.clone()),
            ..candidate
        };
        if let Err(error) =
            write_key_material(&self.directory.join("node-identity.state"), &replacement)
        {
            *staged = Some(replacement);
            return Err(error);
        }
        *active = replacement;
        let _ = fs::remove_file(self.directory.join("node-rotation.pending"));
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    pub fn applied_rotation_ack(&self) -> Result<Option<(String, u64, String)>, BrokerError> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))?;
        let Some(rotation_id) = keys.last_rotation_id.as_ref() else {
            return Ok(None);
        };
        let identity = public_identity(&keys)?;
        Ok(Some((
            rotation_id.clone(),
            keys.version,
            identity.fingerprint,
        )))
    }

    pub fn acknowledge_rotation_event(&self, event_keys: &[String]) -> Result<(), BrokerError> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))?;
        let Some(rotation_id) = keys.last_rotation_id.as_ref() else {
            return Ok(());
        };
        let expected_key = rotation_ack_event_key(rotation_id);
        if !event_keys.iter().any(|key| key == &expected_key) {
            return Ok(());
        }
        let previous = keys.last_rotation_id.take();
        if let Err(error) = write_key_material(&self.directory.join("node-identity.state"), &keys) {
            keys.last_rotation_id = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn enrollment_proof(&self, token: &str) -> Result<String, BrokerError> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))?;
        let mut message = enrollment_proof_message(
            token,
            keys.signing.public_key(),
            keys.recipient.public_key(),
        )
        .map_err(|_| BrokerError::Configuration("invalid enrollment proof request"))?;
        let signature = keys.signing.sign(&message);
        wipe(&mut message);
        let signature = signature?;
        Ok(base64_url_encode(&signature))
    }

    #[allow(clippy::too_many_arguments)] // The signed channel transcript is intentionally explicit.
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
        let keys = self
            .keys
            .lock()
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))?;
        if pin.tenant_id != tenant_id
            || pin.node_id != node_id
            || pin.epoch != issuer_epoch
            || key_version != keys.version
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
        let signature = keys.signing.sign(&message);
        wipe(&mut message);
        Ok(base64_url_encode(&signature?))
    }

    pub(crate) fn sign_node_event(
        &self,
        node_id: &str,
        idempotency_key: &str,
        kind: &str,
        body: &blindpass_core::canon::Value,
    ) -> Result<String, BrokerError> {
        let pin = self.pinned_issuer()?.ok_or(BrokerError::Configuration(
            "controller issuer is not pinned",
        ))?;
        if pin.node_id != node_id {
            return Err(BrokerError::Configuration(
                "node event does not match the enrolled identity",
            ));
        }
        let keys = self
            .keys
            .lock()
            .map_err(|_| BrokerError::Configuration("node key state is unavailable"))?;
        let mut message = node_event_message(node_id, idempotency_key, kind, body)
            .map_err(|_| BrokerError::Configuration("invalid broker event"))?;
        let signature = keys.signing.sign(&message);
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
            DocumentKind::NodeRevocation => {
                let revocation = NodeRevocation::from_value(envelope.body()).map_err(|_| {
                    BrokerError::Configuration("controller node revocation is malformed")
                })?;
                if !valid_state_component(&revocation.node_id) {
                    return Err(BrokerError::Configuration(
                        "controller node revocation id is invalid",
                    ));
                }
                format!("node-revocation-{}.json", revocation.node_id)
            }
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
                || (file_name.starts_with("node-revocation-") && file_name.ends_with(".json"))
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

pub(crate) fn rotation_ack_event_key(rotation_id: &str) -> String {
    format!("rotation_{rotation_id}")
}

fn valid_state_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

impl NodeKeyMaterial {
    fn generate(version: u64) -> Result<Self, BrokerError> {
        if version == 0 {
            return Err(BrokerError::Configuration("node key version is invalid"));
        }
        Ok(Self {
            signing: Ed25519KeyPair::generate()?,
            recipient: RecipientKeyPair::generate()?,
            version,
            last_rotation_id: None,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, BrokerError> {
        if self.version == 0 {
            return Err(BrokerError::Configuration("node key version is invalid"));
        }
        let mut bytes = vec![0; KEY_MATERIAL_BYTES];
        bytes[..8].copy_from_slice(&self.version.to_be_bytes());
        bytes[8..40].copy_from_slice(self.signing.seed_bytes());
        bytes[40..72].copy_from_slice(self.recipient.private_key_bytes());
        if let Some(rotation_id) = &self.last_rotation_id {
            if rotation_id.is_empty() || rotation_id.len() > ROTATION_ID_BYTES {
                wipe(&mut bytes);
                return Err(BrokerError::Configuration("node rotation id is invalid"));
            }
            bytes[72] = u8::try_from(rotation_id.len())
                .map_err(|_| BrokerError::Configuration("node rotation id is invalid"))?;
            bytes[73..73 + rotation_id.len()].copy_from_slice(rotation_id.as_bytes());
        }
        Ok(bytes)
    }
}

fn public_identity(keys: &NodeKeyMaterial) -> Result<PublicIdentity, BrokerError> {
    Ok(PublicIdentity {
        signing_public: base64_url_encode(keys.signing.public_key()),
        recipient_public: base64_url_encode(keys.recipient.public_key()),
        fingerprint: node_key_fingerprint(keys.signing.public_key(), keys.recipient.public_key())
            .map_err(|_| BrokerError::Configuration("node key fingerprint failed"))?,
    })
}

fn load_legacy_key_material(directory: &Path) -> Result<NodeKeyMaterial, BrokerError> {
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
    Ok(NodeKeyMaterial {
        signing,
        recipient,
        version: 1,
        last_rotation_id: None,
    })
}

fn read_key_material(path: &Path) -> std::io::Result<NodeKeyMaterial> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() != KEY_MATERIAL_BYTES as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe node identity state",
        ));
    }
    let mut bytes = Vec::with_capacity(KEY_MATERIAL_BYTES);
    file.read_to_end(&mut bytes)?;
    let result = decode_key_material(&bytes);
    wipe(&mut bytes);
    result.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid node identity state",
        )
    })
}

fn decode_key_material(bytes: &[u8]) -> Result<NodeKeyMaterial, BrokerError> {
    if bytes.len() != KEY_MATERIAL_BYTES {
        return Err(BrokerError::Configuration(
            "node identity state is malformed",
        ));
    }
    let version = u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| BrokerError::Configuration("node identity state is malformed"))?,
    );
    let rotation_len = usize::from(bytes[72]);
    if version == 0 || rotation_len > ROTATION_ID_BYTES {
        return Err(BrokerError::Configuration(
            "node identity state is malformed",
        ));
    }
    let rotation_bytes = &bytes[73..73 + rotation_len];
    if bytes[73 + rotation_len..].iter().any(|byte| *byte != 0) {
        return Err(BrokerError::Configuration(
            "node identity state is malformed",
        ));
    }
    let last_rotation_id = if rotation_len == 0 {
        None
    } else {
        let value = std::str::from_utf8(rotation_bytes)
            .map_err(|_| BrokerError::Configuration("node identity state is malformed"))?;
        if !valid_state_component(value) {
            return Err(BrokerError::Configuration(
                "node identity state is malformed",
            ));
        }
        Some(value.to_owned())
    };
    let mut signing_seed = bytes[8..40].to_vec();
    let signing_result = Ed25519KeyPair::from_seed(&signing_seed);
    wipe(&mut signing_seed);
    let signing = signing_result?;
    let mut recipient_seed = bytes[40..72].to_vec();
    let recipient_result = RecipientKeyPair::from_private_key(&recipient_seed);
    wipe(&mut recipient_seed);
    let recipient = recipient_result?;
    Ok(NodeKeyMaterial {
        signing,
        recipient,
        version,
        last_rotation_id,
    })
}

fn write_key_material(path: &Path, keys: &NodeKeyMaterial) -> Result<(), BrokerError> {
    let mut bytes = keys.encode()?;
    let result = atomic_write_private(path, &bytes);
    wipe(&mut bytes);
    result
}

fn remove_legacy_keys(directory: &Path) -> Result<(), BrokerError> {
    for name in ["node-signing.seed", "node-recipient.key"] {
        match fs::remove_file(directory.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(BrokerError::Configuration(
                    "legacy node key files could not be retired",
                ));
            }
        }
    }
    File::open(directory)?.sync_all()?;
    Ok(())
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
    use blindpass_core::fleet::NodeKeyRotation;
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
        assert_eq!(second.key_version().unwrap(), 1);
        assert_eq!(
            std::fs::metadata(directory.join("node-identity.state"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!directory.join("node-signing.seed").exists());
        assert!(!directory.join("node-recipient.key").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn node_key_rotation_is_staged_persistent_atomic_and_acknowledged() {
        let directory = temporary_directory();
        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let old_public = identity.public_identity().unwrap();
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

        let (candidate_version, candidate_public) = identity.prepare_rotation().unwrap();
        assert_eq!(candidate_version, 2);
        assert_eq!(identity.key_version().unwrap(), 1);
        assert_eq!(identity.public_identity().unwrap(), old_public);
        drop(identity);

        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let (restored_version, restored_candidate) = identity.prepare_rotation().unwrap();
        assert_eq!(restored_version, 2);
        assert_eq!(restored_candidate, candidate_public);
        let rotation = NodeKeyRotation {
            node_id: "nd_a".to_owned(),
            rotation_id: "rot_test_rotation_000000000001".to_owned(),
            from_key_version: 1,
            to_key_version: 2,
            signing_public: candidate_public.signing_public.clone(),
            recipient_public: candidate_public.recipient_public.clone(),
            fingerprint: candidate_public.fingerprint.clone(),
            issuer_epoch: 1,
        };

        let mut mismatched = rotation.clone();
        mismatched.fingerprint = "0".repeat(64);
        assert!(identity.apply_key_rotation(&mismatched).is_err());
        assert_eq!(identity.key_version().unwrap(), 1);
        assert_eq!(identity.public_identity().unwrap(), old_public);

        identity.apply_key_rotation(&rotation).unwrap();
        identity.apply_key_rotation(&rotation).unwrap();
        assert_eq!(identity.key_version().unwrap(), 2);
        assert_eq!(identity.public_identity().unwrap(), candidate_public);
        assert_eq!(
            identity.applied_rotation_ack().unwrap(),
            Some((
                rotation.rotation_id.clone(),
                2,
                candidate_public.fingerprint.clone()
            ))
        );
        drop(identity);

        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        assert_eq!(identity.key_version().unwrap(), 2);
        assert_eq!(identity.public_identity().unwrap(), candidate_public);
        assert!(
            identity
                .acknowledge_rotation_event(&["unrelated-event-key".to_owned()])
                .is_ok()
        );
        assert!(identity.applied_rotation_ack().unwrap().is_some());
        identity
            .acknowledge_rotation_event(&[super::rotation_ack_event_key(&rotation.rotation_id)])
            .unwrap();
        assert_eq!(identity.applied_rotation_ack().unwrap(), None);
        drop(identity);
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
            directory.join("node-identity.state"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(NodeIdentity::load_or_create(&directory).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
