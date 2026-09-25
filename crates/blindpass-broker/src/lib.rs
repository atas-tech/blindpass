// SPDX-License-Identifier: AGPL-3.0-only

//! Privileged local broker transport.
//!
//! The loader and workload sockets intentionally share no listener and no
//! authorization path. The loader requires a root peer plus a pidfd-resolved
//! system unit/invocation. The workload socket requires a registered
//! non-root unit/account/invocation tuple.

mod control;
mod grants;
mod keys;
mod ops;
pub mod os_identity;

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::{CryptoError, EphemeralCustody};
use blindpass_core::delivery::{CredentialRegistry, DeliveryError, DeliveryPolicy};
use blindpass_core::fleet::{ConsumptionMode, PolicySnapshot, Registration};
use blindpass_core::identity::{
    IdentityError, LoaderPolicy, PeerIdentity, WorkloadRegistration, authorize_workload,
};
use blindpass_core::protocol::{
    ProtocolError, error_frame, parse_loader_request, parse_workload_request, workload_ok,
};
use blindpass_core::secret::SecretBytes;
use blindpass_core::{MAX_CREDENTIAL_BYTES, MAX_FRAME_BYTES};
use os_identity::{OsIdentityError, require_root_peer, resolve_peer};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::{CString, c_char};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt, chown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_ACTIVE_CONNECTIONS: usize = 32;
const DEFAULT_OPERATION_DIRECTORY: &str = "/run/blindpass/ops";
pub(crate) const MAX_BROKER_AUDIT_EVENTS: usize = 10_000;
const MAX_NODE_EVENT_BATCH: usize = 100;
const MAX_PENDING_NODE_EVENT_BYTES: usize = 64 * 1024;
const MAX_PENDING_NODE_EVENTS_BYTES: u64 = 64 * 1024 * 1024;
const PENDING_NODE_EVENT_FILE_MODE: u32 = 0o600;
const O_NOFOLLOW: i32 = 0x20000;
static PENDING_EVENT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
pub const DEFAULT_CUSTODY_KEY_LIFETIME: Duration = Duration::from_secs(30);
pub const DEFAULT_CREDENTIAL_LIFETIME: Duration = Duration::from_secs(60 * 60);

#[derive(Debug)]
pub enum BrokerError {
    Io(io::Error),
    Identity(IdentityError),
    Protocol(ProtocolError),
    OsIdentity(OsIdentityError),
    Delivery(DeliveryError),
    Crypto(CryptoError),
    Configuration(&'static str),
}

/// Deliberately malformed loader responses used only by the disposable P01
/// guest harness. The production unit never enables this hook; keeping the
/// mutation in the broker path lets the VM exercise the actual loader,
/// socket, and consumer boundaries instead of only testing files in isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryFault {
    Empty,
    Partial,
    Malformed,
    Oversized,
    Corrupt,
}

impl DeliveryFault {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "empty" => Ok(Self::Empty),
            "partial" => Ok(Self::Partial),
            "malformed" => Ok(Self::Malformed),
            "oversized" => Ok(Self::Oversized),
            "corrupt" => Ok(Self::Corrupt),
            _ => Err("delivery fault must be empty, partial, malformed, oversized or corrupt"),
        }
    }

    fn response(self, credential: &[u8]) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Partial => credential[..credential.len().min(2)].to_vec(),
            Self::Malformed => b"not-a-P01-credential".to_vec(),
            Self::Oversized => vec![0; MAX_CREDENTIAL_BYTES + 1],
            Self::Corrupt => {
                let mut response = credential.to_vec();
                if let Some(first) = response.first_mut() {
                    *first ^= 0x20;
                }
                response
            }
        }
    }
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io:{error}"),
            Self::Identity(error) => write!(formatter, "identity:{error}"),
            Self::Protocol(error) => write!(formatter, "protocol:{error}"),
            Self::OsIdentity(error) => write!(formatter, "os_identity:{error}"),
            Self::Delivery(error) => write!(formatter, "delivery:{error}"),
            Self::Crypto(error) => write!(formatter, "crypto:{error}"),
            Self::Configuration(error) => write!(formatter, "configuration:{error}"),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<io::Error> for BrokerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<IdentityError> for BrokerError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<ProtocolError> for BrokerError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<OsIdentityError> for BrokerError {
    fn from(error: OsIdentityError) -> Self {
        Self::OsIdentity(error)
    }
}

impl From<DeliveryError> for BrokerError {
    fn from(error: DeliveryError) -> Self {
        Self::Delivery(error)
    }
}

impl From<CryptoError> for BrokerError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[derive(Debug)]
pub struct BrokerState {
    pub loader_policy: LoaderPolicy,
    pub workloads: Vec<WorkloadRegistration>,
    fleet_registrations: BTreeMap<String, Registration>,
    fleet_policy: Option<PolicySnapshot>,
    grant_verifier: grants::GrantVerifier,
    operation_directory: PathBuf,
    pending_node_events: VecDeque<PendingNodeEvent>,
    pending_node_events_path: Option<PathBuf>,
    audit_overflow_pending: bool,
    node_revoked: bool,
    node_revocation_ack_pending: bool,
    node_revocation_acknowledged: bool,
    node_revocation_observed_at_ms: Option<u64>,
    pub credentials: CredentialRegistry,
    pub custody: EphemeralCustody,
    credential_expiries: BTreeMap<String, Instant>,
    credential_lifetime: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingNodeEvent {
    pub idempotency_key: String,
    pub kind: String,
    pub body: Value,
}

impl PendingNodeEvent {
    fn from_value(value: &Value) -> Result<Self, BrokerError> {
        let fields = value.as_object().filter(|fields| fields.len() == 3).ok_or(
            BrokerError::Configuration("pending node event is malformed"),
        )?;
        if fields
            .iter()
            .any(|(name, _)| !matches!(name.as_str(), "idempotency_key" | "kind" | "body"))
        {
            return Err(BrokerError::Configuration(
                "pending node event fields are malformed",
            ));
        }
        let idempotency_key = value
            .get("idempotency_key")
            .and_then(Value::as_str)
            .filter(|key| valid_node_event_key(key))
            .ok_or(BrokerError::Configuration(
                "pending node event key is malformed",
            ))?;
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .filter(|kind| matches!(*kind, "operation_request" | "operation_result" | "audit"))
            .ok_or(BrokerError::Configuration(
                "pending node event kind is malformed",
            ))?;
        let body = value
            .get("body")
            .filter(|body| body.as_object().is_some())
            .cloned()
            .ok_or(BrokerError::Configuration(
                "pending node event body is malformed",
            ))?;
        Ok(Self {
            idempotency_key: idempotency_key.to_owned(),
            kind: kind.to_owned(),
            body,
        })
    }

    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("body".to_owned(), self.body.clone()),
            (
                "idempotency_key".to_owned(),
                Value::String(self.idempotency_key.clone()),
            ),
            ("kind".to_owned(), Value::String(self.kind.clone())),
        ])
    }
}

impl BrokerState {
    #[must_use]
    pub fn new(delivery_policy: DeliveryPolicy) -> Self {
        Self::with_lifetimes(
            delivery_policy,
            DEFAULT_CUSTODY_KEY_LIFETIME,
            DEFAULT_CREDENTIAL_LIFETIME,
        )
    }

    pub fn with_lifetimes(
        delivery_policy: DeliveryPolicy,
        custody_key_lifetime: Duration,
        credential_lifetime: Duration,
    ) -> Self {
        Self {
            loader_policy: LoaderPolicy::new(),
            workloads: Vec::new(),
            fleet_registrations: BTreeMap::new(),
            fleet_policy: None,
            grant_verifier: grants::GrantVerifier::default(),
            operation_directory: PathBuf::from(DEFAULT_OPERATION_DIRECTORY),
            pending_node_events: VecDeque::new(),
            pending_node_events_path: None,
            audit_overflow_pending: false,
            node_revoked: false,
            node_revocation_ack_pending: false,
            node_revocation_acknowledged: false,
            node_revocation_observed_at_ms: None,
            credentials: CredentialRegistry::new(delivery_policy),
            custody: EphemeralCustody::new(custody_key_lifetime),
            credential_expiries: BTreeMap::new(),
            credential_lifetime,
        }
    }

    pub fn provision_key(&mut self, unit: &str, credential: &str) -> Result<Vec<u8>, BrokerError> {
        self.validate_mapping(unit, credential)?;
        Ok(self.custody.provision(&format!("{unit}:{credential}"))?)
    }

    pub fn provision_sealed(
        &mut self,
        unit: &str,
        credential: &str,
        enc: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), BrokerError> {
        self.validate_mapping(unit, credential)?;
        let aad = provision_aad(unit, credential);
        let value = self.custody.open_once(
            &format!("{unit}:{credential}"),
            enc,
            ciphertext,
            aad.as_bytes(),
        )?;
        let key = destination_key(unit, credential);
        self.credentials.insert_secret(&key, value)?;
        self.credential_expiries
            .insert(key, Instant::now() + self.credential_lifetime);
        Ok(())
    }

    fn validate_mapping(&self, unit: &str, credential: &str) -> Result<(), BrokerError> {
        if self.loader_policy.credential_for(unit) != Some(credential) {
            return Err(
                IdentityError::BindingMismatch("provision destination is not mapped").into(),
            );
        }
        Ok(())
    }

    pub fn process_loader(
        &mut self,
        peer: &PeerIdentity,
        claimed_unit: &str,
        claimed_credential: &str,
    ) -> Result<SecretBytes, BrokerError> {
        let authorization = self.loader_policy.authorize(peer, claimed_unit)?;
        if authorization.credential_name != claimed_credential {
            return Err(IdentityError::BindingMismatch(
                "requested credential does not match protected unit mapping",
            )
            .into());
        }
        self.purge_expired_credentials();
        Ok(SecretBytes::from_slice(self.credentials.get(
            &destination_key(&authorization.unit, &authorization.credential_name),
        )?))
    }

    fn process_systemd_credential(
        &mut self,
        unit: &str,
        credential: &str,
    ) -> Result<SecretBytes, BrokerError> {
        if self.loader_policy.credential_for(unit) != Some(credential) {
            return Err(IdentityError::BindingMismatch(
                "systemd credential route is not in the protected unit mapping",
            )
            .into());
        }
        self.purge_expired_credentials();
        Ok(SecretBytes::from_slice(
            self.credentials.get(&destination_key(unit, credential))?,
        ))
    }

    fn purge_expired_credentials(&mut self) {
        self.custody.purge_expired();
        self.credential_expiries.retain(|name, expiry| {
            if *expiry <= Instant::now() {
                self.credentials.remove(name);
                false
            } else {
                true
            }
        });
    }

    pub fn process_workload(
        &mut self,
        peer: &PeerIdentity,
        request: &blindpass_core::identity::WorkloadRequest,
    ) -> Result<Vec<u8>, BrokerError> {
        if self.node_revoked {
            return Err(BrokerError::Configuration("node_revoked"));
        }
        let authorization = authorize_workload(peer, request, &self.workloads)?;
        if let Some(encoded) = request.operation.strip_prefix("request:") {
            if self.pending_node_events.len() >= MAX_BROKER_AUDIT_EVENTS {
                self.audit_overflow_pending = true;
                self.persist_pending_node_events()?;
                return Err(BrokerError::Configuration("audit_backpressure"));
            }
            let body = self.operation_request_body(&authorization, encoded)?;
            let event_key = new_node_event_key()?;
            self.pending_node_events.push_back(PendingNodeEvent {
                idempotency_key: event_key.clone(),
                kind: "operation_request".to_owned(),
                body,
            });
            if let Err(error) = self.persist_pending_node_events() {
                self.pending_node_events.pop_back();
                return Err(error);
            }
            return Ok(format!("OK operation_request {event_key}\n").into_bytes());
        }
        if let Some(grant_id) = request.operation.strip_prefix("consume:") {
            if self.pending_node_events.len() > MAX_BROKER_AUDIT_EVENTS - 2 {
                self.audit_overflow_pending = true;
                self.persist_pending_node_events()?;
                return Err(BrokerError::Configuration("audit_backpressure"));
            }
            let observed_at_ms = self
                .grant_verifier
                .trusted_controller_time_ms(
                    grants::boottime_ms().map_err(BrokerError::Configuration)?,
                )
                .ok_or(BrokerError::Configuration("trusted_time_unavailable"))?;
            let event_keys = [new_node_event_key()?, new_node_event_key()?];
            let policy_version = self
                .fleet_policy
                .as_ref()
                .map(|policy| policy.policy_version)
                .ok_or(BrokerError::Configuration("fleet policy is unavailable"))?;
            let now = grants::boottime_ms().map_err(BrokerError::Configuration)?;
            let preview = self
                .grant_verifier
                .preview_consumption(grant_id, &authorization, policy_version, now)
                .map_err(BrokerError::Configuration)?;
            self.queue_operation_result(
                &preview,
                "uncertain",
                "result_uncertain",
                observed_at_ms,
                event_keys.clone(),
            )?;
            let grant =
                match self
                    .grant_verifier
                    .consume(grant_id, &authorization, policy_version, now)
                {
                    Ok(grant) if grant == preview => grant,
                    Ok(_) | Err(_) => {
                        return Ok(format!("OK operation_uncertain {}\n", preview.id).into_bytes());
                    }
                };
            match grant.action.as_str() {
                "noop.marker" => {
                    if ops::noop_marker::create_in(&self.operation_directory, &grant.id).is_err() {
                        return Ok(format!("OK operation_uncertain {}\n", grant.id).into_bytes());
                    }
                }
                _ => return Ok(format!("OK operation_uncertain {}\n", grant.id).into_bytes()),
            }
            if self
                .update_operation_result(
                    &grant,
                    "completed",
                    "marker_created",
                    observed_at_ms,
                    &event_keys,
                )
                .is_err()
            {
                return Ok(format!("OK operation_uncertain {}\n", grant.id).into_bytes());
            }
            return Ok(format!("OK operation_completed {grant_id}\n").into_bytes());
        }
        Ok(workload_ok(request))
    }

    fn operation_request_body(
        &self,
        authorization: &blindpass_core::identity::WorkloadAuthorization,
        encoded: &str,
    ) -> Result<Value, BrokerError> {
        if encoded.is_empty() || encoded.len() > 1_024 {
            return Err(BrokerError::Configuration("invalid_operation_request"));
        }
        let decoded_len = encoded.len().saturating_mul(3) / 4;
        let bytes = blindpass_core::signing::base64_url_decode(encoded, decoded_len)
            .ok_or(BrokerError::Configuration("invalid_operation_request"))?;
        let source = std::str::from_utf8(&bytes)
            .map_err(|_| BrokerError::Configuration("invalid_operation_request"))?;
        let input = parse_json(source)
            .map_err(|_| BrokerError::Configuration("invalid_operation_request"))?;
        let fields = input
            .as_object()
            .filter(|fields| fields.len() == 5)
            .ok_or(BrokerError::Configuration("invalid_operation_request"))?;
        let action = input
            .get("action")
            .and_then(Value::as_str)
            .ok_or(BrokerError::Configuration("invalid_operation_request"))?;
        let mode = input
            .get("mode")
            .and_then(Value::as_str)
            .and_then(ConsumptionMode::parse)
            .ok_or(BrokerError::Configuration("invalid_operation_request"))?;
        let purpose = input
            .get("purpose")
            .and_then(Value::as_str)
            .filter(|value| value.len() <= 512 && !value.contains(['\r', '\n', '\0']))
            .ok_or(BrokerError::Configuration("invalid_operation_request"))?;
        let resource_id = input
            .get("resource_id")
            .and_then(Value::as_str)
            .filter(|value| valid_event_identifier(value))
            .ok_or(BrokerError::Configuration("invalid_operation_request"))?;
        let ttl_seconds = input
            .get("ttl_seconds")
            .and_then(Value::as_u64)
            .filter(|ttl| (1..=3_600).contains(ttl))
            .ok_or(BrokerError::Configuration("invalid_operation_request"))?;
        if fields.iter().any(|(name, _)| {
            !matches!(
                name.as_str(),
                "action" | "mode" | "purpose" | "resource_id" | "ttl_seconds"
            )
        }) || action != "noop.marker"
        {
            return Err(BrokerError::Configuration("invalid_operation_request"));
        }
        let registration = self
            .fleet_registrations
            .get(&authorization.workload_id)
            .filter(|registration| registration.status == "active")
            .ok_or(BrokerError::Configuration(
                "workload registration is unavailable",
            ))?;
        let policy = self
            .fleet_policy
            .as_ref()
            .ok_or(BrokerError::Configuration("fleet policy is unavailable"))?;
        if mode != registration.consumption_mode
            || !matches!(mode, ConsumptionMode::File | ConsumptionMode::Socket)
            || ttl_seconds > registration.local_ceiling_seconds
            || !policy
                .allowed_actions
                .iter()
                .any(|allowed| allowed == action)
            || !policy.allowed_modes.contains(&mode)
        {
            return Err(BrokerError::Configuration(
                "operation request is denied by local policy",
            ));
        }
        let observed_at_ms = self
            .grant_verifier
            .trusted_controller_time_ms(grants::boottime_ms().map_err(BrokerError::Configuration)?)
            .ok_or(BrokerError::Configuration(
                "fresh controller time is unavailable",
            ))?;
        Ok(Value::Object(vec![
            (
                "account".to_owned(),
                Value::String(registration.account.clone()),
            ),
            ("action".to_owned(), Value::String(action.to_owned())),
            (
                "invocation_id".to_owned(),
                Value::String(authorization.invocation_id.clone()),
            ),
            ("mode".to_owned(), Value::String(mode.as_str().to_owned())),
            (
                "node_id".to_owned(),
                Value::String(authorization.node_id.clone()),
            ),
            ("observed_at_ms".to_owned(), Value::Unsigned(observed_at_ms)),
            ("purpose".to_owned(), Value::String(purpose.to_owned())),
            (
                "resource_id".to_owned(),
                Value::String(resource_id.to_owned()),
            ),
            ("ttl_seconds".to_owned(), Value::Unsigned(ttl_seconds)),
            ("unit".to_owned(), Value::String(authorization.unit.clone())),
            (
                "workload_id".to_owned(),
                Value::String(authorization.workload_id.clone()),
            ),
        ]))
    }

    fn queue_operation_result(
        &mut self,
        grant: &blindpass_core::fleet::Grant,
        status: &str,
        result_code: &str,
        observed_at_ms: u64,
        [result_key, audit_key]: [String; 2],
    ) -> Result<(), BrokerError> {
        let previous_events = self.pending_node_events.clone();
        let body = Value::Object(vec![
            ("grant_id".to_owned(), Value::String(grant.id.clone())),
            ("observed_at_ms".to_owned(), Value::Unsigned(observed_at_ms)),
            (
                "operation_id".to_owned(),
                Value::String(grant.operation_id.clone()),
            ),
            (
                "result_code".to_owned(),
                Value::String(result_code.to_owned()),
            ),
            ("status".to_owned(), Value::String(status.to_owned())),
        ]);
        self.pending_node_events.push_back(PendingNodeEvent {
            idempotency_key: result_key,
            kind: "operation_result".to_owned(),
            body: body.clone(),
        });
        self.pending_node_events.push_back(PendingNodeEvent {
            idempotency_key: audit_key,
            kind: "audit".to_owned(),
            body: Value::Object(vec![
                (
                    "action".to_owned(),
                    Value::String("operation_result".to_owned()),
                ),
                ("grant_id".to_owned(), Value::String(grant.id.clone())),
                ("observed_at_ms".to_owned(), Value::Unsigned(observed_at_ms)),
                (
                    "operation_id".to_owned(),
                    Value::String(grant.operation_id.clone()),
                ),
                ("status".to_owned(), Value::String(status.to_owned())),
            ]),
        });
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events = previous_events;
            return Err(error);
        }
        Ok(())
    }

    fn update_operation_result(
        &mut self,
        grant: &blindpass_core::fleet::Grant,
        status: &str,
        result_code: &str,
        observed_at_ms: u64,
        event_keys: &[String; 2],
    ) -> Result<(), BrokerError> {
        let previous_events = self.pending_node_events.clone();
        let result_body = Value::Object(vec![
            ("grant_id".to_owned(), Value::String(grant.id.clone())),
            ("observed_at_ms".to_owned(), Value::Unsigned(observed_at_ms)),
            (
                "operation_id".to_owned(),
                Value::String(grant.operation_id.clone()),
            ),
            (
                "result_code".to_owned(),
                Value::String(result_code.to_owned()),
            ),
            ("status".to_owned(), Value::String(status.to_owned())),
        ]);
        let audit_body = Value::Object(vec![
            (
                "action".to_owned(),
                Value::String("operation_result".to_owned()),
            ),
            ("grant_id".to_owned(), Value::String(grant.id.clone())),
            ("observed_at_ms".to_owned(), Value::Unsigned(observed_at_ms)),
            (
                "operation_id".to_owned(),
                Value::String(grant.operation_id.clone()),
            ),
            ("status".to_owned(), Value::String(status.to_owned())),
        ]);
        let Some(result_index) = self.pending_node_events.iter().position(|event| {
            event.idempotency_key == event_keys[0] && event.kind == "operation_result"
        }) else {
            return Err(BrokerError::Configuration(
                "pending operation result is unavailable",
            ));
        };
        let Some(audit_index) = self
            .pending_node_events
            .iter()
            .position(|event| event.idempotency_key == event_keys[1] && event.kind == "audit")
        else {
            return Err(BrokerError::Configuration(
                "pending operation audit is unavailable",
            ));
        };
        self.pending_node_events[result_index].body = result_body;
        self.pending_node_events[audit_index].body = audit_body;
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events = previous_events;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn pending_node_events(&self, limit: usize) -> Vec<PendingNodeEvent> {
        self.pending_node_events
            .iter()
            .take(limit.min(MAX_NODE_EVENT_BATCH))
            .cloned()
            .collect()
    }

    pub(crate) fn acknowledge_node_events(
        &mut self,
        node_id: &str,
        event_keys: &[String],
    ) -> Result<(), BrokerError> {
        let previous_events = self.pending_node_events.clone();
        let previous_overflow = self.audit_overflow_pending;
        let previous_revocation_pending = self.node_revocation_ack_pending;
        let previous_revocation_acknowledged = self.node_revocation_acknowledged;
        let acknowledged = event_keys.iter().collect::<std::collections::HashSet<_>>();
        if self.pending_node_events.iter().any(|event| {
            acknowledged.contains(&event.idempotency_key)
                && event.kind == "audit"
                && event.body.get("action").and_then(Value::as_str)
                    == Some("node_revocation_applied")
        }) {
            self.node_revocation_ack_pending = false;
            self.node_revocation_acknowledged = true;
        }
        self.pending_node_events
            .retain(|event| !acknowledged.contains(&event.idempotency_key));
        if let Err(error) = self
            .queue_overflow_event_if_possible(node_id)
            .and_then(|()| self.queue_node_revocation_ack_if_possible(node_id))
        {
            self.pending_node_events = previous_events;
            self.audit_overflow_pending = previous_overflow;
            self.node_revocation_ack_pending = previous_revocation_pending;
            self.node_revocation_acknowledged = previous_revocation_acknowledged;
            return Err(error);
        }
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events = previous_events;
            self.audit_overflow_pending = previous_overflow;
            self.node_revocation_ack_pending = previous_revocation_pending;
            self.node_revocation_acknowledged = previous_revocation_acknowledged;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn queue_overflow_event_if_possible(
        &mut self,
        node_id: &str,
    ) -> Result<(), BrokerError> {
        if !self.audit_overflow_pending || self.pending_node_events.len() >= MAX_BROKER_AUDIT_EVENTS
        {
            return Ok(());
        }
        let Some(observed_at_ms) = self
            .grant_verifier
            .trusted_controller_time_ms(grants::boottime_ms().map_err(BrokerError::Configuration)?)
        else {
            return Ok(());
        };
        let event_key = new_node_event_key()?;
        self.pending_node_events.push_back(PendingNodeEvent {
            idempotency_key: event_key,
            kind: "audit".to_owned(),
            body: Value::Object(vec![
                (
                    "action".to_owned(),
                    Value::String("audit_overflow".to_owned()),
                ),
                ("node_id".to_owned(), Value::String(node_id.to_owned())),
                ("observed_at_ms".to_owned(), Value::Unsigned(observed_at_ms)),
            ]),
        });
        self.audit_overflow_pending = false;
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events.pop_back();
            self.audit_overflow_pending = true;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn apply_node_revocation(
        &mut self,
        node_id: &str,
        observed_at_ms: u64,
    ) -> Result<(), BrokerError> {
        self.node_revoked = true;
        self.node_revocation_observed_at_ms = Some(observed_at_ms);
        if !self.node_revocation_acknowledged {
            self.node_revocation_ack_pending = true;
            self.queue_node_revocation_ack_if_possible(node_id)?;
        }
        Ok(())
    }

    pub(crate) fn queue_node_revocation_ack_if_possible(
        &mut self,
        node_id: &str,
    ) -> Result<(), BrokerError> {
        if !self.node_revocation_ack_pending
            || self.node_revocation_acknowledged
            || self.pending_node_events.len() >= MAX_BROKER_AUDIT_EVENTS
        {
            return Ok(());
        }
        let observed_at_ms =
            self.node_revocation_observed_at_ms
                .ok_or(BrokerError::Configuration(
                    "node revocation time is unavailable",
                ))?;
        let event_key = format!("node_revocation_applied_{observed_at_ms}");
        if !self.pending_node_events.iter().any(|event| {
            event.idempotency_key == event_key
                && event.body.get("action").and_then(Value::as_str)
                    == Some("node_revocation_applied")
        }) {
            self.pending_node_events.push_back(PendingNodeEvent {
                idempotency_key: event_key.clone(),
                kind: "audit".to_owned(),
                body: Value::Object(vec![
                    (
                        "action".to_owned(),
                        Value::String("node_revocation_applied".to_owned()),
                    ),
                    ("node_id".to_owned(), Value::String(node_id.to_owned())),
                    ("observed_at_ms".to_owned(), Value::Unsigned(observed_at_ms)),
                ]),
            });
        }
        self.node_revocation_ack_pending = false;
        if let Err(error) = self.persist_pending_node_events() {
            self.node_revocation_ack_pending = true;
            if self
                .pending_node_events
                .back()
                .is_some_and(|event| event.idempotency_key == event_key)
            {
                self.pending_node_events.pop_back();
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn queue_node_key_rotation_ack(
        &mut self,
        node_id: &str,
        rotation_id: &str,
        key_version: u64,
        fingerprint: &str,
    ) -> Result<(), BrokerError> {
        let event_key = keys::rotation_ack_event_key(rotation_id);
        if self
            .pending_node_events
            .iter()
            .any(|event| event.idempotency_key == event_key)
        {
            return Ok(());
        }
        if self.pending_node_events.len() > MAX_BROKER_AUDIT_EVENTS
            || key_version <= 1
            || !valid_event_identifier(rotation_id)
            || fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(BrokerError::Configuration(
                "node key rotation acknowledgement is invalid",
            ));
        }
        self.pending_node_events.push_back(PendingNodeEvent {
            idempotency_key: event_key,
            kind: "audit".to_owned(),
            body: Value::Object(vec![
                (
                    "action".to_owned(),
                    Value::String("node_key_rotation_applied".to_owned()),
                ),
                (
                    "fingerprint".to_owned(),
                    Value::String(fingerprint.to_owned()),
                ),
                ("key_version".to_owned(), Value::Unsigned(key_version)),
                ("node_id".to_owned(), Value::String(node_id.to_owned())),
                (
                    "rotation_id".to_owned(),
                    Value::String(rotation_id.to_owned()),
                ),
            ]),
        });
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events.pop_back();
            return Err(error);
        }
        Ok(())
    }

    fn configure_grant_storage(
        &mut self,
        identity: &keys::NodeIdentity,
    ) -> Result<(), BrokerError> {
        self.grant_verifier = grants::GrantVerifier::with_state_files(
            &identity.consumed_grant_journal_path(),
            &identity.trusted_time_path(),
            &identity.revoked_grant_journal_path(),
        )
        .map_err(BrokerError::Configuration)?;
        let pending_path = identity.pending_node_events_path();
        let (events, overflow_pending, revocation_acknowledged) =
            read_pending_node_events(&pending_path)?;
        self.pending_node_events_path = Some(pending_path);
        self.pending_node_events = events;
        self.audit_overflow_pending = overflow_pending;
        self.node_revocation_acknowledged = revocation_acknowledged;
        Ok(())
    }

    fn persist_pending_node_events(&self) -> Result<(), BrokerError> {
        let Some(path) = self.pending_node_events_path.as_deref() else {
            return Ok(());
        };
        write_pending_node_events(
            path,
            &self.pending_node_events,
            self.audit_overflow_pending,
            self.node_revocation_acknowledged,
        )
    }

    pub(crate) fn validate_fleet_registration(
        &self,
        registration: &Registration,
    ) -> Result<bool, BrokerError> {
        if let Some(previous) = self.fleet_registrations.get(&registration.workload_id) {
            if registration.registration_version < previous.registration_version {
                return Ok(false);
            }
            if registration.registration_version == previous.registration_version {
                if registration == previous {
                    return Ok(false);
                }
                return Err(BrokerError::Configuration(
                    "workload registration version was reused with different bytes",
                ));
            }
        }
        Ok(true)
    }

    pub(crate) fn apply_fleet_registration(
        &mut self,
        registration: Registration,
    ) -> Result<bool, BrokerError> {
        if !self.validate_fleet_registration(&registration)? {
            return Ok(false);
        }
        self.workloads
            .retain(|workload| workload.workload_id != registration.workload_id);
        self.grant_verifier
            .revoke_workload(&registration.workload_id);
        if registration.status == "active" {
            self.workloads.push(WorkloadRegistration {
                node_id: registration.node_id.clone(),
                workload_id: registration.workload_id.clone(),
                unit: registration.unit.clone(),
                account: registration.account.clone(),
                invocation_id: registration.invocation_id.clone(),
            });
        }
        self.fleet_registrations
            .insert(registration.workload_id.clone(), registration);
        Ok(true)
    }

    pub(crate) fn validate_fleet_policy(
        &self,
        policy: &PolicySnapshot,
    ) -> Result<bool, BrokerError> {
        if let Some(previous) = self.fleet_policy.as_ref() {
            if policy.policy_version < previous.policy_version {
                return Ok(false);
            }
            if policy.policy_version == previous.policy_version {
                if policy == previous {
                    return Ok(false);
                }
                return Err(BrokerError::Configuration(
                    "fleet policy version was reused with different bytes",
                ));
            }
        }
        Ok(true)
    }

    pub(crate) fn apply_fleet_policy(
        &mut self,
        policy: PolicySnapshot,
    ) -> Result<bool, BrokerError> {
        if !self.validate_fleet_policy(&policy)? {
            return Ok(false);
        }
        self.grant_verifier
            .revoke_stale_policy(policy.policy_version);
        self.fleet_policy = Some(policy);
        Ok(true)
    }
}

pub fn provision_aad(unit: &str, credential: &str) -> String {
    format!("blindpass:p01:{unit}:{credential}")
}

fn new_node_event_key() -> Result<String, BrokerError> {
    let mut random = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(format!(
        "event_{}",
        blindpass_core::signing::base64_url_encode(&random)
    ))
}

fn valid_node_event_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn read_pending_node_events(
    path: &Path,
) -> Result<(VecDeque<PendingNodeEvent>, bool, bool), BrokerError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok((VecDeque::new(), false, false));
        }
        Err(_) => {
            return Err(BrokerError::Configuration(
                "pending node event queue is unsafe or unreadable",
            ));
        }
    };
    let metadata = file.metadata().map_err(|_| {
        BrokerError::Configuration("pending node event queue metadata is unavailable")
    })?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != PENDING_NODE_EVENT_FILE_MODE
        || metadata.len() > MAX_PENDING_NODE_EVENTS_BYTES
    {
        return Err(BrokerError::Configuration(
            "pending node event queue permissions or size are unsafe",
        ));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut contents)
        .map_err(|_| BrokerError::Configuration("pending node event queue is unreadable"))?;
    if contents.is_empty() || contents.last() != Some(&b'\n') {
        return Err(BrokerError::Configuration(
            "pending node event queue is incomplete",
        ));
    }
    let header_end =
        contents
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(BrokerError::Configuration(
                "pending node event queue header is malformed",
            ))?;
    if header_end > 256 {
        return Err(BrokerError::Configuration(
            "pending node event queue header is oversized",
        ));
    }
    let header_source = std::str::from_utf8(&contents[..header_end])
        .map_err(|_| BrokerError::Configuration("pending node event queue header is malformed"))?;
    let header = parse_json(header_source)
        .map_err(|_| BrokerError::Configuration("pending node event queue header is malformed"))?;
    let header_fields = header.as_object().ok_or(BrokerError::Configuration(
        "pending node event queue header is malformed",
    ))?;
    let header_version = header.get("v").and_then(Value::as_u64);
    let expected_fields = if header_version == Some(1) { 2 } else { 3 };
    if header_fields.len() != expected_fields
        || header_fields.iter().any(|(name, _)| {
            !matches!(
                name.as_str(),
                "v" | "audit_overflow_pending" | "node_revocation_acknowledged"
            )
        })
        || !matches!(header_version, Some(1 | 2))
    {
        return Err(BrokerError::Configuration(
            "pending node event queue version is unsupported",
        ));
    }
    let overflow_pending = match header.get("audit_overflow_pending") {
        Some(Value::Bool(value)) => *value,
        _ => {
            return Err(BrokerError::Configuration(
                "pending node event queue header is malformed",
            ));
        }
    };
    let revocation_acknowledged = match (header_version, header.get("node_revocation_acknowledged"))
    {
        (Some(1), None) => false,
        (Some(2), Some(Value::Bool(value))) => *value,
        _ => {
            return Err(BrokerError::Configuration(
                "pending node event queue header is malformed",
            ));
        }
    };
    let records = &contents[header_end + 1..];
    let mut events = VecDeque::new();
    let mut event_keys = std::collections::HashSet::new();
    for line in records
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > MAX_PENDING_NODE_EVENT_BYTES || events.len() > MAX_BROKER_AUDIT_EVENTS {
            return Err(BrokerError::Configuration(
                "pending node event queue exceeds its limits",
            ));
        }
        let source = std::str::from_utf8(line).map_err(|_| {
            BrokerError::Configuration("pending node event queue record is malformed")
        })?;
        let value = parse_json(source).map_err(|_| {
            BrokerError::Configuration("pending node event queue record is malformed")
        })?;
        let event = PendingNodeEvent::from_value(&value)?;
        if !event_keys.insert(event.idempotency_key.clone()) {
            return Err(BrokerError::Configuration(
                "pending node event key is duplicated",
            ));
        }
        events.push_back(event);
    }
    if events.len() > MAX_BROKER_AUDIT_EVENTS
        && (events.len() != MAX_BROKER_AUDIT_EVENTS + 1
            || events
                .iter()
                .filter(|event| is_node_key_rotation_ack(event))
                .count()
                != 1)
    {
        return Err(BrokerError::Configuration(
            "pending node event queue exceeds its limits",
        ));
    }
    Ok((events, overflow_pending, revocation_acknowledged))
}

fn is_node_key_rotation_ack(event: &PendingNodeEvent) -> bool {
    event.kind == "audit"
        && event.body.get("action").and_then(Value::as_str) == Some("node_key_rotation_applied")
}

fn write_pending_node_events(
    path: &Path,
    events: &VecDeque<PendingNodeEvent>,
    overflow_pending: bool,
    revocation_acknowledged: bool,
) -> Result<(), BrokerError> {
    if events.len() > MAX_BROKER_AUDIT_EVENTS + 1
        || (events.len() > MAX_BROKER_AUDIT_EVENTS
            && (events.len() != MAX_BROKER_AUDIT_EVENTS + 1
                || events
                    .iter()
                    .filter(|event| is_node_key_rotation_ack(event))
                    .count()
                    != 1))
    {
        return Err(BrokerError::Configuration(
            "pending node event queue exceeds its event limit",
        ));
    }
    let parent = path.parent().ok_or(BrokerError::Configuration(
        "pending node event queue path is invalid",
    ))?;
    if events.is_empty() && !overflow_pending && !revocation_acknowledged {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => {
                return Err(BrokerError::Configuration(
                    "pending node event queue could not be cleared",
                ));
            }
        }
        return File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| {
                BrokerError::Configuration("pending node event queue directory is unavailable")
            });
    }
    let header = Value::Object(vec![
        (
            "audit_overflow_pending".to_owned(),
            Value::Bool(overflow_pending),
        ),
        (
            "node_revocation_acknowledged".to_owned(),
            Value::Bool(revocation_acknowledged),
        ),
        ("v".to_owned(), Value::Unsigned(2)),
    ]);
    let mut contents = canonicalize_value(&header)
        .map_err(|_| BrokerError::Configuration("pending node event header is invalid"))?;
    contents.push(b'\n');
    let mut event_keys = std::collections::HashSet::new();
    for event in events {
        PendingNodeEvent::from_value(&event.to_value())?;
        if !event_keys.insert(event.idempotency_key.as_str()) {
            return Err(BrokerError::Configuration(
                "pending node event key is duplicated",
            ));
        }
        let line = canonicalize_value(&event.to_value())
            .map_err(|_| BrokerError::Configuration("pending node event is invalid"))?;
        if line.len() > MAX_PENDING_NODE_EVENT_BYTES {
            return Err(BrokerError::Configuration(
                "pending node event exceeds its size limit",
            ));
        }
        contents.extend_from_slice(&line);
        contents.push(b'\n');
        if contents.len() as u64 > MAX_PENDING_NODE_EVENTS_BYTES {
            return Err(BrokerError::Configuration(
                "pending node event queue exceeds its byte limit",
            ));
        }
    }
    let sequence = PENDING_EVENT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".pending-node-events-{}-{sequence}.tmp",
        std::process::id()
    ));
    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PENDING_NODE_EVENT_FILE_MODE)
            .custom_flags(O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(&contents)?;
        file.set_permissions(fs::Permissions::from_mode(PENDING_NODE_EVENT_FILE_MODE))?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(BrokerError::Configuration(
            "pending node event queue could not be committed",
        ));
    }
    Ok(())
}

fn valid_event_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn destination_key(unit: &str, credential: &str) -> String {
    format!("{unit}:{credential}")
}

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub loader_socket: PathBuf,
    pub workload_socket: PathBuf,
    pub provision_socket: PathBuf,
    pub control_socket: PathBuf,
    pub key_directory: PathBuf,
    pub socket_directory_mode: u32,
    pub loader_socket_mode: u32,
    pub workload_socket_mode: u32,
    pub provision_socket_mode: u32,
    pub control_socket_mode: u32,
    pub read_timeout: Duration,
    pub identity_lookup_delay: Duration,
    pub delivery_fault: Option<DeliveryFault>,
    pub workload_group: Option<String>,
    pub node_group: Option<String>,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            loader_socket: PathBuf::from("/run/blindpass/loader.sock"),
            workload_socket: PathBuf::from("/run/blindpass/workload.sock"),
            provision_socket: PathBuf::from("/run/blindpass/provision.sock"),
            control_socket: PathBuf::from("/run/blindpass/control.sock"),
            key_directory: PathBuf::from("/var/lib/blindpass/broker"),
            socket_directory_mode: 0o751,
            loader_socket_mode: 0o600,
            workload_socket_mode: 0o660,
            provision_socket_mode: 0o600,
            control_socket_mode: 0o660,
            read_timeout: Duration::from_secs(2),
            identity_lookup_delay: Duration::ZERO,
            delivery_fault: None,
            workload_group: None,
            node_group: None,
        }
    }
}

pub fn run(config: BrokerConfig, state: BrokerState) -> Result<(), BrokerError> {
    if effective_uid() != 0 {
        return Err(BrokerError::Configuration(
            "blindpass-broker must run as root",
        ));
    }
    validate_config(&config)?;
    let node_identity = Arc::new(keys::NodeIdentity::load_or_create(&config.key_directory)?);
    let mut state = state;
    state.configure_grant_storage(&node_identity)?;
    control::restore_controller_documents(&mut state, &node_identity)?;
    let loader_listener = bind_socket(
        &config.loader_socket,
        config.socket_directory_mode,
        config.loader_socket_mode,
    )?;
    let workload_listener = bind_socket(
        &config.workload_socket,
        config.socket_directory_mode,
        config.workload_socket_mode,
    )?;
    if let Some(group) = config.workload_group.as_deref() {
        let gid = lookup_gid(group)?;
        chown(&config.workload_socket, None, Some(gid))?;
    }
    let provision_listener = bind_socket(
        &config.provision_socket,
        config.socket_directory_mode,
        config.provision_socket_mode,
    )?;
    let control_listener = bind_socket(
        &config.control_socket,
        config.socket_directory_mode,
        config.control_socket_mode,
    )?;
    let control_group_id = config.node_group.as_deref().map(lookup_gid).transpose()?;
    if let Some(gid) = control_group_id {
        chown(&config.control_socket, None, Some(gid))?;
    }
    let shared = Arc::new(Mutex::new(state));
    let purge_shared = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("blindpass-custody-purge".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                if let Ok(mut state) = purge_shared.lock() {
                    state.purge_expired_credentials();
                }
            }
        })
        .map_err(BrokerError::Io)?;
    let (listener_error_sender, listener_error_receiver) = mpsc::channel();
    let loader_shared = Arc::clone(&shared);
    let loader_timeout = config.read_timeout;
    let loader_identity_lookup_delay = config.identity_lookup_delay;
    let loader_fault = config.delivery_fault;
    spawn_listener_thread(
        "blindpass-loader",
        listener_error_sender.clone(),
        move || {
            serve_loader(
                loader_listener,
                loader_shared,
                loader_timeout,
                loader_identity_lookup_delay,
                loader_fault,
            )
        },
    )?;
    let control_timeout = config.read_timeout;
    let control_shared = Arc::clone(&shared);
    spawn_listener_thread(
        "blindpass-control",
        listener_error_sender.clone(),
        move || {
            serve_connections(
                control_listener,
                control_timeout,
                move |stream, deadline| {
                    control::handle_connection(
                        stream,
                        control_group_id,
                        Arc::clone(&node_identity),
                        Arc::clone(&control_shared),
                        deadline,
                    )
                },
                "control",
            )
        },
    )?;
    let workload_shared = Arc::clone(&shared);
    let workload_timeout = config.read_timeout;
    spawn_listener_thread(
        "blindpass-workload",
        listener_error_sender.clone(),
        move || serve_workload(workload_listener, workload_shared, workload_timeout),
    )?;
    let provision_shared = Arc::clone(&shared);
    let provision_timeout = config.read_timeout;
    spawn_listener_thread(
        "blindpass-provision",
        listener_error_sender.clone(),
        move || serve_provision(provision_listener, provision_shared, provision_timeout),
    )?;
    drop(listener_error_sender);
    notify_ready()?;
    Err(listener_error_receiver
        .recv()
        .map_err(|_| BrokerError::Configuration("all broker listeners stopped"))?)
}

fn spawn_listener_thread<F>(
    name: &'static str,
    errors: Sender<BrokerError>,
    serve: F,
) -> Result<(), BrokerError>
where
    F: FnOnce() -> Result<(), BrokerError> + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(serve));
            let error = match result {
                Ok(Ok(())) => BrokerError::Configuration("broker listener stopped unexpectedly"),
                Ok(Err(error)) => error,
                Err(_) => BrokerError::Configuration("broker listener panicked"),
            };
            let _ = errors.send(error);
        })
        .map(|_| ())
        .map_err(BrokerError::Io)
}

fn notify_ready() -> Result<(), BrokerError> {
    let message = std::ffi::CString::new("READY=1").unwrap();
    let result = unsafe { sd_notify(0, message.as_ptr()) };
    if result < 0 {
        return Err(BrokerError::Io(io::Error::from_raw_os_error(-result)));
    }
    Ok(())
}

#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_notify(unset_environment: i32, state: *const std::ffi::c_char) -> i32;
}

fn validate_config(config: &BrokerConfig) -> Result<(), BrokerError> {
    if config.socket_directory_mode != 0o751
        || config.loader_socket_mode != 0o600
        || config.workload_socket_mode != 0o660
        || config.provision_socket_mode != 0o600
        || config.control_socket_mode != 0o660
    {
        return Err(BrokerError::Configuration(
            "broker socket modes must be directory 0751, loader/provision 0600 and workload/control 0660",
        ));
    }
    if !config.loader_socket.is_absolute()
        || !config.workload_socket.is_absolute()
        || !config.provision_socket.is_absolute()
        || !config.control_socket.is_absolute()
        || !config.key_directory.is_absolute()
    {
        return Err(BrokerError::Configuration(
            "broker socket paths must be absolute",
        ));
    }
    if config.loader_socket == config.workload_socket
        || config.loader_socket == config.provision_socket
        || config.workload_socket == config.provision_socket
        || config.loader_socket == config.control_socket
        || config.workload_socket == config.control_socket
        || config.provision_socket == config.control_socket
    {
        return Err(BrokerError::Configuration(
            "loader, workload, provision and control sockets must be distinct",
        ));
    }
    if config.read_timeout.is_zero() {
        return Err(BrokerError::Configuration(
            "broker read timeout must be non-zero",
        ));
    }
    if config.identity_lookup_delay >= config.read_timeout {
        return Err(BrokerError::Configuration(
            "identity lookup test delay must be shorter than the request deadline",
        ));
    }
    if config
        .workload_group
        .as_deref()
        .is_some_and(|group| group.is_empty() || group.contains('/'))
    {
        return Err(BrokerError::Configuration(
            "workload group must be a non-empty group name",
        ));
    }
    if config
        .node_group
        .as_deref()
        .is_some_and(|group| group.is_empty() || group.contains('/'))
    {
        return Err(BrokerError::Configuration(
            "node group must be a non-empty group name",
        ));
    }
    Ok(())
}

#[repr(C)]
struct GroupEntry {
    name: *mut c_char,
    password: *mut c_char,
    gid: u32,
    members: *mut *mut c_char,
}

unsafe extern "C" {
    fn getgrnam(name: *const c_char) -> *mut GroupEntry;
}

fn lookup_gid(name: &str) -> Result<u32, BrokerError> {
    let name = CString::new(name)
        .map_err(|_| BrokerError::Configuration("workload group name contains NUL"))?;
    let entry = unsafe { getgrnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(BrokerError::Configuration("workload group does not exist"));
    }
    Ok(unsafe { (*entry).gid })
}

fn serve_loader(
    listener: UnixListener,
    state: Arc<Mutex<BrokerState>>,
    timeout: Duration,
    identity_lookup_delay: Duration,
    delivery_fault: Option<DeliveryFault>,
) -> Result<(), BrokerError> {
    serve_connections(
        listener,
        timeout,
        move |stream, deadline| {
            handle_loader_connection(
                stream,
                &state,
                delivery_fault,
                identity_lookup_delay,
                deadline,
            )
        },
        "loader",
    )
}

fn serve_workload(
    listener: UnixListener,
    state: Arc<Mutex<BrokerState>>,
    timeout: Duration,
) -> Result<(), BrokerError> {
    serve_connections(
        listener,
        timeout,
        move |stream, deadline| handle_workload_connection(stream, &state, deadline),
        "workload",
    )
}

fn serve_provision(
    listener: UnixListener,
    state: Arc<Mutex<BrokerState>>,
    timeout: Duration,
) -> Result<(), BrokerError> {
    serve_connections(
        listener,
        timeout,
        move |stream, deadline| handle_provision_connection(stream, &state, deadline),
        "provision",
    )
}

fn serve_connections<F>(
    listener: UnixListener,
    timeout: Duration,
    handler: F,
    role: &'static str,
) -> Result<(), BrokerError>
where
    F: Fn(&mut UnixStream, Instant) -> Result<(), BrokerError> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let active = Arc::new(AtomicUsize::new(0));
    struct ActiveConnection(Arc<AtomicUsize>);
    impl Drop for ActiveConnection {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    for connection in listener.incoming() {
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                eprintln!("{role} listener accept failed: {error}");
                return Err(error.into());
            }
        };
        let deadline = Instant::now() + timeout;
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_ACTIVE_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            reject_connection(
                role,
                &mut stream,
                &BrokerError::Configuration("broker_busy"),
            );
            continue;
        }
        let handler = Arc::clone(&handler);
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            let _slot = ActiveConnection(active);
            let result = (|| {
                stream.set_write_timeout(Some(timeout))?;
                handler(&mut stream, deadline)
            })();
            if let Err(error) = result {
                reject_connection(role, &mut stream, &error);
            }
        });
    }
    Ok(())
}

fn reject_connection(role: &str, stream: &mut UnixStream, error: &BrokerError) {
    eprintln!("{role} request denied: {error}");
    if role == "loader" {
        // LoadCredential= treats the socket stream as credential bytes. Any
        // textual error response would therefore become the credential.
        let _ = stream.shutdown(std::net::Shutdown::Both);
    } else {
        write_error(stream, error);
    }
}

fn handle_loader_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<BrokerState>>,
    delivery_fault: Option<DeliveryFault>,
    identity_lookup_delay: Duration,
    deadline: Instant,
) -> Result<(), BrokerError> {
    let peer = resolve_peer(stream, deadline, identity_lookup_delay)?;
    let _ = remaining(deadline)?;
    if let Some(route) = stream.peer_addr()?.as_abstract_name() {
        return handle_systemd_credential_connection(stream, state, &peer, route, delivery_fault);
    }
    log_peer_identity("loader", &peer);
    let frame = match read_frame(stream, deadline) {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!(
                "loader request denied unit={} invocation={} error={error}",
                peer.unit.as_deref().unwrap_or("<none>"),
                peer.invocation_id.as_deref().unwrap_or("<none>")
            );
            return Err(error);
        }
    };
    let request = parse_loader_request(&frame)?;
    let credential = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .process_loader(&peer, &request.claimed_unit, &request.credential_name)?;
    if let Some(fault) = delivery_fault {
        let response = fault.response(credential.as_bytes());
        stream.write_all(&response)?;
    } else {
        stream.write_all(credential.as_bytes())?;
    }
    Ok(())
}

fn handle_systemd_credential_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<BrokerState>>,
    peer: &PeerIdentity,
    route: &[u8],
    delivery_fault: Option<DeliveryFault>,
) -> Result<(), BrokerError> {
    let (unit, credential) = parse_systemd_credential_route(route)?;
    authorize_systemd_credential_peer(peer, &unit)?;
    eprintln!(
        "identity peer role=systemd-credential uid={} gid={} pidfd={} unit={} invocation={} credential={credential}",
        peer.uid,
        peer.gid,
        peer.pidfd_supported,
        peer.unit.as_deref().unwrap_or("<none>"),
        peer.invocation_id.as_deref().unwrap_or("<none>")
    );
    let value = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .process_systemd_credential(&unit, &credential)?;
    if let Some(fault) = delivery_fault {
        stream.write_all(&fault.response(value.as_bytes()))?;
    } else {
        stream.write_all(value.as_bytes())?;
    }
    Ok(())
}

fn authorize_systemd_credential_peer(
    peer: &PeerIdentity,
    routed_unit: &str,
) -> Result<(), BrokerError> {
    if peer.uid != 0 || !peer.pidfd_supported {
        return Err(BrokerError::Identity(IdentityError::PermissionDenied(
            "native credential delivery requires a root pidfd-authenticated peer",
        )));
    }
    if peer.unit.as_deref() != Some(routed_unit) || peer.invocation_id.is_none() {
        return Err(BrokerError::Identity(IdentityError::BindingMismatch(
            "native credential route does not match pidfd unit identity",
        )));
    }
    Ok(())
}

fn parse_systemd_credential_route(route: &[u8]) -> Result<(String, String), BrokerError> {
    let route = std::str::from_utf8(route)
        .map_err(|_| BrokerError::Protocol(ProtocolError::InvalidUtf8))?;
    let (nonce, route) = route
        .split_once("/unit/")
        .ok_or(BrokerError::Protocol(ProtocolError::InvalidFrame))?;
    if nonce.is_empty() || nonce.len() > 16 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BrokerError::Protocol(ProtocolError::InvalidFrame));
    }
    let (unit, credential) = route
        .split_once('/')
        .ok_or(BrokerError::Protocol(ProtocolError::InvalidFrame))?;
    if unit.is_empty() || credential.is_empty() || credential.contains('/') {
        return Err(BrokerError::Protocol(ProtocolError::InvalidFrame));
    }
    Ok((unit.to_owned(), credential.to_owned()))
}

fn handle_workload_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<BrokerState>>,
    deadline: Instant,
) -> Result<(), BrokerError> {
    let peer = resolve_peer(stream, deadline, Duration::ZERO)?;
    log_peer_identity("workload", &peer);
    let frame = read_frame(stream, deadline)?;
    let request = parse_workload_request(&frame)?;
    let response = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .process_workload(&peer, &request)?;
    stream.write_all(&response)?;
    Ok(())
}

fn handle_provision_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<BrokerState>>,
    deadline: Instant,
) -> Result<(), BrokerError> {
    require_root_peer(stream)?;
    let frame = read_provision_header(stream, deadline)?;
    let text = std::str::from_utf8(&frame).map_err(|_| ProtocolError::InvalidUtf8)?;
    let parts: Vec<&str> = text.trim_end_matches('\n').split(' ').collect();
    if parts.len() != 3 || parts[0] != "PROVISION" {
        return Err(ProtocolError::InvalidFrame.into());
    }
    let (unit, credential) = (parts[1], parts[2]);
    let key = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .provision_key(unit, credential)?;
    stream.write_all(&key)?;
    let mut lengths = [0u8; 8];
    read_exact_until(stream, &mut lengths, deadline)?;
    let enc_len = u32::from_be_bytes(lengths[..4].try_into().unwrap()) as usize;
    let ciphertext_len = u32::from_be_bytes(lengths[4..].try_into().unwrap()) as usize;
    if enc_len != 32 || !(17..=MAX_CREDENTIAL_BYTES + 16).contains(&ciphertext_len) {
        return Err(ProtocolError::TooLarge.into());
    }
    let mut enc = vec![0u8; enc_len];
    let mut ciphertext = vec![0u8; ciphertext_len];
    read_exact_until(stream, &mut enc, deadline)?;
    read_exact_until(stream, &mut ciphertext, deadline)?;
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    let mut trailing = [0u8; 1];
    if stream.read(&mut trailing)? != 0 {
        return Err(ProtocolError::InvalidFrame.into());
    }
    state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .provision_sealed(unit, credential, &enc, &ciphertext)?;
    stream.write_all(b"OK\n")?;
    Ok(())
}

fn read_provision_header(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, BrokerError> {
    let mut frame = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        read_exact_until(stream, &mut byte, deadline)?;
        frame.push(byte[0]);
        if frame.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::TooLarge.into());
        }
        if byte[0] == b'\n' {
            return Ok(frame);
        }
    }
}

fn read_exact_until(
    stream: &mut UnixStream,
    value: &mut [u8],
    deadline: Instant,
) -> Result<(), BrokerError> {
    let mut offset = 0;
    while offset < value.len() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let read = stream.read(&mut value[offset..])?;
        if read == 0 {
            return Err(ProtocolError::InvalidFrame.into());
        }
        offset += read;
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, BrokerError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| {
            BrokerError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline exceeded",
            ))
        })
}

fn log_peer_identity(role: &str, peer: &PeerIdentity) {
    eprintln!(
        "identity peer role={role} uid={} gid={} pidfd={} unit={} invocation={}",
        peer.uid,
        peer.gid,
        peer.pidfd_supported,
        peer.unit.as_deref().unwrap_or("<none>"),
        peer.invocation_id.as_deref().unwrap_or("<none>")
    );
}

fn read_frame(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, BrokerError> {
    let mut frame = Vec::with_capacity(128);
    let mut byte = [0; 1];
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let read = stream.read(&mut byte)?;
        if read == 0 {
            break;
        }
        frame.push(byte[0]);
        if frame.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Protocol(ProtocolError::TooLarge));
        }
        if byte[0] == b'\n' {
            let mut trailing = [0; 1];
            stream.set_read_timeout(Some(remaining(deadline)?))?;
            if stream.read(&mut trailing)? != 0 {
                return Err(BrokerError::Protocol(ProtocolError::InvalidFrame));
            }
            break;
        }
    }
    if frame.is_empty() {
        return Err(BrokerError::Protocol(ProtocolError::Empty));
    }
    Ok(frame)
}

fn write_error(stream: &mut UnixStream, error: &BrokerError) {
    let code = match error {
        BrokerError::Identity(identity) => identity.to_string(),
        BrokerError::OsIdentity(identity) => identity.code().to_owned(),
        BrokerError::Protocol(protocol) => protocol.to_string(),
        BrokerError::Delivery(delivery) => delivery.to_string(),
        BrokerError::Crypto(crypto) => crypto.to_string(),
        BrokerError::Configuration(code) => (*code).to_owned(),
        BrokerError::Io(_) => "io_error".to_owned(),
    };
    let safe_code: String = code
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == ':' {
                character
            } else {
                '_'
            }
        })
        .collect();
    let _ = stream.write_all(&error_frame(&safe_code));
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

pub fn bind_socket(
    path: &Path,
    directory_mode: u32,
    socket_mode: u32,
) -> Result<UnixListener, BrokerError> {
    let parent = path
        .parent()
        .ok_or(BrokerError::Configuration("socket path has no parent"))?;
    match fs::create_dir(parent) {
        Ok(()) => fs::set_permissions(parent, fs::Permissions::from_mode(directory_mode))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(parent)?.file_type().is_dir() {
                return Err(BrokerError::Configuration(
                    "socket parent is not a directory",
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(BrokerError::Configuration(
                "existing socket path is not a socket",
            ));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(socket_mode))?;
    Ok(listener)
}

fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(test)]
mod tests {
    use super::keys::NodeIdentity;
    use super::{
        BrokerConfig, BrokerError, BrokerState, DeliveryFault, MAX_BROKER_AUDIT_EVENTS,
        PendingNodeEvent, authorize_systemd_credential_peer, bind_socket,
        handle_systemd_credential_connection, parse_systemd_credential_route, read_frame,
        reject_connection, spawn_listener_thread, validate_config,
    };
    use blindpass_core::canon::Value;
    use blindpass_core::custody::RecipientKeyPair;
    use blindpass_core::delivery::{CredentialFormat, DeliveryPolicy};
    use blindpass_core::fleet::{ConsumptionMode, PolicySnapshot, Registration, TimeReply};
    use blindpass_core::identity::{PeerIdentity, WorkloadRegistration, WorkloadRequest};
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn state_keeps_loader_and_workload_authorities_separate() {
        let mut state = BrokerState::new(DeliveryPolicy {
            max_bytes: 1024,
            format: CredentialFormat::Utf8,
        });
        state
            .loader_policy
            .map_unit("backup.service", "api-key")
            .unwrap();
        state
            .credentials
            .insert("backup.service:api-key", b"P01-CANARY")
            .unwrap();
        let root_peer = PeerIdentity::fixture(0, 0, "backup.service", "inv-a", "root");
        let output = state
            .process_loader(&root_peer, "backup.service", "api-key")
            .unwrap();
        assert_eq!(output.as_bytes(), b"P01-CANARY");

        state.workloads.push(WorkloadRegistration {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            unit: "agent.service".to_owned(),
            account: "uid:1001".to_owned(),
            invocation_id: Some("inv-a".to_owned()),
        });
        let workload_peer = PeerIdentity::fixture(1001, 1001, "agent.service", "inv-a", "uid:1001");
        let request = WorkloadRequest {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            claimed_unit: "agent.service".to_owned(),
            claimed_invocation_id: "inv-a".to_owned(),
            operation: "health".to_owned(),
        };
        assert!(state.process_workload(&workload_peer, &request).is_ok());
        assert!(state.process_workload(&root_peer, &request).is_err());
    }

    #[test]
    fn pending_node_events_survive_broker_restart_and_acknowledgement() {
        let directory = unique_test_path("pending-events");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let mut state = BrokerState::new(DeliveryPolicy {
            max_bytes: 1024,
            format: CredentialFormat::Utf8,
        });
        state.configure_grant_storage(&identity).unwrap();
        state.pending_node_events.extend([
            PendingNodeEvent {
                idempotency_key: "broker-event-queue-0001".to_owned(),
                kind: "audit".to_owned(),
                body: Value::Object(vec![(
                    "action".to_owned(),
                    Value::String("first".to_owned()),
                )]),
            },
            PendingNodeEvent {
                idempotency_key: "broker-event-queue-0002".to_owned(),
                kind: "audit".to_owned(),
                body: Value::Object(vec![(
                    "action".to_owned(),
                    Value::String("second".to_owned()),
                )]),
            },
        ]);
        state.persist_pending_node_events().unwrap();
        state.audit_overflow_pending = true;
        state.persist_pending_node_events().unwrap();
        let path = identity.pending_node_events_path();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(state);
        drop(identity);

        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let mut restored = BrokerState::new(DeliveryPolicy {
            max_bytes: 1024,
            format: CredentialFormat::Utf8,
        });
        restored.configure_grant_storage(&identity).unwrap();
        assert_eq!(restored.pending_node_events.len(), 2);
        assert!(restored.audit_overflow_pending);
        restored
            .acknowledge_node_events("node-a", &["broker-event-queue-0001".to_owned()])
            .unwrap();
        assert_eq!(restored.pending_node_events.len(), 1);
        assert!(restored.audit_overflow_pending);

        drop(restored);
        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let mut recovered = BrokerState::new(DeliveryPolicy {
            max_bytes: 1024,
            format: CredentialFormat::Utf8,
        });
        recovered.configure_grant_storage(&identity).unwrap();
        assert_eq!(recovered.pending_node_events.len(), 1);
        assert!(recovered.audit_overflow_pending);
        assert_eq!(
            recovered.pending_node_events[0].idempotency_key,
            "broker-event-queue-0002"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn full_broker_audit_buffer_denies_new_operation_requests() {
        let directory = unique_test_path("audit-overflow");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state.configure_grant_storage(&identity).unwrap();
        state.workloads.push(WorkloadRegistration {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            unit: "agent.service".to_owned(),
            account: "uid:1001".to_owned(),
            invocation_id: None,
        });
        state.pending_node_events = (0..MAX_BROKER_AUDIT_EVENTS)
            .map(|index| PendingNodeEvent {
                idempotency_key: format!("broker-event-capacity-{index:08}"),
                kind: "audit".to_owned(),
                body: Value::Object(vec![(
                    "action".to_owned(),
                    Value::String("existing_event".to_owned()),
                )]),
            })
            .collect();
        let peer = PeerIdentity::fixture(1001, 1001, "agent.service", "inv-live", "uid:1001");
        let request = WorkloadRequest {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            claimed_unit: "agent.service".to_owned(),
            claimed_invocation_id: "inv-live".to_owned(),
            operation: "request:bounded-test".to_owned(),
        };

        assert!(matches!(
            state.process_workload(&peer, &request),
            Err(BrokerError::Configuration("audit_backpressure"))
        ));
        assert_eq!(state.pending_node_events.len(), MAX_BROKER_AUDIT_EVENTS);
        assert!(state.audit_overflow_pending);
        let pending_events_path = identity.pending_node_events_path();
        assert!(fs::metadata(&pending_events_path).unwrap().is_file());
        assert_eq!(
            fs::metadata(&pending_events_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        drop(state);
        drop(identity);
        let identity = NodeIdentity::load_or_create(&directory).unwrap();
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state.configure_grant_storage(&identity).unwrap();
        assert_eq!(state.pending_node_events.len(), MAX_BROKER_AUDIT_EVENTS);
        assert!(state.audit_overflow_pending);

        let challenge = state.grant_verifier.begin_time_challenge().unwrap();
        let received_at_ms = super::grants::boottime_ms().unwrap();
        state
            .grant_verifier
            .accept_time_reply(
                &TimeReply {
                    node_id: "node-a".to_owned(),
                    challenge,
                    controller_time_ms: 1_800_000_000_000,
                    issuer_epoch: 1,
                },
                "node-a",
                1,
                received_at_ms,
            )
            .unwrap();
        let acknowledged_key = state.pending_node_events[0].idempotency_key.clone();
        state
            .acknowledge_node_events("node-a", &[acknowledged_key])
            .unwrap();
        assert_eq!(state.pending_node_events.len(), MAX_BROKER_AUDIT_EVENTS);
        assert!(!state.audit_overflow_pending);
        assert_eq!(
            state.pending_node_events.back().unwrap().body.get("action"),
            Some(&Value::String("audit_overflow".to_owned()))
        );
        drop(state);
        drop(identity);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn broker_rejects_operation_request_when_outbox_commit_fails() {
        let directory = unique_test_path("audit-commit-failure");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let queue_path = directory.join("pending-node-events.jsonl");
        fs::create_dir(&queue_path).unwrap();

        let mut state = BrokerState::new(DeliveryPolicy::default());
        state.pending_node_events_path = Some(queue_path.clone());
        state.workloads.push(WorkloadRegistration {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            unit: "agent.service".to_owned(),
            account: "uid:1001".to_owned(),
            invocation_id: None,
        });
        state.fleet_registrations.insert(
            "workload-a".to_owned(),
            Registration {
                node_id: "node-a".to_owned(),
                workload_id: "workload-a".to_owned(),
                unit: "agent.service".to_owned(),
                account: "uid:1001".to_owned(),
                invocation_id: None,
                status: "active".to_owned(),
                consumption_mode: ConsumptionMode::File,
                registration_version: 1,
                policy_version: 1,
                local_ceiling_seconds: 60,
            },
        );
        state.fleet_policy = Some(PolicySnapshot {
            policy_version: 1,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        });
        let challenge = state.grant_verifier.begin_time_challenge().unwrap();
        let received_at_ms = super::grants::boottime_ms().unwrap();
        state
            .grant_verifier
            .accept_time_reply(
                &TimeReply {
                    node_id: "node-a".to_owned(),
                    challenge,
                    controller_time_ms: 1_800_000_000_000,
                    issuer_epoch: 1,
                },
                "node-a",
                1,
                received_at_ms,
            )
            .unwrap();
        let peer = PeerIdentity::fixture(1001, 1001, "agent.service", "inv-live", "uid:1001");
        let payload = br#"{"action":"noop.marker","mode":"file","purpose":"outbox durability","resource_id":"marker-commit-failure","ttl_seconds":60}"#;
        let request = WorkloadRequest {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            claimed_unit: "agent.service".to_owned(),
            claimed_invocation_id: "inv-live".to_owned(),
            operation: format!(
                "request:{}",
                blindpass_core::signing::base64_url_encode(payload)
            ),
        };

        let result = state.process_workload(&peer, &request);
        assert!(
            matches!(
                &result,
                Err(BrokerError::Configuration(
                    "pending node event queue could not be committed"
                ))
            ),
            "outbox commit failure must deny the operation request: {result:?}"
        );
        assert!(state.pending_node_events.is_empty());
        assert!(fs::metadata(&queue_path).unwrap().is_dir());
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            1,
            "failed atomic commit must remove its temporary file"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn socket_modes_and_stale_socket_replacement_are_explicit() {
        let root = unique_test_path("socket-mode");
        let socket = root.join("loader.sock");
        let listener = bind_socket(&socket, 0o750, 0o600).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o750);
        assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
        drop(listener);

        let replacement = bind_socket(&socket, 0o750, 0o660).unwrap();
        assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o660);
        drop(replacement);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_socket_parent_keeps_its_mode() {
        let root = unique_test_path("socket-parent");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("loader.sock");
        let listener = bind_socket(&socket, 0o751, 0o600).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn broker_configuration_keeps_trust_boundaries_distinct() {
        let config = BrokerConfig::default();
        assert!(validate_config(&config).is_ok());

        let mut same_socket = config.clone();
        same_socket.workload_socket = same_socket.loader_socket.clone();
        assert!(
            validate_config(&same_socket)
                .unwrap_err()
                .to_string()
                .contains("distinct")
        );

        let mut relative_socket = config;
        relative_socket.loader_socket = "loader.sock".into();
        assert!(
            validate_config(&relative_socket)
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
    }

    #[test]
    fn delivery_faults_are_explicit_and_do_not_change_the_default() {
        assert_eq!(BrokerConfig::default().delivery_fault, None);
        assert_eq!(DeliveryFault::parse("corrupt"), Ok(DeliveryFault::Corrupt));
        assert!(DeliveryFault::parse("unknown").is_err());
        assert_eq!(DeliveryFault::Empty.response(b"P01-CANARY"), b"");
        assert_eq!(DeliveryFault::Partial.response(b"P01-CANARY"), b"P0");
        assert_eq!(
            DeliveryFault::Malformed.response(b"P01-CANARY"),
            b"not-a-P01-credential"
        );
        assert_eq!(
            DeliveryFault::Corrupt.response(b"P01-CANARY"),
            b"p01-CANARY"
        );
        assert_eq!(
            DeliveryFault::Oversized.response(b"P01-CANARY").len(),
            blindpass_core::MAX_CREDENTIAL_BYTES + 1
        );
    }

    #[test]
    fn systemd_credential_route_parses_only_the_expected_shape() {
        assert_eq!(
            parse_systemd_credential_route(b"d7067f78/unit/backup.service/api-key").unwrap(),
            ("backup.service".to_owned(), "api-key".to_owned())
        );
        for invalid in [
            &b"/unit/backup.service/api-key"[..],
            b"not-hex/unit/backup.service/api-key",
            b"1/unit/backup.service",
            b"1/unit//api-key",
            b"1/unit/backup.service/",
            b"1/unit/backup.service/api-key/other",
        ] {
            assert!(
                parse_systemd_credential_route(invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn native_systemd_route_still_requires_the_protected_mapping() {
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state
            .loader_policy
            .map_unit("backup.service", "api-key")
            .unwrap();
        state
            .credentials
            .insert("backup.service:api-key", b"ERR \0\xffbinary")
            .unwrap();
        assert_eq!(
            state
                .process_systemd_credential("backup.service", "api-key")
                .unwrap()
                .as_bytes(),
            b"ERR \0\xffbinary"
        );
        assert!(
            state
                .process_systemd_credential("backup.service", "other")
                .is_err()
        );
    }

    #[test]
    fn native_systemd_route_must_match_root_pidfd_unit_and_invocation() {
        let matching = PeerIdentity::fixture(0, 0, "backup.service", "inv-backup", "root");
        assert!(authorize_systemd_credential_peer(&matching, "backup.service").is_ok());

        let non_root = PeerIdentity::fixture(1000, 1000, "backup.service", "inv-backup", "user");
        assert!(authorize_systemd_credential_peer(&non_root, "backup.service").is_err());

        let wrong_unit = PeerIdentity::fixture(0, 0, "consumer.service", "inv-consumer", "root");
        assert!(authorize_systemd_credential_peer(&wrong_unit, "backup.service").is_err());

        let mut no_invocation = matching.clone();
        no_invocation.invocation_id = None;
        assert!(authorize_systemd_credential_peer(&no_invocation, "backup.service").is_err());
    }

    #[test]
    fn native_systemd_identity_denial_closes_without_writing_credential_bytes() {
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state
            .loader_policy
            .map_unit("backup.service", "api-key")
            .unwrap();
        state
            .credentials
            .insert("backup.service:api-key", b"P01-CANARY")
            .unwrap();
        let state = Arc::new(Mutex::new(state));
        let peer = PeerIdentity::fixture(0, 0, "attacker.service", "inv-attacker", "root");
        let (mut broker_stream, mut client) = UnixStream::pair().unwrap();

        assert!(
            handle_systemd_credential_connection(
                &mut broker_stream,
                &state,
                &peer,
                b"d7067f78/unit/backup.service/api-key",
                None,
            )
            .is_err()
        );
        drop(broker_stream);
        let mut response = Vec::new();
        std::io::Read::read_to_end(&mut client, &mut response).unwrap();
        assert!(response.is_empty());
    }

    #[test]
    fn native_systemd_delivery_uses_the_configured_fault_response() {
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state
            .loader_policy
            .map_unit("backup.service", "api-key")
            .unwrap();
        state
            .credentials
            .insert("backup.service:api-key", b"P01-CANARY")
            .unwrap();
        let state = Arc::new(Mutex::new(state));
        let peer = PeerIdentity::fixture(0, 0, "backup.service", "inv-backup", "root");
        let (mut broker_stream, mut client) = UnixStream::pair().unwrap();

        handle_systemd_credential_connection(
            &mut broker_stream,
            &state,
            &peer,
            b"d7067f78/unit/backup.service/api-key",
            Some(DeliveryFault::Partial),
        )
        .unwrap();
        drop(broker_stream);
        let mut response = Vec::new();
        std::io::Read::read_to_end(&mut client, &mut response).unwrap();
        assert_eq!(response, b"P0");
    }

    #[test]
    fn native_systemd_stream_preserves_binary_credentials_with_an_error_prefix() {
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state
            .loader_policy
            .map_unit("backup.service", "api-key")
            .unwrap();
        state
            .credentials
            .insert("backup.service:api-key", b"ERR \0\xffbinary")
            .unwrap();
        let state = Arc::new(Mutex::new(state));
        let peer = PeerIdentity::fixture(0, 0, "backup.service", "inv-backup", "root");
        let (mut broker_stream, mut client) = UnixStream::pair().unwrap();

        handle_systemd_credential_connection(
            &mut broker_stream,
            &state,
            &peer,
            b"d7067f78/unit/backup.service/api-key",
            None,
        )
        .unwrap();
        drop(broker_stream);
        let mut response = Vec::new();
        std::io::Read::read_to_end(&mut client, &mut response).unwrap();
        assert_eq!(response, b"ERR \0\xffbinary");
    }

    #[test]
    fn loader_denials_close_without_writing_an_error_credential() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        reject_connection("loader", &mut server, &BrokerError::Configuration("denied"));
        let mut response = Vec::new();
        std::io::Read::read_to_end(&mut client, &mut response).unwrap();
        assert!(response.is_empty());
    }

    #[test]
    fn listener_failure_reaches_the_main_run_loop() {
        let (sender, receiver) = std::sync::mpsc::channel();
        spawn_listener_thread("test-listener", sender.clone(), || {
            Err(BrokerError::Configuration("accept failed"))
        })
        .unwrap();
        drop(sender);
        let error = receiver.recv_timeout(Duration::from_millis(250)).unwrap();
        assert!(error.to_string().contains("accept failed"));
    }

    #[test]
    fn non_socket_path_is_never_overwritten() {
        let root = unique_test_path("socket-confusion");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("loader.sock");
        fs::write(&path, b"do-not-remove").unwrap();
        let error = bind_socket(&path, 0o750, 0o600).unwrap_err();
        assert!(error.to_string().contains("not a socket"));
        assert_eq!(fs::read(&path).unwrap(), b"do-not-remove");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn frame_reader_bounds_stall_and_oversize_inputs() {
        let (_writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let stall = read_frame(
            &mut reader,
            std::time::Instant::now() + Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(
            matches!(stall, super::BrokerError::Io(error) if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock))
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"LOAD unit credential\n").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            read_frame(
                &mut reader,
                std::time::Instant::now() + Duration::from_secs(1)
            )
            .unwrap(),
            b"LOAD unit credential\n"
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"LOAD unit credential\ntrailing").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let error = read_frame(
            &mut reader,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid_frame"));

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&vec![b'x'; blindpass_core::MAX_FRAME_BYTES + 1])
            .unwrap();
        let error = read_frame(
            &mut reader,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("frame_too_large"));
    }

    #[test]
    fn slow_drip_cannot_extend_the_total_request_deadline() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let writer_thread = std::thread::spawn(move || {
            for byte in b"LOAD unit credential\n" {
                if writer.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(12));
            }
        });
        let started = std::time::Instant::now();
        let result = read_frame(&mut reader, started + Duration::from_millis(45));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(150));
        drop(reader);
        writer_thread.join().unwrap();
    }

    #[test]
    fn stalled_peer_does_not_block_a_second_connection() {
        let root = unique_test_path("concurrent-peers");
        let socket = root.join("loader.sock");
        let listener = bind_socket(&socket, 0o750, 0o600).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = super::serve_connections(
                listener,
                Duration::from_millis(250),
                move |stream, deadline| {
                    let frame = read_frame(stream, deadline)?;
                    let _ = sender.send(frame);
                    Ok(())
                },
                "test",
            );
        });
        let stalled = UnixStream::connect(&socket).unwrap();
        let mut ready = UnixStream::connect(&socket).unwrap();
        ready.write_all(b"READY\n").unwrap();
        ready.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_millis(150)).unwrap(),
            b"READY\n"
        );
        drop(stalled);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_state_opens_hpke_only_for_its_mapped_destination() {
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state
            .loader_policy
            .map_unit("consumer.service", "api-key")
            .unwrap();
        state
            .loader_policy
            .map_unit("backup.service", "api-key")
            .unwrap();
        assert!(state.provision_key("other.service", "api-key").is_err());
        let key = state.provision_key("consumer.service", "api-key").unwrap();
        let sealed = RecipientKeyPair::seal(
            &key,
            b"P01-LIVE-CANARY",
            b"blindpass:p01:consumer.service:api-key",
        )
        .unwrap();
        assert!(
            state
                .provision_sealed("other.service", "api-key", &sealed.enc, &sealed.ciphertext)
                .is_err()
        );
        state
            .provision_sealed(
                "consumer.service",
                "api-key",
                &sealed.enc,
                &sealed.ciphertext,
            )
            .unwrap();
        assert_eq!(
            state.credentials.get("consumer.service:api-key").unwrap(),
            b"P01-LIVE-CANARY"
        );
        let backup_peer = PeerIdentity::fixture(0, 0, "backup.service", "inv-b", "root");
        assert!(
            state
                .process_loader(&backup_peer, "backup.service", "api-key")
                .is_err()
        );
        assert!(
            state
                .provision_sealed(
                    "consumer.service",
                    "api-key",
                    &sealed.enc,
                    &sealed.ciphertext
                )
                .is_err()
        );
        let next_key = state.provision_key("consumer.service", "api-key").unwrap();
        let tampered = RecipientKeyPair::seal(&next_key, b"wrong", b"wrong-aad").unwrap();
        assert!(
            state
                .provision_sealed(
                    "consumer.service",
                    "api-key",
                    &tampered.enc,
                    &tampered.ciphertext
                )
                .is_err()
        );
    }

    fn unique_test_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("blindpass-{label}-{}-{nanos}", std::process::id()))
    }
}
