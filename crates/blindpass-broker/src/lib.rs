// SPDX-License-Identifier: AGPL-3.0-only

//! Privileged local broker transport.
//!
//! The loader and workload sockets intentionally share no listener and no
//! authorization path. The loader requires a root peer plus a pidfd-resolved
//! system unit/invocation. The workload socket requires a registered
//! non-root unit/account/invocation tuple.

pub mod browser_catalog;
mod control;
mod grants;
mod keys;
mod operation_request;
mod ops;
pub mod original_workload;
mod owner_retention;
mod provisioning;
#[cfg(test)]
mod provisioning_tests;
pub use ops::browser_session::{ApprovedSession, BrowserResource};
pub use ops::browser_session::{BrowserPreparation, PreparedBrowserLogin, PreparedHelperExchange};
pub use ops::file_credential::{
    CredentialProfile, FileCredentialError, PASSWORD_FILE_MAX_BYTES, resolve_profile_options,
    validate_password_file,
};
mod browser_coordinator;
pub mod browser_proxy;
pub mod browser_supervisor;
pub mod os_identity;
pub mod private_helper;
pub mod runtime_identity;
mod runtime_manager;
pub mod session_journal;
pub mod session_revoker;

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::{CryptoError, EphemeralCustody};
use blindpass_core::delivery::{CredentialRegistry, DeliveryError, DeliveryPolicy};
use blindpass_core::fleet::{ConsumptionMode, PolicySnapshot, Registration};
use blindpass_core::identity::{
    IdentityError, LoaderPolicy, PeerIdentity, WorkloadAuthorization, WorkloadRegistration,
    authorize_workload,
};
use blindpass_core::protocol::{
    CANCEL_OPERATION_PREFIX, ProtocolError, STATUS_OPERATION_PREFIX, error_frame,
    parse_loader_request, parse_workload_request, workload_ok,
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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_ACTIVE_CONNECTIONS: usize = 32;
const DEFAULT_OPERATION_DIRECTORY: &str = "/run/blindpass/ops";
pub(crate) const MAX_BROKER_AUDIT_EVENTS: usize = 10_000;
const MAX_NODE_EVENT_BATCH: usize = 100;
const MAX_DEFERRED_REVOCATION_OUTCOMES: usize = 10_000;
/// Bound for operation ownership and closure records; admission never evicts a live owner.
pub(crate) const MAX_OPERATION_RECORDS: usize = 10_000;
const MAX_PENDING_NODE_EVENT_BYTES: usize = 64 * 1024;
const MAX_PENDING_NODE_EVENTS_BYTES: u64 = 64 * 1024 * 1024;
const PENDING_NODE_EVENT_FILE_MODE: u32 = 0o600;
const O_NOFOLLOW: i32 = blindpass_core::open_flags::O_NOFOLLOW;
static PENDING_EVENT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
pub const DEFAULT_CUSTODY_KEY_LIFETIME: Duration = Duration::from_secs(30);
/// Human provisioning needs far longer than a custody key; the offer is still
/// capped by its grant's expiry and the original consumption deadline.
pub const DEFAULT_BROWSER_OFFER_LIFETIME: Duration = Duration::from_secs(180);
/// Root-owned flag file that arms the VM harness crash hook in test mode.
pub const CONSUME_CRASH_FLAG: &str = "/run/blindpass/test/crash-after-consume-intent";
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
    browser_catalog: Option<browser_catalog::BrowserCatalog>,
    grant_verifier: grants::GrantVerifier,
    /// Controller documents applied in memory whose durable write failed,
    /// keyed by their state file. While any remain the broker is fenced.
    unpersisted_documents: BTreeMap<String, Vec<u8>>,
    operation_directory: PathBuf,
    pending_node_events: VecDeque<PendingNodeEvent>,
    pending_node_events_path: Option<PathBuf>,
    /// Grant revocation outcomes that could not join the full audit queue.
    /// They are emitted once space returns; the revocation itself is never
    /// delayed. Startup rebuilds them from the revocation journal.
    deferred_revocation_outcomes: VecDeque<PendingNodeEvent>,
    revocation_recovery_cursor: Option<String>,
    audit_overflow_pending: bool,
    /// Which workload invocation created each of this broker's operation
    /// requests, so only it may ask for the request's status.
    operation_requests: BoundedRecords<OperationRequestOwner>,
    /// Runtime-only retained original kernel peers. ACK never removes them;
    /// snapshot restore never invents them from a new same-invocation caller.
    original_workload_leases: BTreeMap<String, original_workload::OriginalWorkloadLease>,
    browser_ready: BTreeMap<String, browser_coordinator::BrowserReadyMetadata>,
    /// Request event keys whose protected session-journal record is not
    /// Closed. Maintained by the browser coordinator (superset of the truth
    /// between refreshes); owner retention never evicts these.
    browser_unresolved_requests: std::collections::BTreeSet<String>,
    browser_offers: provisioning::BrowserOfferBook,
    fulfillments: ops::fulfill::FulfillmentBook,
    /// Controller-signed closures and locally verified completion keyed by request event key. Ownership and
    /// closures share the durable outbox snapshot, including after event ACK.
    operation_closures: BoundedRecords<String>,
    pending_state_fenced: AtomicBool,
    node_revoked: bool,
    node_revocation_ack_pending: bool,
    node_revocation_acknowledged: bool,
    node_revocation_observed_at_ms: Option<u64>,
    pub credentials: CredentialRegistry,
    pub custody: EphemeralCustody,
    /// Deadline for a human to answer a browser recipient offer; deliberately
    /// separate from the 30 s custody key lifetime.
    browser_offer_lifetime: Duration,
    credential_expiries: BTreeMap<String, CredentialExpiry>,
    credential_lifetime: Duration,
    /// Application-native credential profiles keyed by credential name
    /// (`--credential-profile`); empty keeps the legacy behaviour.
    credential_profiles: BTreeMap<String, CredentialProfile>,
    /// Test-mode only: abort after a consume intent is durable and before
    /// the operation effect while this root-owned flag file exists.
    consume_crash_flag: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CredentialExpiry {
    runnable: Instant,
    boot: u64,
}
impl CredentialExpiry {
    fn after(lifetime: Duration) -> Result<Self, BrokerError> {
        let boot = grants::boottime_ms()
            .map_err(BrokerError::Configuration)?
            .checked_add(
                u64::try_from(lifetime.as_millis())
                    .map_err(|_| BrokerError::Configuration("credential_lifetime_invalid"))?,
            )
            .ok_or(BrokerError::Configuration("credential_lifetime_invalid"))?;
        let runnable = Instant::now()
            .checked_add(lifetime)
            .ok_or(BrokerError::Configuration("credential_lifetime_invalid"))?;
        Ok(Self { runnable, boot })
    }
    fn current(self) -> bool {
        Instant::now() < self.runnable && grants::boottime_ms().is_ok_and(|now| now < self.boot)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperationRequestOwner {
    workload_id: String,
    invocation_id: String,
    mode: Option<ConsumptionMode>,
    cancel_requested: bool,
    cancel_acknowledged: bool,
    browser_request: Option<operation_request::BrowserRequestBinding>,
}

/// Insertion-ordered map that evicts its oldest entry beyond a fixed bound.
#[derive(Debug, Clone)]
pub(crate) struct BoundedRecords<V> {
    values: BTreeMap<String, V>,
    order: VecDeque<String>,
    limit: usize,
}

impl<V> BoundedRecords<V> {
    fn new(limit: usize) -> Self {
        Self {
            values: BTreeMap::new(),
            order: VecDeque::new(),
            limit,
        }
    }

    fn insert(&mut self, key: &str, value: V) {
        if self.values.insert(key.to_owned(), value).is_none() {
            self.order.push_back(key.to_owned());
        }
        while self.order.len() > self.limit {
            if let Some(oldest) = self.order.pop_front() {
                self.values.remove(&oldest);
            }
        }
    }

    fn get(&self, key: &str) -> Option<&V> {
        self.values.get(key)
    }

    fn remove(&mut self, key: &str) {
        self.values.remove(key);
        self.order.retain(|entry| entry != key);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }
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
            .filter(|kind| {
                matches!(
                    *kind,
                    "operation_request"
                        | "operation_result"
                        | "operation_cancel"
                        | "audit"
                        | "fulfillment_result"
                )
            })
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
        if kind == "operation_cancel" {
            let cancellation = blindpass_core::fleet::OperationCancellation::from_value(&body)
                .map_err(|_| BrokerError::Configuration("pending cancellation is malformed"))?;
            if cancellation
                .event_key()
                .map_err(|_| BrokerError::Configuration("pending cancellation is malformed"))?
                != idempotency_key
            {
                return Err(BrokerError::Configuration(
                    "pending cancellation key mismatch",
                ));
            }
        }
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
            browser_catalog: None,
            grant_verifier: grants::GrantVerifier::default(),
            unpersisted_documents: BTreeMap::new(),
            operation_directory: PathBuf::from(DEFAULT_OPERATION_DIRECTORY),
            pending_node_events: VecDeque::new(),
            pending_node_events_path: None,
            deferred_revocation_outcomes: VecDeque::new(),
            revocation_recovery_cursor: None,
            audit_overflow_pending: false,
            operation_requests: BoundedRecords::new(MAX_OPERATION_RECORDS),
            original_workload_leases: BTreeMap::new(),
            browser_ready: BTreeMap::new(),
            browser_unresolved_requests: std::collections::BTreeSet::new(),
            browser_offers: provisioning::BrowserOfferBook::default(),
            fulfillments: ops::fulfill::FulfillmentBook::default(),
            operation_closures: BoundedRecords::new(MAX_OPERATION_RECORDS),
            pending_state_fenced: AtomicBool::new(false),
            node_revoked: false,
            node_revocation_ack_pending: false,
            node_revocation_acknowledged: false,
            node_revocation_observed_at_ms: None,
            credentials: CredentialRegistry::new(delivery_policy),
            custody: EphemeralCustody::new(custody_key_lifetime),
            browser_offer_lifetime: DEFAULT_BROWSER_OFFER_LIFETIME,
            credential_expiries: BTreeMap::new(),
            credential_lifetime,
            credential_profiles: BTreeMap::new(),
            consume_crash_flag: None,
        }
    }

    /// Arm the crash-after-consume-intent hook used by the disposable VM
    /// harness. The binary calls this only when `BLINDPASS_P01_TEST_MODE=1`.
    pub fn enable_consume_crash_hook(&mut self, flag: PathBuf) {
        self.consume_crash_flag = Some(flag);
    }

    /// Install trusted startup configuration atomically after validating every
    /// source mapping. Catalog data never comes from the workload protocol.
    pub fn configure_browser_catalog(
        &mut self,
        catalog: browser_catalog::BrowserCatalog,
    ) -> Result<(), BrokerError> {
        for resource in catalog.resources() {
            let (unit, credential) = resource.credential_destination();
            self.validate_mapping(unit, credential)?;
            if let Some(profile) = resource.revocation_profile() {
                let (unit, credential) = profile.credential_destination();
                self.validate_mapping(unit, credential)?;
            }
        }
        self.browser_catalog = Some(catalog);
        Ok(())
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
        // The one-use recipient key is spent by the open above. A profile
        // rejection leaves the destination's existing value and expiry untouched.
        self.enforce_provisioned_profile(credential, value.as_bytes())?;
        let key = destination_key(unit, credential);
        let expiry = CredentialExpiry::after(self.credential_lifetime)?;
        self.credentials.insert_secret(&key, value)?;
        self.credential_expiries.insert(key, expiry);
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
        self.revalidate_delivery_profile(&authorization.unit, &authorization.credential_name)?;
        let secret = SecretBytes::from_slice(self.credentials.get(&destination_key(
            &authorization.unit,
            &authorization.credential_name,
        ))?);
        self.note_fulfillment_read(&authorization.unit, &authorization.credential_name);
        Ok(secret)
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
        self.revalidate_delivery_profile(unit, credential)?;
        let secret =
            SecretBytes::from_slice(self.credentials.get(&destination_key(unit, credential))?);
        self.note_fulfillment_read(unit, credential);
        Ok(secret)
    }

    fn purge_expired_credentials(&mut self) {
        self.custody.purge_expired();
        let authorized = self
            .browser_dispatch_candidates()
            .into_iter()
            .map(|candidate| candidate.grant.id)
            .collect();
        self.browser_offers
            .maintain(grants::boottime_ms().ok(), &authorized);
        self.maintain_fulfillments();
        self.credential_expiries.retain(|name, expiry| {
            if !expiry.current() {
                self.credentials.remove(name);
                false
            } else {
                true
            }
        });
    }

    /// Trusted coordinator entry point. Call under the short state lock, then
    /// execute PreparedBrowserLogin::call_helper only after releasing that lock.
    /// Resource and journal are installed root configuration, never workload
    /// selectors. Normal workload framing is wired by the later coordinator.
    pub fn prepare_browser_login(
        &mut self,
        peer: &PeerIdentity,
        request: &blindpass_core::identity::WorkloadRequest,
        resource: &BrowserResource,
        journal: &mut session_journal::SessionJournal,
    ) -> Result<BrowserPreparation, BrokerError> {
        if self.node_revoked {
            return Err(BrokerError::Configuration("node_revoked"));
        }
        let authorization = authorize_workload(peer, request, &self.workloads)?;
        let grant_id = request
            .operation
            .strip_prefix("consume:")
            .filter(|id| valid_event_identifier(id))
            .ok_or(BrokerError::Configuration("invalid_browser_request"))?;
        if let Some((binding, status)) = journal.replay_binding(grant_id) {
            if binding.node_id != authorization.node_id
                || binding.workload_id != authorization.workload_id
                || binding.recipe_fingerprint
                    != resource
                        .recipe_fingerprint()
                        .map_err(BrokerError::Configuration)?
                || binding.workload_unit != authorization.unit
                || binding.workload_invocation != authorization.invocation_id
                || !resource.permits(&authorization.workload_id, &binding.resource)
                || binding.account != resource.account()
            {
                return Err(BrokerError::Configuration("browser_replay_denied"));
            }
            return Ok(BrowserPreparation::Existing(status));
        }
        if self.persistence_fenced() {
            return Err(BrokerError::Configuration("broker_persistence_fenced"));
        }
        if self.pending_node_events.len() > MAX_BROKER_AUDIT_EVENTS - 2 {
            self.flag_audit_overflow()?;
            return Err(BrokerError::Configuration("audit_backpressure"));
        }
        if [
            "BLINDPASS_ALLOW_EXPOSE_PLAINTEXT",
            "DEBUG",
            "PWDEBUG",
            "NODE_OPTIONS",
        ]
        .iter()
        .any(|name| {
            std::env::var_os(name).is_some_and(|value| {
                !value.is_empty()
                    && (name != &"BLINDPASS_ALLOW_EXPOSE_PLAINTEXT"
                        || value != "0" && value != "false")
            })
        }) {
            return Err(BrokerError::Configuration("unsafe_browser_configuration"));
        }
        let now = grants::boottime_ms().map_err(BrokerError::Configuration)?;
        let time = self
            .grant_verifier
            .trusted_controller_time_ms(now)
            .ok_or(BrokerError::Configuration("trusted_time_unavailable"))?;
        let policy = self
            .fleet_policy
            .as_ref()
            .ok_or(BrokerError::Configuration("fleet_policy_unavailable"))?;
        let policy_version = policy.policy_version;
        let (grant, grant_deadline) = self
            .grant_verifier
            .preview_consumption_deadline(grant_id, &authorization, policy_version, now)
            .map_err(|error| BrokerError::Configuration(error.code()))?;
        if grant.action != "browser.session"
            || grant.mode != ConsumptionMode::BrowserSession
            || !resource.permits(&authorization.workload_id, &grant.resource_id)
        {
            return Err(BrokerError::Configuration("browser_resource_denied"));
        }
        self.authorize_browser_request_owner(&grant)?;
        let original_recipe = self
            .operation_requests
            .get(
                grant
                    .request_event_key
                    .as_deref()
                    .expect("validated correlation"),
            )
            .and_then(|owner| owner.browser_request.as_ref())
            .and_then(|binding| binding.recipe_fingerprint.as_deref());
        if original_recipe
            != Some(
                resource
                    .recipe_fingerprint()
                    .map_err(BrokerError::Configuration)?
                    .as_str(),
            )
        {
            return Err(BrokerError::Configuration(
                "browser_request_binding_unavailable",
            ));
        }
        if self
            .grant_verifier
            .preview_request_grant(
                grant
                    .request_event_key
                    .as_deref()
                    .expect("validated request correlation"),
                &authorization,
                policy_version,
                now,
            )
            .as_ref()
            != Some(&grant)
        {
            return Err(BrokerError::Configuration(
                "browser_request_binding_unavailable",
            ));
        }
        let registration = self
            .fleet_registrations
            .get(&authorization.workload_id)
            .ok_or(BrokerError::Configuration(
                "browser_registration_unavailable",
            ))?;
        if registration.status != "active"
            || registration.registration_version != grant.registration_version
            || registration.account != grant.account
            || registration.consumption_mode != grant.mode
            || registration.policy_version != policy_version
            || !policy
                .allowed_actions
                .iter()
                .any(|action| action == "browser.session")
            || !policy
                .allowed_modes
                .contains(&ConsumptionMode::BrowserSession)
        {
            return Err(BrokerError::Configuration("browser_registration_changed"));
        }
        let profile = resource
            .revocation_profile()
            .ok_or(BrokerError::Configuration("browser_revocation_unavailable"))?;
        let (admin_unit, admin_name) = profile.credential_destination();
        self.validate_mapping(admin_unit, admin_name)?;
        self.purge_expired_credentials();
        // The administrator copy is validated before any source copy or journal
        // reservation; actual online preflight gates the later source delivery.
        let revocation_credential = SecretBytes::from_slice(
            self.credentials
                .get(&destination_key(admin_unit, admin_name))
                .map_err(|_| BrokerError::Configuration("browser_revocation_unavailable"))?,
        );
        profile
            .validate_credential(&revocation_credential)
            .map_err(BrokerError::Configuration)?;
        let (unit, credential) = resource.credential_destination();
        self.validate_mapping(unit, credential)?;
        let source_expiry = *self
            .credential_expiries
            .get(&destination_key(unit, credential))
            .filter(|expiry| expiry.current())
            .ok_or(BrokerError::Configuration("browser_source_expired"))?;
        let password =
            SecretBytes::from_slice(self.credentials.get(&destination_key(unit, credential))?);
        let helper_job = resource
            .helper_job(&password)
            .map_err(BrokerError::Configuration)?;
        // The source copy is no longer needed once the private framed job exists.
        drop(password);
        let binding = session_journal::SessionBinding {
            node_id: grant.node_id.clone(),
            workload_id: grant.workload_id.clone(),
            recipe_fingerprint: resource
                .recipe_fingerprint()
                .map_err(BrokerError::Configuration)?,
            operation_id: grant.operation_id.clone(),
            idempotency_key: grant.id.clone(),
            request_event_key: grant.request_event_key.clone(),
            workload_unit: grant.unit.clone(),
            workload_invocation: grant.invocation_id.clone(),
            resource: grant.resource_id.clone(),
            account: resource.account().to_owned(),
        };
        if journal
            .reserve(binding, time)
            .map_err(BrokerError::Configuration)?
            != session_journal::Reservation::New
        {
            return Err(BrokerError::Configuration("browser_operation_conflict"));
        }
        let event_keys = [new_node_event_key()?, new_node_event_key()?];
        self.queue_operation_result(
            &grant,
            "uncertain",
            "result_uncertain",
            time,
            event_keys.clone(),
        )?;
        match self
            .grant_verifier
            .consume(grant_id, &authorization, policy_version, now)
        {
            Ok(consumed) if consumed == grant => {}
            Ok(_) => return Err(BrokerError::Configuration("browser_consume_uncertain")),
            Err(error) => {
                self.withdraw_pending_events(&event_keys);
                return Err(BrokerError::Configuration(error.code()));
            }
        }
        Ok(BrowserPreparation::Login(Box::new(PreparedBrowserLogin {
            original_workload: self
                .original_workload_leases
                .get(
                    grant
                        .request_event_key
                        .as_deref()
                        .expect("validated original owner"),
                )
                .expect("verified original lease")
                .clone(),
            grant,
            resource: resource.clone(),
            helper_job: Some(helper_job),
            source_expiry,
            revocation_credential: Some(revocation_credential),
            event_keys,
            deadline_boottime_ms: grant_deadline.min(
                now.checked_add(120_000)
                    .ok_or(BrokerError::Configuration("browser_deadline_invalid"))?,
            ),
        })))
    }

    /// Recheck after private authentication and before each import/publication.
    /// Consuming the one-use grant does not bypass later revoke or policy changes.
    pub fn authorize_browser_handoff(&self, job: &PreparedBrowserLogin) -> Result<(), BrokerError> {
        if grants::boottime_ms().map_err(BrokerError::Configuration)? >= job.deadline_boottime_ms {
            return Err(BrokerError::Configuration("browser_authority_expired"));
        }
        self.authorize_browser_grant(&job.grant)
    }

    /// Verified cleanup publishes a new immutable pair, independent of ACK of
    /// the provisional intent. Execute only after public authority is closed
    /// and actual helper/website/browser reconciliation is durable.
    /// Root recovery copies only the configured administrator credential.
    /// It does not consume or copy source, restore grant authority or relogin.
    fn browser_recovery_input(
        &mut self,
        record: &session_journal::SessionRecord,
    ) -> Result<(BrowserResource, SecretBytes, u64), BrokerError> {
        let observed = self.browser_trusted_time()?;
        let resource = self
            .browser_catalog
            .as_ref()
            .and_then(|catalog| {
                catalog.select(&record.binding.workload_id, &record.binding.resource)
            })
            .filter(|resource| {
                resource.account() == record.binding.account
                    && resource.recipe_fingerprint().ok().as_deref()
                        == Some(record.binding.recipe_fingerprint.as_str())
            })
            .cloned()
            .ok_or(BrokerError::Configuration(
                "browser_recovery_recipe_unavailable",
            ))?;
        let profile = resource
            .revocation_profile()
            .ok_or(BrokerError::Configuration("browser_revocation_unavailable"))?;
        let (unit, name) = profile.credential_destination();
        self.validate_mapping(unit, name)?;
        self.purge_expired_credentials();
        let administrator =
            SecretBytes::from_slice(self.credentials.get(&destination_key(unit, name))?);
        profile
            .validate_credential(&administrator)
            .map_err(BrokerError::Configuration)?;
        Ok((resource, administrator, observed))
    }
    pub fn finish_browser_operation(
        &mut self,
        job: &PreparedBrowserLogin,
        journal: &session_journal::SessionJournal,
    ) -> Result<[String; 2], BrokerError> {
        let (binding, _) = journal
            .closed_record(job.grant_id())
            .ok_or(BrokerError::Configuration("browser_closure_unavailable"))?;
        if job.grant.action != "browser.session"
            || job.grant.mode != ConsumptionMode::BrowserSession
            || binding.node_id != job.grant.node_id
            || binding.operation_id != job.grant.operation_id
            || binding.workload_id != job.grant.workload_id
            || binding.workload_unit != job.grant.unit
            || binding.workload_invocation != job.grant.invocation_id
            || binding.resource != job.grant.resource_id
            || binding.account != job.resource.account()
            || binding.recipe_fingerprint
                != job
                    .resource
                    .recipe_fingerprint()
                    .map_err(BrokerError::Configuration)?
        {
            return Err(BrokerError::Configuration(
                "browser_closure_binding_invalid",
            ));
        }
        let key = job
            .grant
            .request_event_key
            .as_deref()
            .ok_or(BrokerError::Configuration(
                "browser_closure_binding_invalid",
            ))?;
        let owner = self
            .operation_requests
            .get(key)
            .filter(|owner| {
                owner.mode == Some(ConsumptionMode::BrowserSession)
                    && owner.workload_id == binding.workload_id
                    && owner.invocation_id == binding.workload_invocation
                    && owner.browser_request.as_ref().is_some_and(|request| {
                        request.node_id == binding.node_id
                            && request.unit == binding.workload_unit
                            && request.resource_id.as_deref() == Some(binding.resource.as_str())
                            && request.recipe_fingerprint.as_deref()
                                == Some(binding.recipe_fingerprint.as_str())
                    })
            })
            .ok_or(BrokerError::Configuration(
                "browser_closure_binding_invalid",
            ))?;
        let mark_completed = !owner.cancel_requested && self.operation_closures.get(key).is_none();
        let previous_closures = self.operation_closures.clone();
        // Cleanup already happened: never restore runtime authority on queue or
        // storage failure. Cancellation and signed revocation remain terminal.
        self.original_workload_leases.remove(key);
        if mark_completed {
            let status = self.browser_closure_status(job.grant_id());
            self.operation_closures.insert(key, status.into());
        }
        match self.publish_browser_closure_inner(
            journal,
            &job.grant.node_id,
            job.grant_id(),
            mark_completed,
        ) {
            Ok(keys) => Ok(keys),
            Err(error) => {
                self.operation_closures = previous_closures;
                Err(error)
            }
        }
    }
    /// Recovery may replay a durable closed record without reconstructing an
    /// original process or re-consuming authority. `node_id` is the Root pin's
    /// actual node, never an untrusted caller label. Original close time and
    /// deterministic keys keep acknowledged events byte-for-byte immutable.
    pub fn publish_browser_closure(
        &mut self,
        journal: &session_journal::SessionJournal,
        node_id: &str,
        grant_id: &str,
    ) -> Result<[String; 2], BrokerError> {
        self.publish_browser_closure_inner(journal, node_id, grant_id, false)
    }
    /// Retry durable verified closures without recreating a login or runtime.
    /// Successful records are scanned once per process; restart intentionally
    /// replays canonical event keys/time. ACK cannot start an endless scan loop.
    pub(crate) fn retry_browser_closures(
        &mut self,
        journal: &session_journal::SessionJournal,
        published: &mut std::collections::BTreeSet<String>,
    ) {
        let records = journal.closed_browser_records();
        published.retain(|id| {
            records
                .iter()
                .any(|record| record.binding.idempotency_key == *id)
        });
        for record in records {
            let binding = &record.binding;
            if published.contains(&binding.idempotency_key) {
                continue;
            }
            let key = binding.request_event_key.as_ref().and_then(|key| {
                self.operation_requests.get(key).and_then(|owner| {
                    (owner.mode == Some(ConsumptionMode::BrowserSession)
                        && owner.workload_id == binding.workload_id
                        && owner.invocation_id == binding.workload_invocation
                        && owner.browser_request.as_ref().is_some_and(|request| {
                            request.node_id == binding.node_id
                                && request.unit == binding.workload_unit
                                && request.resource_id.as_deref() == Some(binding.resource.as_str())
                                && request.recipe_fingerprint.as_deref()
                                    == Some(binding.recipe_fingerprint.as_str())
                        }))
                    .then(|| key.clone())
                })
            });
            let previous_closures = self.operation_closures.clone();
            let completed = key.as_ref().is_some_and(|key| {
                self.operation_requests
                    .get(key)
                    .is_some_and(|owner| !owner.cancel_requested)
                    && self.operation_closures.get(key).is_none()
            });
            if let Some(key) = key.as_ref() {
                // The journal proves cleanup. Never restore original authority
                // even if queue/storage prevents reporting the final result.
                self.original_workload_leases.remove(key);
                if completed {
                    let status = self.browser_closure_status(&binding.idempotency_key);
                    self.operation_closures.insert(key, status.into());
                }
            }
            match self.publish_browser_closure_inner(
                journal,
                &binding.node_id,
                &binding.idempotency_key,
                completed,
            ) {
                Ok(_) => {
                    published.insert(binding.idempotency_key.clone());
                }
                Err(_) => {
                    self.operation_closures = previous_closures;
                }
            }
        }
    }
    fn publish_browser_closure_inner(
        &mut self,
        journal: &session_journal::SessionJournal,
        node_id: &str,
        grant_id: &str,
        dirty: bool,
    ) -> Result<[String; 2], BrokerError> {
        let (binding, time) = journal
            .closed_record(grant_id)
            .filter(|(binding, _)| binding.node_id == node_id)
            .ok_or(BrokerError::Configuration("browser_closure_unavailable"))?;
        let material = canonicalize_value(&Value::Array(vec![
            Value::String("blindpass:browser-closure:v1".into()),
            Value::String(node_id.into()),
            Value::String(grant_id.into()),
            Value::String(binding.operation_id.clone()),
        ]))
        .map_err(|_| BrokerError::Configuration("browser_closure_event_invalid"))?;
        let digest = blindpass_core::custody::sha256(&material)?;
        let digest = blindpass_core::signing::base64_url_encode(&digest);
        let keys = [
            format!("event_browser_closed_{digest}"),
            format!("event_browser_closed_audit_{digest}"),
        ];
        let events = [
            PendingNodeEvent {
                idempotency_key: keys[0].clone(),
                kind: "operation_result".into(),
                body: Value::Object(vec![
                    ("grant_id".into(), Value::String(grant_id.into())),
                    (
                        "operation_id".into(),
                        Value::String(binding.operation_id.clone()),
                    ),
                    ("observed_at_ms".into(), Value::Unsigned(time)),
                    ("status".into(), Value::String("completed".into())),
                    (
                        "result_code".into(),
                        Value::String("browser_session_closed".into()),
                    ),
                ]),
            },
            PendingNodeEvent {
                idempotency_key: keys[1].clone(),
                kind: "audit".into(),
                body: Value::Object(vec![
                    ("action".into(), Value::String("operation_result".into())),
                    ("grant_id".into(), Value::String(grant_id.into())),
                    (
                        "operation_id".into(),
                        Value::String(binding.operation_id.clone()),
                    ),
                    ("observed_at_ms".into(), Value::Unsigned(time)),
                    ("status".into(), Value::String("completed".into())),
                ]),
            },
        ];
        let mut missing = Vec::new();
        for event in events {
            match self
                .pending_node_events
                .iter()
                .find(|pending| pending.idempotency_key == event.idempotency_key)
            {
                Some(existing) => {
                    if existing.kind != event.kind
                        || canonicalize_value(&existing.body).map_err(|_| {
                            BrokerError::Configuration("browser_closure_event_invalid")
                        })? != canonicalize_value(&event.body).map_err(|_| {
                            BrokerError::Configuration("browser_closure_event_invalid")
                        })?
                    {
                        return Err(BrokerError::Configuration("browser_closure_event_conflict"));
                    }
                }
                None => missing.push(event),
            }
        }
        if self.pending_node_events.len().saturating_add(missing.len()) > MAX_BROKER_AUDIT_EVENTS {
            return Err(BrokerError::Configuration("audit_backpressure"));
        }
        if !missing.is_empty() || dirty {
            let previous = self.pending_node_events.clone();
            self.pending_node_events.extend(missing);
            if let Err(error) = self.persist_pending_node_events() {
                self.pending_node_events = previous;
                return Err(error);
            }
        }
        Ok(keys)
    }

    fn authorize_browser_request_owner(
        &self,
        grant: &blindpass_core::fleet::Grant,
    ) -> Result<(), BrokerError> {
        let key = grant
            .request_event_key
            .as_deref()
            .ok_or(BrokerError::Configuration(
                "browser_request_binding_unavailable",
            ))?;
        let binding = self
            .operation_requests
            .get(key)
            .and_then(|owner| owner.browser_request.as_ref())
            .ok_or(BrokerError::Configuration(
                "browser_request_binding_unavailable",
            ))?;
        let selected = self
            .browser_catalog
            .as_ref()
            .and_then(|catalog| catalog.select(&grant.workload_id, &grant.resource_id))
            .ok_or(BrokerError::Configuration(
                "browser_request_binding_unavailable",
            ))?;
        if binding.before_admission()
            || binding.node_id != grant.node_id
            || binding.unit != grant.unit
            || binding.resource_id.as_deref() != Some(grant.resource_id.as_str())
            || binding.recipe_fingerprint.as_deref()
                != Some(
                    selected
                        .recipe_fingerprint()
                        .map_err(BrokerError::Configuration)?
                        .as_str(),
                )
        {
            return Err(BrokerError::Configuration(
                "browser_request_binding_unavailable",
            ));
        }
        if self.operation_closures.get(key).is_some()
            || self.operation_requests.get(key).is_none_or(|owner| {
                owner.workload_id != grant.workload_id
                    || owner.invocation_id != grant.invocation_id
                    || owner.mode != Some(ConsumptionMode::BrowserSession)
                    || owner.cancel_requested
            })
        {
            return Err(BrokerError::Configuration(
                "browser_request_binding_unavailable",
            ));
        }
        if self
            .original_workload_leases
            .get(key)
            .is_none_or(|lease| !lease.matches(grant))
        {
            return Err(BrokerError::Configuration(
                "browser_original_owner_unavailable",
            ));
        }
        Ok(())
    }

    /// Current authority after one-use consumption. Independent session and
    /// boot-time runtime deadlines are enforced by the context coordinator.
    fn authorize_browser_grant(
        &self,
        grant: &blindpass_core::fleet::Grant,
    ) -> Result<(), BrokerError> {
        self.authorize_browser_request_owner(grant)?;
        if self.node_revoked
            || self.persistence_fenced()
            || self.grant_verifier.has_tombstone(&grant.id)
            || !self.grant_verifier.matches_issuer_epoch(grant.issuer_epoch)
        {
            return Err(BrokerError::Configuration("browser_authority_revoked"));
        }
        let now = grants::boottime_ms().map_err(BrokerError::Configuration)?;
        if self
            .grant_verifier
            .trusted_controller_time_ms(now)
            .is_none()
        {
            return Err(BrokerError::Configuration("browser_authority_expired"));
        }
        let policy = self
            .fleet_policy
            .as_ref()
            .ok_or(BrokerError::Configuration("fleet_policy_unavailable"))?;
        let registration =
            self.fleet_registrations
                .get(&grant.workload_id)
                .ok_or(BrokerError::Configuration(
                    "browser_registration_unavailable",
                ))?;
        if policy.policy_version != grant.policy_version
            || registration.registration_version != grant.registration_version
            || registration.policy_version != grant.policy_version
            || registration.status != "active"
            || registration.unit != grant.unit
            || registration.account != grant.account
            || registration.consumption_mode != ConsumptionMode::BrowserSession
            || registration
                .invocation_id
                .as_deref()
                .is_some_and(|invocation| invocation != grant.invocation_id)
            || !policy
                .allowed_modes
                .contains(&ConsumptionMode::BrowserSession)
            || !policy
                .allowed_actions
                .iter()
                .any(|action| action == "browser.session")
        {
            return Err(BrokerError::Configuration("browser_registration_changed"));
        }
        Ok(())
    }

    /// Production admission captures only a fresh browser request's original
    /// actual peer. Retry/status/restore cannot attach a replacement process.
    fn process_workload_owned(
        &mut self,
        peer: Arc<os_identity::LivePeer>,
        request: &blindpass_core::identity::WorkloadRequest,
    ) -> Result<Vec<u8>, BrokerError> {
        let _ = self.reap_original_workload_leases();
        let authorization = authorize_workload(peer.identity(), request, &self.workloads)?;
        let fresh = self.needs_original_workload_lease(&authorization, request)?;
        if fresh {
            peer.ensure_alive()?;
        }
        let response = self.process_workload(peer.identity(), request)?;
        if fresh {
            let key = std::str::from_utf8(&response)
                .ok()
                .and_then(|text| text.strip_prefix("OK operation_request "))
                .map(str::trim)
                .filter(|key| valid_event_identifier(key))
                .ok_or(BrokerError::Configuration(
                    "browser_original_owner_unavailable",
                ))?;
            if self.original_workload_leases.contains_key(key) {
                return Err(BrokerError::Configuration(
                    "browser_original_owner_unavailable",
                ));
            }
            match original_workload::OriginalWorkloadLease::captured(
                key,
                authorization.clone(),
                peer,
            ) {
                Ok(lease) => {
                    self.original_workload_leases.insert(key.into(), lease);
                }
                Err(code) => {
                    let _ = self.cancel_browser_operation(&authorization, key);
                    return Err(BrokerError::Configuration(code));
                }
            }
        }
        Ok(response)
    }

    fn needs_original_workload_lease(
        &self,
        authorization: &WorkloadAuthorization,
        request: &blindpass_core::identity::WorkloadRequest,
    ) -> Result<bool, BrokerError> {
        let input = request
            .operation
            .strip_prefix("request:")
            .map(operation_request::RequestInput::parse)
            .transpose()?;
        let fresh = if let Some(input) = &input {
            input.mode == ConsumptionMode::BrowserSession
                && match &input.request_key {
                    Some(key) => self.find_browser_request_key(authorization, key)?.is_none(),
                    None => true,
                }
        } else {
            false
        };
        if fresh
            && self.original_workload_leases.len()
                >= original_workload::MAX_ORIGINAL_WORKLOAD_LEASES
        {
            return Err(BrokerError::Configuration("browser_owner_capacity"));
        }
        Ok(fresh)
    }

    fn browser_dispatch_candidates(&self) -> Vec<browser_coordinator::BrowserCandidate> {
        let Some(policy) = &self.fleet_policy else {
            return Vec::new();
        };
        let Some(catalog) = &self.browser_catalog else {
            return Vec::new();
        };
        let Ok(now) = grants::boottime_ms() else {
            return Vec::new();
        };
        self.original_workload_leases
            .iter()
            .filter_map(|(key, original)| {
                let grant = self.grant_verifier.preview_request_grant(
                    key,
                    original.authorization(),
                    policy.policy_version,
                    now,
                )?;
                self.authorize_browser_grant(&grant).ok()?;
                Some(browser_coordinator::BrowserCandidate {
                    resource: catalog
                        .select(&grant.workload_id, &grant.resource_id)?
                        .clone(),
                    grant,
                    original: original.clone(),
                })
            })
            .collect()
    }
    fn browser_clock_anchor(&self) -> Result<(u64, u64), BrokerError> {
        let boot = grants::boottime_ms().map_err(BrokerError::Configuration)?;
        let controller = self
            .grant_verifier
            .trusted_controller_time_ms(boot)
            .ok_or(BrokerError::Configuration("trusted_time_unavailable"))?;
        Ok((boot, controller))
    }
    fn browser_trusted_time(&self) -> Result<u64, BrokerError> {
        self.grant_verifier
            .trusted_controller_time_ms(grants::boottime_ms().map_err(BrokerError::Configuration)?)
            .ok_or(BrokerError::Configuration("trusted_time_unavailable"))
    }
    /// Clone the original authority for bounded manager IO outside the mutex.
    fn original_workload_for_consumption(
        &self,
        peer: &PeerIdentity,
        request: &blindpass_core::identity::WorkloadRequest,
    ) -> Result<Option<original_workload::OriginalWorkloadLease>, BrokerError> {
        let Some(grant_id) = request.operation.strip_prefix("consume:") else {
            return Ok(None);
        };
        let authorization = authorize_workload(peer, request, &self.workloads)?;
        let policy_version = self
            .fleet_policy
            .as_ref()
            .ok_or(BrokerError::Configuration("fleet_policy_unavailable"))?
            .policy_version;
        let grant = self
            .grant_verifier
            .preview_consumption(
                grant_id,
                &authorization,
                policy_version,
                grants::boottime_ms().map_err(BrokerError::Configuration)?,
            )
            .map_err(|denial| BrokerError::Configuration(denial.code()))?;
        if grant.mode != ConsumptionMode::BrowserSession && grant.action != "browser.session" {
            return Ok(None);
        }
        self.authorize_browser_grant(&grant)?;
        Ok(self
            .original_workload_leases
            .get(
                grant
                    .request_event_key
                    .as_deref()
                    .expect("validated original owner"),
            )
            .cloned())
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
        if let Some(event_key) = request.operation.strip_prefix(STATUS_OPERATION_PREFIX) {
            return self.operation_status(&authorization, event_key);
        }
        if let Some(event_key) = request.operation.strip_prefix(CANCEL_OPERATION_PREFIX) {
            return self.cancel_browser_operation(&authorization, event_key);
        }
        if let Some(key) = request.operation.strip_prefix("cancel-key:") {
            return self.cancel_browser_request_key(&authorization, key);
        }
        let parsed = request
            .operation
            .strip_prefix("request:")
            .map(operation_request::RequestInput::parse)
            .transpose();
        if let Ok(Some(input)) = &parsed
            && let Some(key) = &input.request_key
            && let Some((event_key, owner)) = self.find_browser_request_key(&authorization, key)?
        {
            let binding = owner
                .browser_request
                .as_ref()
                .expect("key lookup has binding");
            if binding.before_admission() {
                return Err(BrokerError::Configuration("operation_request_cancelled"));
            }
            if binding != &self.browser_request_binding(&authorization, input)? {
                return Err(BrokerError::Configuration("operation_request_conflict"));
            }
            // This returns original metadata, never authority or a renewed TTL.
            return Ok(format!("OK operation_request {event_key}\n").into_bytes());
        }
        if (request.operation.starts_with("request:") || request.operation.starts_with("consume:"))
            && self.persistence_fenced()
        {
            return Err(BrokerError::Configuration("broker_persistence_fenced"));
        }
        if let Some(encoded) = request.operation.strip_prefix("request:") {
            if self.pending_node_events.len() >= MAX_BROKER_AUDIT_EVENTS {
                self.flag_audit_overflow()?;
                return Err(BrokerError::Configuration("audit_backpressure"));
            }
            let parsed = parsed?;
            let body = self.operation_request_body(&authorization, encoded)?;
            let mode = body
                .get("mode")
                .and_then(Value::as_str)
                .and_then(ConsumptionMode::parse);
            let browser_request = if mode == Some(ConsumptionMode::BrowserSession) {
                Some(self.browser_request_binding(
                    &authorization,
                    parsed.as_ref().expect("parsed request"),
                )?)
            } else {
                None
            };
            // Only a request that already passed every validation may reclaim
            // finished owners (see owner_retention); a full table of live
            // owners still refuses admission.
            self.ensure_operation_owner_capacity()?;
            let event_key = new_node_event_key()?;
            self.pending_node_events.push_back(PendingNodeEvent {
                idempotency_key: event_key.clone(),
                kind: "operation_request".to_owned(),
                body,
            });
            self.remember_operation_request(
                &event_key,
                &authorization.workload_id,
                &authorization.invocation_id,
            );
            self.operation_requests
                .values
                .get_mut(&event_key)
                .expect("newly inserted request")
                .mode = mode;
            self.operation_requests
                .values
                .get_mut(&event_key)
                .expect("newly inserted request")
                .browser_request = browser_request;
            if let Err(error) = self.persist_pending_node_events() {
                self.pending_node_events.pop_back();
                self.operation_requests.remove(&event_key);
                // A post-rename fsync failure may have published the snapshot.
                // Keep the fence until this withdrawal is itself durable.
                return Err(error);
            }
            return Ok(format!("OK operation_request {event_key}\n").into_bytes());
        }
        if let Some(grant_id) = request.operation.strip_prefix("consume:") {
            if self.pending_node_events.len() > MAX_BROKER_AUDIT_EVENTS - 2 {
                self.flag_audit_overflow()?;
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
                .ok_or(BrokerError::Configuration("fleet_policy_unavailable"))?;
            let now = grants::boottime_ms().map_err(BrokerError::Configuration)?;
            let preview = self
                .grant_verifier
                .preview_consumption(grant_id, &authorization, policy_version, now)
                .map_err(|denial| BrokerError::Configuration(denial.code()))?;
            // Browser work must enter the asynchronous private coordinator.
            // This synchronous native/noop path may not consume its one-use
            // grant or emit an uncertain result merely because it cannot run it.
            if preview.action == "browser.session"
                || preview.mode == ConsumptionMode::BrowserSession
            {
                self.authorize_browser_grant(&preview)?;
                return Err(BrokerError::Configuration("browser_runtime_unavailable"));
            }
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
                    Ok(_) => {
                        return Ok(format!("OK operation_uncertain {}\n", preview.id).into_bytes());
                    }
                    Err(denial) => {
                        // No durable intent was recorded, so nothing was
                        // consumed: withdraw the provisional result.
                        self.withdraw_pending_events(&event_keys);
                        return Err(BrokerError::Configuration(denial.code()));
                    }
                };
            if let Some(flag) = self.consume_crash_flag.as_deref()
                && consume_crash_flag_armed(flag, 0)
            {
                // One-shot: disarm first so the restarted broker keeps running.
                let _ = fs::remove_file(flag);
                eprintln!("test crash hook: aborting after the durable consume intent");
                std::process::abort();
            }
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

    fn browser_request_binding(
        &self,
        authorization: &blindpass_core::identity::WorkloadAuthorization,
        input: &operation_request::RequestInput,
    ) -> Result<operation_request::BrowserRequestBinding, BrokerError> {
        let registration = self
            .fleet_registrations
            .get(&authorization.workload_id)
            .ok_or(BrokerError::Configuration("operation_request_conflict"))?;
        let resource = self
            .browser_catalog
            .as_ref()
            .and_then(|catalog| catalog.select(&authorization.workload_id, &input.resource_id))
            .ok_or(BrokerError::Configuration("operation_request_conflict"))?;
        input.browser_binding(authorization, &registration.account, resource)
    }

    fn find_browser_request_key(
        &self,
        authorization: &blindpass_core::identity::WorkloadAuthorization,
        request_key: &str,
    ) -> Result<Option<(&str, &OperationRequestOwner)>, BrokerError> {
        for (event_key, owner) in &self.operation_requests.values {
            if owner.workload_id == authorization.workload_id
                && let Some(binding) = &owner.browser_request
                && binding.node_id == authorization.node_id
                && binding.request_key.as_deref() == Some(request_key)
            {
                if owner.invocation_id != authorization.invocation_id
                    || binding.unit != authorization.unit
                {
                    return Err(BrokerError::Configuration("operation_request_denied"));
                }
                return Ok(Some((event_key, owner)));
            }
        }
        Ok(None)
    }

    fn cancel_browser_request_key(
        &mut self,
        authorization: &blindpass_core::identity::WorkloadAuthorization,
        request_key: &str,
    ) -> Result<Vec<u8>, BrokerError> {
        if !blindpass_core::protocol::is_valid_event_key(request_key) {
            return Err(BrokerError::Configuration("invalid_operation_cancel"));
        }
        if let Some((event_key, owner)) =
            self.find_browser_request_key(authorization, request_key)?
        {
            if owner
                .browser_request
                .as_ref()
                .expect("key lookup has binding")
                .before_admission()
            {
                self.persist_pending_node_events()?;
                return Ok(b"OK operation_cancel requested\n".to_vec());
            }
            let event_key = event_key.to_owned();
            return self.cancel_browser_operation(authorization, &event_key);
        }
        if authorization.invocation_id.len() != 32
            || !authorization
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self
                .fleet_registrations
                .get(&authorization.workload_id)
                .is_none_or(|r| r.consumption_mode != ConsumptionMode::BrowserSession)
        {
            return Err(BrokerError::Configuration("operation_cancel_unsupported"));
        }
        self.ensure_operation_owner_capacity()?;
        let event_key = new_node_event_key()?;
        self.operation_requests.insert(
            &event_key,
            OperationRequestOwner {
                workload_id: authorization.workload_id.clone(),
                invocation_id: authorization.invocation_id.clone(),
                mode: Some(ConsumptionMode::BrowserSession),
                cancel_requested: true,
                cancel_acknowledged: false,
                browser_request: Some(operation_request::BrowserRequestBinding::withdrawal(
                    authorization,
                    request_key,
                )),
            },
        );
        // The local withdrawal remains effective even if disk persistence fails.
        // It has no original broker request evidence, so nothing is relayed.
        self.persist_pending_node_events()?;
        Ok(b"OK operation_cancel requested\n".to_vec())
    }

    fn cancel_browser_operation(
        &mut self,
        authorization: &blindpass_core::identity::WorkloadAuthorization,
        event_key: &str,
    ) -> Result<Vec<u8>, BrokerError> {
        let owner = self
            .operation_requests
            .get(event_key)
            .ok_or(BrokerError::Configuration("operation_cancel_unknown"))?;
        if owner.workload_id != authorization.workload_id
            || owner.invocation_id != authorization.invocation_id
        {
            return Err(BrokerError::Configuration("operation_cancel_denied"));
        }
        // Native legacy grants do not bind their request key; their existing
        // operator cancellation contract is separate from this browser intent.
        if owner.mode != Some(ConsumptionMode::BrowserSession) {
            return Err(BrokerError::Configuration("operation_cancel_unsupported"));
        }
        if let Some(status) = self.operation_closures.get(event_key) {
            return Ok(format!("OK operation_cancel closed {status}\n").into_bytes());
        }
        let cancellation = blindpass_core::fleet::OperationCancellation {
            node_id: authorization.node_id.clone(),
            workload_id: owner.workload_id.clone(),
            invocation_id: owner.invocation_id.clone(),
            request_event_key: event_key.to_owned(),
        };
        cancellation
            .to_value()
            .map_err(|_| BrokerError::Configuration("invalid_operation_cancel"))?;
        // Never roll the local stop back if storage or remote delivery fails.
        self.operation_requests
            .values
            .get_mut(event_key)
            .ok_or(BrokerError::Configuration("operation_cancel_unknown"))?
            .cancel_requested = true;
        self.queue_pending_cancellations(&authorization.node_id)?;
        self.persist_pending_node_events()?;
        Ok(b"OK operation_cancel requested\n".to_vec())
    }

    /// A full event queue must not postpone the local stop. Rebuild deferred
    /// delivery from durable ownership after restart or when ACK frees space.
    pub(crate) fn queue_pending_cancellations(&mut self, node_id: &str) -> Result<(), BrokerError> {
        let room = MAX_BROKER_AUDIT_EVENTS
            .saturating_sub(self.pending_node_events.len())
            .min(MAX_NODE_EVENT_BATCH);
        if room == 0 {
            return Ok(());
        }
        let mut pending_keys = self
            .pending_node_events
            .iter()
            .map(|event| event.idempotency_key.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut events = Vec::new();
        for (key, owner) in &self.operation_requests.values {
            if !owner.cancel_requested
                || owner.cancel_acknowledged
                || owner
                    .browser_request
                    .as_ref()
                    .is_some_and(|binding| binding.before_admission())
            {
                continue;
            }
            let cancellation = blindpass_core::fleet::OperationCancellation {
                node_id: node_id.to_owned(),
                workload_id: owner.workload_id.clone(),
                invocation_id: owner.invocation_id.clone(),
                request_event_key: key.clone(),
            };
            let idempotency_key = cancellation
                .event_key()
                .map_err(|_| BrokerError::Configuration("invalid_operation_cancel"))?;
            if !pending_keys.insert(idempotency_key.clone()) {
                continue;
            }
            events.push(PendingNodeEvent {
                idempotency_key,
                kind: "operation_cancel".into(),
                body: cancellation
                    .to_value()
                    .map_err(|_| BrokerError::Configuration("invalid_operation_cancel"))?,
            });
            if events.len() >= room {
                break;
            }
        }
        if !events.is_empty() {
            self.pending_node_events.extend(events);
            self.persist_pending_node_events()?;
        }
        Ok(())
    }

    pub(crate) fn remember_operation_request(
        &mut self,
        event_key: &str,
        workload_id: &str,
        invocation_id: &str,
    ) {
        self.operation_requests.insert(
            event_key,
            OperationRequestOwner {
                workload_id: workload_id.to_owned(),
                invocation_id: invocation_id.to_owned(),
                mode: None,
                cancel_requested: false,
                cancel_acknowledged: false,
                browser_request: None,
            },
        );
    }

    /// Withdraw dead original process authority locally, independently of
    /// signed time/backpressure. Existing durable cancellation handles delivery.
    fn reap_original_workload_leases(&mut self) -> Result<(), BrokerError> {
        let leases = self
            .original_workload_leases
            .iter()
            .map(|(key, lease)| (key.clone(), lease.clone()))
            .collect::<Vec<_>>();
        let mut failure = None;
        for (key, lease) in leases {
            let closed = self.operation_closures.get(&key).is_some()
                || self
                    .operation_requests
                    .get(&key)
                    .is_none_or(|owner| owner.cancel_requested);
            if !closed && lease.ensure_alive().is_err() {
                if let Err(error) = self.cancel_browser_operation(lease.authorization(), &key) {
                    failure = Some(error);
                }
                self.original_workload_leases.remove(&key);
            } else if closed {
                self.original_workload_leases.remove(&key);
            }
        }
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(())
        }
    }

    pub(crate) fn record_operation_closure(&mut self, event_key: &str, status: &str) {
        self.operation_closures.insert(event_key, status.to_owned());
        self.original_workload_leases.remove(event_key);
    }

    /// Report a controller-signed closure to the workload invocation that
    /// created the request. The answer carries no authority.
    fn operation_status(
        &self,
        authorization: &blindpass_core::identity::WorkloadAuthorization,
        event_key: &str,
    ) -> Result<Vec<u8>, BrokerError> {
        let Some(owner) = self.operation_requests.get(event_key) else {
            return Ok(b"OK operation_status unknown\n".to_vec());
        };
        if owner.workload_id != authorization.workload_id
            || owner.invocation_id != authorization.invocation_id
        {
            return Err(BrokerError::Configuration("operation_status_denied"));
        }
        if owner.cancel_requested && self.operation_closures.get(event_key).is_none() {
            return Ok(b"OK operation_status cancelling\n".to_vec());
        }
        if self.operation_closures.get(event_key).is_none()
            && let Some(ready) = self.browser_ready.get(event_key)
            && ready.alive.load(Ordering::Acquire)
            && ready.journal_alive.load(Ordering::Acquire)
            && grants::boottime_ms().is_ok_and(|now| now < ready.deadline)
            && self.authorize_browser_grant(&ready.grant).is_ok()
        {
            return Ok(format!("OK operation_status ready {}\n", ready.context).into_bytes());
        }
        if self.operation_closures.get(event_key).is_none()
            && let Some(policy) = self.fleet_policy.as_ref()
            && let Some(grant) = self.grant_verifier.preview_request_grant(
                event_key,
                authorization,
                policy.policy_version,
                grants::boottime_ms().map_err(BrokerError::Configuration)?,
            )
        {
            self.authorize_browser_grant(&grant)?;
            if self.browser_catalog.as_ref().is_some_and(|catalog| {
                catalog
                    .select(&authorization.workload_id, &grant.resource_id)
                    .is_some()
            }) {
                return Ok(format!(
                    "OK operation_status granted {} {}\n",
                    grant.id, grant.operation_id
                )
                .into_bytes());
            }
        }
        Ok(match self.operation_closures.get(event_key) {
            Some(status) => format!("OK operation_status closed {status}\n").into_bytes(),
            None => b"OK operation_status pending\n".to_vec(),
        })
    }

    fn operation_request_body(
        &self,
        authorization: &blindpass_core::identity::WorkloadAuthorization,
        encoded: &str,
    ) -> Result<Value, BrokerError> {
        let input = operation_request::RequestInput::parse(encoded)?;
        let action = input.action.as_str();
        let mode = input.mode;
        let purpose = input.purpose.as_str();
        let resource_id = input.resource_id.as_str();
        let ttl_seconds = input.ttl_seconds;
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
        let supported = match (action, mode) {
            ("noop.marker", ConsumptionMode::File | ConsumptionMode::Socket) => true,
            ("browser.session", ConsumptionMode::BrowserSession) => {
                ttl_seconds <= 120
                    && ttl_seconds <= policy.local_ceiling_seconds
                    && registration.policy_version == policy.policy_version
                    && registration.node_id == authorization.node_id
                    && registration.unit == authorization.unit
                    && self.workloads.iter().any(|workload| {
                        workload.node_id == authorization.node_id
                            && workload.workload_id == authorization.workload_id
                            && workload.unit == authorization.unit
                            && workload.account == registration.account
                    })
                    && registration
                        .invocation_id
                        .as_deref()
                        .is_none_or(|id| id == authorization.invocation_id)
                    && self.browser_catalog.as_ref().is_some_and(|catalog| {
                        catalog
                            .select(&authorization.workload_id, resource_id)
                            .is_some()
                    })
            }
            _ => false,
        };
        if mode != registration.consumption_mode
            || !supported
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
        let mut fields = vec![
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
        ];
        if mode == ConsumptionMode::BrowserSession {
            fields.push(("request_version".to_owned(), Value::Unsigned(2)));
        }
        Ok(Value::Object(fields))
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

    fn withdraw_pending_events(&mut self, event_keys: &[String]) {
        self.pending_node_events
            .retain(|event| !event_keys.contains(&event.idempotency_key));
        if let Err(error) = self.persist_pending_node_events() {
            // The next successful commit drops the withdrawn events.
            eprintln!("withdrawn operation result could not be committed: {error}");
        }
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
        let previous_owners = self.operation_requests.clone();
        let previous_overflow = self.audit_overflow_pending;
        let previous_revocation_pending = self.node_revocation_ack_pending;
        let previous_revocation_acknowledged = self.node_revocation_acknowledged;
        let previous_deferred = self.deferred_revocation_outcomes.clone();
        let previous_recovery_cursor = self.revocation_recovery_cursor.clone();
        let acknowledged = event_keys.iter().collect::<std::collections::HashSet<_>>();
        for event in previous_events.iter().filter(|event| {
            acknowledged.contains(&event.idempotency_key) && event.kind == "operation_cancel"
        }) {
            if let Some(key) = event.body.get("request_event_key").and_then(Value::as_str)
                && let Some(owner) = self.operation_requests.values.get_mut(key)
            {
                owner.cancel_acknowledged = true;
            }
        }
        for event in previous_events.iter().filter(|event| {
            acknowledged.contains(&event.idempotency_key)
                && event.kind == "audit"
                && event.body.get("action").and_then(Value::as_str)
                    == Some("grant_revocation_applied")
        }) {
            if let Some(grant_id) = event.body.get("grant_id").and_then(Value::as_str) {
                self.grant_verifier
                    .acknowledge_revocation_outcome(grant_id)
                    .map_err(BrokerError::Configuration)?;
            }
        }
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
            .and_then(|()| self.restore_revocation_outcomes(node_id))
            .and_then(|()| self.queue_deferred_revocation_outcomes())
            .and_then(|()| self.queue_pending_cancellations(node_id))
        {
            self.pending_node_events = previous_events;
            self.operation_requests = previous_owners;
            self.audit_overflow_pending = previous_overflow;
            self.node_revocation_ack_pending = previous_revocation_pending;
            self.node_revocation_acknowledged = previous_revocation_acknowledged;
            self.deferred_revocation_outcomes = previous_deferred;
            self.revocation_recovery_cursor = previous_recovery_cursor;
            return Err(error);
        }
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events = previous_events;
            self.operation_requests = previous_owners;
            self.audit_overflow_pending = previous_overflow;
            self.node_revocation_ack_pending = previous_revocation_pending;
            self.node_revocation_acknowledged = previous_revocation_acknowledged;
            self.deferred_revocation_outcomes = previous_deferred;
            self.revocation_recovery_cursor = previous_recovery_cursor;
            return Err(error);
        }
        Ok(())
    }

    /// Queue one durable audit event for a verified grant the broker
    /// discarded at receipt, so the relay can advance past it.
    pub(crate) fn queue_grant_rejection_audit(
        &mut self,
        node_id: &str,
        grant_id: &str,
        expires_at_ms: u64,
        reason_code: &'static str,
    ) -> Result<(), BrokerError> {
        let key_prefix = match reason_code {
            "expired_before_receipt" => "grant_expired",
            "binding_mismatch"
            | "stale_at_receipt"
            | "capacity_exceeded"
            | "missing_registration_version" => "grant_rejected",
            _ => {
                return Err(BrokerError::Configuration(
                    "grant rejection reason is not supported",
                ));
            }
        };
        if !valid_event_identifier(node_id)
            || !grant_id.starts_with("gr_")
            || !valid_event_identifier(grant_id)
            || expires_at_ms == 0
        {
            return Err(BrokerError::Configuration(
                "expired grant audit binding is invalid",
            ));
        }
        let digest = blindpass_core::custody::sha256(grant_id.as_bytes())
            .map_err(|_| BrokerError::Configuration("expired grant audit key is unavailable"))?;
        let event_key = format!(
            "{key_prefix}_{}",
            blindpass_core::signing::base64_url_encode(&digest)
        );
        let body = Value::Object(vec![
            (
                "action".to_owned(),
                Value::String("grant_rejected".to_owned()),
            ),
            ("expires_at_ms".to_owned(), Value::Unsigned(expires_at_ms)),
            ("grant_id".to_owned(), Value::String(grant_id.to_owned())),
            ("node_id".to_owned(), Value::String(node_id.to_owned())),
            (
                "reason_code".to_owned(),
                Value::String(reason_code.to_owned()),
            ),
        ]);
        if let Some(existing) = self
            .pending_node_events
            .iter()
            .find(|event| event.idempotency_key == event_key)
        {
            if existing.kind == "audit" && existing.body == body {
                return Ok(());
            }
            return Err(BrokerError::Configuration(
                "expired grant audit key was reused with different content",
            ));
        }
        if self.pending_node_events.len() >= MAX_BROKER_AUDIT_EVENTS {
            return self.flag_audit_overflow();
        }
        self.pending_node_events.push_back(PendingNodeEvent {
            idempotency_key: event_key,
            kind: "audit".to_owned(),
            body,
        });
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events.pop_back();
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

    /// Apply a verified grant revocation and report what it changed. The
    /// outcome is durably recorded with the tombstone. Startup can restore
    /// an unacknowledged outcome after a queue overflow and restart, without
    /// signed-document redelivery.
    pub(crate) fn apply_grant_revocation(
        &mut self,
        node_id: &str,
        revocation: &blindpass_core::fleet::Revocation,
    ) -> Result<(), BrokerError> {
        let newly_revoked = !self.grant_verifier.has_tombstone(&revocation.grant_id);
        let outcome = self.grant_verifier.revocation_outcome(&revocation.grant_id);
        let observed_at_ms = self
            .grant_verifier
            .revocation_observed_at_ms(&revocation.grant_id)
            .unwrap_or_else(|| {
                grants::boottime_ms()
                    .ok()
                    .and_then(|now| self.grant_verifier.trusted_controller_time_ms(now))
                    .unwrap_or(revocation.revoked_at_ms)
            });
        let applied = self.grant_verifier.revoke(revocation, observed_at_ms);
        if newly_revoked
            || self
                .grant_verifier
                .has_recorded_revocation_outcome(&revocation.grant_id)
        {
            self.queue_grant_revocation_outcome(
                node_id,
                &revocation.grant_id,
                outcome,
                observed_at_ms,
            );
        }
        applied.map_err(|reason| {
            eprintln!("grant revocation is in force but not durable: {reason}");
            BrokerError::Configuration("controller_document_not_durable")
        })
    }

    fn queue_grant_revocation_outcome(
        &mut self,
        node_id: &str,
        grant_id: &str,
        outcome: &'static str,
        observed_at_ms: u64,
    ) {
        let Some(event) =
            Self::grant_revocation_outcome_event(node_id, grant_id, outcome, observed_at_ms)
        else {
            eprintln!("grant revocation outcome key exceeds its bound; outcome not reported");
            return;
        };
        if self
            .pending_node_events
            .iter()
            .chain(self.deferred_revocation_outcomes.iter())
            .any(|pending| pending.idempotency_key == event.idempotency_key)
        {
            return;
        }
        if self.deferred_revocation_outcomes.len() >= MAX_DEFERRED_REVOCATION_OUTCOMES {
            // The outcome remains in the tombstone journal. Revisit the
            // journal when acknowledgements make room instead of dropping
            // an older deferred outcome.
            self.revocation_recovery_cursor = None;
            if let Err(error) = self.flag_audit_overflow() {
                eprintln!("audit overflow could not be recorded durably: {error}");
                self.audit_overflow_pending = true;
            }
            return;
        }
        self.deferred_revocation_outcomes.push_back(event);
        if let Err(error) = self.queue_deferred_revocation_outcomes() {
            eprintln!("grant revocation outcome remains deferred: {error}");
        }
        if !self.deferred_revocation_outcomes.is_empty()
            && let Err(error) = self.flag_audit_overflow()
        {
            eprintln!("audit overflow could not be recorded durably: {error}");
            self.audit_overflow_pending = true;
        }
    }

    fn grant_revocation_outcome_event(
        node_id: &str,
        grant_id: &str,
        outcome: &'static str,
        observed_at_ms: u64,
    ) -> Option<PendingNodeEvent> {
        let event = PendingNodeEvent {
            idempotency_key: format!("grant_revocation_applied_{grant_id}"),
            kind: "audit".to_owned(),
            body: Value::Object(vec![
                (
                    "action".to_owned(),
                    Value::String("grant_revocation_applied".to_owned()),
                ),
                ("grant_id".to_owned(), Value::String(grant_id.to_owned())),
                ("node_id".to_owned(), Value::String(node_id.to_owned())),
                ("observed_at_ms".to_owned(), Value::Unsigned(observed_at_ms)),
                ("outcome".to_owned(), Value::String(outcome.to_owned())),
            ]),
        };
        if !valid_node_event_key(&event.idempotency_key) {
            return None;
        }
        Some(event)
    }

    /// Rebuild outcomes whose signed revocation was already acknowledged by
    /// the relay before a full audit queue or restart could publish them.
    fn restore_revocation_outcomes(&mut self, node_id: &str) -> Result<(), BrokerError> {
        let slots = MAX_DEFERRED_REVOCATION_OUTCOMES
            .saturating_sub(self.deferred_revocation_outcomes.len());
        if slots == 0 {
            return Ok(());
        }
        let scan_limit = slots
            .saturating_add(self.pending_node_events.len())
            .saturating_add(self.deferred_revocation_outcomes.len());
        for (grant_id, outcome, observed_at_ms) in
            self.grant_verifier.pending_revocation_outcomes_after(
                self.revocation_recovery_cursor.as_deref(),
                scan_limit,
            )
        {
            if self.deferred_revocation_outcomes.len() >= MAX_DEFERRED_REVOCATION_OUTCOMES {
                break;
            }
            self.revocation_recovery_cursor = Some(grant_id.clone());
            let event =
                Self::grant_revocation_outcome_event(node_id, &grant_id, outcome, observed_at_ms)
                    .ok_or(BrokerError::Configuration(
                    "grant revocation outcome key exceeds its bound",
                ))?;
            if self
                .pending_node_events
                .iter()
                .chain(self.deferred_revocation_outcomes.iter())
                .any(|pending| pending.idempotency_key == event.idempotency_key)
            {
                continue;
            }
            self.deferred_revocation_outcomes.push_back(event);
        }
        Ok(())
    }

    /// Move deferred revocation outcomes into the audit queue while it has
    /// space, committing the queue once.
    pub(crate) fn queue_deferred_revocation_outcomes(&mut self) -> Result<(), BrokerError> {
        if self.deferred_revocation_outcomes.is_empty()
            || self.pending_node_events.len() >= MAX_BROKER_AUDIT_EVENTS
        {
            return Ok(());
        }
        let previous_events = self.pending_node_events.clone();
        let previous_deferred = self.deferred_revocation_outcomes.clone();
        while self.pending_node_events.len() < MAX_BROKER_AUDIT_EVENTS {
            let Some(event) = self.deferred_revocation_outcomes.pop_front() else {
                break;
            };
            self.pending_node_events.push_back(event);
        }
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events = previous_events;
            self.deferred_revocation_outcomes = previous_deferred;
            return Err(error);
        }
        Ok(())
    }

    /// Record that an audit event was refused. The queue file is rewritten
    /// only when the flag changes, not on every denied request.
    fn flag_audit_overflow(&mut self) -> Result<(), BrokerError> {
        if self.audit_overflow_pending {
            return Ok(());
        }
        self.audit_overflow_pending = true;
        if let Err(error) = self.persist_pending_node_events() {
            self.audit_overflow_pending = false;
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

    /// A revocation, registration, policy or node revocation that is in
    /// force only in memory fences the broker: no new grant is accepted or
    /// consumed and no operation is requested until the write succeeds or
    /// the broker restarts and reconciles from durable state.
    pub(crate) fn persistence_fenced(&self) -> bool {
        self.pending_state_fenced.load(Ordering::Acquire)
            || !self.unpersisted_documents.is_empty()
            || self.grant_verifier.has_unpersisted_revocations()
    }

    /// Retry every write that failed after its document was applied.
    pub(crate) fn retry_pending_persistence(&mut self, identity: &keys::NodeIdentity) {
        if self.pending_state_fenced.load(Ordering::Acquire) {
            let _ = self.persist_pending_node_events();
        }
        let pending = std::mem::take(&mut self.unpersisted_documents);
        for (key, document) in pending {
            if identity.persist_controller_document(&document).is_err() {
                self.unpersisted_documents.insert(key, document);
            }
        }
        let _ = self.grant_verifier.retry_revocation_persistence();
    }

    /// Persist an already applied controller document, or fence the broker
    /// and report a retryable error to the relay.
    pub(crate) fn persist_or_fence(
        &mut self,
        identity: &keys::NodeIdentity,
        key: String,
        document: &[u8],
    ) -> Result<(), BrokerError> {
        match identity.persist_controller_document(document) {
            Ok(()) => {
                self.unpersisted_documents.remove(&key);
                Ok(())
            }
            Err(_) => {
                self.unpersisted_documents.insert(key, document.to_vec());
                Err(BrokerError::Configuration(
                    "controller_document_not_durable",
                ))
            }
        }
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
        if let Some(pin) = identity.pinned_issuer()? {
            self.grant_verifier.observe_issuer_epoch(pin.epoch);
        }
        let pending_path = identity.pending_node_events_path();
        let (events, overflow_pending, revocation_acknowledged, owners, closures) =
            read_pending_node_events(&pending_path)?;
        self.operation_requests = owners;
        self.operation_closures = closures;
        self.pending_node_events_path = Some(pending_path);
        self.pending_node_events = events;
        self.audit_overflow_pending = overflow_pending;
        self.node_revocation_acknowledged = revocation_acknowledged;
        self.revocation_recovery_cursor = None;
        if let Some(pin) = identity.pinned_issuer()? {
            self.restore_revocation_outcomes(&pin.node_id)?;
            self.queue_deferred_revocation_outcomes()?;
            if !self.deferred_revocation_outcomes.is_empty() {
                self.flag_audit_overflow()?;
            }
        }
        Ok(())
    }

    fn persist_pending_node_events(&self) -> Result<(), BrokerError> {
        let Some(path) = self.pending_node_events_path.as_deref() else {
            return Ok(());
        };
        let result = write_pending_node_events(
            path,
            &self.pending_node_events,
            self.audit_overflow_pending,
            self.node_revocation_acknowledged,
            &self.operation_requests,
            &self.operation_closures,
        );
        self.pending_state_fenced
            .store(result.is_err(), Ordering::Release);
        result
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

/// The flag must be a regular file (not a symlink) owned by `owner_uid`.
fn consume_crash_flag_armed(path: &Path, owner_uid: u32) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.uid() == owner_uid)
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

fn read_operation_records(
    header: &Value,
    version: u64,
) -> Result<
    (
        BoundedRecords<OperationRequestOwner>,
        BoundedRecords<String>,
    ),
    BrokerError,
> {
    let failure = || BrokerError::Configuration("operation records are malformed");
    let mut owners = BoundedRecords::new(MAX_OPERATION_RECORDS);
    let mut closures = BoundedRecords::new(MAX_OPERATION_RECORDS);
    if version < 3 {
        // Old snapshots cannot recover acknowledged ownership. Do not infer it
        // from a grant or a client claim; unknown remains safely unavailable.
        return Ok((owners, closures));
    }
    let read = |name| {
        header
            .get(name)
            .and_then(Value::as_array)
            .filter(|records| records.len() <= MAX_OPERATION_RECORDS)
            .ok_or_else(failure)
    };
    let mut retry_keys = std::collections::BTreeSet::new();
    for record in read("operation_owners")? {
        let fields = record
            .as_object()
            .filter(|fields| {
                fields.len()
                    == match version {
                        3 => 3,
                        4 => 6,
                        _ => 7,
                    }
            })
            .ok_or_else(failure)?;
        if fields.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "event_key"
                    | "workload_id"
                    | "invocation_id"
                    | "mode"
                    | "cancel_requested"
                    | "cancel_acknowledged"
                    | "browser_request"
            )
        }) {
            return Err(failure());
        }
        let key = record
            .get("event_key")
            .and_then(Value::as_str)
            .filter(|key| valid_node_event_key(key))
            .ok_or_else(failure)?;
        let workload_id = record
            .get("workload_id")
            .and_then(Value::as_str)
            .filter(|id| valid_event_identifier(id))
            .ok_or_else(failure)?;
        let invocation_id = record
            .get("invocation_id")
            .and_then(Value::as_str)
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= 256
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            })
            .ok_or_else(failure)?;
        if owners.get(key).is_some() {
            return Err(failure());
        }
        let (mode, cancel_requested, cancel_acknowledged) = if version == 3 {
            (None, false, false)
        } else {
            let mode = match record.get("mode") {
                Some(Value::Null) => None,
                Some(Value::String(mode)) => {
                    Some(ConsumptionMode::parse(mode).ok_or_else(failure)?)
                }
                _ => return Err(failure()),
            };
            let requested = match record.get("cancel_requested") {
                Some(Value::Bool(value)) => *value,
                _ => return Err(failure()),
            };
            let acknowledged = match record.get("cancel_acknowledged") {
                Some(Value::Bool(value)) => *value,
                _ => return Err(failure()),
            };
            if acknowledged && !requested
                || requested
                    && (mode != Some(ConsumptionMode::BrowserSession)
                        || invocation_id.len() != 32
                        || !invocation_id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            {
                return Err(failure());
            }
            (mode, requested, acknowledged)
        };
        let browser_request = if version < 5 {
            None
        } else {
            match record.get("browser_request") {
                Some(Value::Null) => None,
                Some(value) => Some(operation_request::BrowserRequestBinding::from_value(value)?),
                None => return Err(failure()),
            }
        };
        if let Some(binding) = &browser_request
            && (mode != Some(ConsumptionMode::BrowserSession)
                || binding.before_admission() && (!cancel_requested || cancel_acknowledged)
                || invocation_id.len() != 32
                || !invocation_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || binding.request_key.as_ref().is_some_and(|retry_key| {
                    !retry_keys.insert((
                        binding.node_id.clone(),
                        workload_id.to_owned(),
                        retry_key.clone(),
                    ))
                }))
        {
            return Err(failure());
        }
        owners.insert(
            key,
            OperationRequestOwner {
                workload_id: workload_id.to_owned(),
                invocation_id: invocation_id.to_owned(),
                mode,
                cancel_requested,
                cancel_acknowledged,
                browser_request,
            },
        );
    }
    for record in read("operation_closures")? {
        let fields = record
            .as_object()
            .filter(|fields| fields.len() == 2)
            .ok_or_else(failure)?;
        if fields
            .iter()
            .any(|(key, _)| !matches!(key.as_str(), "event_key" | "status"))
        {
            return Err(failure());
        }
        let key = record
            .get("event_key")
            .and_then(Value::as_str)
            .filter(|key| valid_node_event_key(key))
            .ok_or_else(failure)?;
        let status = record
            .get("status")
            .and_then(Value::as_str)
            .filter(|status| {
                matches!(*status, "rejected" | "cancelled" | "expired" | "denied")
                    || version >= 5 && *status == "completed"
            })
            .ok_or_else(failure)?;
        if status == "completed"
            && owners.get(key).is_none_or(|owner| {
                owner.mode != Some(ConsumptionMode::BrowserSession)
                    || owner.cancel_requested
                    || owner
                        .browser_request
                        .as_ref()
                        .is_none_or(operation_request::BrowserRequestBinding::before_admission)
            })
        {
            return Err(failure());
        }
        if owners.get(key).is_none() || closures.get(key).is_some() {
            return Err(failure());
        }
        closures.insert(key, status.to_owned());
    }
    Ok((owners, closures))
}

type PendingState = (
    VecDeque<PendingNodeEvent>,
    bool,
    bool,
    BoundedRecords<OperationRequestOwner>,
    BoundedRecords<String>,
);

fn read_pending_node_events(path: &Path) -> Result<PendingState, BrokerError> {
    let (_directory, base) = pending_state_directory(path)?;
    let path = base.join(path.file_name().ok_or(BrokerError::Configuration(
        "pending node event path is invalid",
    ))?);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | 0x800)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok((
                VecDeque::new(),
                false,
                false,
                BoundedRecords::new(MAX_OPERATION_RECORDS),
                BoundedRecords::new(MAX_OPERATION_RECORDS),
            ));
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
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != PENDING_NODE_EVENT_FILE_MODE
        || metadata.len() > MAX_PENDING_NODE_EVENTS_BYTES
    {
        return Err(BrokerError::Configuration(
            "pending node event queue permissions or size are unsafe",
        ));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PENDING_NODE_EVENTS_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|_| BrokerError::Configuration("pending node event queue is unreadable"))?;
    if contents.len() as u64 > MAX_PENDING_NODE_EVENTS_BYTES
        || contents.is_empty()
        || contents.last() != Some(&b'\n')
    {
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
    if header_end > 8 * 1024 * 1024 {
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
    let expected_fields = match header_version {
        Some(1) => 2,
        Some(2) => 3,
        Some(3..=5) => 5,
        _ => 0,
    };
    if header_fields.len() != expected_fields
        || header_fields.iter().any(|(name, _)| {
            !matches!(
                name.as_str(),
                "v" | "audit_overflow_pending"
                    | "node_revocation_acknowledged"
                    | "operation_owners"
                    | "operation_closures"
            )
        })
        || !matches!(header_version, Some(1..=5))
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
        (Some(2..=5), Some(Value::Bool(value))) => *value,
        _ => {
            return Err(BrokerError::Configuration(
                "pending node event queue header is malformed",
            ));
        }
    };
    let (owners, closures) = read_operation_records(&header, header_version.unwrap_or(0))?;
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
    Ok((
        events,
        overflow_pending,
        revocation_acknowledged,
        owners,
        closures,
    ))
}

fn is_node_key_rotation_ack(event: &PendingNodeEvent) -> bool {
    event.kind == "audit"
        && event.body.get("action").and_then(Value::as_str) == Some("node_key_rotation_applied")
}

fn pending_state_directory(path: &Path) -> Result<(File, PathBuf), BrokerError> {
    let parent = path.parent().ok_or(BrokerError::Configuration(
        "pending node event queue path is invalid",
    ))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | blindpass_core::open_flags::O_DIRECTORY)
        .open(parent)
        .map_err(|_| BrokerError::Configuration("pending node event directory is unsafe"))?;
    let metadata = directory.metadata()?;
    if metadata.uid() != effective_uid() || metadata.mode() & 0o7777 != 0o700 {
        return Err(BrokerError::Configuration(
            "pending node event directory is unsafe",
        ));
    }
    let base = PathBuf::from(format!(
        "/proc/self/fd/{}",
        std::os::fd::AsRawFd::as_raw_fd(&directory)
    ));
    Ok((directory, base))
}

/// The durable outbox header: ownership, closures and flags. The writer and
/// the owner-retention size projection share this one definition.
fn pending_state_header(
    overflow_pending: bool,
    revocation_acknowledged: bool,
    owners: &BoundedRecords<OperationRequestOwner>,
    closures: &BoundedRecords<String>,
) -> Value {
    Value::Object(vec![
        (
            "audit_overflow_pending".to_owned(),
            Value::Bool(overflow_pending),
        ),
        (
            "node_revocation_acknowledged".to_owned(),
            Value::Bool(revocation_acknowledged),
        ),
        (
            "operation_owners".to_owned(),
            Value::Array(
                owners
                    .values
                    .iter()
                    .map(|(key, owner)| {
                        Value::Object(vec![
                            ("event_key".into(), Value::String(key.clone())),
                            (
                                "workload_id".into(),
                                Value::String(owner.workload_id.clone()),
                            ),
                            (
                                "invocation_id".into(),
                                Value::String(owner.invocation_id.clone()),
                            ),
                            (
                                "mode".into(),
                                owner.mode.map_or(Value::Null, |mode| {
                                    Value::String(mode.as_str().into())
                                }),
                            ),
                            (
                                "cancel_requested".into(),
                                Value::Bool(owner.cancel_requested),
                            ),
                            (
                                "cancel_acknowledged".into(),
                                Value::Bool(owner.cancel_acknowledged),
                            ),
                            (
                                "browser_request".into(),
                                owner.browser_request.as_ref().map_or(
                                    Value::Null,
                                    operation_request::BrowserRequestBinding::to_value,
                                ),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "operation_closures".to_owned(),
            Value::Array(
                closures
                    .values
                    .iter()
                    .map(|(key, status)| {
                        Value::Object(vec![
                            ("event_key".into(), Value::String(key.clone())),
                            ("status".into(), Value::String(status.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("v".to_owned(), Value::Unsigned(5)),
    ])
}

fn write_pending_node_events(
    path: &Path,
    events: &VecDeque<PendingNodeEvent>,
    overflow_pending: bool,
    revocation_acknowledged: bool,
    owners: &BoundedRecords<OperationRequestOwner>,
    closures: &BoundedRecords<String>,
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
    let (_directory, base) = pending_state_directory(path)?;
    let path = base.join(path.file_name().ok_or(BrokerError::Configuration(
        "pending node event path is invalid",
    ))?);
    let parent = base.as_path();
    let path = path.as_path();
    if events.is_empty()
        && !overflow_pending
        && !revocation_acknowledged
        && owners.values.is_empty()
        && closures.values.is_empty()
    {
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
    let header = pending_state_header(overflow_pending, revocation_acknowledged, owners, closures);
    let mut contents = canonicalize_value(&header)
        .map_err(|_| BrokerError::Configuration("pending node event header is invalid"))?;
    read_operation_records(&header, 5)?;
    if contents.len() > 8 * 1024 * 1024 {
        return Err(BrokerError::Configuration(
            "operation records exceed byte limit",
        ));
    }
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
    /// Explicitly enable the fixed root-only /etc/blindpass catalog at startup.
    pub browser_resources_enabled: bool,
    pub browser_runtime_enabled: bool,
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
            browser_resources_enabled: false,
            browser_runtime_enabled: false,
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
    if config.browser_resources_enabled {
        state.configure_browser_catalog(
            browser_catalog::BrowserCatalog::open().map_err(BrokerError::Configuration)?,
        )?;
    }
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
    if config.browser_runtime_enabled {
        if !config.browser_resources_enabled {
            return Err(BrokerError::Configuration(
                "browser_runtime_requires_catalog",
            ));
        }
        browser_coordinator::start(
            Arc::clone(&shared),
            config
                .workload_group
                .as_deref()
                .ok_or(BrokerError::Configuration(
                    "browser_runtime_requires_workload_group",
                ))?,
        )?;
    }
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
    let owner_shared = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("blindpass-browser-owner".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(100));
                if let Ok(mut state) = owner_shared.lock() {
                    let _ = state.reap_original_workload_leases();
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
    if config.workload_group.is_some() && config.workload_group == config.node_group {
        // The control socket trusts its group to relay controller documents;
        // workloads must never share that group.
        return Err(BrokerError::Configuration(
            "workload and node groups must differ",
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
    let live = Arc::new(os_identity::resolve_live_peer(
        stream,
        deadline,
        Duration::ZERO,
    )?);
    log_peer_identity("workload", live.identity());
    let frame = read_frame(stream, deadline)?;
    let request = parse_workload_request(&frame)?;
    let original = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .original_workload_for_consumption(live.identity(), &request)?;
    if let Some(original) = original {
        original.ensure_current(deadline)?;
    }
    let response = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .process_workload_owned(live, &request)?;
    stream.write_all(&response)?;
    Ok(())
}

/// Test-only socket adapter. Production retains the actual live peer instead.
#[cfg(test)]
fn handle_workload_connection_as<R>(
    stream: &mut UnixStream,
    state: &Arc<Mutex<BrokerState>>,
    deadline: Instant,
    resolve: R,
) -> Result<(), BrokerError>
where
    R: FnOnce(&UnixStream, Instant) -> Result<PeerIdentity, BrokerError>,
{
    let peer = resolve(stream, deadline)?;
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
    use blindpass_core::fleet::{ConsumptionMode, Grant, PolicySnapshot, Registration, TimeReply};
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
    fn operation_snapshot_parser_rejects_duplicate_and_unbound_records() {
        fn parse(source: &str) -> Value {
            super::parse_json(source).unwrap()
        }
        let owner = r#"{"event_key":"event_parser_00000001","workload_id":"workload-a","invocation_id":"invocation-a"}"#;
        let closure = r#"{"event_key":"event_parser_00000001","status":"cancelled"}"#;
        let header = |owners: &str, closures: &str| {
            parse(&format!(
                r#"{{"operation_owners":[{owners}],"operation_closures":[{closures}]}}"#
            ))
        };
        assert!(super::read_operation_records(&header(owner, closure), 3).is_ok());
        for (owners, closures) in [
            (format!("{owner},{owner}"), closure.to_owned()),
            (owner.to_owned(), format!("{closure},{closure}")),
            (String::new(), closure.to_owned()),
            (owner.to_owned(), closure.replace("cancelled", "granted")),
            (
                owner.replace("invocation-a", "http://P05-PRIVATE-CANARY"),
                closure.to_owned(),
            ),
            (
                owner.replace("event_parser_00000001", "short"),
                String::new(),
            ),
            (owner.replace("workload_id", "claimed_unit"), String::new()),
        ] {
            assert!(super::read_operation_records(&header(&owners, &closures), 3).is_err());
        }
        let oversized = std::iter::repeat_n(owner, super::MAX_OPERATION_RECORDS + 1)
            .collect::<Vec<_>>()
            .join(",");
        assert!(super::read_operation_records(&header(&oversized, ""), 3).is_err());
        // Historical snapshots must not invent an owner from unsigned claims.
        let (owners, closures) = super::read_operation_records(&parse("{}"), 2).unwrap();
        assert_eq!(owners.len(), 0);
        assert_eq!(closures.len(), 0);
    }

    #[test]
    fn operation_snapshot_uses_private_regular_single_link_state() {
        use std::os::unix::fs::symlink;
        let directory = unique_test_path("operation-snapshot-files");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("pending-node-events.jsonl");
        let mut owners = super::BoundedRecords::new(super::MAX_OPERATION_RECORDS);
        owners.insert(
            "event_snapshot_00000001",
            super::OperationRequestOwner {
                workload_id: "workload-a".into(),
                invocation_id: "invocation-a".into(),
                mode: None,
                cancel_requested: false,
                cancel_acknowledged: false,
                browser_request: None,
            },
        );
        let closures = super::BoundedRecords::new(super::MAX_OPERATION_RECORDS);
        super::write_pending_node_events(
            &path,
            &Default::default(),
            false,
            false,
            &owners,
            &closures,
        )
        .unwrap();
        let (_, _, _, restored, _) = super::read_pending_node_events(&path).unwrap();
        assert_eq!(
            restored.get("event_snapshot_00000001"),
            owners.get("event_snapshot_00000001")
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        let alias = directory.join("hard-link");
        fs::hard_link(&path, &alias).unwrap();
        assert!(super::read_pending_node_events(&path).is_err());
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(super::read_pending_node_events(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&path, &alias).unwrap();
        assert!(super::read_pending_node_events(&alias).is_err());
        fs::remove_file(&alias).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&alias)
            .status()
            .unwrap();
        assert!(status.success());
        let started = std::time::Instant::now();
        assert!(super::read_pending_node_events(&alias).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(super::read_pending_node_events(&path).is_err());
        assert!(
            super::write_pending_node_events(
                &path,
                &Default::default(),
                false,
                false,
                &owners,
                &closures
            )
            .is_err()
        );
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let original = fs::read(&path).unwrap();
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(super::read_pending_node_events(&path).is_err());
        fs::remove_dir_all(directory).unwrap();
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
                    challenge_received_at_ms: 1_800_000_000_000,
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

    fn fill_audit_queue(state: &mut BrokerState, count: usize) {
        state.pending_node_events = (0..count)
            .map(|index| PendingNodeEvent {
                idempotency_key: format!("broker-event-capacity-{index:08}"),
                kind: "audit".to_owned(),
                body: Value::Object(vec![(
                    "action".to_owned(),
                    Value::String("existing_event".to_owned()),
                )]),
            })
            .collect();
    }

    #[test]
    fn revocation_outcome_recovers_after_full_queue_and_restart() {
        use blindpass_core::fleet::Revocation;

        let (directory, mut state, grant) = fleet_state_with_grant("revocation-outcome-recovery");
        fill_audit_queue(&mut state, MAX_BROKER_AUDIT_EVENTS);
        state.persist_pending_node_events().unwrap();
        let revocation = Revocation {
            grant_id: grant.id.clone(),
            node_id: grant.node_id.clone(),
            reason: "operator_revoked".to_owned(),
            revoked_at_ms: grant.issued_at_ms,
            retain_until_ms: grant.expires_at_ms + 60_000,
            issuer_epoch: grant.issuer_epoch,
        };
        state.apply_grant_revocation("node-a", &revocation).unwrap();
        assert!(!state.deferred_revocation_outcomes.is_empty());
        let original_body = state.deferred_revocation_outcomes[0].body.clone();
        drop(state);

        let mut restored = BrokerState::new(DeliveryPolicy::default());
        restored.grant_verifier = super::grants::GrantVerifier::with_state_files(
            &directory.join("consumed.jsonl"),
            &directory.join("trusted-time"),
            &directory.join("revoked-grants.jsonl"),
        )
        .unwrap();
        let queue = directory.join("pending-node-events.jsonl");
        let (events, overflow, acknowledged, owners, closures) =
            super::read_pending_node_events(&queue).unwrap();
        restored.operation_requests = owners;
        restored.operation_closures = closures;
        restored.pending_node_events_path = Some(queue);
        restored.pending_node_events = events;
        restored.audit_overflow_pending = overflow;
        restored.node_revocation_acknowledged = acknowledged;
        assert!(restored.deferred_revocation_outcomes.is_empty());
        restored.restore_revocation_outcomes("node-a").unwrap();
        assert!(!restored.deferred_revocation_outcomes.is_empty());
        let cleared = restored
            .pending_node_events
            .iter()
            .take(3)
            .map(|event| event.idempotency_key.clone())
            .collect::<Vec<_>>();
        restored
            .acknowledge_node_events("node-a", &cleared)
            .unwrap();
        let event = restored
            .pending_node_events
            .iter()
            .find(|event| event.idempotency_key == format!("grant_revocation_applied_{}", grant.id))
            .unwrap();
        assert_eq!(
            event.body.get("outcome"),
            Some(&Value::String("revoked_before_consumption".to_owned()))
        );
        assert_eq!(event.body, original_body);
        let event_key = event.idempotency_key.clone();
        let acknowledgements = directory.join("revoked-grants.acks");
        fs::create_dir(&acknowledgements).unwrap();
        assert!(
            restored
                .acknowledge_node_events("node-a", std::slice::from_ref(&event_key))
                .is_err()
        );
        assert!(
            restored
                .pending_node_events
                .iter()
                .any(|pending| pending.idempotency_key == event_key)
        );
        fs::remove_dir(&acknowledgements).unwrap();
        restored
            .acknowledge_node_events("node-a", std::slice::from_ref(&event_key))
            .unwrap();
        assert_eq!(
            fs::read_to_string(directory.join("revoked-grants.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert_eq!(
            fs::read_to_string(&acknowledgements)
                .unwrap()
                .lines()
                .count(),
            1
        );
        restored
            .apply_grant_revocation("node-a", &revocation)
            .unwrap();
        assert!(
            !restored
                .pending_node_events
                .iter()
                .any(|event| event.idempotency_key == event_key)
        );
        drop(restored);
        let verifier = super::grants::GrantVerifier::with_state_files(
            &directory.join("consumed.jsonl"),
            &directory.join("trusted-time"),
            &directory.join("revoked-grants.jsonl"),
        )
        .unwrap();
        assert!(!verifier.has_recorded_revocation_outcome(&grant.id));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn repeated_backpressure_denials_rewrite_the_queue_only_when_overflow_is_first_flagged() {
        use std::os::unix::fs::MetadataExt;
        let (directory, mut state, grant) = fleet_state_with_grant("backpressure-persist");
        fill_audit_queue(&mut state, MAX_BROKER_AUDIT_EVENTS);
        let queue = directory.join("pending-node-events.jsonl");
        let peer = workload_peer();
        assert_eq!(
            error_code(state.process_workload(&peer, &consume_request(&grant.id))),
            b"ERR audit_backpressure\n"
        );
        assert!(state.audit_overflow_pending);
        let first = fs::metadata(&queue).unwrap().ino();
        let mut request = consume_request(&grant.id);
        request.operation = "request:bounded-test".to_owned();
        for _ in 0..3 {
            assert_eq!(
                error_code(state.process_workload(&peer, &consume_request(&grant.id))),
                b"ERR audit_backpressure\n"
            );
            assert_eq!(
                error_code(state.process_workload(&peer, &request)),
                b"ERR audit_backpressure\n"
            );
        }
        assert_eq!(
            fs::metadata(&queue).unwrap().ino(),
            first,
            "an unchanged overflow flag must not rewrite up to 10,000 events"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn workload_requests_resolve_the_registration_from_the_pidfd_unit() {
        let mut state = BrokerState::new(DeliveryPolicy::default());
        let registration = |workload: &str, version: u64, status: &str| Registration {
            node_id: "node-a".to_owned(),
            workload_id: workload.to_owned(),
            unit: "agent.service".to_owned(),
            account: "uid:1001".to_owned(),
            invocation_id: None,
            status: status.to_owned(),
            consumption_mode: ConsumptionMode::File,
            registration_version: version,
            policy_version: 1,
            local_ceiling_seconds: 60,
        };
        state
            .apply_fleet_registration(registration("workload-a", 1, "active"))
            .unwrap();
        let peer = workload_peer();
        let health = |workload: &str| WorkloadRequest {
            node_id: "node-a".to_owned(),
            workload_id: workload.to_owned(),
            claimed_unit: "agent.service".to_owned(),
            claimed_invocation_id: "inv-live".to_owned(),
            operation: "health".to_owned(),
        };
        assert!(state.process_workload(&peer, &health("workload-a")).is_ok());
        assert_eq!(
            error_code(state.process_workload(&peer, &health("workload-b"))),
            b"ERR workload_mismatch\n"
        );

        // A second active registration for the same unit fails closed for
        // every caller-sent workload id until one of them is revoked.
        state
            .apply_fleet_registration(registration("workload-b", 1, "active"))
            .unwrap();
        for workload in ["workload-a", "workload-b"] {
            assert_eq!(
                error_code(state.process_workload(&peer, &health(workload))),
                b"ERR ambiguous_registration\n"
            );
        }
        state
            .apply_fleet_registration(registration("workload-a", 2, "revoked"))
            .unwrap();
        assert!(state.process_workload(&peer, &health("workload-b")).is_ok());
        assert_eq!(
            error_code(state.process_workload(&peer, &health("workload-a"))),
            b"ERR workload_mismatch\n"
        );
    }

    #[test]
    fn concurrent_consumers_on_two_workload_socket_connections_create_one_marker() {
        let (directory, state, grant) = fleet_state_with_grant("socket-race");
        let state = Arc::new(Mutex::new(state));
        let socket = directory.join("workload.sock");
        let listener = bind_socket(&socket, 0o700, 0o600).unwrap();
        // Both server threads resolve their peer and then wait for each
        // other, so the two consume requests reach the broker together.
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let server_state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = super::serve_connections(
                listener,
                Duration::from_secs(5),
                move |stream, deadline| {
                    let barrier = Arc::clone(&barrier);
                    super::handle_workload_connection_as(
                        stream,
                        &server_state,
                        deadline,
                        move |_, _| {
                            barrier.wait();
                            Ok(workload_peer())
                        },
                    )
                },
                "workload",
            );
        });
        let frame = format!(
            "WORK node-a workload-a agent.service inv-live consume:{}\n",
            grant.id
        );
        let clients = (0..2)
            .map(|_| {
                let socket = socket.clone();
                let frame = frame.clone();
                std::thread::spawn(move || {
                    let mut stream = UnixStream::connect(&socket).unwrap();
                    stream.write_all(frame.as_bytes()).unwrap();
                    stream.shutdown(std::net::Shutdown::Write).unwrap();
                    let mut response = Vec::new();
                    std::io::Read::read_to_end(&mut stream, &mut response).unwrap();
                    response
                })
            })
            .collect::<Vec<_>>();
        let mut responses = clients
            .into_iter()
            .map(|client| client.join().unwrap())
            .collect::<Vec<_>>();
        responses.sort();
        assert_eq!(
            responses,
            [
                b"ERR grant_consumed\n".to_vec(),
                format!("OK operation_completed {}\n", grant.id).into_bytes(),
            ]
        );
        let markers = fs::read_dir(directory.join("ops")).unwrap().count();
        assert_eq!(markers, 1, "exactly one operation effect may run");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn consumption_near_audit_capacity_is_denied_before_any_effect() {
        let peer = workload_peer();
        for queued in [MAX_BROKER_AUDIT_EVENTS - 1, MAX_BROKER_AUDIT_EVENTS] {
            let (directory, mut state, grant) = fleet_state_with_grant("consume-capacity");
            fill_audit_queue(&mut state, queued);
            assert_eq!(
                error_code(state.process_workload(&peer, &consume_request(&grant.id))),
                b"ERR audit_backpressure\n",
                "{queued} queued events leave no room for the result and audit pair"
            );
            assert_eq!(state.pending_node_events.len(), queued);
            assert!(state.grant_verifier.is_accepted(&grant.id));
            assert!(
                !fs::exists(directory.join("ops").join(format!("{}.marker", grant.id))).unwrap()
            );
            assert!(!fs::exists(directory.join("consumed.jsonl")).unwrap());
            fs::remove_dir_all(directory).unwrap();
        }
        // Two free slots are exactly enough for the result and its audit.
        let (directory, mut state, grant) = fleet_state_with_grant("consume-capacity");
        fill_audit_queue(&mut state, MAX_BROKER_AUDIT_EVENTS - 2);
        assert_eq!(
            state
                .process_workload(&peer, &consume_request(&grant.id))
                .unwrap(),
            format!("OK operation_completed {}\n", grant.id).as_bytes()
        );
        assert_eq!(state.pending_node_events.len(), MAX_BROKER_AUDIT_EVENTS);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn consume_crash_hook_is_off_by_default_and_needs_an_owned_regular_flag_file() {
        assert!(
            BrokerState::new(DeliveryPolicy::default())
                .consume_crash_flag
                .is_none()
        );
        let directory = unique_test_path("crash-flag");
        fs::create_dir(&directory).unwrap();
        let flag = directory.join("crash-after-consume-intent");
        let uid = fs::metadata(&directory).unwrap().uid();
        assert!(!super::consume_crash_flag_armed(&flag, uid), "missing flag");
        fs::write(&flag, b"").unwrap();
        assert!(super::consume_crash_flag_armed(&flag, uid));
        assert!(
            !super::consume_crash_flag_armed(&flag, uid.wrapping_add(1)),
            "a flag owned by anyone else, e.g. a non-root user, is ignored"
        );
        let link = directory.join("linked-flag");
        std::os::unix::fs::symlink(&flag, &link).unwrap();
        assert!(
            !super::consume_crash_flag_armed(&link, uid),
            "symlinks are ignored"
        );
        fs::remove_file(&flag).unwrap();
        fs::create_dir(&flag).unwrap();
        assert!(
            !super::consume_crash_flag_armed(&flag, uid),
            "directories are ignored"
        );

        // Without the hook armed in state, an existing flag changes nothing.
        let (grant_directory, mut state, grant) = fleet_state_with_grant("crash-flag-off");
        assert_eq!(
            state
                .process_workload(&workload_peer(), &consume_request(&grant.id))
                .unwrap(),
            format!("OK operation_completed {}\n", grant.id).as_bytes()
        );
        fs::remove_dir_all(grant_directory).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn consume_journal_failure_is_a_denial_without_an_uncertain_result() {
        let (directory, mut state, grant) = fleet_state_with_grant("journal-failure");
        let journal = directory.join("consumed.jsonl");
        fs::create_dir(&journal).unwrap();
        let peer = workload_peer();
        assert_eq!(
            error_code(state.process_workload(&peer, &consume_request(&grant.id))),
            b"ERR consumption_unavailable\n"
        );
        assert!(
            state.pending_node_events.is_empty(),
            "nothing was consumed, so no uncertain result may be reported"
        );
        assert!(!fs::exists(directory.join("pending-node-events.jsonl")).unwrap());
        assert!(!fs::exists(directory.join("ops").join(format!("{}.marker", grant.id))).unwrap());

        // The grant was never consumed and remains usable once the journal
        // can be written.
        fs::remove_dir(&journal).unwrap();
        assert_eq!(
            state
                .process_workload(&peer, &consume_request(&grant.id))
                .unwrap(),
            format!("OK operation_completed {}\n", grant.id).as_bytes()
        );
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
                    challenge_received_at_ms: 1_800_000_000_000,
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
        assert_eq!(state.operation_requests.len(), 0);
        assert!(state.persistence_fenced());
        assert!(fs::metadata(&queue_path).unwrap().is_dir());
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            1,
            "failed atomic commit must remove its temporary file"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    /// A broker with durable grant state, a fleet registration and policy,
    /// fresh signed controller time and one accepted, unconsumed grant.
    fn fleet_state_with_grant(label: &str) -> (std::path::PathBuf, BrokerState, Grant) {
        let directory = unique_test_path(label);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state.grant_verifier = super::grants::GrantVerifier::with_state_files(
            &directory.join("consumed.jsonl"),
            &directory.join("trusted-time"),
            &directory.join("revoked-grants.jsonl"),
        )
        .unwrap();
        state.grant_verifier.observe_issuer_epoch(1);
        state.pending_node_events_path = Some(directory.join("pending-node-events.jsonl"));
        state.operation_directory = directory.join("ops");
        state.workloads.push(WorkloadRegistration {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            unit: "agent.service".to_owned(),
            account: "uid:1001".to_owned(),
            invocation_id: None,
        });
        let registration = Registration {
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
        };
        let policy = PolicySnapshot {
            policy_version: 1,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        state
            .fleet_registrations
            .insert("workload-a".to_owned(), registration.clone());
        state.fleet_policy = Some(policy.clone());
        let challenge = state.grant_verifier.begin_time_challenge().unwrap();
        let received_at_ms = super::grants::boottime_ms().unwrap();
        state
            .grant_verifier
            .accept_time_reply(
                &TimeReply {
                    node_id: "node-a".to_owned(),
                    challenge,
                    challenge_received_at_ms: 1_800_000_000_000,
                    controller_time_ms: 1_800_000_000_000,
                    issuer_epoch: 1,
                },
                "node-a",
                1,
                received_at_ms,
            )
            .unwrap();
        let grant = Grant {
            id: "gr_0123456789abcdef0123456789abcdef".to_owned(),
            operation_id: "op_0123456789abcdef0123456789abcdef".to_owned(),
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            invocation_id: "inv-live".to_owned(),
            unit: "agent.service".to_owned(),
            account: "uid:1001".to_owned(),
            resource_id: "marker-a".to_owned(),
            recipient_key_id: "node-a-1".to_owned(),
            registration_version: 1,
            policy_version: 1,
            approval_reference: None,
            request_event_key: None,
            action: "noop.marker".to_owned(),
            mode: ConsumptionMode::File,
            audience: "blindpass-node".to_owned(),
            issuer_epoch: 1,
            issued_at_ms: 1_800_000_000_000,
            expires_at_ms: 1_800_000_060_000,
            local_ceiling_seconds: 60,
        };
        state
            .grant_verifier
            .accept_grant(
                grant.clone(),
                b"signed-grant",
                "node-a",
                "node-a-1",
                &policy,
                &registration,
                super::grants::boottime_ms().unwrap(),
            )
            .unwrap();
        (directory, state, grant)
    }

    pub(crate) fn browser_grant_fixture(
        label: &str,
    ) -> (
        std::path::PathBuf,
        BrokerState,
        Grant,
        super::BrowserResource,
        super::session_journal::SessionJournal,
    ) {
        let (directory, mut state, mut grant) = fleet_state_with_grant(label);
        grant.id = "gr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        grant.invocation_id = "a".repeat(32);
        grant.mode = ConsumptionMode::BrowserSession;
        grant.action = "browser.session".into();
        grant.request_event_key = Some("event_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        state.remember_operation_request(
            grant.request_event_key.as_ref().unwrap(),
            &grant.workload_id,
            &grant.invocation_id,
        );
        grant.resource_id = "report-primary".into();
        let registration = state.fleet_registrations.get_mut("workload-a").unwrap();
        registration.consumption_mode = ConsumptionMode::BrowserSession;
        let registration = registration.clone();
        let policy = state.fleet_policy.as_mut().unwrap();
        policy.allowed_actions = vec!["browser.session".into()];
        policy.allowed_modes = vec![ConsumptionMode::BrowserSession];
        let policy = policy.clone();
        state
            .grant_verifier
            .accept_grant(
                grant.clone(),
                b"signed-browser-grant",
                "node-a",
                "node-a-1",
                &policy,
                &registration,
                super::grants::boottime_ms().unwrap(),
            )
            .unwrap();
        let resource=super::BrowserResource::from_value(&super::parse_json(r#"{"resource_id":"report-primary","workload_ids":["workload-a"],"credential_unit":"blindpass-login-helper@.service","credential_name":"primary-password","revocation":{"kind":"fixture-admin","credential_unit":"blindpass-session-revoker@.service","credential_name":"fixture-admin"},"configuration":{"kind":"fixture","origin":"https://127.0.0.1:4443","account":"primary","sessionMaxMs":300000}}"#).unwrap()).unwrap();
        let catalog_bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        let (unit, name) = resource.credential_destination();
        state.loader_policy.map_unit(unit, name).unwrap();
        let (admin_unit, admin_name) = resource
            .revocation_profile()
            .unwrap()
            .credential_destination();
        state
            .loader_policy
            .map_unit(admin_unit, admin_name)
            .unwrap();
        state
            .credentials
            .insert(
                &super::destination_key(admin_unit, admin_name),
                "a".repeat(64).as_bytes(),
            )
            .unwrap();
        state
            .configure_browser_catalog(
                super::browser_catalog::BrowserCatalog::from_bytes(&catalog_bytes).unwrap(),
            )
            .unwrap();
        let (peer, request) = browser_peer_and_request(&grant);
        let authorization = super::authorize_workload(&peer, &request, &state.workloads).unwrap();
        let key = grant.request_event_key.as_deref().unwrap();
        let (lease, _) = super::original_workload::OriginalWorkloadLease::fixture(
            key,
            authorization.clone(),
            peer.clone(),
        );
        state.original_workload_leases.insert(key.into(), lease);
        let encoded = blindpass_core::signing::base64_url_encode(br#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":60}"#);
        let input = super::operation_request::RequestInput::parse(&encoded).unwrap();
        let binding = state
            .browser_request_binding(&authorization, &input)
            .unwrap();
        let owner = state
            .operation_requests
            .values
            .get_mut(grant.request_event_key.as_deref().unwrap())
            .unwrap();
        owner.mode = Some(ConsumptionMode::BrowserSession);
        owner.browser_request = Some(binding);
        state
            .credentials
            .insert(&super::destination_key(unit, name), b"P05-SOURCE-CANARY")
            .unwrap();
        state.credential_expiries.insert(
            super::destination_key(unit, name),
            super::CredentialExpiry::after(Duration::from_secs(300)).unwrap(),
        );
        let sessions = directory.join("sessions");
        fs::create_dir(&sessions).unwrap();
        fs::set_permissions(&sessions, fs::Permissions::from_mode(0o700)).unwrap();
        let journal =
            super::session_journal::SessionJournal::open_at(&sessions, super::effective_uid())
                .unwrap();
        (directory, state, grant, resource, journal)
    }
    #[test]
    fn browser_source_requires_its_own_live_custody_expiry_before_reservation() {
        for mode in ["missing", "runnable-expired", "boot-expired"] {
            let (directory, mut state, grant, resource, mut journal) = browser_grant_fixture(mode);
            let (unit, name) = resource.credential_destination();
            let key = super::destination_key(unit, name);
            if mode == "missing" {
                state.credential_expiries.remove(&key);
            } else {
                let expiry = state.credential_expiries.get_mut(&key).unwrap();
                if mode == "boot-expired" {
                    expiry.boot = super::grants::boottime_ms().unwrap();
                } else {
                    expiry.runnable = std::time::Instant::now() - Duration::from_secs(1);
                }
            }
            let (peer, request) = browser_peer_and_request(&grant);
            assert!(matches!(
                state.prepare_browser_login(&peer, &request, &resource, &mut journal),
                Err(super::BrokerError::Configuration("browser_source_expired"))
            ));
            assert!(journal.pending().is_empty());
            assert!(state.pending_node_events.is_empty());
            drop(journal);
            drop(state);
            fs::remove_dir_all(directory).unwrap();
        }
    }
    #[test]
    fn prepared_source_expiry_does_not_become_a_website_or_grant_deadline() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("prepared-source-expiry");
        let (unit, name) = resource.credential_destination();
        let boot = super::grants::boottime_ms().unwrap();
        state.credential_expiries.insert(
            super::destination_key(unit, name),
            super::CredentialExpiry {
                runnable: std::time::Instant::now() + Duration::from_secs(60),
                boot: boot + 10_000,
            },
        );
        let (peer, request) = browser_peer_and_request(&grant);
        let super::BrowserPreparation::Login(mut job) = state
            .prepare_browser_login(&peer, &request, &resource, &mut journal)
            .unwrap()
        else {
            panic!("expected prepared login");
        };
        assert!(job.source_is_current());
        assert!(job.deadline_boottime_ms > job.source_expiry.boot);
        job.source_expiry.boot = super::grants::boottime_ms().unwrap();
        assert!(!job.source_is_current());
        assert!(state.authorize_browser_handoff(&job).is_ok());
        drop(job);
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_recovery_uses_only_administrator_custody_and_exact_original_recipe() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-recovery-input");
        let (peer, request) = browser_peer_and_request(&grant);
        state
            .prepare_browser_login(&peer, &request, &resource, &mut journal)
            .unwrap();
        let record = journal.pending()[0].clone();
        let (unit, name) = resource.credential_destination();
        state
            .credentials
            .remove(&super::destination_key(unit, name));
        let (selected, administrator, _) = state.browser_recovery_input(&record).unwrap();
        assert_eq!(
            selected.recipe_fingerprint().unwrap(),
            record.binding.recipe_fingerprint
        );
        assert_eq!(administrator.as_bytes(), "a".repeat(64).as_bytes());
        assert_eq!(journal.pending().len(), 1);
        assert!(state.browser_dispatch_candidates().is_empty());
        let mut changed = record.clone();
        changed.binding.recipe_fingerprint = "b".repeat(64);
        assert!(state.browser_recovery_input(&changed).is_err());
        changed = record.clone();
        changed.binding.account = "other".into();
        assert!(state.browser_recovery_input(&changed).is_err());
        let (unit, name) = resource
            .revocation_profile()
            .unwrap()
            .credential_destination();
        state
            .credentials
            .remove(&super::destination_key(unit, name));
        assert!(state.browser_recovery_input(&record).is_err());
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_preparation_withholds_source_without_administrator_revocation_configuration() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-no-revoker");
        let mut value = resource.to_value();
        if let Value::Object(fields) = &mut value {
            fields.retain(|(key, _)| key != "revocation");
        }
        let resource = super::BrowserResource::from_value(&value).unwrap();
        let catalog = super::browser_catalog::BrowserCatalog::from_bytes(
            &super::canonicalize_value(&Value::Object(vec![
                ("version".into(), Value::Unsigned(1)),
                ("resources".into(), Value::Array(vec![resource.to_value()])),
            ]))
            .unwrap(),
        )
        .unwrap();
        state.configure_browser_catalog(catalog).unwrap();
        let (peer, request) = browser_peer_and_request(&grant);
        let authorization = super::authorize_workload(&peer, &request, &state.workloads).unwrap();
        let input = super::operation_request::RequestInput::parse(&blindpass_core::signing::base64_url_encode(br#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":60}"#)).unwrap();
        let binding = state
            .browser_request_binding(&authorization, &input)
            .unwrap();
        state
            .operation_requests
            .values
            .get_mut(grant.request_event_key.as_deref().unwrap())
            .unwrap()
            .browser_request = Some(binding);
        assert!(matches!(
            state.prepare_browser_login(&peer, &request, &resource, &mut journal),
            Err(super::BrokerError::Configuration(
                "browser_revocation_unavailable"
            ))
        ));
        assert!(journal.pending().is_empty());
        assert!(state.pending_node_events.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_preparation_requires_available_valid_unexpired_administrator_custody() {
        for mode in ["missing", "malformed", "expired"] {
            let (directory, mut state, grant, resource, mut journal) = browser_grant_fixture(mode);
            let (unit, name) = resource
                .revocation_profile()
                .unwrap()
                .credential_destination();
            let key = super::destination_key(unit, name);
            // An expired credential follows the same broker custody purge as source.
            if mode == "missing" {
                state.credentials.remove(&key);
            } else if mode == "malformed" {
                state
                    .credentials
                    .insert(&key, b"P05-ADMIN-CANARY-INVALID")
                    .unwrap();
            } else {
                state.credential_expiries.insert(
                    key,
                    super::CredentialExpiry {
                        runnable: std::time::Instant::now() - Duration::from_secs(1),
                        boot: super::grants::boottime_ms().unwrap() + 60_000,
                    },
                );
            }
            let (peer, request) = browser_peer_and_request(&grant);
            assert!(matches!(
                state.prepare_browser_login(&peer, &request, &resource, &mut journal),
                Err(super::BrokerError::Configuration(
                    "browser_revocation_unavailable"
                ))
            ));
            assert!(journal.pending().is_empty());
            assert!(state.pending_node_events.is_empty());
            fs::remove_dir_all(directory).unwrap();
        }
    }
    #[test]
    fn browser_preparation_cannot_reconstruct_original_process_from_durable_owner_metadata() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-owner-process-restart");
        // Round-trip the durable snapshot without retaining any runtime pidfd.
        state.persist_pending_node_events().unwrap();
        let path = directory.join("pending-node-events.jsonl");
        let (_, _, _, owners, closures) = super::read_pending_node_events(&path).unwrap();
        let mut restored = super::BrokerState::new(super::DeliveryPolicy::default());
        restored.operation_requests = owners;
        restored.operation_closures = closures;
        // Use current signed/custody/configuration foundations, while deliberately
        // supplying only durable ownership as a restart would.
        restored.workloads = state.workloads.clone();
        restored.fleet_registrations = state.fleet_registrations.clone();
        restored.fleet_policy = state.fleet_policy.clone();
        restored.browser_catalog = state.browser_catalog.take();
        restored.grant_verifier = state.grant_verifier;
        restored.loader_policy = state.loader_policy;
        restored.credentials = state.credentials;
        let (peer, request) = browser_peer_and_request(&grant);
        assert!(matches!(
            restored.authorize_browser_grant(&grant),
            Err(super::BrokerError::Configuration(
                "browser_original_owner_unavailable"
            ))
        ));
        assert!(matches!(
            restored.prepare_browser_login(&peer, &request, &resource, &mut journal),
            Err(super::BrokerError::Configuration(
                "browser_original_owner_unavailable"
            ))
        ));
        assert!(journal.pending().is_empty());
        assert!(restored.pending_node_events.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn original_workload_lease_matches_only_the_admitted_grant_and_live_process() {
        let (directory, state, grant, _, _) = browser_grant_fixture("owner-binding");
        let key = grant.request_event_key.as_deref().unwrap();
        let lease = state.original_workload_leases.get(key).unwrap();
        assert!(lease.matches(&grant));
        for field in [
            "request",
            "node",
            "workload",
            "unit",
            "invocation",
            "account",
        ] {
            let mut changed = grant.clone();
            match field {
                "request" => changed.request_event_key = Some("event_other".into()),
                "node" => changed.node_id.push('b'),
                "workload" => changed.workload_id.push('b'),
                "unit" => changed.unit.push('b'),
                "invocation" => changed.invocation_id.push('b'),
                "account" => changed.account.push('b'),
                _ => unreachable!(),
            }
            assert!(!lease.matches(&changed), "{field}");
        }
        let (peer, request) = browser_peer_and_request(&grant);
        let authorization = super::authorize_workload(&peer, &request, &state.workloads).unwrap();
        let (dead, alive) =
            super::original_workload::OriginalWorkloadLease::fixture(key, authorization, peer);
        alive.store(false, super::Ordering::Release);
        assert!(!dead.matches(&grant));
        assert!(dead.ensure_current(std::time::Instant::now()).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn original_workload_exit_withdraws_authority_despite_time_queue_or_storage_failure() {
        for fault in ["normal", "clock", "queue", "storage"] {
            let (directory, mut state, grant, resource, mut journal) =
                browser_grant_fixture(&format!("owner-exit-{fault}"));
            let (peer, request) = browser_peer_and_request(&grant);
            let authorization =
                super::authorize_workload(&peer, &request, &state.workloads).unwrap();
            let key = grant.request_event_key.as_deref().unwrap();
            let (lease, alive) = super::original_workload::OriginalWorkloadLease::fixture(
                key,
                authorization,
                peer.clone(),
            );
            state.original_workload_leases.insert(key.into(), lease);
            state.persist_pending_node_events().unwrap();
            match fault {
                "clock" => state.grant_verifier = super::grants::GrantVerifier::default(),
                "queue" => fill_audit_queue(&mut state, super::MAX_BROKER_AUDIT_EVENTS),
                "storage" => {
                    let path = state.pending_node_events_path.as_ref().unwrap();
                    fs::remove_file(path).unwrap();
                    fs::create_dir(path).unwrap();
                }
                _ => {}
            }
            alive.store(false, super::Ordering::Release);
            let reaped = state.reap_original_workload_leases();
            assert_eq!(reaped.is_err(), fault == "storage");
            assert!(state.original_workload_leases.is_empty());
            assert!(state.operation_requests.get(key).unwrap().cancel_requested);
            assert!(
                state
                    .prepare_browser_login(&peer, &request, &resource, &mut journal)
                    .is_err()
            );
            assert!(journal.pending().is_empty());
            assert!(state.reap_original_workload_leases().is_ok());
            let cancellations = state
                .pending_node_events
                .iter()
                .filter(|e| e.kind == "operation_cancel")
                .count();
            assert_eq!(cancellations, usize::from(fault != "queue"));
            if fault == "storage" {
                assert!(state.persistence_fenced());
            }
            if fault != "storage" {
                let (_, _, _, owners, _) = super::read_pending_node_events(
                    state.pending_node_events_path.as_ref().unwrap(),
                )
                .unwrap();
                assert!(owners.get(key).unwrap().cancel_requested);
            }
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn original_workload_lease_survives_event_ack_and_releases_on_signed_closure() {
        let (directory, mut state, grant, _, _) = browser_grant_fixture("owner-ack");
        let key = grant.request_event_key.as_deref().unwrap();
        state
            .queue_operation_result(
                &grant,
                "uncertain",
                "result_uncertain",
                grant.issued_at_ms,
                [
                    "event_11111111111111111111111111111111".into(),
                    "event_22222222222222222222222222222222".into(),
                ],
            )
            .unwrap();
        let events = state
            .pending_node_events
            .iter()
            .map(|e| e.idempotency_key.clone())
            .collect::<Vec<_>>();
        state
            .acknowledge_node_events(&grant.node_id, &events)
            .unwrap();
        assert!(state.pending_node_events.is_empty());
        assert!(
            state
                .original_workload_leases
                .get(key)
                .unwrap()
                .matches(&grant)
        );
        state.record_operation_closure(key, "revoked");
        assert!(state.original_workload_leases.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn original_workload_capacity_denies_new_admission_and_preserves_metadata_retry() {
        let (directory, mut state, peer, request) = retry_fixture("owner-capacity");
        let authorization = super::authorize_workload(&peer, &request, &state.workloads).unwrap();
        assert!(
            state
                .needs_original_workload_lease(&authorization, &request)
                .unwrap()
        );
        let reply = state.process_workload(&peer, &request).unwrap();
        assert!(
            !state
                .needs_original_workload_lease(&authorization, &request)
                .unwrap()
        );
        for index in 0..super::original_workload::MAX_ORIGINAL_WORKLOAD_LEASES {
            let key = format!("event_{index:032}");
            let (lease, _) = super::original_workload::OriginalWorkloadLease::fixture(
                &key,
                authorization.clone(),
                peer.clone(),
            );
            state.original_workload_leases.insert(key, lease);
        }
        let mut fresh = request.clone();
        fresh.operation = retry_request("read report", 60, "retry_new_0123456789abcdef");
        assert!(matches!(
            state.needs_original_workload_lease(&authorization, &fresh),
            Err(BrokerError::Configuration("browser_owner_capacity"))
        ));
        assert!(
            !state
                .needs_original_workload_lease(&authorization, &request)
                .unwrap()
        );
        assert_eq!(state.process_workload(&peer, &request).unwrap(), reply);
        assert_eq!(state.pending_node_events.len(), 1);
        assert_eq!(state.operation_requests.values.len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }
    fn browser_peer_and_request(grant: &Grant) -> (PeerIdentity, WorkloadRequest) {
        (
            PeerIdentity::fixture(
                1001,
                1001,
                "agent.service",
                &grant.invocation_id,
                "uid:1001",
            ),
            WorkloadRequest {
                node_id: grant.node_id.clone(),
                workload_id: grant.workload_id.clone(),
                claimed_unit: grant.unit.clone(),
                claimed_invocation_id: grant.invocation_id.clone(),
                operation: format!("consume:{}", grant.id),
            },
        )
    }

    #[test]
    fn production_browser_dispatch_uses_only_the_original_current_signed_candidate() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("production-dispatch");
        let candidates = state.browser_dispatch_candidates();
        assert_eq!(candidates.len(), 1);
        let candidate = candidates.into_iter().next().unwrap();
        assert_eq!(candidate.grant, grant);
        assert_eq!(candidate.resource.resource_id(), resource.resource_id());
        let (_, request) = browser_peer_and_request(&grant);
        let super::BrowserPreparation::Login(_) = state
            .prepare_browser_login(
                candidate.original.identity(),
                &request,
                &candidate.resource,
                &mut journal,
            )
            .unwrap()
        else {
            panic!("expected fresh preparation");
        };
        assert!(
            state.browser_dispatch_candidates().is_empty(),
            "one-use consumption cannot redispatch"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn production_browser_dispatch_withdrawal_and_missing_original_never_create_effects() {
        for missing in [false, true] {
            let (directory, mut state, grant, _, journal) =
                browser_grant_fixture("production-dispatch-denied");
            if missing {
                state.original_workload_leases.clear();
            } else {
                state
                    .operation_requests
                    .values
                    .get_mut(grant.request_event_key.as_deref().unwrap())
                    .unwrap()
                    .cancel_requested = true;
            }
            let events = state.pending_node_events.len();
            assert!(state.browser_dispatch_candidates().is_empty());
            assert_eq!(events, state.pending_node_events.len());
            assert!(journal.pending().is_empty());
            fs::remove_dir_all(directory).unwrap();
        }
    }
    #[test]
    fn browser_request_dispatch_selects_catalog_and_persists_only_safe_event_metadata() {
        let (directory, mut state, grant, resource, journal) =
            browser_grant_fixture("browser-request-dispatch");
        let catalog_bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        state
            .configure_browser_catalog(
                super::browser_catalog::BrowserCatalog::from_bytes(&catalog_bytes).unwrap(),
            )
            .unwrap();
        let (peer, mut request) = browser_peer_and_request(&grant);
        request.operation = format!("request:{}", blindpass_core::signing::base64_url_encode(br#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":60}"#));
        let response = state.process_workload(&peer, &request).unwrap();
        assert!(response.starts_with(b"OK operation_request "));
        let body = &state.pending_node_events.back().unwrap().body;
        assert_eq!(
            body.get("action").and_then(Value::as_str),
            Some("browser.session")
        );
        assert_eq!(
            body.get("account").and_then(Value::as_str),
            Some("uid:1001")
        );
        let disk = fs::read(directory.join("pending-node-events.jsonl")).unwrap();
        for protected in [
            b"P05-SOURCE-CANARY".as_slice(),
            b"127.0.0.1",
            b"primary-password",
        ] {
            assert!(
                !disk
                    .windows(protected.len())
                    .any(|bytes| bytes == protected)
            );
        }
        assert!(
            journal.pending().is_empty(),
            "requesting approval cannot create login intent"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_request_dispatch_denies_missing_catalog_substitution_modes_and_stale_registration() {
        let (directory, mut state, grant, resource, journal) =
            browser_grant_fixture("browser-request-denials");
        state.browser_catalog = None;
        let (peer, mut request) = browser_peer_and_request(&grant);
        let payload = r#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":60}"#;
        request.operation = format!(
            "request:{}",
            blindpass_core::signing::base64_url_encode(payload.as_bytes())
        );
        assert!(state.process_workload(&peer, &request).is_err());
        let bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        state
            .configure_browser_catalog(
                super::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap(),
            )
            .unwrap();
        for bad in [
            payload.replace("report-primary", "report-unapproved"),
            payload.replace("browser_session", "file"),
            payload.replace("browser.session", "noop.marker"),
            payload.replace("\"ttl_seconds\":60", "\"ttl_seconds\":61"),
            payload.replace("\"ttl_seconds\":60", "\"ttl_seconds\":121"),
            payload.replace("\"ttl_seconds\":60", "\"ttl_seconds\":0"),
            payload.replace(
                "\"purpose\":",
                "\"endpoint\":\"https://unapproved.invalid\",\"purpose\":",
            ),
        ] {
            request.operation = format!(
                "request:{}",
                blindpass_core::signing::base64_url_encode(bad.as_bytes())
            );
            assert!(
                state.process_workload(&peer, &request).is_err(),
                "must deny {bad}"
            );
        }
        request.operation = format!(
            "request:{}",
            blindpass_core::signing::base64_url_encode(payload.as_bytes())
        );
        state
            .fleet_registrations
            .get_mut("workload-a")
            .unwrap()
            .policy_version = 2;
        assert!(state.process_workload(&peer, &request).is_err());
        assert!(state.pending_node_events.is_empty());
        assert!(journal.pending().is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_request_catalog_installation_is_atomic_and_requires_source_mapping() {
        let (directory, mut state, grant, resource, journal) =
            browser_grant_fixture("browser-catalog-install");
        let bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        let mut value = resource.to_value();
        let Value::Object(fields) = &mut value else {
            panic!("object");
        };
        fields
            .iter_mut()
            .find(|(key, _)| key == "credential_name")
            .unwrap()
            .1 = Value::String("unmapped-password".into());
        let bad = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![value])),
        ]))
        .unwrap();
        state
            .configure_browser_catalog(
                super::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap(),
            )
            .unwrap();
        assert!(
            state
                .configure_browser_catalog(
                    super::browser_catalog::BrowserCatalog::from_bytes(&bad).unwrap()
                )
                .is_err()
        );
        let (peer, mut request) = browser_peer_and_request(&grant);
        request.operation = format!("request:{}", blindpass_core::signing::base64_url_encode(br#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":60}"#));
        assert!(
            state.process_workload(&peer, &request).is_ok(),
            "failed replacement must retain original catalog"
        );
        assert!(journal.pending().is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_request_dispatch_obeys_independent_operation_policy_and_registration_ceiling() {
        let (directory, mut state, grant, resource, journal) =
            browser_grant_fixture("browser-request-ceilings");
        let bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        state
            .configure_browser_catalog(
                super::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap(),
            )
            .unwrap();
        let (peer, mut request) = browser_peer_and_request(&grant);
        state.fleet_policy.as_mut().unwrap().local_ceiling_seconds = 180;
        state
            .fleet_registrations
            .get_mut("workload-a")
            .unwrap()
            .local_ceiling_seconds = 180;
        let payload = r#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":120}"#;
        request.operation = format!(
            "request:{}",
            blindpass_core::signing::base64_url_encode(payload.as_bytes())
        );
        assert!(state.process_workload(&peer, &request).is_ok());
        let event_count = state.pending_node_events.len();
        request.operation = format!(
            "request:{}",
            blindpass_core::signing::base64_url_encode(payload.replace(":120", ":121").as_bytes())
        );
        assert!(state.process_workload(&peer, &request).is_err());
        request.operation = format!(
            "request:{}",
            blindpass_core::signing::base64_url_encode(payload.as_bytes())
        );
        state.fleet_policy.as_mut().unwrap().local_ceiling_seconds = 119;
        assert!(state.process_workload(&peer, &request).is_err());
        state.fleet_policy.as_mut().unwrap().local_ceiling_seconds = 180;
        state
            .fleet_registrations
            .get_mut("workload-a")
            .unwrap()
            .local_ceiling_seconds = 119;
        assert!(state.process_workload(&peer, &request).is_err());
        state
            .fleet_registrations
            .get_mut("workload-a")
            .unwrap()
            .local_ceiling_seconds = 180;
        state.fleet_policy.as_mut().unwrap().allowed_actions.clear();
        assert!(state.process_workload(&peer, &request).is_err());
        state.fleet_policy.as_mut().unwrap().allowed_actions = vec!["browser.session".into()];
        state.grant_verifier = super::grants::GrantVerifier::default();
        assert!(state.process_workload(&peer, &request).is_err());
        assert_eq!(state.pending_node_events.len(), event_count);
        assert!(journal.pending().is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    fn browser_cancel_request_fixture(
        label: &str,
    ) -> (
        std::path::PathBuf,
        BrokerState,
        PeerIdentity,
        WorkloadRequest,
        String,
    ) {
        let (directory, mut state, grant, resource, journal) = browser_grant_fixture(label);
        let bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        state
            .configure_browser_catalog(
                super::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap(),
            )
            .unwrap();
        let (peer, mut request) = browser_peer_and_request(&grant);
        request.operation = format!("request:{}", blindpass_core::signing::base64_url_encode(br#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":60}"#));
        let reply = state.process_workload(&peer, &request).unwrap();
        let key = std::str::from_utf8(&reply)
            .unwrap()
            .strip_prefix("OK operation_request ")
            .unwrap()
            .trim()
            .to_owned();
        assert!(journal.pending().is_empty());
        drop(journal);
        request.operation = format!("cancel:{key}");
        (directory, state, peer, request, key)
    }

    #[test]
    fn browser_cancel_needs_no_fresh_controller_time_to_stop_locally() {
        let (directory, mut state, peer, request, _) =
            browser_cancel_request_fixture("cancel-no-clock");
        state.grant_verifier = super::grants::GrantVerifier::default();
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_cancel requested\n"
        );
        assert_eq!(
            state
                .pending_node_events
                .iter()
                .filter(|e| e.kind == "operation_cancel")
                .count(),
            1
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_cancel_stops_a_correlated_grant_before_source_preparation() {
        let (directory, mut state, peer, request, key) =
            browser_cancel_request_fixture("cancel-grant-authority");
        let (_, reference, mut grant, resource, _) =
            browser_grant_fixture("cancel-grant-reference");
        let reference_directory = reference
            .pending_node_events_path
            .as_ref()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        grant.id = "gr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        let authorization = super::authorize_workload(&peer, &request, &state.workloads).unwrap();
        let (lease, _) = super::original_workload::OriginalWorkloadLease::fixture(
            &key,
            authorization,
            peer.clone(),
        );
        state.original_workload_leases.insert(key.clone(), lease);
        grant.request_event_key = Some(key);
        let policy = state.fleet_policy.clone().unwrap();
        let registration = state.fleet_registrations["workload-a"].clone();
        state
            .grant_verifier
            .accept_grant(
                grant.clone(),
                b"signed-cancel-fixture",
                "node-a",
                "node-a-1",
                &policy,
                &registration,
                super::grants::boottime_ms().unwrap(),
            )
            .unwrap();
        assert!(state.authorize_browser_grant(&grant).is_ok());
        state.process_workload(&peer, &request).unwrap();
        assert!(state.authorize_browser_grant(&grant).is_err());
        let mut consume = request;
        consume.operation = format!("consume:{}", grant.id);
        let journal_path = directory.join("cancel-sessions");
        fs::create_dir(&journal_path).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal =
            super::session_journal::SessionJournal::open_at(&journal_path, super::effective_uid())
                .unwrap();
        assert!(
            state
                .prepare_browser_login(&peer, &consume, &resource, &mut journal)
                .is_err()
        );
        assert!(journal.pending().is_empty());
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(reference_directory).unwrap();
    }

    #[test]
    fn legacy_operation_owner_cannot_acquire_browser_cancellation_type() {
        let (directory, mut state, peer, request, key) =
            browser_cancel_request_fixture("cancel-legacy-owner");
        state.operation_requests.values.get_mut(&key).unwrap().mode = None;
        assert!(matches!(
            state.process_workload(&peer, &request),
            Err(BrokerError::Configuration("operation_cancel_unsupported"))
        ));
        assert_eq!(state.pending_node_events.len(), 1);
        let header = super::parse_json(&format!(r#"{{"operation_owners":[{{"event_key":"{key}","workload_id":"workload-a","invocation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],"operation_closures":[]}}"#)).unwrap();
        let (owners, _) = super::read_operation_records(&header, 3).unwrap();
        assert_eq!(owners.get(&key).unwrap().mode, None);
        assert!(!owners.get(&key).unwrap().cancel_requested);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_cancel_crosses_actual_control_transport_with_broker_signature() {
        use std::io::{Read, Write};
        let (directory, mut state, peer, request, _) =
            browser_cancel_request_fixture("cancel-control-signature");
        state.process_workload(&peer, &request).unwrap();
        let identity = Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
        let issuer =
            blindpass_core::signing::ed25519::Ed25519KeyPair::from_seed(&[123; 32]).unwrap();
        identity
            .pin_issuer(super::keys::PinnedIssuer {
                tenant_id: "tenant-a".into(),
                node_id: "node-a".into(),
                epoch: 1,
                key_id: format!(
                    "ed25519-{}",
                    blindpass_core::signing::base64_url_encode(issuer.public_key())
                ),
                public_key: blindpass_core::signing::base64_url_encode(issuer.public_key()),
            })
            .unwrap();
        let state = Arc::new(Mutex::new(state));
        let (mut broker, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"PULL_EVENTS\n").unwrap();
        super::control::handle_connection(
            &mut broker,
            Some(fs::metadata(&directory).unwrap().gid()),
            identity.clone(),
            state,
            std::time::Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        drop(broker);
        let mut result = String::new();
        client.read_to_string(&mut result).unwrap();
        let (_, json) = result.trim_end().split_once('\n').unwrap();
        let events = super::parse_json(json).unwrap();
        let event = events
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event.get("kind").and_then(Value::as_str) == Some("operation_cancel"))
            .unwrap();
        let public = identity.public_identity().unwrap();
        let public =
            blindpass_core::signing::base64_url_decode(&public.signing_public, 32).unwrap();
        let signature = blindpass_core::signing::base64_url_decode(
            event
                .get("broker_signature")
                .and_then(Value::as_str)
                .unwrap(),
            64,
        )
        .unwrap();
        let key = event
            .get("idempotency_key")
            .and_then(Value::as_str)
            .unwrap();
        let message = blindpass_core::fleet::node_event_message(
            "node-a",
            key,
            "operation_cancel",
            event.get("body").unwrap(),
        )
        .unwrap();
        assert!(blindpass_core::signing::ed25519::verify(&public, &message, &signature).unwrap());
        assert!(!result.contains("P05-SOURCE-CANARY"));
        assert!(!result.contains("127.0.0.1"));
        assert!(!result.contains("primary-password"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_cancel_is_private_idempotent_and_durable_after_ack() {
        let (directory, mut state, peer, mut request, key) =
            browser_cancel_request_fixture("cancel-replay");
        for _ in 0..2 {
            assert_eq!(
                state.process_workload(&peer, &request).unwrap(),
                b"OK operation_cancel requested\n"
            );
        }
        let cancellations = state
            .pending_node_events
            .iter()
            .filter(|e| e.kind == "operation_cancel")
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(cancellations.len(), 1);
        assert_eq!(
            cancellations[0]
                .body
                .get("request_event_key")
                .and_then(Value::as_str),
            Some(key.as_str())
        );
        let bytes = super::canonicalize_value(&cancellations[0].body).unwrap();
        for forbidden in [
            b"P05-SOURCE-CANARY".as_slice(),
            b"127.0.0.1",
            b"primary-password",
        ] {
            assert!(!bytes.windows(forbidden.len()).any(|part| part == forbidden));
        }
        state
            .acknowledge_node_events(
                "node-a",
                &[key.clone(), cancellations[0].idempotency_key.clone()],
            )
            .unwrap();
        assert!(state.pending_node_events.is_empty());
        let (_, _, _, owners, _) =
            super::read_pending_node_events(&directory.join("pending-node-events.jsonl")).unwrap();
        state.operation_requests = owners;
        request.operation = format!("status:{key}");
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_status cancelling\n"
        );
        request.operation = format!("cancel:{key}");
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_cancel requested\n"
        );
        assert!(state.pending_node_events.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_cancel_denies_another_invocation_and_unknown_key() {
        let (directory, mut state, peer, mut request, key) =
            browser_cancel_request_fixture("cancel-owner-denial");
        let other = PeerIdentity::fixture(
            peer.uid,
            peer.gid,
            "agent.service",
            &"b".repeat(32),
            "uid:1001",
        );
        request.claimed_invocation_id = "b".repeat(32);
        assert!(state.process_workload(&other, &request).is_err());
        request.claimed_invocation_id = "a".repeat(32);
        request.operation = "cancel:event_unknown_00000001".into();
        assert!(state.process_workload(&peer, &request).is_err());
        request.operation = format!("status:{key}");
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_status pending\n"
        );
        assert_eq!(state.pending_node_events.len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_cancel_survives_a_full_outbox_and_emits_when_space_returns() {
        let (directory, mut state, peer, request, _) =
            browser_cancel_request_fixture("cancel-full-outbox");
        fill_audit_queue(&mut state, MAX_BROKER_AUDIT_EVENTS);
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_cancel requested\n"
        );
        assert_eq!(state.pending_node_events.len(), MAX_BROKER_AUDIT_EVENTS);
        let key = state.pending_node_events[0].idempotency_key.clone();
        state.acknowledge_node_events("node-a", &[key]).unwrap();
        assert_eq!(
            state
                .pending_node_events
                .iter()
                .filter(|e| e.kind == "operation_cancel")
                .count(),
            1
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_cancel_write_failure_keeps_the_local_stop_and_fence() {
        let (directory, mut state, peer, mut request, key) =
            browser_cancel_request_fixture("cancel-write-failure");
        let path = directory.join("pending-node-events.jsonl");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(state.process_workload(&peer, &request).is_err());
        assert!(state.persistence_fenced());
        request.operation = format!("status:{key}");
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_status cancelling\n"
        );
        fs::remove_dir(&path).unwrap();
        state.persist_pending_node_events().unwrap();
        assert!(!state.persistence_fenced());
        assert_eq!(
            state
                .pending_node_events
                .iter()
                .filter(|e| e.kind == "operation_cancel")
                .count(),
            1
        );
        let (_, _, _, owners, _) = super::read_pending_node_events(&path).unwrap();
        state.operation_requests = owners;
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_status cancelling\n"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_request_dispatch_runs_through_actual_workload_wire_and_safe_runtime_denial() {
        use std::io::{Read, Write};
        let (directory, mut state, grant, resource, journal) =
            browser_grant_fixture("browser-request-wire");
        let bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        state
            .configure_browser_catalog(
                super::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap(),
            )
            .unwrap();
        let state = Arc::new(Mutex::new(state));
        let (peer, request) = browser_peer_and_request(&grant);
        let encoded = blindpass_core::signing::base64_url_encode(br#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":60}"#);
        for (operation, prefix) in [
            (
                format!("request:{encoded}"),
                "OK operation_request ".to_owned(),
            ),
            (
                request.operation,
                "ERR browser_runtime_unavailable\n".to_owned(),
            ),
        ] {
            let (mut server, mut client) = UnixStream::pair().unwrap();
            let shared = Arc::clone(&state);
            let identity = peer.clone();
            let handler = std::thread::spawn(move || {
                if let Err(error) = super::handle_workload_connection_as(
                    &mut server,
                    &shared,
                    std::time::Instant::now() + Duration::from_secs(2),
                    |_, _| Ok(identity),
                ) {
                    super::write_error(&mut server, &error);
                }
            });
            client
                .write_all(
                    format!(
                        "WORK node-a workload-a agent.service {} {operation}\n",
                        grant.invocation_id
                    )
                    .as_bytes(),
                )
                .unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut result = String::new();
            client.read_to_string(&mut result).unwrap();
            handler.join().unwrap();
            assert!(result.starts_with(&prefix));
            assert!(!result.contains("P05-SOURCE-CANARY"));
            assert!(!result.contains("127.0.0.1"));
        }
        assert!(journal.pending().is_empty());
        assert_eq!(state.lock().unwrap().pending_node_events.len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_grant_requires_its_original_request_owner_before_fresh_login() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-grant-request-owner");
        let (peer, request) = browser_peer_and_request(&grant);
        let original_owner = state
            .operation_requests
            .get(grant.request_event_key.as_deref().unwrap())
            .unwrap()
            .clone();
        state.operation_requests = super::BoundedRecords::new(super::MAX_OPERATION_RECORDS);
        assert!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .is_err()
        );
        assert!(journal.pending().is_empty());
        assert!(state.pending_node_events.is_empty());
        let key = grant.request_event_key.as_ref().unwrap();
        state.remember_operation_request(key, &grant.workload_id, "b".repeat(32).as_str());
        assert!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .is_err()
        );
        state.remember_operation_request(key, &grant.workload_id, &grant.invocation_id);
        assert!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .is_err(),
            "legacy unbound owner cannot authorize login"
        );
        state
            .operation_requests
            .insert(grant.request_event_key.as_deref().unwrap(), original_owner);
        assert!(matches!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .unwrap(),
            super::BrowserPreparation::Login(_)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_operation_status_returns_only_its_live_signed_correlated_grant() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-grant-status");
        let bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        state
            .configure_browser_catalog(
                super::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap(),
            )
            .unwrap();
        let (peer, mut request) = browser_peer_and_request(&grant);
        let key = grant.request_event_key.as_ref().unwrap();
        request.operation = format!("status:{key}");
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            format!(
                "OK operation_status granted {} {}\n",
                grant.id, grant.operation_id
            )
            .as_bytes()
        );
        let mut duplicate = grant.clone();
        duplicate.id = "gr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        let policy = state.fleet_policy.as_ref().unwrap().clone();
        let registration = state
            .fleet_registrations
            .get(&grant.workload_id)
            .unwrap()
            .clone();
        state
            .grant_verifier
            .accept_grant(
                duplicate,
                b"duplicate-signed-fixture",
                "node-a",
                "node-a-1",
                &policy,
                &registration,
                super::grants::boottime_ms().unwrap(),
            )
            .unwrap();
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_status pending\n"
        );
        let (_, consume) = browser_peer_and_request(&grant);
        assert!(
            state
                .prepare_browser_login(&peer, &consume, &resource, &mut journal)
                .is_err()
        );
        assert!(journal.pending().is_empty());
        let old = grant.invocation_id.clone();
        let other = PeerIdentity::fixture(1001, 1001, "agent.service", &"b".repeat(32), "uid:1001");
        request.claimed_invocation_id = "b".repeat(32);
        assert!(state.process_workload(&other, &request).is_err());
        request.claimed_invocation_id = old;
        state.record_operation_closure(key, "cancelled");
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_status closed cancelled\n"
        );
        request.operation = format!("consume:{}", grant.id);
        assert!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .is_err()
        );
        assert!(journal.pending().is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_consume_dispatch_never_burns_grant_through_noop_fallback() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-consume-dispatch");
        let (peer, request) = browser_peer_and_request(&grant);
        let result = state.process_workload(&peer, &request);
        assert!(matches!(
            result,
            Err(BrokerError::Configuration("browser_runtime_unavailable"))
        ));
        assert!(state.pending_node_events.is_empty());
        assert!(journal.pending().is_empty());
        assert!(
            matches!(
                state
                    .prepare_browser_login(&peer, &request, &resource, &mut journal)
                    .unwrap(),
                super::BrowserPreparation::Login(_)
            ),
            "runtime-unavailable denial must preserve the one-use grant"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_preparation_records_intent_consumes_once_and_replays_only_status() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-preparation");
        let (peer, request) = browser_peer_and_request(&grant);
        let super::BrowserPreparation::Login(job) = state
            .prepare_browser_login(&peer, &request, &resource, &mut journal)
            .unwrap()
        else {
            panic!("first login")
        };
        assert!(!format!("{job:?}").contains("P05-SOURCE-CANARY"));
        assert_eq!(journal.pending().len(), 1);
        assert_eq!(
            journal.pending()[0].binding.account,
            "primary",
            "application account differs from OS uid account"
        );
        assert_eq!(state.pending_node_events.len(), 2);
        assert!(
            state
                .grant_verifier
                .preview_consumption(
                    &grant.id,
                    &blindpass_core::identity::authorize_workload(
                        &peer,
                        &request,
                        &state.workloads
                    )
                    .unwrap(),
                    1,
                    super::grants::boottime_ms().unwrap()
                )
                .is_err()
        );
        assert!(matches!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .unwrap(),
            super::BrowserPreparation::Existing(super::session_journal::SessionState::Reserved)
        ));
        drop(journal);
        let mut restored = super::session_journal::SessionJournal::open_at(
            &directory.join("sessions"),
            super::effective_uid(),
        )
        .unwrap();
        assert!(matches!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut restored)
                .unwrap(),
            super::BrowserPreparation::Existing(
                super::session_journal::SessionState::BlockedUncertain
            )
        ));
        drop(restored);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_preparation_denies_wrong_invocation_and_resource_before_consuming() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-preparation-denial");
        let (peer, mut request) = browser_peer_and_request(&grant);
        request.claimed_invocation_id = "b".repeat(32);
        assert!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .is_err()
        );
        let mut value = resource.to_value();
        let Value::Object(fields) = &mut value else {
            panic!("object")
        };
        fields
            .iter_mut()
            .find(|(key, _)| key == "resource_id")
            .unwrap()
            .1 = Value::String("other-report".into());
        let other = super::BrowserResource::from_value(&value).unwrap();
        let (peer, request) = browser_peer_and_request(&grant);
        assert!(
            state
                .prepare_browser_login(&peer, &request, &other, &mut journal)
                .is_err()
        );
        assert!(journal.pending().is_empty());
        assert!(state.pending_node_events.is_empty());
        assert!(matches!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .unwrap(),
            super::BrowserPreparation::Login(_)
        ));
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_handoff_rechecks_current_policy_and_revocation_after_job_preparation() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-handoff-revalidation");
        let (peer, request) = browser_peer_and_request(&grant);
        let super::BrowserPreparation::Login(job) = state
            .prepare_browser_login(&peer, &request, &resource, &mut journal)
            .unwrap()
        else {
            panic!("login")
        };
        assert!(state.authorize_browser_handoff(&job).is_ok());
        state.fleet_policy.as_mut().unwrap().policy_version = 2;
        assert!(state.authorize_browser_handoff(&job).is_err());
        state.fleet_policy.as_mut().unwrap().policy_version = 1;
        let revocation = blindpass_core::fleet::Revocation {
            grant_id: grant.id.clone(),
            node_id: grant.node_id.clone(),
            reason: "operator_revoked".into(),
            revoked_at_ms: grant.issued_at_ms,
            retain_until_ms: grant.expires_at_ms + 60_000,
            issuer_epoch: grant.issuer_epoch,
        };
        state
            .apply_grant_revocation(&grant.node_id, &revocation)
            .unwrap();
        assert!(state.authorize_browser_handoff(&job).is_err());
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_source_missing_and_failed_outbox_never_start_helper() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-preparation-durability");
        let (peer, request) = browser_peer_and_request(&grant);
        let (unit, name) = resource.credential_destination();
        state
            .credentials
            .remove(&super::destination_key(unit, name));
        assert!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .is_err()
        );
        assert!(journal.pending().is_empty());
        state
            .credentials
            .insert(&super::destination_key(unit, name), b"P05-SOURCE-CANARY")
            .unwrap();
        fs::create_dir(directory.join("pending-node-events.jsonl")).unwrap();
        assert!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .is_err()
        );
        assert_eq!(
            journal.pending().len(),
            1,
            "durable uncertainty blocks retry"
        );
        assert!(matches!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .unwrap(),
            super::BrowserPreparation::Existing(super::session_journal::SessionState::Reserved)
        ));
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_replay_is_bound_to_original_workload_id_and_recipe() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-replay-resource");
        let (peer, mut request) = browser_peer_and_request(&grant);
        state
            .prepare_browser_login(&peer, &request, &resource, &mut journal)
            .unwrap();
        let mut value = resource.to_value();
        let Value::Object(fields) = &mut value else {
            panic!("object")
        };
        let Value::Object(configuration) = &mut fields
            .iter_mut()
            .find(|(key, _)| key == "configuration")
            .unwrap()
            .1
        else {
            panic!("configuration")
        };
        configuration
            .iter_mut()
            .find(|(key, _)| key == "origin")
            .unwrap()
            .1 = Value::String("https://other.invalid".into());
        configuration
            .iter_mut()
            .find(|(key, _)| key == "loginOrigin")
            .unwrap()
            .1 = Value::String("https://other.invalid".into());
        let changed = super::BrowserResource::from_value(&value).unwrap();
        assert!(
            state
                .prepare_browser_login(&peer, &request, &changed, &mut journal)
                .is_err()
        );
        let mut value = resource.to_value();
        let Value::Object(fields) = &mut value else {
            panic!("object")
        };
        fields
            .iter_mut()
            .find(|(key, _)| key == "workload_ids")
            .unwrap()
            .1 = Value::Array(vec![Value::String("workload-b".into())]);
        let next = super::BrowserResource::from_value(&value).unwrap();
        state.workloads[0].workload_id = "workload-b".into();
        request.workload_id = "workload-b".into();
        assert!(
            state
                .prepare_browser_login(&peer, &request, &next, &mut journal)
                .is_err()
        );
        state.workloads[0].workload_id = "workload-a".into();
        request.workload_id = "workload-a".into();
        state.workloads[0].node_id = "node-b".into();
        request.node_id = "node-b".into();
        assert!(
            state
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .is_err()
        );
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_stage_reply_persists_validated_handle_and_rejects_another_account() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("browser-staged-reply");
        let (peer, request) = browser_peer_and_request(&grant);
        let super::BrowserPreparation::Login(job) = state
            .prepare_browser_login(&peer, &request, &resource, &mut journal)
            .unwrap()
        else {
            panic!("login")
        };
        let now = state
            .grant_verifier
            .trusted_controller_time_ms(super::grants::boottime_ms().unwrap())
            .unwrap();
        journal
            .record_helper(
                &grant.operation_id,
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                now,
            )
            .unwrap();
        let deadline = now + 300_000;
        let envelope = |account: &str| {
            super::parse_json(&format!(r#"{{"status":"authenticated","originalDeadlineMs":{deadline},"revokeHandle":{{"kind":"fixture","account":"{account}","sessionReference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"cookies":[{{"name":"__Host-bp-fixture","value":"P05-COOKIE-CANARY","domain":"127.0.0.1","path":"/","secure":true,"httpOnly":true,"sameSite":"Strict","expires":{}}}]}}"#,deadline/1000)).unwrap()
        };
        let wrong =
            super::private_helper::HelperReply::Session(blindpass_core::secret::SecretBytes::new(
                super::canonicalize_value(&envelope("isolation")).unwrap(),
            ));
        assert!(matches!(
            job.stage_reply(wrong, &mut journal, now),
            Err(super::private_helper::HelperStatus::Uncertain)
        ));
        assert!(journal.pending()[0].revoke_handle.is_none());
        let protected =
            super::private_helper::HelperReply::Session(blindpass_core::secret::SecretBytes::new(
                super::canonicalize_value(&envelope("primary")).unwrap(),
            ));
        let session = job.stage_reply(protected, &mut journal, now).unwrap();
        assert_eq!(journal.pending()[0].original_deadline_ms, Some(deadline));
        assert_eq!(
            journal.pending()[0].revoke_handle.as_ref(),
            Some(session.revoke_handle())
        );
        assert!(!format!("{session:?} {job:?}").contains("P05-COOKIE-CANARY"));
        assert!(state.authorize_browser_handoff(&job).is_ok());
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }

    fn prepared_closed_fixture(
        label: &str,
    ) -> (
        std::path::PathBuf,
        BrokerState,
        Box<super::PreparedBrowserLogin>,
        super::session_journal::SessionJournal,
        u64,
    ) {
        let (directory, mut state, grant, resource, mut journal) = browser_grant_fixture(label);
        let (peer, request) = browser_peer_and_request(&grant);
        let super::BrowserPreparation::Login(mut job) = state
            .prepare_browser_login(&peer, &request, &resource, &mut journal)
            .unwrap()
        else {
            panic!("fresh fixture");
        };
        let time = state
            .grant_verifier
            .trusted_controller_time_ms(super::grants::boottime_ms().unwrap())
            .unwrap()
            + 100;
        // Trusted reconciliation fixture only; these booleans do not constitute
        // actual website/cgroup execution evidence.
        job.helper_job.take();
        journal
            .record_helper(
                job.operation_id(),
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                time + 1,
            )
            .unwrap();
        journal
            .record_login(
                job.operation_id(),
                time + 300_000,
                super::session_journal::RevokeHandle::Fixture {
                    account: "primary".into(),
                    session_reference: "NONBEARER-REFERENCE".into(),
                },
                time + 2,
            )
            .unwrap();
        (directory, state, job, journal, time)
    }

    #[test]
    fn closed_browser_scan_never_withdraws_another_request_for_the_same_recipe() {
        let (directory, mut state, job, mut journal, time) =
            prepared_closed_fixture("closed-scan-other-request");
        let original = job.grant.request_event_key.as_ref().unwrap();
        let other = "event_00000000000000000000000000000000";
        assert!(other < original.as_str());
        let owner = state.operation_requests.get(original).unwrap().clone();
        state.operation_requests.insert(other, owner);
        let lease = state
            .original_workload_leases
            .get(original)
            .unwrap()
            .clone();
        state.original_workload_leases.insert(other.into(), lease);
        journal
            .reconcile(job.operation_id(), true, true, time + 3)
            .unwrap();
        state.retry_browser_closures(&journal, &mut std::collections::BTreeSet::new());
        assert!(state.original_workload_leases.contains_key(other));
        assert!(state.operation_closures.get(other).is_none());
        assert!(!state.original_workload_leases.contains_key(original));
        assert_eq!(
            state.operation_closures.get(original),
            Some(&"completed".into())
        );
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn legacy_closed_browser_scan_reports_without_guessing_a_request_owner() {
        let (directory, mut state, job, mut journal, time) =
            prepared_closed_fixture("closed-scan-legacy-owner");
        let original = job.grant.request_event_key.as_ref().unwrap();
        journal
            .reconcile(job.operation_id(), true, true, time + 3)
            .unwrap();
        drop(journal);
        let path = directory.join("sessions/state.json");
        let mut snapshot =
            blindpass_core::canon::parse_json(&fs::read_to_string(&path).unwrap()).unwrap();
        if let Value::Object(fields) = &mut snapshot {
            fields
                .iter_mut()
                .find(|(key, _)| key == "version")
                .unwrap()
                .1 = Value::Unsigned(3);
            if let Value::Array(records) = &mut fields
                .iter_mut()
                .find(|(key, _)| key == "records")
                .unwrap()
                .1
            {
                for record in records {
                    if let Value::Object(fields) = record
                        && let Value::Object(binding) = &mut fields
                            .iter_mut()
                            .find(|(key, _)| key == "binding")
                            .unwrap()
                            .1
                    {
                        binding.retain(|(key, _)| key != "request_event_key");
                    }
                }
            }
        }
        fs::write(
            &path,
            blindpass_core::canon::canonicalize_value(&snapshot).unwrap(),
        )
        .unwrap();
        let journal = super::session_journal::SessionJournal::open_at(
            &directory.join("sessions"),
            super::effective_uid(),
        )
        .unwrap();
        assert!(
            journal.closed_browser_records()[0]
                .binding
                .request_event_key
                .is_none()
        );
        state.pending_node_events.clear();
        state.retry_browser_closures(&journal, &mut std::collections::BTreeSet::new());
        assert_eq!(state.pending_node_events.len(), 2);
        assert!(state.original_workload_leases.contains_key(original));
        assert!(state.operation_closures.get(original).is_none());
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn closed_browser_scan_retries_backpressure_then_stops_after_ack() {
        let (directory, mut state, job, mut journal, time) =
            prepared_closed_fixture("closed-scan-pressure");
        journal
            .reconcile(job.operation_id(), true, true, time + 3)
            .unwrap();
        while state.pending_node_events.len() < super::MAX_BROKER_AUDIT_EVENTS {
            let n = state.pending_node_events.len();
            state
                .pending_node_events
                .push_back(super::PendingNodeEvent {
                    idempotency_key: format!("event_pressure_{n:032}"),
                    kind: "audit".into(),
                    body: Value::Null,
                });
        }
        let mut published = std::collections::BTreeSet::new();
        state.retry_browser_closures(&journal, &mut published);
        assert!(published.is_empty());
        assert!(journal.closed_record(job.grant_id()).is_some());
        state.pending_node_events.clear();
        state.retry_browser_closures(&journal, &mut published);
        assert_eq!(published.len(), 1);
        assert_eq!(state.pending_node_events.len(), 2);
        let keys = state
            .pending_node_events
            .iter()
            .map(|e| e.idempotency_key.clone())
            .collect::<Vec<_>>();
        state
            .acknowledge_node_events(&job.grant.node_id, &keys)
            .unwrap();
        state.retry_browser_closures(&journal, &mut published);
        assert!(state.pending_node_events.is_empty());
        assert_eq!(
            state
                .operation_closures
                .get(job.grant.request_event_key.as_ref().unwrap()),
            Some(&"completed".into())
        );
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn closed_browser_scan_ignores_unconfirmed_cleanup_and_canonically_replays_once() {
        let (directory, mut state, job, mut journal, time) =
            prepared_closed_fixture("closed-scan-restart");
        let mut published = std::collections::BTreeSet::new();
        let before = state.pending_node_events.clone();
        state.retry_browser_closures(&journal, &mut published);
        assert_eq!(state.pending_node_events, before);
        assert!(published.is_empty());
        state.pending_node_events.clear();
        journal
            .reconcile(job.operation_id(), true, true, time + 3)
            .unwrap();
        state.retry_browser_closures(&journal, &mut published);
        let events = state.pending_node_events.clone();
        let keys = events
            .iter()
            .map(|e| e.idempotency_key.clone())
            .collect::<Vec<_>>();
        state
            .acknowledge_node_events(&job.grant.node_id, &keys)
            .unwrap();
        published.clear(); // a new coordinator process starts with no volatile scan marks
        state.retry_browser_closures(&journal, &mut published);
        assert_eq!(state.pending_node_events, events);
        state.retry_browser_closures(&journal, &mut published);
        assert_eq!(state.pending_node_events, events);
        assert!(state.browser_dispatch_candidates().is_empty());
        drop(journal);
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn closed_browser_scan_retries_storage_without_restoring_authority_or_cancel() {
        for cancelled in [false, true] {
            let (directory, mut state, job, mut journal, time) =
                prepared_closed_fixture("closed-scan-storage");
            let key = job.grant.request_event_key.as_ref().unwrap();
            state
                .operation_requests
                .values
                .get_mut(key)
                .unwrap()
                .cancel_requested = cancelled;
            journal
                .reconcile(job.operation_id(), true, true, time + 3)
                .unwrap();
            let path = state.pending_node_events_path.clone().unwrap();
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            let before = state.pending_node_events.clone();
            let mut published = std::collections::BTreeSet::new();
            state.retry_browser_closures(&journal, &mut published);
            assert!(published.is_empty());
            assert_eq!(state.pending_node_events, before);
            assert!(state.original_workload_leases.is_empty());
            assert!(state.operation_closures.get(key).is_none());
            assert!(state.persistence_fenced());
            fs::remove_dir(&path).unwrap();
            state.retry_browser_closures(&journal, &mut published);
            assert_eq!(published.len(), 1);
            assert_eq!(
                state.operation_requests.get(key).unwrap().cancel_requested,
                cancelled
            );
            assert_eq!(state.operation_closures.get(key).is_some(), !cancelled);
            assert!(state.browser_dispatch_candidates().is_empty());
            drop(journal);
            drop(state);
            fs::remove_dir_all(directory).unwrap();
        }
    }
    #[test]
    fn browser_closure_after_a_controller_revocation_is_cancelled_never_completed() {
        // Clients accept only rejected/expired/cancelled/denied/completed, so a
        // revoked session ends as `cancelled`; a signed closure already
        // recorded for the request is never overwritten.
        for (revoked, signed, replay, expected) in [
            (false, None, false, "completed"),
            (true, None, false, "cancelled"),
            (true, None, true, "cancelled"),
            (false, None, true, "completed"),
            (true, Some("expired"), false, "expired"),
        ] {
            let (directory, mut state, job, mut journal, time) =
                prepared_closed_fixture("closure-revoked");
            let key = job.grant.request_event_key.clone().unwrap();
            if revoked {
                let revocation = blindpass_core::fleet::Revocation {
                    grant_id: job.grant.id.clone(),
                    node_id: job.grant.node_id.clone(),
                    reason: "operator_revoked".into(),
                    revoked_at_ms: job.grant.issued_at_ms,
                    retain_until_ms: job.grant.expires_at_ms + 60_000,
                    issuer_epoch: job.grant.issuer_epoch,
                };
                state
                    .apply_grant_revocation(&job.grant.node_id, &revocation)
                    .unwrap();
            }
            if let Some(status) = signed {
                state.record_operation_closure(&key, status);
                state
                    .original_workload_leases
                    .insert(key.clone(), job.original_workload.clone());
            }
            journal
                .reconcile(job.operation_id(), true, true, time + 3)
                .unwrap();
            if replay {
                let mut published = std::collections::BTreeSet::new();
                state.retry_browser_closures(&journal, &mut published);
                assert_eq!(published.len(), 1);
            } else {
                state.finish_browser_operation(&job, &journal).unwrap();
            }
            assert_eq!(
                state.operation_closures.get(&key).map(String::as_str),
                Some(expected),
                "revoked={revoked} signed={signed:?} replay={replay}"
            );
            // The result reported to the controller is unchanged.
            assert_eq!(
                state
                    .pending_node_events
                    .iter()
                    .rfind(|event| event.kind == "operation_result")
                    .and_then(|event| event.body.get("result_code"))
                    .and_then(Value::as_str),
                Some("browser_session_closed")
            );
            drop(journal);
            drop(state);
            fs::remove_dir_all(directory).unwrap();
        }
    }
    #[test]
    fn browser_closure_events_are_distinct_immutable_and_replay_after_ack_restart() {
        let (directory, mut state, job, mut journal, time) =
            prepared_closed_fixture("async-closure-replay");
        let intent = state.pending_node_events.clone();
        state
            .acknowledge_node_events(&job.grant.node_id, job.event_keys())
            .unwrap();
        assert!(state.pending_node_events.is_empty());
        assert!(state.finish_browser_operation(&job, &journal).is_err());
        journal
            .reconcile(job.operation_id(), true, true, time + 3)
            .unwrap();
        let keys = state.finish_browser_operation(&job, &journal).unwrap();
        assert!(
            keys.iter()
                .all(|key| !intent.iter().any(|event| &event.idempotency_key == key))
        );
        let final_events = state.pending_node_events.clone();
        assert_eq!(final_events.len(), 2);
        assert_eq!(
            final_events[0]
                .body
                .get("result_code")
                .and_then(Value::as_str),
            Some("browser_session_closed")
        );
        assert_eq!(
            state.finish_browser_operation(&job, &journal).unwrap(),
            keys
        );
        assert_eq!(state.pending_node_events, final_events);
        state
            .acknowledge_node_events(&job.grant.node_id, &keys)
            .unwrap();
        drop(journal);
        let restored = super::session_journal::SessionJournal::open_at(
            &directory.join("sessions"),
            super::effective_uid(),
        )
        .unwrap();
        let (events, _, _, owners, closures) =
            super::read_pending_node_events(state.pending_node_events_path.as_ref().unwrap())
                .unwrap();
        state.pending_node_events = events;
        state.operation_requests = owners;
        state.operation_closures = closures;
        state.original_workload_leases.clear();
        state.grant_verifier = super::grants::GrantVerifier::default();
        assert_eq!(
            state
                .publish_browser_closure(&restored, &job.grant.node_id, job.grant_id())
                .unwrap(),
            keys
        );
        assert_eq!(state.pending_node_events, final_events);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_closure_denies_wrong_binding_incomplete_reconciliation_and_backpressure() {
        let (directory, mut state, mut job, mut journal, time) =
            prepared_closed_fixture("async-closure-denial");
        assert!(
            journal
                .reconcile(job.operation_id(), false, true, time + 3)
                .is_err()
        );
        assert!(state.finish_browser_operation(&job, &journal).is_err());
        journal
            .reconcile(job.operation_id(), true, true, time + 4)
            .unwrap();
        job.grant.resource_id = "report-isolation".into();
        assert!(state.finish_browser_operation(&job, &journal).is_err());
        job.grant.resource_id = "report-primary".into();
        assert!(
            state
                .publish_browser_closure(&journal, "node-other", job.grant_id())
                .is_err()
        );
        fill_audit_queue(&mut state, super::MAX_BROKER_AUDIT_EVENTS - 1);
        assert!(state.finish_browser_operation(&job, &journal).is_err());
        assert!(state.original_workload_leases.is_empty());
        state.pending_node_events.clear();
        state.finish_browser_operation(&job, &journal).unwrap();
        assert_eq!(state.pending_node_events.len(), 2);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_closure_keeps_local_stop_on_storage_failure_and_never_reopens_cancel() {
        let (directory, mut state, job, mut journal, time) =
            prepared_closed_fixture("async-closure-storage");
        let key = job.grant.request_event_key.as_ref().unwrap();
        state
            .operation_requests
            .values
            .get_mut(key)
            .unwrap()
            .cancel_requested = true;
        journal
            .reconcile(job.operation_id(), true, true, time + 3)
            .unwrap();
        let before = state.pending_node_events.clone();
        let path = state.pending_node_events_path.clone().unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(state.finish_browser_operation(&job, &journal).is_err());
        assert!(state.persistence_fenced());
        assert_eq!(state.pending_node_events, before);
        assert!(state.original_workload_leases.is_empty());
        fs::remove_dir(&path).unwrap();
        state.finish_browser_operation(&job, &journal).unwrap();
        assert!(state.operation_closures.get(key).is_none());
        assert!(state.operation_requests.get(key).unwrap().cancel_requested);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn browser_closure_partial_ack_and_pending_restart_keep_original_event_bytes() {
        let (directory, mut state, job, mut journal, time) =
            prepared_closed_fixture("async-closure-partial-ack");
        state
            .acknowledge_node_events(&job.grant.node_id, job.event_keys())
            .unwrap();
        journal
            .reconcile(job.operation_id(), true, true, time + 3)
            .unwrap();
        let keys = state.finish_browser_operation(&job, &journal).unwrap();
        let original = super::canonicalize_value(&Value::Array(
            state
                .pending_node_events
                .iter()
                .map(|event| {
                    Value::Object(vec![
                        (
                            "idempotency_key".into(),
                            Value::String(event.idempotency_key.clone()),
                        ),
                        ("kind".into(), Value::String(event.kind.clone())),
                        ("body".into(), event.body.clone()),
                    ])
                })
                .collect(),
        ))
        .unwrap();
        let path = state.pending_node_events_path.clone().unwrap();
        let (events, _, _, owners, closures) = super::read_pending_node_events(&path).unwrap();
        state.pending_node_events = events;
        state.operation_requests = owners;
        state.operation_closures = closures;
        state
            .publish_browser_closure(&journal, &job.grant.node_id, job.grant_id())
            .unwrap();
        assert_eq!(
            super::canonicalize_value(&Value::Array(
                state
                    .pending_node_events
                    .iter()
                    .map(|event| Value::Object(vec![
                        (
                            "idempotency_key".into(),
                            Value::String(event.idempotency_key.clone())
                        ),
                        ("kind".into(), Value::String(event.kind.clone())),
                        ("body".into(), event.body.clone())
                    ]))
                    .collect()
            ))
            .unwrap(),
            original
        );
        state
            .acknowledge_node_events(&job.grant.node_id, &[keys[0].clone()])
            .unwrap();
        state
            .publish_browser_closure(&journal, &job.grant.node_id, job.grant_id())
            .unwrap();
        assert_eq!(state.pending_node_events.len(), 2);
        state.pending_node_events[0].kind = "operation_request".into();
        assert!(matches!(
            state.publish_browser_closure(&journal, &job.grant.node_id, job.grant_id()),
            Err(BrokerError::Configuration("browser_closure_event_conflict"))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    fn workload_peer() -> PeerIdentity {
        PeerIdentity::fixture(1001, 1001, "agent.service", "inv-live", "uid:1001")
    }

    fn consume_request(grant_id: &str) -> WorkloadRequest {
        WorkloadRequest {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            claimed_unit: "agent.service".to_owned(),
            claimed_invocation_id: "inv-live".to_owned(),
            operation: format!("consume:{grant_id}"),
        }
    }

    fn error_code(result: Result<Vec<u8>, BrokerError>) -> Vec<u8> {
        let error = result.expect_err("request must be denied");
        let (mut server, mut client) = UnixStream::pair().unwrap();
        super::write_error(&mut server, &error);
        drop(server);
        let mut response = Vec::new();
        std::io::Read::read_to_end(&mut client, &mut response).unwrap();
        response
    }

    #[test]
    fn workload_socket_reports_stable_consume_denial_codes() {
        let (directory, mut state, grant) = fleet_state_with_grant("consume-codes");
        let peer = workload_peer();
        assert_eq!(
            error_code(state.process_workload(
                &peer,
                &consume_request("gr_1123456789abcdef0123456789abcdef")
            )),
            b"ERR grant_unknown\n"
        );
        let mut other_invocation = consume_request(&grant.id);
        other_invocation.claimed_invocation_id = "inv-other".to_owned();
        let other_peer =
            PeerIdentity::fixture(1001, 1001, "agent.service", "inv-other", "uid:1001");
        assert_eq!(
            error_code(state.process_workload(&other_peer, &other_invocation)),
            b"ERR grant_identity_mismatch\n"
        );
        assert_eq!(
            state
                .process_workload(&peer, &consume_request(&grant.id))
                .unwrap(),
            format!("OK operation_completed {}\n", grant.id).as_bytes()
        );
        assert_eq!(
            error_code(state.process_workload(&peer, &consume_request(&grant.id))),
            b"ERR grant_consumed\n"
        );
        state.fleet_policy = None;
        assert_eq!(
            error_code(state.process_workload(&peer, &consume_request(&grant.id))),
            b"ERR fleet_policy_unavailable\n"
        );
        state.grant_verifier = super::grants::GrantVerifier::default();
        assert_eq!(
            error_code(state.process_workload(&peer, &consume_request(&grant.id))),
            b"ERR trusted_time_unavailable\n"
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

        let mut shared_group = config.clone();
        shared_group.workload_group = Some("blindpass-node".to_owned());
        shared_group.node_group = Some("blindpass-node".to_owned());
        assert!(
            validate_config(&shared_group)
                .unwrap_err()
                .to_string()
                .contains("workload and node groups must differ"),
            "a shared group would let workloads reach the control socket"
        );
        let mut separate_groups = shared_group.clone();
        separate_groups.workload_group = Some("blindpass-workload".to_owned());
        assert!(validate_config(&separate_groups).is_ok());

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

    fn retry_request(purpose: &str, ttl: u64, key: &str) -> String {
        let bytes = super::canonicalize_value(&Value::Object(vec![
            ("action".into(), Value::String("browser.session".into())),
            ("mode".into(), Value::String("browser_session".into())),
            ("purpose".into(), Value::String(purpose.into())),
            ("resource_id".into(), Value::String("report-primary".into())),
            ("ttl_seconds".into(), Value::Unsigned(ttl)),
            ("request_key".into(), Value::String(key.into())),
        ]))
        .unwrap();
        format!(
            "request:{}",
            blindpass_core::signing::base64_url_encode(&bytes)
        )
    }
    fn retry_fixture(
        label: &str,
    ) -> (
        std::path::PathBuf,
        BrokerState,
        PeerIdentity,
        WorkloadRequest,
    ) {
        let (directory, mut state, peer, mut request, _) = browser_cancel_request_fixture(label);
        state.pending_node_events.clear();
        state.operation_requests = super::BoundedRecords::new(super::MAX_OPERATION_RECORDS);
        request.operation = retry_request("read report", 60, "retry_0123456789abcdef");
        (directory, state, peer, request)
    }

    #[test]
    fn browser_new_request_advertises_automatic_controller_version() {
        let (directory, mut state, peer, request) = retry_fixture("automatic-version");
        state.process_workload(&peer, &request).unwrap();
        let event = state.pending_node_events.back().unwrap();
        assert_eq!(event.kind, "operation_request");
        assert_eq!(
            event.body.get("request_version").and_then(Value::as_u64),
            Some(2)
        );
        assert!(event.body.get("request_key").is_none());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_returns_original_key_after_ack_restart_and_json_reordering() {
        let (directory, mut state, peer, mut request) = retry_fixture("retry-restart");
        let first = state.process_workload(&peer, &request).unwrap();
        let count = state.pending_node_events.len();
        request.operation = format!("request:{}", blindpass_core::signing::base64_url_encode(br#"{"ttl_seconds":60,"resource_id":"report-primary","request_key":"retry_0123456789abcdef","purpose":"read report","mode":"browser_session","action":"browser.session"}"#));
        assert_eq!(state.process_workload(&peer, &request).unwrap(), first);
        assert_eq!(state.pending_node_events.len(), count);
        let event_key = std::str::from_utf8(&first)
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .to_owned();
        state
            .acknowledge_node_events("node-a", &[event_key])
            .unwrap();
        let path = state.pending_node_events_path.clone().unwrap();
        let (events, _, _, owners, closures) = super::read_pending_node_events(&path).unwrap();
        state.operation_requests = super::BoundedRecords::new(super::MAX_OPERATION_RECORDS);
        state.pending_node_events = events;
        state.operation_requests = owners;
        state.operation_closures = closures;
        assert_eq!(state.process_workload(&peer, &request).unwrap(), first);
        assert!(state.pending_node_events.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_conflicts_deny_changed_fields_and_restarted_invocation() {
        let (directory, mut state, peer, mut request) = retry_fixture("retry-conflict");
        state.process_workload(&peer, &request).unwrap();
        for (purpose, ttl) in [("different purpose", 60), ("read report", 59)] {
            request.operation = retry_request(purpose, ttl, "retry_0123456789abcdef");
            assert!(matches!(
                state.process_workload(&peer, &request),
                Err(BrokerError::Configuration("operation_request_conflict"))
            ));
        }
        request.operation = retry_request("read report", 60, "retry_0123456789abcdef");
        let other = String::from_utf8(
            blindpass_core::signing::base64_url_decode(
                request.operation.strip_prefix("request:").unwrap(),
                request.operation.strip_prefix("request:").unwrap().len() * 3 / 4,
            )
            .unwrap(),
        )
        .unwrap()
        .replace("report-primary", "report-other");
        request.operation = format!(
            "request:{}",
            blindpass_core::signing::base64_url_encode(other.as_bytes())
        );
        assert!(matches!(
            state.process_workload(&peer, &request),
            Err(BrokerError::Configuration("operation_request_conflict"))
        ));
        request.operation = retry_request("read report", 60, "retry_0123456789abcdef");
        request.claimed_invocation_id = "b".repeat(32);
        let restarted = PeerIdentity::fixture(
            1001,
            1001,
            "agent.service",
            &request.claimed_invocation_id,
            "uid:1001",
        );
        assert!(matches!(
            state.process_workload(&restarted, &request),
            Err(BrokerError::Configuration("operation_request_denied"))
        ));
        assert_eq!(state.pending_node_events.len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_is_metadata_under_clock_queue_and_persistence_fences() {
        let (directory, mut state, peer, request) = retry_fixture("retry-fenced");
        let first = state.process_workload(&peer, &request).unwrap();
        state.grant_verifier = super::grants::GrantVerifier::default();
        state
            .pending_state_fenced
            .store(true, super::Ordering::Release);
        let duplicate = state.pending_node_events.front().unwrap().clone();
        while state.pending_node_events.len() < super::MAX_BROKER_AUDIT_EVENTS {
            state.pending_node_events.push_back(duplicate.clone());
        }
        assert_eq!(state.process_workload(&peer, &request).unwrap(), first);
        assert_eq!(
            state.pending_node_events.len(),
            super::MAX_BROKER_AUDIT_EVENTS
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_cancel_before_admission_survives_restart_and_blocks_late_request() {
        let (directory, mut state, peer, request) = retry_fixture("retry-cancel-before");
        let mut cancel = request.clone();
        cancel.operation = "cancel-key:retry_0123456789abcdef".into();
        assert_eq!(
            state.process_workload(&peer, &cancel).unwrap(),
            b"OK operation_cancel requested\n"
        );
        assert!(state.pending_node_events.is_empty());
        let path = state.pending_node_events_path.clone().unwrap();
        let (events, _, _, owners, closures) = super::read_pending_node_events(&path).unwrap();
        state.pending_node_events = events;
        state.operation_requests = owners;
        state.operation_closures = closures;
        assert_eq!(
            state.process_workload(&peer, &cancel).unwrap(),
            b"OK operation_cancel requested\n"
        );
        assert!(matches!(
            state.process_workload(&peer, &request),
            Err(BrokerError::Configuration("operation_request_cancelled"))
        ));
        state.queue_pending_cancellations("node-a").unwrap();
        assert!(state.pending_node_events.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_cancel_after_lost_reply_uses_original_signed_event() {
        let (directory, mut state, peer, request) = retry_fixture("retry-cancel-after");
        let first = state.process_workload(&peer, &request).unwrap();
        let event_key = std::str::from_utf8(&first)
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .to_owned();
        let mut cancel = request.clone();
        cancel.operation = "cancel-key:retry_0123456789abcdef".into();
        assert_eq!(
            state.process_workload(&peer, &cancel).unwrap(),
            b"OK operation_cancel requested\n"
        );
        assert_eq!(state.process_workload(&peer, &request).unwrap(), first);
        let cancellations = state
            .pending_node_events
            .iter()
            .filter(|e| e.kind == "operation_cancel")
            .collect::<Vec<_>>();
        assert_eq!(cancellations.len(), 1);
        assert_eq!(
            cancellations[0]
                .body
                .get("request_event_key")
                .and_then(Value::as_str),
            Some(event_key.as_str())
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_actual_unix_lost_reply_reconnect_keeps_one_request() {
        use std::io::{Read, Write};
        let (directory, state, peer, request) = retry_fixture("retry-lost-wire");
        let socket = directory.join("retry.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let state = Arc::new(Mutex::new(state));
        let server_state = state.clone();
        let worker = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let identity = peer.clone();
                let _ = super::handle_workload_connection_as(
                    &mut stream,
                    &server_state,
                    std::time::Instant::now() + Duration::from_secs(2),
                    move |_, _| Ok(identity.clone()),
                );
            }
        });
        let frame = format!(
            "WORK {} {} {} {} {}\n",
            request.node_id,
            request.workload_id,
            request.claimed_unit,
            request.claimed_invocation_id,
            request.operation
        );
        let mut lost = UnixStream::connect(&socket).unwrap();
        lost.write_all(frame.as_bytes()).unwrap();
        drop(lost);
        let mut retry = UnixStream::connect(&socket).unwrap();
        retry
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        retry.write_all(frame.as_bytes()).unwrap();
        retry.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        retry.read_to_string(&mut reply).unwrap();
        worker.join().unwrap();
        assert!(reply.starts_with("OK operation_request event_"));
        let state = state.lock().unwrap();
        assert_eq!(state.pending_node_events.len(), 1);
        assert_eq!(state.operation_requests.values.len(), 1);
        assert!(!reply.contains("P05-SOURCE-CANARY"));
        assert!(!reply.contains("127.0.0.1"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_precancel_write_failure_keeps_stop_and_durable_retry() {
        let (directory, mut state, peer, request) = retry_fixture("retry-cancel-write");
        let path = state.pending_node_events_path.clone().unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let mut cancel = request.clone();
        cancel.operation = "cancel-key:retry_0123456789abcdef".into();
        assert!(state.process_workload(&peer, &cancel).is_err());
        assert!(state.persistence_fenced());
        assert!(matches!(
            state.process_workload(&peer, &request),
            Err(BrokerError::Configuration("operation_request_cancelled"))
        ));
        assert!(state.pending_node_events.is_empty());
        fs::remove_dir(&path).unwrap();
        assert_eq!(
            state.process_workload(&peer, &cancel).unwrap(),
            b"OK operation_cancel requested\n"
        );
        let (_, _, _, owners, _) = super::read_pending_node_events(&path).unwrap();
        assert_eq!(owners.values.len(), 1);
        assert!(!state.persistence_fenced());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_recipe_change_denies_unused_grant_before_source_and_journal() {
        let (directory, mut state, grant, resource, mut journal) =
            browser_grant_fixture("retry-original-recipe");
        let (peer, request) = browser_peer_and_request(&grant);
        let original = super::canonicalize_value(&resource.to_value()).unwrap();
        let path = state.pending_node_events_path.clone().unwrap();
        state.persist_pending_node_events().unwrap();
        let (_, _, _, owners, closures) = super::read_pending_node_events(&path).unwrap();
        state.operation_requests = owners;
        state.operation_closures = closures;
        for (from, to) in [
            ("4443", "4444"),
            ("\"primary\"", "\"isolation\""),
            ("primary-password", "other-password"),
        ] {
            let changed = String::from_utf8(original.clone())
                .unwrap()
                .replace(from, to);
            let resource_changed =
                super::BrowserResource::from_value(&super::parse_json(&changed).unwrap()).unwrap();
            assert_ne!(
                resource.recipe_fingerprint().unwrap(),
                resource_changed.recipe_fingerprint().unwrap()
            );
            let bytes = super::canonicalize_value(&Value::Object(vec![
                ("version".into(), Value::Unsigned(1)),
                (
                    "resources".into(),
                    Value::Array(vec![resource_changed.to_value()]),
                ),
            ]))
            .unwrap();
            state.browser_catalog =
                Some(super::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap());
            assert!(state.authorize_browser_grant(&grant).is_err());
            assert!(matches!(
                state.prepare_browser_login(&peer, &request, &resource_changed, &mut journal),
                Err(BrokerError::Configuration(
                    "browser_request_binding_unavailable"
                ))
            ));
            assert!(journal.pending().is_empty());
            assert!(state.pending_node_events.is_empty());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_snapshot_rejects_invalid_binding_and_duplicate_scoped_keys() {
        fn set(value: &mut Value, key: &str, new: Value) {
            let Value::Object(fields) = value else {
                panic!("object fixture")
            };
            fields.iter_mut().find(|(name, _)| name == key).unwrap().1 = new;
        }
        let (directory, mut state, peer, request) = retry_fixture("retry-snapshot");
        state.process_workload(&peer, &request).unwrap();
        let bytes = fs::read(state.pending_node_events_path.as_ref().unwrap()).unwrap();
        let header =
            super::parse_json(std::str::from_utf8(&bytes).unwrap().lines().next().unwrap())
                .unwrap();
        assert!(super::read_operation_records(&header, 5).is_ok());
        let owner = header.get("operation_owners").unwrap().as_array().unwrap()[0].clone();
        for (field, new) in [
            ("fingerprint", Value::String("f".repeat(65))),
            ("request_key", Value::String("short".into())),
            ("resource_id", Value::Null),
        ] {
            let mut bad = owner.clone();
            let mut binding = bad.get("browser_request").unwrap().clone();
            set(&mut binding, field, new);
            set(&mut bad, "browser_request", binding);
            let mut candidate = header.clone();
            set(&mut candidate, "operation_owners", Value::Array(vec![bad]));
            assert!(super::read_operation_records(&candidate, 5).is_err());
        }
        let mut duplicate = owner.clone();
        set(
            &mut duplicate,
            "event_key",
            Value::String("event_duplicated_retry_012345".into()),
        );
        let mut candidate = header;
        set(
            &mut candidate,
            "operation_owners",
            Value::Array(vec![owner, duplicate]),
        );
        assert!(super::read_operation_records(&candidate, 5).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_precancel_handles_queue_clock_capacity_and_owner_denial() {
        let (directory, mut state, peer, request) = retry_fixture("retry-cancel-boundaries");
        state.grant_verifier = super::grants::GrantVerifier::default();
        for index in 0..super::MAX_BROKER_AUDIT_EVENTS {
            state
                .pending_node_events
                .push_back(super::PendingNodeEvent {
                    idempotency_key: format!("event_pressure_{index:08}"),
                    kind: "audit".into(),
                    body: Value::Object(vec![("event".into(), Value::String("dummy".into()))]),
                });
        }
        let mut cancel = request.clone();
        cancel.operation = "cancel-key:retry_0123456789abcdef".into();
        assert_eq!(
            state.process_workload(&peer, &cancel).unwrap(),
            b"OK operation_cancel requested\n"
        );
        assert_eq!(
            state.pending_node_events.len(),
            super::MAX_BROKER_AUDIT_EVENTS
        );
        cancel.claimed_invocation_id = "b".repeat(32);
        let changed = PeerIdentity::fixture(
            1001,
            1001,
            "agent.service",
            &cancel.claimed_invocation_id,
            "uid:1001",
        );
        assert!(matches!(
            state.process_workload(&changed, &cancel),
            Err(BrokerError::Configuration("operation_request_denied"))
        ));
        cancel.claimed_invocation_id = request.claimed_invocation_id.clone();
        for index in 1..super::MAX_OPERATION_RECORDS {
            state.remember_operation_request(
                &format!("event_owner_{index:08}"),
                "other-workload",
                &request.claimed_invocation_id,
            );
        }
        cancel.operation = "cancel-key:retry_other_0123456789".into();
        assert!(matches!(
            state.process_workload(&peer, &cancel),
            Err(BrokerError::Configuration("operation_record_capacity"))
        ));
        assert_eq!(
            state.operation_requests.values.len(),
            super::MAX_OPERATION_RECORDS
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_failed_admission_does_not_advertise_or_relay_intent() {
        let (directory, mut state, peer, request) = retry_fixture("retry-admission-write");
        let path = state.pending_node_events_path.clone().unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(state.process_workload(&peer, &request).is_err());
        assert!(state.persistence_fenced());
        assert!(state.pending_node_events.is_empty());
        assert!(state.operation_requests.values.is_empty());
        assert!(matches!(
            state.process_workload(&peer, &request),
            Err(BrokerError::Configuration("broker_persistence_fenced"))
        ));
        fs::remove_dir(&path).unwrap();
        state.persist_pending_node_events().unwrap();
        assert!(
            state
                .process_workload(&peer, &request)
                .unwrap()
                .starts_with(b"OK operation_request ")
        );
        assert_eq!(state.pending_node_events.len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_retry_changed_catalog_conflicts_without_new_event() {
        let (directory, mut state, peer, request) = retry_fixture("retry-catalog-conflict");
        state.process_workload(&peer, &request).unwrap();
        let resource = state
            .browser_catalog
            .as_ref()
            .unwrap()
            .select("workload-a", "report-primary")
            .unwrap();
        let changed = String::from_utf8(super::canonicalize_value(&resource.to_value()).unwrap())
            .unwrap()
            .replace("primary-password", "other-password");
        let entry = super::parse_json(&changed).unwrap();
        let bytes = super::canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![entry])),
        ]))
        .unwrap();
        state.browser_catalog =
            Some(super::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap());
        assert!(matches!(
            state.process_workload(&peer, &request),
            Err(BrokerError::Configuration("operation_request_conflict"))
        ));
        assert_eq!(state.pending_node_events.len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    fn unique_test_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("blindpass-{label}-{}-{nanos}", std::process::id()))
    }
}
