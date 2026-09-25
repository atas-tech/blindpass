// SPDX-License-Identifier: AGPL-3.0-only

//! Privileged local broker transport.
//!
//! The loader and workload sockets intentionally share no listener and no
//! authorization path. The loader requires a root peer plus a pidfd-resolved
//! system unit/invocation. The workload socket requires a registered
//! non-root unit/account/invocation tuple.

mod control;
mod keys;
pub mod os_identity;

use blindpass_core::custody::{CryptoError, EphemeralCustody};
use blindpass_core::delivery::{CredentialRegistry, DeliveryError, DeliveryPolicy};
use blindpass_core::fleet::{PolicySnapshot, Registration};
use blindpass_core::identity::{
    IdentityError, LoaderPolicy, PeerIdentity, WorkloadRegistration, authorize_workload,
};
use blindpass_core::protocol::{
    ProtocolError, error_frame, parse_loader_request, parse_workload_request, workload_ok,
};
use blindpass_core::secret::SecretBytes;
use blindpass_core::{MAX_CREDENTIAL_BYTES, MAX_FRAME_BYTES};
use os_identity::{OsIdentityError, require_root_peer, resolve_peer};
use std::collections::BTreeMap;
use std::ffi::{CString, c_char};
use std::fs;
use std::io::{self, Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt, chown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_ACTIVE_CONNECTIONS: usize = 32;
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
    pub credentials: CredentialRegistry,
    pub custody: EphemeralCustody,
    credential_expiries: BTreeMap<String, Instant>,
    credential_lifetime: Duration,
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
        &self,
        peer: &PeerIdentity,
        request: &blindpass_core::identity::WorkloadRequest,
    ) -> Result<Vec<u8>, BrokerError> {
        authorize_workload(peer, request, &self.workloads)?;
        Ok(workload_ok(request))
    }

    pub(crate) fn validate_fleet_registration(
        &self,
        registration: &Registration,
    ) -> Result<bool, BrokerError> {
        if let Some(previous) = self.fleet_registrations.get(&registration.workload_id) {
            if registration.registration_version < previous.registration_version {
                return Err(BrokerError::Configuration("stale workload registration"));
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
                return Err(BrokerError::Configuration("stale fleet policy"));
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
        self.fleet_policy = Some(policy);
        Ok(true)
    }
}

pub fn provision_aad(unit: &str, credential: &str) -> String {
    format!("blindpass:p01:{unit}:{credential}")
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
    use super::{
        BrokerConfig, BrokerError, BrokerState, DeliveryFault, authorize_systemd_credential_peer,
        bind_socket, handle_systemd_credential_connection, parse_systemd_credential_route,
        read_frame, reject_connection, spawn_listener_thread, validate_config,
    };
    use blindpass_core::custody::RecipientKeyPair;
    use blindpass_core::delivery::{CredentialFormat, DeliveryPolicy};
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
