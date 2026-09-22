// SPDX-License-Identifier: AGPL-3.0-only

//! Privileged local broker transport.
//!
//! The loader and workload sockets intentionally share no listener and no
//! authorization path. The loader requires a root peer plus a pidfd-resolved
//! system unit/invocation. The workload socket requires a registered
//! non-root unit/account/invocation tuple.

pub mod os_identity;

use blindpass_core::delivery::{CredentialRegistry, DeliveryError, DeliveryPolicy};
use blindpass_core::identity::{
    IdentityError, LoaderPolicy, PeerIdentity, WorkloadRegistration, authorize_workload,
};
use blindpass_core::protocol::{
    ProtocolError, error_frame, parse_loader_request, parse_workload_request, workload_ok,
};
use blindpass_core::secret::SecretBytes;
use blindpass_core::{MAX_CREDENTIAL_BYTES, MAX_FRAME_BYTES};
use os_identity::{OsIdentityError, resolve_peer};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug)]
pub enum BrokerError {
    Io(io::Error),
    Identity(IdentityError),
    Protocol(ProtocolError),
    OsIdentity(OsIdentityError),
    Delivery(DeliveryError),
    Configuration(&'static str),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io:{error}"),
            Self::Identity(error) => write!(formatter, "identity:{error}"),
            Self::Protocol(error) => write!(formatter, "protocol:{error}"),
            Self::OsIdentity(error) => write!(formatter, "os_identity:{error}"),
            Self::Delivery(error) => write!(formatter, "delivery:{error}"),
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

#[derive(Debug)]
pub struct BrokerState {
    pub loader_policy: LoaderPolicy,
    pub workloads: Vec<WorkloadRegistration>,
    pub credentials: CredentialRegistry,
}

impl BrokerState {
    #[must_use]
    pub fn new(delivery_policy: DeliveryPolicy) -> Self {
        Self {
            loader_policy: LoaderPolicy::new(),
            workloads: Vec::new(),
            credentials: CredentialRegistry::new(delivery_policy),
        }
    }

    pub fn process_loader(
        &self,
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
        Ok(SecretBytes::from_slice(
            self.credentials.get(&authorization.credential_name)?,
        ))
    }

    pub fn process_workload(
        &self,
        peer: &PeerIdentity,
        request: &blindpass_core::identity::WorkloadRequest,
    ) -> Result<Vec<u8>, BrokerError> {
        authorize_workload(peer, request, &self.workloads)?;
        Ok(workload_ok(request))
    }
}

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub loader_socket: PathBuf,
    pub workload_socket: PathBuf,
    pub socket_directory_mode: u32,
    pub loader_socket_mode: u32,
    pub workload_socket_mode: u32,
    pub read_timeout: Duration,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            loader_socket: PathBuf::from("/run/blindpass/loader.sock"),
            workload_socket: PathBuf::from("/run/blindpass/workload.sock"),
            socket_directory_mode: 0o750,
            loader_socket_mode: 0o600,
            workload_socket_mode: 0o660,
            read_timeout: Duration::from_secs(2),
        }
    }
}

pub fn run(config: BrokerConfig, state: BrokerState) -> Result<(), BrokerError> {
    if effective_uid() != 0 {
        return Err(BrokerError::Configuration(
            "blindpass-broker must run as root",
        ));
    }
    if config.socket_directory_mode != 0o750
        || config.loader_socket_mode != 0o600
        || config.workload_socket_mode != 0o660
    {
        return Err(BrokerError::Configuration(
            "broker socket modes must be directory 0750, loader 0600 and workload 0660",
        ));
    }
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
    let shared = Arc::new(Mutex::new(state));
    let loader_shared = Arc::clone(&shared);
    let loader_timeout = config.read_timeout;
    let loader_thread = std::thread::Builder::new()
        .name("blindpass-loader".to_owned())
        .spawn(move || serve_loader(loader_listener, loader_shared, loader_timeout))
        .map_err(BrokerError::Io)?;
    let workload_shared = Arc::clone(&shared);
    let workload_timeout = config.read_timeout;
    let workload_thread = std::thread::Builder::new()
        .name("blindpass-workload".to_owned())
        .spawn(move || serve_workload(workload_listener, workload_shared, workload_timeout))
        .map_err(BrokerError::Io)?;
    loader_thread
        .join()
        .map_err(|_| BrokerError::Configuration("loader thread panicked"))??;
    workload_thread
        .join()
        .map_err(|_| BrokerError::Configuration("workload thread panicked"))??;
    Ok(())
}

fn serve_loader(
    listener: UnixListener,
    state: Arc<Mutex<BrokerState>>,
    timeout: Duration,
) -> Result<(), BrokerError> {
    for connection in listener.incoming() {
        let mut stream = connection?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let result = handle_loader_connection(&mut stream, &state);
        if let Err(error) = result {
            write_error(&mut stream, &error);
        }
    }
    Ok(())
}

fn serve_workload(
    listener: UnixListener,
    state: Arc<Mutex<BrokerState>>,
    timeout: Duration,
) -> Result<(), BrokerError> {
    for connection in listener.incoming() {
        let mut stream = connection?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let result = handle_workload_connection(&mut stream, &state);
        if let Err(error) = result {
            write_error(&mut stream, &error);
        }
    }
    Ok(())
}

fn handle_loader_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<BrokerState>>,
) -> Result<(), BrokerError> {
    let peer = resolve_peer(stream)?;
    let frame = read_frame(stream)?;
    let request = parse_loader_request(&frame)?;
    let credential = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .process_loader(&peer, &request.claimed_unit, &request.credential_name)?;
    stream.write_all(credential.as_bytes())?;
    Ok(())
}

fn handle_workload_connection(
    stream: &mut UnixStream,
    state: &Arc<Mutex<BrokerState>>,
) -> Result<(), BrokerError> {
    let peer = resolve_peer(stream)?;
    let frame = read_frame(stream)?;
    let request = parse_workload_request(&frame)?;
    let response = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker state poisoned"))?
        .process_workload(&peer, &request)?;
    stream.write_all(&response)?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, BrokerError> {
    let mut frame = Vec::with_capacity(128);
    let mut byte = [0; 1];
    loop {
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
}

pub fn bind_socket(
    path: &Path,
    directory_mode: u32,
    socket_mode: u32,
) -> Result<UnixListener, BrokerError> {
    let parent = path
        .parent()
        .ok_or(BrokerError::Configuration("socket path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(directory_mode))?;
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

pub fn load_protected_credential(path: &Path) -> Result<SecretBytes, BrokerError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_BYTES as u64
    {
        return Err(BrokerError::Configuration(
            "credential file must be a non-empty root-owned mode-0600 regular file within the size limit",
        ));
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(BrokerError::Configuration(
            "credential file is empty or exceeds the maximum size",
        ));
    }
    Ok(SecretBytes::new(bytes))
}

fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(test)]
mod tests {
    use super::{BrokerState, bind_socket, read_frame};
    use blindpass_core::delivery::{CredentialFormat, DeliveryPolicy};
    use blindpass_core::identity::{PeerIdentity, WorkloadRegistration, WorkloadRequest};
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn state_keeps_loader_and_workload_authorities_separate() {
        let mut state = BrokerState::new(DeliveryPolicy {
            max_bytes: 1024,
            deadline: Duration::from_secs(1),
            format: CredentialFormat::Utf8,
        });
        state
            .loader_policy
            .map_unit("backup.service", "api-key")
            .unwrap();
        state.credentials.insert("api-key", b"P01-CANARY").unwrap();
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
            invocation_id: "inv-a".to_owned(),
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
        let stall = read_frame(&mut reader).unwrap_err();
        assert!(
            matches!(stall, super::BrokerError::Io(error) if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock))
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"LOAD unit credential\n").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(read_frame(&mut reader).unwrap(), b"LOAD unit credential\n");

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"LOAD unit credential\ntrailing").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let error = read_frame(&mut reader).unwrap_err();
        assert!(error.to_string().contains("invalid_frame"));

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&vec![b'x'; blindpass_core::MAX_FRAME_BYTES + 1])
            .unwrap();
        let error = read_frame(&mut reader).unwrap_err();
        assert!(error.to_string().contains("frame_too_large"));
    }

    fn unique_test_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("blindpass-{label}-{}-{nanos}", std::process::id()))
    }
}
