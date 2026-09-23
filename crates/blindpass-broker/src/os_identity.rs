// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::identity::PeerIdentity;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const SOL_SOCKET: c_int = 1;
const SO_PEERCRED: c_int = 17;
const SO_PEERPIDFD: c_int = 77;
const POLLIN: i16 = 0x0001;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

#[repr(C)]
struct Ucred {
    // ABI field required by struct ucred; the broker never reads raw PIDs.
    _pid: c_int,
    uid: u32,
    gid: u32,
}

#[allow(non_camel_case_types)]
type sd_bus = c_void;
#[allow(non_camel_case_types)]
type sd_bus_message = c_void;

#[repr(C)]
struct SdBusError {
    name: *const c_char,
    message: *const c_char,
    need_free: c_int,
}

unsafe extern "C" {
    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsIdentityError {
    UnsupportedHost(&'static str),
    PermissionDenied(&'static str),
    LookupFailed(&'static str),
    PeerExited { unit: String, invocation_id: String },
    PeerExitedBeforeLookup,
    System(io::ErrorKind),
}

impl OsIdentityError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedHost(_) => "unsupported_host",
            Self::PermissionDenied(_) => "permission_denied",
            Self::LookupFailed(_) => "identity_lookup_failed",
            Self::PeerExited { .. } => "peer_exited",
            Self::PeerExitedBeforeLookup => "peer_exited",
            Self::System(_) => "identity_system_error",
        }
    }
}

impl fmt::Display for OsIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost(reason) => write!(formatter, "unsupported_host:{reason}"),
            Self::PermissionDenied(reason) => write!(formatter, "permission_denied:{reason}"),
            Self::LookupFailed(reason) => write!(formatter, "identity_lookup_failed:{reason}"),
            Self::PeerExited {
                unit,
                invocation_id,
            } => {
                write!(
                    formatter,
                    "peer_exited unit={unit} invocation={invocation_id}"
                )
            }
            Self::PeerExitedBeforeLookup => write!(formatter, "peer_exited before unit lookup"),
            Self::System(kind) => write!(formatter, "identity_system_error:{kind:?}"),
        }
    }
}

impl std::error::Error for OsIdentityError {}

#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_bus_open_system(ret: *mut *mut sd_bus) -> c_int;
    fn sd_bus_unref(bus: *mut sd_bus) -> *mut sd_bus;
    fn sd_bus_set_method_call_timeout(bus: *mut sd_bus, usec: u64) -> c_int;
    fn sd_bus_call_method(
        bus: *mut sd_bus,
        destination: *const c_char,
        path: *const c_char,
        interface: *const c_char,
        member: *const c_char,
        error: *mut SdBusError,
        reply: *mut *mut sd_bus_message,
        types: *const c_char,
        ...
    ) -> c_int;
    fn sd_bus_message_unref(message: *mut sd_bus_message) -> *mut sd_bus_message;
    fn sd_bus_error_free(error: *mut SdBusError) -> *mut SdBusError;
    fn sd_bus_message_read(message: *mut sd_bus_message, types: *const c_char, ...) -> c_int;
    fn sd_bus_message_read_array(
        message: *mut sd_bus_message,
        element_type: c_char,
        data: *mut *const c_void,
        length: *mut usize,
    ) -> c_int;
}

pub fn resolve_peer(
    stream: &UnixStream,
    deadline: Instant,
    identity_lookup_delay: Duration,
) -> Result<PeerIdentity, OsIdentityError> {
    let credentials = peer_credentials(stream.as_raw_fd())?;
    let pidfd = peer_pidfd(stream.as_raw_fd())?;
    if !identity_lookup_delay.is_zero() {
        eprintln!("identity lookup test delay after pidfd capture");
        std::thread::sleep(identity_lookup_delay);
    }
    let (unit, invocation_id) = resolve_unit_and_invocation(pidfd.as_raw_fd(), deadline)?;
    ensure_peer_alive(pidfd.as_raw_fd(), &unit, &invocation_id)?;
    Ok(PeerIdentity {
        uid: credentials.uid,
        gid: credentials.gid,
        pidfd_supported: true,
        unit: Some(unit),
        invocation_id: Some(invocation_id),
        account: Some(format!("uid:{}", credentials.uid)),
    })
}

fn ensure_peer_alive(pidfd: RawFd, unit: &str, invocation_id: &str) -> Result<(), OsIdentityError> {
    let mut descriptor = PollFd {
        fd: pidfd,
        events: POLLIN,
        revents: 0,
    };
    let result = unsafe { poll(&mut descriptor, 1, 0) };
    if result < 0 {
        return Err(OsIdentityError::System(io::Error::last_os_error().kind()));
    }
    if result > 0 && descriptor.revents & POLLIN != 0 {
        return Err(OsIdentityError::PeerExited {
            unit: unit.to_owned(),
            invocation_id: invocation_id.to_owned(),
        });
    }
    Ok(())
}

/// Provisioning is a local root administration operation, independent of a
/// systemd workload identity. The protected socket is checked again here.
pub fn require_root_peer(stream: &UnixStream) -> Result<(), OsIdentityError> {
    if peer_credentials(stream.as_raw_fd())?.uid != 0 {
        return Err(OsIdentityError::PermissionDenied(
            "provisioning requires uid 0",
        ));
    }
    Ok(())
}

fn peer_credentials(fd: RawFd) -> Result<Ucred, OsIdentityError> {
    let mut credentials = Ucred {
        _pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<Ucred>() as u32;
    let result = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credentials as *mut Ucred).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(92 | 38)) {
            Err(OsIdentityError::UnsupportedHost("SO_PEERCRED unavailable"))
        } else {
            Err(OsIdentityError::System(error.kind()))
        };
    }
    Ok(credentials)
}

fn peer_pidfd(fd: RawFd) -> Result<OwnedFd, OsIdentityError> {
    let mut pidfd: RawFd = -1;
    let mut length = std::mem::size_of::<RawFd>() as u32;
    let result = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut pidfd as *mut RawFd).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 || pidfd < 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(22 | 92 | 38)) {
            Err(OsIdentityError::UnsupportedHost("SO_PEERPIDFD unavailable"))
        } else {
            Err(OsIdentityError::System(error.kind()))
        };
    }
    // SAFETY: the kernel returned a new owned descriptor through SO_PEERPIDFD.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}

fn resolve_unit_and_invocation(
    pidfd: RawFd,
    deadline: Instant,
) -> Result<(String, String), OsIdentityError> {
    remaining(deadline)?;
    let mut bus = std::ptr::null_mut();
    if unsafe { sd_bus_open_system(&mut bus) } < 0 || bus.is_null() {
        return Err(OsIdentityError::UnsupportedHost("system bus unavailable"));
    }
    let result = resolve_unit_and_invocation_on_bus(bus, pidfd, deadline);
    unsafe { sd_bus_unref(bus) };
    result
}

fn resolve_unit_and_invocation_on_bus(
    bus: *mut sd_bus,
    pidfd: RawFd,
    deadline: Instant,
) -> Result<(String, String), OsIdentityError> {
    let timeout = remaining(deadline)?;
    let timeout_usec = u64::try_from(timeout.as_micros())
        .ok()
        .filter(|usec| *usec > 0)
        .ok_or(OsIdentityError::UnsupportedHost(
            "identity lookup deadline elapsed",
        ))?;
    if unsafe { sd_bus_set_method_call_timeout(bus, timeout_usec) } < 0 {
        return Err(OsIdentityError::UnsupportedHost(
            "system bus timeout configuration unavailable",
        ));
    }

    let destination = CString::new("org.freedesktop.systemd1").unwrap();
    let manager_path = CString::new("/org/freedesktop/systemd1").unwrap();
    let manager_interface = CString::new("org.freedesktop.systemd1.Manager").unwrap();
    let member = CString::new("GetUnitByPIDFD").unwrap();
    let types = CString::new("h").unwrap();
    let mut reply = std::ptr::null_mut();
    let mut bus_error = SdBusError {
        name: std::ptr::null(),
        message: std::ptr::null(),
        need_free: 0,
    };
    let call_result = unsafe {
        sd_bus_call_method(
            bus,
            destination.as_ptr(),
            manager_path.as_ptr(),
            manager_interface.as_ptr(),
            member.as_ptr(),
            &mut bus_error,
            &mut reply,
            types.as_ptr(),
            pidfd,
        )
    };
    let error_name = if bus_error.name.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(bus_error.name) }
                .to_bytes()
                .to_vec(),
        )
    };
    unsafe { sd_bus_error_free(&mut bus_error) };
    if Instant::now() >= deadline {
        if !reply.is_null() {
            unsafe { sd_bus_message_unref(reply) };
        }
        return Err(OsIdentityError::System(io::ErrorKind::TimedOut));
    }
    if call_result < 0 || reply.is_null() {
        if !reply.is_null() {
            unsafe { sd_bus_message_unref(reply) };
        }
        if call_result == -110 {
            return Err(OsIdentityError::System(io::ErrorKind::TimedOut));
        }
        return Err(classify_unit_lookup_error(
            call_result,
            error_name.as_deref(),
        ));
    }
    let object_and_unit_types = CString::new("os").unwrap();
    let mut object_path: *const c_char = std::ptr::null();
    let mut unit_id: *const c_char = std::ptr::null();
    let read_result = unsafe {
        sd_bus_message_read(
            reply,
            object_and_unit_types.as_ptr(),
            &mut object_path,
            &mut unit_id,
        )
    };
    if read_result <= 0 || object_path.is_null() || unit_id.is_null() {
        unsafe { sd_bus_message_unref(reply) };
        return Err(OsIdentityError::LookupFailed("unit identity reply"));
    }
    // The manager returns the unit path, unit name, and InvocationID in the
    // same pidfd-bound reply. Keep that identity atomic; a second property
    // request could observe a replacement invocation.
    let unit = unsafe { CStr::from_ptr(unit_id) }.to_bytes().to_vec();
    let mut invocation_data: *const c_void = std::ptr::null();
    let mut invocation_length = 0;
    let read_result = unsafe {
        sd_bus_message_read_array(
            reply,
            b'y' as c_char,
            &mut invocation_data,
            &mut invocation_length,
        )
    };
    if read_result <= 0 || invocation_data.is_null() {
        unsafe { sd_bus_message_unref(reply) };
        return Err(OsIdentityError::LookupFailed("invocation id array"));
    }
    // SAFETY: systemd owns these reply fields for the lifetime of the message.
    // Copy them before releasing it so no borrowed D-Bus state escapes.
    let invocation_bytes = unsafe {
        std::slice::from_raw_parts(invocation_data.cast::<u8>(), invocation_length).to_vec()
    };
    unsafe { sd_bus_message_unref(reply) };
    let unit = String::from_utf8(unit)
        .map_err(|_| OsIdentityError::LookupFailed("unit name is not utf8"))?;
    let invocation_id = format_invocation_id(&invocation_bytes)?;
    Ok((unit, invocation_id))
}

fn classify_unit_lookup_error(result: c_int, name: Option<&[u8]>) -> OsIdentityError {
    if result == -3
        || name.is_some_and(|name| {
            name.ends_with(b".NoUnitForPID") || name.ends_with(b".NoUnitForPIDFD")
        })
    {
        return OsIdentityError::PeerExitedBeforeLookup;
    }
    if name.is_some_and(|name| name == b"org.freedesktop.DBus.Error.UnknownMethod") {
        return OsIdentityError::UnsupportedHost("systemd GetUnitByPIDFD unavailable");
    }
    OsIdentityError::LookupFailed("systemd GetUnitByPIDFD call")
}

fn remaining(deadline: Instant) -> Result<Duration, OsIdentityError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(OsIdentityError::System(io::ErrorKind::TimedOut))
}

fn format_invocation_id(bytes: &[u8]) -> Result<String, OsIdentityError> {
    if bytes.len() != 16 {
        return Err(OsIdentityError::LookupFailed(
            "invalid invocation id length",
        ));
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

unsafe extern "C" {
    fn getsockopt(
        socket: c_int,
        level: c_int,
        option: c_int,
        value: *mut c_void,
        length: *mut u32,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::{OsIdentityError, classify_unit_lookup_error, format_invocation_id};

    #[test]
    fn unit_lookup_distinguishes_dead_peer_from_missing_api() {
        assert_eq!(
            classify_unit_lookup_error(-3, None),
            OsIdentityError::PeerExitedBeforeLookup
        );
        assert_eq!(
            classify_unit_lookup_error(-1, Some(b"org.freedesktop.systemd1.NoUnitForPIDFD")),
            OsIdentityError::PeerExitedBeforeLookup
        );
        assert_eq!(
            classify_unit_lookup_error(-1, Some(b"org.freedesktop.DBus.Error.UnknownMethod")),
            OsIdentityError::UnsupportedHost("systemd GetUnitByPIDFD unavailable")
        );
        assert_eq!(
            classify_unit_lookup_error(-1, None),
            OsIdentityError::LookupFailed("systemd GetUnitByPIDFD call")
        );
    }

    #[test]
    fn invocation_id_is_the_systemd_lowercase_hex_array() {
        let bytes: Vec<u8> = (0..16).collect();
        assert_eq!(
            format_invocation_id(&bytes).unwrap(),
            "000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(
            format_invocation_id(&bytes[..15]),
            Err(OsIdentityError::LookupFailed(
                "invalid invocation id length"
            ))
        );
    }
}
