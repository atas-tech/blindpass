// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::identity::PeerIdentity;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::net::UnixStream;

const SOL_SOCKET: c_int = 1;
const SO_PEERCRED: c_int = 17;
const SO_PEERPIDFD: c_int = 77;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsIdentityError {
    UnsupportedHost(&'static str),
    PermissionDenied(&'static str),
    LookupFailed(&'static str),
    System(io::ErrorKind),
}

impl OsIdentityError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedHost(_) => "unsupported_host",
            Self::PermissionDenied(_) => "permission_denied",
            Self::LookupFailed(_) => "identity_lookup_failed",
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
            Self::System(kind) => write!(formatter, "identity_system_error:{kind:?}"),
        }
    }
}

impl std::error::Error for OsIdentityError {}

#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_pidfd_get_unit(pidfd: c_int, ret_unit: *mut *mut c_char) -> c_int;
    fn sd_bus_open_system(ret: *mut *mut sd_bus) -> c_int;
    fn sd_bus_unref(bus: *mut sd_bus) -> *mut sd_bus;
    fn sd_bus_call_method(
        bus: *mut sd_bus,
        destination: *const c_char,
        path: *const c_char,
        interface: *const c_char,
        member: *const c_char,
        error: *mut c_void,
        reply: *mut *mut sd_bus_message,
        types: *const c_char,
        ...
    ) -> c_int;
    fn sd_bus_message_unref(message: *mut sd_bus_message) -> *mut sd_bus_message;
    fn sd_bus_message_read(message: *mut sd_bus_message, types: *const c_char, ...) -> c_int;
    fn sd_bus_get_property_string(
        bus: *mut sd_bus,
        destination: *const c_char,
        path: *const c_char,
        interface: *const c_char,
        member: *const c_char,
        error: *mut c_void,
        ret_value: *mut *mut c_char,
    ) -> c_int;
    fn free(pointer: *mut c_void);
}

pub fn resolve_peer(stream: &UnixStream) -> Result<PeerIdentity, OsIdentityError> {
    let credentials = peer_credentials(stream.as_raw_fd())?;
    let pidfd = peer_pidfd(stream.as_raw_fd())?;
    let (unit, invocation_id) = resolve_unit_and_invocation(pidfd.as_raw_fd())?;
    Ok(PeerIdentity {
        uid: credentials.uid,
        gid: credentials.gid,
        pidfd_supported: true,
        unit: Some(unit),
        invocation_id: Some(invocation_id),
        account: Some(format!("uid:{}", credentials.uid)),
    })
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
        return Err(OsIdentityError::System(io::Error::last_os_error().kind()));
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

fn resolve_unit_and_invocation(pidfd: RawFd) -> Result<(String, String), OsIdentityError> {
    let mut unit_pointer = std::ptr::null_mut();
    let result = unsafe { sd_pidfd_get_unit(pidfd, &mut unit_pointer) };
    if result < 0 || unit_pointer.is_null() {
        return Err(OsIdentityError::LookupFailed("sd_pidfd_get_unit"));
    }
    let unit = unsafe { CStr::from_ptr(unit_pointer) }.to_bytes().to_vec();
    unsafe { free(unit_pointer.cast::<c_void>()) };
    let unit =
        String::from_utf8(unit).map_err(|_| OsIdentityError::LookupFailed("unit is not utf8"))?;
    let invocation_id = resolve_invocation_id(pidfd)?;
    Ok((unit, invocation_id))
}

fn resolve_invocation_id(pidfd: RawFd) -> Result<String, OsIdentityError> {
    let mut bus = std::ptr::null_mut();
    if unsafe { sd_bus_open_system(&mut bus) } < 0 || bus.is_null() {
        return Err(OsIdentityError::UnsupportedHost("system bus unavailable"));
    }
    let result = resolve_invocation_id_on_bus(bus, pidfd);
    unsafe { sd_bus_unref(bus) };
    result
}

fn resolve_invocation_id_on_bus(bus: *mut sd_bus, pidfd: RawFd) -> Result<String, OsIdentityError> {
    let destination = CString::new("org.freedesktop.systemd1").unwrap();
    let manager_path = CString::new("/org/freedesktop/systemd1").unwrap();
    let manager_interface = CString::new("org.freedesktop.systemd1.Manager").unwrap();
    let member = CString::new("GetUnitByPIDFD").unwrap();
    let types = CString::new("h").unwrap();
    let mut reply = std::ptr::null_mut();
    let call_result = unsafe {
        sd_bus_call_method(
            bus,
            destination.as_ptr(),
            manager_path.as_ptr(),
            manager_interface.as_ptr(),
            member.as_ptr(),
            std::ptr::null_mut(),
            &mut reply,
            types.as_ptr(),
            pidfd,
        )
    };
    if call_result < 0 || reply.is_null() {
        return Err(OsIdentityError::UnsupportedHost(
            "systemd GetUnitByPIDFD unavailable",
        ));
    }
    let object_type = CString::new("o").unwrap();
    let mut object_path: *const c_char = std::ptr::null();
    let read_result = unsafe { sd_bus_message_read(reply, object_type.as_ptr(), &mut object_path) };
    if read_result <= 0 || object_path.is_null() {
        unsafe { sd_bus_message_unref(reply) };
        return Err(OsIdentityError::LookupFailed("unit object path"));
    }
    let object_path = unsafe { CStr::from_ptr(object_path) }.to_bytes().to_vec();
    unsafe { sd_bus_message_unref(reply) };
    let object_path = String::from_utf8(object_path)
        .map_err(|_| OsIdentityError::LookupFailed("unit object path is not utf8"))?;

    let service_interface = CString::new("org.freedesktop.systemd1.Service").unwrap();
    let property = CString::new("InvocationID").unwrap();
    let object_path =
        CString::new(object_path).map_err(|_| OsIdentityError::LookupFailed("unit path"))?;
    let mut invocation = std::ptr::null_mut();
    let property_result = unsafe {
        sd_bus_get_property_string(
            bus,
            destination.as_ptr(),
            object_path.as_ptr(),
            service_interface.as_ptr(),
            property.as_ptr(),
            std::ptr::null_mut(),
            &mut invocation,
        )
    };
    if property_result < 0 || invocation.is_null() {
        return Err(OsIdentityError::UnsupportedHost(
            "systemd invocation lookup unavailable",
        ));
    }
    let invocation_text = unsafe { CStr::from_ptr(invocation) }.to_bytes().to_vec();
    unsafe { free(invocation.cast::<c_void>()) };
    let invocation_text = String::from_utf8(invocation_text)
        .map_err(|_| OsIdentityError::LookupFailed("invocation is not utf8"))?;
    if invocation_text.is_empty() {
        return Err(OsIdentityError::LookupFailed("empty invocation id"));
    }
    Ok(invocation_text)
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
