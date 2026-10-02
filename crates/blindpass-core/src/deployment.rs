// SPDX-License-Identifier: AGPL-3.0-only

//! Linux deployment credential files. Directory descriptors anchor operations
//! across rename races; all path components are opened without following links.
//! No credentials are generated as a side effect of validation.

use crate::secret::SecretBytes;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

pub const KEY_NAMES: [&str; 3] = ["root-secret", "agent-jwt-secret", "issuer-key"];
pub const DEFAULT_KEYS_DIR: &str = "/etc/blindpass/keys";
pub const DEFAULT_DATA_DIR: &str = "/var/lib/blindpass/controller";

const O_DIRECTORY: i32 = 0x10000;
const O_NOFOLLOW: i32 = 0x20000;
const O_CLOEXEC: i32 = 0x80000;
const O_NONBLOCK: i32 = 0x800;
const O_WRONLY: i32 = 1;
const O_CREAT: i32 = 0x40;
const O_EXCL: i32 = 0x80;

unsafe extern "C" {
    fn openat(dirfd: i32, path: *const std::ffi::c_char, flags: i32, mode: u32) -> i32;
    fn mkdirat(dirfd: i32, path: *const std::ffi::c_char, mode: u32) -> i32;
    fn unlinkat(dirfd: i32, path: *const std::ffi::c_char, flags: i32) -> i32;
    fn geteuid() -> u32;
    fn flock(fd: i32, operation: i32) -> i32;
    fn fgetxattr(
        fd: i32,
        name: *const std::ffi::c_char,
        value: *mut std::ffi::c_void,
        size: usize,
    ) -> isize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsafeCredential;

/// A directory reached through an absolute path without symlink components.
pub struct Directory(File);

impl Directory {
    pub fn open(path: &Path) -> Result<Self, UnsafeCredential> {
        if !path.is_absolute() {
            return Err(UnsafeCredential);
        }
        let mut file = File::options()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            .open("/")
            .map_err(|_| UnsafeCredential)?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes()).map_err(|_| UnsafeCredential)?;
                    file = open_relative(&file, &name, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0)?;
                }
                _ => return Err(UnsafeCredential),
            }
        }
        Ok(Self(file))
    }

    /// Existing private directories are accepted but never chmodded/chowned.
    pub fn open_private(path: &Path) -> Result<Self, UnsafeCredential> {
        let directory = Self::open(path)?;
        directory.validate_private()?;
        Ok(directory)
    }

    pub fn create_private(path: &Path) -> Result<Self, UnsafeCredential> {
        let name = path.file_name().ok_or(UnsafeCredential)?;
        let parent = Self::open(path.parent().ok_or(UnsafeCredential)?)?;
        let name = CString::new(name.as_bytes()).map_err(|_| UnsafeCredential)?;
        // SAFETY: descriptor is live; name is a valid NUL-terminated string.
        let result = unsafe { mkdirat(parent.0.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(UnsafeCredential);
        }
        let directory = Self(open_relative(
            &parent.0,
            &name,
            O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )?);
        directory.validate_private()?;
        parent.sync()?;
        Ok(directory)
    }

    fn validate_private(&self) -> Result<(), UnsafeCredential> {
        let metadata = self.0.metadata().map_err(|_| UnsafeCredential)?;
        // SAFETY: geteuid has no arguments or memory effects.
        let uid = unsafe { geteuid() };
        if !metadata.is_dir()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.uid() != uid
        {
            return Err(UnsafeCredential);
        }
        Ok(())
    }

    /// Hold a nonblocking directory lock for the lifetime of this descriptor.
    pub fn lock(&self, exclusive: bool) -> Result<(), UnsafeCredential> {
        // SAFETY: descriptor is live and flock takes no pointers.
        if unsafe { flock(self.0.as_raw_fd(), if exclusive { 2 | 4 } else { 1 | 4 }) } != 0 {
            return Err(UnsafeCredential);
        }
        Ok(())
    }

    pub fn read(&self, name: &str, limit: usize) -> Result<SecretBytes, UnsafeCredential> {
        let name = member_name(name)?;
        let file = open_relative(&self.0, &name, O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0)?;
        read_private(file, limit)
    }

    fn create(&self, name: &str) -> Result<File, UnsafeCredential> {
        let name = member_name(name)?;
        open_relative(
            &self.0,
            &name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        )
    }

    fn remove(&self, name: &str) {
        if let Ok(name) = member_name(name) {
            // SAFETY: descriptor/name remain live for this call.
            unsafe { unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) };
        }
    }

    pub fn sync(&self) -> Result<(), UnsafeCredential> {
        self.0.sync_all().map_err(|_| UnsafeCredential)
    }
}

fn open_relative(
    parent: &File,
    name: &CString,
    flags: i32,
    mode: u32,
) -> Result<File, UnsafeCredential> {
    // SAFETY: parent descriptor is live, name is NUL-terminated. A successful
    // openat transfers exactly one owned descriptor to File.
    let descriptor = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        return Err(UnsafeCredential);
    }
    // SAFETY: descriptor is newly opened and exclusively owned here.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn member_name(name: &str) -> Result<CString, UnsafeCredential> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(UnsafeCredential);
    }
    CString::new(name).map_err(|_| UnsafeCredential)
}

fn read_private(file: File, limit: usize) -> Result<SecretBytes, UnsafeCredential> {
    let metadata = file.metadata().map_err(|_| UnsafeCredential)?;
    // SAFETY: geteuid takes no pointers.
    let uid = unsafe { geteuid() };
    let private_permissions = metadata.permissions().mode() & 0o7077 == 0;
    // systemd 255 uses a root-owned read-only file plus one named-user ACL.
    // Its mask appears as group-read in st_mode even though the owning group
    // has no access. Accept only this exact descriptor-checked ACL, never a
    // generic group-readable file or a grant to another user/group.
    let service_credential = if metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.permissions().mode() & 0o7777 == 0o440
        && uid != 0
    {
        let mut acl = [0u8; 44];
        // SAFETY: fd is live; the name is terminated and the writable buffer
        // is exactly the advertised size. Longer/unsupported ACLs fail closed.
        let length = unsafe {
            fgetxattr(
                file.as_raw_fd(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_mut_ptr().cast(),
                acl.len(),
            )
        };
        length == acl.len() as isize && private_service_acl(&acl, uid)
    } else {
        false
    };
    if !metadata.is_file()
        || !(private_permissions || service_credential)
        || metadata.nlink() != 1
        || (metadata.uid() != uid && metadata.uid() != 0)
        || metadata.len() > limit as u64
    {
        return Err(UnsafeCredential);
    }
    // Take a bounded read even if the file grows after fstat.
    let mut buffer = Vec::new();
    let result = file.take(limit as u64 + 1).read_to_end(&mut buffer);
    let bytes = SecretBytes::new(buffer);
    if result.is_err() || bytes.len() > limit {
        return Err(UnsafeCredential);
    }
    Ok(bytes)
}

pub fn read_private_file(path: &Path, limit: usize) -> Result<SecretBytes, UnsafeCredential> {
    let parent = Directory::open(path.parent().ok_or(UnsafeCredential)?)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(UnsafeCredential)?;
    parent.read(name, limit)
}

/// Create all three names exclusively before writing any key. Failed retries
/// cannot overwrite existing trust. A crash may leave an incomplete set; it
/// remains invalid and requires explicit operator recovery, never auto-fill.
pub fn initialize_keys(path: &Path) -> Result<(), UnsafeCredential> {
    let directory = Directory::create_private(path)?;
    directory.lock(true)?;
    let mut files = Vec::new();
    for name in KEY_NAMES {
        match directory.create(name) {
            Ok(file) => files.push((name, file)),
            Err(error) => {
                for (created, _) in &files {
                    directory.remove(created);
                }
                let _ = directory.sync();
                return Err(error);
            }
        }
    }
    let result = (|| {
        let mut random = File::open("/dev/urandom").map_err(|_| UnsafeCredential)?;
        for (_, file) in &mut files {
            let mut key = [0u8; 32];
            let result = random
                .read_exact(&mut key)
                .map_err(|_| UnsafeCredential)
                .and_then(|()| file.write_all(&key).map_err(|_| UnsafeCredential));
            crate::secret::wipe(&mut key);
            result?;
            file.sync_all().map_err(|_| UnsafeCredential)?;
        }
        directory.sync()
    })();
    if result.is_err() {
        for (name, _) in &files {
            directory.remove(name);
        }
        let _ = directory.sync();
    }
    result
}

pub fn check_keys(path: &Path) -> Result<(), UnsafeCredential> {
    let directory = Directory::open_private(path)?;
    directory.lock(false)?;
    for name in KEY_NAMES {
        let bytes = directory.read(name, 32)?;
        if bytes.len() != 32 {
            return Err(UnsafeCredential);
        }
    }
    Ok(())
}

fn private_service_acl(acl: &[u8], uid: u32) -> bool {
    // Linux POSIX ACL xattr ABI: version 2, followed by canonical 8-byte
    // little-endian entries. Compare one allowed representation, not a
    // permissive/general ACL parser. Base entries have an undefined ID.
    if acl.len() != 44 || uid == 0 || uid == u32::MAX || acl[..4] != 2u32.to_le_bytes() {
        return false;
    }
    let expected = [
        (1u16, 4u16, u32::MAX),
        (2, 4, uid),
        (4, 0, u32::MAX),
        (16, 4, u32::MAX),
        (32, 0, u32::MAX),
    ];
    acl[4..]
        .as_chunks::<8>()
        .0
        .iter()
        .zip(expected)
        .all(|(entry, (tag, permissions, id))| {
            entry[..2] == tag.to_le_bytes()
                && entry[2..4] == permissions.to_le_bytes()
                && entry[4..] == id.to_le_bytes()
        })
}

#[cfg(test)]
mod acl_tests {
    use super::private_service_acl;

    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, permissions, uid) in entries {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(permissions.to_le_bytes());
            bytes.extend(uid.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn systemd_read_only_acl_admits_only_the_service_user() {
        let undefined = u32::MAX;
        let entries = [
            (1, 4, undefined),
            (2, 4, 999),
            (4, 0, undefined),
            (16, 4, undefined),
            (32, 0, undefined),
        ];
        assert!(private_service_acl(&acl(&entries), 999));
        assert!(!private_service_acl(&acl(&entries), 998));
        assert!(!private_service_acl(&acl(&entries), 0));
    }

    #[test]
    fn group_other_write_execute_or_extra_acl_authority_is_refused() {
        let undefined = u32::MAX;
        let entries = [
            (1, 4, undefined),
            (2, 4, 999),
            (4, 0, undefined),
            (16, 4, undefined),
            (32, 0, undefined),
        ];
        for (index, permissions) in [(0, 6), (1, 6), (1, 5), (2, 4), (3, 6), (4, 4)] {
            let mut changed = entries;
            changed[index].1 = permissions;
            assert!(!private_service_acl(&acl(&changed), 999));
        }
        let mut extra = entries.to_vec();
        extra.insert(2, (2, 4, 998));
        assert!(!private_service_acl(&acl(&extra), 999));
        extra[2] = (8, 4, 998);
        assert!(!private_service_acl(&acl(&extra), 999));
    }

    #[test]
    fn malformed_or_unknown_acl_representations_are_refused() {
        let undefined = u32::MAX;
        let entries = [
            (1, 4, undefined),
            (2, 4, 999),
            (4, 0, undefined),
            (16, 4, undefined),
            (32, 0, undefined),
        ];
        let bytes = acl(&entries);
        for length in 0..bytes.len() {
            assert!(!private_service_acl(&bytes[..length], 999));
        }
        let mut changed = bytes.clone();
        changed[0] = 3;
        assert!(!private_service_acl(&changed, 999));
        let mut changed = entries;
        changed[2].0 = 8;
        assert!(!private_service_acl(&acl(&changed), 999));
        let mut changed = entries;
        changed[4].2 = 999;
        assert!(!private_service_acl(&acl(&changed), 999));
    }
}
