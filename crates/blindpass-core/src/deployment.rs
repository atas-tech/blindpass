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
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o7077 != 0
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
