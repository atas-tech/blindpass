// SPDX-License-Identifier: AGPL-3.0-only
//! Memory-backed staging for decrypted restore material (ADR 0013). The decrypted
//! tar, extracted members and controller keys exist only on a private tmpfs or
//! ramfs directory; the database and, just before publication, the keys are then
//! copied into the persistent destination stage.
use super::BackupError;
use blindpass_core::deployment::Directory;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, BackupError>;
const UNAVAILABLE: BackupError = BackupError("restore staging requires private tmpfs");
const OVERHEAD: u64 = 8 * 1024 * 1024;
const ENVIRONMENT: &str = "BLINDPASS_RESTORE_STAGING_DIR";

unsafe extern "C" {
    fn geteuid() -> u32;
}

/// Ordered candidates. A directory named explicitly or through the environment is
/// the only candidate: a refusal there never falls back to another location.
fn candidates(
    explicit: Option<&Path>,
    environment: Option<&Path>,
    runtime_dir: Option<&Path>,
    uid: u32,
) -> Vec<PathBuf> {
    if let Some(path) = explicit.or(environment) {
        return vec![path.to_owned()];
    }
    let mut list = Vec::new();
    if let Some(runtime) = runtime_dir.filter(|p| p.is_absolute()) {
        list.push(runtime.join("blindpass-restore"));
    }
    list.push(PathBuf::from(format!("/dev/shm/blindpass-restore-{uid}")));
    list
}

/// Resolve and prepare the restore staging directory for `archive`. The result is
/// owned by this user with mode 0700 on tmpfs/ramfs, with room for the decrypted
/// tar plus its members (twice the archive size) and fixed overhead.
pub fn restore_staging_directory(explicit: Option<&Path>, archive: &Path) -> Result<PathBuf> {
    let needed = fs::metadata(archive)
        .map_err(|_| UNAVAILABLE)?
        .len()
        .saturating_mul(2)
        .saturating_add(OVERHEAD);
    let environment = std::env::var_os(ENVIRONMENT)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    // SAFETY: geteuid has no arguments or memory effects.
    let uid = unsafe { geteuid() };
    let mut last = UNAVAILABLE;
    for candidate in candidates(explicit, environment.as_deref(), runtime.as_deref(), uid) {
        match prepare(&candidate, needed) {
            Ok(()) => return Ok(candidate),
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn prepare(path: &Path, needed: u64) -> Result<()> {
    if !path.is_absolute() {
        return Err(UNAVAILABLE);
    }
    let created = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Never create a directory on a filesystem that will be refused.
            let parent = path.parent().ok_or(UNAVAILABLE)?;
            Directory::open(parent)
                .and_then(|p| p.memory_backed_free_bytes())
                .map_err(|_| UNAVAILABLE)?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| UNAVAILABLE)?;
            true
        }
        Err(_) => return Err(UNAVAILABLE),
    };
    let checked = Directory::open_private(path)
        .and_then(|d| d.memory_backed_free_bytes())
        .map_err(|_| UNAVAILABLE)
        .and_then(|free| {
            if free >= needed {
                Ok(())
            } else {
                Err(UNAVAILABLE)
            }
        });
    if checked.is_err() && created {
        let _ = fs::remove_dir(path);
    }
    checked
}

/// Copy one regular file into a new private (0600) file and flush it. An existing
/// destination, a link on either side or a failed copy never leaves a replaced or
/// partial destination behind.
pub fn copy_private_file(from: &Path, to: &Path) -> std::io::Result<()> {
    let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let metadata = fs::symlink_metadata(from)?;
    if !metadata.file_type().is_file() {
        return Err(denied());
    }
    let mut source = File::open(from)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)?;
    let copied = std::io::copy(&mut source, &mut destination)
        .and_then(|_| destination.flush())
        .and_then(|_| destination.sync_all());
    if copied.is_err() {
        drop(destination);
        let _ = fs::remove_file(to);
    }
    copied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p06_d29_resolution_order_and_no_fallback_for_named_directories() {
        let named = Path::new("/mnt/named");
        let env = Path::new("/mnt/env");
        let runtime = Path::new("/run/user/1000");
        assert_eq!(
            candidates(Some(named), Some(env), Some(runtime), 1000),
            [named]
        );
        assert_eq!(candidates(None, Some(env), Some(runtime), 1000), [env]);
        assert_eq!(
            candidates(None, None, Some(runtime), 1000),
            [
                PathBuf::from("/run/user/1000/blindpass-restore"),
                PathBuf::from("/dev/shm/blindpass-restore-1000")
            ]
        );
        assert_eq!(
            candidates(None, None, Some(Path::new("relative")), 7),
            [PathBuf::from("/dev/shm/blindpass-restore-7")]
        );
        assert_eq!(
            candidates(None, None, None, 7),
            [PathBuf::from("/dev/shm/blindpass-restore-7")]
        );
    }
}
