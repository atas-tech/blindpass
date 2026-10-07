// SPDX-License-Identifier: AGPL-3.0-only

//! P03's fixed, argument-free operation effect.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const MARKER_MODE: u32 = 0o444;
/// Searchable but not listable by other users, so a marker can be opened by
/// its grant id while the set of consumed grant ids is not enumerable.
const DIRECTORY_MODE: u32 = 0o711;
/// The listable mode earlier brokers created; it is tightened in place.
const LEGACY_DIRECTORY_MODE: u32 = 0o755;
const O_NOFOLLOW: i32 = blindpass_core::open_flags::O_NOFOLLOW;

pub(crate) fn create_in(directory: &Path, grant_id: &str) -> Result<(), &'static str> {
    if !valid_opaque_id(grant_id) {
        return Err("operation marker identifier is invalid");
    }
    ensure_directory(directory)?;
    let path = directory.join(format!("{grant_id}.marker"));
    let marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MARKER_MODE)
        .custom_flags(O_NOFOLLOW)
        .open(&path)
        .map_err(|_| "operation marker could not be created exclusively")?;
    marker
        .set_permissions(fs::Permissions::from_mode(MARKER_MODE))
        .and_then(|()| marker.sync_all())
        .map_err(|_| "operation marker could not be synchronized")?;
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "operation marker directory could not be synchronized")?;
    Ok(())
}

fn ensure_directory(directory: &Path) -> Result<(), &'static str> {
    let was_missing = match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == effective_uid()
                && metadata.permissions().mode() & 0o777 == LEGACY_DIRECTORY_MODE
            {
                fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE))
                    .map_err(|_| "operation marker directory permissions are unsafe")?;
            }
            let metadata = fs::symlink_metadata(directory)
                .map_err(|_| "operation marker directory could not be inspected safely")?;
            validate_directory(&metadata)?;
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(directory).map_err(|_| "operation marker directory is unavailable")?;
            fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|_| "operation marker directory permissions are unsafe")?;
            true
        }
        Err(_) => return Err("operation marker directory could not be inspected safely"),
    };
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| "operation marker directory could not be inspected safely")?;
    validate_directory(&metadata)?;
    if was_missing && let Some(parent) = directory.parent() {
        File::open(parent)
            .and_then(|parent| parent.sync_all())
            .map_err(|_| "operation marker parent directory could not be synchronized")?;
    }
    Ok(())
}

fn validate_directory(metadata: &fs::Metadata) -> Result<(), &'static str> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o777 != DIRECTORY_MODE
    {
        return Err("operation marker directory ownership or mode is unsafe");
    }
    Ok(())
}

fn valid_opaque_id(value: &str) -> bool {
    blindpass_core::fleet::is_valid_opaque_id(value)
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
    use super::{create_in, effective_uid};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "blindpass-noop-marker-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        root.join("ops")
    }

    #[test]
    fn marker_is_empty_private_to_the_broker_and_exclusive() {
        let directory = temporary_directory();
        create_in(&directory, "gr_0123456789abcdef0123456789abcdef").unwrap();
        let marker = directory.join("gr_0123456789abcdef0123456789abcdef.marker");
        let metadata = std::fs::symlink_metadata(&marker).unwrap();
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), effective_uid());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o444);
        assert_eq!(metadata.len(), 0);
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o711,
            "other local users can open a marker by name but cannot list grant ids"
        );
        assert!(create_in(&directory, "gr_0123456789abcdef0123456789abcdef").is_err());
        assert!(create_in(&directory, "../outside").is_err());
        std::fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }

    #[test]
    fn marker_directory_rejects_symlinks_and_writable_modes() {
        let root = temporary_directory().parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&root).unwrap();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = root.join("linked");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(create_in(&link, "gr_0123456789abcdef0123456789abcdef").is_err());
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(create_in(&real, "gr_1123456789abcdef0123456789abcdef").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_listable_marker_directory_from_an_earlier_broker_is_tightened() {
        let root = temporary_directory().parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&root).unwrap();
        let legacy = root.join("legacy");
        std::fs::create_dir(&legacy).unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_in(&legacy, "gr_2123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            std::fs::metadata(&legacy).unwrap().permissions().mode() & 0o777,
            0o711
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
