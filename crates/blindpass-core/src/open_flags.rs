// SPDX-License-Identifier: AGPL-3.0-only

//! Linux `open(2)` flag values whose numbers differ by architecture. Callers
//! use these for link- and directory-anchoring protections; a wrong number
//! compiles but silently opens `O_LARGEFILE`/`O_DIRECT` instead.

/// `O_DIRECTORY` and `O_NOFOLLOW` use the asm-generic values on arm and
/// aarch64 and the x86 values elsewhere this project builds.
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub const O_DIRECTORY: i32 = 0o40000;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub const O_NOFOLLOW: i32 = 0o100000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
pub const O_DIRECTORY: i32 = 0o200000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
pub const O_NOFOLLOW: i32 = 0o400000;
/// Identical on every supported architecture.
pub const O_CLOEXEC: i32 = 0o2000000;

#[cfg(test)]
mod tests {
    use super::{O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW};
    use std::os::unix::fs::{OpenOptionsExt, symlink};

    #[test]
    fn nofollow_refuses_a_final_symlink_and_directory_refuses_a_file() {
        let dir = std::env::temp_dir().join(format!("blindpass-flags-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        symlink(&file, dir.join("link")).unwrap();
        let link = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(dir.join("link"));
        assert_eq!(link.unwrap_err().raw_os_error(), Some(40), "ELOOP");
        let not_dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY)
            .open(&file);
        assert_eq!(not_dir.unwrap_err().raw_os_error(), Some(20), "ENOTDIR");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
