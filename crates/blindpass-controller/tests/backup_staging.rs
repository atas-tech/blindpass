// SPDX-License-Identifier: AGPL-3.0-only
//! P06-D29 (ADR 0013): decrypted restore material is staged only on a private,
//! user-owned tmpfs/ramfs directory with room for it; anything else refuses.
use blindpass_controller::backup::{copy_private_file, restore_staging_directory};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

static NEXT: AtomicU32 = AtomicU32::new(0);

fn unique(base: &Path) -> PathBuf {
    base.join(format!(
        "p06-d29-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn archive(bytes: usize) -> PathBuf {
    let path = unique(Path::new(env!("CARGO_TARGET_TMPDIR")));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, vec![0u8; bytes]).unwrap();
    path
}
/// A candidate directory on memory-backed storage; `None` when the host has no
/// writable tmpfs at `/dev/shm`, in which case the positive cases cannot run.
fn tmpfs_candidate() -> Option<PathBuf> {
    let shm = Path::new("/dev/shm");
    let probe = unique(shm);
    fs::create_dir(&probe).ok()?;
    fs::remove_dir(&probe).ok()?;
    Some(unique(shm))
}
fn disk_candidate() -> PathBuf {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(&base).unwrap();
    unique(&base)
}

#[test]
fn p06_d29_s01_a_disk_directory_is_never_used_for_decrypted_material() {
    let disk = disk_candidate();
    let archive = archive(1024);
    assert!(restore_staging_directory(Some(&disk), &archive).is_err());
    // Even an already-correct private directory on disk is refused.
    fs::create_dir(&disk).unwrap();
    fs::set_permissions(&disk, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(restore_staging_directory(Some(&disk), &archive).is_err());
    fs::remove_dir(&disk).unwrap();
    // A refusal never falls through to another location when one was named.
    assert!(
        fs::read_dir(env!("CARGO_TARGET_TMPDIR"))
            .unwrap()
            .all(|e| e.unwrap().path() != disk)
    );
}

#[test]
fn p06_d29_s02_a_private_tmpfs_directory_is_created_and_reused() {
    let Some(candidate) = tmpfs_candidate() else {
        eprintln!("no writable /dev/shm; positive tmpfs case not executed");
        return;
    };
    let archive = archive(1024);
    let resolved = restore_staging_directory(Some(&candidate), &archive).unwrap();
    assert_eq!(resolved, candidate);
    let metadata = fs::metadata(&candidate).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    // A second resolution of the same existing directory is accepted.
    assert_eq!(
        restore_staging_directory(Some(&candidate), &archive).unwrap(),
        candidate
    );
    fs::remove_dir(&candidate).unwrap();
}

#[test]
fn p06_d29_s03_unsafe_existing_directories_are_refused() {
    let Some(candidate) = tmpfs_candidate() else {
        return;
    };
    let archive = archive(1024);
    fs::create_dir(&candidate).unwrap();
    for mode in [0o755, 0o750, 0o770, 0o705, 0o1700] {
        fs::set_permissions(&candidate, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            restore_staging_directory(Some(&candidate), &archive).is_err(),
            "mode {mode:o} was accepted"
        );
    }
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(restore_staging_directory(Some(&candidate), &archive).is_ok());
    // A symlink to a good tmpfs directory is not followed.
    let link = unique(Path::new("/dev/shm"));
    symlink(&candidate, &link).unwrap();
    assert!(restore_staging_directory(Some(&link), &archive).is_err());
    fs::remove_file(&link).unwrap();
    // A relative path is refused.
    assert!(restore_staging_directory(Some(Path::new("relative-staging")), &archive).is_err());
    // A regular file is refused.
    fs::remove_dir(&candidate).unwrap();
    fs::write(&candidate, b"P06_DUMMY").unwrap();
    assert!(restore_staging_directory(Some(&candidate), &archive).is_err());
    fs::remove_file(&candidate).unwrap();
}

#[test]
fn p06_d29_s04_free_space_must_cover_twice_the_archive_plus_overhead() {
    let Some(candidate) = tmpfs_candidate() else {
        return;
    };
    let free = {
        let probe = unique(Path::new("/dev/shm"));
        fs::create_dir(&probe).unwrap();
        let mut stat = [0u64; 15];
        unsafe extern "C" {
            fn statfs(path: *const std::ffi::c_char, buf: *mut [u64; 15]) -> i32;
        }
        let path = std::ffi::CString::new("/dev/shm").unwrap();
        assert_eq!(unsafe { statfs(path.as_ptr(), &mut stat) }, 0);
        fs::remove_dir(&probe).unwrap();
        stat[1].saturating_mul(stat[4])
    };
    // A sparse archive claims more bytes than the tmpfs can hold twice over.
    let big = unique(Path::new(env!("CARGO_TARGET_TMPDIR")));
    fs::create_dir_all(big.parent().unwrap()).unwrap();
    let file = fs::File::create(&big).unwrap();
    file.set_len(free / 2 + 1).unwrap();
    assert!(restore_staging_directory(Some(&candidate), &big).is_err());
    // The refused call must not leave the directory behind.
    assert!(!candidate.exists() || fs::remove_dir(&candidate).is_ok());
    fs::remove_file(&big).unwrap();
}

#[test]
fn p06_d29_s05_copy_private_file_is_exclusive_private_and_leaves_no_partial() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(&base).unwrap();
    let from = unique(&base);
    let to = unique(&base);
    fs::write(&from, b"P06_DUMMY_KEY_MATERIAL").unwrap();
    copy_private_file(&from, &to).unwrap();
    assert_eq!(fs::read(&to).unwrap(), b"P06_DUMMY_KEY_MATERIAL");
    assert_eq!(
        fs::metadata(&to).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    // Existing destinations are never replaced.
    assert!(copy_private_file(&from, &to).is_err());
    assert_eq!(fs::read(&to).unwrap(), b"P06_DUMMY_KEY_MATERIAL");
    // A dangling-link destination is refused, not followed.
    let link = unique(&base);
    symlink(unique(&base), &link).unwrap();
    assert!(copy_private_file(&from, &link).is_err());
    // A link source is refused.
    let source_link = unique(&base);
    symlink(&from, &source_link).unwrap();
    assert!(copy_private_file(&source_link, &unique(&base)).is_err());
    // A non-regular destination parent is refused.
    assert!(copy_private_file(&from, &base.join("missing-dir/x")).is_err());
    assert_eq!(fs::metadata(&to).unwrap().nlink(), 1);
    for path in [from, to, link, source_link] {
        let _ = fs::remove_file(path);
    }
}
