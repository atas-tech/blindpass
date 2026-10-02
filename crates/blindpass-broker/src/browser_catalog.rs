// SPDX-License-Identifier: AGPL-3.0-only

//! Fixed root-installed recipes. Workload requests contain only opaque resource
//! IDs; endpoints, source destinations and browser options are administrator data.

use crate::BrowserResource;
use blindpass_core::canon::{Value, parse_json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

const FAILURE: &str = "browser_catalog_unavailable";
const MAX_BYTES: usize = 65_536;
const MAX_RESOURCES: usize = 128;
const NOFOLLOW: i32 = 0x20000;
const NONBLOCK: i32 = 0x800;
const DIRECTORY: i32 = 0x10000;
const CLOEXEC: i32 = 0x80000;
unsafe extern "C" {
    fn openat(dirfd: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
}

#[derive(Debug)]
pub struct BrowserCatalog {
    resources: BTreeMap<String, BrowserResource>,
}
impl BrowserCatalog {
    /// Startup-only installation. Every component is opened relative to a
    /// retained directory descriptor; symlinks and writable ancestors fail.
    pub fn open() -> Result<Self, &'static str> {
        let mut directory = File::open("/").map_err(|_| FAILURE)?;
        check_directory(&directory.metadata().map_err(|_| FAILURE)?, 0)?;
        for name in ["etc", "blindpass"] {
            directory = open_child(&directory, name, DIRECTORY)?;
            check_directory(&directory.metadata().map_err(|_| FAILURE)?, 0)?;
        }
        Self::read_in(&directory, 0)
    }
    fn read_in(directory: &File, owner: u32) -> Result<Self, &'static str> {
        check_directory(&directory.metadata().map_err(|_| FAILURE)?, owner)?;
        let mut file = open_child(directory, "browser-resources.json", 0)?;
        let before = file.metadata().map_err(|_| FAILURE)?;
        if !before.is_file()
            || before.uid() != owner
            || before.mode() & 0o7777 != 0o600
            || before.nlink() != 1
            || before.len() > MAX_BYTES as u64
        {
            return Err(FAILURE);
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| FAILURE)?;
        let after = file.metadata().map_err(|_| FAILURE)?;
        if bytes.len() as u64 != before.len()
            || before.len() != after.len()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || after.mode() != before.mode()
            || after.uid() != owner
            || after.nlink() != 1
        {
            return Err(FAILURE);
        }
        Self::from_bytes(&bytes)
    }
    /// Trusted embedding API; this parser does not establish file ownership.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(FAILURE);
        }
        let value =
            parse_json(std::str::from_utf8(bytes).map_err(|_| FAILURE)?).map_err(|_| FAILURE)?;
        let fields = value.as_object().ok_or(FAILURE)?;
        if fields.len() != 2
            || fields
                .iter()
                .any(|(name, _)| !matches!(name.as_str(), "version" | "resources"))
            || value.get("version").and_then(Value::as_u64) != Some(1)
        {
            return Err(FAILURE);
        }
        let entries = value
            .get("resources")
            .and_then(Value::as_array)
            .ok_or(FAILURE)?;
        if !(1..=MAX_RESOURCES).contains(&entries.len()) {
            return Err(FAILURE);
        }
        let mut resources = BTreeMap::new();
        let mut accounts = BTreeSet::new();
        for entry in entries {
            let resource = BrowserResource::from_value(entry).map_err(|_| FAILURE)?;
            // Journal account locks are global. An alias must never select a
            // second recipe for an account already reserved through another ID.
            if !crate::valid_event_identifier(resource.resource_id())
                || !accounts.insert(resource.account().to_owned())
                || resources
                    .insert(resource.resource_id().to_owned(), resource)
                    .is_some()
            {
                return Err(FAILURE);
            }
        }
        Ok(Self { resources })
    }
    #[must_use]
    pub fn select(&self, workload: &str, resource: &str) -> Option<&BrowserResource> {
        self.resources
            .get(resource)
            .filter(|entry| entry.permits(workload, resource))
    }
    pub(crate) fn resources(&self) -> impl Iterator<Item = &BrowserResource> {
        self.resources.values()
    }
}
fn check_directory(metadata: &Metadata, owner: u32) -> Result<(), &'static str> {
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7022 != 0 {
        Err(FAILURE)
    } else {
        Ok(())
    }
}
fn open_child(parent: &File, name: &str, flags: i32) -> Result<File, &'static str> {
    let name = CString::new(name).map_err(|_| FAILURE)?;
    // SAFETY: parent is retained, name is NUL-terminated, no creation flags;
    // successful openat transfers a new descriptor to File exactly once.
    let fd = unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | NOFOLLOW | NONBLOCK | CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(FAILURE);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    const RECIPE: &str = r#"{"resource_id":"report-primary","workload_ids":["workload-a"],"credential_unit":"blindpass-login-helper@.service","credential_name":"primary-password","configuration":{"kind":"fixture","origin":"https://127.0.0.1:4443","account":"primary","sessionMaxMs":300000}}"#;
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    fn source(recipe: &str) -> Vec<u8> {
        format!(r#"{{"version":1,"resources":[{recipe}]}}"#).into_bytes()
    }
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "blindpass-browser-catalog-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn open(&self) -> File {
            File::open(&self.0).unwrap()
        }
        fn write(&self, bytes: &[u8], mode: u32) {
            if self.0.join("browser-resources.json").exists() {
                fs::set_permissions(
                    self.0.join("browser-resources.json"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            fs::write(self.0.join("browser-resources.json"), bytes).unwrap();
            fs::set_permissions(
                self.0.join("browser-resources.json"),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn browser_catalog_selects_only_the_exact_installed_resource_and_workload() {
        let catalog = BrowserCatalog::from_bytes(&source(RECIPE)).unwrap();
        assert!(catalog.select("workload-a", "report-primary").is_some());
        assert!(catalog.select("workload-b", "report-primary").is_none());
        assert!(
            catalog
                .select("workload-a", "https://unapproved.invalid")
                .is_none()
        );
        assert!(!format!("{catalog:?}").contains("127.0.0.1"));
        assert!(!format!("{catalog:?}").contains("primary-password"));
    }
    #[test]
    fn browser_catalog_rejects_duplicates_unknown_fields_and_bounds() {
        for bytes in [
            br#"{"version":1,"resources":[]}"#.to_vec(),
            br#"{"version":2,"resources":[]}"#.to_vec(),
            br#"{"version":1,"resources":[],"capture":true}"#.to_vec(),
            br#"{"version":1,"version":1,"resources":[]}"#.to_vec(),
            source(&format!("{RECIPE},{RECIPE}")),
            source(&format!(
                "{RECIPE},{}",
                RECIPE.replace("report-primary", "report-alias")
            )),
            source(
                &std::iter::repeat_n(RECIPE, 129)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            vec![b' '; 65_537],
            vec![0xff],
        ] {
            assert!(BrowserCatalog::from_bytes(&bytes).is_err());
        }
        assert!(
            BrowserCatalog::from_bytes(&source(&RECIPE.replace("https://", "http://"))).is_err()
        );
    }
    #[test]
    fn browser_catalog_uses_a_bounded_private_single_link_regular_file() {
        let directory = Directory::new();
        directory.write(&source(RECIPE), 0o600);
        let parent = directory.open();
        let owner = fs::metadata(&directory.0).unwrap().uid();
        assert!(BrowserCatalog::read_in(&parent, owner).is_ok());
        for mode in [0o644, 0o660, 0o666, 0o400] {
            fs::set_permissions(
                directory.0.join("browser-resources.json"),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            assert!(BrowserCatalog::read_in(&parent, owner).is_err());
        }
        directory.write(&vec![b' '; 65_537], 0o600);
        assert!(BrowserCatalog::read_in(&parent, owner).is_err());
        directory.write(&source(RECIPE), 0o600);
        fs::hard_link(
            directory.0.join("browser-resources.json"),
            directory.0.join("alias.json"),
        )
        .unwrap();
        assert!(BrowserCatalog::read_in(&parent, owner).is_err());
    }
    #[test]
    fn browser_catalog_rejects_symlinks_directories_and_unsafe_parent_metadata() {
        let directory = Directory::new();
        let owner = fs::metadata(&directory.0).unwrap().uid();
        directory.write(&source(RECIPE), 0o600);
        fs::rename(
            directory.0.join("browser-resources.json"),
            directory.0.join("actual.json"),
        )
        .unwrap();
        symlink("actual.json", directory.0.join("browser-resources.json")).unwrap();
        assert!(BrowserCatalog::read_in(&directory.open(), owner).is_err());
        fs::remove_file(directory.0.join("browser-resources.json")).unwrap();
        fs::create_dir(directory.0.join("browser-resources.json")).unwrap();
        assert!(BrowserCatalog::read_in(&directory.open(), owner).is_err());
        fs::remove_dir(directory.0.join("browser-resources.json")).unwrap();
        directory.write(&source(RECIPE), 0o600);
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(BrowserCatalog::read_in(&directory.open(), owner).is_err());
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(BrowserCatalog::read_in(&directory.open(), owner.wrapping_add(1)).is_err());
    }
    #[test]
    fn browser_catalog_fifo_is_rejected_before_waiting_for_a_writer() {
        unsafe extern "C" {
            fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
        }
        let directory = Directory::new();
        let owner = fs::metadata(&directory.0).unwrap().uid();
        let name = CString::new(
            directory
                .0
                .join("browser-resources.json")
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { mkfifo(name.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert!(BrowserCatalog::read_in(&directory.open(), owner).is_err());
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }
}
