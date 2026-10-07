// SPDX-License-Identifier: AGPL-3.0-only
//! Locked controller upgrade: a verified encrypted pre-upgrade backup is
//! published before any older schema is migrated, and only the newest few are
//! retained. The backup is the supported rollback; there is no downgrade.
use crate::backup::{SealArgs, SealKeys, SnapshotInfo, create_backup_described, verify_backup};
use blindpass_core::deployment::Directory;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Most recent pre-upgrade backups kept after a completed upgrade.
pub const RETAINED_BACKUPS: usize = 3;
const PREFIX: &str = "pre-upgrade-";

pub struct PreUpgradeBackup {
    directory: PathBuf,
    seal: SealArgs,
}

/// What `migrate` did, without any path or secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct MigrationOutcome {
    pub from_schema: i64,
    pub to_schema: i64,
    pub backup_taken: bool,
}

impl PreUpgradeBackup {
    /// `migrate` flags: none, or `--pre-upgrade-backup-dir` (absolute) with either
    /// `--recovery-key-file` or `--signing-credential-file` plus
    /// `--recipient-certificate-file` (ADR 0013), each absolute and given once.
    pub fn from_args(args: &[String]) -> Result<Option<Self>, &'static str> {
        const USAGE: &str = "migrate accepts only --pre-upgrade-backup-dir <absolute-dir> with --recovery-key-file <file> or --signing-credential-file <file> --recipient-certificate-file <file>";
        if args.is_empty() {
            return Ok(None);
        }
        if !args.len().is_multiple_of(2) {
            return Err(USAGE);
        }
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let name = pair[0].as_str();
            if !(name == "--pre-upgrade-backup-dir" || crate::backup::SEAL_OPTIONS.contains(&name))
                || values.insert(name, pair[1].as_str()).is_some()
            {
                return Err(USAGE);
            }
        }
        let directory = PathBuf::from(*values.get("--pre-upgrade-backup-dir").ok_or(USAGE)?);
        if !directory.is_absolute() {
            return Err("pre-upgrade backup paths must be absolute");
        }
        values.remove("--pre-upgrade-backup-dir");
        let seal = SealArgs::from_values(&values)
            .map_err(|_| "pre-upgrade backup paths must be absolute and one credential model")?;
        // SealArgs ignores unrelated names, so insist on exactly its options.
        if values.len()
            != if values.contains_key("--recovery-key-file") {
                1
            } else {
                2
            }
        {
            return Err(USAGE);
        }
        Ok(Some(Self { directory, seal }))
    }

    /// Publish and independently re-verify an encrypted backup of the still
    /// unmigrated database. Any failure leaves no published backup behind.
    pub(crate) async fn take(&self, from_schema: i64, tenant_id: &str) -> Result<(), &'static str> {
        let base = Directory::create_private(&self.directory)
            .map_err(|_| "unsafe pre-upgrade backup directory")?;
        base.lock(true)
            .map_err(|_| "pre-upgrade backup directory busy")?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock unavailable")?
            .as_millis();
        let output = self
            .directory
            .join(format!("{PREFIX}{stamp:013}-v{from_schema}"));
        if fs::symlink_metadata(&output).is_ok() {
            return Err("pre-upgrade backup name collision");
        }
        let result = async {
            let keys = self.seal.keys();
            let (archive, mut snapshot) = create_backup_described(&output, &keys)
                .await
                .map_err(|_| "pre-upgrade backup could not be created and verified")?;
            // A single credential also re-opens the published archive. With split
            // custody this host cannot decrypt it: create already measured the
            // sealed bytes through a throwaway co-recipient, and the operator's
            // `backup verify` with the offline recipient key is the remaining proof.
            if let SealKeys::Single(recovery_key) = keys {
                snapshot = verify_backup(&archive, recovery_key, &output)
                    .await
                    .map_err(|_| "pre-upgrade backup could not be re-verified")?
                    .snapshot;
            }
            let snapshot: SnapshotInfo = snapshot;
            if snapshot.schema_version != from_schema || snapshot.tenant_id != tenant_id {
                return Err("pre-upgrade backup does not describe the database being upgraded");
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            // Only the directory this call just created, never a pre-existing one.
            let _ = fs::remove_dir_all(&output);
        }
        let _ = base.sync();
        result
    }

    /// Best effort after a completed upgrade: keep the newest backups, never
    /// touch an unrecognized name or follow a link. Returns how many were removed.
    pub(crate) fn retain(&self) -> usize {
        let Ok(base) = Directory::open_private(&self.directory) else {
            return 0;
        };
        if base.lock(true).is_err() {
            return 0;
        }
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return 0;
        };
        let mut owned: Vec<(u64, PathBuf)> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let stamp = parse_name(entry.file_name().to_str()?)?;
                let metadata = fs::symlink_metadata(entry.path()).ok()?;
                (metadata.is_dir() && !metadata.file_type().is_symlink())
                    .then(|| (stamp, entry.path()))
            })
            .collect();
        owned.sort();
        let excess = owned.len().saturating_sub(RETAINED_BACKUPS);
        let removed = owned
            .into_iter()
            .take(excess)
            .filter(|(_, path)| remove_backup(path))
            .count();
        let _ = base.sync();
        removed
    }
}

fn remove_backup(path: &Path) -> bool {
    fs::remove_dir_all(path).is_ok()
}

/// `pre-upgrade-<13 digit ms>-v<schema>` and nothing else.
fn parse_name(name: &str) -> Option<u64> {
    let rest = name.strip_prefix(PREFIX)?;
    let (stamp, version) = rest.split_once("-v")?;
    if stamp.len() != 13
        || !stamp.bytes().all(|b| b.is_ascii_digit())
        || version.is_empty()
        || version.len() > 3
        || !version.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    stamp.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p06_up09_only_exact_backup_names_are_recognized() {
        assert_eq!(parse_name("pre-upgrade-0000001790000-v16"), Some(1_790_000));
        for name in [
            "pre-upgrade-keep-me",
            "pre-upgrade-000000179000-v16",
            "pre-upgrade-0000001790000-v",
            "pre-upgrade-0000001790000-v1600",
            "pre-upgrade-0000001790000-v16.bak",
            "operator-notes",
            "../pre-upgrade-0000001790000-v16",
        ] {
            assert_eq!(parse_name(name), None, "{name}");
        }
    }

    #[test]
    fn p06_up09_arguments_are_both_or_neither_and_absolute() {
        let a = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(PreUpgradeBackup::from_args(&[]).unwrap().is_none());
        for good in [
            a(&[
                "--pre-upgrade-backup-dir",
                "/b",
                "--signing-credential-file",
                "/s",
                "--recipient-certificate-file",
                "/c",
            ]),
            a(&[
                "--recipient-certificate-file",
                "/c",
                "--signing-credential-file",
                "/s",
                "--pre-upgrade-backup-dir",
                "/b",
            ]),
        ] {
            assert!(
                PreUpgradeBackup::from_args(&good).unwrap().is_some(),
                "{good:?}"
            );
        }
        for bad in [
            // One half of the split pair, a mixture of both models, relative paths.
            a(&[
                "--pre-upgrade-backup-dir",
                "/b",
                "--signing-credential-file",
                "/s",
            ]),
            a(&[
                "--pre-upgrade-backup-dir",
                "/b",
                "--recipient-certificate-file",
                "/c",
            ]),
            a(&[
                "--pre-upgrade-backup-dir",
                "/b",
                "--recovery-key-file",
                "/k",
                "--signing-credential-file",
                "/s",
                "--recipient-certificate-file",
                "/c",
            ]),
            a(&[
                "--pre-upgrade-backup-dir",
                "/b",
                "--signing-credential-file",
                "s",
                "--recipient-certificate-file",
                "/c",
            ]),
            a(&[
                "--pre-upgrade-backup-dir",
                "/b",
                "--signing-credential-file",
                "/s",
                "--signing-credential-file",
                "/s",
                "--recipient-certificate-file",
                "/c",
            ]),
        ] {
            assert!(PreUpgradeBackup::from_args(&bad).is_err(), "{bad:?}");
        }
        assert!(
            PreUpgradeBackup::from_args(&a(&[
                "--pre-upgrade-backup-dir",
                "/b",
                "--recovery-key-file",
                "/k"
            ]))
            .unwrap()
            .is_some()
        );
        assert!(
            PreUpgradeBackup::from_args(&a(&[
                "--recovery-key-file",
                "/k",
                "--pre-upgrade-backup-dir",
                "/b"
            ]))
            .unwrap()
            .is_some()
        );
        for bad in [
            a(&["--pre-upgrade-backup-dir", "/b"]),
            a(&["--recovery-key-file", "/k"]),
            a(&["--pre-upgrade-backup-dir", "b", "--recovery-key-file", "/k"]),
            a(&[
                "--pre-upgrade-backup-dir",
                "/b",
                "--recovery-key-file",
                "/k",
                "--x",
            ]),
            a(&["--unknown"]),
        ] {
            assert!(PreUpgradeBackup::from_args(&bad).is_err(), "{bad:?}");
        }
    }
}
