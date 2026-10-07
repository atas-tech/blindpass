// SPDX-License-Identifier: AGPL-3.0-only

//! Complete backups use standard CMS SignedData over AuthEnvelopedData.
//! OpenSSL owns cryptography; private staging is never an activated store.

use blindpass_core::deployment::{Directory, read_private_file};
use rand::{RngCore, rngs::OsRng};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::{
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    process::CommandExt,
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Previously shipped candidate schema16 remains verifiable for a protected
/// forward migration. Verification alone never permits serving old state.
pub(crate) fn supported_snapshot_schema(version: i64) -> bool {
    (16..=crate::store::SCHEMA_VERSION).contains(&version)
}

pub const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: u64 = MAX_BUNDLE_BYTES + 1024 * 1024;
const TOOL_DEADLINE: Duration = Duration::from_secs(60);
mod archive;
pub(crate) mod postgres;
mod staging;
pub(crate) use archive::digest as archive_digest;
pub use archive::{ArchiveManifest, Backend, extract_archive, write_archive};
pub use staging::{copy_private_file, restore_staging_directory};

#[derive(Debug, Clone, Copy)]
pub struct BackupError(pub(crate) &'static str);
impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for BackupError {}
type Result<T> = std::result::Result<T, BackupError>;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotInfo {
    pub schema_version: i64,
    pub tenant_id: String,
    /// Snapshot's issuer epoch; NOT an external recovery high-watermark.
    pub recovery_generation: u64,
    pub clock_ms: i64,
    pub table_rows: std::collections::BTreeMap<String, u64>,
}

pub use crate::store::backup::PostgresSnapshot;

/// Export source state only. This does not create or verify a PostgreSQL backup.
pub async fn begin_postgres_snapshot(store: &crate::store::Store) -> Result<PostgresSnapshot> {
    let started = Instant::now();
    let snapshot = tokio::time::timeout(TOOL_DEADLINE, store.begin_postgres_snapshot())
        .await
        .map_err(|_| BackupError("PostgreSQL snapshot timed out"))?
        .map_err(|_| BackupError("PostgreSQL snapshot capture or validation failed"))?;
    if started.elapsed() >= TOOL_DEADLINE {
        return Err(BackupError("PostgreSQL snapshot timed out"));
    }
    Ok(snapshot)
}

pub async fn capture_sqlite(store: &crate::store::Store, output: &Path) -> Result<SnapshotInfo> {
    let file = private_create(output)?;
    let started = Instant::now();
    let result = tokio::time::timeout(TOOL_DEADLINE, store.capture_sqlite(output))
        .await
        .map_err(|_| BackupError("SQLite snapshot timed out"))
        .and_then(|value| {
            value.map_err(|_| BackupError("SQLite snapshot capture or validation failed"))
        })
        .and_then(|info| {
            if started.elapsed() >= TOOL_DEADLINE {
                return Err(BackupError("SQLite snapshot timed out"));
            }
            file.sync_all()
                .map_err(|_| BackupError("SQLite snapshot flush failed"))?;
            if file
                .metadata()
                .map_err(|_| BackupError("SQLite snapshot unavailable"))?
                .len()
                > MAX_BUNDLE_BYTES
            {
                return Err(BackupError("SQLite snapshot exceeds limit"));
            }
            Ok(info)
        });
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}
pub async fn inspect_sqlite(path: &Path) -> Result<SnapshotInfo> {
    let _file = private_input(path, MAX_BUNDLE_BYTES)?;
    let started = Instant::now();
    let result = tokio::time::timeout(TOOL_DEADLINE, crate::store::backup::inspect_sqlite(path))
        .await
        .map_err(|_| BackupError("SQLite snapshot verification timed out"))?
        .map_err(|_| BackupError("SQLite snapshot integrity or schema validation failed"))?;
    if started.elapsed() >= TOOL_DEADLINE {
        return Err(BackupError("SQLite snapshot verification timed out"));
    }
    Ok(result)
}

/// Which credential material seals an archive (ADR 0013). `Single` is the 0010
/// credential acting as both roles; `Split` keeps the decrypting key off this host.
#[derive(Debug, Clone, Copy)]
pub enum SealKeys<'a> {
    Single(&'a Path),
    Split {
        signing_credential: &'a Path,
        recipient_certificate: &'a Path,
    },
}

/// Which credential material opens an archive. `Split` takes the offline recipient
/// key and the signer's certificate (certificate-only or a full credential).
#[derive(Debug, Clone, Copy)]
pub enum OpenKeys<'a> {
    Single(&'a Path),
    Split {
        recipient_key: &'a Path,
        signing_certificate: &'a Path,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    Signing,
    Recipient,
}

pub async fn verify_backup(
    archive: &Path,
    recovery_key: &Path,
    work: &Path,
) -> Result<ArchiveManifest> {
    verify_backup_with(archive, &OpenKeys::Single(recovery_key), work).await
}

pub async fn verify_backup_with(
    archive: &Path,
    keys: &OpenKeys<'_>,
    work: &Path,
) -> Result<ArchiveManifest> {
    let working_directory = Directory::open_private(work)
        .map_err(|_| BackupError("unsafe backup verification directory"))?;
    working_directory
        .lock(false)
        .map_err(|_| BackupError("backup verification directory busy"))?;
    Ok(verified_backup_members_with(archive, keys, work, work)
        .await?
        .manifest
        .clone())
}

/// Authenticated members stay in the same private stage throughout inspection
/// and restore; callers cannot verify one input and then extract another.
pub(crate) struct VerifiedBackup {
    pub(crate) manifest: ArchiveManifest,
    _stage: Stage,
    _tool_stage: Option<Stage>,
    members: Stage,
}
impl VerifiedBackup {
    pub(crate) fn member(&self, name: &str) -> PathBuf {
        self.members.member(name)
    }
}
/// `secret_work` holds the decrypted tar and every extracted member (including the
/// controller keys); `work` holds only tool state that never contains key material,
/// such as the PostgreSQL verification cluster. Verification passes the same
/// directory for both; restore passes a tmpfs directory for `secret_work`.
pub(crate) async fn verified_backup_members_with(
    archive: &Path,
    keys: &OpenKeys<'_>,
    work: &Path,
    secret_work: &Path,
) -> Result<VerifiedBackup> {
    let stage = Stage::new(secret_work)?;
    let tool_stage = if secret_work == work {
        None
    } else {
        Some(Stage::new(work)?)
    };
    let plain = stage.member("archive.tar");
    decrypt_bundle_with(archive, &plain, keys, &stage.0)?;
    let members = Stage::new(&stage.0)?;
    let manifest = extract_archive(&plain, &members.0)?;
    let snapshot = match manifest.backend {
        Backend::Sqlite => inspect_sqlite(&members.member("database.sqlite")).await?,
        Backend::Postgres => {
            // Complete restore in a private cluster; the restored state is measured
            // like the live snapshot and must equal the authenticated manifest.
            postgres::verify_dump(
                &members.member("database.pgcustom"),
                &manifest.snapshot,
                tool_stage.as_ref().unwrap_or(&members),
            )
            .await?;
            manifest.snapshot.clone()
        }
    };
    if snapshot != manifest.snapshot {
        return Err(BackupError("backup snapshot metadata mismatch"));
    }
    Ok(VerifiedBackup {
        manifest,
        _stage: stage,
        _tool_stage: tool_stage,
        members,
    })
}

/// Explicitly remove interrupted private staging, never published archives.
/// Managed capture and verification hold conflicting locks for their lifetime.
pub fn cleanup_staging(work: &Path) -> Result<usize> {
    let directory = Directory::open_private(work)
        .map_err(|_| BackupError("unsafe backup cleanup directory"))?;
    directory
        .lock(true)
        .map_err(|_| BackupError("backup cleanup directory busy"))?;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(work).map_err(|_| BackupError("backup cleanup unavailable"))? {
        let entry = entry.map_err(|_| BackupError("backup cleanup unavailable"))?;
        let name = entry.file_name();
        let Some(suffix) = name.to_str().and_then(|name| name.strip_prefix(".backup-")) else {
            continue;
        };
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            continue;
        }
        // Validate every candidate before deleting any. Anchored no-follow
        // checks reject linked ancestors, symlinks and another UID's staging.
        let candidate = Directory::open_private(&entry.path())
            .map_err(|_| BackupError("unsafe backup staging residue"))?;
        candidate
            .lock(true)
            .map_err(|_| BackupError("backup staging residue busy"))?;
        candidates.push((entry.path(), candidate));
    }
    for (path, _custody) in &candidates {
        // remove_dir_all does not follow symlinks within a private stage.
        // Same-UID uncooperative mutation is outside this custody boundary.
        fs::remove_dir_all(path).map_err(|_| BackupError("backup staging cleanup failed"))?;
    }
    directory
        .sync()
        .map_err(|_| BackupError("backup cleanup flush failed"))?;
    Ok(candidates.len())
}

/// Dump exactly the exported snapshot, then release it. The caller verifies the
/// sealed archive by a complete isolated restore before publication.
async fn capture_postgres(
    store: &crate::store::Store,
    connection: &postgres::PgConnection,
    stage: &Stage,
) -> Result<SnapshotInfo> {
    postgres::require_toolkit(stage)?;
    let snapshot = begin_postgres_snapshot(store).await;
    let result = async {
        let snapshot = snapshot?;
        let dumped = (|| {
            postgres::dump(
                connection,
                snapshot.schema(),
                snapshot.id()?,
                stage,
                &stage.member("database.pgcustom"),
            )
        })();
        let info = snapshot.info().clone();
        let closed = snapshot.close().await;
        dumped?;
        closed?;
        Ok(info)
    }
    .await;
    store.close().await;
    result
}

pub async fn create_backup(output: &Path, recovery_key: &Path) -> Result<PathBuf> {
    create_backup_with(output, &SealKeys::Single(recovery_key)).await
}

pub async fn create_backup_with(output: &Path, seal_keys: &SealKeys<'_>) -> Result<PathBuf> {
    create_backup_described(output, seal_keys)
        .await
        .map(|(path, _)| path)
}

/// As [`create_backup_with`], also returning the snapshot description that the
/// complete decrypt-and-restore verification measured and matched.
pub async fn create_backup_described(
    output: &Path,
    seal_keys: &SealKeys<'_>,
) -> Result<(PathBuf, SnapshotInfo)> {
    let output_directory = Directory::create_private(output)
        .map_err(|_| BackupError("unsafe backup output directory"))?;
    output_directory
        .lock(true)
        .map_err(|_| BackupError("backup output directory busy"))?;
    let keys_path = std::env::var_os("BLINDPASS_KEYS_DIR")
        .map(PathBuf::from)
        .ok_or(BackupError("backup requires explicit BLINDPASS_KEYS_DIR"))?;
    let keys = Directory::open_private(&keys_path)
        .map_err(|_| BackupError("unsafe controller key directory"))?;
    // Controller key changes must hold this directory's exclusive lock.
    // Captured values are immutable and compared to the loaded configuration.
    keys.lock(false)
        .map_err(|_| BackupError("controller key directory busy"))?;
    let config = crate::config::Config::from_env_offline()
        .map_err(|_| BackupError("backup controller configuration invalid"))?;
    let expected = [
        config.root_secret(),
        config.agent_jwt_secret(),
        config
            .issuer_keypair()
            .ok_or(BackupError("backup issuer key missing"))?
            .seed_bytes(),
    ];
    let stage = Stage::new(output)?;
    for (name, expected) in blindpass_core::deployment::KEY_NAMES
        .into_iter()
        .zip(expected)
    {
        let captured = keys
            .read(name, 32)
            .map_err(|_| BackupError("backup controller key missing or unsafe"))?;
        if captured.len() != 32 || captured.as_bytes() != expected {
            return Err(BackupError(
                "backup controller key set changed or differs from configuration",
            ));
        }
        private_write(&stage.member(name), captured.as_bytes())?;
    }
    let postgres = !config.database_url().starts_with("sqlite:");
    let store = tokio::time::timeout(
        Duration::from_secs(15),
        crate::store::Store::connect_existing_for_snapshot(
            config.database_url(),
            config.clock_tolerance_ms(),
        ),
    )
    .await
    .map_err(|_| BackupError("backup database connection timed out"))?
    .map_err(|_| BackupError("backup requires intact initialized controller state"))?;
    let snapshot = if postgres {
        let connection = postgres::PgConnection::parse(config.database_url())?;
        capture_postgres(&store, &connection, &stage).await
    } else {
        let captured = capture_sqlite(&store, &stage.member("database.sqlite")).await;
        store.close().await;
        captured
    };
    let snapshot = snapshot?;
    let tar = stage.member("archive.tar");
    write_archive(
        &stage.0,
        &tar,
        if postgres {
            Backend::Postgres
        } else {
            Backend::Sqlite
        },
        &snapshot,
    )?;
    let sealed = stage.member("sealed.bpbackup");
    let verified = match seal_keys {
        SealKeys::Single(recovery_key) => {
            encrypt_bundle(&tar, &sealed, recovery_key, &stage.0)?;
            verify_backup(&sealed, recovery_key, &stage.0).await?
        }
        SealKeys::Split {
            signing_credential,
            recipient_certificate,
        } => {
            // This host holds no key that opens what it writes. A throwaway
            // recipient, destroyed with the stage, lets the complete decrypt and
            // isolated-restore verification run on the exact sealed bytes.
            let throwaway = stage.member("throwaway.pem");
            let throwaway_certificate = stage.member("throwaway-certificate.pem");
            initialize_role_credentials(KeyRole::Recipient, &throwaway, &throwaway_certificate)?;
            encrypt_bundle_to(
                &tar,
                &sealed,
                signing_credential,
                &[recipient_certificate, &throwaway_certificate],
                &stage.0,
            )?;
            verify_backup_with(
                &sealed,
                &OpenKeys::Split {
                    recipient_key: &throwaway,
                    signing_certificate: signing_credential,
                },
                &stage.0,
            )
            .await?
        }
    };
    if verified.snapshot != snapshot {
        return Err(BackupError("backup verification mismatch"));
    }
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let path = output.join(format!("controller-backup-{suffix}.bpbackup"));
    publish(&sealed, &path)?;
    Ok((path, snapshot))
}

/// Options that carry a path versus options that carry a short fixed value.
const PATH_OPTIONS: &[&str] = &[
    "--output",
    "--certificate-output",
    "--recovery-key-file",
    "--signing-credential-file",
    "--recipient-certificate-file",
    "--recipient-key-file",
    "--signing-certificate-file",
    "--archive",
    "--work-directory",
];
const VALUE_OPTIONS: &[&str] = &["--role", "--expected-archive-sha256"];

/// Digest of the sealed archive exactly as stored, so an operator can pin the file
/// they recorded off-host. A mismatch refuses before any decryption.
pub fn archive_sha256(archive: &Path, work: &Path) -> Result<String> {
    archive_digest(archive, work)
}

pub fn require_archive_sha256(archive: &Path, work: &Path, expected: &str) -> Result<()> {
    if !valid_digest(expected) || archive_sha256(archive, work)? != expected {
        return Err(BackupError("backup archive digest mismatch"));
    }
    Ok(())
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Options that open an archive for restore or handoff import: one credential
/// model, an optional operator-recorded digest and an optional staging directory.
pub(crate) const OPEN_OPTIONS: [&str; 5] = [
    "--recovery-key-file",
    "--recipient-key-file",
    "--signing-certificate-file",
    "--expected-archive-sha256",
    "--staging-directory",
];

/// Options that seal an archive: one credential model, never a mixture.
pub(crate) const SEAL_OPTIONS: [&str; 3] = [
    "--recovery-key-file",
    "--signing-credential-file",
    "--recipient-certificate-file",
];

pub(crate) struct SealArgs {
    single: Option<PathBuf>,
    split: Option<(PathBuf, PathBuf)>,
}
impl SealArgs {
    pub(crate) fn from_values(values: &std::collections::BTreeMap<&str, &str>) -> Result<Self> {
        let invalid = BackupError("invalid backup options");
        let path = |name: &str| -> Result<Option<PathBuf>> {
            values
                .get(name)
                .map(|value| {
                    let path = PathBuf::from(value);
                    path.is_absolute().then_some(path).ok_or(invalid)
                })
                .transpose()
        };
        let single = path("--recovery-key-file")?;
        let split = match (
            path("--signing-credential-file")?,
            path("--recipient-certificate-file")?,
        ) {
            (Some(signing), Some(recipient)) => Some((signing, recipient)),
            (None, None) => None,
            _ => return Err(invalid),
        };
        if single.is_some() == split.is_some() {
            return Err(invalid);
        }
        Ok(Self { single, split })
    }

    pub(crate) fn keys(&self) -> SealKeys<'_> {
        match (&self.single, &self.split) {
            (Some(key), _) => SealKeys::Single(key),
            (None, Some((signing, recipient))) => SealKeys::Split {
                signing_credential: signing,
                recipient_certificate: recipient,
            },
            (None, None) => unreachable!("validated in from_values"),
        }
    }
}

pub(crate) struct OpenArgs {
    single: Option<PathBuf>,
    split: Option<(PathBuf, PathBuf)>,
    expected_sha256: Option<String>,
    staging: Option<PathBuf>,
}
impl OpenArgs {
    /// `--recovery-key-file` alone, or both split flags; never a mixture.
    pub(crate) fn from_values(values: &std::collections::BTreeMap<&str, &str>) -> Result<Self> {
        let invalid = BackupError("invalid backup options");
        let path = |name: &str| -> Result<Option<PathBuf>> {
            values
                .get(name)
                .map(|value| {
                    let path = PathBuf::from(value);
                    path.is_absolute().then_some(path).ok_or(invalid)
                })
                .transpose()
        };
        let single = path("--recovery-key-file")?;
        let split = match (
            path("--recipient-key-file")?,
            path("--signing-certificate-file")?,
        ) {
            (Some(key), Some(certificate)) => Some((key, certificate)),
            (None, None) => None,
            _ => return Err(invalid),
        };
        if single.is_some() == split.is_some() {
            return Err(invalid);
        }
        let expected_sha256 = values
            .get("--expected-archive-sha256")
            .map(|value| {
                valid_digest(value)
                    .then(|| (*value).to_owned())
                    .ok_or(invalid)
            })
            .transpose()?;
        Ok(Self {
            single,
            split,
            expected_sha256,
            staging: path("--staging-directory")?,
        })
    }

    fn keys(&self) -> OpenKeys<'_> {
        match (&self.single, &self.split) {
            (Some(key), _) => OpenKeys::Single(key),
            (None, Some((key, certificate))) => OpenKeys::Split {
                recipient_key: key,
                signing_certificate: certificate,
            },
            (None, None) => unreachable!("validated in from_values"),
        }
    }

    /// Verify the pinned digest first, then decrypt and extract into private
    /// memory-backed staging. `work` (persistent) holds only tool state such as the
    /// PostgreSQL verification cluster, never decrypted bytes.
    pub(crate) async fn open(&self, archive: &Path, work: &Path) -> Result<VerifiedBackup> {
        if let Some(expected) = &self.expected_sha256 {
            require_archive_sha256(archive, work, expected)?;
        }
        let secret_work = restore_staging_directory(self.staging.as_deref(), archive)?;
        verified_backup_members_with(archive, &self.keys(), work, &secret_work).await
    }
}

/// Refusal text that names an option and the rule it broke. `BackupError` holds a
/// static string, so each known option has its own literal. Only the option name
/// is ever shown: never a path, a value or anything read from a file.
macro_rules! named_refusal {
    ($name:expr, $prefix:literal, $suffix:literal) => {
        match $name {
            "--output" => BackupError(concat!($prefix, " --output ", $suffix)),
            "--certificate-output" => {
                BackupError(concat!($prefix, " --certificate-output ", $suffix))
            }
            "--recovery-key-file" => {
                BackupError(concat!($prefix, " --recovery-key-file ", $suffix))
            }
            "--signing-credential-file" => {
                BackupError(concat!($prefix, " --signing-credential-file ", $suffix))
            }
            "--recipient-certificate-file" => {
                BackupError(concat!($prefix, " --recipient-certificate-file ", $suffix))
            }
            "--recipient-key-file" => {
                BackupError(concat!($prefix, " --recipient-key-file ", $suffix))
            }
            "--signing-certificate-file" => {
                BackupError(concat!($prefix, " --signing-certificate-file ", $suffix))
            }
            "--archive" => BackupError(concat!($prefix, " --archive ", $suffix)),
            "--work-directory" => BackupError(concat!($prefix, " --work-directory ", $suffix)),
            "--role" => BackupError(concat!($prefix, " --role ", $suffix)),
            "--expected-archive-sha256" => {
                BackupError(concat!($prefix, " --expected-archive-sha256 ", $suffix))
            }
            _ => BackupError(concat!($prefix, " an option ", $suffix)),
        }
    };
}

/// The checks `private_input` applies later, made first so that a refusal names
/// the option instead of reporting a generic "unsafe backup input". It never
/// accepts anything the later check would refuse. Only the archive uses it;
/// credential files are read by `read_private_file` (see `check_credential_option`).
fn check_input_option(name: &str, path: &Path, limit: u64) -> Result<()> {
    macro_rules! refuse {
        ($suffix:literal) => {
            named_refusal!(name, "unsafe backup input:", $suffix)
        };
    }
    let Some(parent) = path.parent() else {
        return Err(refuse!(
            "must be inside a directory owned by the current user with mode 0700"
        ));
    };
    Directory::open_private(parent).map_err(|_| {
        refuse!("is in a directory that is not owned by the current user with mode 0700")
    })?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            blindpass_core::open_flags::O_NOFOLLOW | blindpass_core::open_flags::O_CLOEXEC | 0x800,
        )
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                refuse!("does not exist")
            } else {
                refuse!("cannot be read or is a symbolic link")
            }
        })?;
    let metadata = file.metadata().map_err(|_| refuse!("cannot be read"))?;
    let parent_metadata =
        fs::metadata(parent).map_err(|_| refuse!("is in an unreadable directory"))?;
    if !metadata.is_file() {
        return Err(refuse!("must be a regular file"));
    }
    if metadata.nlink() != 1 || metadata.uid() != parent_metadata.uid() {
        return Err(refuse!(
            "must have one link and be owned by the same user as its directory"
        ));
    }
    if metadata.mode() & 0o7077 != 0 {
        return Err(refuse!(
            "must not be accessible by group or world (use mode 0600 or 0400)"
        ));
    }
    if metadata.len() == 0 {
        return Err(refuse!("is empty"));
    }
    if metadata.len() > limit {
        return Err(refuse!("is larger than the supported maximum"));
    }
    Ok(())
}

/// A credential, certificate or key option. The real reader, `read_private_file`,
/// is the ground truth: it accepts an owner-private file in any directory and a
/// systemd service credential (root-owned 0440 plus an exact named-user ACL, as the
/// packaged backup unit delivers it), and it does not need a private parent. This
/// asks that same reader first and only classifies a refusal, so the early check can
/// never refuse what the later read accepts. An empty file is refused here because
/// the parsers would otherwise fail with a less specific message.
fn check_credential_option(name: &str, path: &Path) -> Result<()> {
    macro_rules! refuse {
        ($suffix:literal) => {
            named_refusal!(name, "unsafe backup recovery credential:", $suffix)
        };
    }
    match read_private_file(path, MAX_CREDENTIAL_BYTES as usize) {
        Ok(bytes) if bytes.is_empty() => return Err(refuse!("is empty")),
        Ok(_) => return Ok(()),
        Err(_) => {}
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            blindpass_core::open_flags::O_NOFOLLOW | blindpass_core::open_flags::O_CLOEXEC | 0x800,
        )
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                refuse!("does not exist")
            } else {
                refuse!("cannot be read or is a symbolic link")
            }
        })?;
    let metadata = file.metadata().map_err(|_| refuse!("cannot be read"))?;
    if !metadata.is_file() {
        return Err(refuse!("must be a regular file"));
    }
    if metadata.nlink() != 1 {
        return Err(refuse!("must have exactly one link"));
    }
    if metadata.mode() & 0o7077 != 0 {
        return Err(refuse!(
            "must not be accessible by group or world (use mode 0600 or 0400)"
        ));
    }
    if metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(refuse!("is larger than the supported maximum"));
    }
    Err(refuse!(
        "must be owned by the current user and in a directory that can be opened"
    ))
}

fn check_work_directory(path: &Path) -> Result<()> {
    Directory::open_private(path).map(|_| ()).map_err(|_| {
        named_refusal!(
            "--work-directory",
            "unsafe backup input:",
            "must be an existing directory owned by the current user with mode 0700"
        )
    })
}

/// Largest credential or certificate file the backup tools accept.
const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;

pub async fn run_command(args: &[String]) -> Result<()> {
    let (action, rest) = args
        .split_first()
        .ok_or(BackupError("backup command required"))?;
    if !matches!(
        action.as_str(),
        "key-init" | "create" | "verify" | "cleanup"
    ) {
        return Err(BackupError("unknown backup command"));
    }
    if rest.len() % 2 != 0 {
        return Err(BackupError(
            "invalid backup options: every option needs a value",
        ));
    }
    let mut paths = std::collections::BTreeMap::new();
    let mut values = std::collections::BTreeMap::new();
    for pair in rest.as_chunks::<2>().0 {
        let name = pair[0].as_str();
        if PATH_OPTIONS.contains(&name) {
            if !Path::new(&pair[1]).is_absolute() {
                return Err(named_refusal!(
                    name,
                    "invalid backup options:",
                    "must be an absolute path"
                ));
            }
            if paths.insert(name, Path::new(&pair[1])).is_some() {
                return Err(named_refusal!(
                    name,
                    "invalid backup options:",
                    "was given more than once"
                ));
            }
        } else if VALUE_OPTIONS.contains(&name) {
            if values.insert(name, pair[1].as_str()).is_some() {
                return Err(named_refusal!(
                    name,
                    "invalid backup options:",
                    "was given more than once"
                ));
            }
        } else {
            return Err(BackupError(
                "invalid backup options: unknown option for this command",
            ));
        }
    }
    // The exact option sets each form accepts; anything else is refused.
    let has = |names: &[&str]| {
        names
            .iter()
            .all(|n| paths.contains_key(n) || values.contains_key(n))
    };
    let count = paths.len() + values.len();
    if let Some(expected) = values.get("--expected-archive-sha256")
        && !valid_digest(expected)
    {
        return Err(BackupError(
            "invalid backup options: --expected-archive-sha256 must be 64 lowercase hexadecimal characters",
        ));
    }
    match action.as_str() {
        "key-init" => {
            if has(&["--output"]) && count == 1 {
                initialize_recovery_key(paths["--output"])?;
                println!("{}", serde_json::json!({"recovery_key_created":true}));
            } else if has(&["--output", "--certificate-output", "--role"]) && count == 3 {
                let role = match values["--role"] {
                    "signing" => KeyRole::Signing,
                    "recipient" => KeyRole::Recipient,
                    _ => {
                        return Err(BackupError(
                            "invalid backup options: --role must be signing or recipient",
                        ));
                    }
                };
                initialize_role_credentials(
                    role,
                    paths["--output"],
                    paths["--certificate-output"],
                )?;
                println!(
                    "{}",
                    serde_json::json!({"role_credential_created":values["--role"]})
                );
            } else {
                return Err(BackupError(
                    "invalid backup options: key-init needs --output, or --output with --certificate-output and --role",
                ));
            }
        }
        "create" => {
            let (keys, custody) = if has(&["--output", "--recovery-key-file"]) && count == 2 {
                (SealKeys::Single(paths["--recovery-key-file"]), "single")
            } else if has(&[
                "--output",
                "--signing-credential-file",
                "--recipient-certificate-file",
            ]) && count == 3
            {
                (
                    SealKeys::Split {
                        signing_credential: paths["--signing-credential-file"],
                        recipient_certificate: paths["--recipient-certificate-file"],
                    },
                    "split",
                )
            } else {
                return Err(BackupError(
                    "invalid backup options: create needs --output and either --recovery-key-file or both --signing-credential-file and --recipient-certificate-file",
                ));
            };
            for name in [
                "--recovery-key-file",
                "--signing-credential-file",
                "--recipient-certificate-file",
            ] {
                if let Some(path) = paths.get(name) {
                    check_credential_option(name, path)?;
                }
            }
            let path = create_backup_with(paths["--output"], &keys).await?;
            let digest = archive_sha256(&path, paths["--output"])?;
            println!(
                "{}",
                serde_json::json!({"backup":path.file_name().and_then(|name| name.to_str()),"verified":true,"custody":custody,"archive_sha256":digest})
            );
        }
        "verify" => {
            let expected = values.get("--expected-archive-sha256").copied();
            let base = 2 + usize::from(expected.is_some());
            let keys = if has(&["--archive", "--work-directory", "--recovery-key-file"])
                && count == base + 1
            {
                OpenKeys::Single(paths["--recovery-key-file"])
            } else if has(&[
                "--archive",
                "--work-directory",
                "--recipient-key-file",
                "--signing-certificate-file",
            ]) && count == base + 2
            {
                OpenKeys::Split {
                    recipient_key: paths["--recipient-key-file"],
                    signing_certificate: paths["--signing-certificate-file"],
                }
            } else {
                return Err(BackupError(
                    "invalid backup options: verify needs --archive, --work-directory and either --recovery-key-file or both --recipient-key-file and --signing-certificate-file, and may add --expected-archive-sha256",
                ));
            };
            check_input_option("--archive", paths["--archive"], MAX_ENVELOPE_BYTES)?;
            for name in [
                "--recovery-key-file",
                "--recipient-key-file",
                "--signing-certificate-file",
            ] {
                if let Some(path) = paths.get(name) {
                    check_credential_option(name, path)?;
                }
            }
            check_work_directory(paths["--work-directory"])?;
            if let Some(expected) = expected {
                require_archive_sha256(paths["--archive"], paths["--work-directory"], expected)?;
            }
            let manifest =
                verify_backup_with(paths["--archive"], &keys, paths["--work-directory"]).await?;
            println!(
                "{}",
                serde_json::json!({"verified":true,"backend":manifest.backend,"schema_version":manifest.snapshot.schema_version})
            );
        }
        "cleanup" => {
            if !(has(&["--work-directory"]) && count == 1) {
                return Err(BackupError(
                    "invalid backup options: cleanup needs only --work-directory",
                ));
            }
            check_work_directory(paths["--work-directory"])?;
            let removed = cleanup_staging(paths["--work-directory"])?;
            println!(
                "{}",
                serde_json::json!({"removed_staging_directories":removed})
            );
        }
        _ => unreachable!(),
    }
    Ok(())
}

pub(crate) struct Stage(pub(crate) PathBuf);
impl Stage {
    pub(crate) fn new(parent: &Path) -> Result<Self> {
        Directory::open_private(parent)
            .map_err(|_| BackupError("unsafe backup staging directory"))?;
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = parent.join(format!(".backup-{name}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| BackupError("backup staging unavailable"))?;
        Ok(Self(path))
    }
    pub(crate) fn member(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn credential(&self, key: &Path) -> Result<PathBuf> {
        self.credential_as(key, "recovery.pem")
    }
    /// A credential file holds exactly one private key followed by one certificate.
    fn credential_as(&self, key: &Path, name: &str) -> Result<PathBuf> {
        let bytes = read_private_file(key, 16 * 1024)
            .map_err(|_| BackupError("unsafe backup recovery credential"))?;
        let text = std::str::from_utf8(bytes.as_bytes())
            .map_err(|_| BackupError("invalid backup recovery credential"))?;
        let (private, certificate) = text
            .trim()
            .split_once("-----END PRIVATE KEY-----")
            .ok_or(BackupError("invalid backup recovery credential"))?;
        if !private.starts_with("-----BEGIN PRIVATE KEY-----")
            || private.matches("-----BEGIN").count() != 1
            || !certificate
                .trim()
                .starts_with("-----BEGIN CERTIFICATE-----")
            || !certificate.trim().ends_with("-----END CERTIFICATE-----")
            || certificate.matches("-----BEGIN").count() != 1
            || certificate.matches("-----END").count() != 1
        {
            return Err(BackupError(
                "recovery credential requires one private key and one certificate",
            ));
        }
        let path = self.member(name);
        private_write(&path, bytes.as_bytes())?;
        Ok(path)
    }
    /// The one certificate in a file, written to its own staging member. With
    /// `refuse_private_key` the file must be certificate-only: a recipient private
    /// key is never accepted where backups are created.
    fn certificate_as(
        &self,
        file: &Path,
        name: &str,
        refuse_private_key: bool,
    ) -> Result<(PathBuf, String)> {
        let bytes = read_private_file(file, 16 * 1024)
            .map_err(|_| BackupError("unsafe backup certificate file"))?;
        let text = std::str::from_utf8(bytes.as_bytes())
            .map_err(|_| BackupError("invalid backup certificate file"))?;
        if refuse_private_key && text.contains("PRIVATE KEY") {
            return Err(BackupError(
                "backup recipient file must not contain a private key",
            ));
        }
        const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
        const END: &str = "-----END CERTIFICATE-----";
        if text.matches(BEGIN).count() != 1 || text.matches(END).count() != 1 {
            return Err(BackupError(
                "backup certificate file requires exactly one certificate",
            ));
        }
        let start = text.find(BEGIN).expect("counted");
        let end = text.find(END).expect("counted") + END.len();
        if end <= start {
            return Err(BackupError("invalid backup certificate file"));
        }
        let certificate = format!("{}\n", &text[start..end]);
        let path = self.member(name);
        private_write(&path, certificate.as_bytes())?;
        Ok((path, certificate))
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_create(path: &Path) -> Result<File> {
    Directory::open_private(path.parent().ok_or(BackupError("unsafe backup output"))?)
        .map_err(|_| BackupError("unsafe backup output"))?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(
            blindpass_core::open_flags::O_NOFOLLOW | blindpass_core::open_flags::O_CLOEXEC,
        )
        .open(path)
        .map_err(|_| BackupError("backup output already exists or is unavailable"))
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = private_create(path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| BackupError("backup write failed"))
}
fn private_input(path: &Path, limit: u64) -> Result<File> {
    Directory::open_private(path.parent().ok_or(BackupError("unsafe backup input"))?)
        .map_err(|_| BackupError("unsafe backup input"))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            blindpass_core::open_flags::O_NOFOLLOW | blindpass_core::open_flags::O_CLOEXEC | 0x800,
        )
        .open(path)
        .map_err(|_| BackupError("backup input unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| BackupError("backup input unavailable"))?;
    // The parent is already owned by this effective UID. Input must not be
    // another account's file, a FIFO/device/link, or group/world accessible.
    let parent = fs::metadata(path.parent().expect("checked parent"))
        .map_err(|_| BackupError("unsafe backup input"))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != parent.uid()
        || metadata.mode() & 0o7077 != 0
        || metadata.len() == 0
        || metadata.len() > limit
    {
        return Err(BackupError("unsafe or oversized backup input"));
    }
    Ok(file)
}

/// Child restrictions applied between fork and exec: die with the parent, no new
/// privileges, no core dumps and, for bounded tools, a file-size ceiling.
pub(crate) fn restrict_child(command: &mut Command, file_limit: Option<u64>) {
    let parent = std::process::id();
    let limit = file_limit.unwrap_or(u64::MAX);
    // SAFETY: the child closure performs only Linux syscalls before exec.
    // A killed CLI cannot leave a child retaining plaintext, and child core
    // dumps cannot persist recovery keys or decrypted data.
    unsafe {
        command.pre_exec(move || {
            unsafe extern "C" {
                fn prctl(option: i32, ...) -> i32;
                fn getppid() -> i32;
                fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
            }
            if prctl(1, 9usize, 0usize, 0usize, 0usize) != 0
                || getppid() as u32 != parent
                || prctl(38, 1usize, 0usize, 0usize, 0usize) != 0
                || setrlimit(4, &[0, 0]) != 0
                || (limit != u64::MAX && setrlimit(1, &[limit, limit]) != 0)
            {
                return Err(std::io::Error::from_raw_os_error(1));
            }
            Ok(())
        });
    }
}

pub(crate) struct ToolChild(pub(crate) Child);
impl Drop for ToolChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn tool(command: Command, input: Option<File>, output: File) -> Result<()> {
    tool_with_deadline(command, input, output, TOOL_DEADLINE)
}
fn tool_with_deadline(
    command: Command,
    input: Option<File>,
    output: File,
    deadline: Duration,
) -> Result<()> {
    tool_with_env(command, &[], input, output, deadline)
}
/// Same bounded child lifecycle with explicit extra environment (for example
/// libpq connection settings). The environment is otherwise empty.
fn tool_with_env(
    mut command: Command,
    envs: &[(&str, &std::ffi::OsStr)],
    input: Option<File>,
    output: File,
    deadline: Duration,
) -> Result<()> {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("OPENSSL_CONF", "/dev/null")
        .envs(envs.iter().copied())
        .stdin(input.map_or_else(Stdio::null, Stdio::from))
        .stdout(
            output
                .try_clone()
                .map_err(|_| BackupError("backup output unavailable"))?,
        )
        .stderr(Stdio::null());
    restrict_child(&mut command, Some(MAX_ENVELOPE_BYTES));
    let mut child = ToolChild(
        command
            .spawn()
            .map_err(|_| BackupError("backup tool unavailable"))?,
    );
    let start = Instant::now();
    loop {
        if start.elapsed() >= deadline {
            return Err(BackupError("backup tool timed out"));
        }
        if output
            .metadata()
            .map_err(|_| BackupError("backup output unavailable"))?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(BackupError("backup output exceeds limit"));
        }
        match child.0.try_wait() {
            Ok(Some(status)) if status.success() => {
                if start.elapsed() >= deadline {
                    return Err(BackupError("backup tool timed out"));
                }
                output
                    .sync_all()
                    .map_err(|_| BackupError("backup flush failed"))?;
                let size = output
                    .metadata()
                    .map_err(|_| BackupError("backup output unavailable"))?
                    .len();
                if size > MAX_ENVELOPE_BYTES {
                    return Err(BackupError("backup output exceeds limit"));
                }
                return Ok(());
            }
            Ok(Some(_)) => return Err(BackupError("backup cryptographic operation failed")),
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return Err(BackupError("backup tool failed")),
        }
    }
}
fn openssl(args: &[&str]) -> Command {
    let mut command = Command::new("/usr/bin/openssl");
    command.args(args);
    command
}

fn upstream_openssl_patched(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let Ok(major) = parts[0].parse::<u32>() else {
        return false;
    };
    let Ok(minor) = parts[1].parse::<u32>() else {
        return false;
    };
    let Ok(patch) = parts[2].parse::<u32>() else {
        return false;
    };
    major == 3
        && match minor {
            0 => patch >= 19,
            3 => patch >= 6,
            4 => patch >= 4,
            5 => patch >= 5,
            6 => patch >= 1,
            _ => false,
        }
}

fn require_patched_openssl(stage: &Stage) -> Result<()> {
    let output = stage.member("openssl-version");
    tool(openssl(&["version"]), None, private_create(&output)?)?;
    let bytes = read_private_file(&output, 512)
        .map_err(|_| BackupError("backup requires patched system OpenSSL"))?;
    let text = std::str::from_utf8(bytes.as_bytes())
        .map_err(|_| BackupError("backup requires patched system OpenSSL"))?;
    let mut words = text.split_whitespace();
    if words.next() != Some("OpenSSL") {
        return Err(BackupError("backup requires patched system OpenSSL"));
    }
    let version = words
        .next()
        .ok_or(BackupError("backup requires patched system OpenSSL"))?;
    if let Some((_, library)) = text.split_once("(Library: OpenSSL ")
        && library.split_whitespace().next() != Some(version)
    {
        return Err(BackupError(
            "backup requires matching patched OpenSSL library",
        ));
    }
    if upstream_openssl_patched(version) {
        return Ok(());
    }
    // Supported native distributions backport fixes without changing the
    // upstream patch number. Check BOTH the command and library package.
    let mut os = String::new();
    File::open("/etc/os-release")
        .and_then(|file| file.take(4097).read_to_string(&mut os))
        .map_err(|_| BackupError("backup requires patched system OpenSSL"))?;
    if os.len() > 4096 {
        return Err(BackupError("backup requires patched system OpenSSL"));
    }
    let field = |name: &str| {
        os.lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim_matches('"'))
    };
    let (library_package, minimum) = match (field("ID="), field("VERSION_ID="), version) {
        (Some("debian"), Some("12"), "3.0.18") => ("libssl3", "3.0.18-1~deb12u2"),
        (Some("ubuntu"), Some("24.04"), "3.0.13") => ("libssl3t64", "3.0.13-0ubuntu3.7"),
        _ => return Err(BackupError("backup requires patched system OpenSSL")),
    };
    let output = stage.member("openssl-packages");
    let mut query = Command::new("/usr/bin/dpkg-query");
    query.args([
        "--show",
        "--showformat=${Version}\n",
        "openssl",
        library_package,
    ]);
    tool(query, None, private_create(&output)?)?;
    let bytes = read_private_file(&output, 512)
        .map_err(|_| BackupError("backup requires patched system OpenSSL"))?;
    let packages = std::str::from_utf8(bytes.as_bytes())
        .map_err(|_| BackupError("backup requires patched system OpenSSL"))?;
    let versions: Vec<_> = packages.lines().collect();
    if versions.len() != 2 {
        return Err(BackupError("backup requires patched system OpenSSL"));
    }
    for (index, version) in versions.iter().enumerate() {
        let mut compare = Command::new("/usr/bin/dpkg");
        compare.args(["--compare-versions", version, "ge", minimum]);
        tool(
            compare,
            None,
            private_create(&stage.member(&format!("version-check-{index}")))?,
        )
        .map_err(|_| BackupError("backup requires patched system OpenSSL"))?;
    }
    Ok(())
}

/// Explicit creation only: a dedicated RSA-3072 recovery key and certificate.
/// Keep an offline protected copy; this is not a controller identity key.
pub fn initialize_recovery_key(path: &Path) -> Result<()> {
    generate_credential(
        path,
        "/CN=BlindPass backup recovery",
        "digitalSignature,keyEncipherment",
        None,
    )
}

/// Creates one role credential (private key and certificate) and a certificate-only
/// copy, both mode 0600 in the same private directory, never overwriting either.
/// Signing: the credential stays on the backup host, the certificate goes to the
/// operator. Recipient: the credential stays offline, the certificate goes to the
/// backup host.
pub fn initialize_role_credentials(
    role: KeyRole,
    credential: &Path,
    certificate: &Path,
) -> Result<()> {
    let (subject, usage) = match role {
        KeyRole::Signing => ("/CN=BlindPass backup signing", "digitalSignature"),
        KeyRole::Recipient => ("/CN=BlindPass backup recipient", "keyEncipherment"),
    };
    generate_credential(credential, subject, usage, Some(certificate))
}

fn generate_credential(
    path: &Path,
    subject: &str,
    key_usage: &str,
    certificate_output: Option<&Path>,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(BackupError("unsafe recovery key output"))?;
    if let Some(certificate) = certificate_output
        && certificate.parent() != Some(parent)
    {
        return Err(BackupError(
            "credential and certificate outputs must share one directory",
        ));
    }
    let directory = Directory::open_private(parent)
        .map_err(|_| BackupError("unsafe recovery key directory"))?;
    // A concurrent fork in this process can hold a copy of the descriptor for a
    // moment before it execs, so absorb a transient conflict before reporting busy.
    let mut attempts = 0;
    while directory.lock(true).is_err() {
        attempts += 1;
        if attempts >= 40 {
            return Err(BackupError("recovery key directory busy"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if let Some(certificate) = certificate_output
        && fs::symlink_metadata(certificate).is_ok()
    {
        return Err(BackupError("recovery certificate output already exists"));
    }
    let stage = Stage::new(parent)?;
    require_patched_openssl(&stage)?;
    let key = stage.member("private.pem");
    drop(private_create(&key)?);
    let cert = stage.member("certificate.pem");
    let mut command = openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:3072",
        "-nodes",
        "-sha256",
        "-days",
        "36500",
        "-subj",
        subject,
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
    ]);
    command
        .arg(format!("keyUsage=critical,{key_usage}"))
        .arg("-keyout");
    command.arg(&key);
    tool(command, None, private_create(&cert)?)?;
    let private =
        read_private_file(&key, 8192).map_err(|_| BackupError("recovery key generation failed"))?;
    let certificate = read_private_file(&cert, 8192)
        .map_err(|_| BackupError("recovery certificate generation failed"))?;
    let mut output = private_create(path)?;
    let result = output
        .write_all(private.as_bytes())
        .and_then(|()| output.write_all(certificate.as_bytes()))
        .and_then(|()| output.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(path);
        return Err(BackupError("recovery key write failed"));
    }
    if let Some(certificate_path) = certificate_output {
        let written = private_create(certificate_path).and_then(|mut file| {
            file.write_all(certificate.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| BackupError("recovery certificate write failed"))
        });
        if let Err(error) = written {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(certificate_path);
            return Err(error);
        }
    }
    directory
        .sync()
        .map_err(|_| BackupError("recovery key flush failed"))
}

/// The input is already a private complete bundle. Neither secret key bytes nor
/// plaintext are command-line arguments or diagnostics. No output overwrite.
pub fn encrypt_bundle(input: &Path, output: &Path, key: &Path, work: &Path) -> Result<()> {
    encrypt_bundle_with(input, output, &SealKeys::Single(key), work)
}

pub fn encrypt_bundle_with(
    input: &Path,
    output: &Path,
    keys: &SealKeys<'_>,
    work: &Path,
) -> Result<()> {
    match keys {
        SealKeys::Single(key) => {
            let stage = Stage::new(work)?;
            require_patched_openssl(&stage)?;
            let credential = stage.credential(key)?;
            seal(
                &stage,
                input,
                output,
                &credential,
                std::slice::from_ref(&credential),
            )
        }
        SealKeys::Split {
            signing_credential,
            recipient_certificate,
        } => encrypt_bundle_to(
            input,
            output,
            signing_credential,
            &[recipient_certificate],
            work,
        ),
    }
}

/// Split-model sealing: sign with the signing credential and encrypt to every
/// certificate-only recipient file (the offline recipient and, at create time, a
/// throwaway verification recipient). A recipient file with a private key, or one
/// whose certificate equals the signer's, is refused before anything is written.
pub fn encrypt_bundle_to(
    input: &Path,
    output: &Path,
    signing_credential: &Path,
    recipient_certificates: &[&Path],
    work: &Path,
) -> Result<()> {
    if recipient_certificates.is_empty() || recipient_certificates.len() > 4 {
        return Err(BackupError("backup requires one to four recipients"));
    }
    let stage = Stage::new(work)?;
    require_patched_openssl(&stage)?;
    let signer = stage.credential_as(signing_credential, "signing.pem")?;
    let (_, signer_certificate) =
        stage.certificate_as(&signer, "signing-certificate.pem", false)?;
    let mut recipients = Vec::new();
    let mut seen = vec![signer_certificate];
    for (index, file) in recipient_certificates.iter().enumerate() {
        let (path, certificate) =
            stage.certificate_as(file, &format!("recipient-{index}.pem"), true)?;
        if seen.contains(&certificate) {
            return Err(BackupError(
                "backup recipient certificate must differ from every other role",
            ));
        }
        seen.push(certificate);
        recipients.push(path);
    }
    seal(&stage, input, output, &signer, &recipients)
}

fn seal(
    stage: &Stage,
    input: &Path,
    output: &Path,
    signer: &Path,
    recipients: &[PathBuf],
) -> Result<()> {
    let encrypted = stage.member("encrypted.der");
    let mut encrypt = openssl(&[
        "cms",
        "-encrypt",
        "-binary",
        "-aes-256-gcm",
        "-outform",
        "DER",
    ]);
    for recipient in recipients {
        encrypt.arg("-recip").arg(recipient).args([
            "-keyopt",
            "rsa_padding_mode:oaep",
            "-keyopt",
            "rsa_oaep_md:sha256",
        ]);
    }
    tool(
        encrypt,
        Some(private_input(input, MAX_BUNDLE_BYTES)?),
        private_create(&encrypted)?,
    )?;
    let signed = stage.member("signed.der");
    let mut sign = openssl(&[
        "cms",
        "-sign",
        "-binary",
        "-nodetach",
        "-nocerts",
        "-md",
        "sha256",
        "-outform",
        "DER",
        "-signer",
    ]);
    sign.arg(signer).arg("-inkey").arg(signer).args([
        "-keyopt",
        "rsa_padding_mode:pss",
        "-keyopt",
        "rsa_pss_saltlen:digest",
        "-passin",
        "pass:",
    ]);
    tool(
        sign,
        Some(private_input(&encrypted, MAX_ENVELOPE_BYTES)?),
        private_create(&signed)?,
    )?;
    publish(&signed, output)
}

/// Authenticated decryption AND signature verification with the independently
/// supplied exact recovery certificate. Never trust an embedded signer cert.
pub fn decrypt_bundle(input: &Path, output: &Path, key: &Path, work: &Path) -> Result<()> {
    decrypt_bundle_with(input, output, &OpenKeys::Single(key), work)
}

pub fn decrypt_bundle_with(
    input: &Path,
    output: &Path,
    keys: &OpenKeys<'_>,
    work: &Path,
) -> Result<()> {
    let stage = Stage::new(work)?;
    require_patched_openssl(&stage)?;
    let (signer, recipient) = match keys {
        OpenKeys::Single(key) => {
            let credential = stage.credential(key)?;
            (credential.clone(), credential)
        }
        OpenKeys::Split {
            recipient_key,
            signing_certificate,
        } => {
            let recipient = stage.credential_as(recipient_key, "recipient.pem")?;
            let (signer, _) =
                stage.certificate_as(signing_certificate, "signer-certificate.pem", false)?;
            (signer, recipient)
        }
    };
    // Verify the pinned signer BEFORE passing attacker-controlled AEAD
    // parameters to the CMS decryptor. No embedded certificate is trusted.
    let mut signed_input = private_input(input, MAX_ENVELOPE_BYTES)?;
    require_content_info(
        &mut signed_input,
        &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        ],
    )?;
    use std::io::{Seek, SeekFrom};
    signed_input
        .seek(SeekFrom::Start(0))
        .map_err(|_| BackupError("backup input unavailable"))?;
    let encrypted = stage.member("authenticated.der");
    let mut verify = openssl(&[
        "cms",
        "-verify",
        "-binary",
        "-inform",
        "DER",
        "-nointern",
        "-noverify",
        "-certfile",
    ]);
    verify.arg(&signer);
    tool(verify, Some(signed_input), private_create(&encrypted)?)?;
    let mut file = private_input(&encrypted, MAX_ENVELOPE_BYTES)?;
    require_auth_envelope(&mut file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BackupError("backup input unavailable"))?;
    let plain = stage.member("verified.tar");
    let mut decrypt = openssl(&["cms", "-decrypt", "-binary", "-inform", "DER", "-recip"]);
    decrypt
        .arg(&recipient)
        .arg("-inkey")
        .arg(&recipient)
        .args(["-passin", "pass:"]);
    tool(decrypt, Some(file), private_create(&plain)?)?;
    if fs::metadata(&plain)
        .map_err(|_| BackupError("backup output unavailable"))?
        .len()
        > MAX_BUNDLE_BYTES
    {
        return Err(BackupError("backup output exceeds limit"));
    }
    publish(&plain, output)
}

// A narrow ContentInfo header check, not an ASN.1 decoder. OpenSSL parses the
// CMS body. Accept only definite-length DER and the AuthEnvelopedData OID;
// generic CMS decryption otherwise also accepts unauthenticated CBC envelopes.
fn require_auth_envelope(file: &mut File) -> Result<()> {
    require_content_info(
        file,
        &[
            0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x17,
        ],
    )
}
fn require_content_info(file: &mut File, oid: &[u8]) -> Result<()> {
    let mut header = [0u8; 24];
    file.read_exact(&mut header)
        .map_err(|_| BackupError("invalid backup envelope"))?;
    if header[0] != 0x30 {
        return Err(BackupError("invalid backup envelope"));
    }
    let (length, offset) = if header[1] < 128 {
        (u64::from(header[1]), 2)
    } else {
        let n = usize::from(header[1] & 127);
        if n == 0 || n > 8 || header[2] == 0 {
            return Err(BackupError("invalid backup envelope"));
        }
        let length = header[2..2 + n]
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        if length < 128 {
            return Err(BackupError("invalid backup envelope"));
        }
        (length, 2 + n)
    };
    if length.checked_add(offset as u64)
        != Some(
            file.metadata()
                .map_err(|_| BackupError("invalid backup envelope"))?
                .len(),
        )
        || header.get(offset..offset + oid.len()) != Some(oid)
    {
        return Err(BackupError("backup CMS content type mismatch"));
    }
    Ok(())
}

fn publish(input: &Path, output: &Path) -> Result<()> {
    let directory =
        Directory::open_private(output.parent().ok_or(BackupError("unsafe backup output"))?)
            .map_err(|_| BackupError("unsafe backup output"))?;
    // link+unlink is atomic no-replace publication on this same filesystem.
    fs::hard_link(input, output)
        .map_err(|_| BackupError("backup output already exists or cannot be published"))?;
    if fs::remove_file(input).is_err() || directory.sync().is_err() {
        let _ = fs::remove_file(output);
        return Err(BackupError("backup publication failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn p06_b10_cms_parser_requires_upstream_fix_or_explicit_vendor_backport_check() {
        for version in [
            "3.0.19", "3.0.22", "3.3.6", "3.4.4", "3.5.5", "3.6.1", "3.6.4",
        ] {
            assert!(
                upstream_openssl_patched(version),
                "rejected fixed upstream version"
            );
        }
        for version in [
            "3.0.17",
            "3.0.18",
            "3.0.13",
            "3.3.5",
            "3.4.3",
            "3.5.4",
            "3.6.0",
            "1.1.1",
            "3.6.1-alpha",
            "junk",
        ] {
            assert!(
                !upstream_openssl_patched(version),
                "accepted vulnerable or unknown version"
            );
        }
    }
    #[test]
    fn p06_b10_hanging_child_is_killed_reaped_and_has_fixed_diagnostic() {
        let parent = std::env::temp_dir();
        // The system /tmp is not a private work directory; create a fixture
        // explicitly before exercising the same real child lifecycle.
        let path = parent.join(format!(
            "blindpass-backup-timeout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let stage = Stage(path);
        let output = stage.member("output");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf '%s' \"$$\"; exec /usr/bin/sleep 10"]);
        let start = Instant::now();
        let error = tool_with_deadline(
            command,
            None,
            private_create(&output).unwrap(),
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(error.to_string(), "backup tool timed out");
        let pid = fs::read_to_string(&output).unwrap();
        assert!(pid.parse::<u32>().is_ok());
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "timed-out child was not reaped"
        );
        let mut missing = Command::new("/p06-dummy-missing-backup-tool");
        missing.arg("P06-DUMMY-NOT-IN-DIAGNOSTICS");
        let error = tool(
            missing,
            None,
            private_create(&stage.member("missing")).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "backup tool unavailable");
    }
}
