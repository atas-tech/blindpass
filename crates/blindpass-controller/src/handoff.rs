// SPDX-License-Identifier: AGPL-3.0-only
//! Planned same-owner handoff of a SQLite controller (P06-D28).
//!
//! This is not a restore. The source is stopped and its authority record is
//! `fenced`; `export` seals the existing authenticated archive and persists a
//! retirement marker next to the database so the stale copy can never serve or
//! migrate again. `import` publishes the archive into a new private root under
//! the SAME owner and unchanged epoch, without recovery reservation or
//! invalidation, and leaves the record fenced for the operator's ordinary
//! activation. Two sequential holders are kept apart by the exact authority
//! revision: abort needs the exported revision unchanged, and a destination's
//! first start needs the revision directly after it. Neither command is
//! previous-host stop proof.
use crate::{
    backup::{
        self, Backend, BackupError, OPEN_OPTIONS, OpenArgs, SEAL_OPTIONS, SealArgs, SealKeys,
        Stage, copy_private_file, create_backup_with,
    },
    config::Config,
    ownership_session::claim_ownership,
    recovery_authority::{Authority, AuthorityContext, ProcessOwnership},
    store::{SCHEMA_VERSION, StoreError},
};
use blindpass_core::{
    deployment::{Directory, KEY_NAMES, read_private_file},
    signing::{base64_url_encode, ed25519::Ed25519KeyPair},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const MARKER_NAME: &str = "handoff-marker.json";
const ROLE_RECEIPT: &str = "receipt";
const ROLE_SOURCE: &str = "source";
const ROLE_DESTINATION: &str = "destination";
const SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Reasons the startup guards report through `store_failure_reason`.
pub(crate) const RETIRED: &str = "source retired by handoff";
pub(crate) const STALE: &str = "destination activation does not match handoff";

type Result<T> = std::result::Result<T, BackupError>;
const EXPORT_REFUSED: BackupError = BackupError("handoff export refused");
const IMPORT_REFUSED: BackupError = BackupError("handoff import refused");
const ABORT_REFUSED: BackupError = BackupError("handoff abort refused");
const OPEN: BackupError = BackupError("a different handoff is already open for this source");
const ACTIVATED: BackupError =
    BackupError("authority moved after the export; rollback is restore-only");

fn opaque(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Receipt written beside the archive, the source's retirement marker and the
/// destination's pending-activation marker share one fixed layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    role: String,
    handoff_id: String,
    tenant_id: String,
    issuer_key_id: String,
    owner_id: String,
    epoch: u64,
    revision: u64,
    archive: String,
    archive_sha256: String,
    created_ms: u64,
    /// Destination only: a start attempt already consumed a revision.
    attempted: bool,
}

impl Record {
    fn valid(&self, role: &str) -> bool {
        self.version == 1
            && self.role == role
            && [
                &self.handoff_id,
                &self.tenant_id,
                &self.issuer_key_id,
                &self.owner_id,
            ]
            .iter()
            .all(|value| opaque(value))
            && (1..=SAFE_INTEGER).contains(&self.epoch)
            && (1..=SAFE_INTEGER).contains(&self.revision)
            && self.archive.len() <= 128
            && self.archive.ends_with(".bpbackup")
            && self
                .archive
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            && !self.archive.starts_with('.')
            && self.archive_sha256.len() == 64
            && self
                .archive_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && !(self.attempted && self.role != ROLE_DESTINATION)
    }
    fn same_authority(&self, context: &AuthorityContext, epoch: u64, revision: u64) -> bool {
        self.tenant_id == context.tenant_id
            && self.issuer_key_id == context.issuer_key_id
            && self.owner_id == context.owner_id
            && self.epoch == epoch
            && self.revision == revision
    }
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(BackupError("system clock unavailable"))
}

/// Filesystem path of a SQLite controller database, or `None` for another
/// backend or an in-memory database (no handoff state can live there).
pub(crate) fn database_path(url: &str) -> Option<PathBuf> {
    let rest = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))?;
    let path = rest.split(['?', '#']).next()?;
    if path.is_empty() || path.starts_with(":memory:") {
        return None;
    }
    let mut decoded = Vec::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    let path = PathBuf::from(String::from_utf8(decoded).ok()?);
    if path.is_absolute() {
        Some(path)
    } else {
        std::env::current_dir().ok().map(|dir| dir.join(path))
    }
}

fn marker_path(url: &str) -> Option<PathBuf> {
    database_path(url)?
        .parent()
        .map(|dir| dir.join(MARKER_NAME))
}

fn read_record(path: &Path, role: &str) -> Result<Option<Record>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BackupError("handoff record unavailable")),
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(BackupError("handoff record unavailable"));
        }
        Ok(_) => {}
    }
    let bytes = read_private_file(path, 16 * 1024)
        .map_err(|_| BackupError("handoff record is unsafe or unreadable"))?;
    let record: Record = serde_json::from_slice(bytes.as_bytes())
        .map_err(|_| BackupError("handoff record is invalid"))?;
    if !record.valid(role) {
        return Err(BackupError("handoff record is invalid"));
    }
    Ok(Some(record))
}

fn temporary_name() -> String {
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!(".handoff-{suffix}.tmp")
}

fn write_temporary(directory: &Path, record: &Record) -> Result<PathBuf> {
    let path = directory.join(temporary_name());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(
            blindpass_core::open_flags::O_NOFOLLOW | blindpass_core::open_flags::O_CLOEXEC,
        )
        .open(&path)
        .map_err(|_| BackupError("handoff record could not be written"))?;
    let bytes = serde_json::to_vec(record).map_err(|_| BackupError("handoff record invalid"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            let _ = fs::remove_file(&path);
            BackupError("handoff record could not be written")
        })?;
    Ok(path)
}

fn sync_directory(directory: &Path) -> Result<()> {
    Directory::open_private(directory)
        .and_then(|d| d.sync())
        .map_err(|_| BackupError("handoff record could not be flushed"))
}

/// Create a record that must not exist yet: the temporary file is linked, never
/// renamed, so an existing name is preserved.
fn write_new(path: &Path, record: &Record) -> Result<()> {
    let directory = path
        .parent()
        .ok_or(BackupError("unsafe handoff location"))?;
    Directory::open_private(directory).map_err(|_| BackupError("unsafe handoff location"))?;
    let temporary = write_temporary(directory, record)?;
    let linked = fs::hard_link(&temporary, path);
    let _ = fs::remove_file(&temporary);
    linked.map_err(|_| BackupError("handoff record already exists or is unavailable"))?;
    sync_directory(directory)
}

fn replace_record(path: &Path, record: &Record) -> Result<()> {
    let directory = path
        .parent()
        .ok_or(BackupError("unsafe handoff location"))?;
    let temporary = write_temporary(directory, record)?;
    fs::rename(&temporary, path).map_err(|_| {
        let _ = fs::remove_file(&temporary);
        BackupError("handoff record could not be replaced")
    })?;
    sync_directory(directory)
}

fn remove_record(path: &Path) -> Result<()> {
    let directory = path
        .parent()
        .ok_or(BackupError("unsafe handoff location"))?;
    fs::remove_file(path).map_err(|_| BackupError("handoff record could not be removed"))?;
    sync_directory(directory)
}

fn pairs<'a>(args: &'a [String], allowed: &[&str]) -> Option<BTreeMap<&'a str, &'a str>> {
    if !args.len().is_multiple_of(2) {
        return None;
    }
    let mut values = BTreeMap::new();
    for pair in args.as_chunks::<2>().0 {
        if !allowed.contains(&pair[0].as_str())
            || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return None;
        }
    }
    Some(values)
}

fn absolute(values: &BTreeMap<&str, &str>, key: &str) -> Option<PathBuf> {
    let path = PathBuf::from(*values.get(key)?);
    path.is_absolute().then_some(path)
}

fn identifier(values: &BTreeMap<&str, &str>, key: &str) -> Option<String> {
    let value = *values.get(key)?;
    opaque(value).then(|| value.to_owned())
}

pub async fn run_command(args: &[String]) -> Result<()> {
    match args.split_first() {
        Some((action, rest)) if action == "export" => export(rest).await,
        Some((action, rest)) if action == "import" => import(rest).await,
        Some((action, rest)) if action == "abort" => abort(rest).await,
        _ => Err(BackupError("unknown handoff command")),
    }
}

/// Maintenance claim over the fenced record of the controller named by the
/// ordinary environment, plus the marker location of its SQLite database.
async fn claim_source(
    config: &Config,
    refused: BackupError,
) -> Result<(crate::ownership_session::OwnershipSession, PathBuf)> {
    let marker = marker_path(config.database_url()).ok_or(refused)?;
    let session = claim_ownership(config, true)
        .await
        .map_err(|_| refused)?
        .ok_or(refused)?;
    Ok((session, marker))
}

async fn finish_session(mut session: crate::ownership_session::OwnershipSession) {
    session.monitor.abort();
    let _ = (&mut session.monitor).await;
    let _ = session.owner.quiesce().await;
    session.close_authority().await;
}

async fn export(args: &[String]) -> Result<()> {
    let mut allowed = vec!["--output", "--handoff-id"];
    allowed.extend(SEAL_OPTIONS);
    let values = pairs(args, &allowed).ok_or(EXPORT_REFUSED)?;
    let output = absolute(&values, "--output").ok_or(EXPORT_REFUSED)?;
    let seal = SealArgs::from_values(&values).map_err(|_| EXPORT_REFUSED)?;
    // output, handoff id and exactly one credential model, nothing else.
    if values.len()
        != 2 + if values.contains_key("--recovery-key-file") {
            1
        } else {
            2
        }
    {
        return Err(EXPORT_REFUSED);
    }
    let id = identifier(&values, "--handoff-id").ok_or(EXPORT_REFUSED)?;
    let config = Config::from_env_offline().map_err(|_| EXPORT_REFUSED)?;
    let (session, marker) = claim_source(&config, EXPORT_REFUSED).await?;
    let result = export_claimed(&session.owner, &marker, &output, &seal.keys(), &id).await;
    finish_session(session).await;
    println!("{}", result?);
    Ok(())
}

async fn export_claimed(
    owner: &Arc<ProcessOwnership>,
    marker: &Path,
    output: &Path,
    keys: &SealKeys<'_>,
    id: &str,
) -> Result<serde_json::Value> {
    let (context, record) = owner.recovery_context();
    if record.phase != "fenced" {
        return Err(EXPORT_REFUSED);
    }
    let receipt_name = format!("handoff-{id}.json");
    if let Some(existing) = read_record(marker, ROLE_SOURCE)? {
        // An interrupted export of the same handoff repeats to the same receipt.
        if existing.handoff_id != id
            || !existing.same_authority(context, record.epoch, record.revision)
        {
            return Err(OPEN);
        }
        let directory = Directory::open_private(output).map_err(|_| EXPORT_REFUSED)?;
        directory.lock(true).map_err(|_| EXPORT_REFUSED)?;
        let archive = output.join(&existing.archive);
        if backup::archive_digest(&archive, output)? != existing.archive_sha256 {
            return Err(EXPORT_REFUSED);
        }
        ensure_receipt(&output.join(&receipt_name), &existing)?;
        return Ok(summary("exported", &existing, &receipt_name));
    }
    let archive = create_backup_with(output, keys)
        .await
        .map_err(|_| EXPORT_REFUSED)?;
    crate::p02_test_failpoint("handoff_export_after_archive");
    let archive_name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(EXPORT_REFUSED)?
        .to_owned();
    let marker_record = Record {
        version: 1,
        role: ROLE_SOURCE.into(),
        handoff_id: id.to_owned(),
        tenant_id: context.tenant_id.clone(),
        issuer_key_id: context.issuer_key_id.clone(),
        owner_id: context.owner_id.clone(),
        epoch: record.epoch,
        revision: record.revision,
        archive_sha256: backup::archive_digest(&archive, output)?,
        archive: archive_name,
        created_ms: now_ms()?,
        attempted: false,
    };
    owner.check().await.map_err(|_| EXPORT_REFUSED)?;
    write_new(marker, &marker_record)?;
    ensure_receipt(&output.join(&receipt_name), &marker_record)?;
    Ok(summary("exported", &marker_record, &receipt_name))
}

/// The receipt is the marker's public twin: same facts, role `receipt`.
fn ensure_receipt(path: &Path, source: &Record) -> Result<()> {
    let receipt = Record {
        role: ROLE_RECEIPT.into(),
        ..source.clone()
    };
    match read_record(path, ROLE_RECEIPT)? {
        Some(existing) if existing == receipt => Ok(()),
        Some(_) => Err(EXPORT_REFUSED),
        None => write_new(path, &receipt),
    }
}

fn summary(phase: &str, record: &Record, receipt: &str) -> serde_json::Value {
    serde_json::json!({
        "handoff": phase,
        "handoff_id": record.handoff_id,
        "archive": record.archive,
        "receipt": receipt,
        "archive_sha256": record.archive_sha256,
        "epoch": record.epoch,
        "revision": record.revision,
    })
}

async fn abort(args: &[String]) -> Result<()> {
    let values = pairs(args, &["--handoff-id", "--output"])
        .filter(|v| v.contains_key("--handoff-id"))
        .ok_or(ABORT_REFUSED)?;
    let id = identifier(&values, "--handoff-id").ok_or(ABORT_REFUSED)?;
    let output = match values.get("--output") {
        Some(_) => Some(absolute(&values, "--output").ok_or(ABORT_REFUSED)?),
        None => None,
    };
    let config = Config::from_env_offline().map_err(|_| ABORT_REFUSED)?;
    let (session, marker) = claim_source(&config, ABORT_REFUSED).await?;
    let result = abort_claimed(&session.owner, &marker, output.as_deref(), &id).await;
    finish_session(session).await;
    println!("{}", result?);
    Ok(())
}

async fn abort_claimed(
    owner: &Arc<ProcessOwnership>,
    marker: &Path,
    output: Option<&Path>,
    id: &str,
) -> Result<serde_json::Value> {
    let (context, record) = owner.recovery_context();
    let existing = read_record(marker, ROLE_SOURCE)?.ok_or(ABORT_REFUSED)?;
    if existing.handoff_id != id
        || existing.tenant_id != context.tenant_id
        || existing.issuer_key_id != context.issuer_key_id
        || existing.owner_id != context.owner_id
    {
        return Err(ABORT_REFUSED);
    }
    // Any ledger transition after the export moved the revision: a destination
    // may have activated, so the source can no longer be proven current.
    if record.phase != "fenced"
        || record.epoch != existing.epoch
        || record.revision != existing.revision
    {
        return Err(ACTIVATED);
    }
    owner.check().await.map_err(|_| ABORT_REFUSED)?;
    remove_record(marker)?;
    let mut removed = 0;
    if let Some(output) = output {
        // The transfer package must not outlive the handoff it belonged to.
        for name in [format!("handoff-{id}.json"), existing.archive.clone()] {
            if fs::remove_file(output.join(name)).is_ok() {
                removed += 1;
            }
        }
    }
    Ok(serde_json::json!({
        "handoff": "aborted",
        "handoff_id": id,
        "removed_transfer_files": removed,
    }))
}

struct ImportOptions {
    archive: PathBuf,
    receipt: PathBuf,
    open: OpenArgs,
    destination: PathBuf,
    authority_url: PathBuf,
    tenant: String,
    owner: String,
}

impl ImportOptions {
    fn parse(args: &[String]) -> Result<Self> {
        let mut allowed = vec![
            "--archive",
            "--receipt",
            "--destination",
            "--authority-url-file",
            "--tenant-id",
            "--owner-id",
        ];
        allowed.extend(OPEN_OPTIONS);
        let values = pairs(args, &allowed).ok_or(IMPORT_REFUSED)?;
        Ok(Self {
            archive: absolute(&values, "--archive").ok_or(IMPORT_REFUSED)?,
            receipt: absolute(&values, "--receipt").ok_or(IMPORT_REFUSED)?,
            open: OpenArgs::from_values(&values).map_err(|_| IMPORT_REFUSED)?,
            destination: absolute(&values, "--destination").ok_or(IMPORT_REFUSED)?,
            authority_url: absolute(&values, "--authority-url-file").ok_or(IMPORT_REFUSED)?,
            tenant: identifier(&values, "--tenant-id").ok_or(IMPORT_REFUSED)?,
            owner: identifier(&values, "--owner-id").ok_or(IMPORT_REFUSED)?,
        })
    }
}

async fn import(args: &[String]) -> Result<()> {
    let options = ImportOptions::parse(args)?;
    let parent_path = options.destination.parent().ok_or(IMPORT_REFUSED)?;
    let target = options
        .destination
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .ok_or(IMPORT_REFUSED)?;
    let parent = Directory::open_private(parent_path).map_err(|_| IMPORT_REFUSED)?;
    parent.lock(true).map_err(|_| IMPORT_REFUSED)?;
    // Existing names, including dangling links, are always preserved.
    match fs::symlink_metadata(&options.destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(IMPORT_REFUSED),
    }
    let receipt = read_record(&options.receipt, ROLE_RECEIPT)
        .ok()
        .flatten()
        .ok_or(IMPORT_REFUSED)?;
    if receipt.tenant_id != options.tenant || receipt.owner_id != options.owner {
        return Err(IMPORT_REFUSED);
    }
    if options.archive.file_name().and_then(|n| n.to_str()) != Some(receipt.archive.as_str())
        || backup::archive_digest(&options.archive, parent_path).map_err(|_| IMPORT_REFUSED)?
            != receipt.archive_sha256
    {
        return Err(IMPORT_REFUSED);
    }
    let verified = options
        .open
        .open(&options.archive, parent_path)
        .await
        .map_err(|_| IMPORT_REFUSED)?;
    // A handoff moves a current SQLite store of this tree's schema unchanged.
    if verified.manifest.backend != Backend::Sqlite
        || verified.manifest.snapshot.schema_version != SCHEMA_VERSION
        || verified.manifest.snapshot.tenant_id != options.tenant
        || verified.manifest.snapshot.recovery_generation != receipt.epoch
    {
        return Err(IMPORT_REFUSED);
    }
    let seed = read_private_file(&verified.member("issuer-key"), 32).map_err(|_| IMPORT_REFUSED)?;
    let issuer = Ed25519KeyPair::from_seed(seed.as_bytes()).map_err(|_| IMPORT_REFUSED)?;
    let issuer_key_id = format!("ed25519-{}", base64_url_encode(issuer.public_key()));
    drop(seed);
    if issuer_key_id != receipt.issuer_key_id {
        return Err(IMPORT_REFUSED);
    }
    let context = AuthorityContext {
        tenant_id: options.tenant.clone(),
        issuer_key_id,
        owner_id: options.owner.clone(),
    };
    let url = read_private_file(&options.authority_url, 16 * 1024).map_err(|_| IMPORT_REFUSED)?;
    let url_text = std::str::from_utf8(url.as_bytes())
        .map_err(|_| IMPORT_REFUSED)?
        .trim();
    let authority = Authority::connect_existing(url_text)
        .await
        .map_err(|_| IMPORT_REFUSED)?;
    drop(url);
    let result = async {
        let record = authority.read(&context).await.map_err(|_| IMPORT_REFUSED)?;
        // The exact fenced record the export saw: nothing activated or fenced since.
        if record.phase != "fenced"
            || record.epoch != receipt.epoch
            || record.revision != receipt.revision
        {
            return Err(IMPORT_REFUSED);
        }
        let owner = Arc::new(
            authority
                .claim_process(&context, &record)
                .await
                .map_err(|_| IMPORT_REFUSED)?,
        );
        let monitor = owner.spawn_monitor();
        let staged = import_stage(&options, &verified, &receipt, &owner, &parent, target).await;
        monitor.abort();
        let _ = monitor.await;
        let drained = owner.quiesce().await.map_err(|_| IMPORT_REFUSED);
        let summary = staged?;
        drained?;
        Ok(summary)
    }
    .await;
    authority.close().await;
    println!("{}", result?);
    Ok(())
}

async fn import_stage(
    options: &ImportOptions,
    verified: &backup::VerifiedBackup,
    receipt: &Record,
    owner: &Arc<ProcessOwnership>,
    parent: &Directory,
    target: &str,
) -> Result<serde_json::Value> {
    let stage = Stage::new(options.destination.parent().ok_or(IMPORT_REFUSED)?)?;
    for name in ["keys", "data"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(stage.member(name))
            .map_err(|_| IMPORT_REFUSED)?;
    }
    // Decrypted members live on tmpfs; only the database and, last, the keys are
    // copied onto the persistent stage.
    copy_private_file(
        &verified.member("database.sqlite"),
        &stage.member("data/controller.db"),
    )
    .map_err(|_| IMPORT_REFUSED)?;
    let pending = Record {
        role: ROLE_DESTINATION.into(),
        ..receipt.clone()
    };
    write_new(&stage.member("data").join(MARKER_NAME), &pending)?;
    for name in KEY_NAMES {
        let from = verified.member(name);
        copy_private_file(&from, &stage.member("keys").join(name)).map_err(|_| IMPORT_REFUSED)?;
        fs::remove_file(from).map_err(|_| IMPORT_REFUSED)?;
    }
    for directory in ["keys", "data"].map(|name| stage.member(name)) {
        for entry in fs::read_dir(&directory).map_err(|_| IMPORT_REFUSED)? {
            File::open(entry.map_err(|_| IMPORT_REFUSED)?.path())
                .and_then(|f| f.sync_all())
                .map_err(|_| IMPORT_REFUSED)?;
        }
        Directory::open_private(&directory)
            .and_then(|d| d.sync())
            .map_err(|_| IMPORT_REFUSED)?;
    }
    owner.check().await.map_err(|_| IMPORT_REFUSED)?;
    crate::p02_test_failpoint("handoff_import_before_publish");
    let source = stage
        .0
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(IMPORT_REFUSED)?;
    parent
        .publish_directory(source, target)
        .map_err(|_| IMPORT_REFUSED)?;
    // A published destination is retained even if proof is lost afterwards.
    owner.check().await.map_err(|_| IMPORT_REFUSED)?;
    Ok(serde_json::json!({
        "handoff": "imported",
        "handoff_id": receipt.handoff_id,
        "epoch": receipt.epoch,
        "revision": receipt.revision,
        "backend": "sqlite",
        "activation_required": true,
    }))
}

/// A retired source never opens its store again, whatever the record says.
pub(crate) fn refuse_retired_source(url: &str) -> std::result::Result<(), StoreError> {
    let Some(marker) = marker_path(url) else {
        return Ok(());
    };
    match fs::symlink_metadata(&marker) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StoreError::InvalidInput("handoff marker unavailable")),
        Ok(_) => match read_record(&marker, ROLE_SOURCE) {
            Ok(Some(_)) => Err(StoreError::InvalidInput(RETIRED)),
            // A destination marker does not retire anything; a damaged one fails closed.
            _ => match read_record(&marker, ROLE_DESTINATION) {
                Ok(Some(_)) => Ok(()),
                _ => Err(StoreError::InvalidInput("handoff marker unreadable")),
            },
        },
    }
}

/// What a destination's first start may rely on, resolved before the store opens.
pub(crate) struct DestinationStart {
    marker: PathBuf,
}

impl DestinationStart {
    /// Remove the pending marker once the controller has opened its store: the
    /// imported state is adopted and the handoff is over.
    pub(crate) fn consume(self) -> std::result::Result<(), StoreError> {
        remove_record(&self.marker)
            .map_err(|_| StoreError::InvalidInput("handoff marker unavailable"))
    }
}

/// Active start of an imported destination: the first start must hold exactly the
/// revision after the import; after an attempt any later revision does, because by
/// then the source can no longer abort. The attempt is recorded before the store
/// is touched.
pub(crate) fn guard_destination_start(
    url: &str,
    owner: &ProcessOwnership,
) -> std::result::Result<Option<DestinationStart>, StoreError> {
    let Some(marker) = marker_path(url) else {
        return Ok(None);
    };
    let record = match read_record(&marker, ROLE_DESTINATION) {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(None),
        Err(_) => return Err(StoreError::InvalidInput("handoff marker unreadable")),
    };
    let (context, current) = owner.recovery_context();
    let ledger_matches = record.tenant_id == context.tenant_id
        && record.issuer_key_id == context.issuer_key_id
        && record.owner_id == context.owner_id
        && record.epoch == current.epoch;
    let expected = if record.attempted {
        current.revision > record.revision.saturating_add(1)
    } else {
        current.revision == record.revision.saturating_add(1)
    };
    if !ledger_matches || !expected || current.phase != "active" {
        return Err(StoreError::InvalidInput(STALE));
    }
    if !record.attempted {
        let attempted = Record {
            attempted: true,
            ..record
        };
        replace_record(&marker, &attempted)
            .map_err(|_| StoreError::InvalidInput("handoff marker unavailable"))?;
    }
    Ok(Some(DestinationStart { marker }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p06_ho_unit_database_paths_decode_and_other_backends_have_none() {
        assert_eq!(
            database_path("sqlite:///data/controller.db?mode=rwc"),
            Some(PathBuf::from("/data/controller.db"))
        );
        assert_eq!(
            database_path("sqlite:///srv/a%20b/controller.db?mode=rw"),
            Some(PathBuf::from("/srv/a b/controller.db"))
        );
        for url in [
            "postgres://u@h/db",
            "sqlite::memory:",
            "sqlite://",
            "sqlite:///d%zz/x",
        ] {
            assert_eq!(database_path(url), None, "{url}");
        }
        assert_eq!(
            marker_path("sqlite:///data/controller.db?mode=rwc"),
            Some(PathBuf::from("/data/handoff-marker.json"))
        );
    }

    #[test]
    fn p06_ho_unit_records_reject_unknown_fields_and_wrong_roles() {
        let record = Record {
            version: 1,
            role: ROLE_SOURCE.into(),
            handoff_id: "ho_unit".into(),
            tenant_id: "t".into(),
            issuer_key_id: "ed25519-abc".into(),
            owner_id: "o".into(),
            epoch: 1,
            revision: 1,
            archive: "controller-backup-0a.bpbackup".into(),
            archive_sha256: "a".repeat(64),
            created_ms: 1,
            attempted: false,
        };
        assert!(record.valid(ROLE_SOURCE));
        assert!(!record.valid(ROLE_DESTINATION));
        let mut bad = record.clone();
        bad.archive = "../x.bpbackup".into();
        assert!(!bad.valid(ROLE_SOURCE));
        bad = record.clone();
        bad.archive_sha256 = "A".repeat(64);
        assert!(!bad.valid(ROLE_SOURCE));
        bad = record.clone();
        bad.attempted = true;
        assert!(
            !bad.valid(ROLE_SOURCE),
            "only a destination can have attempted"
        );
        let mut value = serde_json::to_value(&record).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Record>(value).is_err());
    }
}
