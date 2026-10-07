// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated isolated restoration. Publication always remains fenced;
//! neither local drainage nor this command is previous-host stop proof.
use crate::{
    backup::{Backend, BackupError, OPEN_OPTIONS, OpenArgs, Stage, copy_private_file},
    recovery_authority::{Authority, AuthorityContext, ProcessOwnership},
    store::{FleetSigner, Store},
};
use blindpass_core::{
    deployment::{Directory, KEY_NAMES, read_private_file},
    signing::{base64_url_encode, ed25519::Ed25519KeyPair},
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const REFUSAL: BackupError = BackupError("authenticated fenced restore refused");
type Result<T> = std::result::Result<T, BackupError>;
struct Options {
    archive: PathBuf,
    open: OpenArgs,
    destination: PathBuf,
    authority_url: PathBuf,
    /// PostgreSQL archives restore into this empty target; SQLite archives never take it.
    database_url: Option<PathBuf>,
    tenant: String,
    owner: String,
    recovery_id: String,
}
fn opaque(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        if !args.len().is_multiple_of(2) {
            return Err(REFUSAL);
        }
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            if !matches!(
                pair[0].as_str(),
                "--archive"
                    | "--destination"
                    | "--authority-url-file"
                    | "--database-url-file"
                    | "--tenant-id"
                    | "--owner-id"
                    | "--recovery-id"
            ) && !OPEN_OPTIONS.contains(&pair[0].as_str())
                || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err(REFUSAL);
            }
        }
        let path = |key| -> Result<PathBuf> {
            let p = PathBuf::from(*values.get(key).ok_or(REFUSAL)?);
            if !p.is_absolute() {
                return Err(REFUSAL);
            }
            Ok(p)
        };
        let identifier = |key| -> Result<String> {
            let s = *values.get(key).ok_or(REFUSAL)?;
            if !opaque(s) {
                return Err(REFUSAL);
            }
            Ok(s.to_owned())
        };
        Ok(Self {
            archive: path("--archive")?,
            open: OpenArgs::from_values(&values).map_err(|_| REFUSAL)?,
            destination: path("--destination")?,
            authority_url: path("--authority-url-file")?,
            database_url: values
                .contains_key("--database-url-file")
                .then(|| path("--database-url-file"))
                .transpose()?,
            tenant: identifier("--tenant-id")?,
            owner: identifier("--owner-id")?,
            recovery_id: identifier("--recovery-id")?,
        })
    }
}

pub async fn run_command(args: &[String]) -> Result<()> {
    let options = Options::parse(args)?;
    let started = Instant::now();
    let parent_path = options.destination.parent().ok_or(REFUSAL)?;
    let target = options
        .destination
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .ok_or(REFUSAL)?;
    let parent = Directory::open_private(parent_path).map_err(|_| REFUSAL)?;
    parent.lock(true).map_err(|_| REFUSAL)?;
    // Existing names, including dangling links, are always preserved. The
    // kernel no-replace operation also protects the eventual publication race.
    match fs::symlink_metadata(&options.destination) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(REFUSAL),
    }
    let verified = options
        .open
        .open(&options.archive, parent_path)
        .await
        .map_err(|_| REFUSAL)?;
    // The argument form must match the archive: a PostgreSQL archive restores into
    // an explicit target database, a SQLite archive into a staged directory.
    let form_matches = match verified.manifest.backend {
        Backend::Sqlite => options.database_url.is_none(),
        Backend::Postgres => options.database_url.is_some(),
    };
    if !form_matches || verified.manifest.snapshot.tenant_id != options.tenant {
        return Err(REFUSAL);
    }
    let seed = read_private_file(&verified.member("issuer-key"), 32).map_err(|_| REFUSAL)?;
    let key = Ed25519KeyPair::from_seed(seed.as_bytes()).map_err(|_| REFUSAL)?;
    let key_id = format!("ed25519-{}", base64_url_encode(key.public_key()));
    drop(seed);
    let context = AuthorityContext {
        tenant_id: options.tenant.clone(),
        issuer_key_id: key_id.clone(),
        owner_id: options.owner.clone(),
    };
    let url = read_private_file(&options.authority_url, 16 * 1024).map_err(|_| REFUSAL)?;
    let url_text = std::str::from_utf8(url.as_bytes())
        .map_err(|_| REFUSAL)?
        .trim();
    let authority = Authority::connect_existing(url_text)
        .await
        .map_err(|_| REFUSAL)?;
    drop(url);
    let result = async {
        let record = authority.read(&context).await.map_err(|_| REFUSAL)?;
        if record.phase != "recovering"
            || record.epoch <= verified.manifest.snapshot.recovery_generation
        {
            return Err(REFUSAL);
        }
        let owner = Arc::new(
            authority
                .claim_process(&context, &record)
                .await
                .map_err(|_| REFUSAL)?,
        );
        let monitor = owner.spawn_monitor();
        let result = restore_stage(
            &options,
            &verified,
            Arc::new(key),
            &key_id,
            &owner,
            &parent,
            target,
            started,
        )
        .await;
        monitor.abort();
        let _ = monitor.await;
        let drained = owner.quiesce().await.map_err(|_| REFUSAL);
        let receipt = result?;
        drained?;
        Ok(receipt)
    }
    .await;
    authority.close().await;
    let receipt = result?;
    println!("{receipt}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn restore_stage(
    options: &Options,
    verified: &crate::backup::VerifiedBackup,
    key: Arc<Ed25519KeyPair>,
    key_id: &str,
    owner: &Arc<ProcessOwnership>,
    parent: &Directory,
    target: &str,
    started: Instant,
) -> Result<serde_json::Value> {
    let stage = Stage::new(options.destination.parent().ok_or(REFUSAL)?)?;
    let postgres = verified.manifest.backend == Backend::Postgres;
    let directories: &[&str] = if postgres {
        &["keys"]
    } else {
        &["keys", "data"]
    };
    for name in directories {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(stage.member(name))
            .map_err(|_| REFUSAL)?;
    }
    // Only a schema this command restored into an empty PostgreSQL target is
    // ever removed again, and only before publication.
    let mut restored: Option<(String, String)> = None;
    let url = if postgres {
        let text = read_private_file(options.database_url.as_ref().ok_or(REFUSAL)?, 16 * 1024)
            .map_err(|_| REFUSAL)?;
        let url = std::str::from_utf8(text.as_bytes())
            .map_err(|_| REFUSAL)?
            .trim()
            .to_owned();
        drop(text);
        let connection = crate::backup::postgres::PgConnection::parse(&url).map_err(|_| REFUSAL)?;
        let schema = crate::backup::postgres::restore_into_target(
            &connection,
            &url,
            &verified.member("database.pgcustom"),
            &verified.manifest.snapshot,
            &stage,
        )
        .await
        .map_err(|error| {
            if error.0 == crate::backup::postgres::EMPTY_SCHEMA_REFUSAL.0 {
                error
            } else {
                REFUSAL
            }
        })?;
        restored = Some((url.clone(), schema));
        url
    } else {
        let database = stage.member("data/controller.db");
        // Decrypted members live on tmpfs; the store opens a copy on the stage.
        copy_private_file(&verified.member("database.sqlite"), &database).map_err(|_| REFUSAL)?;
        sqlite_url(&database)
    };
    let outcome = restore_prepare_and_publish(
        options, verified, key, key_id, owner, parent, target, started, &stage, &url, postgres,
    )
    .await;
    if let (Err(_), Some((url, schema))) = (&outcome, &restored)
        && !published(&options.destination)
    {
        let _ = crate::store::backup::drop_restored_schema(url, schema).await;
    }
    outcome
}

/// A published destination is retained even if proof is lost afterwards.
fn published(destination: &Path) -> bool {
    fs::symlink_metadata(destination).is_ok()
}

#[allow(clippy::too_many_arguments)]
async fn restore_prepare_and_publish(
    options: &Options,
    verified: &crate::backup::VerifiedBackup,
    key: Arc<Ed25519KeyPair>,
    key_id: &str,
    owner: &Arc<ProcessOwnership>,
    parent: &Directory,
    target: &str,
    started: Instant,
    stage: &Stage,
    url: &str,
    postgres: bool,
) -> Result<serde_json::Value> {
    crate::p02_test_failpoint("restore_after_extract");
    let store = Store::connect_existing_for_restore(
        url,
        owner.clone(),
        key_id,
        &verified.manifest.snapshot,
    )
    .await
    .map_err(|_| REFUSAL)?
    .with_fleet_signer(FleetSigner::new(key));
    let prepared = async {
        store.bind_verified_recovery_snapshot(owner, &options.recovery_id, verified).await.map_err(|_| REFUSAL)?;
        let status = store.invalidate_recovery(owner, &options.recovery_id).await.map_err(|_| REFUSAL)?;
        if status.phase != "invalidated" || !store.recovery_required() { return Err(REFUSAL); }
        crate::p02_test_failpoint("restore_after_invalidate");
        store.checkpoint_restore(owner).await.map_err(|_| REFUSAL)?;
        Ok(serde_json::json!({"phase":"recovery_required", "activation_permitted":false, "target_epoch":status.target_epoch, "snapshot_epoch":status.snapshot_epoch, "schema_version":crate::store::SCHEMA_VERSION, "backend":if postgres {"postgres"} else {"sqlite"}, "recovery_id":options.recovery_id}))
    }.await;
    store.close().await;
    let receipt = prepared?;
    // Keys reach persistent storage only now, after every step that can still fail.
    for name in KEY_NAMES {
        let from = verified.member(name);
        copy_private_file(&from, &stage.member("keys").join(name)).map_err(|_| REFUSAL)?;
        fs::remove_file(from).map_err(|_| REFUSAL)?;
    }
    let mut receipt_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(stage.member("restore.json"))
        .map_err(|_| REFUSAL)?;
    receipt_file
        .write_all(
            serde_json::to_string(&receipt)
                .map_err(|_| REFUSAL)?
                .as_bytes(),
        )
        .map_err(|_| REFUSAL)?;
    receipt_file.sync_all().map_err(|_| REFUSAL)?;
    let synced: &[&str] = if postgres {
        &["keys"]
    } else {
        &["keys", "data"]
    };
    for directory in synced.iter().map(|name| stage.member(name)) {
        for entry in fs::read_dir(&directory).map_err(|_| REFUSAL)? {
            File::open(entry.map_err(|_| REFUSAL)?.path())
                .and_then(|f| f.sync_all())
                .map_err(|_| REFUSAL)?;
        }
        Directory::open_private(&directory)
            .and_then(|d| d.sync())
            .map_err(|_| REFUSAL)?;
    }
    owner.check().await.map_err(|_| REFUSAL)?;
    // The SQLite stage is bounded at one minute; a PostgreSQL restore may spend up
    // to the toolkit's own restore deadline before publication.
    let bound = if postgres { 360 } else { 60 };
    if started.elapsed() >= Duration::from_secs(bound) {
        return Err(REFUSAL);
    }
    let _publication = owner.begin_recovery_operation().map_err(|_| REFUSAL)?;
    crate::p02_test_failpoint("restore_before_publish");
    #[cfg(feature = "p02-test-failpoints")]
    if std::env::var("BLINDPASS_TEST_MODE").as_deref() == Ok("1")
        && std::env::var("BLINDPASS_TEST_FAILPOINT").as_deref()
            == Ok("restore_pause_before_publish")
    {
        // Dedicated fault build only: stop this process at the publication
        // boundary so the test can revoke its actual external socket.
        let status = std::process::Command::new("/bin/kill")
            .args(["-STOP", &std::process::id().to_string()])
            .status()
            .map_err(|_| REFUSAL)?;
        if !status.success() {
            return Err(REFUSAL);
        }
    }
    owner.check().await.map_err(|_| REFUSAL)?;
    let source = stage
        .0
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(REFUSAL)?;
    parent
        .publish_directory(source, target)
        .map_err(|_| REFUSAL)?;
    // If proof is lost after rename, retain the published fenced destination.
    // Failure is never an excuse to erase potentially durable recovered state.
    owner.check().await.map_err(|_| REFUSAL)?;
    Ok(receipt)
}

/// Encode path bytes so query/fragment characters cannot alter SQLite options.
fn sqlite_url(path: &Path) -> String {
    let mut url = String::from("sqlite://");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
            url.push(*byte as char);
        } else {
            url.push_str(&format!("%{byte:02X}"));
        }
    }
    url.push_str("?mode=rw");
    url
}
