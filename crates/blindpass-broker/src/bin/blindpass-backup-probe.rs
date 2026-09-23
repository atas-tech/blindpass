// SPDX-License-Identifier: AGPL-3.0-only

//! Small credential-consuming backup/restore fixture for the P01 VM gate.
//! It records only a checksum of the received bytes, never the credential
//! itself, so a restore proves rotation without persisting the canary.

use blindpass_core::delivery::{CredentialFormat, validate_consumer_bytes};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAGIC: &[u8] = b"BP01-BACKUP\0";
const MAX_ARTIFACT_BYTES: usize = 128;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-backup-probe: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut credential_file = None;
    let mut artifact = None;
    let mut mode = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--credential-file" => {
                credential_file = Some(PathBuf::from(next(&args, &mut index)?));
            }
            "--artifact" => artifact = Some(PathBuf::from(next(&args, &mut index)?)),
            "--mode" => mode = Some(next(&args, &mut index)?),
            "--help" | "-h" => {
                println!(
                    "blindpass-backup-probe --credential-file PATH --artifact PATH --mode write|restore"
                );
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
        index += 1;
    }
    let credential_file = credential_file.ok_or("--credential-file is required")?;
    let artifact = artifact.ok_or("--artifact is required")?;
    let mode = mode.ok_or("--mode is required")?;
    let credential = fs::read(credential_file).map_err(|error| error.to_string())?;
    validate_consumer_bytes(
        &credential,
        blindpass_core::MAX_CREDENTIAL_BYTES,
        &CredentialFormat::Prefix(b"P01-".to_vec()),
    )
    .map_err(|error| error.to_string())?;
    let checksum = checksum(&credential);
    match mode.as_str() {
        "write" => write_artifact(&artifact, checksum),
        "restore" => restore_artifact(&artifact, checksum),
        _ => Err("--mode must be write or restore".to_owned()),
    }
}

fn write_artifact(path: &Path, checksum: u64) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(MAGIC).map_err(|error| error.to_string())?;
    file.write_all(&checksum.to_be_bytes())
        .map_err(|error| error.to_string())?;
    file.write_all(b"P01-DISPOSABLE-BACKUP\n")
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    println!("BACKUP_WRITTEN");
    Ok(())
}

fn restore_artifact(path: &Path, expected_checksum: u64) -> Result<(), String> {
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut artifact = Vec::new();
    file.read_to_end(&mut artifact)
        .map_err(|error| error.to_string())?;
    if artifact.len() > MAX_ARTIFACT_BYTES
        || artifact.len() < MAGIC.len() + std::mem::size_of::<u64>()
        || !artifact.starts_with(MAGIC)
    {
        return Err("backup artifact is malformed".to_owned());
    }
    let offset = MAGIC.len();
    let mut checksum_bytes = [0; 8];
    let end = offset + checksum_bytes.len();
    checksum_bytes.copy_from_slice(&artifact[offset..end]);
    if u64::from_be_bytes(checksum_bytes) != expected_checksum {
        return Err("backup artifact credential checksum mismatch".to_owned());
    }
    println!("BACKUP_RESTORED");
    Ok(())
}

fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |state, byte| {
        (state ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}
