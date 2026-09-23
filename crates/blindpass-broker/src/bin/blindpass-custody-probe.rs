// SPDX-License-Identifier: AGPL-3.0-only

//! Disposable P01 custody lifecycle probe.
//!
//! The parent process exercises destination binding, authentication failure,
//! one-use delivery, and expiry. It then writes only an HPKE envelope (never
//! a private key or plaintext) and starts a fresh process to prove that
//! ephemeral broker state is unavailable after restart.

use blindpass_core::MAX_CREDENTIAL_BYTES;
use blindpass_core::custody::{CryptoError, EphemeralCustody, RecipientKeyPair, SealedMessage};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const CANARY: &[u8] = b"P01-CUSTODY-CANARY";
const AAD: &[u8] = b"p01:node-a:workload-a";
const RECIPIENT_ID: &str = "p01-recipient";
const ENVELOPE_NAME: &str = "sealed-envelope.bin";
const MAGIC: &[u8; 4] = b"BP01";

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-custody-probe: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut workdir = None;
    let mut recover = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--workdir" => workdir = Some(PathBuf::from(next(&args, &mut index)?)),
            "--recover" => recover = true,
            "--help" | "-h" => {
                println!("blindpass-custody-probe --workdir PATH [--recover]");
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
        index += 1;
    }
    let workdir = workdir.ok_or("--workdir is required")?;
    if recover {
        recover_after_restart(&workdir)
    } else {
        exercise(&workdir)
    }
}

fn exercise(workdir: &Path) -> Result<(), String> {
    fs::create_dir_all(workdir).map_err(|error| error.to_string())?;
    fs::set_permissions(workdir, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;

    let mut custody = EphemeralCustody::new(Duration::from_secs(30));
    let public_key = custody
        .provision(RECIPIENT_ID)
        .map_err(|error| error.to_string())?;
    if !matches!(
        custody.provision(RECIPIENT_ID),
        Err(CryptoError::OpenSsl("recipient already provisioned"))
    ) {
        return Err("duplicate recipient provisioning was accepted".to_owned());
    }
    let message =
        RecipientKeyPair::seal(&public_key, CANARY, AAD).map_err(|error| error.to_string())?;
    let opened = custody
        .open_once(RECIPIENT_ID, &message.enc, &message.ciphertext, AAD)
        .map_err(|error| error.to_string())?;
    if opened.as_bytes() != CANARY {
        return Err("custody opened the wrong bytes".to_owned());
    }
    if !matches!(
        custody.open_once(RECIPIENT_ID, &message.enc, &message.ciphertext, AAD),
        Err(CryptoError::OpenSsl("recipient key missing or expired"))
    ) {
        return Err("custody permitted a second open".to_owned());
    }

    let recipient = RecipientKeyPair::generate().map_err(|error| error.to_string())?;
    let protected = RecipientKeyPair::seal(recipient.public_key(), CANARY, AAD)
        .map_err(|error| error.to_string())?;
    let wrong_recipient = RecipientKeyPair::generate().map_err(|error| error.to_string())?;
    if !matches!(
        wrong_recipient.open(&protected.enc, &protected.ciphertext, AAD),
        Err(CryptoError::AuthenticationFailed)
    ) {
        return Err("wrong recipient key was accepted".to_owned());
    }
    let mut tampered = protected.ciphertext.clone();
    tampered[0] ^= 1;
    if !matches!(
        recipient.open(&protected.enc, &tampered, AAD),
        Err(CryptoError::AuthenticationFailed)
    ) {
        return Err("tampered ciphertext was accepted".to_owned());
    }
    if !matches!(
        recipient.open(&protected.enc, &protected.ciphertext, b"wrong-aad"),
        Err(CryptoError::AuthenticationFailed)
    ) {
        return Err("wrong destination binding was accepted".to_owned());
    }

    let mut expiring = EphemeralCustody::new(Duration::ZERO);
    let expiring_public = expiring
        .provision("p01-expiring")
        .map_err(|error| error.to_string())?;
    let expiring_message =
        RecipientKeyPair::seal(&expiring_public, CANARY, AAD).map_err(|error| error.to_string())?;
    if !matches!(
        expiring.open_once(
            "p01-expiring",
            &expiring_message.enc,
            &expiring_message.ciphertext,
            AAD,
        ),
        Err(CryptoError::OpenSsl("recipient key missing or expired"))
    ) || !expiring.is_empty()
    {
        return Err("expired custody retained a usable key".to_owned());
    }

    let restart_recipient = RecipientKeyPair::generate().map_err(|error| error.to_string())?;
    let restart_message = RecipientKeyPair::seal(restart_recipient.public_key(), CANARY, AAD)
        .map_err(|error| error.to_string())?;
    let envelope = workdir.join(ENVELOPE_NAME);
    write_envelope(&envelope, &restart_message, AAD)?;
    drop(restart_recipient);
    let status = Command::new(std::env::current_exe().map_err(|error| error.to_string())?)
        .arg("--recover")
        .arg("--workdir")
        .arg(workdir)
        .status()
        .map_err(|error| error.to_string())?;
    let _ = fs::remove_file(&envelope);
    if !status.success() {
        return Err("fresh custody process did not fail closed".to_owned());
    }
    if workdir
        .read_dir()
        .map_err(|error| error.to_string())?
        .next()
        .is_some()
    {
        return Err("custody probe left an artifact after cleanup".to_owned());
    }
    let _ = fs::remove_dir(workdir);
    println!("P01-I05 custody binding, expiry and one-use lifecycle: PASS");
    Ok(())
}

fn recover_after_restart(workdir: &Path) -> Result<(), String> {
    let (message, aad) = read_envelope(&workdir.join(ENVELOPE_NAME))?;
    let mut custody = EphemeralCustody::new(Duration::from_secs(30));
    if !matches!(
        custody.open_once(RECIPIENT_ID, &message.enc, &message.ciphertext, &aad),
        Err(CryptoError::OpenSsl("recipient key missing or expired"))
    ) {
        return Err("fresh custody unexpectedly recovered a private key".to_owned());
    }
    let wrong_recipient = RecipientKeyPair::generate().map_err(|error| error.to_string())?;
    if !matches!(
        wrong_recipient.open(&message.enc, &message.ciphertext, &aad),
        Err(CryptoError::AuthenticationFailed)
    ) {
        return Err("wrong restart recipient was accepted".to_owned());
    }
    assert_no_plaintext(workdir)?;
    println!("P01-I05 custody restart without key: PASS");
    Ok(())
}

fn write_envelope(path: &Path, message: &SealedMessage, aad: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(MAGIC).map_err(|error| error.to_string())?;
    write_length(&mut file, message.enc.len())?;
    write_length(&mut file, message.ciphertext.len())?;
    write_length(&mut file, aad.len())?;
    file.write_all(&message.enc)
        .map_err(|error| error.to_string())?;
    file.write_all(&message.ciphertext)
        .map_err(|error| error.to_string())?;
    file.write_all(aad).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    Ok(())
}

fn read_envelope(path: &Path) -> Result<(SealedMessage, Vec<u8>), String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut magic = [0; 4];
    file.read_exact(&mut magic)
        .map_err(|error| error.to_string())?;
    if &magic != MAGIC {
        return Err("custody envelope magic is invalid".to_owned());
    }
    let enc_length = read_length(&mut file)?;
    let ciphertext_length = read_length(&mut file)?;
    let aad_length = read_length(&mut file)?;
    if enc_length > 32 || ciphertext_length > MAX_CREDENTIAL_BYTES || aad_length > 256 {
        return Err("custody envelope exceeds bounds".to_owned());
    }
    let mut enc = vec![0; enc_length];
    let mut ciphertext = vec![0; ciphertext_length];
    let mut aad = vec![0; aad_length];
    file.read_exact(&mut enc)
        .map_err(|error| error.to_string())?;
    file.read_exact(&mut ciphertext)
        .map_err(|error| error.to_string())?;
    file.read_exact(&mut aad)
        .map_err(|error| error.to_string())?;
    Ok((SealedMessage { enc, ciphertext }, aad))
}

fn assert_no_plaintext(workdir: &Path) -> Result<(), String> {
    for entry in fs::read_dir(workdir).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_file() {
            let bytes = fs::read(path).map_err(|error| error.to_string())?;
            if bytes.windows(CANARY.len()).any(|window| window == CANARY) {
                return Err("custody canary appeared in a persisted artifact".to_owned());
            }
        }
    }
    Ok(())
}

fn write_length(file: &mut File, length: usize) -> Result<(), String> {
    let length = u32::try_from(length).map_err(|_| "custody envelope length overflow")?;
    file.write_all(&length.to_be_bytes())
        .map_err(|error| error.to_string())
}

fn read_length(file: &mut File) -> Result<usize, String> {
    let mut bytes = [0; 4];
    file.read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    usize::try_from(u32::from_be_bytes(bytes))
        .map_err(|_| "custody envelope length overflow".to_owned())
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}
