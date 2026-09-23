// SPDX-License-Identifier: AGPL-3.0-only

//! Send an administrator-provided credential to the live broker over HPKE.
//! Plaintext is read from stdin and never placed in argv or a transport frame.

use blindpass_broker::provision_aad;
use blindpass_core::MAX_CREDENTIAL_BYTES;
use blindpass_core::custody::{RecipientKeyPair, SealedMessage};
use blindpass_core::secret::SecretBytes;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-provision: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut socket = PathBuf::from("/run/blindpass/provision.sock");
    let mut unit = None;
    let mut credential = None;
    let mut test_fault = None;
    let mut test_delay = Duration::ZERO;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--socket" => socket = PathBuf::from(next(&args, &mut index)?),
            "--unit" => unit = Some(next(&args, &mut index)?),
            "--credential" => credential = Some(next(&args, &mut index)?),
            "--test-fault" => test_fault = Some(next(&args, &mut index)?),
            "--test-delay-before-seal-ms" => {
                test_delay =
                    Duration::from_millis(next(&args, &mut index)?.parse().map_err(|_| {
                        "--test-delay-before-seal-ms must be an integer".to_owned()
                    })?);
            }
            "--help" | "-h" => {
                println!(
                    "blindpass-provision --unit UNIT --credential NAME [--socket PATH] < secret-file"
                );
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
        index += 1;
    }
    let unit = unit.ok_or("--unit is required")?;
    let credential = credential.ok_or("--credential is required")?;
    if (test_fault.is_some() || !test_delay.is_zero())
        && std::env::var("BLINDPASS_P01_TEST_MODE").as_deref() != Ok("1")
    {
        return Err("P01 probe options require BLINDPASS_P01_TEST_MODE=1".to_owned());
    }
    if test_fault.as_deref().is_some_and(|fault| {
        !matches!(
            fault,
            "wrong-key" | "tampered-ciphertext" | "wrong-aad" | "replay" | "expired-key"
        )
    }) {
        return Err("unknown --test-fault".to_owned());
    }
    if test_fault.as_deref() == Some("expired-key") && test_delay.is_zero() {
        return Err("expired-key requires --test-delay-before-seal-ms".to_owned());
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|error| error.to_string())?;
    if input.is_empty() || input.len() > MAX_CREDENTIAL_BYTES {
        return Err("credential is empty or exceeds the maximum size".to_owned());
    }
    let secret = SecretBytes::new(input);
    let mut stream = open_provision_request(&socket, &unit, &credential)?;
    let mut key = [0u8; 32];
    stream
        .read_exact(&mut key)
        .map_err(|error| error.to_string())?;
    if !test_delay.is_zero() {
        std::thread::sleep(test_delay);
    }
    let aad = provision_aad(&unit, &credential);
    let sealed = seal_for_test_fault(
        &key,
        secret.as_bytes(),
        aad.as_bytes(),
        test_fault.as_deref(),
    )?;
    send_sealed(&mut stream, &sealed)?;
    let reply = read_reply(&mut stream)?;

    if test_fault.as_deref() == Some("replay") {
        if reply != b"OK\n" {
            return Err(format!(
                "initial provisioning failed: {}",
                display_reply(&reply)
            ));
        }
        let mut replay = open_provision_request(&socket, &unit, &credential)?;
        let mut replacement_key = [0u8; 32];
        replay
            .read_exact(&mut replacement_key)
            .map_err(|error| error.to_string())?;
        send_sealed(&mut replay, &sealed)?;
        let replay_reply = read_reply(&mut replay)?;
        if !replay_reply.starts_with(b"ERR ") {
            return Err("replayed HPKE envelope was not rejected by the broker".to_owned());
        }
        println!(
            "P01-PROVISION-DENIED fault=replay response={}",
            display_reply(&replay_reply)
        );
        return Ok(());
    }

    if let Some(fault) = test_fault.as_deref() {
        if !reply.starts_with(b"ERR ") {
            return Err(format!(
                "broker accepted {fault}: {}",
                display_reply(&reply)
            ));
        }
        println!(
            "P01-PROVISION-DENIED fault={fault} response={}",
            display_reply(&reply)
        );
        return Ok(());
    }
    if reply != b"OK\n" {
        return Err(format!(
            "broker rejected provisioning: {}",
            display_reply(&reply)
        ));
    }
    println!("Credential provisioned for {unit}");
    Ok(())
}

fn open_provision_request(
    socket: &std::path::Path,
    unit: &str,
    credential: &str,
) -> Result<UnixStream, String> {
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(format!("PROVISION {unit} {credential}\n").as_bytes())
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

fn seal_for_test_fault(
    public_key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    fault: Option<&str>,
) -> Result<SealedMessage, String> {
    let mut sealed = if fault == Some("wrong-key") {
        let wrong_recipient = RecipientKeyPair::generate().map_err(|error| error.to_string())?;
        RecipientKeyPair::seal(wrong_recipient.public_key(), plaintext, aad)
    } else if fault == Some("wrong-aad") {
        let mut wrong_aad = aad.to_vec();
        wrong_aad.extend_from_slice(b":wrong");
        RecipientKeyPair::seal(public_key, plaintext, &wrong_aad)
    } else {
        RecipientKeyPair::seal(public_key, plaintext, aad)
    }
    .map_err(|error| error.to_string())?;
    if fault == Some("tampered-ciphertext") {
        sealed.ciphertext[0] ^= 1;
    }
    Ok(sealed)
}

fn send_sealed(stream: &mut UnixStream, sealed: &SealedMessage) -> Result<(), String> {
    let lengths = [
        (sealed.enc.len() as u32).to_be_bytes(),
        (sealed.ciphertext.len() as u32).to_be_bytes(),
    ]
    .concat();
    stream
        .write_all(&lengths)
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&sealed.enc)
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&sealed.ciphertext)
        .map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn read_reply(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .map_err(|error| error.to_string())?;
    Ok(reply)
}

fn display_reply(reply: &[u8]) -> String {
    String::from_utf8_lossy(reply)
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | ':' | ' ') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}
