// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::secret::SecretBytes;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-credential-loader: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut socket = PathBuf::from("/run/blindpass/loader.sock");
    let mut unit = None;
    let mut credential = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--socket" => socket = PathBuf::from(next(&args, &mut index)?),
            "--unit" => unit = Some(next(&args, &mut index)?),
            "--credential" => credential = Some(next(&args, &mut index)?),
            "--output" => output = Some(PathBuf::from(next(&args, &mut index)?)),
            "--help" | "-h" => {
                println!(
                    "blindpass-credential-loader --socket PATH --unit UNIT --credential NAME --output PATH"
                );
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
        index += 1;
    }
    let unit = unit.ok_or("--unit is required")?;
    let credential = credential.ok_or("--credential is required")?;
    let output = output.ok_or("--output is required")?;
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .write_all(format!("LOAD {unit} {credential}\n").as_bytes())
        .map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    stream
        .take((blindpass_core::MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    if response.starts_with(b"ERR ") {
        return Err(String::from_utf8_lossy(&response).trim().to_owned());
    }
    if response.is_empty() || response.len() > blindpass_core::MAX_CREDENTIAL_BYTES {
        return Err("broker returned empty or oversized credential".to_owned());
    }
    let response = SecretBytes::new(response);
    let parent = output.parent().ok_or("output path has no parent")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temp = output.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    file.write_all(response.as_bytes())
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    fs::rename(temp, output).map_err(|error| error.to_string())
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}
