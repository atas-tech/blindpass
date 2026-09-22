// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::delivery::{CredentialFormat, validate_consumer_bytes};
use std::fs;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-consumer: {error}");
        std::process::exit(1);
    }
    println!("READY");
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut file = None;
    let mut max_bytes = blindpass_core::MAX_CREDENTIAL_BYTES;
    let mut prefix = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--credential-file" => file = Some(PathBuf::from(next(&args, &mut index)?)),
            "--max-bytes" => {
                max_bytes = next(&args, &mut index)?
                    .parse::<usize>()
                    .map_err(|_| "--max-bytes must be a positive integer".to_owned())?;
            }
            "--prefix" => prefix = Some(next(&args, &mut index)?.into_bytes()),
            "--help" | "-h" => {
                println!(
                    "blindpass-consumer --credential-file PATH [--max-bytes N] [--prefix BYTES]"
                );
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
        index += 1;
    }
    let file = file.ok_or("--credential-file is required")?;
    let bytes = fs::read(file).map_err(|error| error.to_string())?;
    let format = prefix.map_or(CredentialFormat::Utf8, CredentialFormat::Prefix);
    validate_consumer_bytes(&bytes, max_bytes, &format).map_err(|error| error.to_string())
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}
