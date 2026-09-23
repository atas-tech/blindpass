// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::secret::SecretBytes;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::raw::c_char;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::chown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

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
    let mut owner_user = None;
    let mut pre_request_delay = Duration::ZERO;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--socket" => socket = PathBuf::from(next(&args, &mut index)?),
            "--unit" => unit = Some(next(&args, &mut index)?),
            "--credential" => credential = Some(next(&args, &mut index)?),
            "--output" => output = Some(PathBuf::from(next(&args, &mut index)?)),
            "--owner-user" => owner_user = Some(next(&args, &mut index)?),
            "--pre-request-delay-ms" => {
                pre_request_delay = Duration::from_millis(
                    next(&args, &mut index)?
                        .parse()
                        .map_err(|_| "--pre-request-delay-ms must be an integer".to_owned())?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "blindpass-credential-loader --socket PATH --unit UNIT --credential NAME --output PATH [--owner-user USER] [--pre-request-delay-ms N]"
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
    let temp = output.with_extension("tmp");
    for stale in [&output, &temp] {
        if let Err(error) = fs::remove_file(stale)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.to_string());
        }
    }
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    std::thread::sleep(pre_request_delay);
    stream
        .write_all(format!("LOAD {unit} {credential}\n").as_bytes())
        .map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let response = read_credential_response(&mut stream)?;
    let parent = output.parent().ok_or("output path has no parent")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(response.as_bytes()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    drop(file);
    if let Some(user) = owner_user {
        let uid = lookup_uid(&user)?;
        if let Err(error) = chown(&temp, Some(uid), None) {
            let _ = fs::remove_file(&temp);
            return Err(error.to_string());
        }
    }
    if let Err(error) = fs::rename(&temp, output) {
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    Ok(())
}

fn read_credential_response(reader: impl Read) -> Result<SecretBytes, String> {
    let mut response = Vec::new();
    reader
        .take((blindpass_core::MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    if response.is_empty() || response.len() > blindpass_core::MAX_CREDENTIAL_BYTES {
        return Err("broker returned empty or oversized credential".to_owned());
    }
    Ok(SecretBytes::new(response))
}

#[repr(C)]
struct Passwd {
    name: *mut c_char,
    password: *mut c_char,
    uid: u32,
    gid: u32,
    gecos: *mut c_char,
    home: *mut c_char,
    shell: *mut c_char,
}

unsafe extern "C" {
    fn getpwnam(name: *const c_char) -> *mut Passwd;
}

fn lookup_uid(user: &str) -> Result<u32, String> {
    let name = CString::new(user).map_err(|_| "owner user contains NUL".to_owned())?;
    let entry = unsafe { getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return Err("owner user does not exist".to_owned());
    }
    Ok(unsafe { (*entry).uid })
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}

#[cfg(test)]
mod tests {
    use super::read_credential_response;
    use std::io::Cursor;

    #[test]
    fn binary_credential_may_begin_with_the_old_error_prefix() {
        let expected = b"ERR \0\xffbinary";
        let credential = read_credential_response(Cursor::new(expected)).unwrap();
        assert_eq!(credential.as_bytes(), expected);
    }

    #[test]
    fn empty_broker_response_is_rejected() {
        assert!(read_credential_response(Cursor::new([])).is_err());
    }
}
