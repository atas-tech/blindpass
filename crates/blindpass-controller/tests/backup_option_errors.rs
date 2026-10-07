// SPDX-License-Identifier: AGPL-3.0-only

//! P07 slice 7 (cold-operator dry run, step 30): `backup verify` refused with
//! "invalid backup options" and then "unsafe backup input", naming no option, no
//! rule and no path, so the operator found the fix by guessing. Every refusal
//! below must name the offending OPTION and the RULE, and must never echo the
//! path or any value the operator supplied. The checks run before any archive
//! is opened, so no real backup is needed.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "blindpass-bo-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }

    fn dir(&self, name: &str, mode: u32) -> PathBuf {
        let path = self.root.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn file(&self, directory: &Path, name: &str, mode: u32, bytes: &[u8]) -> PathBuf {
        let path = directory.join(name);
        let _ = fs::remove_file(&path);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .env_clear()
        .arg("backup")
        .args(arguments)
        .output()
        .unwrap()
}

fn refusal(arguments: &[&str]) -> String {
    let output = run(arguments);
    assert!(!output.status.success(), "must refuse: {arguments:?}");
    assert!(output.stdout.is_empty(), "no success output on refusal");
    String::from_utf8(output.stderr).unwrap()
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A verify command with every input valid; one test breaks one thing.
struct Verify {
    archive: PathBuf,
    key: PathBuf,
    certificate: PathBuf,
    work: PathBuf,
}

fn valid_verify(fixture: &Fixture) -> Verify {
    let inputs = fixture.dir("inputs", 0o700);
    let work = fixture.dir("work", 0o700);
    Verify {
        archive: fixture.file(&inputs, "backup.bpbackup", 0o600, b"not a real archive"),
        key: fixture.file(&inputs, "recipient.pem", 0o600, b"placeholder"),
        certificate: fixture.file(&inputs, "signing-certificate.pem", 0o600, b"placeholder"),
        work,
    }
}

fn verify_arguments<'a>(verify: &'a Verify, extra: &[&'a str]) -> Vec<&'a str> {
    let mut arguments = vec![
        "verify",
        "--archive",
        text(&verify.archive),
        "--recipient-key-file",
        text(&verify.key),
        "--signing-certificate-file",
        text(&verify.certificate),
        "--work-directory",
        text(&verify.work),
    ];
    arguments.extend_from_slice(extra);
    arguments
}

#[test]
fn p07_bo01_a_relative_path_names_the_option_and_says_absolute() {
    let fixture = Fixture::new("relative");
    let verify = valid_verify(&fixture);
    let mut arguments = verify_arguments(&verify, &[]);
    let position = arguments.iter().position(|a| *a == "--archive").unwrap();
    arguments[position + 1] = "relative/backup.bpbackup";
    let stderr = refusal(&arguments);
    assert!(stderr.contains("--archive"), "{stderr}");
    assert!(stderr.contains("absolute"), "{stderr}");
    assert!(
        !stderr.contains("relative/backup"),
        "never echo the value: {stderr}"
    );
}

#[test]
fn p07_bo02_a_missing_value_and_a_repeated_option_are_distinct_refusals() {
    let fixture = Fixture::new("shape");
    let verify = valid_verify(&fixture);
    let mut missing = verify_arguments(&verify, &[]);
    missing.pop();
    let stderr = refusal(&missing);
    assert!(stderr.contains("needs a value"), "{stderr}");

    let repeated = verify_arguments(&verify, &["--work-directory", text(&verify.work)]);
    let stderr = refusal(&repeated);
    assert!(stderr.contains("--work-directory"), "{stderr}");
    assert!(stderr.contains("more than once"), "{stderr}");

    let unknown = verify_arguments(&verify, &["--no-such-option", "x"]);
    let stderr = refusal(&unknown);
    assert!(stderr.contains("unknown option"), "{stderr}");
    assert!(
        !stderr.contains("no-such-option"),
        "never echo the value: {stderr}"
    );
}

#[test]
fn p07_bo03_the_wrong_option_set_lists_what_each_command_needs() {
    let fixture = Fixture::new("sets");
    let verify = valid_verify(&fixture);
    // Only one half of the split credential model.
    let stderr = refusal(&[
        "verify",
        "--archive",
        text(&verify.archive),
        "--recipient-key-file",
        text(&verify.key),
        "--work-directory",
        text(&verify.work),
    ]);
    for needed in [
        "verify needs",
        "--archive",
        "--work-directory",
        "--recipient-key-file",
        "--signing-certificate-file",
    ] {
        assert!(stderr.contains(needed), "{needed}: {stderr}");
    }
    let stderr = refusal(&["create", "--output", text(&verify.work)]);
    assert!(stderr.contains("create needs"), "{stderr}");
    assert!(stderr.contains("--signing-credential-file"), "{stderr}");
    let stderr = refusal(&[
        "cleanup",
        "--work-directory",
        text(&verify.work),
        "--archive",
        text(&verify.archive),
    ]);
    assert!(
        stderr.contains("cleanup needs only --work-directory"),
        "{stderr}"
    );
    let stderr = refusal(&["key-init"]);
    assert!(stderr.contains("key-init needs"), "{stderr}");
}

#[test]
fn p07_bo04_a_malformed_digest_is_named_and_is_not_a_mismatch() {
    let fixture = Fixture::new("digest");
    let verify = valid_verify(&fixture);
    let stderr = refusal(&verify_arguments(
        &verify,
        &["--expected-archive-sha256", "ABC"],
    ));
    assert!(stderr.contains("--expected-archive-sha256"), "{stderr}");
    assert!(stderr.contains("64 lowercase hexadecimal"), "{stderr}");
    assert!(
        !stderr.contains("mismatch"),
        "a malformed digest is not a mismatch: {stderr}"
    );
    let stderr = refusal(&[
        "key-init",
        "--output",
        "/tmp/x.pem",
        "--certificate-output",
        "/tmp/x.crt",
        "--role",
        "owner",
    ]);
    assert!(stderr.contains("--role"), "{stderr}");
    assert!(stderr.contains("signing or recipient"), "{stderr}");
}

#[test]
fn p07_bo05_an_input_whose_directory_is_not_private_names_the_option_and_the_0700_rule() {
    let fixture = Fixture::new("directory");
    let loose = fixture.dir("loose", 0o755);
    let archive = fixture.file(&loose, "backup.bpbackup", 0o600, b"not a real archive");
    let verify = valid_verify(&fixture);
    let stderr = refusal(&[
        "verify",
        "--archive",
        text(&archive),
        "--recipient-key-file",
        text(&verify.key),
        "--signing-certificate-file",
        text(&verify.certificate),
        "--work-directory",
        text(&verify.work),
    ]);
    assert!(stderr.contains("--archive"), "{stderr}");
    assert!(stderr.contains("directory"), "{stderr}");
    assert!(stderr.contains("0700"), "{stderr}");
    assert!(!stderr.contains("loose"), "never echo the path: {stderr}");
}

/// Credential files are read by `read_private_file`, which accepts an owner-private file
/// in any directory (and a systemd service credential, which cannot be built unprivileged;
/// the packaged backup unit on the native VM covers that). The early check must never refuse
/// what that reader accepts: the first VM run of the check refused the service credential
/// with "directory ... 0700" and broke the packaged backup unit (B08).
#[test]
fn p07_bo05b_a_credential_the_reader_accepts_is_never_refused_for_its_directory() {
    let fixture = Fixture::new("credential-directory");
    let loose = fixture.dir("loose", 0o755);
    let verify = valid_verify(&fixture);
    for mode in [0o600, 0o400] {
        let key = fixture.file(&loose, "recipient.pem", mode, b"placeholder");
        let certificate = fixture.file(&loose, "signing-certificate.pem", mode, b"placeholder");
        let output = run(&[
            "verify",
            "--archive",
            text(&verify.archive),
            "--recipient-key-file",
            text(&key),
            "--signing-certificate-file",
            text(&certificate),
            "--work-directory",
            text(&verify.work),
        ]);
        assert!(
            !output.status.success(),
            "the placeholder archive cannot verify"
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            !stderr.contains("unsafe backup recovery credential") && !stderr.contains("0700"),
            "mode {mode:o}: refused a credential the reader accepts: {stderr}"
        );
    }
    // A group-readable credential in the same directory is still refused, by option and rule.
    let key = fixture.file(&loose, "recipient.pem", 0o640, b"placeholder");
    let stderr = refusal(&[
        "verify",
        "--archive",
        text(&verify.archive),
        "--recipient-key-file",
        text(&key),
        "--signing-certificate-file",
        text(&verify.certificate),
        "--work-directory",
        text(&verify.work),
    ]);
    assert!(
        stderr.contains("--recipient-key-file") && stderr.contains("group or world"),
        "{stderr}"
    );
}

#[test]
fn p07_bo06_an_input_file_that_is_group_readable_missing_empty_or_not_a_file_is_named() {
    let fixture = Fixture::new("file");
    let verify = valid_verify(&fixture);
    let inputs = verify.archive.parent().unwrap().to_path_buf();

    fs::set_permissions(&verify.archive, fs::Permissions::from_mode(0o644)).unwrap();
    let stderr = refusal(&verify_arguments(&verify, &[]));
    assert!(
        stderr.contains("--archive") && stderr.contains("0600"),
        "{stderr}"
    );
    assert!(stderr.contains("group or world"), "{stderr}");

    fs::set_permissions(&verify.archive, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&verify.certificate).unwrap();
    let stderr = refusal(&verify_arguments(&verify, &[]));
    assert!(stderr.contains("--signing-certificate-file"), "{stderr}");
    assert!(stderr.contains("does not exist"), "{stderr}");

    fixture.file(&inputs, "signing-certificate.pem", 0o600, b"");
    let stderr = refusal(&verify_arguments(&verify, &[]));
    assert!(
        stderr.contains("--signing-certificate-file") && stderr.contains("empty"),
        "{stderr}"
    );

    fs::remove_file(&verify.certificate).unwrap();
    fs::create_dir(&verify.certificate).unwrap();
    fs::set_permissions(&verify.certificate, fs::Permissions::from_mode(0o700)).unwrap();
    let stderr = refusal(&verify_arguments(&verify, &[]));
    assert!(
        stderr.contains("--signing-certificate-file") && stderr.contains("regular file"),
        "{stderr}"
    );
}

#[test]
fn p07_bo07_a_work_directory_that_is_missing_or_not_private_is_named() {
    let fixture = Fixture::new("work");
    let mut verify = valid_verify(&fixture);
    verify.work = fixture.root.join("does-not-exist");
    let stderr = refusal(&verify_arguments(&verify, &[]));
    assert!(stderr.contains("--work-directory"), "{stderr}");
    assert!(
        stderr.contains("existing directory") && stderr.contains("0700"),
        "{stderr}"
    );
    verify.work = fixture.dir("loose-work", 0o755);
    let stderr = refusal(&verify_arguments(&verify, &[]));
    assert!(
        stderr.contains("--work-directory") && stderr.contains("0700"),
        "{stderr}"
    );
    // `cleanup` needs the same directory and says the same thing.
    let stderr = refusal(&["cleanup", "--work-directory", text(&verify.work)]);
    assert!(
        stderr.contains("--work-directory") && stderr.contains("0700"),
        "{stderr}"
    );
}

#[test]
fn p07_bo08_refusals_never_contain_the_supplied_paths_or_credential_text() {
    let fixture = Fixture::new("noecho");
    let verify = valid_verify(&fixture);
    fs::set_permissions(&verify.key, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&verify.key, b"P07-DUMMY-CREDENTIAL-CANARY").unwrap();
    let mut outputs = Vec::new();
    outputs.push(refusal(&verify_arguments(&verify, &[])));
    outputs.push(refusal(&verify_arguments(
        &verify,
        &["--expected-archive-sha256", "P07-DUMMY-CANARY"],
    )));
    for stderr in outputs {
        for forbidden in [
            fixture.root.to_str().unwrap(),
            "P07-DUMMY-CREDENTIAL-CANARY",
            "P07-DUMMY-CANARY",
            "backup.bpbackup",
            "recipient.pem",
        ] {
            assert!(!stderr.contains(forbidden), "{forbidden} echoed: {stderr}");
        }
    }
}
