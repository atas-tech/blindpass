// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_core::deployment::initialize_keys;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

#[test]
fn p06_b03_b06_b07_sqlite_create_verifies_complete_bundle_and_never_initializes_lost_state() {
    let root = std::env::temp_dir().join(format!(
        "blindpass-backup-command-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let keys = root.join("keys");
    initialize_keys(&keys).unwrap();
    let data = root.join("data");
    fs::create_dir(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    // Configured authority credentials remain outside this read-only capture.
    // A private reserved endpoint detects any unintended authority connection.
    let authority_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    authority_listener.set_nonblocking(true).unwrap();
    let authority_file = root.join("authority-url");
    let authority_canary = "P06-DUMMY-BACKUP-AUTHORITY-CREDENTIAL";
    fs::write(
        &authority_file,
        format!(
            "postgres://backup:{authority_canary}@{}/backup",
            authority_listener.local_addr().unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&authority_file, fs::Permissions::from_mode(0o600)).unwrap();
    let command = |args: &[&std::ffi::OsStr]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
            .env_clear()
            .env("BLINDPASS_KEYS_DIR", &keys)
            .env("BLINDPASS_DATA_DIR", &data)
            .env("BLINDPASS_PUBLIC_URL", "https://controller.p06.invalid")
            .env("BLINDPASS_UI_BASE_URL", "https://controller.p06.invalid")
            .env("BLINDPASS_AUTHORITY_URL_FILE", &authority_file)
            .env("BLINDPASS_CONTROLLER_TENANT_ID", "P06_DUMMY_BACKUP")
            .env("BLINDPASS_CONTROLLER_OWNER_ID", "P06_DUMMY_BACKUP_OWNER")
            .args(args)
            .output()
            .unwrap()
    };
    let key = root.join("recovery.pem");
    let output = command(&[
        "backup".as_ref(),
        "key-init".as_ref(),
        "--output".as_ref(),
        key.as_os_str(),
    ]);
    assert!(output.status.success(), "recovery command failed");
    let backup_dir = data.join("backups");
    let create = [
        "backup".as_ref(),
        "create".as_ref(),
        "--output".as_ref(),
        backup_dir.as_os_str(),
        "--recovery-key-file".as_ref(),
        key.as_os_str(),
    ];
    assert!(!command(&create).status.success());
    assert!(!data.join("controller.db").exists());
    // Isolated fixture initialization; production initialization is covered by PW05.
    let initialized = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .env_clear()
        .env("BLINDPASS_TEST_MODE", "1")
        .env("BLINDPASS_KEYS_DIR", &keys)
        .env("BLINDPASS_DATA_DIR", &data)
        .env("BLINDPASS_PUBLIC_URL", "https://controller.p06.invalid")
        .env("BLINDPASS_UI_BASE_URL", "https://controller.p06.invalid")
        .arg("migrate")
        .output()
        .unwrap();
    assert!(initialized.status.success());
    let clock = || {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let pool = sqlx::SqlitePool::connect(&format!(
                "sqlite://{}",
                data.join("controller.db").display()
            ))
            .await
            .unwrap();
            let value: i64 =
                sqlx::query_scalar("SELECT last_observed_ms FROM controller_clock WHERE id=1")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            pool.close().await;
            value
        })
    };
    let clock_before = clock();
    let output = command(&create);
    assert!(output.status.success(), "backup command failed");
    assert_eq!(
        clock(),
        clock_before,
        "offline capture changed the controller clock without ownership"
    );
    assert_eq!(
        authority_listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(authority_canary));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(authority_canary));
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["verified"], true);
    let archive = backup_dir.join(summary["backup"].as_str().unwrap());
    let manifest = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(blindpass_controller::backup::verify_backup(
            &archive, &key, &root,
        ))
        .unwrap();
    let mut members = manifest
        .members
        .iter()
        .map(|member| member.name.as_str())
        .collect::<Vec<_>>();
    members.sort_unstable();
    assert_eq!(
        members,
        vec![
            "agent-jwt-secret",
            "database.sqlite",
            "issuer-key",
            "root-secret"
        ]
    );
    assert!(
        !fs::read(data.join("controller.db"))
            .unwrap()
            .windows(authority_canary.len())
            .any(|window| window == authority_canary.as_bytes())
    );

    assert_eq!(
        fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let entries: Vec<_> = fs::read_dir(&backup_dir).unwrap().collect();
    assert_eq!(entries.len(), 1, "plaintext or partial staging remained");
    let verify = [
        "backup".as_ref(),
        "verify".as_ref(),
        "--archive".as_ref(),
        archive.as_os_str(),
        "--recovery-key-file".as_ref(),
        key.as_os_str(),
        "--work-directory".as_ref(),
        root.as_os_str(),
    ];
    let verified = command(&verify);
    assert!(verified.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified.stdout).unwrap()["verified"],
        true
    );
    {
        let locked = blindpass_core::deployment::Directory::open_private(&keys).unwrap();
        locked.lock(true).unwrap();
        assert!(!command(&create).status.success());
        assert_eq!(fs::read_dir(&backup_dir).unwrap().count(), 1);
    }
    fs::remove_file(keys.join("issuer-key")).unwrap();
    assert!(!command(&create).status.success());
    assert!(
        command(&verify).status.success(),
        "verification required production keys"
    );
    assert!(!keys.join("issuer-key").exists());
    assert_eq!(fs::read_dir(&backup_dir).unwrap().count(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn p06_d29_split_credentials_create_on_the_host_and_verify_only_with_the_offline_key() {
    let root = std::env::temp_dir().join(format!(
        "blindpass-backup-split-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let keys = root.join("keys");
    initialize_keys(&keys).unwrap();
    let data = root.join("data");
    fs::create_dir(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    let authority_file = root.join("authority-url");
    fs::write(
        &authority_file,
        "postgres://backup:P06-DUMMY@127.0.0.1:9/backup",
    )
    .unwrap();
    fs::set_permissions(&authority_file, fs::Permissions::from_mode(0o600)).unwrap();
    let env = |c: &mut Command| {
        c.env_clear()
            .env("BLINDPASS_KEYS_DIR", &keys)
            .env("BLINDPASS_DATA_DIR", &data)
            .env("BLINDPASS_PUBLIC_URL", "https://controller.p06.invalid")
            .env("BLINDPASS_UI_BASE_URL", "https://controller.p06.invalid");
    };
    let command = |args: &[&std::ffi::OsStr]| -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
        env(&mut c);
        c.env("BLINDPASS_AUTHORITY_URL_FILE", &authority_file)
            .env("BLINDPASS_CONTROLLER_TENANT_ID", "P06_DUMMY_SPLIT")
            .env("BLINDPASS_CONTROLLER_OWNER_ID", "P06_DUMMY_SPLIT_OWNER")
            .args(args)
            .output()
            .unwrap()
    };
    let signing_dir = root.join("signing");
    let recipient_dir = root.join("recipient");
    for dir in [&signing_dir, &recipient_dir] {
        fs::create_dir(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (signing, signing_certificate) = (
        signing_dir.join("signing.pem"),
        signing_dir.join("signing-certificate.pem"),
    );
    let (recipient, recipient_certificate) = (
        recipient_dir.join("recipient.pem"),
        recipient_dir.join("recipient-certificate.pem"),
    );
    for (role, credential, certificate) in [
        ("signing", &signing, &signing_certificate),
        ("recipient", &recipient, &recipient_certificate),
    ] {
        let output = command(&[
            "backup".as_ref(),
            "key-init".as_ref(),
            "--role".as_ref(),
            role.as_ref(),
            "--output".as_ref(),
            credential.as_os_str(),
            "--certificate-output".as_ref(),
            certificate.as_os_str(),
        ]);
        assert!(output.status.success(), "{role} key-init failed");
        assert!(
            !command(&[
                "backup".as_ref(),
                "key-init".as_ref(),
                "--role".as_ref(),
                role.as_ref(),
                "--output".as_ref(),
                credential.as_os_str(),
                "--certificate-output".as_ref(),
                certificate.as_os_str(),
            ])
            .status
            .success()
        );
    }
    // An unknown role, a missing certificate output, or mixing the legacy form is refused.
    for bad in [vec!["--role", "other"], vec!["--role", "signing"]] {
        let mut args: Vec<&std::ffi::OsStr> = vec!["backup".as_ref(), "key-init".as_ref()];
        let extra: Vec<std::ffi::OsString> = bad.iter().map(Into::into).collect();
        args.extend(extra.iter().map(|v| v.as_os_str()));
        let out = root.join("never.pem");
        args.extend(["--output".as_ref(), out.as_os_str()]);
        assert!(!command(&args).status.success());
        assert!(!out.exists());
    }
    // Isolated fixture initialization, as in the single-credential test.
    let mut migrate = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
    env(&mut migrate);
    assert!(
        migrate
            .env("BLINDPASS_TEST_MODE", "1")
            .arg("migrate")
            .output()
            .unwrap()
            .status
            .success()
    );
    let backup_dir = data.join("backups");
    let create = |signing: &std::path::Path, recipient: &std::path::Path| -> Output {
        command(&[
            "backup".as_ref(),
            "create".as_ref(),
            "--output".as_ref(),
            backup_dir.as_os_str(),
            "--signing-credential-file".as_ref(),
            signing.as_os_str(),
            "--recipient-certificate-file".as_ref(),
            recipient.as_os_str(),
        ])
    };
    // Wrong-role material never creates an archive.
    for (s, r) in [
        (&signing, &recipient),
        (&signing, &signing_certificate),
        (&signing, &signing),
    ] {
        assert!(!create(s, r).status.success());
    }
    assert!(!backup_dir.exists() || fs::read_dir(&backup_dir).unwrap().count() == 0);
    let created = create(&signing, &recipient_certificate);
    assert!(
        created.status.success(),
        "split create failed: {}",
        String::from_utf8_lossy(&created.stdout)
    );
    let summary: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(summary["verified"], true);
    assert_eq!(summary["custody"], "split");
    let digest = summary["archive_sha256"].as_str().unwrap().to_owned();
    assert_eq!(digest.len(), 64);
    let archive = backup_dir.join(summary["backup"].as_str().unwrap());
    assert_eq!(
        fs::read_dir(&backup_dir).unwrap().count(),
        1,
        "staging or throwaway key material remained"
    );
    // The throwaway credential and the staging plaintext are gone.
    let listing = String::from_utf8_lossy(&created.stdout).into_owned()
        + &String::from_utf8_lossy(&created.stderr);
    assert!(!listing.contains("PRIVATE KEY"));
    let verify =
        |recipient: &std::path::Path, signer: &std::path::Path, extra: &[&str]| -> Output {
            let mut args: Vec<&std::ffi::OsStr> = vec![
                "backup".as_ref(),
                "verify".as_ref(),
                "--archive".as_ref(),
                archive.as_os_str(),
                "--recipient-key-file".as_ref(),
                recipient.as_os_str(),
                "--signing-certificate-file".as_ref(),
                signer.as_os_str(),
                "--work-directory".as_ref(),
                root.as_os_str(),
            ];
            args.extend(extra.iter().map(|v| std::ffi::OsStr::new(*v)));
            command(&args)
        };
    let ok = verify(&recipient, &signing_certificate, &[]);
    assert!(ok.status.success(), "offline verification failed");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&ok.stdout).unwrap()["verified"],
        true
    );
    // Pinned archive digest: the recorded one passes, any other is refused.
    assert!(
        verify(
            &recipient,
            &signing_certificate,
            &["--expected-archive-sha256", &digest]
        )
        .status
        .success()
    );
    let wrong = "0".repeat(64);
    assert!(
        !verify(
            &recipient,
            &signing_certificate,
            &["--expected-archive-sha256", &wrong]
        )
        .status
        .success()
    );
    // The host's own credential cannot open its archive; the wrong signer is refused.
    assert!(!verify(&signing, &signing_certificate, &[]).status.success());
    assert!(
        !verify(&recipient, &recipient_certificate, &[])
            .status
            .success()
    );
    fs::remove_dir_all(root).unwrap();
}
