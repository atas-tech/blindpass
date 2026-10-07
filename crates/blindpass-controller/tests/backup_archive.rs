// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_controller::{
    backup::{
        Backend, capture_sqlite, encrypt_bundle, extract_archive, initialize_recovery_key,
        verify_backup, write_archive,
    },
    store::Store,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn p06_b05_b07_fixed_members_bind_keys_database_and_coherent_metadata() {
    let root =
        std::env::temp_dir().join(format!("blindpass-backup-archive-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let source = root.join("source");
    let target = root.join("target");
    for path in [&source, &target] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (name, bytes) in [
        ("root-secret", vec![1; 32]),
        ("agent-jwt-secret", vec![2; 32]),
        ("issuer-key", vec![3; 32]),
    ] {
        fs::write(source.join(name), bytes).unwrap();
        fs::set_permissions(source.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::connect(&format!(
        "sqlite://{}?mode=rwc",
        root.join("source.db").display()
    ))
    .await
    .unwrap();
    let snapshot = capture_sqlite(&store, &source.join("database.sqlite"))
        .await
        .unwrap();
    write_archive(
        &source,
        &root.join("archive.tar"),
        Backend::Sqlite,
        &snapshot,
    )
    .unwrap();
    let manifest = extract_archive(&root.join("archive.tar"), &target).unwrap();
    assert_eq!(manifest.snapshot, snapshot);
    for name in [
        "root-secret",
        "agent-jwt-secret",
        "issuer-key",
        "database.sqlite",
    ] {
        assert_eq!(
            fs::read(source.join(name)).unwrap(),
            fs::read(target.join(name)).unwrap()
        );
        assert_eq!(
            fs::metadata(target.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let original = fs::read(root.join("archive.tar")).unwrap();
    for (index, kind) in [
        "traversal",
        "link",
        "checksum",
        "body",
        "truncated",
        "trailing",
        "duplicate-member",
        "unknown-member",
        "nonzero-padding",
        "oversized-manifest",
        "unknown-format",
        "newer-schema",
        "unknown-field",
        "duplicate-json-field",
        "duplicate-manifest-member",
        "oversized-member",
    ]
    .into_iter()
    .enumerate()
    {
        let mut changed = original.clone();
        match kind {
            "traversal" => {
                changed[..3].copy_from_slice(b"../");
                checksum(&mut changed[..512]);
            }
            "link" => {
                changed[156] = b'2';
                checksum(&mut changed[..512]);
            }
            "checksum" => changed[148] ^= 1,
            "body" => {
                let n = changed.len() - 1536;
                changed[n] ^= 1;
            }
            "truncated" => {
                changed.truncate(changed.len() - 512);
            }
            "trailing" => changed.extend_from_slice(&[0; 512]),
            "duplicate-member" | "unknown-member" => {
                let n = first_member(&changed);
                // Change a later member after the first key was already
                // extracted, exercising cleanup of partial plaintext.
                let header = &mut changed[n + 1024..n + 1536];
                header[..100].fill(0);
                let name: &[u8] = if kind == "duplicate-member" {
                    b"root-secret"
                } else {
                    b"unexpected-private-key"
                };
                header[..name.len()].copy_from_slice(name);
                checksum(header);
            }
            "nonzero-padding" => {
                let n = first_member(&changed);
                changed[n + 512 + 32] = 1;
            }
            "oversized-manifest" => {
                changed[124..136].copy_from_slice(format!("{:011o}\0", 65537).as_bytes());
                checksum(&mut changed[..512]);
            }
            "duplicate-json-field" => {
                let manifest_size = member_size(&changed);
                let mut json = changed[512..512 + manifest_size].to_vec();
                json.splice(1..1, b"\"format_version\":1,".iter().copied());
                changed = replace_manifest(&changed, &json);
            }
            "unknown-format"
            | "newer-schema"
            | "unknown-field"
            | "duplicate-manifest-member"
            | "oversized-member" => {
                let mut json: serde_json::Value =
                    serde_json::from_slice(&changed[512..512 + member_size(&changed)]).unwrap();
                match kind {
                    "unknown-format" => json["format_version"] = 2.into(),
                    "newer-schema" => json["snapshot"]["schema_version"] = 999.into(),
                    "unknown-field" => json["unexpected"] = true.into(),
                    "duplicate-manifest-member" => {
                        json["members"][1]["name"] = "root-secret".into();
                    }
                    "oversized-member" => json["members"][3]["bytes"] = u64::MAX.into(),
                    _ => unreachable!(),
                }
                changed = replace_manifest(&changed, &serde_json::to_vec(&json).unwrap());
            }
            _ => unreachable!(),
        }
        let input = root.join(format!("bad-{index}.tar"));
        fs::write(&input, changed).unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        let target = root.join(format!("target-{index}"));
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(extract_archive(&input, &target).is_err(), "accepted {kind}");
        assert_eq!(
            fs::read_dir(&target).unwrap().count(),
            0,
            "failed extraction retained plaintext"
        );
    }
    assert!(!root.join("root-secret").exists());
    let key = root.join("recovery.pem");
    initialize_recovery_key(&key).unwrap();
    encrypt_bundle(
        &root.join("archive.tar"),
        &root.join("valid.bpbackup"),
        &key,
        &root,
    )
    .unwrap();
    assert_eq!(
        verify_backup(&root.join("valid.bpbackup"), &key, &root)
            .await
            .unwrap(),
        manifest
    );
    // A valid signature and freshly recomputed digests cannot replace actual
    // database integrity/schema checks with archive authenticity alone.
    fs::write(
        source.join("database.sqlite"),
        b"P06-DUMMY-DAMAGED-DATABASE",
    )
    .unwrap();
    write_archive(
        &source,
        &root.join("damaged.tar"),
        Backend::Sqlite,
        &snapshot,
    )
    .unwrap();
    encrypt_bundle(
        &root.join("damaged.tar"),
        &root.join("damaged.bpbackup"),
        &key,
        &root,
    )
    .unwrap();
    assert!(
        verify_backup(&root.join("damaged.bpbackup"), &key, &root)
            .await
            .is_err()
    );
    store.close().await;
    fs::remove_dir_all(root).unwrap();
}

fn checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
}

fn member_size(archive: &[u8]) -> usize {
    usize::from_str_radix(std::str::from_utf8(&archive[124..135]).unwrap(), 8).unwrap()
}

fn first_member(archive: &[u8]) -> usize {
    512 + member_size(archive).div_ceil(512) * 512
}

fn replace_manifest(archive: &[u8], json: &[u8]) -> Vec<u8> {
    let mut header = archive[..512].to_vec();
    header[124..136].copy_from_slice(format!("{:011o}\0", json.len()).as_bytes());
    checksum(&mut header);
    header.extend_from_slice(json);
    header.resize(512 + json.len().div_ceil(512) * 512, 0);
    header.extend_from_slice(&archive[first_member(archive)..]);
    header
}
