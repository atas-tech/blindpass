// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_controller::backup::{decrypt_bundle, encrypt_bundle, initialize_recovery_key};
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct PrivateFixture(PathBuf);
impl PrivateFixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blindpass-backup-envelope-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn member(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for PrivateFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn private_write(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn p06_b03_b04_authenticated_roundtrip_requires_exact_recovery_signer() {
    let f = PrivateFixture::new();
    let key = f.member("recovery.pem");
    initialize_recovery_key(&key).unwrap();
    let original_key = fs::read(&key).unwrap();
    assert!(initialize_recovery_key(&key).is_err());
    assert!(
        original_key == fs::read(&key).unwrap(),
        "recovery key was overwritten"
    );
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    private_write(&f.member("plain"), b"P06-DUMMY-PRIVATE-BUNDLE\0\xff");
    encrypt_bundle(&f.member("plain"), &f.member("sealed"), &key, &f.0).unwrap();
    let sealed = fs::read(f.member("sealed")).unwrap();
    assert!(
        !sealed
            .windows(b"P06-DUMMY-PRIVATE-BUNDLE".len())
            .any(|b| b == b"P06-DUMMY-PRIVATE-BUNDLE")
    );
    decrypt_bundle(&f.member("sealed"), &f.member("opened"), &key, &f.0).unwrap();
    assert_eq!(
        fs::read(f.member("plain")).unwrap(),
        fs::read(f.member("opened")).unwrap()
    );
    let wrong_key = f.member("wrong.pem");
    initialize_recovery_key(&wrong_key).unwrap();
    assert!(
        decrypt_bundle(
            &f.member("sealed"),
            &f.member("wrong-open"),
            &wrong_key,
            &f.0
        )
        .is_err()
    );
    assert!(!f.member("wrong-open").exists());
    for (i, index) in [sealed.len() / 2, sealed.len() - 1].into_iter().enumerate() {
        let mut changed = sealed.clone();
        changed[index] ^= 1;
        let input = f.member(&format!("changed-{i}"));
        private_write(&input, &changed);
        assert!(decrypt_bundle(&input, &f.member("changed-open"), &key, &f.0).is_err());
        assert!(!f.member("changed-open").exists());
    }
    private_write(&f.member("truncated"), &sealed[..sealed.len() - 20]);
    assert!(
        decrypt_bundle(
            &f.member("truncated"),
            &f.member("truncated-open"),
            &key,
            &f.0
        )
        .is_err()
    );
    assert!(!f.member("truncated-open").exists());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(encrypt_bundle(&f.member("plain"), &f.member("unsafe-output"), &key, &f.0).is_err());
    assert!(!f.member("unsafe-output").exists());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&key, f.member("linked-key")).unwrap();
    assert!(
        decrypt_bundle(
            &f.member("sealed"),
            &f.member("linked-open"),
            &f.member("linked-key"),
            &f.0
        )
        .is_err()
    );
    assert!(!f.member("linked-open").exists());
    fs::hard_link(&key, f.member("hardlinked-key")).unwrap();
    assert!(
        decrypt_bundle(
            &f.member("sealed"),
            &f.member("hardlinked-open"),
            &key,
            &f.0
        )
        .is_err()
    );
    assert!(!f.member("hardlinked-open").exists());
}

#[test]
fn p06_b04_unsigned_and_unauthenticated_envelopes_are_rejected() {
    use std::process::{Command, Stdio};
    let f = PrivateFixture::new();
    let key = f.member("recovery.pem");
    initialize_recovery_key(&key).unwrap();
    let wrong = f.member("wrong-signer.pem");
    initialize_recovery_key(&wrong).unwrap();
    private_write(&f.member("plain"), b"P06-DUMMY-UNSIGNED");
    for (name, cipher) in [("unsigned", "-aes-256-gcm"), ("cbc", "-aes256")] {
        let output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(f.member(name))
            .unwrap();
        assert!(
            Command::new("/usr/bin/openssl")
                .args([
                    "cms", "-encrypt", "-binary", "-outform", "DER", cipher, "-recip"
                ])
                .arg(&key)
                .stdin(fs::File::open(f.member("plain")).unwrap())
                .stdout(output)
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        assert!(decrypt_bundle(&f.member(name), &f.member("rejected"), &key, &f.0).is_err());
        assert!(!f.member("rejected").exists());
        // Anyone holding a public recipient certificate can encrypt a forged
        // replacement. Its embedded signing certificate must not be trusted.
        let forged = f.member(&format!("forged-{name}"));
        let output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&forged)
            .unwrap();
        assert!(
            Command::new("/usr/bin/openssl")
                .args([
                    "cms",
                    "-sign",
                    "-binary",
                    "-nodetach",
                    "-md",
                    "sha256",
                    "-outform",
                    "DER",
                    "-signer"
                ])
                .arg(&wrong)
                .arg("-inkey")
                .arg(&wrong)
                .stdin(fs::File::open(f.member(name)).unwrap())
                .stdout(output)
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        assert!(decrypt_bundle(&forged, &f.member("forged-open"), &key, &f.0).is_err());
        assert!(!f.member("forged-open").exists());
        if name == "unsigned" {
            // Keep the outer signature valid while corrupting the GCM tag.
            // The decryptor can emit plaintext before reporting tag failure;
            // the wrapper must discard it and never publish that output.
            let mut changed = fs::read(f.member(name)).unwrap();
            *changed.last_mut().unwrap() ^= 1;
            private_write(&f.member("bad-tag"), &changed);
            let signed = f.member("signed-bad-tag");
            let output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&signed)
                .unwrap();
            assert!(
                Command::new("/usr/bin/openssl")
                    .args([
                        "cms",
                        "-sign",
                        "-binary",
                        "-nodetach",
                        "-md",
                        "sha256",
                        "-outform",
                        "DER",
                        "-signer"
                    ])
                    .arg(&key)
                    .arg("-inkey")
                    .arg(&key)
                    .stdin(fs::File::open(f.member("bad-tag")).unwrap())
                    .stdout(output)
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(decrypt_bundle(&signed, &f.member("bad-tag-open"), &key, &f.0).is_err());
            assert!(!f.member("bad-tag-open").exists());
        }
        if name == "cbc" {
            let signed = f.member("signed-cbc");
            let output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&signed)
                .unwrap();
            assert!(
                Command::new("/usr/bin/openssl")
                    .args([
                        "cms",
                        "-sign",
                        "-binary",
                        "-nodetach",
                        "-md",
                        "sha256",
                        "-outform",
                        "DER",
                        "-signer"
                    ])
                    .arg(&key)
                    .arg("-inkey")
                    .arg(&key)
                    .stdin(fs::File::open(f.member(name)).unwrap())
                    .stdout(output)
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            let error =
                decrypt_bundle(&signed, &f.member("signed-cbc-open"), &key, &f.0).unwrap_err();
            assert_eq!(error.to_string(), "backup CMS content type mismatch");
            assert!(!f.member("signed-cbc-open").exists());
        }
    }
}

// ---- P06-D29: signing credential and offline recipient key (ADR 0013) ----
mod custody_split {
    use super::*;
    use blindpass_controller::backup::{
        KeyRole, OpenKeys, SealKeys, decrypt_bundle_with, encrypt_bundle_to, encrypt_bundle_with,
        initialize_role_credentials,
    };

    struct Roles {
        signing: PathBuf,
        signing_certificate: PathBuf,
        recipient: PathBuf,
        recipient_certificate: PathBuf,
    }
    fn roles(f: &PrivateFixture) -> Roles {
        let roles = Roles {
            signing: f.member("signing.pem"),
            signing_certificate: f.member("signing-certificate.pem"),
            recipient: f.member("recipient.pem"),
            recipient_certificate: f.member("recipient-certificate.pem"),
        };
        initialize_role_credentials(KeyRole::Signing, &roles.signing, &roles.signing_certificate)
            .unwrap();
        initialize_role_credentials(
            KeyRole::Recipient,
            &roles.recipient,
            &roles.recipient_certificate,
        )
        .unwrap();
        roles
    }
    fn text(path: &Path) -> String {
        String::from_utf8(fs::read(path).unwrap()).unwrap()
    }
    fn certificate_only(path: &Path) {
        let body = text(path);
        assert_eq!(body.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        assert!(
            !body.contains("PRIVATE KEY"),
            "certificate file holds a key"
        );
    }
    fn credential(path: &Path) {
        let body = text(path);
        assert_eq!(body.matches("-----BEGIN PRIVATE KEY-----").count(), 1);
        assert_eq!(body.matches("-----BEGIN CERTIFICATE-----").count(), 1);
    }

    #[test]
    fn p06_d29_role_credentials_are_private_separate_and_never_overwritten() {
        let f = PrivateFixture::new();
        let r = roles(&f);
        credential(&r.signing);
        credential(&r.recipient);
        certificate_only(&r.signing_certificate);
        certificate_only(&r.recipient_certificate);
        for path in [
            &r.signing,
            &r.signing_certificate,
            &r.recipient,
            &r.recipient_certificate,
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_ne!(text(&r.signing_certificate), text(&r.recipient_certificate));
        // The certificate-only files are exactly the certificates of the credentials.
        assert!(text(&r.signing).contains(text(&r.signing_certificate).trim()));
        assert!(text(&r.recipient).contains(text(&r.recipient_certificate).trim()));
        // No overwrite of either output, and a taken certificate path creates no credential.
        let before = fs::read(&r.signing).unwrap();
        assert!(
            initialize_role_credentials(KeyRole::Signing, &r.signing, &f.member("other.pem"))
                .is_err()
        );
        assert_eq!(before, fs::read(&r.signing).unwrap());
        assert!(!f.member("other.pem").exists());
        assert!(
            initialize_role_credentials(
                KeyRole::Recipient,
                &f.member("fresh.pem"),
                &r.recipient_certificate
            )
            .is_err()
        );
        assert!(!f.member("fresh.pem").exists());
    }

    #[test]
    fn p06_d29_split_roundtrip_needs_the_offline_key_and_the_pinned_signer() {
        let f = PrivateFixture::new();
        let r = roles(&f);
        private_write(&f.member("plain"), b"P06-DUMMY-SPLIT-BUNDLE\0\xff");
        encrypt_bundle_with(
            &f.member("plain"),
            &f.member("sealed"),
            &SealKeys::Split {
                signing_credential: &r.signing,
                recipient_certificate: &r.recipient_certificate,
            },
            &f.0,
        )
        .unwrap();
        let sealed = fs::read(f.member("sealed")).unwrap();
        assert!(
            !sealed
                .windows(b"P06-DUMMY-SPLIT-BUNDLE".len())
                .any(|w| w == b"P06-DUMMY-SPLIT-BUNDLE")
        );
        // Offline key plus the signer's certificate (certificate-only or full credential).
        for (i, signer) in [&r.signing_certificate, &r.signing].into_iter().enumerate() {
            let out = f.member(&format!("opened-{i}"));
            decrypt_bundle_with(
                &f.member("sealed"),
                &out,
                &OpenKeys::Split {
                    recipient_key: &r.recipient,
                    signing_certificate: signer,
                },
                &f.0,
            )
            .unwrap();
            assert_eq!(
                fs::read(&out).unwrap(),
                fs::read(f.member("plain")).unwrap()
            );
        }
        // The backup host's own credential cannot read the archive it signed.
        assert!(
            decrypt_bundle_with(
                &f.member("sealed"),
                &f.member("host-open"),
                &OpenKeys::Split {
                    recipient_key: &r.signing,
                    signing_certificate: &r.signing_certificate,
                },
                &f.0
            )
            .is_err()
        );
        assert!(!f.member("host-open").exists());
        // A different signer certificate is refused even with the right recipient key.
        let other = f.member("other-signing.pem");
        let other_certificate = f.member("other-signing-certificate.pem");
        initialize_role_credentials(KeyRole::Signing, &other, &other_certificate).unwrap();
        assert!(
            decrypt_bundle_with(
                &f.member("sealed"),
                &f.member("wrong-signer-open"),
                &OpenKeys::Split {
                    recipient_key: &r.recipient,
                    signing_certificate: &other_certificate,
                },
                &f.0
            )
            .is_err()
        );
        assert!(!f.member("wrong-signer-open").exists());
        // Corruption is refused.
        for (i, index) in [sealed.len() / 2, sealed.len() - 1].into_iter().enumerate() {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            let input = f.member(&format!("changed-{i}"));
            private_write(&input, &changed);
            assert!(
                decrypt_bundle_with(
                    &input,
                    &f.member("changed-open"),
                    &OpenKeys::Split {
                        recipient_key: &r.recipient,
                        signing_certificate: &r.signing_certificate,
                    },
                    &f.0
                )
                .is_err()
            );
            assert!(!f.member("changed-open").exists());
        }
    }

    #[test]
    fn p06_d29_create_path_refuses_wrong_role_material() {
        let f = PrivateFixture::new();
        let r = roles(&f);
        private_write(&f.member("plain"), b"P06-DUMMY-ROLE-REFUSAL");
        let attempts: [(&str, &Path, &Path); 4] = [
            // A recipient file holding a private key must never sit on the backup host.
            ("recipient-private", &r.signing, &r.recipient),
            // The same certificate for both roles.
            ("same-certificate", &r.signing, &r.signing_certificate),
            // The same file for both roles.
            ("same-file", &r.signing, &r.signing),
            // A signing file without a private key cannot sign.
            (
                "signing-certificate-only",
                &r.signing_certificate,
                &r.recipient_certificate,
            ),
        ];
        for (name, signing, recipient) in attempts {
            let out = f.member(&format!("refused-{name}"));
            assert!(
                encrypt_bundle_with(
                    &f.member("plain"),
                    &out,
                    &SealKeys::Split {
                        signing_credential: signing,
                        recipient_certificate: recipient,
                    },
                    &f.0
                )
                .is_err(),
                "{name} was accepted"
            );
            assert!(!out.exists(), "{name} left an archive");
        }
    }

    #[test]
    fn p06_d29_single_credential_archives_open_under_both_models() {
        let f = PrivateFixture::new();
        let key = f.member("recovery.pem");
        initialize_recovery_key(&key).unwrap();
        private_write(&f.member("plain"), b"P06-DUMMY-LEGACY-BUNDLE");
        encrypt_bundle(&f.member("plain"), &f.member("sealed"), &key, &f.0).unwrap();
        decrypt_bundle_with(
            &f.member("sealed"),
            &f.member("single-open"),
            &OpenKeys::Single(&key),
            &f.0,
        )
        .unwrap();
        // One credential acting as both roles is a valid split argument form.
        decrypt_bundle_with(
            &f.member("sealed"),
            &f.member("split-open"),
            &OpenKeys::Split {
                recipient_key: &key,
                signing_certificate: &key,
            },
            &f.0,
        )
        .unwrap();
        assert_eq!(
            fs::read(f.member("plain")).unwrap(),
            fs::read(f.member("split-open")).unwrap()
        );
        // The legacy sealing path is unchanged: Single both signs and encrypts.
        encrypt_bundle_with(
            &f.member("plain"),
            &f.member("sealed-single"),
            &SealKeys::Single(&key),
            &f.0,
        )
        .unwrap();
        decrypt_bundle(
            &f.member("sealed-single"),
            &f.member("legacy-open"),
            &key,
            &f.0,
        )
        .unwrap();
    }

    #[test]
    fn p06_d29_throwaway_co_recipient_and_offline_recipient_both_decrypt() {
        let f = PrivateFixture::new();
        let r = roles(&f);
        let throwaway = f.member("throwaway.pem");
        let throwaway_certificate = f.member("throwaway-certificate.pem");
        initialize_role_credentials(KeyRole::Recipient, &throwaway, &throwaway_certificate)
            .unwrap();
        private_write(&f.member("plain"), b"P06-DUMMY-TWO-RECIPIENTS");
        encrypt_bundle_to(
            &f.member("plain"),
            &f.member("sealed"),
            &r.signing,
            &[&r.recipient_certificate, &throwaway_certificate],
            &f.0,
        )
        .unwrap();
        for (name, key) in [("offline", &r.recipient), ("throwaway", &throwaway)] {
            let out = f.member(&format!("opened-{name}"));
            decrypt_bundle_with(
                &f.member("sealed"),
                &out,
                &OpenKeys::Split {
                    recipient_key: key,
                    signing_certificate: &r.signing_certificate,
                },
                &f.0,
            )
            .unwrap();
            assert_eq!(
                fs::read(&out).unwrap(),
                fs::read(f.member("plain")).unwrap()
            );
        }
        // A key that is neither recipient still cannot read it.
        let stranger = f.member("stranger.pem");
        initialize_recovery_key(&stranger).unwrap();
        assert!(
            decrypt_bundle_with(
                &f.member("sealed"),
                &f.member("stranger-open"),
                &OpenKeys::Split {
                    recipient_key: &stranger,
                    signing_certificate: &r.signing_certificate,
                },
                &f.0
            )
            .is_err()
        );
    }
}
