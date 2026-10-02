// SPDX-License-Identifier: AGPL-3.0-only

//! Application-native credential profiles (P05-D6).
//!
//! A profile describes the exact bytes an ordinary application will read from
//! its systemd credential file. The only profile today is `password-file`: raw
//! password bytes for an application that reads a password file (restic).
//! There is deliberately no decoding adapter: a JSON envelope, base64 or any
//! other wrapper is not unwrapped, so a value either passes the character
//! rules and is delivered literally, or it is rejected.
//!
//! Profiles are selected by trusted startup flags
//! (`--credential-profile CREDENTIAL=password-file`) and are keyed by
//! credential name. Without a flag the legacy behaviour is unchanged.

use crate::{BrokerError, BrokerState, destination_key};
use std::collections::BTreeSet;
use std::fmt;

/// Longest accepted password-file credential. A password is a short secret; the
/// profile is stricter than the generic 64 KiB delivery cap.
pub const PASSWORD_FILE_MAX_BYTES: usize = 1024;

const SUPPORTED_PROFILES: &str = "password-file";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialProfile {
    /// Raw password bytes for an application that reads a password file.
    PasswordFile,
}

impl CredentialProfile {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "password-file" => Some(Self::PasswordFile),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PasswordFile => "password-file",
        }
    }

    pub fn validate(self, value: &[u8]) -> Result<(), FileCredentialError> {
        match self {
            Self::PasswordFile => validate_password_file(value),
        }
    }
}

/// Fixed rejection codes. A code never carries or reflects input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCredentialError {
    Empty,
    TooLong,
    InvalidUtf8,
    ControlCharacter,
    ByteOrderMark,
    EdgeWhitespace,
}

impl FileCredentialError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "password_file_empty",
            Self::TooLong => "password_file_too_long",
            Self::InvalidUtf8 => "password_file_invalid_utf8",
            Self::ControlCharacter => "password_file_control_character",
            Self::ByteOrderMark => "password_file_byte_order_mark",
            Self::EdgeWhitespace => "password_file_edge_whitespace",
        }
    }
}

impl fmt::Display for FileCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FileCredentialError {}

/// Strict pure validator for the `password-file` profile.
///
/// Why this strict: restic trims surrounding whitespace from the file and
/// decodes a byte-order mark, so any such byte would make the repository
/// password differ from the operator-typed bytes. The broker therefore rejects
/// them instead of delivering a value the application would silently alter.
/// The rules are: non-empty, at most [`PASSWORD_FILE_MAX_BYTES`], valid UTF-8,
/// no Unicode control character (`Cc`: NUL, CR, LF, TAB, DEL, C1) anywhere, no
/// leading U+FEFF and no leading or trailing Unicode white space. A trailing
/// newline is reported as `password_file_control_character`.
pub fn validate_password_file(value: &[u8]) -> Result<(), FileCredentialError> {
    if value.is_empty() {
        return Err(FileCredentialError::Empty);
    }
    if value.len() > PASSWORD_FILE_MAX_BYTES {
        return Err(FileCredentialError::TooLong);
    }
    let text = std::str::from_utf8(value).map_err(|_| FileCredentialError::InvalidUtf8)?;
    if text.chars().any(char::is_control) {
        return Err(FileCredentialError::ControlCharacter);
    }
    if text.starts_with('\u{feff}') {
        return Err(FileCredentialError::ByteOrderMark);
    }
    if text.starts_with(char::is_whitespace) || text.ends_with(char::is_whitespace) {
        return Err(FileCredentialError::EdgeWhitespace);
    }
    Ok(())
}

/// Resolve repeated `--credential-profile CREDENTIAL=PROFILE` values against the
/// credential names that at least one `--map` entry names. Every failure is a
/// startup error; none echoes more than the operator-supplied configuration.
pub fn resolve_profile_options(
    options: &[String],
    mapped_credentials: &BTreeSet<String>,
) -> Result<Vec<(String, CredentialProfile)>, String> {
    let mut resolved: Vec<(String, CredentialProfile)> = Vec::new();
    for option in options {
        let (credential, name) = option
            .split_once('=')
            .filter(|(credential, name)| !credential.is_empty() && !name.is_empty())
            .ok_or("--credential-profile requires CREDENTIAL=PROFILE")?;
        let profile = CredentialProfile::parse(name).ok_or_else(|| {
            format!("unknown credential profile {name}; supported: {SUPPORTED_PROFILES}")
        })?;
        if !mapped_credentials.contains(credential) {
            return Err(format!(
                "--credential-profile {credential} is not mapped by any --map UNIT=CREDENTIAL"
            ));
        }
        if resolved.iter().any(|(existing, _)| existing == credential) {
            return Err(format!(
                "duplicate --credential-profile for credential {credential}"
            ));
        }
        resolved.push((credential.to_owned(), profile));
    }
    Ok(resolved)
}

impl BrokerState {
    /// Select the profile for every destination whose credential has this name.
    pub fn set_credential_profile(&mut self, credential: &str, profile: CredentialProfile) {
        self.credential_profiles
            .insert(credential.to_owned(), profile);
    }

    #[must_use]
    pub fn credential_profile(&self, credential: &str) -> Option<CredentialProfile> {
        self.credential_profiles.get(credential).copied()
    }

    /// Provisioning gate: runs after the HPKE open and before any insertion.
    pub(crate) fn enforce_provisioned_profile(
        &self,
        credential: &str,
        plaintext: &[u8],
    ) -> Result<(), BrokerError> {
        match self.credential_profile(credential) {
            Some(profile) => profile
                .validate(plaintext)
                .map_err(|error| BrokerError::Configuration(error.code())),
            None => Ok(()),
        }
    }

    /// Delivery gate: re-validates the stored value before any byte leaves the
    /// broker. A value that no longer passes is removed (fail closed). An absent
    /// value is left to the caller's ordinary missing-credential error.
    pub(crate) fn revalidate_delivery_profile(
        &mut self,
        unit: &str,
        credential: &str,
    ) -> Result<(), BrokerError> {
        let Some(profile) = self.credential_profile(credential) else {
            return Ok(());
        };
        let key = destination_key(unit, credential);
        let Ok(value) = self.credentials.get(&key) else {
            return Ok(());
        };
        if let Err(error) = profile.validate(value) {
            self.credentials.remove(&key);
            self.credential_expiries.remove(&key);
            return Err(BrokerError::Configuration(error.code()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialProfile, FileCredentialError, PASSWORD_FILE_MAX_BYTES, resolve_profile_options,
        validate_password_file,
    };
    use crate::{
        BrokerError, BrokerState, destination_key, handle_systemd_credential_connection,
        provision_aad, reject_connection,
    };
    use blindpass_core::custody::RecipientKeyPair;
    use blindpass_core::delivery::{DeliveryError, DeliveryPolicy};
    use blindpass_core::identity::PeerIdentity;
    use std::collections::BTreeSet;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const UNIT: &str = "example-backup.service";
    const CREDENTIAL: &str = "restic-password";
    const ROUTE: &[u8] = b"d7067f78/unit/example-backup.service/restic-password";

    fn peer() -> PeerIdentity {
        PeerIdentity::fixture(0, 0, UNIT, "inv-example-backup", "root")
    }

    fn profiled_state(credential_lifetime: Duration) -> BrokerState {
        let mut state = BrokerState::with_lifetimes(
            DeliveryPolicy::default(),
            Duration::from_secs(30),
            credential_lifetime,
        );
        state.loader_policy.map_unit(UNIT, CREDENTIAL).unwrap();
        state.set_credential_profile(CREDENTIAL, CredentialProfile::PasswordFile);
        state
    }

    /// The real provisioning path: a one-use recipient key, an HPKE seal bound to
    /// the destination AAD, then `provision_sealed`.
    fn provision(state: &mut BrokerState, value: &[u8]) -> Result<(), BrokerError> {
        let key = state.provision_key(UNIT, CREDENTIAL).unwrap();
        let sealed =
            RecipientKeyPair::seal(&key, value, provision_aad(UNIT, CREDENTIAL).as_bytes())
                .unwrap();
        state.provision_sealed(UNIT, CREDENTIAL, &sealed.enc, &sealed.ciphertext)
    }

    fn deliver(state: &mut BrokerState) -> Result<Vec<u8>, BrokerError> {
        state
            .process_loader(&peer(), UNIT, CREDENTIAL)
            .map(|value| value.as_bytes().to_vec())
    }

    fn stored(state: &BrokerState) -> Option<Vec<u8>> {
        state
            .credentials
            .get(&destination_key(UNIT, CREDENTIAL))
            .ok()
            .map(<[u8]>::to_vec)
    }

    fn code_of(error: &BrokerError) -> &'static str {
        match error {
            BrokerError::Configuration(code) => code,
            other => panic!("expected a configuration code, got {other}"),
        }
    }

    // ---- validator ------------------------------------------------------

    #[test]
    fn password_file_accepts_plain_passwords_and_json_looking_text_literally() {
        for value in [
            &b"P05-RESTIC-PASSWORD-0123456789abcdef"[..],
            b"a",
            b"inner space and\xc3\xa9\xe4\xb8\xad unicode ok",
            // A JSON envelope is not decoded. It is only ever accepted as
            // literal password text because it passes the character rules.
            br#"{"v":1,"password":"P05-RESTIC-PASSWORD","sha256":"00"}"#,
            b"\"quoted\"",
            // Interior U+2028 is not a control character and restic does not touch it.
            "inner\u{2028}separator".as_bytes(),
        ] {
            assert_eq!(validate_password_file(value), Ok(()), "{value:?}");
        }
    }

    #[test]
    fn password_file_rejects_empty_oversized_and_non_utf8() {
        assert_eq!(validate_password_file(b""), Err(FileCredentialError::Empty));
        assert_eq!(
            validate_password_file(&vec![b'a'; PASSWORD_FILE_MAX_BYTES + 1]),
            Err(FileCredentialError::TooLong)
        );
        // Length is checked before decoding, so oversized invalid UTF-8 is "too long".
        assert_eq!(
            validate_password_file(&vec![0xff; PASSWORD_FILE_MAX_BYTES + 1]),
            Err(FileCredentialError::TooLong)
        );
        for value in [&b"\xff\xfe"[..], b"ab\x80cd", b"\xc3", b"\xed\xa0\x80"] {
            assert_eq!(
                validate_password_file(value),
                Err(FileCredentialError::InvalidUtf8),
                "{value:?}"
            );
        }
    }

    #[test]
    fn password_file_length_boundary_is_exact() {
        assert_eq!(
            validate_password_file(&vec![b'a'; PASSWORD_FILE_MAX_BYTES]),
            Ok(())
        );
        assert_eq!(
            validate_password_file(&vec![b'a'; PASSWORD_FILE_MAX_BYTES + 1]),
            Err(FileCredentialError::TooLong)
        );
    }

    #[test]
    fn password_file_rejects_every_control_character_including_a_trailing_newline() {
        // restic strips surrounding whitespace from the file, so a trailing
        // newline would make the repository password differ from the operator's.
        for value in [
            &b"secret\n"[..],
            b"secret\r\n",
            b"secret\r",
            b"\nsecret",
            b"sec\tret",
            b"sec\0ret",
            b"sec\x1bret",
            b"sec\x7fret",
            "sec\u{85}ret".as_bytes(),
            "sec\u{9f}ret".as_bytes(),
        ] {
            assert_eq!(
                validate_password_file(value),
                Err(FileCredentialError::ControlCharacter),
                "{value:?}"
            );
        }
        for control in (0u32..0x20).chain(0x7f..=0x9f) {
            let value = format!("a{}b", char::from_u32(control).unwrap());
            assert_eq!(
                validate_password_file(value.as_bytes()),
                Err(FileCredentialError::ControlCharacter),
                "U+{control:04X}"
            );
        }
    }

    #[test]
    fn password_file_rejects_leading_or_trailing_whitespace_and_a_leading_bom() {
        for value in [
            " secret",
            "secret ",
            " ",
            "\u{a0}secret",
            "secret\u{2003}",
            "\u{3000}secret",
            "secret\u{2028}",
            "\u{2029}secret",
        ] {
            assert_eq!(
                validate_password_file(value.as_bytes()),
                Err(FileCredentialError::EdgeWhitespace),
                "{value:?}"
            );
        }
        assert_eq!(
            validate_password_file("\u{feff}secret".as_bytes()),
            Err(FileCredentialError::ByteOrderMark)
        );
        // The same code point is not stripped when it is not the first one.
        assert_eq!(validate_password_file("se\u{feff}cret".as_bytes()), Ok(()));
    }

    #[test]
    fn password_file_errors_are_fixed_codes_that_never_contain_bytes() {
        let canary = "P05-ERROR-CANARY-0123456789 \n";
        let error = validate_password_file(canary.as_bytes()).unwrap_err();
        for text in [
            error.to_string(),
            format!("{error:?}"),
            error.code().to_owned(),
        ] {
            assert!(!text.contains("P05-ERROR-CANARY"), "{text}");
        }
        for (error, code) in [
            (FileCredentialError::Empty, "password_file_empty"),
            (FileCredentialError::TooLong, "password_file_too_long"),
            (
                FileCredentialError::InvalidUtf8,
                "password_file_invalid_utf8",
            ),
            (
                FileCredentialError::ControlCharacter,
                "password_file_control_character",
            ),
            (
                FileCredentialError::ByteOrderMark,
                "password_file_byte_order_mark",
            ),
            (
                FileCredentialError::EdgeWhitespace,
                "password_file_edge_whitespace",
            ),
        ] {
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), code);
        }
    }

    // ---- startup selection ---------------------------------------------

    fn mapped(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn options(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn profile_options_accept_repeated_mapped_credentials() {
        let resolved = resolve_profile_options(
            &options(&[
                "restic-password=password-file",
                "other-password=password-file",
            ]),
            &mapped(&["restic-password", "other-password", "api-key"]),
        )
        .unwrap();
        assert_eq!(
            resolved,
            vec![
                (
                    "restic-password".to_owned(),
                    CredentialProfile::PasswordFile
                ),
                ("other-password".to_owned(), CredentialProfile::PasswordFile),
            ]
        );
        assert!(
            resolve_profile_options(&[], &mapped(&["api-key"]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn profile_options_reject_unknown_unmapped_duplicate_and_malformed_values() {
        let mapped = mapped(&["restic-password"]);
        let unknown = resolve_profile_options(&options(&["restic-password=json"]), &mapped);
        assert!(unknown.unwrap_err().contains("unknown credential profile"));
        let unmapped = resolve_profile_options(&options(&["missing=password-file"]), &mapped);
        assert!(unmapped.unwrap_err().contains("not mapped"));
        let duplicate = resolve_profile_options(
            &options(&[
                "restic-password=password-file",
                "restic-password=password-file",
            ]),
            &mapped,
        );
        assert!(duplicate.unwrap_err().contains("duplicate"));
        for malformed in ["", "restic-password", "=password-file", "restic-password="] {
            assert!(
                resolve_profile_options(&options(&[malformed]), &mapped).is_err(),
                "{malformed:?}"
            );
        }
    }

    // ---- provisioning enforcement --------------------------------------

    #[test]
    fn invalid_plaintext_is_rejected_after_open_with_a_fixed_code_and_nothing_stored() {
        let mut state = profiled_state(Duration::from_secs(60));
        let canary = b"P05-REJECTED-CANARY-0123456789\n";
        let key = state.provision_key(UNIT, CREDENTIAL).unwrap();
        let sealed =
            RecipientKeyPair::seal(&key, canary, provision_aad(UNIT, CREDENTIAL).as_bytes())
                .unwrap();
        let error = state
            .provision_sealed(UNIT, CREDENTIAL, &sealed.enc, &sealed.ciphertext)
            .unwrap_err();
        assert_eq!(code_of(&error), "password_file_control_character");
        assert!(!error.to_string().contains("P05-REJECTED-CANARY"));
        assert_eq!(stored(&state), None);
        assert!(state.credential_expiries.is_empty());
        // The one-use recipient key was spent by the open, so the same envelope
        // cannot be retried and a fresh key is required.
        assert_eq!(state.custody.len(), 0);
        assert!(
            state
                .provision_sealed(UNIT, CREDENTIAL, &sealed.enc, &sealed.ciphertext)
                .is_err()
        );
        assert_eq!(stored(&state), None);
    }

    #[test]
    fn rejected_provisioning_keeps_the_existing_credential_and_its_expiry() {
        let mut state = profiled_state(Duration::from_secs(60));
        provision(&mut state, b"P05-FIRST-VALID-PASSWORD").unwrap();
        let key = destination_key(UNIT, CREDENTIAL);
        let before = *state.credential_expiries.get(&key).unwrap();
        for invalid in [
            &b"P05-SECOND\n"[..],
            b"",
            b" padded",
            b"\xff\xfe",
            &[b'x'; PASSWORD_FILE_MAX_BYTES + 1],
        ] {
            // An empty plaintext cannot even be sealed by the CLI, but the broker
            // gate must still hold if a peer sends one.
            assert!(provision(&mut state, invalid).is_err(), "{invalid:?}");
            assert_eq!(
                deliver(&mut state).unwrap(),
                b"P05-FIRST-VALID-PASSWORD",
                "{invalid:?}"
            );
        }
        let after = *state.credential_expiries.get(&key).unwrap();
        assert_eq!(before.boot, after.boot);
        assert_eq!(before.runnable, after.runnable);
    }

    // ---- rotation, expiry and restart ----------------------------------

    #[test]
    fn rotation_delivers_exactly_the_latest_provisioned_value() {
        let mut state = profiled_state(Duration::from_secs(60));
        provision(&mut state, b"P05-ROTATION-A-0123456789").unwrap();
        assert_eq!(deliver(&mut state).unwrap(), b"P05-ROTATION-A-0123456789");
        provision(&mut state, b"P05-ROTATION-B-abcdef").unwrap();
        let delivered = deliver(&mut state).unwrap();
        assert_eq!(delivered, b"P05-ROTATION-B-abcdef");
        // Not a prefix, suffix or padded variant of the previous (longer) value.
        assert_eq!(delivered.len(), b"P05-ROTATION-B-abcdef".len());
        assert_eq!(
            state
                .credentials
                .get(&destination_key(UNIT, CREDENTIAL))
                .unwrap(),
            delivered
        );
    }

    #[test]
    fn credential_lifetime_expiry_denies_delivery_and_leaves_no_bytes() {
        let mut state = profiled_state(Duration::from_millis(600));
        provision(&mut state, b"P05-EXPIRY-CANARY-0123456789").unwrap();
        assert_eq!(
            deliver(&mut state).unwrap(),
            b"P05-EXPIRY-CANARY-0123456789"
        );
        std::thread::sleep(Duration::from_millis(1000));
        assert!(matches!(
            deliver(&mut state),
            Err(BrokerError::Delivery(DeliveryError::Missing))
        ));
        assert!(matches!(
            state.process_systemd_credential(UNIT, CREDENTIAL),
            Err(BrokerError::Delivery(DeliveryError::Missing))
        ));
        assert_eq!(stored(&state), None);
        assert!(state.credential_expiries.is_empty());
    }

    #[test]
    fn broker_restart_loses_custody_and_delivery_fails_closed_until_reprovisioned() {
        let mut state = profiled_state(Duration::from_secs(60));
        provision(&mut state, b"P05-RESTART-CANARY-0123456789").unwrap();
        assert!(deliver(&mut state).is_ok());
        drop(state);
        // A restarted broker is a fresh BrokerState with the same flags: custody is
        // memory-only, so nothing is deliverable and no unattended restart exists.
        let state = Arc::new(Mutex::new(profiled_state(Duration::from_secs(60))));
        let (mut broker_stream, mut client) = UnixStream::pair().unwrap();
        let result =
            handle_systemd_credential_connection(&mut broker_stream, &state, &peer(), ROUTE, None);
        assert!(matches!(
            result,
            Err(BrokerError::Delivery(DeliveryError::Missing))
        ));
        reject_connection("loader", &mut broker_stream, &result.unwrap_err());
        drop(broker_stream);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.is_empty());
        // Recovery: re-provision, then delivery works again.
        provision(&mut state.lock().unwrap(), b"P05-RESTART-REPROVISIONED").unwrap();
        assert_eq!(
            deliver(&mut state.lock().unwrap()).unwrap(),
            b"P05-RESTART-REPROVISIONED"
        );
    }

    // ---- delivery enforcement ------------------------------------------

    #[test]
    fn a_damaged_stored_value_fails_closed_without_bytes_and_is_purged() {
        for route_is_systemd in [false, true] {
            let mut state = profiled_state(Duration::from_secs(60));
            // Bypass provisioning to model damage of the in-memory value.
            state
                .credentials
                .insert(&destination_key(UNIT, CREDENTIAL), b"P05-DAMAGED-CANARY\n")
                .unwrap();
            let error = if route_is_systemd {
                state
                    .process_systemd_credential(UNIT, CREDENTIAL)
                    .unwrap_err()
            } else {
                state.process_loader(&peer(), UNIT, CREDENTIAL).unwrap_err()
            };
            assert_eq!(code_of(&error), "password_file_control_character");
            assert!(!error.to_string().contains("P05-DAMAGED-CANARY"));
            assert_eq!(stored(&state), None, "the damaged value is purged");
        }
        // Through the connection handler the peer receives no bytes at all.
        let mut state = profiled_state(Duration::from_secs(60));
        state
            .credentials
            .insert(&destination_key(UNIT, CREDENTIAL), b"P05-DAMAGED-CANARY\n")
            .unwrap();
        let state = Arc::new(Mutex::new(state));
        let (mut broker_stream, mut client) = UnixStream::pair().unwrap();
        let error =
            handle_systemd_credential_connection(&mut broker_stream, &state, &peer(), ROUTE, None)
                .unwrap_err();
        reject_connection("loader", &mut broker_stream, &error);
        drop(broker_stream);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.is_empty());
    }

    #[test]
    fn delivered_frame_length_equals_the_credential_length() {
        for length in [1, 17, 512, PASSWORD_FILE_MAX_BYTES] {
            let password: Vec<u8> = (0..length)
                .map(|index| b"abcdefghijklmnopqrstuvwxyz0123456789"[index % 36])
                .collect();
            let mut state = profiled_state(Duration::from_secs(60));
            provision(&mut state, &password).unwrap();
            let state = Arc::new(Mutex::new(state));
            let (mut broker_stream, mut client) = UnixStream::pair().unwrap();
            handle_systemd_credential_connection(&mut broker_stream, &state, &peer(), ROUTE, None)
                .unwrap();
            drop(broker_stream);
            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            assert_eq!(response.len(), length);
            assert_eq!(response, password);
        }
    }

    #[test]
    fn the_profile_is_scoped_to_its_credential_and_legacy_delivery_is_unchanged() {
        let mut state = profiled_state(Duration::from_secs(60));
        state
            .loader_policy
            .map_unit("legacy.service", "api-key")
            .unwrap();
        assert_eq!(
            state.credential_profile(CREDENTIAL),
            Some(CredentialProfile::PasswordFile)
        );
        assert_eq!(state.credential_profile("api-key"), None);
        // The legacy credential keeps accepting any non-empty bytes, byte for byte.
        let legacy: &[u8] = b"ERR \0\xffbinary\n";
        let key = state.provision_key("legacy.service", "api-key").unwrap();
        let sealed = RecipientKeyPair::seal(
            &key,
            legacy,
            provision_aad("legacy.service", "api-key").as_bytes(),
        )
        .unwrap();
        state
            .provision_sealed("legacy.service", "api-key", &sealed.enc, &sealed.ciphertext)
            .unwrap();
        let legacy_peer = PeerIdentity::fixture(0, 0, "legacy.service", "inv-legacy", "root");
        assert_eq!(
            state
                .process_loader(&legacy_peer, "legacy.service", "api-key")
                .unwrap()
                .as_bytes(),
            legacy
        );
        // With no profile configured at all the same bytes are accepted for the
        // restic credential name too.
        let mut plain = BrokerState::with_lifetimes(
            DeliveryPolicy::default(),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        plain.loader_policy.map_unit(UNIT, CREDENTIAL).unwrap();
        provision(&mut plain, b"trailing newline\n").unwrap();
        assert_eq!(deliver(&mut plain).unwrap(), b"trailing newline\n");
    }

    // ---- startup bound over a real Unix socket --------------------------

    #[test]
    fn a_preprovisioned_credential_is_available_within_the_five_second_startup_bound() {
        const BOUND: Duration = Duration::from_secs(5);
        let directory = std::env::temp_dir().join(format!(
            "blindpass-p05-loader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let socket = directory.join("loader.sock");
        let listener = crate::bind_socket(&socket, 0o750, 0o600).unwrap();
        let mut state = profiled_state(Duration::from_secs(60));
        provision(&mut state, b"P05-PREPROVISIONED-0123456789").unwrap();
        let state = Arc::new(Mutex::new(state));
        let served = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = crate::serve_connections(
                listener,
                Duration::from_secs(2),
                move |stream, _deadline| {
                    // The kernel identity step is replaced by a fixed root peer; the
                    // route parse, protected mapping, custody read and frame write
                    // are the production handler.
                    handle_systemd_credential_connection(stream, &served, &peer(), ROUTE, None)
                },
                "loader",
            );
        });
        let started = Instant::now();
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.set_read_timeout(Some(BOUND)).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let elapsed = started.elapsed();
        eprintln!(
            "P05-STARTUP-BOUND connect_to_eof_ms={} bound_ms={}",
            elapsed.as_millis(),
            BOUND.as_millis()
        );
        assert_eq!(response, b"P05-PREPROVISIONED-0123456789");
        assert!(elapsed < BOUND, "{elapsed:?}");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
