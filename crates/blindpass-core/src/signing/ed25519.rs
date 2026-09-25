// SPDX-License-Identifier: AGPL-3.0-only

//! Ed25519 signatures backed by the host OpenSSL libcrypto.

use crate::custody::CryptoError;
use crate::secret::{SecretBytes, wipe};
use std::fmt;
use std::os::raw::{c_int, c_void};
use std::ptr;

const SEED_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const EVP_PKEY_ED25519: c_int = 1087;

#[allow(non_camel_case_types)]
type EVP_PKEY = c_void;
#[allow(non_camel_case_types)]
type EVP_MD_CTX = c_void;
#[allow(non_camel_case_types)]
type EVP_PKEY_CTX = c_void;
#[allow(non_camel_case_types)]
type EVP_MD = c_void;

#[link(name = "crypto")]
unsafe extern "C" {
    fn RAND_bytes(buffer: *mut u8, length: c_int) -> c_int;
    fn EVP_PKEY_new_raw_private_key(
        key_type: c_int,
        engine: *mut c_void,
        key: *const u8,
        length: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_new_raw_public_key(
        key_type: c_int,
        engine: *mut c_void,
        key: *const u8,
        length: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_get_raw_public_key(
        key: *const EVP_PKEY,
        public_key: *mut u8,
        length: *mut usize,
    ) -> c_int;
    fn EVP_PKEY_free(key: *mut EVP_PKEY);
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(context: *mut EVP_MD_CTX);
    fn EVP_DigestSignInit(
        context: *mut EVP_MD_CTX,
        key_context: *mut *mut EVP_PKEY_CTX,
        digest: *const EVP_MD,
        engine: *mut c_void,
        key: *mut EVP_PKEY,
    ) -> c_int;
    fn EVP_DigestSign(
        context: *mut EVP_MD_CTX,
        signature: *mut u8,
        signature_length: *mut usize,
        message: *const u8,
        message_length: usize,
    ) -> c_int;
    fn EVP_DigestVerifyInit(
        context: *mut EVP_MD_CTX,
        key_context: *mut *mut EVP_PKEY_CTX,
        digest: *const EVP_MD,
        engine: *mut c_void,
        key: *mut EVP_PKEY,
    ) -> c_int;
    fn EVP_DigestVerify(
        context: *mut EVP_MD_CTX,
        signature: *const u8,
        signature_length: usize,
        message: *const u8,
        message_length: usize,
    ) -> c_int;
}

/// An Ed25519 seed and its public key. Debug output never includes key bytes.
pub struct Ed25519KeyPair {
    seed: SecretBytes,
    public_key: [u8; PUBLIC_KEY_BYTES],
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ed25519KeyPair")
            .field("public_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Ed25519KeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0; SEED_BYTES];
        // SAFETY: OpenSSL writes exactly SEED_BYTES to a valid writable buffer.
        let result = unsafe { RAND_bytes(seed.as_mut_ptr(), c_int::try_from(seed.len()).unwrap()) };
        if result != 1 {
            wipe(&mut seed);
            return Err(CryptoError::OpenSsl("RAND_bytes failed"));
        }
        let result = Self::from_seed(&seed);
        wipe(&mut seed);
        result
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() != SEED_BYTES {
            return Err(CryptoError::InvalidKeyLength);
        }
        let key = PKey::from_private(seed)?;
        let mut public_key = [0; PUBLIC_KEY_BYTES];
        let mut length = public_key.len();
        // SAFETY: key is valid and public_key has the OpenSSL Ed25519 key size.
        let result =
            unsafe { EVP_PKEY_get_raw_public_key(key.0, public_key.as_mut_ptr(), &mut length) };
        if result != 1 || length != PUBLIC_KEY_BYTES {
            wipe(&mut public_key);
            return Err(CryptoError::OpenSsl("EVP_PKEY_get_raw_public_key failed"));
        }
        Ok(Self {
            seed: SecretBytes::from_slice(seed),
            public_key,
        })
    }

    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], CryptoError> {
        let key = PKey::from_private(self.seed.as_bytes())?;
        let context = MdContext::new()?;
        // SAFETY: key and context are live; Ed25519 requires a null digest.
        if unsafe {
            EVP_DigestSignInit(
                context.0,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                key.0,
            )
        } != 1
        {
            return Err(CryptoError::OpenSsl("EVP_DigestSignInit failed"));
        }
        let mut signature = [0; SIGNATURE_BYTES];
        let mut signature_length = signature.len();
        // SAFETY: the context was initialized with key and output has 64 bytes.
        let result = unsafe {
            EVP_DigestSign(
                context.0,
                signature.as_mut_ptr(),
                &mut signature_length,
                message_pointer(message),
                message.len(),
            )
        };
        if result != 1 || signature_length != SIGNATURE_BYTES {
            wipe(&mut signature);
            return Err(CryptoError::OpenSsl("EVP_DigestSign failed"));
        }
        Ok(signature)
    }
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    if public_key.len() != PUBLIC_KEY_BYTES || signature.len() != SIGNATURE_BYTES {
        return Ok(false);
    }
    // SAFETY: lengths were checked against the Ed25519 raw key format.
    let key = unsafe {
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519,
            ptr::null_mut(),
            public_key.as_ptr(),
            public_key.len(),
        )
    };
    let key = PKey(key);
    if key.0.is_null() {
        return Err(CryptoError::OpenSsl("EVP_PKEY_new_raw_public_key failed"));
    }
    let context = MdContext::new()?;
    // SAFETY: key and context are live; Ed25519 requires a null digest.
    if unsafe {
        EVP_DigestVerifyInit(
            context.0,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            key.0,
        )
    } != 1
    {
        return Err(CryptoError::OpenSsl("EVP_DigestVerifyInit failed"));
    }
    // SAFETY: pointers refer to buffers of the lengths supplied below.
    Ok(unsafe {
        EVP_DigestVerify(
            context.0,
            signature.as_ptr(),
            signature.len(),
            message_pointer(message),
            message.len(),
        ) == 1
    })
}

fn message_pointer(message: &[u8]) -> *const u8 {
    if message.is_empty() {
        ptr::null()
    } else {
        message.as_ptr()
    }
}

struct PKey(*mut EVP_PKEY);

impl PKey {
    fn from_private(seed: &[u8]) -> Result<Self, CryptoError> {
        // SAFETY: seed length is validated by callers before this helper is used.
        let key = unsafe {
            EVP_PKEY_new_raw_private_key(
                EVP_PKEY_ED25519,
                ptr::null_mut(),
                seed.as_ptr(),
                seed.len(),
            )
        };
        if key.is_null() {
            Err(CryptoError::OpenSsl("EVP_PKEY_new_raw_private_key failed"))
        } else {
            Ok(Self(key))
        }
    }
}

impl Drop for PKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns a live EVP_PKEY.
            unsafe { EVP_PKEY_free(self.0) };
        }
    }
}

struct MdContext(*mut EVP_MD_CTX);

impl MdContext {
    fn new() -> Result<Self, CryptoError> {
        // SAFETY: OpenSSL allocates a new digest context or returns null.
        let context = unsafe { EVP_MD_CTX_new() };
        if context.is_null() {
            Err(CryptoError::OpenSsl("EVP_MD_CTX_new failed"))
        } else {
            Ok(Self(context))
        }
    }
}

impl Drop for MdContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns a live EVP_MD_CTX.
            unsafe { EVP_MD_CTX_free(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519KeyPair, verify};

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        let mut output = [0; N];
        assert_eq!(value.len(), N * 2);
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid hex vector"),
            };
            output[index] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        output
    }

    #[test]
    fn matches_rfc_8032_test_vector_one() {
        let seed = hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public =
            hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = hex::<64>(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
            5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let key_pair = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key_pair.public_key(), &expected_public);
        let signature = key_pair.sign(b"").unwrap();
        assert_eq!(signature, expected_signature);
        assert!(verify(&expected_public, b"", &signature).unwrap());
    }

    #[test]
    fn signatures_reject_changed_messages_and_malformed_lengths() {
        let seed = [7; 32];
        let key_pair = Ed25519KeyPair::from_seed(&seed).unwrap();
        let signature = key_pair.sign(b"fleet-message").unwrap();
        assert!(verify(key_pair.public_key(), b"fleet-message", &signature).unwrap());
        assert!(!verify(key_pair.public_key(), b"changed", &signature).unwrap());
        assert!(!verify(key_pair.public_key(), b"fleet-message", &[0; 63]).unwrap());
        assert!(!verify(&[0; 31], b"fleet-message", &signature).unwrap());
    }

    #[test]
    fn debug_does_not_include_seed_or_public_key_bytes() {
        let seed = [0x5a; 32];
        let key_pair = Ed25519KeyPair::from_seed(&seed).unwrap();
        let output = format!("{key_pair:?}");
        assert!(output.contains("redacted"));
        assert!(!output.contains("5a"));
    }
}
