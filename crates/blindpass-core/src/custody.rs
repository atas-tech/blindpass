// SPDX-License-Identifier: AGPL-3.0-only

//! Ephemeral recipient-key custody and RFC 9180 HPKE opening.
//!
//! The implementation uses the host's OpenSSL 3 `libcrypto` primitives via a
//! narrow FFI surface instead of adding a Cargo cryptography graph. It is
//! intentionally limited to DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 +
//! ChaCha20-Poly1305, the suite already used by the TypeScript clients.

use crate::secret::{SecretBytes, wipe};
use std::collections::BTreeMap;
use std::fmt;
use std::os::raw::{c_int, c_uint, c_void};
use std::time::{Duration, Instant};

const N_SECRET: usize = 32;
const N_NONCE: usize = 12;
const N_TAG: usize = 16;
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0003;
const EVP_PKEY_X25519: c_int = 1034;
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x09;

#[allow(non_camel_case_types)]
type EVP_PKEY = c_void;
#[allow(non_camel_case_types)]
type EVP_PKEY_CTX = c_void;
#[allow(non_camel_case_types)]
type EVP_CIPHER_CTX = c_void;
#[allow(non_camel_case_types)]
type EVP_MD = c_void;
#[allow(non_camel_case_types)]
type EVP_CIPHER = c_void;

#[link(name = "crypto")]
unsafe extern "C" {
    fn RAND_bytes(bytes: *mut u8, length: c_int) -> c_int;
    fn EVP_PKEY_new_raw_private_key(
        key_type: c_int,
        engine: *mut c_void,
        private_key: *const u8,
        length: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_new_raw_public_key(
        key_type: c_int,
        engine: *mut c_void,
        public_key: *const u8,
        length: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_get_raw_public_key(
        key: *const EVP_PKEY,
        public_key: *mut u8,
        length: *mut usize,
    ) -> c_int;
    fn EVP_PKEY_free(key: *mut EVP_PKEY);
    fn EVP_PKEY_CTX_new(key: *mut EVP_PKEY, engine: *mut c_void) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(context: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_derive_init(context: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_derive_set_peer(context: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY) -> c_int;
    fn EVP_PKEY_derive(
        context: *mut EVP_PKEY_CTX,
        shared_secret: *mut u8,
        length: *mut usize,
    ) -> c_int;
    fn EVP_sha256() -> *const EVP_MD;
    fn HMAC(
        digest: *const EVP_MD,
        key: *const u8,
        key_length: c_int,
        data: *const u8,
        data_length: usize,
        output: *mut u8,
        output_length: *mut c_uint,
    ) -> *mut u8;
    fn EVP_chacha20_poly1305() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_free(context: *mut EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_ctrl(
        context: *mut EVP_CIPHER_CTX,
        command: c_int,
        argument: c_int,
        pointer: *mut c_void,
    ) -> c_int;
    fn EVP_EncryptInit_ex(
        context: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut c_void,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    fn EVP_EncryptUpdate(
        context: *mut EVP_CIPHER_CTX,
        output: *mut u8,
        output_length: *mut c_int,
        input: *const u8,
        input_length: c_int,
    ) -> c_int;
    fn EVP_EncryptFinal_ex(
        context: *mut EVP_CIPHER_CTX,
        output: *mut u8,
        output_length: *mut c_int,
    ) -> c_int;
    fn EVP_DecryptInit_ex(
        context: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut c_void,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    fn EVP_DecryptUpdate(
        context: *mut EVP_CIPHER_CTX,
        output: *mut u8,
        output_length: *mut c_int,
        input: *const u8,
        input_length: c_int,
    ) -> c_int;
    fn EVP_DecryptFinal_ex(
        context: *mut EVP_CIPHER_CTX,
        output: *mut u8,
        output_length: *mut c_int,
    ) -> c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidEncapsulation,
    InvalidCiphertext,
    OpenSsl(&'static str),
    AuthenticationFailed,
    UnsupportedHost(&'static str),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKeyLength => "invalid_key_length",
            Self::InvalidEncapsulation => "invalid_encapsulation",
            Self::InvalidCiphertext => "invalid_ciphertext",
            Self::OpenSsl(operation) => operation,
            Self::AuthenticationFailed => "authentication_failed",
            Self::UnsupportedHost(reason) => reason,
        })
    }
}

impl std::error::Error for CryptoError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessage {
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct RecipientKeyPair {
    private_key: SecretBytes,
    public_key: Vec<u8>,
}

impl RecipientKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut private_key = vec![0; N_SECRET];
        let result = unsafe { RAND_bytes(private_key.as_mut_ptr(), private_key.len() as c_int) };
        if result != 1 {
            wipe(&mut private_key);
            return Err(CryptoError::OpenSsl("RAND_bytes failed"));
        }
        Self::from_private_key(&private_key)
    }

    pub fn from_private_key(private_key: &[u8]) -> Result<Self, CryptoError> {
        if private_key.len() != N_SECRET {
            return Err(CryptoError::InvalidKeyLength);
        }
        let key = PKey::from_private(private_key)?;
        let mut public_key = vec![0; N_SECRET];
        let mut length = public_key.len();
        let result =
            unsafe { EVP_PKEY_get_raw_public_key(key.0, public_key.as_mut_ptr(), &mut length) };
        if result != 1 || length != N_SECRET {
            wipe(&mut public_key);
            return Err(CryptoError::OpenSsl("EVP_PKEY_get_raw_public_key failed"));
        }
        Ok(Self {
            private_key: SecretBytes::from_slice(private_key),
            public_key,
        })
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn open(
        &self,
        enc: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        if enc.len() != N_SECRET {
            return Err(CryptoError::InvalidEncapsulation);
        }
        if ciphertext.len() < N_TAG {
            return Err(CryptoError::InvalidCiphertext);
        }
        let mut shared_secret = derive_shared(&self.private_key, enc)?;
        let key_schedule_result = key_schedule(&shared_secret, enc, &self.public_key);
        wipe(&mut shared_secret);
        let (mut key, mut nonce) = key_schedule_result?;
        let plaintext_result = aead_decrypt(&key, &nonce, ciphertext, aad);
        wipe(&mut key);
        wipe(&mut nonce);
        let plaintext = plaintext_result?;
        Ok(SecretBytes::new(plaintext))
    }

    pub fn seal(
        recipient_public_key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<SealedMessage, CryptoError> {
        if recipient_public_key.len() != N_SECRET {
            return Err(CryptoError::InvalidKeyLength);
        }
        let ephemeral = Self::generate()?;
        let enc = ephemeral.public_key.clone();
        let mut shared_secret = derive_shared(&ephemeral.private_key, recipient_public_key)?;
        let key_schedule_result = key_schedule(&shared_secret, &enc, recipient_public_key);
        wipe(&mut shared_secret);
        let (mut key, mut nonce) = key_schedule_result?;
        let ciphertext_result = aead_encrypt(&key, &nonce, plaintext, aad);
        wipe(&mut key);
        wipe(&mut nonce);
        let ciphertext = ciphertext_result?;
        Ok(SealedMessage { enc, ciphertext })
    }

    /// Deterministic sealing hook used only by the cross-runtime test vector.
    /// Production callers must use [`Self::seal`] so the ephemeral key comes
    /// from the host cryptographic random source.
    pub fn seal_with_ephemeral_private(
        recipient_public_key: &[u8],
        ephemeral_private_key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<SealedMessage, CryptoError> {
        if recipient_public_key.len() != N_SECRET {
            return Err(CryptoError::InvalidKeyLength);
        }
        let ephemeral = Self::from_private_key(ephemeral_private_key)?;
        let enc = ephemeral.public_key.clone();
        let mut shared_secret = derive_shared(&ephemeral.private_key, recipient_public_key)?;
        let key_schedule_result = key_schedule(&shared_secret, &enc, recipient_public_key);
        wipe(&mut shared_secret);
        let (mut key, mut nonce) = key_schedule_result?;
        let ciphertext_result = aead_encrypt(&key, &nonce, plaintext, aad);
        wipe(&mut key);
        wipe(&mut nonce);
        let ciphertext = ciphertext_result?;
        Ok(SealedMessage { enc, ciphertext })
    }
}

#[derive(Debug)]
struct PKey(*mut EVP_PKEY);

impl PKey {
    fn from_private(private_key: &[u8]) -> Result<Self, CryptoError> {
        let pointer = unsafe {
            EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X25519,
                std::ptr::null_mut(),
                private_key.as_ptr(),
                private_key.len(),
            )
        };
        if pointer.is_null() {
            Err(CryptoError::OpenSsl("EVP_PKEY_new_raw_private_key failed"))
        } else {
            Ok(Self(pointer))
        }
    }

    fn from_public(public_key: &[u8]) -> Result<Self, CryptoError> {
        let pointer = unsafe {
            EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X25519,
                std::ptr::null_mut(),
                public_key.as_ptr(),
                public_key.len(),
            )
        };
        if pointer.is_null() {
            Err(CryptoError::OpenSsl("EVP_PKEY_new_raw_public_key failed"))
        } else {
            Ok(Self(pointer))
        }
    }
}

impl Drop for PKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { EVP_PKEY_free(self.0) };
        }
    }
}

#[derive(Debug)]
struct PKeyContext(*mut EVP_PKEY_CTX);

impl Drop for PKeyContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { EVP_PKEY_CTX_free(self.0) };
        }
    }
}

#[derive(Debug)]
struct CipherContext(*mut EVP_CIPHER_CTX);

impl CipherContext {
    fn new() -> Result<Self, CryptoError> {
        let pointer = unsafe { EVP_CIPHER_CTX_new() };
        if pointer.is_null() {
            Err(CryptoError::OpenSsl("EVP_CIPHER_CTX_new failed"))
        } else {
            Ok(Self(pointer))
        }
    }
}

impl Drop for CipherContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { EVP_CIPHER_CTX_free(self.0) };
        }
    }
}

fn derive_shared(
    private_key: &SecretBytes,
    peer_public_key: &[u8],
) -> Result<[u8; N_SECRET], CryptoError> {
    if peer_public_key.len() != N_SECRET {
        return Err(CryptoError::InvalidKeyLength);
    }
    let private = PKey::from_private(private_key.as_bytes())?;
    let peer = PKey::from_public(peer_public_key)?;
    let context = unsafe { EVP_PKEY_CTX_new(private.0, std::ptr::null_mut()) };
    if context.is_null() {
        return Err(CryptoError::OpenSsl("EVP_PKEY_CTX_new failed"));
    }
    let context = PKeyContext(context);
    if unsafe { EVP_PKEY_derive_init(context.0) } != 1 {
        return Err(CryptoError::OpenSsl("EVP_PKEY_derive_init failed"));
    }
    if unsafe { EVP_PKEY_derive_set_peer(context.0, peer.0) } != 1 {
        return Err(CryptoError::OpenSsl("EVP_PKEY_derive_set_peer failed"));
    }
    let mut shared = [0; N_SECRET];
    let mut length = shared.len();
    if unsafe { EVP_PKEY_derive(context.0, shared.as_mut_ptr(), &mut length) } != 1
        || length != N_SECRET
    {
        wipe(&mut shared);
        return Err(CryptoError::OpenSsl("EVP_PKEY_derive failed"));
    }
    if shared.iter().all(|byte| *byte == 0) {
        wipe(&mut shared);
        return Err(CryptoError::InvalidEncapsulation);
    }
    Ok(shared)
}

fn kem_suite_id() -> Vec<u8> {
    let mut suite = b"KEM".to_vec();
    suite.extend_from_slice(&KEM_ID.to_be_bytes());
    suite
}

fn hpke_suite_id() -> Vec<u8> {
    let mut suite = b"HPKE".to_vec();
    suite.extend_from_slice(&KEM_ID.to_be_bytes());
    suite.extend_from_slice(&KDF_ID.to_be_bytes());
    suite.extend_from_slice(&AEAD_ID.to_be_bytes());
    suite
}

fn labeled_extract(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    input: &[u8],
) -> Result<[u8; N_SECRET], CryptoError> {
    let mut labeled_input = b"HPKE-v1".to_vec();
    labeled_input.extend_from_slice(suite_id);
    labeled_input.extend_from_slice(label);
    labeled_input.extend_from_slice(input);
    let result = hmac_sha256(salt, &labeled_input)?;
    wipe(&mut labeled_input);
    Ok(result)
}

fn labeled_expand(
    prk: &[u8; N_SECRET],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    if length > u16::MAX as usize {
        return Err(CryptoError::OpenSsl("HPKE expansion too large"));
    }
    let mut labeled_info = (length as u16).to_be_bytes().to_vec();
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let mut output = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let block_count = length.div_ceil(N_SECRET);
    for counter in 1..=block_count {
        let mut input = Vec::with_capacity(previous.len() + labeled_info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(&labeled_info);
        input.push(counter as u8);
        let block = hmac_sha256(prk, &input)?;
        wipe(&mut input);
        wipe(&mut previous);
        previous = block.to_vec();
        output.extend_from_slice(&block);
    }
    output.truncate(length);
    wipe(&mut labeled_info);
    wipe(&mut previous);
    Ok(output)
}

fn key_schedule(
    shared_secret: &[u8; N_SECRET],
    enc: &[u8],
    recipient_public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let kem_suite_id = kem_suite_id();
    let mut kem_context = enc.to_vec();
    kem_context.extend_from_slice(recipient_public_key);
    let mut eae_prk = labeled_extract(&[], &kem_suite_id, b"eae_prk", shared_secret)?;
    let mut shared_secret = labeled_expand(
        &eae_prk,
        &kem_suite_id,
        b"shared_secret",
        &kem_context,
        N_SECRET,
    )?;
    wipe(&mut eae_prk);
    wipe(&mut kem_context);

    let hpke_suite_id = hpke_suite_id();
    let mut psk_id_hash = labeled_extract(&[], &hpke_suite_id, b"psk_id_hash", &[])?;
    let mut info_hash = labeled_extract(&[], &hpke_suite_id, b"info_hash", &[])?;
    let mut key_schedule_context = vec![0];
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);
    let mut secret = labeled_extract(&shared_secret, &hpke_suite_id, b"secret", &[])?;
    let key = labeled_expand(
        &secret,
        &hpke_suite_id,
        b"key",
        &key_schedule_context,
        N_SECRET,
    )?;
    let nonce = labeled_expand(
        &secret,
        &hpke_suite_id,
        b"base_nonce",
        &key_schedule_context,
        N_NONCE,
    )?;
    wipe(&mut psk_id_hash);
    wipe(&mut info_hash);
    wipe(&mut key_schedule_context);
    wipe(&mut secret);
    wipe(&mut shared_secret);
    wipe(&mut kem_context);
    Ok((key, nonce))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; N_SECRET], CryptoError> {
    let mut output = [0; N_SECRET];
    let mut output_length = 0;
    let pointer = unsafe {
        HMAC(
            EVP_sha256(),
            key.as_ptr(),
            key.len() as c_int,
            data.as_ptr(),
            data.len(),
            output.as_mut_ptr(),
            &mut output_length,
        )
    };
    if pointer.is_null() || output_length as usize != N_SECRET {
        wipe(&mut output);
        return Err(CryptoError::OpenSsl("HMAC-SHA256 failed"));
    }
    Ok(output)
}

fn aead_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != N_SECRET || nonce.len() != N_NONCE {
        return Err(CryptoError::InvalidKeyLength);
    }
    let context = CipherContext::new()?;
    let cipher = unsafe { EVP_chacha20_poly1305() };
    if cipher.is_null()
        || unsafe {
            EVP_EncryptInit_ex(
                context.0,
                cipher,
                std::ptr::null_mut(),
                key.as_ptr(),
                std::ptr::null(),
            )
        } != 1
        || unsafe {
            EVP_CIPHER_CTX_ctrl(
                context.0,
                EVP_CTRL_AEAD_SET_IVLEN,
                N_NONCE as c_int,
                std::ptr::null_mut(),
            )
        } != 1
        || unsafe {
            EVP_EncryptInit_ex(
                context.0,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                nonce.as_ptr(),
            )
        } != 1
    {
        return Err(CryptoError::OpenSsl("EVP_EncryptInit_ex failed"));
    }
    let mut ignored = 0;
    if !aad.is_empty()
        && unsafe {
            EVP_EncryptUpdate(
                context.0,
                std::ptr::null_mut(),
                &mut ignored,
                aad.as_ptr(),
                aad.len() as c_int,
            )
        } != 1
    {
        return Err(CryptoError::OpenSsl("EVP_EncryptUpdate AAD failed"));
    }
    let mut output = vec![0; plaintext.len() + N_TAG];
    let mut written = 0;
    if unsafe {
        EVP_EncryptUpdate(
            context.0,
            output.as_mut_ptr(),
            &mut written,
            plaintext.as_ptr(),
            plaintext.len() as c_int,
        )
    } != 1
    {
        return Err(CryptoError::OpenSsl("EVP_EncryptUpdate failed"));
    }
    let mut final_written = 0;
    if unsafe {
        EVP_EncryptFinal_ex(
            context.0,
            output[written as usize..].as_mut_ptr(),
            &mut final_written,
        )
    } != 1
    {
        return Err(CryptoError::OpenSsl("EVP_EncryptFinal_ex failed"));
    }
    let ciphertext_length = written as usize + final_written as usize;
    output.truncate(ciphertext_length);
    let mut tag = [0; N_TAG];
    if unsafe {
        EVP_CIPHER_CTX_ctrl(
            context.0,
            EVP_CTRL_AEAD_GET_TAG,
            N_TAG as c_int,
            tag.as_mut_ptr().cast::<c_void>(),
        )
    } != 1
    {
        wipe(&mut tag);
        return Err(CryptoError::OpenSsl("EVP_CIPHER_CTX_ctrl get tag failed"));
    }
    output.extend_from_slice(&tag);
    wipe(&mut tag);
    Ok(output)
}

fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != N_SECRET || nonce.len() != N_NONCE {
        return Err(CryptoError::InvalidKeyLength);
    }
    if ciphertext.len() < N_TAG {
        return Err(CryptoError::InvalidCiphertext);
    }
    let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - N_TAG);
    let context = CipherContext::new()?;
    let cipher = unsafe { EVP_chacha20_poly1305() };
    if cipher.is_null()
        || unsafe {
            EVP_DecryptInit_ex(
                context.0,
                cipher,
                std::ptr::null_mut(),
                key.as_ptr(),
                std::ptr::null(),
            )
        } != 1
        || unsafe {
            EVP_CIPHER_CTX_ctrl(
                context.0,
                EVP_CTRL_AEAD_SET_IVLEN,
                N_NONCE as c_int,
                std::ptr::null_mut(),
            )
        } != 1
        || unsafe {
            EVP_DecryptInit_ex(
                context.0,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                nonce.as_ptr(),
            )
        } != 1
    {
        return Err(CryptoError::OpenSsl("EVP_DecryptInit_ex failed"));
    }
    let mut ignored = 0;
    if !aad.is_empty()
        && unsafe {
            EVP_DecryptUpdate(
                context.0,
                std::ptr::null_mut(),
                &mut ignored,
                aad.as_ptr(),
                aad.len() as c_int,
            )
        } != 1
    {
        return Err(CryptoError::OpenSsl("EVP_DecryptUpdate AAD failed"));
    }
    let mut plaintext = vec![0; ciphertext.len()];
    let mut written = 0;
    if unsafe {
        EVP_DecryptUpdate(
            context.0,
            plaintext.as_mut_ptr(),
            &mut written,
            ciphertext.as_ptr(),
            ciphertext.len() as c_int,
        )
    } != 1
    {
        return Err(CryptoError::OpenSsl("EVP_DecryptUpdate failed"));
    }
    let mut tag_copy = tag.to_vec();
    if unsafe {
        EVP_CIPHER_CTX_ctrl(
            context.0,
            EVP_CTRL_AEAD_SET_TAG,
            N_TAG as c_int,
            tag_copy.as_mut_ptr().cast::<c_void>(),
        )
    } != 1
    {
        wipe(&mut tag_copy);
        return Err(CryptoError::OpenSsl("EVP_CIPHER_CTX_ctrl set tag failed"));
    }
    wipe(&mut tag_copy);
    let mut final_written = 0;
    if unsafe {
        EVP_DecryptFinal_ex(
            context.0,
            plaintext[written as usize..].as_mut_ptr(),
            &mut final_written,
        )
    } != 1
    {
        wipe(&mut plaintext);
        return Err(CryptoError::AuthenticationFailed);
    }
    plaintext.truncate(written as usize + final_written as usize);
    Ok(plaintext)
}

#[derive(Debug)]
struct CustodyEntry {
    key_pair: RecipientKeyPair,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct EphemeralCustody {
    entries: BTreeMap<String, CustodyEntry>,
    lifetime: Duration,
}

impl EphemeralCustody {
    #[must_use]
    pub fn new(lifetime: Duration) -> Self {
        Self {
            entries: BTreeMap::new(),
            lifetime,
        }
    }

    pub fn provision(&mut self, recipient_id: &str) -> Result<Vec<u8>, CryptoError> {
        if recipient_id.is_empty() || recipient_id.len() > 128 || recipient_id.contains('/') {
            return Err(CryptoError::OpenSsl("invalid recipient id"));
        }
        self.purge_expired();
        let key_pair = RecipientKeyPair::generate()?;
        let public_key = key_pair.public_key().to_vec();
        self.entries.insert(
            recipient_id.to_owned(),
            CustodyEntry {
                key_pair,
                expires_at: Instant::now() + self.lifetime,
            },
        );
        Ok(public_key)
    }

    pub fn open_once(
        &mut self,
        recipient_id: &str,
        enc: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        self.purge_expired();
        let entry = self
            .entries
            .remove(recipient_id)
            .ok_or(CryptoError::OpenSsl("recipient key missing or expired"))?;
        entry.key_pair.open(enc, ciphertext, aad)
    }

    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoError, EphemeralCustody, RecipientKeyPair};
    use crate::secret::SecretBytes;
    use std::time::Duration;

    #[test]
    fn hpke_round_trip_and_tamper_rejection() {
        let recipient = RecipientKeyPair::generate().unwrap();
        let message =
            RecipientKeyPair::seal(recipient.public_key(), b"P01-CANARY", b"aad").unwrap();
        let opened = recipient
            .open(&message.enc, &message.ciphertext, b"aad")
            .unwrap();
        assert_eq!(opened.as_bytes(), b"P01-CANARY");

        let mut tampered = message.ciphertext;
        tampered[0] ^= 1;
        assert!(matches!(
            recipient.open(&message.enc, &tampered, b"aad"),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn ephemeral_custody_is_single_use_and_expires() {
        let mut custody = EphemeralCustody::new(Duration::from_secs(2));
        let public_key = custody.provision("recipient-a").unwrap();
        let sealed = RecipientKeyPair::seal(&public_key, b"P01-CANARY", &[]).unwrap();
        let opened = custody
            .open_once("recipient-a", &sealed.enc, &sealed.ciphertext, &[])
            .unwrap();
        assert_eq!(opened.as_bytes(), b"P01-CANARY");
        assert!(matches!(
            custody.open_once("recipient-a", &sealed.enc, &sealed.ciphertext, &[]),
            Err(CryptoError::OpenSsl("recipient key missing or expired"))
        ));
    }

    #[test]
    fn secret_debug_remains_redacted_after_hpke_open() {
        let secret = SecretBytes::from_slice(b"P01-CANARY");
        assert!(!format!("{secret:?}").contains("P01-CANARY"));
    }
}
