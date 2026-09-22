// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};

/// Best-effort memory clearing for short-lived secret buffers.
///
/// Rust cannot promise erasure from copies made by the operating system or an
/// optimizing foreign library. This function prevents the compiler from
/// deleting the local clearing loop and is paired with explicit lifetime
/// bounds everywhere a secret is held by the broker.
pub fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid, uniquely borrowed byte in `bytes`.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// A byte buffer that is cleared before its allocation is released.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        let bytes = std::mem::take(&mut self.0);
        std::mem::forget(self);
        bytes
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, wipe};

    #[test]
    fn secret_debug_does_not_expose_bytes() {
        let secret = SecretBytes::from_slice(b"P01-CANARY");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("P01-CANARY"));
        assert!(rendered.contains("len"));
    }

    #[test]
    fn wipe_clears_a_buffer() {
        let mut bytes = *b"P01-CANARY";
        wipe(&mut bytes);
        assert_eq!(bytes, [0; 10]);
    }
}
