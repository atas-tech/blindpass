// SPDX-License-Identifier: AGPL-3.0-only

use crate::MAX_CREDENTIAL_BYTES;
use crate::secret::SecretBytes;
use std::fmt;
use std::io::{self, Write};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialFormat {
    NonEmpty,
    Utf8,
    Prefix(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
    Missing,
    Empty,
    TooLarge,
    InvalidEncoding,
    InvalidPrefix,
    Io(String),
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "credential_missing",
            Self::Empty => "credential_empty",
            Self::TooLarge => "credential_too_large",
            Self::InvalidEncoding => "credential_invalid_encoding",
            Self::InvalidPrefix => "credential_invalid_prefix",
            Self::Io(_) => "credential_delivery_io",
        })
    }
}

impl std::error::Error for DeliveryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryPolicy {
    pub max_bytes: usize,
    pub deadline: Duration,
    pub format: CredentialFormat,
}

impl Default for DeliveryPolicy {
    fn default() -> Self {
        Self {
            max_bytes: MAX_CREDENTIAL_BYTES,
            deadline: Duration::from_secs(2),
            format: CredentialFormat::NonEmpty,
        }
    }
}

impl DeliveryPolicy {
    pub fn validate(&self, value: &[u8]) -> Result<(), DeliveryError> {
        if value.is_empty() {
            return Err(DeliveryError::Empty);
        }
        if value.len() > self.max_bytes || value.len() > MAX_CREDENTIAL_BYTES {
            return Err(DeliveryError::TooLarge);
        }
        match &self.format {
            CredentialFormat::NonEmpty => {}
            CredentialFormat::Utf8 => {
                std::str::from_utf8(value).map_err(|_| DeliveryError::InvalidEncoding)?;
            }
            CredentialFormat::Prefix(prefix) => {
                if !value.starts_with(prefix) {
                    return Err(DeliveryError::InvalidPrefix);
                }
            }
        }
        Ok(())
    }

    pub fn write_one<W: Write>(
        &self,
        writer: &mut W,
        value: &[u8],
    ) -> Result<usize, DeliveryError> {
        self.validate(value)?;
        writer
            .write_all(value)
            .map_err(|error| DeliveryError::Io(error.to_string()))?;
        Ok(value.len())
    }
}

#[derive(Debug)]
pub struct CredentialRegistry {
    entries: std::collections::BTreeMap<String, SecretBytes>,
    policy: DeliveryPolicy,
}

impl CredentialRegistry {
    #[must_use]
    pub fn new(policy: DeliveryPolicy) -> Self {
        Self {
            entries: std::collections::BTreeMap::new(),
            policy,
        }
    }

    pub fn insert(&mut self, name: &str, value: &[u8]) -> Result<(), DeliveryError> {
        self.policy.validate(value)?;
        self.entries
            .insert(name.to_owned(), SecretBytes::from_slice(value));
        Ok(())
    }

    pub fn insert_secret(&mut self, name: &str, value: SecretBytes) -> Result<(), DeliveryError> {
        self.policy.validate(value.as_bytes())?;
        self.entries.insert(name.to_owned(), value);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Option<SecretBytes> {
        self.entries.remove(name)
    }

    pub fn get(&self, name: &str) -> Result<&[u8], DeliveryError> {
        self.entries
            .get(name)
            .map(SecretBytes::as_bytes)
            .ok_or(DeliveryError::Missing)
    }

    pub fn deliver<W: Write>(&self, name: &str, writer: &mut W) -> Result<usize, DeliveryError> {
        let value = self.get(name)?;
        self.policy.write_one(writer, value)
    }

    #[must_use]
    pub fn policy(&self) -> &DeliveryPolicy {
        &self.policy
    }
}

pub fn validate_consumer_bytes(
    value: &[u8],
    max_bytes: usize,
    format: &CredentialFormat,
) -> Result<(), DeliveryError> {
    DeliveryPolicy {
        max_bytes,
        deadline: Duration::from_secs(2),
        format: format.clone(),
    }
    .validate(value)
}

pub fn map_io(error: io::Error) -> DeliveryError {
    DeliveryError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{CredentialFormat, CredentialRegistry, DeliveryError, DeliveryPolicy};

    #[test]
    fn registry_rejects_empty_partial_and_oversized_material() {
        let mut registry = CredentialRegistry::new(DeliveryPolicy {
            max_bytes: 8,
            deadline: std::time::Duration::from_millis(20),
            format: CredentialFormat::Prefix(b"key_".to_vec()),
        });
        assert_eq!(registry.insert("api-key", b""), Err(DeliveryError::Empty));
        assert_eq!(
            registry.insert("api-key", b"wrong"),
            Err(DeliveryError::InvalidPrefix)
        );
        assert_eq!(
            registry.insert("api-key", b"key_too_long"),
            Err(DeliveryError::TooLarge)
        );
        registry.insert("api-key", b"key_ok").unwrap();
        let mut output = Vec::new();
        assert_eq!(registry.deliver("api-key", &mut output).unwrap(), 6);
        assert_eq!(output, b"key_ok");
    }

    #[test]
    fn consumer_validation_rejects_each_malformed_delivery() {
        let format = CredentialFormat::Prefix(b"key_".to_vec());
        assert_eq!(
            super::validate_consumer_bytes(b"", 64, &format),
            Err(DeliveryError::Empty)
        );
        assert_eq!(
            super::validate_consumer_bytes(b"key_", 3, &format),
            Err(DeliveryError::TooLarge)
        );
        assert_eq!(
            super::validate_consumer_bytes(b"partial", 64, &format),
            Err(DeliveryError::InvalidPrefix)
        );
        assert_eq!(
            super::validate_consumer_bytes(b"key_ok", 64, &CredentialFormat::Utf8),
            Ok(())
        );
        assert_eq!(
            super::validate_consumer_bytes(&[0xff], 64, &CredentialFormat::Utf8),
            Err(DeliveryError::InvalidEncoding)
        );
    }
}
