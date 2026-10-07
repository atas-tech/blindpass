// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit legacy JWT/HMAC authority versioning. No reservation or activation.
use crate::store::StoreError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blindpass_core::secret::{SecretBytes, wipe};
use jsonwebtoken::{Algorithm, EncodingKey};

const MAX_EPOCH: u64 = 9_007_199_254_740_991;
const DOMAIN: &[u8] = b"blindpass:controller-legacy-authority:v1\0";

pub(crate) fn safe_epoch(epoch: u64) -> bool {
    (1..=MAX_EPOCH).contains(&epoch)
}

pub(crate) fn epoch_claim(epoch: u64) -> Option<u64> {
    (epoch > 1).then_some(epoch)
}

pub(crate) fn matches_epoch(epoch: u64, claim: Option<u64>) -> bool {
    safe_epoch(epoch)
        && match claim {
            Some(claim) => claim == epoch,
            None => epoch == 1,
        }
}

pub(crate) struct LegacyAuthorityKeys {
    pub(crate) root: SecretBytes,
    pub(crate) agent_jwt: SecretBytes,
    pub(crate) epoch: u64,
}

impl LegacyAuthorityKeys {
    pub(crate) fn derive(
        root: &[u8],
        agent_jwt: &[u8],
        tenant: &str,
        epoch: u64,
    ) -> Result<Self, StoreError> {
        if !safe_epoch(epoch)
            || tenant.is_empty()
            || tenant.len() > 128
            || !tenant
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || root.is_empty()
            || agent_jwt.is_empty()
        {
            return Err(StoreError::MissingState("legacy authority context"));
        }
        Ok(Self {
            root: version_key(root, b"root", tenant, epoch)?,
            agent_jwt: version_key(agent_jwt, b"agent-jwt", tenant, epoch)?,
            epoch,
        })
    }
}

fn version_key(
    master: &[u8],
    purpose: &[u8],
    tenant: &str,
    epoch: u64,
) -> Result<SecretBytes, StoreError> {
    // Generation1 is the accepted SPS wire/crypto baseline. This exception is
    // never used for a later generation and does not permit a stale restore
    // to reset external ownership/high-watermark or return to generation1.
    if epoch == 1 {
        return Ok(SecretBytes::from_slice(master));
    }
    let mut context = DOMAIN.to_vec();
    context.extend_from_slice(purpose);
    context.push(0);
    context.extend_from_slice(&(tenant.len() as u32).to_be_bytes());
    context.extend_from_slice(tenant.as_bytes());
    context.extend_from_slice(&epoch.to_be_bytes());
    // The same reviewed HS256 primitive already used by node-channel MACs.
    // Clear its encoded derived-key buffer as well as the owned raw key.
    let signed = jsonwebtoken::crypto::sign(
        &context,
        &EncodingKey::from_secret(master),
        Algorithm::HS256,
    )
    .map_err(|_| StoreError::MissingState("legacy authority key"));
    wipe(&mut context);
    let mut encoded = signed?.into_bytes();
    let digest = URL_SAFE_NO_PAD
        .decode(&encoded)
        .map_err(|_| StoreError::MissingState("legacy authority key"));
    wipe(&mut encoded);
    let mut digest = digest?;
    if digest.len() != 32 {
        wipe(&mut digest);
        return Err(StoreError::MissingState("legacy authority key"));
    }
    Ok(SecretBytes::new(digest))
}

#[cfg(test)]
mod tests {
    use super::{LegacyAuthorityKeys, matches_epoch};
    fn keys(tenant: &str, epoch: u64) -> LegacyAuthorityKeys {
        LegacyAuthorityKeys::derive(&[b'R'; 32], &[b'A'; 32], tenant, epoch).unwrap()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn p06_la06_independent_dummy_hmac_vectors_match_explicit_context() {
        // Independently calculated with Python stdlib HMAC-SHA256. Fixed
        // purpose, length-prefixed tenant and big-endian epoch bind the key.
        let k = keys("P06_DUMMY_TENANT", 9);
        assert_eq!(
            hex(k.root.as_bytes()),
            "6c9cebe8e59d188a3508adcf0dbaae988212e1bd10211c58cbeabd30c47624d7"
        );
        assert_eq!(
            hex(k.agent_jwt.as_bytes()),
            "ea4d12f4404469bff7641c1d37b9be285ccce732b36d20562a4d7aee574bcf0d"
        );
    }
    #[test]
    fn p06_la06_baseline_is_compatible_and_later_contexts_are_distinct() {
        let base = keys("P06_DUMMY_TENANT", 1);
        assert_eq!(base.root.as_bytes(), &[b'R'; 32]);
        assert_eq!(base.agent_jwt.as_bytes(), &[b'A'; 32]);
        let current = keys("P06_DUMMY_TENANT", 9);
        for other in [
            base,
            keys("P06_DUMMY_TENANT", 10),
            keys("P06_DUMMY_OTHER", 9),
        ] {
            assert_ne!(current.root.as_bytes(), other.root.as_bytes());
            assert_ne!(current.agent_jwt.as_bytes(), other.agent_jwt.as_bytes());
        }
        // Even an installation using identical master bytes cannot mix the
        // root-link authority with agent-JWT authority after generation1.
        let same =
            LegacyAuthorityKeys::derive(&[b'R'; 32], &[b'R'; 32], "P06_DUMMY_TENANT", 9).unwrap();
        assert_ne!(same.root.as_bytes(), same.agent_jwt.as_bytes());
    }
    #[test]
    fn p06_la06_invalid_context_and_unversioned_later_claims_refuse() {
        for epoch in [0, 9_007_199_254_740_992, u64::MAX] {
            assert!(
                LegacyAuthorityKeys::derive(b"P06_DUMMY", b"P06_DUMMY", "P06_DUMMY", epoch)
                    .is_err()
            );
            assert!(!matches_epoch(epoch, Some(epoch)));
        }
        for tenant in ["", "../P06_DUMMY", "P06 DUMMY"] {
            assert!(LegacyAuthorityKeys::derive(b"P06_DUMMY", b"P06_DUMMY", tenant, 9).is_err());
        }
        assert!(matches_epoch(1, None));
        assert!(matches_epoch(1, Some(1)));
        assert!(matches_epoch(9, Some(9)));
        assert!(!matches_epoch(9, None));
        assert!(!matches_epoch(9, Some(1)));
        assert!(!matches_epoch(9, Some(10)));
    }
}
