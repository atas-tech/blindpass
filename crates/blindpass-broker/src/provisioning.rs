// SPDX-License-Identifier: AGPL-3.0-only
//! Broker-only ephemeral browser offers. Public-key encryption alone does not
//! authorize a Source write: admission requires a current controller signature.
use crate::keys::NodeIdentity;
use crate::{BrokerError, BrokerState, CredentialExpiry, destination_key};
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::{EphemeralCustody, sha256};
use blindpass_core::fleet::{DocumentKind, SignedEnvelope};
use blindpass_core::provisioning::{BrowserProvisioningBinding, BrowserProvisioningDelivery};
use blindpass_core::signing::{base64_url_decode, base64_url_encode};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;
const MAX_OFFERS: usize = 16;
const DENIED: &str = "browser_provisioning_denied";
fn denied() -> BrokerError {
    BrokerError::Configuration(DENIED)
}

#[derive(Debug)]
struct PendingOffer {
    binding: BrowserProvisioningBinding,
    signed: SignedEnvelope,
    custody: EphemeralCustody,
    grant_deadline: u64,
    offer_deadline: u64,
    attempted: bool,
    accepted_receipt: Option<[u8; 32]>,
}
#[derive(Debug, Default)]
pub(crate) struct BrowserOfferBook {
    entries: BTreeMap<String, PendingOffer>,
}
impl BrowserOfferBook {
    fn purge(&mut self, boot: u64) {
        // Retain spent/expired offers until the ORIGINAL grant deadline so a
        // retry cannot mint a fresh key or extend collection within that grant.
        self.entries.retain(|_, entry| {
            entry.custody.purge_expired();
            boot < entry.grant_deadline
        });
    }
    pub(super) fn maintain(
        &mut self,
        boot: Option<u64>,
        authorized: &std::collections::BTreeSet<String>,
    ) {
        if let Some(boot) = boot {
            self.purge(boot);
        }
        for (id, entry) in &mut self.entries {
            if boot.is_none() || !authorized.contains(id) {
                entry.custody = EphemeralCustody::new(Duration::ZERO);
                entry.attempted = true;
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn expire_all_for_test(&mut self) {
        for entry in self.entries.values_mut() {
            entry.offer_deadline = 0;
        }
    }
}
impl BrokerState {
    fn browser_offer_candidate(
        &self,
        grant_id: &str,
    ) -> Result<crate::browser_coordinator::BrowserCandidate, BrokerError> {
        let candidate = self
            .browser_dispatch_candidates()
            .into_iter()
            .find(|candidate| candidate.grant.id == grant_id)
            .ok_or_else(denied)?;
        candidate.original.ensure_alive().map_err(|_| denied())?;
        Ok(candidate)
    }
    pub(crate) fn browser_recipient_offer(
        &mut self,
        identity: &NodeIdentity,
        grant_id: &str,
    ) -> Result<SignedEnvelope, BrokerError> {
        self.mint_browser_offer(identity, grant_id)
            .map_err(|_| denied())
    }
    /// The same immutable offer as `browser_recipient_offer`, wrapped as one
    /// PULL_EVENTS-style `recipient_offer` node event signed by this broker so
    /// the unprivileged relay can publish it byte for byte. Only offers minted
    /// here are signed; the relay never supplies a body.
    pub(crate) fn browser_recipient_offer_event(
        &mut self,
        identity: &NodeIdentity,
        grant_id: &str,
    ) -> Result<Vec<u8>, BrokerError> {
        self.mint_offer_event(identity, grant_id)
            .map_err(|_| denied())
    }
    fn mint_offer_event(
        &mut self,
        identity: &NodeIdentity,
        grant_id: &str,
    ) -> Result<Vec<u8>, BrokerError> {
        let offer = self.mint_browser_offer(identity, grant_id)?;
        let pin = identity.pinned_issuer()?.ok_or_else(denied)?;
        // Sign the body in the exact re-parsed form the controller canonicalises.
        let encoded = offer.to_json().map_err(|_| denied())?;
        let body = parse_json(std::str::from_utf8(&encoded).map_err(|_| denied())?)
            .map_err(|_| denied())?;
        let digest = sha256(grant_id.as_bytes())?;
        let key = format!(
            "ro_{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let signature = identity.sign_node_event(&pin.node_id, &key, "recipient_offer", &body)?;
        canonicalize_value(&Value::Object(vec![
            ("body".to_owned(), body),
            ("broker_signature".to_owned(), Value::String(signature)),
            ("idempotency_key".to_owned(), Value::String(key)),
            (
                "kind".to_owned(),
                Value::String("recipient_offer".to_owned()),
            ),
        ]))
        .map_err(|_| denied())
    }
    fn mint_browser_offer(
        &mut self,
        identity: &NodeIdentity,
        grant_id: &str,
    ) -> Result<SignedEnvelope, BrokerError> {
        let candidate = self.browser_offer_candidate(grant_id)?;
        let grant = &candidate.grant;
        let (boot, now) = self.browser_clock_anchor()?;
        let version = identity.key_version()?;
        let (unit, credential) = candidate.resource.credential_destination();
        self.validate_mapping(unit, credential)?;
        self.browser_offers.purge(boot);
        if let Some(entry) = self.browser_offers.entries.get(grant_id) {
            entry
                .binding
                .validate_against(grant, version, now)
                .map_err(|_| denied())?;
            if entry.attempted
                || boot >= entry.offer_deadline
                || entry.binding.source_unit != unit
                || entry.binding.credential != credential
            {
                return Err(denied());
            }
            // Signer's current enrollment/version is checked without replacing
            // the immutable original key, ID, signature or deadline.
            identity.sign_browser_offer(&entry.binding)?;
            return Ok(entry.signed.clone());
        }
        if self.browser_offers.entries.len() >= MAX_OFFERS {
            return Err(denied());
        }
        let policy = self.fleet_policy.as_ref().ok_or_else(denied)?;
        let mut consuming = candidate.original.authorization().clone();
        consuming.operation = format!("consume:{grant_id}");
        let (_, grant_deadline) = self
            .grant_verifier
            .preview_consumption_deadline(grant_id, &consuming, policy.policy_version, boot)
            .map_err(|_| denied())?;
        let remaining = grant_deadline
            .checked_sub(boot)
            .ok_or_else(denied)?
            .min(grant.expires_at_ms.checked_sub(now).ok_or_else(denied)?)
            .min(u64::try_from(self.browser_offer_lifetime.as_millis()).map_err(|_| denied())?);
        if remaining == 0 {
            return Err(denied());
        }
        let mut random = [0_u8; 24];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let offer_id = format!("pv_{}", base64_url_encode(&random));
        let mut custody = EphemeralCustody::new(Duration::from_millis(remaining));
        let recipient_public = base64_url_encode(&custody.provision(&offer_id)?);
        let binding = BrowserProvisioningBinding {
            offer_id,
            node_key_version: version,
            source_unit: unit.into(),
            credential: credential.into(),
            recipient_public,
            issued_at_ms: now,
            expires_at_ms: now.checked_add(remaining).ok_or_else(denied)?,
            grant: grant.clone(),
        };
        let signed = identity.sign_browser_offer(&binding)?;
        self.browser_offers.entries.insert(
            grant_id.into(),
            PendingOffer {
                binding,
                signed: signed.clone(),
                custody,
                grant_deadline,
                offer_deadline: boot.checked_add(remaining).ok_or_else(denied)?,
                attempted: false,
                accepted_receipt: None,
            },
        );
        Ok(signed)
    }
    /// Only ciphertext enters this method. Current controller authorization is
    /// verified before touching one-use key custody. Exact successful retry is
    /// a receipt acknowledgement and neither stores nor renews Source.
    pub(crate) fn accept_browser_provisioning(
        &mut self,
        identity: &NodeIdentity,
        document: &[u8],
    ) -> Result<bool, BrokerError> {
        self.admit_browser_source(identity, document)
            .map_err(|_| denied())
    }
    fn admit_browser_source(
        &mut self,
        identity: &NodeIdentity,
        document: &[u8],
    ) -> Result<bool, BrokerError> {
        if document.len() > 131_072 {
            return Err(denied());
        }
        let envelope =
            SignedEnvelope::from_json(std::str::from_utf8(document).map_err(|_| denied())?)
                .map_err(|_| denied())?;
        if envelope.kind() != DocumentKind::ProvisioningDelivery {
            return Err(denied());
        }
        let pin = identity.pinned_issuer()?.ok_or_else(denied)?;
        let public = base64_url_decode(&pin.public_key, 32).ok_or_else(denied)?;
        if envelope.epoch() != pin.epoch
            || !envelope
                .verify(&public, &pin.key_id, pin.epoch)
                .map_err(|_| denied())?
        {
            return Err(denied());
        }
        let delivery =
            BrowserProvisioningDelivery::from_value(envelope.body()).map_err(|_| denied())?;
        let binding = &delivery.binding;
        if binding.grant.node_id != pin.node_id
            || binding.node_key_version != identity.key_version()?
        {
            return Err(denied());
        }
        let digest = sha256(&envelope.to_json().map_err(|_| denied())?)?;
        let entry = self
            .browser_offers
            .entries
            .get(&binding.grant.id)
            .ok_or_else(denied)?;
        if &entry.binding != binding {
            return Err(denied());
        }
        if entry.accepted_receipt == Some(digest) {
            return Ok(false);
        }
        if entry.attempted {
            return Err(denied());
        }
        let candidate = self.browser_offer_candidate(&binding.grant.id)?;
        let (boot, now) = self.browser_clock_anchor()?;
        binding
            .validate_against(&candidate.grant, identity.key_version()?, now)
            .map_err(|_| denied())?;
        let (unit, credential) = candidate.resource.credential_destination();
        if unit != binding.source_unit || credential != binding.credential {
            return Err(denied());
        }
        self.validate_mapping(unit, credential)?;
        let (enc, ciphertext) = delivery.sealed_bytes().map_err(|_| denied())?;
        let entry = self
            .browser_offers
            .entries
            .get_mut(&binding.grant.id)
            .ok_or_else(denied)?;
        if boot >= entry.offer_deadline {
            return Err(denied());
        }
        entry.attempted = true;
        let source = entry.custody.open_once(
            &binding.offer_id,
            &enc,
            &ciphertext,
            &binding.aad().map_err(|_| denied())?,
        )?;
        if source.is_empty()
            || source.len() > 65_536
            || std::str::from_utf8(source.as_bytes()).is_err()
        {
            return Err(denied());
        }
        let (boot, now) = self.browser_clock_anchor()?;
        if boot >= self.browser_offers.entries[&binding.grant.id].offer_deadline
            || now >= binding.expires_at_ms
        {
            return Err(denied());
        }
        self.browser_offer_candidate(&binding.grant.id)?;
        let expiry = CredentialExpiry::after(self.credential_lifetime)?;
        let destination = destination_key(unit, credential);
        self.credentials.insert_secret(&destination, source)?;
        self.credential_expiries.insert(destination, expiry);
        self.browser_offers
            .entries
            .get_mut(&binding.grant.id)
            .ok_or_else(denied)?
            .accepted_receipt = Some(digest);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pv06_b02_capacity_denies_without_evicting_existing_private_keys() {
        let (directory, mut state, grant, _, _) =
            crate::tests::browser_grant_fixture("pv06-capacity");
        let identity = NodeIdentity::load_or_create(&directory.join("keys")).unwrap();
        let issuer = blindpass_core::signing::ed25519::Ed25519KeyPair::generate().unwrap();
        let public = base64_url_encode(issuer.public_key());
        identity
            .pin_issuer(crate::keys::PinnedIssuer {
                tenant_id: "tenant-a".into(),
                node_id: "node-a".into(),
                epoch: 1,
                key_id: format!("ed25519-{public}"),
                public_key: public,
            })
            .unwrap();
        state.browser_recipient_offer(&identity, &grant.id).unwrap();
        let original = state.browser_offers.entries.remove(&grant.id).unwrap();
        let mut probes = Vec::new();
        for index in 0..MAX_OFFERS {
            let id = format!("pending_{index}");
            let offer_id = format!("pv_capacity_offer_{index:016}");
            let mut custody = EphemeralCustody::new(Duration::from_secs(30));
            let public = custody.provision(&offer_id).unwrap();
            let mut binding = original.binding.clone();
            binding.offer_id = offer_id;
            binding.recipient_public = base64_url_encode(&public);
            let signed = identity.sign_browser_offer(&binding).unwrap();
            let sealed = blindpass_core::custody::RecipientKeyPair::seal(
                &public,
                b"DUMMY-PV06-CAPACITY",
                &binding.aad().unwrap(),
            )
            .unwrap();
            probes.push((id.clone(), sealed));
            state.browser_offers.entries.insert(
                id,
                PendingOffer {
                    binding,
                    signed,
                    custody,
                    grant_deadline: original.grant_deadline,
                    offer_deadline: original.offer_deadline,
                    attempted: false,
                    accepted_receipt: None,
                },
            );
        }
        assert!(state.browser_recipient_offer(&identity, &grant.id).is_err());
        assert_eq!(state.browser_offers.entries.len(), MAX_OFFERS);
        for (id, sealed) in probes {
            let entry = state.browser_offers.entries.get_mut(&id).unwrap();
            let opened = entry
                .custody
                .open_once(
                    &entry.binding.offer_id,
                    &sealed.enc,
                    &sealed.ciphertext,
                    &entry.binding.aad().unwrap(),
                )
                .unwrap();
            assert_eq!(opened.as_bytes(), b"DUMMY-PV06-CAPACITY");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
