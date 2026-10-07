// SPDX-License-Identifier: AGPL-3.0-only

//! P10 cross-workload fulfillment, broker side (`reencrypt` mode).
//!
//! The recipient broker mints a one-use X25519 key per fulfillment and signs an
//! offer; the issuer broker seals its in-memory credential to that key and signs
//! the result with its node key; the recipient broker opens the relayed
//! ciphertext once into its own custody. Nothing here reaches the network: every
//! document arrives through the control socket and every event leaves through it.
//!
//! Plaintext holders and lifetimes: the issuer broker reads its source
//! credential from custody only while sealing and never alters it; the
//! recipient broker holds the opened credential in its credential registry under
//! the ordinary broker credential lifetime, and removes it early only while it is
//! unread at revocation, epoch change or fulfillment expiry. The book itself
//! holds keys, signed public documents and ciphertext, never plaintext.
//!
//! A permanently unappliable but correctly signed document is acknowledged as
//! discarded (`fulfillment_discarded_rejected`) so it cannot wedge the node
//! inbox; when it is addressed to this node the controller learns why through a
//! `fulfillment_result` failed event. Only transient conditions return an error,
//! which leaves the document queued for retry.

use crate::keys::{NodeIdentity, PinnedIssuer};
use crate::{
    BrokerError, BrokerState, CredentialExpiry, MAX_BROKER_AUDIT_EVENTS, PendingNodeEvent,
};
use crate::{destination_key, grants};
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::{EphemeralCustody, sha256};
use blindpass_core::fleet::{DocumentKind, SignedEnvelope};
use blindpass_core::fulfillment::{
    FulfillmentAuthorization, FulfillmentDelivery, FulfillmentOffer, FulfillmentParty,
    FulfillmentResult, FulfillmentRevocation, FulfillmentSide, FulfillmentTerms,
    MAX_OFFER_LIFETIME_MS, MAX_PLAINTEXT_BYTES, ResultState, fulfillment_aad, fulfillment_info,
    verify_offer,
};
use blindpass_core::signing::base64_url_encode;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read;
use std::time::Duration;

/// Live fulfillments per broker, across both roles. Capacity never evicts.
const MAX_ENTRIES: usize = 16;
const MAX_TOMBSTONES: usize = 64;
/// A revocation tombstone only has to outlive the longest terms.
const MAX_TOMBSTONE_MS: u64 = 3_600_000;
const DENIED: &str = "fulfillment_denied";
const REJECTED: &str = "fulfillment_discarded_rejected";
const BACKPRESSURE: &str = "audit_backpressure";

fn denied() -> BrokerError {
    BrokerError::Configuration(DENIED)
}

fn malformed() -> BrokerError {
    BrokerError::Configuration("controller fulfillment document is malformed")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn id_digest(id: &str) -> Result<String, BrokerError> {
    Ok(hex(&sha256(id.as_bytes())?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Recipient: the one-use key is live (until its own deadline).
    Offered,
    /// Recipient: nothing was stored and nothing will be; the key is spent.
    Failed,
    /// Recipient: opened and held in custody, not yet read by the unit.
    Stored,
    /// Recipient: the unit read it through the loader. It cannot be recalled.
    Consumed,
    /// Recipient: a later fulfillment named this one and replaced its credential.
    Replaced,
    /// Issuer: the signed submission is ready.
    Sealed,
}

#[derive(Debug)]
struct Entry {
    side: FulfillmentSide,
    terms: FulfillmentTerms,
    digest: String,
    phase: Phase,
    /// Boot-clock deadlines: no wall clock or controller reply can extend them.
    deadline_boot: u64,
    offer_deadline_boot: u64,
    anchor_boot: u64,
    anchor_controller_ms: u64,
    /// Recipient: this broker's own signed offer.
    offer: Option<SignedEnvelope>,
    /// Issuer: the signed, sealed submission.
    submit: Option<SignedEnvelope>,
    /// Recipient: holds the one-use private key until it is spent.
    custody: EphemeralCustody,
    /// Digest of the delivery document that was applied.
    receipt: Option<[u8; 32]>,
    replaces: Option<String>,
    /// Results the node queue could not take yet; retried, never dropped.
    unreported: Vec<FulfillmentResult>,
}

impl Entry {
    fn controller_ms_at(&self, boot: u64) -> u64 {
        self.anchor_controller_ms
            .saturating_add(boot.saturating_sub(self.anchor_boot))
    }

    fn spend_key(&mut self) {
        self.custody = EphemeralCustody::new(Duration::ZERO);
    }
}

#[derive(Debug)]
struct Tombstone {
    id: String,
    digest: String,
    until_boot: u64,
}

#[derive(Debug, Default)]
pub(crate) struct FulfillmentBook {
    sources: BTreeSet<String>,
    destinations: BTreeSet<String>,
    offer_lifetime: Duration,
    entries: BTreeMap<String, Entry>,
    tombstones: VecDeque<Tombstone>,
}

impl FulfillmentBook {
    fn tombstoned(&self, id: &str, digest: &str, boot: u64) -> bool {
        self.tombstones
            .iter()
            .any(|stone| stone.id == id && stone.digest == digest && boot < stone.until_boot)
    }

    fn bury(&mut self, id: &str, digest: &str, until_boot: u64) {
        self.tombstones
            .retain(|stone| !(stone.id == id && stone.digest == digest));
        if self.tombstones.len() >= MAX_TOMBSTONES {
            self.tombstones.pop_front();
        }
        self.tombstones.push_back(Tombstone {
            id: id.to_owned(),
            digest: digest.to_owned(),
            until_boot,
        });
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

fn result_key(result: &FulfillmentResult) -> Result<String, BrokerError> {
    let material = format!(
        "{}|{}|{}|{}|{}",
        result.fulfillment_id,
        result.terms_digest,
        result.side.as_str(),
        result.state.as_str(),
        result.code.as_deref().unwrap_or("")
    );
    Ok(format!("fr_{}", id_digest(&material)?))
}

impl BrokerState {
    /// Install the local ceilings. Neither list is ever widened by a controller
    /// document; with both empty the broker refuses every fulfillment.
    pub fn configure_fulfillment(
        &mut self,
        sources: &[String],
        destinations: &[String],
        offer_lifetime: Duration,
    ) -> Result<(), BrokerError> {
        let ceiling = Duration::from_millis(MAX_OFFER_LIFETIME_MS);
        if offer_lifetime.is_zero() || offer_lifetime > ceiling {
            return Err(BrokerError::Configuration(
                "fulfillment_offer_lifetime_invalid",
            ));
        }
        for unit in sources.iter().chain(destinations) {
            if self.loader_policy.credential_for(unit).is_none() {
                return Err(BrokerError::Configuration("fulfillment_unit_unmapped"));
            }
        }
        self.fulfillments.sources = sources.iter().cloned().collect();
        self.fulfillments.destinations = destinations.iter().cloned().collect();
        self.fulfillments.offer_lifetime = offer_lifetime;
        Ok(())
    }

    /// Apply one verified controller fulfillment document. The caller has
    /// verified the signature and the pinned epoch.
    pub(crate) fn apply_fulfillment_document(
        &mut self,
        identity: &NodeIdentity,
        pin: &PinnedIssuer,
        envelope: &SignedEnvelope,
    ) -> Result<&'static str, BrokerError> {
        match envelope.kind() {
            DocumentKind::FulfillmentRevocation => {
                let revocation =
                    FulfillmentRevocation::from_value(envelope.body()).map_err(|_| malformed())?;
                if revocation.node_id != pin.node_id {
                    return Ok(REJECTED);
                }
                self.revoke_fulfillment(&revocation)?;
                Ok("fulfillment_revocation")
            }
            DocumentKind::FulfillmentAuthorization | DocumentKind::FulfillmentDelivery => {
                if self.node_revoked {
                    return Ok(REJECTED);
                }
                if self.persistence_fenced() {
                    return Err(BrokerError::Configuration("broker_persistence_fenced"));
                }
                if envelope.kind() == DocumentKind::FulfillmentAuthorization {
                    self.apply_authorization(identity, pin, envelope)
                } else {
                    self.apply_delivery(identity, pin, envelope)
                }
            }
            _ => Err(BrokerError::Configuration(
                "controller document kind is not supported by this broker",
            )),
        }
    }

    /// Every party binding the controller attested must still match what this
    /// broker holds. Returns the stable failure code of the first mismatch.
    fn fulfillment_party_check(
        &self,
        identity: &NodeIdentity,
        party: &FulfillmentParty,
        terms: &FulfillmentTerms,
    ) -> Result<Option<&'static str>, BrokerError> {
        let public = identity.public_identity()?;
        if party.key_version != identity.key_version()?
            || party.signing_public != public.signing_public
            || party.recipient_public != public.recipient_public
            || party.fingerprint != public.fingerprint
        {
            return Ok(Some("identity_mismatch"));
        }
        let registered = self
            .fleet_registrations
            .get(&party.workload_id)
            .is_some_and(|r| {
                r.node_id == party.node_id
                    && r.unit == party.unit
                    && r.status == "active"
                    && r.registration_version == party.registration_version
            });
        if !registered {
            return Ok(Some("registration_mismatch"));
        }
        if self
            .fleet_policy
            .as_ref()
            .is_none_or(|policy| policy.policy_version != terms.policy_version)
        {
            return Ok(Some("policy_stale"));
        }
        if self.loader_policy.credential_for(&party.unit) != Some(party.credential.as_str()) {
            return Ok(Some("unmapped"));
        }
        Ok(None)
    }

    fn apply_authorization(
        &mut self,
        identity: &NodeIdentity,
        pin: &PinnedIssuer,
        envelope: &SignedEnvelope,
    ) -> Result<&'static str, BrokerError> {
        let authorization =
            FulfillmentAuthorization::from_value(envelope.body()).map_err(|_| malformed())?;
        let side = authorization.side;
        let terms = &authorization.terms;
        let party = match side {
            FulfillmentSide::Issuer => &terms.issuer,
            FulfillmentSide::Recipient => &terms.recipient,
        };
        // Not addressed to this node or tenant: nothing to report and nothing to keep.
        if party.node_id != pin.node_id || terms.tenant_id != pin.tenant_id {
            return Ok(REJECTED);
        }
        let digest = terms.digest_hex().map_err(|_| malformed())?;
        let (boot, now) = self.browser_clock_anchor()?;
        if self
            .fulfillments
            .tombstoned(&terms.fulfillment_id, &digest, boot)
        {
            return Ok(REJECTED);
        }
        self.purge_expired_credentials();
        if let Some(existing) = self.fulfillments.entries.get(&terms.fulfillment_id) {
            if existing.digest == digest && existing.side == side {
                return Ok("fulfillment_authorization");
            }
            return self.reject_fulfillment(terms, side, "terms_conflict", now);
        }
        let enabled = match side {
            FulfillmentSide::Issuer => self.fulfillments.sources.contains(&party.unit),
            FulfillmentSide::Recipient => self.fulfillments.destinations.contains(&party.unit),
        };
        if !enabled {
            return self.reject_fulfillment(terms, side, "not_enabled", now);
        }
        if now >= terms.expires_at_ms {
            return self.reject_fulfillment(terms, side, "terms_expired", now);
        }
        if now < terms.issued_at_ms {
            return self.reject_fulfillment(terms, side, "terms_not_yet_valid", now);
        }
        if let Some(code) = self.fulfillment_party_check(identity, party, terms)? {
            return self.reject_fulfillment(terms, side, code, now);
        }
        match side {
            FulfillmentSide::Recipient => {
                self.authorize_recipient(identity, pin, terms, digest, boot, now)
            }
            FulfillmentSide::Issuer => {
                let offer = authorization.offer.as_ref().ok_or_else(malformed)?;
                self.authorize_issuer(identity, terms, offer, digest, boot, now)
            }
        }
    }

    fn authorize_recipient(
        &mut self,
        identity: &NodeIdentity,
        pin: &PinnedIssuer,
        terms: &FulfillmentTerms,
        digest: String,
        boot: u64,
        now: u64,
    ) -> Result<&'static str, BrokerError> {
        let side = FulfillmentSide::Recipient;
        let (unit, credential) = (&terms.recipient.unit, &terms.recipient.credential);
        let pending = self.fulfillments.entries.values().any(|entry| {
            entry.side == side
                && entry.phase == Phase::Offered
                && boot < entry.offer_deadline_boot
                && &entry.terms.recipient.unit == unit
                && &entry.terms.recipient.credential == credential
        });
        if pending {
            return self.reject_fulfillment(terms, side, "destination_busy", now);
        }
        let live = self
            .credentials
            .get(&destination_key(unit, credential))
            .is_ok();
        let owner = self.fulfillment_owner(unit, credential);
        let replaces = match (live, owner) {
            (false, _) => None,
            (true, None) => {
                return self.reject_fulfillment(terms, side, "destination_occupied", now);
            }
            (true, Some(owner)) => {
                if terms.prior_fulfillment_id.as_deref() != Some(owner.as_str()) {
                    return self.reject_fulfillment(terms, side, "destination_busy", now);
                }
                Some(owner)
            }
        };
        if self.fulfillments.entries.len() >= MAX_ENTRIES {
            return self.reject_fulfillment(terms, side, "capacity", now);
        }
        let remaining = terms
            .expires_at_ms
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(denied)?
            .min(
                u64::try_from(self.fulfillments.offer_lifetime.as_millis())
                    .map_err(|_| denied())?,
            )
            .min(MAX_OFFER_LIFETIME_MS);
        let mut random = [0_u8; 24];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let offer_id = format!("fo_{}", base64_url_encode(&random));
        let mut custody = EphemeralCustody::new(Duration::from_millis(remaining));
        let recipient_public = base64_url_encode(&custody.provision(&offer_id)?);
        let offer = FulfillmentOffer {
            fulfillment_id: terms.fulfillment_id.clone(),
            terms_digest: digest.clone(),
            offer_id,
            node_id: pin.node_id.clone(),
            node_key_version: identity.key_version()?,
            recipient_public,
            issued_at_ms: now,
            expires_at_ms: now.checked_add(remaining).ok_or_else(denied)?,
        };
        let signed = identity.sign_fulfillment_offer(&offer)?;
        let entry = self.new_entry(
            side,
            terms,
            digest,
            Phase::Offered,
            boot,
            now,
            custody,
            remaining,
        )?;
        self.fulfillments.entries.insert(
            terms.fulfillment_id.clone(),
            Entry {
                offer: Some(signed),
                replaces,
                ..entry
            },
        );
        Ok("fulfillment_authorization")
    }

    fn authorize_issuer(
        &mut self,
        identity: &NodeIdentity,
        terms: &FulfillmentTerms,
        offer_envelope: &SignedEnvelope,
        digest: String,
        boot: u64,
        now: u64,
    ) -> Result<&'static str, BrokerError> {
        let side = FulfillmentSide::Issuer;
        let Ok(unverified) = FulfillmentOffer::from_value(offer_envelope.body()) else {
            return self.reject_fulfillment(terms, side, "offer_invalid", now);
        };
        if now >= unverified.expires_at_ms {
            return self.reject_fulfillment(terms, side, "offer_expired", now);
        }
        let Ok(offer) = verify_offer(offer_envelope, terms, now) else {
            return self.reject_fulfillment(terms, side, "offer_invalid", now);
        };
        if self.fulfillments.entries.len() >= MAX_ENTRIES {
            return self.reject_fulfillment(terms, side, "capacity", now);
        }
        let (unit, credential) = (&terms.issuer.unit, &terms.issuer.credential);
        if self.revalidate_delivery_profile(unit, credential).is_err() {
            return self.reject_fulfillment(terms, side, "source_invalid", now);
        }
        let key = destination_key(unit, credential);
        let Some(length) = self.credentials.get(&key).ok().map(<[u8]>::len) else {
            return self.reject_fulfillment(terms, side, "source_missing", now);
        };
        let length = u64::try_from(length).map_err(|_| denied())?;
        if length > terms.max_plaintext_bytes || length > MAX_PLAINTEXT_BYTES {
            return self.reject_fulfillment(terms, side, "source_too_large", now);
        }
        // The source stays in custody untouched; the borrow ends with the seal.
        let sealed = {
            let plaintext = self.credentials.get(&key).map_err(|_| denied())?;
            identity.seal_fulfillment(terms, &offer, plaintext, now)
        };
        let Ok(submit) = sealed else {
            return self.reject_fulfillment(terms, side, "seal_failed", now);
        };
        let entry = self.new_entry(
            side,
            terms,
            digest,
            Phase::Sealed,
            boot,
            now,
            EphemeralCustody::new(Duration::ZERO),
            0,
        )?;
        self.fulfillments.entries.insert(
            terms.fulfillment_id.clone(),
            Entry {
                submit: Some(submit),
                ..entry
            },
        );
        Ok("fulfillment_authorization")
    }

    #[allow(clippy::too_many_arguments)]
    fn new_entry(
        &self,
        side: FulfillmentSide,
        terms: &FulfillmentTerms,
        digest: String,
        phase: Phase,
        boot: u64,
        now: u64,
        custody: EphemeralCustody,
        offer_remaining: u64,
    ) -> Result<Entry, BrokerError> {
        let terms_remaining = terms.expires_at_ms.saturating_sub(now);
        Ok(Entry {
            side,
            terms: terms.clone(),
            digest,
            phase,
            deadline_boot: boot.checked_add(terms_remaining).ok_or_else(denied)?,
            offer_deadline_boot: boot.checked_add(offer_remaining).ok_or_else(denied)?,
            anchor_boot: boot,
            anchor_controller_ms: now,
            offer: None,
            submit: None,
            custody,
            receipt: None,
            replaces: None,
            unreported: Vec::new(),
        })
    }

    /// The fulfillment whose credential currently occupies a destination.
    fn fulfillment_owner(&self, unit: &str, credential: &str) -> Option<String> {
        self.credentials
            .get(&destination_key(unit, credential))
            .ok()?;
        self.fulfillments
            .entries
            .iter()
            .find(|(_, entry)| {
                entry.side == FulfillmentSide::Recipient
                    && matches!(entry.phase, Phase::Stored | Phase::Consumed)
                    && entry.terms.recipient.unit == unit
                    && entry.terms.recipient.credential == credential
            })
            .map(|(id, _)| id.clone())
    }

    fn apply_delivery(
        &mut self,
        identity: &NodeIdentity,
        pin: &PinnedIssuer,
        envelope: &SignedEnvelope,
    ) -> Result<&'static str, BrokerError> {
        let delivery = FulfillmentDelivery::from_value(envelope.body()).map_err(|_| malformed())?;
        let terms = &delivery.terms;
        let side = FulfillmentSide::Recipient;
        if terms.recipient.node_id != pin.node_id || terms.tenant_id != pin.tenant_id {
            return Ok(REJECTED);
        }
        let digest = terms.digest_hex().map_err(|_| malformed())?;
        let id = terms.fulfillment_id.clone();
        let (boot, now) = self.browser_clock_anchor()?;
        if self.fulfillments.tombstoned(&id, &digest, boot) {
            return Ok(REJECTED);
        }
        self.purge_expired_credentials();
        let receipt = sha256(&envelope.to_json().map_err(|_| malformed())?)?;
        let Some(entry) = self.fulfillments.entries.get(&id) else {
            return self.reject_fulfillment(terms, side, "unknown_fulfillment", now);
        };
        if entry.side == side && entry.receipt == Some(receipt) {
            // An exact retry of a delivery that was applied: acknowledge it.
            self.flush_fulfillment_reports()?;
            return Ok("fulfillment_delivery");
        }
        if entry.side != side
            || entry.digest != digest
            || entry.offer.as_ref() != Some(&delivery.offer)
        {
            return self.reject_fulfillment(terms, side, "delivery_invalid", now);
        }
        if entry.phase != Phase::Offered {
            // Already stored, replaced or failed and reported: a second body can
            // never be opened under a spent key, and needs no second report.
            return Ok(REJECTED);
        }
        let replaces = entry.replaces.clone();
        let offer_deadline = entry.offer_deadline_boot;
        let offer_expires = FulfillmentOffer::from_value(delivery.offer.body())
            .map_err(|_| malformed())?
            .expires_at_ms;
        if boot >= offer_deadline || now >= offer_expires {
            self.fail_recipient(&id);
            return self.reject_fulfillment(terms, side, "offer_expired", now);
        }
        // Signatures and bindings first: a forgery never touches the one-use key.
        let Ok((offer, submit)) = delivery.verify(now) else {
            return self.reject_fulfillment(terms, side, "delivery_invalid", now);
        };
        if submit.issued_at_ms < offer.issued_at_ms || submit.issued_at_ms >= offer.expires_at_ms {
            return self.reject_fulfillment(terms, side, "delivery_invalid", now);
        }
        let Ok((enc, ciphertext)) = submit.sealed_bytes() else {
            return self.reject_fulfillment(terms, side, "delivery_invalid", now);
        };
        // Everything the controller attested must still be true before the key is spent.
        if now >= terms.expires_at_ms {
            self.fail_recipient(&id);
            return self.reject_fulfillment(terms, side, "terms_expired", now);
        }
        if let Some(code) = self.fulfillment_party_check(identity, &terms.recipient, terms)? {
            self.fail_recipient(&id);
            return self.reject_fulfillment(terms, side, code, now);
        }
        let (unit, credential) = (&terms.recipient.unit, &terms.recipient.credential);
        let key = destination_key(unit, credential);
        if self.credentials.get(&key).is_ok() {
            let owner = self.fulfillment_owner(unit, credential);
            let code = match (&owner, &replaces) {
                (None, _) => Some("destination_occupied"),
                (Some(owner), Some(named)) if owner == named => None,
                (Some(_), _) => Some("destination_busy"),
            };
            if let Some(code) = code {
                self.fail_recipient(&id);
                return self.reject_fulfillment(terms, side, code, now);
            }
        }
        let expiry = CredentialExpiry::after(self.credential_lifetime)?;
        let info = fulfillment_info(terms).map_err(|_| denied())?;
        let aad = fulfillment_aad(&offer).map_err(|_| denied())?;
        // The key is spent by the open, whether or not it succeeds.
        let entry = self.fulfillments.entries.get_mut(&id).ok_or_else(denied)?;
        entry.phase = Phase::Failed;
        let opened =
            entry
                .custody
                .open_once_with_info(&offer.offer_id, &enc, &ciphertext, &info, &aad);
        let plaintext = match opened {
            Ok(plaintext) => plaintext,
            Err(_) => return self.reject_fulfillment(terms, side, "open_failed", now),
        };
        let bound = usize::try_from(terms.max_plaintext_bytes.min(MAX_PLAINTEXT_BYTES))
            .map_err(|_| denied())?;
        if plaintext.is_empty()
            || plaintext.len() > bound
            || self
                .enforce_provisioned_profile(credential, plaintext.as_bytes())
                .is_err()
            || self.credentials.insert_secret(&key, plaintext).is_err()
        {
            return self.reject_fulfillment(terms, side, "plaintext_invalid", now);
        }
        self.credential_expiries.insert(key, expiry);
        if let Some(previous) = replaces
            && let Some(old) = self.fulfillments.entries.get_mut(&previous)
        {
            old.phase = Phase::Replaced;
        }
        let stored = FulfillmentResult {
            fulfillment_id: id.clone(),
            terms_digest: digest,
            side,
            state: ResultState::Stored,
            code: None,
            observed_at_ms: now,
        };
        let entry = self.fulfillments.entries.get_mut(&id).ok_or_else(denied)?;
        entry.phase = Phase::Stored;
        entry.receipt = Some(receipt);
        self.report_or_hold(&id, stored);
        Ok("fulfillment_delivery")
    }

    fn fail_recipient(&mut self, id: &str) {
        if let Some(entry) = self.fulfillments.entries.get_mut(id) {
            entry.spend_key();
            entry.phase = Phase::Failed;
        }
    }

    /// Queue a result; if the node queue cannot take it now, keep it on the
    /// entry and retry on the next maintenance pass instead of dropping it.
    fn report_or_hold(&mut self, id: &str, result: FulfillmentResult) {
        if self.queue_fulfillment_result(&result).is_err()
            && let Some(entry) = self.fulfillments.entries.get_mut(id)
        {
            entry.unreported.push(result);
        }
    }

    fn queue_fulfillment_result(&mut self, result: &FulfillmentResult) -> Result<(), BrokerError> {
        let body = result.to_value().map_err(|_| denied())?;
        let key = result_key(result)?;
        if self
            .pending_node_events
            .iter()
            .any(|event| event.idempotency_key == key)
        {
            return Ok(());
        }
        // Keep two slots for the revocation and acknowledgement events.
        if self.pending_node_events.len() > MAX_BROKER_AUDIT_EVENTS - 2 {
            return Err(BrokerError::Configuration(BACKPRESSURE));
        }
        self.pending_node_events.push_back(PendingNodeEvent {
            idempotency_key: key,
            kind: "fulfillment_result".to_owned(),
            body,
        });
        if let Err(error) = self.persist_pending_node_events() {
            self.pending_node_events.pop_back();
            return Err(error);
        }
        Ok(())
    }

    /// Discard a correctly signed document that can never be applied, and tell
    /// the controller why. A full node queue drops the report (and flags the
    /// overflow) rather than wedging the inbox; a persistence failure retries.
    fn reject_fulfillment(
        &mut self,
        terms: &FulfillmentTerms,
        side: FulfillmentSide,
        code: &'static str,
        now: u64,
    ) -> Result<&'static str, BrokerError> {
        let result = FulfillmentResult {
            fulfillment_id: terms.fulfillment_id.clone(),
            terms_digest: terms.digest_hex().map_err(|_| malformed())?,
            side,
            state: ResultState::Failed,
            code: Some(code.to_owned()),
            observed_at_ms: now,
        };
        match self.queue_fulfillment_result(&result) {
            Ok(()) => {}
            Err(BrokerError::Configuration(BACKPRESSURE)) => self.flag_audit_overflow()?,
            Err(error) => return Err(error),
        }
        Ok(REJECTED)
    }

    /// Retry results the node queue could not take earlier.
    pub(crate) fn flush_fulfillment_reports(&mut self) -> Result<(), BrokerError> {
        let ids: Vec<String> = self
            .fulfillments
            .entries
            .iter()
            .filter(|(_, entry)| !entry.unreported.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let Some(entry) = self.fulfillments.entries.get_mut(&id) else {
                continue;
            };
            let held = std::mem::take(&mut entry.unreported);
            for (index, result) in held.iter().enumerate() {
                if let Err(error) = self.queue_fulfillment_result(result) {
                    if let Some(entry) = self.fulfillments.entries.get_mut(&id) {
                        entry.unreported = held[index..].to_vec();
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Called after a loader read of a credential the unit is mapped to. A read
    /// of a credential this broker stored for a fulfillment reports `consumed`
    /// exactly once. A failure to queue never fails the read.
    pub(crate) fn note_fulfillment_read(&mut self, unit: &str, credential: &str) {
        let Some(id) = self
            .fulfillments
            .entries
            .iter()
            .find(|(_, entry)| {
                entry.side == FulfillmentSide::Recipient
                    && entry.phase == Phase::Stored
                    && entry.terms.recipient.unit == unit
                    && entry.terms.recipient.credential == credential
            })
            .map(|(id, _)| id.clone())
        else {
            return;
        };
        let boot = grants::boottime_ms().unwrap_or_default();
        let Some(entry) = self.fulfillments.entries.get_mut(&id) else {
            return;
        };
        entry.phase = Phase::Consumed;
        let consumed = FulfillmentResult {
            fulfillment_id: id.clone(),
            terms_digest: entry.digest.clone(),
            side: FulfillmentSide::Recipient,
            state: ResultState::Consumed,
            code: None,
            observed_at_ms: entry.controller_ms_at(boot).max(1),
        };
        self.report_or_hold(&id, consumed);
    }

    /// Drop spent offers, expired fulfillments and their unread credentials.
    /// A read credential is never touched: it cannot be recalled.
    pub(crate) fn maintain_fulfillments(&mut self) {
        let boot = grants::boottime_ms().ok();
        let mut finished = Vec::new();
        for (id, entry) in &mut self.fulfillments.entries {
            let Some(boot) = boot else {
                // No trustworthy clock: withdraw every live key.
                entry.spend_key();
                continue;
            };
            let key = destination_key(
                &entry.terms.recipient.unit,
                &entry.terms.recipient.credential,
            );
            if entry.phase == Phase::Stored && boot >= entry.deadline_boot {
                self.credentials.remove(&key);
                self.credential_expiries.remove(&key);
                entry.phase = Phase::Failed;
            }
            let holds_credential = matches!(entry.phase, Phase::Stored | Phase::Consumed)
                && self.credentials.get(&key).is_ok();
            if boot >= entry.deadline_boot && !holds_credential && entry.unreported.is_empty() {
                finished.push(id.clone());
            }
        }
        for id in finished {
            self.fulfillments.entries.remove(&id);
        }
        if let Some(boot) = boot {
            self.fulfillments
                .tombstones
                .retain(|stone| boot < stone.until_boot);
        }
    }

    /// A signed revocation deletes only what this broker holds. An unread stored
    /// credential is removed; a read one stays. Older epochs are honoured too,
    /// because a revocation only ever removes authority.
    pub(crate) fn revoke_fulfillment(
        &mut self,
        revocation: &FulfillmentRevocation,
    ) -> Result<(), BrokerError> {
        let boot = grants::boottime_ms().map_err(BrokerError::Configuration)?;
        let window = revocation
            .retain_until_ms
            .saturating_sub(revocation.revoked_at_ms)
            .min(MAX_TOMBSTONE_MS);
        self.fulfillments.bury(
            &revocation.fulfillment_id,
            &revocation.terms_digest,
            boot.saturating_add(window),
        );
        let matches = self
            .fulfillments
            .entries
            .get(&revocation.fulfillment_id)
            .is_some_and(|entry| entry.digest == revocation.terms_digest);
        if matches {
            self.retire_fulfillment(&revocation.fulfillment_id);
        }
        Ok(())
    }

    /// Remove one fulfillment's pending state and, if still unread, its credential.
    fn retire_fulfillment(&mut self, id: &str) {
        let Some(entry) = self.fulfillments.entries.get_mut(id) else {
            return;
        };
        entry.spend_key();
        match entry.phase {
            Phase::Consumed => {
                // Kept so a rotation can still name it; the credential stays.
                entry.unreported.clear();
                return;
            }
            Phase::Stored => {
                let key = destination_key(
                    &entry.terms.recipient.unit,
                    &entry.terms.recipient.credential,
                );
                self.credentials.remove(&key);
                self.credential_expiries.remove(&key);
            }
            _ => {}
        }
        self.fulfillments.entries.remove(id);
    }

    /// An advanced issuer epoch retires older authority, exactly as for grants.
    pub(crate) fn observe_fulfillment_epoch(&mut self, epoch: u64) {
        let stale: Vec<String> = self
            .fulfillments
            .entries
            .iter()
            .filter(|(_, entry)| entry.terms.issuer_epoch < epoch)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            self.retire_fulfillment(&id);
        }
    }

    /// The signed `fulfillment_offer` (recipient) or `fulfillment_submit`
    /// (issuer) node event for a fulfillment this broker holds, as canonical
    /// bytes. Repeated calls return identical bytes. Only documents minted here
    /// are signed; the unprivileged relay never supplies a body.
    pub(crate) fn fulfillment_event(
        &mut self,
        identity: &NodeIdentity,
        fulfillment_id: &str,
    ) -> Result<Vec<u8>, BrokerError> {
        self.fulfillment_event_bytes(identity, fulfillment_id)
            .map_err(|_| denied())
    }

    fn fulfillment_event_bytes(
        &self,
        identity: &NodeIdentity,
        fulfillment_id: &str,
    ) -> Result<Vec<u8>, BrokerError> {
        if self.node_revoked {
            return Err(denied());
        }
        let pin = identity.pinned_issuer()?.ok_or_else(denied)?;
        let boot = grants::boottime_ms().map_err(BrokerError::Configuration)?;
        let entry = self
            .fulfillments
            .entries
            .get(fulfillment_id)
            .ok_or_else(denied)?;
        let (kind, prefix, envelope) = match (entry.side, entry.phase) {
            (FulfillmentSide::Recipient, Phase::Offered) if boot < entry.offer_deadline_boot => {
                ("fulfillment_offer", "fo_", entry.offer.as_ref())
            }
            (FulfillmentSide::Issuer, Phase::Sealed) if boot < entry.deadline_boot => {
                ("fulfillment_submit", "fs_", entry.submit.as_ref())
            }
            _ => return Err(denied()),
        };
        let encoded = envelope
            .ok_or_else(denied)?
            .to_json()
            .map_err(|_| denied())?;
        let body = parse_json(std::str::from_utf8(&encoded).map_err(|_| denied())?)
            .map_err(|_| denied())?;
        let key = format!("{prefix}{}", id_digest(fulfillment_id)?);
        let signature = identity.sign_node_event(&pin.node_id, &key, kind, &body)?;
        canonicalize_value(&Value::Object(vec![
            ("body".to_owned(), body),
            ("broker_signature".to_owned(), Value::String(signature)),
            ("idempotency_key".to_owned(), Value::String(key)),
            ("kind".to_owned(), Value::String(kind.to_owned())),
        ]))
        .map_err(|_| denied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::apply_controller_document_to_state;
    use crate::keys::PinnedIssuer;
    use blindpass_core::canon::{Value, canonicalize_value, parse_json};
    use blindpass_core::custody::{RecipientKeyPair, sha256};
    use blindpass_core::delivery::DeliveryPolicy;
    use blindpass_core::fleet::{
        ConsumptionMode, DocumentKind, PolicySnapshot, Registration, TimeReply, node_event_message,
    };
    use blindpass_core::fulfillment::{
        FulfillmentAuthorization, FulfillmentDelivery, FulfillmentOffer, FulfillmentParty,
        FulfillmentResult, FulfillmentRevocation, FulfillmentSide, FulfillmentTerms, ResultState,
        RevocationReason, verify_offer, verify_submit,
    };
    use blindpass_core::signing::base64_url_encode;
    use blindpass_core::signing::ed25519::{Ed25519KeyPair, verify};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const SECRET: &[u8] = b"DUMMY-P10-BROKER-CREDENTIAL-0123";
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn wall_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    struct World {
        seed: u8,
        controller: Ed25519KeyPair,
        key_id: String,
        public: String,
        epoch: u64,
        now_ms: u64,
    }

    impl World {
        fn new(seed: u8) -> Self {
            let controller = Ed25519KeyPair::from_seed(&[seed; 32]).unwrap();
            let public = base64_url_encode(controller.public_key());
            Self {
                seed,
                key_id: format!("ed25519-{public}"),
                controller,
                public,
                epoch: 1,
                now_ms: wall_ms(),
            }
        }

        fn sign_at(&self, kind: DocumentKind, body: Value, epoch: u64) -> Vec<u8> {
            SignedEnvelope::sign(kind, body, &self.key_id, epoch, &self.controller)
                .unwrap()
                .to_json()
                .unwrap()
        }

        fn sign(&self, kind: DocumentKind, body: Value) -> Vec<u8> {
            self.sign_at(kind, body, self.epoch)
        }

        /// The same controller key, one rotation later.
        fn at_epoch(&self, epoch: u64) -> World {
            let mut next = World::new(self.seed);
            next.epoch = epoch;
            next.now_ms = self.now_ms;
            next
        }
    }

    struct Node {
        directory: PathBuf,
        identity: NodeIdentity,
        state: BrokerState,
        node_id: String,
        workload_id: String,
        unit: String,
        credential: String,
    }

    impl Node {
        fn new(world: &World, name: &str, source: bool, destination: bool) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "blindpass-p10-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory).unwrap();
            let node_id = format!("nd_{name}");
            let identity = NodeIdentity::load_or_create(&directory).unwrap();
            identity
                .pin_issuer(PinnedIssuer {
                    tenant_id: "tenant-a".to_owned(),
                    node_id: node_id.clone(),
                    epoch: world.epoch,
                    key_id: world.key_id.clone(),
                    public_key: world.public.clone(),
                })
                .unwrap();
            let mut state = BrokerState::new(DeliveryPolicy::default());
            state.operation_directory = directory.join("ops");
            state.configure_grant_storage(&identity).unwrap();
            let unit = format!("{name}-app.service");
            let credential = "api-token".to_owned();
            state.loader_policy.map_unit(&unit, &credential).unwrap();
            let mut node = Self {
                directory,
                identity,
                state,
                workload_id: format!("wl_{name}"),
                node_id,
                unit,
                credential,
            };
            let registration = Registration {
                node_id: node.node_id.clone(),
                workload_id: node.workload_id.clone(),
                unit: node.unit.clone(),
                account: "worker".to_owned(),
                invocation_id: None,
                status: "active".to_owned(),
                consumption_mode: ConsumptionMode::File,
                registration_version: 1,
                policy_version: 4,
                local_ceiling_seconds: 60,
            };
            let policy = PolicySnapshot {
                policy_version: 4,
                local_ceiling_seconds: 60,
                allowed_actions: vec!["noop.marker".to_owned()],
                allowed_modes: vec![ConsumptionMode::File],
            };
            for (kind, body) in [
                (DocumentKind::Registration, registration.to_value().unwrap()),
                (DocumentKind::PolicySnapshot, policy.to_value().unwrap()),
            ] {
                node.apply(&world.sign(kind, body)).unwrap();
            }
            node.refresh_time(world);
            let sources: Vec<String> = source.then(|| node.unit.clone()).into_iter().collect();
            let destinations: Vec<String> =
                destination.then(|| node.unit.clone()).into_iter().collect();
            node.state
                .configure_fulfillment(&sources, &destinations, Duration::from_secs(180))
                .unwrap();
            node
        }

        fn apply(&mut self, document: &[u8]) -> Result<&'static str, BrokerError> {
            apply_controller_document_to_state(&mut self.state, &self.identity, document, false)
        }

        fn refresh_time(&mut self, world: &World) {
            let challenge = self.state.grant_verifier.begin_time_challenge().unwrap();
            let reply = TimeReply {
                node_id: self.node_id.clone(),
                challenge,
                challenge_received_at_ms: world.now_ms,
                controller_time_ms: world.now_ms,
                issuer_epoch: world.epoch,
            };
            assert_eq!(
                self.apply(&world.sign(DocumentKind::TimeReply, reply.to_value().unwrap()))
                    .unwrap(),
                "time_reply"
            );
        }

        /// A controller at a newer epoch proves itself with a signed time reply,
        /// which advances this node's issuer pin.
        fn advance_epoch(&mut self, world: &World, epoch: u64) {
            self.refresh_time(&world.at_epoch(epoch));
        }

        fn provision(&mut self, secret: &[u8]) {
            let public = self
                .state
                .provision_key(&self.unit, &self.credential)
                .unwrap();
            let aad = crate::provision_aad(&self.unit, &self.credential);
            let sealed = RecipientKeyPair::seal(&public, secret, aad.as_bytes()).unwrap();
            self.state
                .provision_sealed(
                    &self.unit,
                    &self.credential,
                    &sealed.enc,
                    &sealed.ciphertext,
                )
                .unwrap();
        }

        /// What the recipient unit would receive from the loader; a read counts
        /// as consumption.
        fn read(&mut self) -> Option<Vec<u8>> {
            self.state
                .process_systemd_credential(&self.unit, &self.credential)
                .ok()
                .map(|secret| secret.as_bytes().to_vec())
        }

        /// Whether broker custody holds a credential now, without reading it.
        fn has(&mut self) -> bool {
            self.state.purge_expired_credentials();
            self.state
                .credentials
                .get(&crate::destination_key(&self.unit, &self.credential))
                .is_ok()
        }

        fn party(&self) -> FulfillmentParty {
            let public = self.identity.public_identity().unwrap();
            FulfillmentParty {
                node_id: self.node_id.clone(),
                workload_id: self.workload_id.clone(),
                unit: self.unit.clone(),
                credential: self.credential.clone(),
                registration_version: 1,
                key_version: self.identity.key_version().unwrap(),
                signing_public: public.signing_public,
                recipient_public: public.recipient_public,
                fingerprint: public.fingerprint,
            }
        }

        fn result_events(&self) -> Vec<FulfillmentResult> {
            self.state
                .pending_node_events(1_000)
                .iter()
                .filter(|event| event.kind == "fulfillment_result")
                .map(|event| FulfillmentResult::from_value(&event.body).unwrap())
                .collect()
        }

        fn failure_codes(&self) -> Vec<String> {
            self.result_events()
                .into_iter()
                .filter(|result| result.state == ResultState::Failed)
                .map(|result| result.code.unwrap())
                .collect()
        }
    }

    impl Drop for Node {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn terms(world: &World, issuer: &Node, recipient: &Node, id: &str) -> FulfillmentTerms {
        FulfillmentTerms {
            fulfillment_id: id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            issuer: issuer.party(),
            recipient: recipient.party(),
            policy_version: 4,
            rule_id: "rule-cross-1".to_owned(),
            approval_reference: Some("oa_0123456789abcdef".to_owned()),
            prior_fulfillment_id: None,
            max_plaintext_bytes: 8192,
            issued_at_ms: world.now_ms,
            expires_at_ms: world.now_ms + 600_000,
            issuer_epoch: world.epoch,
        }
    }

    fn authorization(
        world: &World,
        side: FulfillmentSide,
        terms: &FulfillmentTerms,
        offer: Option<&SignedEnvelope>,
    ) -> Vec<u8> {
        let body = FulfillmentAuthorization {
            side,
            terms: terms.clone(),
            offer: offer.cloned(),
        }
        .to_value()
        .unwrap();
        world.sign_at(
            DocumentKind::FulfillmentAuthorization,
            body,
            terms.issuer_epoch,
        )
    }

    fn delivery(
        world: &World,
        terms: &FulfillmentTerms,
        offer: &SignedEnvelope,
        submit: &SignedEnvelope,
    ) -> Vec<u8> {
        let body = FulfillmentDelivery {
            terms: terms.clone(),
            offer: offer.clone(),
            submit: submit.clone(),
        }
        .to_value()
        .unwrap();
        world.sign_at(DocumentKind::FulfillmentDelivery, body, terms.issuer_epoch)
    }

    fn revocation(world: &World, terms: &FulfillmentTerms, node_id: &str) -> Vec<u8> {
        let body = FulfillmentRevocation {
            fulfillment_id: terms.fulfillment_id.clone(),
            terms_digest: terms.digest_hex().unwrap(),
            node_id: node_id.to_owned(),
            reason: RevocationReason::Operator,
            revoked_at_ms: world.now_ms,
            retain_until_ms: world.now_ms + 7 * 86_400_000,
            issuer_epoch: terms.issuer_epoch,
        }
        .to_value()
        .unwrap();
        world.sign_at(
            DocumentKind::FulfillmentRevocation,
            body,
            terms.issuer_epoch,
        )
    }

    /// Parse and signature-check a broker-produced node event, returning its
    /// kind, idempotency key and the envelope carried in its body.
    fn open_event(node: &Node, bytes: &[u8], expected_kind: &str) -> (String, SignedEnvelope) {
        let value = parse_json(std::str::from_utf8(bytes).unwrap()).unwrap();
        assert_eq!(
            canonicalize_value(&value).unwrap(),
            bytes,
            "canonical bytes"
        );
        let kind = value.get("kind").and_then(Value::as_str).unwrap();
        assert_eq!(kind, expected_kind);
        let key = value
            .get("idempotency_key")
            .and_then(Value::as_str)
            .unwrap();
        let body = value.get("body").unwrap();
        let signature = value
            .get("broker_signature")
            .and_then(Value::as_str)
            .unwrap();
        let message = node_event_message(&node.node_id, key, kind, body).unwrap();
        let public = node.identity.public_identity().unwrap();
        assert!(
            verify(
                &blindpass_core::signing::base64_url_decode(&public.signing_public, 32).unwrap(),
                &message,
                &blindpass_core::signing::base64_url_decode(signature, 64).unwrap(),
            )
            .unwrap(),
            "the event is signed by the node key"
        );
        let envelope = SignedEnvelope::from_json(
            std::str::from_utf8(&canonicalize_value(body).unwrap()).unwrap(),
        )
        .unwrap();
        (key.to_owned(), envelope)
    }

    struct Flow {
        terms: FulfillmentTerms,
        offer: SignedEnvelope,
        submit: SignedEnvelope,
        delivery: Vec<u8>,
    }

    /// Drive the whole exchange up to, but not including, the delivery.
    fn flow(world: &World, issuer: &mut Node, recipient: &mut Node, id: &str) -> Flow {
        flow_replacing(world, issuer, recipient, id, None)
    }

    /// As `flow`, for terms that name the fulfillment they replace.
    fn flow_replacing(
        world: &World,
        issuer: &mut Node,
        recipient: &mut Node,
        id: &str,
        prior: Option<&str>,
    ) -> Flow {
        if !issuer.has() {
            issuer.provision(SECRET);
        }
        let mut terms = terms(world, issuer, recipient, id);
        terms.prior_fulfillment_id = prior.map(str::to_owned);
        assert_eq!(
            recipient
                .apply(&authorization(
                    world,
                    FulfillmentSide::Recipient,
                    &terms,
                    None
                ))
                .unwrap(),
            "fulfillment_authorization"
        );
        let offer_event = recipient
            .state
            .fulfillment_event(&recipient.identity, id)
            .unwrap();
        let (_, offer) = open_event(recipient, &offer_event, "fulfillment_offer");
        assert_eq!(
            issuer
                .apply(&authorization(
                    world,
                    FulfillmentSide::Issuer,
                    &terms,
                    Some(&offer)
                ))
                .unwrap(),
            "fulfillment_authorization"
        );
        let submit_event = issuer
            .state
            .fulfillment_event(&issuer.identity, id)
            .unwrap();
        let (_, submit) = open_event(issuer, &submit_event, "fulfillment_submit");
        let delivery = delivery(world, &terms, &offer, &submit);
        Flow {
            terms,
            offer,
            submit,
            delivery,
        }
    }

    /// A time inside the offer's own window; the broker mints offers at the
    /// trusted controller time, which runs slightly ahead of the test world.
    fn after(offer: &SignedEnvelope, milliseconds: u64) -> u64 {
        FulfillmentOffer::from_value(offer.body())
            .unwrap()
            .issued_at_ms
            + milliseconds
    }

    fn pair(world: &World) -> (Node, Node) {
        (
            Node::new(world, "issuer", true, false),
            Node::new(world, "recipient", false, true),
        )
    }

    const ID: &str = "ful_0123456789abcdefABCDEF";

    #[test]
    fn p10_b01_end_to_end_transfer_then_loader_read_marks_consumed_once() {
        let world = World::new(41);
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        // The issuer's own custody is untouched and still readable.
        assert_eq!(issuer.read().as_deref(), Some(SECRET));
        // The controller-visible documents verify against the terms' keys only.
        let verified_offer = verify_offer(&f.offer, &f.terms, after(&f.offer, 1)).unwrap();
        verify_submit(&f.submit, &f.terms, &verified_offer).unwrap();
        assert_eq!(
            recipient.apply(&f.delivery).unwrap(),
            "fulfillment_delivery"
        );
        assert_eq!(
            recipient
                .result_events()
                .iter()
                .map(|r| (r.side, r.state))
                .collect::<Vec<_>>(),
            vec![(FulfillmentSide::Recipient, ResultState::Stored)]
        );
        // The recipient unit reads it through the loader: consumed, exactly once.
        assert_eq!(recipient.read().as_deref(), Some(SECRET));
        assert_eq!(recipient.read().as_deref(), Some(SECRET));
        let states: Vec<_> = recipient.result_events().iter().map(|r| r.state).collect();
        assert_eq!(states, vec![ResultState::Stored, ResultState::Consumed]);
        // No plaintext reaches a queued event.
        for event in recipient.state.pending_node_events(1_000) {
            let bytes = canonicalize_value(&event.to_value()).unwrap();
            assert!(!bytes.windows(SECRET.len()).any(|w| w == SECRET));
        }
        let book = format!("{:?}", recipient.state.fulfillments);
        assert!(!book.contains("DUMMY-P10"));
    }

    #[test]
    fn p10_b02_every_document_refuses_without_local_opt_in() {
        let world = World::new(42);
        let mut issuer = Node::new(&world, "issuer", false, false);
        let mut recipient = Node::new(&world, "recipient", false, false);
        issuer.provision(SECRET);
        let t = terms(&world, &issuer, &recipient, ID);
        // Valid, signed, addressed to this node, but the broker never opted in.
        assert_eq!(
            recipient
                .apply(&authorization(&world, FulfillmentSide::Recipient, &t, None))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(recipient.failure_codes(), vec!["not_enabled"]);
        assert_eq!(recipient.state.fulfillments.len(), 0);
        assert!(
            recipient
                .state
                .fulfillment_event(&recipient.identity, ID)
                .is_err()
        );
        // The issuer side refuses the same way, whatever offer it is shown.
        let offer = FulfillmentOffer {
            fulfillment_id: ID.to_owned(),
            terms_digest: t.digest_hex().unwrap(),
            offer_id: "fo_0123456789abcdefABCDEF".to_owned(),
            node_id: recipient.node_id.clone(),
            node_key_version: recipient.identity.key_version().unwrap(),
            recipient_public: base64_url_encode(RecipientKeyPair::generate().unwrap().public_key()),
            issued_at_ms: world.now_ms,
            expires_at_ms: world.now_ms + 120_000,
        };
        let envelope = recipient.identity.sign_fulfillment_offer(&offer).unwrap();
        assert_eq!(
            issuer
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Issuer,
                    &t,
                    Some(&envelope)
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(issuer.failure_codes(), vec!["not_enabled"]);
        assert!(issuer.has(), "the source credential is untouched");
        // A recipient-side document is not for the issuer's node at all.
        let before = issuer.state.pending_node_events(100).len();
        assert_eq!(
            issuer
                .apply(&authorization(&world, FulfillmentSide::Recipient, &t, None))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(issuer.state.pending_node_events(100).len(), before);
    }

    #[test]
    fn p10_b02_configuration_requires_mapped_units() {
        let world = World::new(43);
        let mut node = Node::new(&world, "issuer", false, false);
        assert!(
            node.state
                .configure_fulfillment(&["other.service".to_owned()], &[], Duration::from_secs(10))
                .is_err(),
            "an unmapped unit cannot be opted in"
        );
        assert!(
            node.state
                .configure_fulfillment(&[], &[], Duration::from_secs(181))
                .is_err(),
            "the offer lifetime is capped at 180 s"
        );
        assert!(
            node.state
                .configure_fulfillment(&[], &[], Duration::ZERO)
                .is_err()
        );
    }

    #[test]
    fn p10_b03_bindings_the_controller_cannot_widen() {
        let world = World::new(44);
        // Registration version, policy version, credential mapping, key version.
        type Mutation = fn(&mut FulfillmentTerms);
        let cases: Vec<(&str, Mutation)> = vec![
            ("registration_mismatch", |t| {
                t.recipient.registration_version = 9
            }),
            ("policy_stale", |t| t.policy_version = 3),
            ("unmapped", |t| {
                t.recipient.credential = "other-token".into()
            }),
        ];
        for (code, mutate) in cases {
            let (issuer, mut recipient) = pair(&world);
            let mut terms = terms(&world, &issuer, &recipient, ID);
            mutate(&mut terms);
            assert_eq!(
                recipient
                    .apply(&authorization(
                        &world,
                        FulfillmentSide::Recipient,
                        &terms,
                        None
                    ))
                    .unwrap(),
                "fulfillment_discarded_rejected",
                "{code}"
            );
            assert_eq!(recipient.failure_codes(), vec![code.to_owned()]);
            assert_eq!(recipient.state.fulfillments.len(), 0, "{code}");
        }
    }

    #[test]
    fn p10_b03_identity_and_scope_mismatches() {
        let world = World::new(45);
        let (issuer, mut recipient) = pair(&world);
        let good = terms(&world, &issuer, &recipient, ID);

        // Another key version or another fingerprint: addressed to this node, so a
        // failure is reported, but nothing is installed.
        let mut other_key = good.clone();
        other_key.recipient.key_version = 5;
        assert_eq!(
            recipient
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &other_key,
                    None
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(recipient.failure_codes(), vec!["identity_mismatch"]);
        assert_eq!(recipient.state.fulfillments.len(), 0);

        // Addressed to another node: discarded without any event at all.
        let (mut other_issuer, other_recipient) = pair(&world);
        let mut misdirected = terms(
            &world,
            &other_issuer,
            &other_recipient,
            "ful_ffffffffffffffffffffff",
        );
        misdirected.issuer = issuer.party();
        let before = other_issuer.state.pending_node_events(100).len();
        assert_eq!(
            other_issuer
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &misdirected,
                    None
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(other_issuer.state.pending_node_events(100).len(), before);

        // Another tenant.
        let mut foreign = good.clone();
        foreign.tenant_id = "tenant-z".into();
        let before = recipient.state.pending_node_events(100).len();
        assert_eq!(
            recipient
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &foreign,
                    None
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(recipient.state.pending_node_events(100).len(), before);
    }

    #[test]
    fn p10_b03_signature_epoch_and_expiry() {
        let world = World::new(46);
        let (issuer, mut recipient) = pair(&world);
        let good = terms(&world, &issuer, &recipient, ID);
        // Signed by a different controller key.
        let forger = World::new(99);
        assert!(
            recipient
                .apply(&authorization(
                    &forger,
                    FulfillmentSide::Recipient,
                    &good,
                    None
                ))
                .is_err()
        );
        assert_eq!(recipient.state.fulfillments.len(), 0);
        // An older epoch is acknowledged and ignored; it confers nothing.
        let mut older = good.clone();
        older.issuer_epoch = 1;
        recipient.advance_epoch(&world, 2);
        assert_eq!(
            recipient
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &older,
                    None
                ))
                .unwrap(),
            "stale_epoch"
        );
        assert_eq!(recipient.state.fulfillments.len(), 0);

        // Expired terms: the controller signed them, but they are already over.
        let (issuer, mut recipient) = pair(&world);
        let mut expired = terms(&world, &issuer, &recipient, ID);
        expired.issued_at_ms = world.now_ms - 650_000;
        expired.expires_at_ms = world.now_ms - 50_000;
        assert_eq!(
            recipient
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &expired,
                    None
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(recipient.failure_codes(), vec!["terms_expired"]);
    }

    #[test]
    fn p10_b04_issuer_refusals() {
        let world = World::new(47);
        // Source missing.
        let (mut issuer, mut recipient) = pair(&world);
        let t = terms(&world, &issuer, &recipient, ID);
        recipient
            .apply(&authorization(&world, FulfillmentSide::Recipient, &t, None))
            .unwrap();
        let offer_event = recipient
            .state
            .fulfillment_event(&recipient.identity, ID)
            .unwrap();
        let (_, offer) = open_event(&recipient, &offer_event, "fulfillment_offer");
        assert_eq!(
            issuer
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Issuer,
                    &t,
                    Some(&offer)
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(issuer.failure_codes(), vec!["source_missing"]);

        // Source larger than the terms allow.
        let (mut issuer, mut recipient) = pair(&world);
        issuer.provision(SECRET);
        let mut small = terms(&world, &issuer, &recipient, ID);
        small.max_plaintext_bytes = 8;
        recipient
            .apply(&authorization(
                &world,
                FulfillmentSide::Recipient,
                &small,
                None,
            ))
            .unwrap();
        let offer_event = recipient
            .state
            .fulfillment_event(&recipient.identity, ID)
            .unwrap();
        let (_, offer) = open_event(&recipient, &offer_event, "fulfillment_offer");
        assert_eq!(
            issuer
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Issuer,
                    &small,
                    Some(&offer)
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(issuer.failure_codes(), vec!["source_too_large"]);

        // An offer whose signature is not the recipient node's.
        let (mut issuer, recipient) = pair(&world);
        issuer.provision(SECRET);
        let t = terms(&world, &issuer, &recipient, ID);
        let offer = FulfillmentOffer {
            fulfillment_id: ID.to_owned(),
            terms_digest: t.digest_hex().unwrap(),
            offer_id: "fo_0123456789abcdefABCDEF".to_owned(),
            node_id: recipient.node_id.clone(),
            node_key_version: recipient.identity.key_version().unwrap(),
            recipient_public: base64_url_encode(RecipientKeyPair::generate().unwrap().public_key()),
            issued_at_ms: world.now_ms,
            expires_at_ms: world.now_ms + 120_000,
        };
        assert!(
            issuer.identity.sign_fulfillment_offer(&offer).is_err(),
            "a node cannot sign an offer that names another node"
        );
        let forged =
            blindpass_core::fulfillment::sign_offer(&offer, &Ed25519KeyPair::generate().unwrap())
                .unwrap();
        assert_eq!(
            issuer
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Issuer,
                    &t,
                    Some(&forged)
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(issuer.failure_codes(), vec!["offer_invalid"]);
        assert_eq!(issuer.state.fulfillments.len(), 0);
    }

    #[test]
    fn p10_b05_recipient_refusals_and_destination_ownership() {
        let world = World::new(48);
        // Destination already holds a live credential from another source.
        let (issuer, mut recipient) = pair(&world);
        recipient.provision(b"DUMMY-EXISTING-CREDENTIAL");
        let t = terms(&world, &issuer, &recipient, ID);
        assert_eq!(
            recipient
                .apply(&authorization(&world, FulfillmentSide::Recipient, &t, None))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(recipient.failure_codes(), vec!["destination_occupied"]);
        assert_eq!(
            recipient.read().as_deref(),
            Some(b"DUMMY-EXISTING-CREDENTIAL".as_slice()),
            "an occupying credential is never overwritten or removed"
        );
        // Revoking the refused fulfillment must not touch it either.
        recipient
            .apply(&revocation(&world, &t, &recipient.node_id.clone()))
            .unwrap();
        assert_eq!(
            recipient.read().as_deref(),
            Some(b"DUMMY-EXISTING-CREDENTIAL".as_slice())
        );

        // Only one active fulfillment per recipient destination.
        let (issuer, mut recipient) = pair(&world);
        let first = terms(&world, &issuer, &recipient, ID);
        assert_eq!(
            recipient
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &first,
                    None
                ))
                .unwrap(),
            "fulfillment_authorization"
        );
        let second = terms(&world, &issuer, &recipient, "ful_eeeeeeeeeeeeeeeeeeeeee");
        assert_eq!(
            recipient
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &second,
                    None
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(recipient.failure_codes(), vec!["destination_busy"]);

        // A rotation names the fulfillment that owns the destination.
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        recipient.apply(&f.delivery).unwrap();
        let mut rotation = terms(&world, &issuer, &recipient, "ful_dddddddddddddddddddddd");
        rotation.prior_fulfillment_id = Some(ID.to_owned());
        assert_eq!(
            recipient
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &rotation,
                    None
                ))
                .unwrap(),
            "fulfillment_authorization",
            "the prior owner is replaceable by name"
        );
        let mut unnamed = terms(&world, &issuer, &recipient, "ful_cccccccccccccccccccccc");
        unnamed.prior_fulfillment_id = Some("ful_bbbbbbbbbbbbbbbbbbbbbb".to_owned());
        let rejected = recipient
            .apply(&authorization(
                &world,
                FulfillmentSide::Recipient,
                &unnamed,
                None,
            ))
            .unwrap();
        assert_eq!(rejected, "fulfillment_discarded_rejected");
    }

    #[test]
    fn p10_b06_delivery_is_idempotent_and_the_key_is_one_use() {
        let world = World::new(49);
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        assert_eq!(
            recipient.apply(&f.delivery).unwrap(),
            "fulfillment_delivery"
        );
        // The exact retry changes nothing and queues nothing new.
        let queued = recipient.state.pending_node_events(100).len();
        assert_eq!(
            recipient.apply(&f.delivery).unwrap(),
            "fulfillment_delivery"
        );
        assert_eq!(recipient.state.pending_node_events(100).len(), queued);
        // A different body for the same fulfillment: a second ciphertext under the
        // same spent key can never be opened and never replaces the stored value.
        let other_submit = {
            let verified = verify_offer(&f.offer, &f.terms, after(&f.offer, 1)).unwrap();
            issuer
                .identity
                .seal_fulfillment(
                    &f.terms,
                    &verified,
                    b"DUMMY-OTHER-PLAINTEXT",
                    after(&f.offer, 2),
                )
                .unwrap()
        };
        let different = delivery(&world, &f.terms, &f.offer, &other_submit);
        assert_eq!(
            recipient.apply(&different).unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(recipient.read().as_deref(), Some(SECRET));
    }

    #[test]
    fn p10_b06_a_forged_submission_never_touches_the_key() {
        let world = World::new(50);
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        // The genuine sealed bytes, re-signed by a key that is not the issuer's.
        let forged = SignedEnvelope::sign(
            DocumentKind::FulfillmentSubmit,
            f.submit.body().clone(),
            &f.terms.issuer.key_id(),
            f.terms.issuer.key_version,
            &Ed25519KeyPair::generate().unwrap(),
        )
        .unwrap();
        assert_eq!(
            recipient
                .apply(&delivery(&world, &f.terms, &f.offer, &forged))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert!(!recipient.has(), "nothing was stored");
        assert_eq!(recipient.failure_codes(), vec!["delivery_invalid"]);
        // A forgery fails before the one-use key is opened, so the honest delivery works.
        assert_eq!(
            recipient.apply(&f.delivery).unwrap(),
            "fulfillment_delivery"
        );
        assert_eq!(recipient.read().as_deref(), Some(SECRET));
    }

    #[test]
    fn p10_b06_a_failed_open_spends_the_one_use_key() {
        let world = World::new(57);
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        // A submission genuinely signed by the issuer node but sealed to some other key:
        // it verifies, cannot be opened, and burns the offer.
        let verified = verify_offer(&f.offer, &f.terms, after(&f.offer, 1)).unwrap();
        let mut stray = verified.clone();
        stray.recipient_public =
            base64_url_encode(RecipientKeyPair::generate().unwrap().public_key());
        let stray_submit = issuer
            .identity
            .seal_fulfillment(&f.terms, &stray, b"DUMMY-STRAY", after(&f.offer, 2))
            .unwrap();
        assert_eq!(
            recipient
                .apply(&delivery(&world, &f.terms, &f.offer, &stray_submit))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert_eq!(recipient.failure_codes(), vec!["open_failed"]);
        assert!(!recipient.has());
        // The key is gone: even the honest delivery can no longer be applied.
        assert_eq!(
            recipient.apply(&f.delivery).unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert!(!recipient.has());
    }

    #[test]
    fn p10_b07_offer_expiry_and_unknown_fulfillment() {
        let world = World::new(51);
        let mut issuer = Node::new(&world, "issuer", true, false);
        let mut recipient = Node::new(&world, "recipient", false, false);
        recipient
            .state
            .configure_fulfillment(&[], &[recipient.unit.clone()], Duration::from_millis(150))
            .unwrap();
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            recipient.apply(&f.delivery).unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert!(!recipient.has());
        assert!(
            recipient
                .failure_codes()
                .contains(&"offer_expired".to_owned())
        );

        // After a restart the book is empty, so a delivery cannot be applied.
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        let mut restarted = BrokerState::new(DeliveryPolicy::default());
        restarted
            .configure_grant_storage(&recipient.identity)
            .unwrap();
        restarted
            .loader_policy
            .map_unit(&recipient.unit, &recipient.credential)
            .unwrap();
        std::mem::swap(&mut recipient.state, &mut restarted);
        // Re-establish registration, policy and time, as startup would restore them.
        let registration = Registration {
            node_id: recipient.node_id.clone(),
            workload_id: recipient.workload_id.clone(),
            unit: recipient.unit.clone(),
            account: "worker".to_owned(),
            invocation_id: None,
            status: "active".to_owned(),
            consumption_mode: ConsumptionMode::File,
            registration_version: 1,
            policy_version: 4,
            local_ceiling_seconds: 60,
        };
        let policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        recipient
            .apply(&world.sign(DocumentKind::Registration, registration.to_value().unwrap()))
            .unwrap();
        recipient
            .apply(&world.sign(DocumentKind::PolicySnapshot, policy.to_value().unwrap()))
            .unwrap();
        recipient.refresh_time(&world);
        recipient
            .state
            .configure_fulfillment(&[], &[recipient.unit.clone()], Duration::from_secs(180))
            .unwrap();
        assert_eq!(
            recipient.apply(&f.delivery).unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert!(!recipient.has());
        assert!(
            recipient
                .failure_codes()
                .contains(&"unknown_fulfillment".to_owned())
        );
    }

    #[test]
    fn p10_b08_revocation_before_store_after_store_and_after_consume() {
        let world = World::new(52);
        // Before the credential is stored: the offer key dies and a later delivery fails.
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        let node = recipient.node_id.clone();
        assert_eq!(
            recipient
                .apply(&revocation(&world, &f.terms, &node))
                .unwrap(),
            "fulfillment_revocation"
        );
        assert_eq!(
            recipient.apply(&f.delivery).unwrap(),
            "fulfillment_discarded_rejected"
        );
        assert!(!recipient.has());

        // After store, before the unit reads it: removed.
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        recipient.apply(&f.delivery).unwrap();
        let node = recipient.node_id.clone();
        recipient
            .apply(&revocation(&world, &f.terms, &node))
            .unwrap();
        assert!(!recipient.has(), "an unread credential is removed");

        // After the unit read it: it stays; the consumed credential cannot be recalled.
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        recipient.apply(&f.delivery).unwrap();
        assert_eq!(recipient.read().as_deref(), Some(SECRET));
        let node = recipient.node_id.clone();
        recipient
            .apply(&revocation(&world, &f.terms, &node))
            .unwrap();
        assert_eq!(recipient.read().as_deref(), Some(SECRET));

        // A revocation for other terms of the same id changes nothing.
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        recipient.apply(&f.delivery).unwrap();
        let mut other = f.terms.clone();
        other.policy_version = 4;
        other.rule_id = "rule-other".into();
        let node = recipient.node_id.clone();
        recipient.apply(&revocation(&world, &other, &node)).unwrap();
        assert_eq!(recipient.read().as_deref(), Some(SECRET));

        // The issuer drops its pending state and cannot seal afterwards.
        let (mut issuer, mut recipient) = pair(&world);
        issuer.provision(SECRET);
        let t = terms(&world, &issuer, &recipient, ID);
        recipient
            .apply(&authorization(&world, FulfillmentSide::Recipient, &t, None))
            .unwrap();
        let offer_event = recipient
            .state
            .fulfillment_event(&recipient.identity, ID)
            .unwrap();
        let (_, offer) = open_event(&recipient, &offer_event, "fulfillment_offer");
        issuer
            .apply(&authorization(
                &world,
                FulfillmentSide::Issuer,
                &t,
                Some(&offer),
            ))
            .unwrap();
        let node = issuer.node_id.clone();
        issuer.apply(&revocation(&world, &t, &node)).unwrap();
        assert!(
            issuer
                .state
                .fulfillment_event(&issuer.identity, ID)
                .is_err()
        );
    }

    #[test]
    fn p10_b09_epoch_advance_drops_older_fulfillments() {
        let world = World::new(53);
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        recipient.apply(&f.delivery).unwrap();
        assert_eq!(recipient.state.fulfillments.len(), 1);
        // A newer-epoch time reply advances the pin; older authority is retired and
        // the unread credential goes with it.
        recipient.advance_epoch(&world, 2);
        assert_eq!(recipient.state.fulfillments.len(), 0);
        assert!(!recipient.has());
    }

    #[test]
    fn p10_b10_capacity_is_bounded_without_evicting_existing_state() {
        let world = World::new(54);
        let mut issuer = Node::new(&world, "issuer", true, false);
        let recipient = Node::new(&world, "recipient", false, true);
        issuer.provision(SECRET);
        let mut accepted = 0;
        for index in 0..20_u32 {
            let id = format!("ful_cap{index:018}");
            let t = terms(&world, &issuer, &recipient, &id);
            let offer = FulfillmentOffer {
                fulfillment_id: id.clone(),
                terms_digest: t.digest_hex().unwrap(),
                offer_id: format!("fo_cap{index:018}"),
                node_id: recipient.node_id.clone(),
                node_key_version: recipient.identity.key_version().unwrap(),
                recipient_public: base64_url_encode(
                    RecipientKeyPair::generate().unwrap().public_key(),
                ),
                issued_at_ms: world.now_ms,
                expires_at_ms: world.now_ms + 120_000,
            };
            let envelope = recipient.identity.sign_fulfillment_offer(&offer).unwrap();
            let outcome = issuer
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Issuer,
                    &t,
                    Some(&envelope),
                ))
                .unwrap();
            if outcome == "fulfillment_authorization" {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 16);
        assert_eq!(issuer.state.fulfillments.len(), 16);
        assert_eq!(
            issuer
                .failure_codes()
                .iter()
                .filter(|code| *code == "capacity")
                .count(),
            4
        );
    }

    #[test]
    fn p10_b11_events_are_idempotent_persistent_and_leave_on_ack() {
        let world = World::new(55);
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        // A repeated request returns identical signed bytes.
        let first = recipient
            .state
            .fulfillment_event(&recipient.identity, ID)
            .unwrap();
        let second = recipient
            .state
            .fulfillment_event(&recipient.identity, ID)
            .unwrap();
        assert_eq!(first, second);
        let (offer_key, _) = open_event(&recipient, &first, "fulfillment_offer");
        let digest = sha256(ID.as_bytes()).unwrap();
        let expected: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(offer_key, format!("fo_{expected}"));
        let again = issuer
            .state
            .fulfillment_event(&issuer.identity, ID)
            .unwrap();
        assert_eq!(
            open_event(&issuer, &again, "fulfillment_submit").0,
            format!("fs_{expected}")
        );
        // A result event survives a restart from the durable queue until acknowledged.
        recipient.apply(&f.delivery).unwrap();
        let results = recipient.state.pending_node_events(100);
        let stored_key = results
            .iter()
            .find(|e| e.kind == "fulfillment_result")
            .unwrap()
            .idempotency_key
            .clone();
        assert!(stored_key.starts_with("fr_") && stored_key.len() == 67);
        let mut reloaded = BrokerState::new(DeliveryPolicy::default());
        reloaded
            .configure_grant_storage(&recipient.identity)
            .unwrap();
        assert!(
            reloaded
                .pending_node_events(100)
                .iter()
                .any(|e| e.idempotency_key == stored_key)
        );
        recipient
            .state
            .acknowledge_node_events(&recipient.node_id, std::slice::from_ref(&stored_key))
            .unwrap();
        assert!(
            !recipient
                .state
                .pending_node_events(100)
                .iter()
                .any(|e| e.idempotency_key == stored_key)
        );
    }

    #[test]
    fn p10_b12_secrets_do_not_appear_in_errors_or_debug_output() {
        let world = World::new(56);
        let (mut issuer, mut recipient) = pair(&world);
        let f = flow(&world, &mut issuer, &mut recipient, ID);
        recipient.apply(&f.delivery).unwrap();
        let rendered = format!(
            "{:?}{:?}",
            issuer.state.fulfillments, recipient.state.fulfillments
        );
        assert!(!rendered.contains("DUMMY-P10"));
        let error = recipient
            .state
            .fulfillment_event(&recipient.identity, "ful_unknownunknownunknown")
            .unwrap_err();
        assert!(!format!("{error:?}").contains("DUMMY-P10"));
    }

    #[test]
    fn p10_b13_a_rotation_replaces_the_credential_and_reports_its_own_read() {
        let world = World::new(58);
        let (mut issuer, mut recipient) = pair(&world);
        let first = flow(&world, &mut issuer, &mut recipient, ID);
        recipient.apply(&first.delivery).unwrap();
        assert_eq!(recipient.read().as_deref(), Some(SECRET));
        // The issuer's source changes; a rotation names the fulfillment it replaces.
        let rotated: &[u8] = b"DUMMY-P10-ROTATED-CREDENTIAL-0123";
        issuer.provision(rotated);
        let rotation_id = "ful_dddddddddddddddddddddd";
        let second = flow_replacing(&world, &mut issuer, &mut recipient, rotation_id, Some(ID));
        // Until the rotation is delivered the unit still reads the old credential,
        // and that read belongs to the first fulfillment only.
        assert_eq!(recipient.read().as_deref(), Some(SECRET));
        let consumed = |node: &Node| -> Vec<String> {
            node.result_events()
                .into_iter()
                .filter(|result| result.state == ResultState::Consumed)
                .map(|result| result.fulfillment_id)
                .collect()
        };
        assert_eq!(consumed(&recipient), vec![ID.to_owned()]);
        assert_eq!(
            recipient.apply(&second.delivery).unwrap(),
            "fulfillment_delivery"
        );
        assert_eq!(recipient.read().as_deref(), Some(rotated));
        assert_eq!(
            consumed(&recipient),
            vec![ID.to_owned(), rotation_id.to_owned()]
        );
        // The replaced fulfillment no longer owns the destination.
        let mut stale = terms(&world, &issuer, &recipient, "ful_aaaaaaaaaaaaaaaaaaaaaa");
        stale.prior_fulfillment_id = Some(ID.to_owned());
        assert_eq!(
            recipient
                .apply(&authorization(
                    &world,
                    FulfillmentSide::Recipient,
                    &stale,
                    None
                ))
                .unwrap(),
            "fulfillment_discarded_rejected"
        );
    }
}
