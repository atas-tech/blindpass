// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded retention of operation owners. Owners and closures are bounded at
//! `MAX_OPERATION_RECORDS`; without reclamation a broker stops admitting
//! requests after that many lifetime requests. Only owners that are provably
//! finished are ever evicted.
//!
//! An owner is TERMINAL only when ALL of the following hold:
//!
//! 1. It is not a pre-admission withdrawal. Those records are the only barrier
//!    against a late request that reuses the withdrawn retry key.
//! 2. A closure is recorded for its key: a controller-signed closure or the
//!    locally verified completion of a browser session. Native-mode and
//!    untyped owners carry no grant correlation (their grants bind no request
//!    event key), so the grant ledger cannot prove their end; the signed
//!    closure is the only evidence and without it they are never evicted.
//! 3. Any requested cancellation was acknowledged by the controller, so the
//!    durable relay of the cancellation no longer needs the owner.
//! 4. No runtime authority remains: no retained original kernel peer lease
//!    and no ready browser context.
//! 5. No unfinished protected session-journal record correlates to the key
//!    (`browser_unresolved_requests`, refreshed by the coordinator).
//! 6. No queued node event still refers to the key (the request event itself
//!    or a cancellation).
//!
//! Evicting is fail safe for every later use: status reports `unknown`,
//! cancellation reports an unknown operation and a late grant for the key is
//! refused because every browser authorization requires the owner. The only
//! behavioural difference is that a retry that reuses the request key of an
//! evicted terminal operation is admitted as a new request.

use crate::{BrokerError, BrokerState, MAX_OPERATION_RECORDS};
use blindpass_core::canon::{MAX_CANONICAL_JSON_BYTES, Value};
use std::collections::HashSet;

/// Owners evicted per scan step. A batch amortises the snapshot rewrite while
/// keeping the retry-key memory window large.
pub(crate) const EVICTION_BATCH: usize = 64;
/// The periodic tick starts reclaiming at this occupancy so that admission
/// rarely pays for the rewrite.
const HIGH_WATER: usize = MAX_OPERATION_RECORDS - MAX_OPERATION_RECORDS / 10;
const TICK_BATCH: usize = 256;
/// The durable header is canonical JSON bounded at `MAX_CANONICAL_JSON_BYTES`
/// (1 MiB), which a table of realistic browser owners reaches long before
/// `MAX_OPERATION_RECORDS`. Admission must therefore also keep the projected
/// header below that bound: room for one more owner at maximum field sizes,
/// plus a reserve for the closure every unclosed owner will eventually get.
const NEW_OWNER_RESERVE: usize = 2_560;
const CLOSURE_RESERVE: usize = 96;
/// Below this many owners the header cannot approach its bound.
const SIZE_CHECK_FLOOR: usize = 256;

/// Canonical object framing around the record arrays and flags.
const HEADER_FIXED_BYTES: usize = 192;
/// Identifier-like fields are validated to an alphabet that needs no escaping.
fn plain(value: &str) -> usize {
    2 + value.len()
}
/// Upper bound of one owner's canonical JSON plus its array separator: seven
/// keys with punctuation (133 with the three quoted values) and the values.
fn owner_record_bound(key: &str, owner: &crate::OperationRequestOwner) -> usize {
    let mode = if owner.mode.is_some() { 17 } else { 4 };
    let binding = owner.browser_request.as_ref().map_or(4, |binding| {
        // Six keys with punctuation (87) and two digests (66 each, or null).
        87 + binding.fingerprint.as_ref().map_or(4, |_| 66)
            + binding.recipe_fingerprint.as_ref().map_or(4, |_| 66)
            + plain(&binding.node_id)
            + binding.request_key.as_ref().map_or(4, |value| plain(value))
            + binding.resource_id.as_ref().map_or(4, |value| plain(value))
            // The unit may hold any graphic character; escaping can double it.
            + 2 + binding.unit.len() * 2
    });
    133 + key.len() + owner.invocation_id.len() + owner.workload_id.len() + mode + binding
}
fn closure_record_bound(key: &str, status: &str) -> usize {
    29 + key.len() + status.len()
}

impl BrokerState {
    /// Make room for one more owner, evicting the oldest terminal ones when
    /// the table is full by count or by projected durable size. Refuses
    /// (`operation_record_capacity`) only when every owner is non-terminal; a
    /// failed durable write restores the tables and is returned as is.
    pub(crate) fn ensure_operation_owner_capacity(&mut self) -> Result<(), BrokerError> {
        if !self.operation_table_full() {
            return Ok(());
        }
        let previous_owners = self.operation_requests.clone();
        let previous_closures = self.operation_closures.clone();
        let queued = self.queued_event_references();
        let candidates = self
            .operation_requests
            .order
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut cursor = 0;
        let mut evicted = 0;
        while self.operation_table_full() {
            let mut batch = Vec::new();
            while cursor < candidates.len() && batch.len() < EVICTION_BATCH {
                let key = &candidates[cursor];
                cursor += 1;
                if self.owner_is_terminal(key, &queued) {
                    batch.push(key.clone());
                }
            }
            if batch.is_empty() {
                break;
            }
            for key in &batch {
                self.operation_requests.remove(key);
                self.operation_closures.remove(key);
            }
            evicted += batch.len();
        }
        if evicted == 0 {
            return Err(BrokerError::Configuration("operation_record_capacity"));
        }
        if let Err(error) = self.persist_pending_node_events() {
            self.operation_requests = previous_owners;
            self.operation_closures = previous_closures;
            return Err(error);
        }
        if self.operation_table_full() {
            Err(BrokerError::Configuration("operation_record_capacity"))
        } else {
            Ok(())
        }
    }

    /// Opportunistic reclamation from the coordinator tick, so that admission
    /// rarely finds the table full.
    pub(crate) fn prune_crowded_owners(&mut self) -> Result<usize, BrokerError> {
        let owners = self.operation_requests.values.len();
        if owners < HIGH_WATER
            && (owners < SIZE_CHECK_FLOOR
                || self.projected_header_bytes() < MAX_CANONICAL_JSON_BYTES / 4 * 3)
        {
            return Ok(0);
        }
        self.evict_terminal_owners(TICK_BATCH)
    }

    /// Remove up to `limit` of the OLDEST terminal owners together with their
    /// closures and make the result durable through the outbox snapshot. A
    /// failed write restores both tables (the broker stays fenced by the
    /// failed write until it is retried) so memory never gets ahead of disk.
    pub(crate) fn evict_terminal_owners(&mut self, limit: usize) -> Result<usize, BrokerError> {
        if limit == 0 {
            return Ok(0);
        }
        let queued = self.queued_event_references();
        let victims = self
            .operation_requests
            .order
            .iter()
            .filter(|key| self.owner_is_terminal(key, &queued))
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        if victims.is_empty() {
            return Ok(0);
        }
        let previous_owners = self.operation_requests.clone();
        let previous_closures = self.operation_closures.clone();
        for key in &victims {
            self.operation_requests.remove(key);
            self.operation_closures.remove(key);
        }
        if let Err(error) = self.persist_pending_node_events() {
            self.operation_requests = previous_owners;
            self.operation_closures = previous_closures;
            return Err(error);
        }
        Ok(victims.len())
    }

    fn operation_table_full(&self) -> bool {
        let owners = self.operation_requests.values.len();
        owners >= MAX_OPERATION_RECORDS
            || owners >= SIZE_CHECK_FLOOR
                && self
                    .projected_header_bytes()
                    .saturating_add(NEW_OWNER_RESERVE)
                    > MAX_CANONICAL_JSON_BYTES
    }

    /// Upper bound of the canonical size of the durable header the writer
    /// would produce now, plus the closure growth already implied by unclosed
    /// owners. Computed arithmetically (no allocation) because admission asks
    /// on every request; `header_estimate_is_a_tight_upper_bound` checks it
    /// against the real canonical encoding.
    fn projected_header_bytes(&self) -> usize {
        let owners = self
            .operation_requests
            .values
            .iter()
            .map(|(key, owner)| owner_record_bound(key, owner))
            .sum::<usize>();
        let closures = self
            .operation_closures
            .values
            .iter()
            .map(|(key, status)| closure_record_bound(key, status))
            .sum::<usize>();
        let unclosed = self
            .operation_requests
            .values
            .len()
            .saturating_sub(self.operation_closures.values.len());
        HEADER_FIXED_BYTES
            .saturating_add(owners)
            .saturating_add(closures)
            .saturating_add(unclosed.saturating_mul(CLOSURE_RESERVE))
    }

    /// See the module documentation for the exact definition.
    #[cfg(test)]
    pub(crate) fn operation_owner_is_terminal(&self, key: &str) -> bool {
        self.owner_is_terminal(key, &self.queued_event_references())
    }

    /// Keys named by queued node events: the request event itself and any
    /// cancellation. Computed once per scan so a scan stays linear.
    fn queued_event_references(&self) -> HashSet<String> {
        let mut keys = HashSet::new();
        for event in &self.pending_node_events {
            keys.insert(event.idempotency_key.clone());
            if let Some(key) = event.body.get("request_event_key").and_then(Value::as_str) {
                keys.insert(key.to_owned());
            }
        }
        keys
    }

    fn owner_is_terminal(&self, key: &str, queued: &HashSet<String>) -> bool {
        let Some(owner) = self.operation_requests.get(key) else {
            return false;
        };
        // 1. A withdrawal before admission is the only barrier against a late
        // request that reuses the retry key.
        if owner
            .browser_request
            .as_ref()
            .is_some_and(|binding| binding.before_admission())
        {
            return false;
        }
        // 2. Closure evidence.
        if self.operation_closures.get(key).is_none() {
            return false;
        }
        // 3. A requested cancellation was acknowledged by the controller.
        if owner.cancel_requested && !owner.cancel_acknowledged {
            return false;
        }
        // 4. No runtime authority remains.
        if self.original_workload_leases.contains_key(key) || self.browser_ready.contains_key(key) {
            return false;
        }
        // 5. No unfinished protected journal record.
        if self.browser_unresolved_requests.contains(key) {
            return false;
        }
        // 6. Nothing queued still refers to it.
        !queued.contains(key)
    }

    /// Local closure status for a browser session whose cleanup is confirmed.
    /// A session the controller revoked (grant tombstone, or a revoked node)
    /// ended by revocation and is never reported as `completed`. Clients and
    /// the durable snapshot accept only rejected/expired/cancelled/denied/
    /// completed, so the revocation is recorded as `cancelled`. A signed
    /// closure already recorded for the request is never replaced by this.
    pub(crate) fn browser_closure_status(&self, grant_id: &str) -> &'static str {
        if self.node_revoked || self.grant_verifier.has_tombstone(grant_id) {
            "cancelled"
        } else {
            "completed"
        }
    }

    /// Refresh the view of unfinished journal records, from the same critical
    /// section that reserves or closes them.
    pub(crate) fn sync_browser_unresolved_requests(
        &mut self,
        journal: &crate::session_journal::SessionJournal,
    ) {
        self.browser_unresolved_requests = journal.unresolved_request_keys();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoundedRecords;
    use blindpass_core::canon::canonicalize_value;
    use blindpass_core::identity::{PeerIdentity, WorkloadRequest};
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn key(index: usize) -> String {
        format!("event_retention_{index:08}")
    }
    /// An owner that satisfies every terminal condition: closed, nothing live.
    fn terminal(state: &mut BrokerState, index: usize) -> String {
        let key = key(index);
        state.remember_operation_request(&key, "workload-a", &"a".repeat(32));
        state.record_operation_closure(&key, "expired");
        key
    }
    fn fill_terminal(state: &mut BrokerState, count: usize) {
        for index in 0..count {
            terminal(state, index);
        }
    }
    fn request_peer(grant: &blindpass_core::fleet::Grant) -> (PeerIdentity, WorkloadRequest) {
        (
            PeerIdentity::fixture(
                1001,
                1001,
                "agent.service",
                &grant.invocation_id,
                "uid:1001",
            ),
            WorkloadRequest {
                node_id: grant.node_id.clone(),
                workload_id: grant.workload_id.clone(),
                claimed_unit: grant.unit.clone(),
                claimed_invocation_id: grant.invocation_id.clone(),
                operation: String::new(),
            },
        )
    }
    fn browser_request(purpose: &str, retry: Option<&str>) -> String {
        let mut fields = vec![
            ("action".into(), Value::String("browser.session".into())),
            ("mode".into(), Value::String("browser_session".into())),
            ("purpose".into(), Value::String(purpose.into())),
            ("resource_id".into(), Value::String("report-primary".into())),
            ("ttl_seconds".into(), Value::Unsigned(60)),
        ];
        if let Some(retry) = retry {
            fields.push(("request_key".into(), Value::String(retry.into())));
        }
        format!(
            "request:{}",
            blindpass_core::signing::base64_url_encode(
                &blindpass_core::canon::canonicalize_value(&Value::Object(fields)).unwrap()
            )
        )
    }
    fn reply_key(reply: Vec<u8>) -> String {
        std::str::from_utf8(&reply)
            .unwrap()
            .strip_prefix("OK operation_request ")
            .unwrap()
            .trim()
            .to_owned()
    }

    /// Owners the size of real browser requests: generated event keys and a
    /// full binding, copied from the fixture's live owner.
    fn realistic_owner(
        state: &mut BrokerState,
        template: &crate::OperationRequestOwner,
        index: usize,
        closed: bool,
    ) -> String {
        let key = format!("event_{index:043}");
        state.operation_requests.insert(&key, template.clone());
        if closed {
            state.record_operation_closure(&key, "expired");
        }
        key
    }
    fn fill_realistic(
        state: &mut BrokerState,
        template: &crate::OperationRequestOwner,
        closed: bool,
    ) -> usize {
        // The size projection is linear, so test in chunks.
        let mut count = 0;
        while !state.operation_table_full() {
            for _ in 0..32 {
                realistic_owner(state, template, count, closed);
                count += 1;
            }
            assert!(count < MAX_OPERATION_RECORDS, "size bound never reached");
        }
        count
    }

    #[test]
    fn durable_size_bound_is_reached_before_the_count_bound_and_reclaims_terminal_owners() {
        let (directory, mut state, grant, _, _) =
            crate::tests::browser_grant_fixture("retention-size");
        let live = grant.request_event_key.clone().unwrap();
        let template = state.operation_requests.get(&live).cloned().unwrap();
        let count = fill_realistic(&mut state, &template, true);
        // Real owners hit the 1 MiB header bound well before 10 000 records;
        // the last admitted table must still be writable.
        assert!(
            count < MAX_OPERATION_RECORDS / 2,
            "{count} realistic owners fit"
        );
        assert!(state.operation_requests.len() < MAX_OPERATION_RECORDS);
        state.persist_pending_node_events().unwrap();
        // Admission now evicts finished owners instead of failing the write.
        let (peer, mut request) = request_peer(&grant);
        request.operation = browser_request("read report", None);
        let created = reply_key(state.process_workload(&peer, &request).unwrap());
        assert!(!state.persistence_fenced());
        assert!(state.operation_requests.get(&created).is_some());
        assert!(state.operation_requests.get(&live).is_some());
        // Oldest first: the earliest owners went, in whole batches, and the
        // newest finished owner is still there; only as many as needed went.
        let evicted = (count + 1) - (state.operation_requests.len() - 1);
        assert!(
            (EVICTION_BATCH..=4 * EVICTION_BATCH).contains(&evicted),
            "{evicted}"
        );
        assert!(
            state
                .operation_requests
                .get(&format!("event_{:043}", 0))
                .is_none()
        );
        assert!(
            state
                .operation_closures
                .get(&format!("event_{:043}", 0))
                .is_none()
        );
        assert!(
            state
                .operation_requests
                .get(&format!("event_{:043}", evicted - 1))
                .is_none()
        );
        assert!(
            state
                .operation_requests
                .get(&format!("event_{:043}", evicted))
                .is_some()
        );
        assert!(
            state
                .operation_closures
                .get(&format!("event_{:043}", evicted))
                .is_some()
        );
        assert!(
            state
                .operation_requests
                .get(&format!("event_{:043}", count - 1))
                .is_some()
        );
        // The snapshot on disk reads back and matches memory.
        let path = state.pending_node_events_path.clone().unwrap();
        let (_events, _, _, owners, closures) = crate::read_pending_node_events(&path).unwrap();
        assert_eq!(owners.len(), state.operation_requests.len());
        assert_eq!(closures.len(), state.operation_closures.len());
        assert!(owners.get(&created).is_some() && owners.get(&live).is_some());
        // Lifetime requests keep being admitted across a second reclamation.
        for round in 0..(EVICTION_BATCH + 8) {
            request.operation = browser_request(&format!("report {round}"), None);
            let key = reply_key(state.process_workload(&peer, &request).unwrap());
            state.record_operation_closure(&key, "expired");
            state.original_workload_leases.remove(&key);
        }
        assert!(!state.persistence_fenced());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn durable_size_bound_with_unfinished_owners_refuses_admission_without_side_effects() {
        let (directory, mut state, grant, _, _) =
            crate::tests::browser_grant_fixture("retention-size-refused");
        let live = grant.request_event_key.clone().unwrap();
        let template = state.operation_requests.get(&live).cloned().unwrap();
        fill_realistic(&mut state, &template, false);
        state.persist_pending_node_events().unwrap();
        let owners = state.operation_requests.len();
        let events = state.pending_node_events.len();
        let (peer, mut request) = request_peer(&grant);
        request.operation = browser_request("read report", None);
        assert!(matches!(
            state.process_workload(&peer, &request),
            Err(BrokerError::Configuration("operation_record_capacity"))
        ));
        assert_eq!(state.operation_requests.len(), owners);
        assert_eq!(state.pending_node_events.len(), events);
        assert!(!state.persistence_fenced());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn withdrawal_by_retry_key_also_reclaims_terminal_owners() {
        let (directory, mut state, grant, _, _) =
            crate::tests::browser_grant_fixture("retention-withdrawal");
        let live = grant.request_event_key.clone().unwrap();
        let template = state.operation_requests.get(&live).cloned().unwrap();
        let count = fill_realistic(&mut state, &template, true);
        state.persist_pending_node_events().unwrap();
        let (peer, mut request) = request_peer(&grant);
        request.operation = "cancel-key:retry_0123456789abcdef".into();
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_cancel requested\n"
        );
        assert!(state.operation_requests.len() < count + 1);
        assert!(
            state
                .operation_requests
                .get(&format!("event_{:043}", 0))
                .is_none()
        );
        assert!(!state.persistence_fenced());
        // The withdrawal itself is durable and never reclaimable.
        let path = state.pending_node_events_path.clone().unwrap();
        let (_events, _, _, owners, _) = crate::read_pending_node_events(&path).unwrap();
        assert_eq!(owners.len(), state.operation_requests.len());
        let withdrawal = owners
            .values
            .values()
            .find(|owner| {
                owner
                    .browser_request
                    .as_ref()
                    .is_some_and(|binding| binding.before_admission())
            })
            .expect("withdrawal record persisted");
        assert!(withdrawal.cancel_requested);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn owners_that_are_not_provably_finished_are_never_evicted() {
        let (directory, mut state, grant, _, _) =
            crate::tests::browser_grant_fixture("retention-live");
        let live = grant.request_event_key.clone().unwrap();
        state.operation_requests = BoundedRecords::new(MAX_OPERATION_RECORDS);
        state.operation_closures = BoundedRecords::new(MAX_OPERATION_RECORDS);
        // Every protected owner has a closure so only the named reason protects it.
        let owner = |state: &mut BrokerState, index: usize| {
            let key = terminal(state, index);
            assert!(state.operation_owner_is_terminal(&key));
            key
        };
        // (1) retained original process lease
        let leased = owner(&mut state, 0);
        let lease = state.original_workload_leases.get(&live).cloned().unwrap();
        state.original_workload_leases.insert(leased.clone(), lease);
        // (2) ready browser context
        let ready = owner(&mut state, 1);
        state.browser_ready.insert(
            ready.clone(),
            crate::browser_coordinator::BrowserReadyMetadata {
                grant: grant.clone(),
                context: "ctx_fixture".into(),
                deadline: u64::MAX,
                alive: Arc::new(AtomicBool::new(true)),
                journal_alive: Arc::new(AtomicBool::new(true)),
            },
        );
        // (3) unresolved protected journal record
        let unresolved = owner(&mut state, 2);
        state.browser_unresolved_requests.insert(unresolved.clone());
        // (4) cancellation not yet acknowledged
        let cancelling = owner(&mut state, 3);
        let entry = state
            .operation_requests
            .values
            .get_mut(&cancelling)
            .unwrap();
        entry.mode = Some(blindpass_core::fleet::ConsumptionMode::BrowserSession);
        entry.cancel_requested = true;
        entry.cancel_acknowledged = false;
        // (5) no closure recorded at all
        let open = key(4);
        state.remember_operation_request(&open, "workload-a", &"a".repeat(32));
        // (6) request event still queued for relay
        let queued = owner(&mut state, 5);
        state
            .pending_node_events
            .push_back(crate::PendingNodeEvent {
                idempotency_key: queued.clone(),
                kind: "operation_request".into(),
                body: Value::Object(vec![]),
            });
        // (7) a queued cancellation naming the key
        let relayed = owner(&mut state, 6);
        let cancellation = blindpass_core::fleet::OperationCancellation {
            node_id: "node-a".into(),
            workload_id: "workload-a".into(),
            invocation_id: "a".repeat(32),
            request_event_key: relayed.clone(),
        };
        state
            .pending_node_events
            .push_back(crate::PendingNodeEvent {
                idempotency_key: cancellation.event_key().unwrap(),
                kind: "operation_cancel".into(),
                body: cancellation.to_value().unwrap(),
            });
        // (8) a pre-admission withdrawal never expires, even with a closure
        let withdrawn = owner(&mut state, 7);
        let (peer, _) = request_peer(&grant);
        let authorization = blindpass_core::identity::authorize_workload(
            &peer,
            &WorkloadRequest {
                node_id: grant.node_id.clone(),
                workload_id: grant.workload_id.clone(),
                claimed_unit: grant.unit.clone(),
                claimed_invocation_id: grant.invocation_id.clone(),
                operation: "status:x".into(),
            },
            &state.workloads,
        )
        .unwrap();
        let entry = state.operation_requests.values.get_mut(&withdrawn).unwrap();
        entry.mode = Some(blindpass_core::fleet::ConsumptionMode::BrowserSession);
        entry.cancel_requested = true;
        entry.browser_request = Some(crate::operation_request::BrowserRequestBinding::withdrawal(
            &authorization,
            "retry_0123456789abcdef",
        ));
        for protected in [
            &leased,
            &ready,
            &unresolved,
            &cancelling,
            &open,
            &queued,
            &relayed,
            &withdrawn,
        ] {
            assert!(
                !state.operation_owner_is_terminal(protected),
                "{protected} must be protected"
            );
        }
        // Finished owners placed after them are the only ones evicted.
        for index in 8..40 {
            terminal(&mut state, index);
        }
        let before = state.operation_requests.len();
        assert_eq!(state.evict_terminal_owners(1_000).unwrap(), 32);
        assert_eq!(state.operation_requests.len(), before - 32);
        for protected in [
            &leased,
            &ready,
            &unresolved,
            &cancelling,
            &open,
            &queued,
            &relayed,
            &withdrawn,
        ] {
            assert!(
                state.operation_requests.get(protected).is_some(),
                "{protected} survived eviction"
            );
        }
        assert_eq!(state.evict_terminal_owners(1_000).unwrap(), 0);
        // Acknowledging the cancellation and clearing the other reasons makes
        // each of them terminal in turn.
        state
            .operation_requests
            .values
            .get_mut(&cancelling)
            .unwrap()
            .cancel_acknowledged = true;
        assert!(state.operation_owner_is_terminal(&cancelling));
        state.browser_unresolved_requests.clear();
        assert!(state.operation_owner_is_terminal(&unresolved));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn full_table_of_unfinished_owners_still_refuses_admission_without_side_effects() {
        let (directory, mut state, grant, _, _) =
            crate::tests::browser_grant_fixture("retention-refused");
        state.pending_node_events_path = None;
        state.operation_requests = BoundedRecords::new(MAX_OPERATION_RECORDS);
        for index in 0..MAX_OPERATION_RECORDS {
            state.remember_operation_request(&key(index), "workload-a", &"a".repeat(32));
        }
        let events = state.pending_node_events.len();
        let (peer, mut request) = request_peer(&grant);
        request.operation = browser_request("read report", None);
        let error = state.process_workload(&peer, &request).unwrap_err();
        assert!(matches!(
            error,
            BrokerError::Configuration("operation_record_capacity")
        ));
        assert_eq!(state.operation_requests.len(), MAX_OPERATION_RECORDS);
        assert_eq!(state.pending_node_events.len(), events);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn status_cancel_and_late_grant_for_an_evicted_owner_fail_safe() {
        let (directory, mut state, grant, resource, mut journal) =
            crate::tests::browser_grant_fixture("retention-evicted");
        let live = grant.request_event_key.clone().unwrap();
        // The operation completed: closure recorded, lease and journal gone.
        state.record_operation_closure(&live, "completed");
        assert!(state.original_workload_leases.is_empty());
        assert!(state.operation_owner_is_terminal(&live));
        assert_eq!(state.evict_terminal_owners(10).unwrap(), 1);
        assert!(state.operation_requests.get(&live).is_none());
        assert!(state.operation_closures.get(&live).is_none());
        let (peer, mut request) = request_peer(&grant);
        request.operation = format!("status:{live}");
        assert_eq!(
            state.process_workload(&peer, &request).unwrap(),
            b"OK operation_status unknown\n"
        );
        request.operation = format!("cancel:{live}");
        assert!(matches!(
            state.process_workload(&peer, &request).unwrap_err(),
            BrokerError::Configuration("operation_cancel_unknown")
        ));
        // A late signed grant for the evicted key cannot start a login.
        request.operation = format!("consume:{}", grant.id);
        assert!(state.browser_dispatch_candidates().is_empty());
        let result = state.prepare_browser_login(&peer, &request, &resource, &mut journal);
        assert!(matches!(
            result,
            Err(BrokerError::Configuration(
                "browser_request_binding_unavailable"
            ))
        ));
        assert!(journal.pending().is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_snapshot_restores_owners_and_closures_and_keeps_the_fence() {
        let (directory, mut state, _, _, _) =
            crate::tests::browser_grant_fixture("retention-persist-failure");
        fill_terminal(&mut state, 100);
        let path = state.pending_node_events_path.clone().unwrap();
        state.persist_pending_node_events().unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let owners = state.operation_requests.len();
        let closures = state.operation_closures.len();
        assert!(state.evict_terminal_owners(10).is_err());
        assert_eq!(state.operation_requests.len(), owners);
        assert_eq!(state.operation_closures.len(), closures);
        assert!(state.operation_requests.get(&key(0)).is_some());
        assert!(state.persistence_fenced());
        fs::remove_dir(&path).unwrap();
        state.persist_pending_node_events().unwrap();
        assert!(!state.persistence_fenced());
        assert_eq!(state.evict_terminal_owners(10).unwrap(), 10);
        let (_events, _, _, restored, restored_closures) =
            crate::read_pending_node_events(&path).unwrap();
        assert_eq!(restored.len(), owners - 10);
        assert_eq!(restored_closures.len(), closures - 10);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn lifetime_requests_beyond_the_bound_keep_being_admitted_when_owners_finish() {
        let mut state = BrokerState::new(blindpass_core::delivery::DeliveryPolicy::default());
        for index in 0..MAX_OPERATION_RECORDS + 1_000 {
            state
                .ensure_operation_owner_capacity()
                .unwrap_or_else(|_| panic!("request {index} was refused"));
            terminal(&mut state, index);
        }
        assert!(state.operation_requests.len() <= MAX_OPERATION_RECORDS);
        assert!(state.operation_closures.len() <= MAX_OPERATION_RECORDS);
        assert!(
            state
                .operation_requests
                .get(&key(MAX_OPERATION_RECORDS + 999))
                .is_some()
        );
        assert!(state.operation_requests.get(&key(0)).is_none());
    }

    #[test]
    fn periodic_reclamation_waits_for_occupancy_and_evicts_only_finished_owners() {
        let (directory, mut state, grant, _, _) =
            crate::tests::browser_grant_fixture("retention-tick");
        let live = grant.request_event_key.clone().unwrap();
        let template = state.operation_requests.get(&live).cloned().unwrap();
        state.pending_node_events_path = None;
        // Light occupancy: nothing to do.
        fill_terminal(&mut state, 100);
        assert_eq!(state.prune_crowded_owners().unwrap(), 0);
        // Grow with finished realistic owners to three quarters of the bound
        // but not to the point where admission would be refused.
        let mut index = 0;
        while state.projected_header_bytes() < MAX_CANONICAL_JSON_BYTES / 4 * 3 {
            for _ in 0..32 {
                realistic_owner(&mut state, &template, index, true);
                index += 1;
            }
        }
        assert!(!state.operation_table_full());
        let before = state.operation_requests.len();
        assert_eq!(state.prune_crowded_owners().unwrap(), TICK_BATCH);
        assert_eq!(state.operation_requests.len(), before - TICK_BATCH);
        // The same occupancy with unfinished owners evicts nothing.
        let mut crowded = BrokerState::new(blindpass_core::delivery::DeliveryPolicy::default());
        let mut index = 0;
        while crowded.projected_header_bytes() < MAX_CANONICAL_JSON_BYTES / 4 * 3 {
            for _ in 0..32 {
                realistic_owner(&mut crowded, &template, index, false);
                index += 1;
            }
        }
        assert_eq!(crowded.prune_crowded_owners().unwrap(), 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn coordinator_view_tracks_unfinished_journal_records() {
        let (directory, mut state, _, _, mut journal) =
            crate::tests::browser_grant_fixture("retention-view");
        let correlated = crate::session_journal::SessionBinding {
            node_id: "node-a".into(),
            workload_id: "workload-a".into(),
            operation_id: "operation-view".into(),
            idempotency_key: "retry-view".into(),
            request_event_key: Some("event_viewviewviewviewviewviewviewview".into()),
            workload_unit: "agent.service".into(),
            workload_invocation: "a".repeat(32),
            resource: "report-primary".into(),
            recipe_fingerprint: "a".repeat(64),
            account: "primary".into(),
        };
        journal.reserve(correlated, 1_000).unwrap();
        state.sync_browser_unresolved_requests(&journal);
        assert!(
            state
                .browser_unresolved_requests
                .contains("event_viewviewviewviewviewviewviewview")
        );
        journal
            .reconcile("operation-view", true, true, 1_001)
            .unwrap();
        state.sync_browser_unresolved_requests(&journal);
        assert!(state.browser_unresolved_requests.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn header_estimate_is_a_tight_upper_bound() {
        let (directory, mut state, grant, _, _) =
            crate::tests::browser_grant_fixture("retention-estimate");
        let live = grant.request_event_key.clone().unwrap();
        let template = state.operation_requests.get(&live).cloned().unwrap();
        state.operation_requests = BoundedRecords::new(MAX_OPERATION_RECORDS);
        state.operation_closures = BoundedRecords::new(MAX_OPERATION_RECORDS);
        for round in 0..3 {
            let before = state.projected_header_bytes();
            for index in 0..300 {
                let closed = index % 2 == 0;
                match round {
                    0 => {
                        terminal(&mut state, round * 1_000 + index);
                    }
                    1 => {
                        realistic_owner(&mut state, &template, round * 1_000 + index, closed);
                    }
                    _ => {
                        // Maximum-size fields: escapes in the unit and long keys.
                        let mut owner = template.clone();
                        owner.workload_id = "w".repeat(100);
                        let binding = owner.browser_request.as_mut().unwrap();
                        binding.unit = "u\"x\\".repeat(60);
                        binding.request_key = Some("k".repeat(128));
                        let key = format!("event_{}_{index}", "z".repeat(90));
                        state.operation_requests.insert(&key, owner);
                        if closed {
                            state.record_operation_closure(&key, "completed");
                        }
                    }
                }
            }
            assert!(state.projected_header_bytes() > before);
            let exact = canonicalize_value(&crate::pending_state_header(
                state.audit_overflow_pending,
                state.node_revocation_acknowledged,
                &state.operation_requests,
                &state.operation_closures,
            ))
            .unwrap()
            .len();
            let unclosed = state.operation_requests.len() - state.operation_closures.len();
            let estimate = state.projected_header_bytes() - unclosed * CLOSURE_RESERVE;
            assert!(estimate >= exact, "round {round}: {estimate} < {exact}");
            assert!(
                estimate <= exact + exact / 10 + 256,
                "round {round}: estimate {estimate} too loose for {exact}"
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
