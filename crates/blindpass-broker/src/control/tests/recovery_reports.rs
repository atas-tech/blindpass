// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use blindpass_core::recovery::pages::{
    PageAccumulator, ReportIdentity, ReportPage, ReportRequest, SignedReportRequest,
};
use blindpass_core::signing::base64_url_decode;

fn framed(response: &[u8], command: &str) -> Value {
    let end = response.iter().position(|byte| *byte == b'\n').unwrap();
    let header = std::str::from_utf8(&response[..end]).unwrap();
    let length: usize = header
        .strip_prefix(&format!("{command} "))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(response.len(), end + 1 + length);
    parse_json(std::str::from_utf8(&response[end + 1..]).unwrap()).unwrap()
}

fn request(fleet: &Fleet, generation: u64) -> ReportRequest {
    let challenge = framed(
        &control_exchange(&fleet.identity, &fleet.state, b"RECOVERY_CHALLENGE\n"),
        "RECOVERY_CHALLENGE",
    );
    let pin = fleet.identity.pinned_issuer().unwrap().unwrap();
    ReportRequest {
        identity: ReportIdentity {
            tenant_id: pin.tenant_id,
            node_id: pin.node_id,
            node_key_version: fleet.identity.key_version().unwrap(),
            issuer_key_id: pin.key_id,
            recovery_id: "recovery_dummy_control".into(),
            recovery_generation: generation,
            challenge: base64_url_encode(&[91; 32]),
        },
        broker_challenge: challenge
            .get("broker_challenge")
            .unwrap()
            .as_str()
            .unwrap()
            .into(),
        report_id: None,
        page_index: 0,
    }
}

fn exchange_value(fleet: &Fleet, body: Value) -> Vec<u8> {
    let body = canonicalize_value(&body).unwrap();
    let mut frame = format!("RECOVERY_REPORT {}\n", body.len()).into_bytes();
    frame.extend(body);
    control_exchange(&fleet.identity, &fleet.state, &frame)
}

fn exchange(fleet: &Fleet, request: ReportRequest) -> Vec<u8> {
    exchange_value(
        fleet,
        SignedReportRequest::sign(request, &fleet.issuer)
            .unwrap()
            .to_value()
            .unwrap(),
    )
}

fn verified_page(
    fleet: &Fleet,
    response: &[u8],
    expected: &ReportIdentity,
    accumulator: &mut PageAccumulator,
) -> ReportPage {
    let value = framed(response, "RECOVERY_REPORT");
    let page = ReportPage::from_value(value.get("body").unwrap()).unwrap();
    let public = base64_url_decode(
        &fleet.identity.public_identity().unwrap().signing_public,
        32,
    )
    .unwrap();
    let signature =
        base64_url_decode(value.get("broker_signature").unwrap().as_str().unwrap(), 64).unwrap();
    accumulator
        .push(page.verify(expected, 1, &public, &signature).unwrap())
        .unwrap();
    page
}

#[test]
fn p06_br05_control_export_reads_129_real_intents_and_fences_old_grants() {
    let fleet = Fleet::new(92);
    let mut expected = std::collections::BTreeMap::new();
    for index in 0..129 {
        let grant = fleet.grant(index, 1);
        assert_eq!(fleet.deliver(&grant), b"OK document_applied grant\n");
        assert!(fleet.consume(&grant.id).is_ok());
        assert!(fleet.marker_exists(&grant.id));
        expected.insert(grant.id, grant.operation_id);
    }
    let old = fleet.grant(200, 1);
    assert_eq!(fleet.deliver(&old), b"OK document_applied grant\n");
    let mut request = request(&fleet, 2);
    let first = exchange(&fleet, request.clone());
    assert_eq!(exchange(&fleet, request.clone()), first);
    assert_eq!(fleet.identity.pinned_issuer().unwrap().unwrap().epoch, 2);
    assert!(fleet.consume(&old.id).is_err());
    assert!(!fleet.marker_exists(&old.id));
    let mut accumulator = PageAccumulator::new();
    let page0 = verified_page(&fleet, &first, &request.identity, &mut accumulator);
    assert_eq!(page0.manifest.observed_issuer_epoch, 1);
    assert_eq!(page0.manifest.total_records, 129);
    assert_eq!(page0.records.len(), 128);
    assert!(page0.manifest.coverage.covers(fleet.now_ms));
    request.report_id = Some(page0.manifest.report_id.clone());
    request.page_index = 1;
    let second = exchange(&fleet, request.clone());
    let page1 = verified_page(&fleet, &second, &request.identity, &mut accumulator);
    assert!(accumulator.complete());
    assert_eq!(page1.records.len(), 1);
    for record in page0.records.iter().chain(&page1.records) {
        assert_eq!(record.operation_id.as_ref(), expected.get(&record.grant_id));
        assert_eq!(record.issuer_epoch, Some(1));
        assert_eq!(record.expires_at_ms, fleet.now_ms + 60_000);
    }
    assert!(std::fs::read_dir(&fleet.directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".recovery-history-")
    }));
}

#[test]
fn p06_br06_control_refuses_forgery_scope_version_nonce_and_caller_records() {
    let fleet = Fleet::new(93);
    let valid = request(&fleet, 2);
    for field in 0..5 {
        let mut wrong = valid.clone();
        match field {
            0 => wrong.identity.tenant_id = "tenant_wrong".into(),
            1 => wrong.identity.node_id = "node_wrong".into(),
            2 => wrong.identity.node_key_version += 1,
            3 => wrong.identity.issuer_key_id = "issuer_wrong".into(),
            _ => wrong.broker_challenge = base64_url_encode(&[99; 32]),
        }
        assert_eq!(exchange(&fleet, wrong), b"ERR recovery_report_denied\n");
        assert_eq!(fleet.identity.pinned_issuer().unwrap().unwrap().epoch, 1);
    }
    let forged = SignedReportRequest::sign(
        valid.clone(),
        &Ed25519KeyPair::from_seed(&[94; 32]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        exchange_value(&fleet, forged.to_value().unwrap()),
        b"ERR recovery_report_denied\n"
    );
    let mut injected = SignedReportRequest::sign(valid.clone(), &fleet.issuer)
        .unwrap()
        .to_value()
        .unwrap();
    if let Value::Object(fields) = &mut injected {
        fields.push(("records".into(), Value::Array(vec![])));
    }
    assert_eq!(
        exchange_value(&fleet, injected),
        b"ERR recovery_report_denied\n"
    );
    let response = exchange(&fleet, valid.clone());
    let mut accumulator = PageAccumulator::new();
    let page = verified_page(&fleet, &response, &valid.identity, &mut accumulator);
    assert!(accumulator.complete());
    assert_eq!(page.manifest.total_records, 0);
}

#[test]
fn p06_br07_control_snapshot_is_immutable_and_restart_cannot_recreate_receipt() {
    let mut fleet = Fleet::new(95);
    for index in 0..129 {
        let grant = fleet.grant(index, 1);
        assert_eq!(fleet.deliver(&grant), b"OK document_applied grant\n");
        fleet.consume(&grant.id).unwrap();
    }
    let mut request = request(&fleet, 2);
    let response = exchange(&fleet, request.clone());
    let mut accumulator = PageAccumulator::new();
    let first = verified_page(&fleet, &response, &request.identity, &mut accumulator);
    // Fixture-only issuer advances time and records another real intent. This
    // asserts immutable export, not production recovering-state permission.
    let snapshot_ms = fleet.now_ms;
    fleet.now_ms += 24 * 60 * 60 * 1_000 + 60_001;
    fleet.refresh_time(2);
    let new = fleet.grant(200, 2);
    assert_eq!(fleet.deliver(&new), b"OK document_applied grant\n");
    fleet.consume(&new.id).unwrap();
    request.report_id = Some(first.manifest.report_id.clone());
    request.page_index = 1;
    let second = verified_page(
        &fleet,
        &exchange(&fleet, request.clone()),
        &request.identity,
        &mut accumulator,
    );
    assert_eq!(second.manifest, first.manifest);
    assert!(accumulator.complete());
    assert!(
        second
            .records
            .iter()
            .all(|record| record.grant_id != new.id)
    );
    let mut restarted = BrokerState::new(DeliveryPolicy::default());
    restarted.configure_grant_storage(&fleet.identity).unwrap();
    fleet.state = std::sync::Arc::new(std::sync::Mutex::new(restarted));
    assert_eq!(exchange(&fleet, request), b"ERR recovery_report_denied\n");
    let fresh = super::recovery_reports::request(&fleet, 3);
    let mut accumulator = PageAccumulator::new();
    let page = verified_page(
        &fleet,
        &exchange(&fleet, fresh.clone()),
        &fresh.identity,
        &mut accumulator,
    );
    assert_eq!(page.manifest.observed_issuer_epoch, 2);
    assert_eq!(page.manifest.total_records, 1);
    assert_eq!(
        page.manifest.coverage.pruned_through_ms,
        snapshot_ms + 60_000
    );
    assert!(!page.manifest.coverage.covers(snapshot_ms));
    assert_eq!(page.records[0].grant_id, new.id);
}

#[test]
fn p06_br07_key_rotation_invalidates_cached_old_version_page() {
    let fleet = Fleet::new(96);
    let request = request(&fleet, 2);
    let response = exchange(&fleet, request.clone());
    assert!(response.starts_with(b"RECOVERY_REPORT "));
    let (to_key_version, candidate) = fleet.identity.prepare_rotation().unwrap();
    let rotation = NodeKeyRotation {
        node_id: "nd_node-a".into(),
        rotation_id: "rotation_dummy_recovery".into(),
        from_key_version: 1,
        to_key_version,
        signing_public: candidate.signing_public,
        recipient_public: candidate.recipient_public,
        fingerprint: candidate.fingerprint,
        issuer_epoch: 2,
    };
    assert_eq!(
        fleet.relay(&fleet.sign(
            DocumentKind::NodeKeyRotation,
            rotation.to_value().unwrap(),
            2
        )),
        b"OK document_applied node_key_rotation\n"
    );
    assert_eq!(exchange(&fleet, request), b"ERR recovery_report_denied\n");
}

#[test]
fn p06_br06_frozen_report_refuses_changed_recovery_context_and_new_challenge() {
    let fleet = Fleet::new(97);
    let original = request(&fleet, 2);
    let first = exchange(&fleet, original.clone());
    assert!(first.starts_with(b"RECOVERY_REPORT "));
    for field in 0..4 {
        let mut changed = original.clone();
        match field {
            0 => changed.identity.recovery_id = "recovery_other".into(),
            1 => changed.identity.challenge = base64_url_encode(&[90; 32]),
            2 => changed.identity.recovery_generation = 3,
            _ => changed.report_id = Some(base64_url_encode(&[89; 32])),
        }
        assert_eq!(exchange(&fleet, changed), b"ERR recovery_report_denied\n");
    }
    assert_eq!(exchange(&fleet, original.clone()), first);
    let fresh = request(&fleet, 3);
    assert_eq!(exchange(&fleet, original), b"ERR recovery_report_denied\n");
    assert!(exchange(&fleet, fresh).starts_with(b"RECOVERY_REPORT "));
}

#[test]
fn p06_br07_real_boottime_expiry_refuses_cached_page_and_stale_nonce() {
    let cached = Fleet::new(98);
    let request_cached = request(&cached, 2);
    assert!(exchange(&cached, request_cached.clone()).starts_with(b"RECOVERY_REPORT "));
    let pending = Fleet::new(99);
    let request_pending = request(&pending, 2);
    std::thread::sleep(Duration::from_millis(30_100));
    assert_eq!(
        exchange(&cached, request_cached),
        b"ERR recovery_report_denied\n"
    );
    assert_eq!(
        exchange(&pending, request_pending),
        b"ERR recovery_report_denied\n"
    );
    assert_eq!(pending.identity.pinned_issuer().unwrap().unwrap().epoch, 1);
    let fresh = request(&cached, 3);
    assert!(exchange(&cached, fresh).starts_with(b"RECOVERY_REPORT "));
}

#[test]
fn p06_br02_control_missing_history_stays_unknown_even_when_export_completes() {
    let mut fleet = Fleet::new(100);
    std::fs::remove_file(fleet.identity.consumed_grant_journal_path()).unwrap();
    let mut state = BrokerState::new(DeliveryPolicy::default());
    state.configure_grant_storage(&fleet.identity).unwrap();
    fleet.state = std::sync::Arc::new(std::sync::Mutex::new(state));
    let request = request(&fleet, 2);
    let mut accumulator = PageAccumulator::new();
    let page = verified_page(
        &fleet,
        &exchange(&fleet, request.clone()),
        &request.identity,
        &mut accumulator,
    );
    assert!(accumulator.complete());
    assert_eq!(page.manifest.coverage.history_id, None);
    assert!(!page.manifest.coverage.covers(fleet.now_ms));
}

#[test]
fn p06_br05_control_preserves_observation_above_proposed_generation() {
    let fleet = Fleet::new(101);
    let mut pin = fleet.identity.pinned_issuer().unwrap().unwrap();
    pin.epoch = 9;
    fleet.identity.pin_issuer(pin).unwrap();
    let request = request(&fleet, 8);
    let mut accumulator = PageAccumulator::new();
    let page = verified_page(
        &fleet,
        &exchange(&fleet, request.clone()),
        &request.identity,
        &mut accumulator,
    );
    assert!(accumulator.complete());
    assert_eq!(page.manifest.identity.recovery_generation, 8);
    assert_eq!(page.manifest.observed_issuer_epoch, 9);
    assert_eq!(fleet.identity.pinned_issuer().unwrap().unwrap().epoch, 9);
}
