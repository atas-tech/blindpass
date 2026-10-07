// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::canon::canonicalize_value;
use blindpass_core::recovery::pages::{
    HistoryCoverage, IntentRecord, PageAccumulator, PageDigest, ReportIdentity, ReportManifest,
    ReportPage, ReportRequest, SignedReportRequest,
};
use blindpass_core::signing::base64_url_encode;
use blindpass_core::signing::ed25519::Ed25519KeyPair;

fn fixture(count: usize, unmapped: bool) -> (ReportManifest, Vec<IntentRecord>) {
    let records: Vec<_> = (0..count)
        .map(|index| IntentRecord {
            grant_id: format!("grant_{index:08}"),
            expires_at_ms: 1_800_000_060_000,
            operation_id: (!unmapped).then(|| format!("operation_{index:08}")),
            issuer_epoch: (!unmapped).then_some(7),
        })
        .collect();
    let mut manifest = ReportManifest {
        identity: ReportIdentity {
            tenant_id: "tenant_dummy".into(),
            node_id: "node_dummy".into(),
            node_key_version: 2,
            issuer_key_id: "issuer_dummy".into(),
            recovery_id: "recovery_dummy".into(),
            recovery_generation: 8,
            challenge: base64_url_encode(&[11; 32]),
        },
        report_id: base64_url_encode(&[12; 32]),
        observed_issuer_epoch: 7,
        coverage: HistoryCoverage {
            history_id: (!unmapped).then(|| base64_url_encode(&[13; 32])),
            pruned_through_ms: 0,
            unmapped_records: if unmapped { count as u64 } else { 0 },
        },
        total_records: count as u64,
        records_digest: base64_url_encode(&[0; 32]),
    };
    let mut digest = PageDigest::new(&manifest).unwrap();
    for record in &records {
        digest.push(record).unwrap();
    }
    manifest.records_digest = digest.finish().unwrap();
    (manifest, records)
}

#[test]
fn p06_br06_signed_requests_are_strict_bounded_and_domain_bound() {
    let signer = Ed25519KeyPair::from_seed(&[25; 32]).unwrap();
    let other = Ed25519KeyPair::from_seed(&[26; 32]).unwrap();
    let (manifest, _) = fixture(0, false);
    let request = ReportRequest {
        identity: manifest.identity,
        broker_challenge: base64_url_encode(&[27; 32]),
        report_id: None,
        page_index: 0,
    };
    let signed = SignedReportRequest::sign(request.clone(), &signer).unwrap();
    let bytes = canonicalize_value(&signed.to_value().unwrap()).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let parsed = SignedReportRequest::from_json(text).unwrap();
    parsed.verify(signer.public_key()).unwrap();
    assert!(parsed.verify(other.public_key()).is_err());
    let mut changed = parsed.clone();
    changed.request.identity.recovery_generation += 1;
    assert!(changed.verify(signer.public_key()).is_err());
    assert!(SignedReportRequest::from_json(&format!("{text}{}", " ".repeat(4096))).is_err());
    for field in ["records", "signing_message", "path"] {
        let mut injected = signed.to_value().unwrap();
        if let blindpass_core::canon::Value::Object(fields) = &mut injected {
            fields.push((field.into(), blindpass_core::canon::Value::Null));
        }
        assert!(
            SignedReportRequest::from_json(
                std::str::from_utf8(&canonicalize_value(&injected).unwrap()).unwrap()
            )
            .is_err()
        );
    }
    let duplicate = text.replacen("{", "{\"body\":null,", 1);
    assert!(SignedReportRequest::from_json(&duplicate).is_err());
    let mut invalid = request.clone();
    invalid.page_index = 1;
    assert!(SignedReportRequest::sign(invalid, &signer).is_err());
    for size in [0, 1, 31, 33] {
        let mut invalid = request.clone();
        invalid.broker_challenge = base64_url_encode(&vec![1; size]);
        assert!(SignedReportRequest::sign(invalid, &signer).is_err());
    }
}

#[test]
fn p06_br05_completion_is_poisoned_by_replay_or_changed_manifest() {
    let signer = Ed25519KeyPair::from_seed(&[28; 32]).unwrap();
    let (manifest, records) = fixture(129, false);
    let verify_page = |page: ReportPage| {
        let signature = signer.sign(&page.signing_message().unwrap()).unwrap();
        page.verify(&manifest.identity, 1, signer.public_key(), &signature)
            .unwrap()
    };
    let mut accumulator = PageAccumulator::new();
    accumulator
        .push(verify_page(page(&manifest, &records, 0)))
        .unwrap();
    let mut changed = page(&manifest, &records, 1);
    changed.manifest.report_id = base64_url_encode(&[29; 32]);
    assert!(accumulator.push(verify_page(changed)).is_err());
    assert!(
        accumulator
            .push(verify_page(page(&manifest, &records, 1)))
            .is_err()
    );
    assert!(!accumulator.complete());
    let mut complete = PageAccumulator::new();
    for index in 0..2 {
        complete
            .push(verify_page(page(&manifest, &records, index)))
            .unwrap();
    }
    assert!(complete.complete());
    assert!(
        complete
            .push(verify_page(page(&manifest, &records, 1)))
            .is_err()
    );
    assert!(!complete.complete());
}

fn page(manifest: &ReportManifest, records: &[IntentRecord], index: u64) -> ReportPage {
    let start = index as usize * 128;
    ReportPage {
        manifest: manifest.clone(),
        page_index: index,
        records: records[start..records.len().min(start + 128)].to_vec(),
    }
}

#[test]
fn p06_br05_empty_one_full_boundary_and_multiple_pages_complete_exactly() {
    let signer = Ed25519KeyPair::from_seed(&[23; 32]).unwrap();
    for count in [0, 1, 128, 129, 384] {
        let (manifest, records) = fixture(count, false);
        let mut accumulator = PageAccumulator::new();
        for index in 0..manifest.page_count() {
            let page = page(&manifest, &records, index);
            let body = canonicalize_value(&page.to_value().unwrap()).unwrap();
            assert!(body.len() <= 64 * 1024);
            let parsed = ReportPage::from_json(std::str::from_utf8(&body).unwrap()).unwrap();
            assert_eq!(parsed, page);
            let signature = signer.sign(&page.signing_message().unwrap()).unwrap();
            let verified = parsed
                .verify(&manifest.identity, 1, signer.public_key(), &signature)
                .unwrap();
            assert_eq!(
                accumulator.push(verified).unwrap(),
                index + 1 == manifest.page_count()
            );
        }
        assert!(accumulator.complete());
    }
}

#[test]
fn p06_br05_gap_duplicate_reorder_and_digest_tamper_never_complete() {
    let signer = Ed25519KeyPair::from_seed(&[23; 32]).unwrap();
    let (manifest, records) = fixture(129, false);
    for indices in [vec![1], vec![0, 0], vec![1, 0]] {
        let mut accumulator = PageAccumulator::new();
        for index in indices {
            let page = page(&manifest, &records, index);
            let sig = signer.sign(&page.signing_message().unwrap()).unwrap();
            let verified = page
                .verify(&manifest.identity, 1, signer.public_key(), &sig)
                .unwrap();
            if accumulator.push(verified).is_err() {
                break;
            }
        }
        assert!(!accumulator.complete());
    }
    let mut accumulator = PageAccumulator::new();
    for index in 0..2 {
        let mut page = page(&manifest, &records, index);
        if index == 1 {
            page.records[0].operation_id = Some("tampered_operation".into());
        }
        let sig = signer.sign(&page.signing_message().unwrap()).unwrap();
        let result = accumulator.push(
            page.verify(&manifest.identity, 1, signer.public_key(), &sig)
                .unwrap(),
        );
        assert_eq!(result.is_err(), index == 1);
    }
    assert!(!accumulator.complete());
}

#[test]
fn p06_br05_count_sort_context_and_current_key_are_strict() {
    let signer = Ed25519KeyPair::from_seed(&[23; 32]).unwrap();
    let stale = Ed25519KeyPair::from_seed(&[24; 32]).unwrap();
    let (manifest, records) = fixture(129, false);
    let original = page(&manifest, &records, 0);
    let sig = signer.sign(&original.signing_message().unwrap()).unwrap();
    assert!(
        original
            .verify(&manifest.identity, 1, stale.public_key(), &sig)
            .is_err()
    );
    let mut wrong = manifest.identity.clone();
    wrong.node_key_version = 1;
    assert!(
        original
            .verify(&wrong, 1, signer.public_key(), &sig)
            .is_err()
    );
    let mut short = original.clone();
    short.records.pop();
    assert!(short.to_value().is_err());
    let mut duplicate = original.clone();
    duplicate.records[1] = duplicate.records[0].clone();
    assert!(duplicate.to_value().is_err());
    let mut reordered = original.clone();
    reordered.records.swap(0, 1);
    assert!(reordered.to_value().is_err());
    let mut oversized = original;
    oversized.manifest.total_records = 1_000_001;
    assert!(oversized.to_value().is_err());
}

#[test]
fn p06_br02_delivery_completion_does_not_turn_unknown_or_pruned_history_into_coverage() {
    let (manifest, _) = fixture(3, true);
    assert!(!manifest.coverage.covers(1_800_000_000_000));
    let (mut manifest, _) = fixture(0, false);
    assert!(manifest.coverage.covers(1_800_000_000_000));
    manifest.coverage.pruned_through_ms = 1_800_000_000_000;
    assert!(!manifest.coverage.covers(1_800_000_000_000));
    assert!(manifest.coverage.covers(1_800_000_000_001));
}

#[test]
fn p06_br05_observation_above_proposed_generation_remains_attestable() {
    let (mut manifest, records) = fixture(1, false);
    manifest.observed_issuer_epoch = 9;
    let mut digest = PageDigest::new(&manifest).unwrap();
    digest.push(&records[0]).unwrap();
    manifest.records_digest = digest.finish().unwrap();
    let page = page(&manifest, &records, 0);
    let signer = Ed25519KeyPair::from_seed(&[23; 32]).unwrap();
    let signature = signer.sign(&page.signing_message().unwrap()).unwrap();
    page.verify(&manifest.identity, 1, signer.public_key(), &signature)
        .unwrap();
    assert_eq!(page.manifest.observed_issuer_epoch, 9);
    assert_eq!(page.manifest.identity.recovery_generation, 8);
}
