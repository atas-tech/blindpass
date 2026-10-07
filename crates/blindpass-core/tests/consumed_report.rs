// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::fleet::node_event_message;
use blindpass_core::recovery::{
    ConsumedOutcome, ConsumedRecord, ConsumedReport, MAX_CONSUMED_REPORT_BYTES,
    MAX_CONSUMED_REPORT_RECORDS, ReportContext,
};
use blindpass_core::signing::base64_url_encode;
use blindpass_core::signing::ed25519::Ed25519KeyPair;

const EVENT: &str = "recovery_report_event_001";

#[test]
fn p06_cr06_recovery_challenge_requires_exactly_32_decoded_bytes() {
    for length in 0..32 {
        let mut report = report();
        report.challenge = base64_url_encode(&vec![11; length]);
        assert!(
            report.to_value().is_err(),
            "accepted short canonical nonce of {length} bytes"
        );
    }
}

fn report() -> ConsumedReport {
    ConsumedReport {
        tenant_id: "tenant_dummy".into(),
        node_id: "node_dummy".into(),
        node_key_version: 2,
        issuer_key_id: "issuer_dummy".into(),
        recovery_id: "recovery_dummy".into(),
        recovery_generation: 8,
        observed_issuer_epoch: 7,
        challenge: base64_url_encode(&[11; 32]),
        records: vec![
            ConsumedRecord {
                grant_id: "grant_a".into(),
                operation_id: "operation_a".into(),
                issuer_epoch: 5,
                outcome: ConsumedOutcome::Consumed,
            },
            ConsumedRecord {
                grant_id: "grant_b".into(),
                operation_id: "operation_b".into(),
                issuer_epoch: 6,
                outcome: ConsumedOutcome::Revoked,
            },
            ConsumedRecord {
                grant_id: "grant_c".into(),
                operation_id: "operation_c".into(),
                issuer_epoch: 7,
                outcome: ConsumedOutcome::Uncertain,
            },
        ],
    }
}

fn context(report: &ConsumedReport) -> ReportContext<'_> {
    ReportContext {
        tenant_id: &report.tenant_id,
        node_id: &report.node_id,
        node_key_version: report.node_key_version,
        issuer_key_id: &report.issuer_key_id,
        recovery_id: &report.recovery_id,
        recovery_generation: report.recovery_generation,
        minimum_observed_epoch: report.observed_issuer_epoch,
        challenge: &report.challenge,
    }
}

fn replace(value: &mut Value, key: &str, replacement: Value) {
    let Value::Object(fields) = value else {
        panic!("expected object")
    };
    fields.iter_mut().find(|(name, _)| name == key).unwrap().1 = replacement;
}

#[test]
fn p06_cr01_canonical_round_trip_and_authentic_all_outcomes() {
    let report = report();
    let key = Ed25519KeyPair::from_seed(&[23; 32]).unwrap();
    let message = report.signing_message(EVENT).unwrap();
    let prefix = b"blindpass:fleet-node-event:v1\0";
    assert!(message.starts_with(prefix));
    let envelope = parse_json(std::str::from_utf8(&message[prefix.len()..]).unwrap()).unwrap();
    assert_eq!(
        envelope.get("kind").and_then(Value::as_str),
        Some("consumed_report")
    );
    assert_eq!(
        envelope.get("node_id").and_then(Value::as_str),
        Some(report.node_id.as_str())
    );
    assert_eq!(
        envelope.get("idempotency_key").and_then(Value::as_str),
        Some(EVENT)
    );
    assert_eq!(
        canonicalize_value(envelope.get("body").unwrap()).unwrap(),
        canonicalize_value(&report.to_value().unwrap()).unwrap()
    );
    let signature = key.sign(&message).unwrap();
    report
        .verify(EVENT, &context(&report), key.public_key(), &signature)
        .unwrap();
    let bytes = canonicalize_value(&report.to_value().unwrap()).unwrap();
    let parsed = ConsumedReport::from_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
    assert_eq!(parsed, report);
    assert_eq!(parsed.signing_message(EVENT).unwrap(), message);
    assert_eq!(parsed.records[2].outcome, ConsumedOutcome::Uncertain);
    let mut empty = report.clone();
    empty.records.clear();
    assert_eq!(
        ConsumedReport::from_value(&empty.to_value().unwrap()).unwrap(),
        empty
    );
}

#[test]
fn p06_cr02_signature_binds_every_context_field_and_event_key() {
    let report = report();
    let key = Ed25519KeyPair::from_seed(&[23; 32]).unwrap();
    let signature = key.sign(&report.signing_message(EVENT).unwrap()).unwrap();
    let mut variants = Vec::new();
    for field in [
        "tenant",
        "node",
        "key",
        "issuer",
        "recovery",
        "generation",
        "challenge",
    ] {
        let mut changed = report.clone();
        match field {
            "tenant" => changed.tenant_id.push('x'),
            "node" => changed.node_id.push('x'),
            "key" => changed.node_key_version += 1,
            "issuer" => changed.issuer_key_id.push('x'),
            "recovery" => changed.recovery_id.push('x'),
            "generation" => changed.recovery_generation += 1,
            "challenge" => changed.challenge = base64_url_encode(&[12; 32]),
            _ => unreachable!(),
        }
        variants.push(changed);
    }
    for changed in variants {
        assert!(
            report
                .verify(EVENT, &context(&changed), key.public_key(), &signature)
                .is_err()
        );
        assert!(
            changed
                .verify(EVENT, &context(&changed), key.public_key(), &signature)
                .is_err()
        );
    }
    let wrong_key = Ed25519KeyPair::from_seed(&[24; 32]).unwrap();
    assert!(
        report
            .verify(EVENT, &context(&report), wrong_key.public_key(), &signature)
            .is_err()
    );
    assert!(
        report
            .verify(
                "different_event_key_001",
                &context(&report),
                key.public_key(),
                &signature
            )
            .is_err()
    );
    let mut changed = report.clone();
    changed.records[0].outcome = ConsumedOutcome::Uncertain;
    assert!(
        changed
            .verify(EVENT, &context(&changed), key.public_key(), &signature)
            .is_err()
    );
    assert!(
        report
            .verify(EVENT, &context(&report), key.public_key(), &signature[..63])
            .is_err()
    );
}

#[test]
fn p06_cr03_strict_fields_order_bounds_and_no_truncation() {
    let report = report();
    let value = report.to_value().unwrap();
    for field in value.as_object().unwrap() {
        let mut missing = value.clone();
        let Value::Object(fields) = &mut missing else {
            unreachable!()
        };
        fields.retain(|(key, _)| key != &field.0);
        assert!(ConsumedReport::from_value(&missing).is_err());
    }
    for field in ["unknown", "tenant_id"] {
        let mut extra = value.clone();
        let Value::Object(fields) = &mut extra else {
            unreachable!()
        };
        fields.push((field.into(), Value::String("dummy".into())));
        assert!(ConsumedReport::from_value(&extra).is_err());
    }
    let json = String::from_utf8(canonicalize_value(&value).unwrap()).unwrap();
    assert!(ConsumedReport::from_json(&json.replacen('{', "{\"version\":1,", 1)).is_err());
    assert!(ConsumedReport::from_json(&" ".repeat(MAX_CONSUMED_REPORT_BYTES + 1)).is_err());
    for (field, invalid) in [
        ("version", Value::Unsigned(2)),
        ("node_key_version", Value::Integer(-1)),
        (
            "recovery_generation",
            Value::Unsigned(9_007_199_254_740_992),
        ),
        ("tenant_id", Value::String("../dummy".into())),
        ("challenge", Value::String("a".repeat(43))),
        ("challenge", Value::String("a".repeat(44))),
        ("records", Value::Null),
    ] {
        let mut changed = value.clone();
        replace(&mut changed, field, invalid);
        assert!(ConsumedReport::from_value(&changed).is_err());
    }
    for change in [
        "unknown",
        "duplicate",
        "missing",
        "outcome",
        "operation",
        "unsafe_epoch",
    ] {
        let mut changed = value.clone();
        let Value::Object(fields) = &mut changed else {
            unreachable!()
        };
        let Value::Array(records) = &mut fields
            .iter_mut()
            .find(|(key, _)| key == "records")
            .unwrap()
            .1
        else {
            unreachable!()
        };
        let Value::Object(fields) = &mut records[0] else {
            unreachable!()
        };
        match change {
            "unknown" => fields.push(("payload".into(), Value::String("dummy".into()))),
            "duplicate" => fields.push(fields[0].clone()),
            "missing" => {
                fields.pop();
            }
            "outcome" => replace(
                &mut records[0],
                "outcome",
                Value::String("completed".into()),
            ),
            "operation" => replace(
                &mut records[0],
                "operation_id",
                Value::String("/dummy".into()),
            ),
            "unsafe_epoch" => replace(&mut records[0], "issuer_epoch", Value::Unsigned(u64::MAX)),
            _ => unreachable!(),
        }
        assert!(ConsumedReport::from_value(&changed).is_err());
    }
    let mut changed = report.clone();
    changed.records.swap(0, 1);
    assert!(changed.to_value().is_err());
    changed.records = vec![report.records[0].clone(); 2];
    assert!(changed.to_value().is_err());
    changed.records = (0..MAX_CONSUMED_REPORT_RECORDS)
        .map(|i| ConsumedRecord {
            grant_id: format!("grant_{i:04}"),
            ..report.records[0].clone()
        })
        .collect();
    let exact = changed.to_value().unwrap();
    assert_eq!(
        ConsumedReport::from_value(&exact).unwrap().records.len(),
        MAX_CONSUMED_REPORT_RECORDS
    );
    changed.records.push(ConsumedRecord {
        grant_id: "grant_9999".into(),
        ..report.records[0].clone()
    });
    assert!(changed.to_value().is_err());
    assert!(report.signing_message("short").is_err());
}

#[test]
fn p06_cr04_stale_observation_and_future_or_zero_epochs_refuse() {
    let report = report();
    let key = Ed25519KeyPair::from_seed(&[23; 32]).unwrap();
    let signature = key.sign(&report.signing_message(EVENT).unwrap()).unwrap();
    let mut expected = context(&report);
    expected.minimum_observed_epoch = 8;
    assert!(
        report
            .verify(EVENT, &expected, key.public_key(), &signature)
            .is_err()
    );
    expected.minimum_observed_epoch = 0;
    assert!(
        report
            .verify(EVENT, &expected, key.public_key(), &signature)
            .is_err()
    );
    for change in [
        "zero_observed",
        "future_observed",
        "zero_record",
        "future_record",
        "zero_target",
        "zero_key",
    ] {
        let mut changed = report.clone();
        match change {
            "zero_observed" => changed.observed_issuer_epoch = 0,
            "future_observed" => changed.observed_issuer_epoch = 9,
            "zero_record" => changed.records[0].issuer_epoch = 0,
            "future_record" => changed.records[0].issuer_epoch = 8,
            "zero_target" => changed.recovery_generation = 0,
            "zero_key" => changed.node_key_version = 0,
            _ => unreachable!(),
        }
        assert!(changed.to_value().is_err());
        assert!(changed.signing_message(EVENT).is_err());
    }
    let mut current = report.clone();
    current.recovery_generation = 12;
    current.recovery_id = "later_recovery_dummy".into();
    current.challenge = base64_url_encode(&[13; 32]);
    assert!(
        report
            .verify(EVENT, &context(&current), key.public_key(), &signature)
            .is_err()
    );
}

#[test]
fn p06_cr05_generic_event_admission_stays_closed() {
    let report = report();
    assert!(report.signing_message(EVENT).is_ok());
    assert!(
        node_event_message(
            &report.node_id,
            EVENT,
            "consumed_report",
            &report.to_value().unwrap()
        )
        .is_err()
    );
}
