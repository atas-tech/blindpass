-- SPDX-License-Identifier: AGPL-3.0-only
-- Application is quarantine metadata, never provider success or admission.
CREATE TABLE IF NOT EXISTS controller_recovery_reports (
    recovery_id TEXT NOT NULL REFERENCES controller_recoveries(recovery_id),
    node_id TEXT NOT NULL,
    report_id TEXT NOT NULL CHECK (length(report_id)=43),
    records_digest TEXT NOT NULL CHECK (length(records_digest)=43),
    trust_revision BIGINT NOT NULL CHECK (trust_revision BETWEEN 1 AND 9007199254740991),
    node_key_version BIGINT NOT NULL CHECK (node_key_version BETWEEN 1 AND 9007199254740991),
    matched BIGINT NOT NULL CHECK (matched>=0),
    unknown_records BIGINT NOT NULL CHECK (unknown_records>=0),
    conflicting BIGINT NOT NULL CHECK (conflicting>=0),
    unmapped BIGINT NOT NULL CHECK (unmapped>=0),
    state TEXT NOT NULL CHECK (state='quarantined'),
    PRIMARY KEY (recovery_id,node_id)
);
CREATE TABLE IF NOT EXISTS controller_recovery_intents (
    recovery_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    operation_id TEXT,
    issuer_epoch BIGINT CHECK (issuer_epoch BETWEEN 1 AND 9007199254740991),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms BETWEEN 1 AND 9007199254740991),
    mapping TEXT NOT NULL CHECK (mapping IN ('matched','unknown','conflicting','unmapped')),
    PRIMARY KEY (recovery_id,node_id,grant_id),
    FOREIGN KEY (recovery_id,node_id) REFERENCES controller_recovery_reports(recovery_id,node_id),
    CHECK ((operation_id IS NULL)=(issuer_epoch IS NULL))
);
