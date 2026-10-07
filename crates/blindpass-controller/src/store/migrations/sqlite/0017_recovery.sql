-- SPDX-License-Identifier: AGPL-3.0-only
-- A prepared record is a durable fence, not permission to activate.
CREATE TABLE IF NOT EXISTS controller_recoveries (
    recovery_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    snapshot_epoch BIGINT NOT NULL CHECK (snapshot_epoch BETWEEN 1 AND 9007199254740991),
    target_epoch BIGINT NOT NULL CHECK (target_epoch > snapshot_epoch AND target_epoch <= 9007199254740991),
    authority_revision BIGINT NOT NULL CHECK (authority_revision BETWEEN 1 AND 9007199254740991),
    phase TEXT NOT NULL CHECK (phase IN ('prepared', 'invalidated')),
    prepared_at BIGINT NOT NULL,
    invalidated_at BIGINT,
    summary_json TEXT,
    UNIQUE (tenant_id, target_epoch),
    CHECK ((phase='prepared' AND invalidated_at IS NULL AND summary_json IS NULL)
        OR (phase='invalidated' AND invalidated_at IS NOT NULL AND summary_json IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS controller_recovery_nodes (
    recovery_id TEXT NOT NULL REFERENCES controller_recoveries(recovery_id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    snapshot_status TEXT NOT NULL CHECK (snapshot_status IN ('active','revoked')),
    snapshot_key_version BIGINT NOT NULL CHECK (snapshot_key_version BETWEEN 1 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state='quarantined'),
    PRIMARY KEY (recovery_id,node_id)
);
CREATE TABLE IF NOT EXISTS controller_recovery_operations (
    recovery_id TEXT NOT NULL REFERENCES controller_recoveries(recovery_id),
    operation_id TEXT NOT NULL REFERENCES operations(id),
    snapshot_status TEXT NOT NULL,
    snapshot_result_json TEXT,
    snapshot_completed_at BIGINT,
    state TEXT NOT NULL CHECK (state='uncertain'),
    PRIMARY KEY (recovery_id,operation_id)
);
CREATE TABLE IF NOT EXISTS controller_recovery_reviews (
    recovery_id TEXT NOT NULL REFERENCES controller_recoveries(recovery_id),
    category TEXT NOT NULL CHECK (category IN ('agent','operator','legacy_policy','fleet_policy','workload','source_binding','node_key_rotation')),
    subject_id TEXT NOT NULL,
    related_id TEXT NOT NULL,
    snapshot_version BIGINT NOT NULL CHECK (snapshot_version BETWEEN 0 AND 9007199254740991),
    snapshot_status TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state='quarantined'),
    PRIMARY KEY (recovery_id,category,subject_id,related_id)
);
