-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE IF NOT EXISTS enrollment_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    node_id TEXT,
    submitted_signing_pub TEXT,
    submitted_recipient_pub TEXT,
    fingerprint TEXT,
    host_facts_json TEXT,
    status TEXT NOT NULL CHECK (status IN ('issued', 'submitted', 'approved', 'rejected', 'expired')),
    version BIGINT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    signing_pub TEXT NOT NULL,
    recipient_pub TEXT NOT NULL,
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    protocol_version TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    last_seen_at BIGINT,
    last_poll_at BIGINT,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT,
    version BIGINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS node_key_history (
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    signing_pub TEXT NOT NULL,
    recipient_pub TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    retired_at BIGINT,
    PRIMARY KEY (node_id, key_version)
);

CREATE TABLE IF NOT EXISTS node_sessions (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    nonce_hash TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT
);

CREATE TABLE IF NOT EXISTS workloads (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    name TEXT NOT NULL,
    unit TEXT NOT NULL,
    account TEXT NOT NULL,
    consumption_mode TEXT NOT NULL CHECK (consumption_mode IN ('file', 'socket', 'browser_session')),
    local_ceiling_seconds BIGINT NOT NULL CHECK (local_ceiling_seconds BETWEEN 1 AND 3600),
    registration_version BIGINT NOT NULL CHECK (registration_version > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT,
    version BIGINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, node_id, name)
);

CREATE TABLE IF NOT EXISTS fleet_policies (
    tenant_id TEXT PRIMARY KEY,
    version BIGINT NOT NULL CHECK (version > 0),
    document_json TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    workload_id TEXT NOT NULL REFERENCES workloads(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    invocation_id TEXT NOT NULL,
    action TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('file', 'socket', 'browser_session')),
    requested_by TEXT NOT NULL,
    purpose TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'pending_approval', 'deny')),
    decision_hash TEXT,
    status TEXT NOT NULL CHECK (status IN ('requested', 'awaiting_approval', 'granted', 'executing', 'completed', 'failed', 'uncertain', 'denied', 'revoked', 'cancelled')),
    approval_id TEXT,
    grant_id TEXT,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    completed_at BIGINT,
    version BIGINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, requested_by, idempotency_key)
);

CREATE TABLE IF NOT EXISTS operation_approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    operation_ids_json TEXT NOT NULL,
    requester_summary_json TEXT NOT NULL,
    verified_identity_json TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    decided_by TEXT,
    decided_at BIGINT,
    expires_at BIGINT NOT NULL,
    idempotency_key TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE REFERENCES operations(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    workload_id TEXT NOT NULL REFERENCES workloads(id),
    invocation_id TEXT NOT NULL,
    service_delivery_binding TEXT,
    account TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    recipient_key_id TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    approval_reference TEXT,
    request_use_id TEXT NOT NULL,
    unit TEXT NOT NULL,
    action TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('file', 'socket', 'browser_session')),
    audience TEXT NOT NULL,
    issuer_epoch BIGINT NOT NULL CHECK (issuer_epoch > 0),
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    body_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('issued', 'delivered', 'consumed', 'revoked', 'expired')),
    consumed_at BIGINT,
    revoked_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS grant_tombstones (
    grant_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    reason TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    retain_until BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_inbox (
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    envelope_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    delivered_at BIGINT,
    acked_at BIGINT,
    PRIMARY KEY (node_id, seq)
);

CREATE TABLE IF NOT EXISTS node_events (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    body_json TEXT NOT NULL,
    body_hash TEXT NOT NULL,
    received_at BIGINT NOT NULL,
    UNIQUE (node_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS enrollment_requests_pending_idx
    ON enrollment_requests (tenant_id, status, expires_at, id);
CREATE INDEX IF NOT EXISTS nodes_liveness_idx
    ON nodes (tenant_id, status, last_seen_at, id);
CREATE INDEX IF NOT EXISTS workloads_node_status_idx
    ON workloads (tenant_id, node_id, status, id);
CREATE INDEX IF NOT EXISTS operations_status_idx
    ON operations (tenant_id, status, created_at, id);
CREATE INDEX IF NOT EXISTS operation_approvals_pending_idx
    ON operation_approvals (tenant_id, status, expires_at, id);
CREATE INDEX IF NOT EXISTS grants_node_status_idx
    ON grants (tenant_id, node_id, status, expires_at, id);
CREATE INDEX IF NOT EXISTS grant_tombstones_retention_idx
    ON grant_tombstones (retain_until, grant_id);
