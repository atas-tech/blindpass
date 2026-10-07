-- SPDX-License-Identifier: AGPL-3.0-only
-- P10 cross-workload fulfillment. Metadata is immutable lineage; the only
-- secret-derived bytes are one-use ciphertext sealed to a key the recipient
-- broker minted, kept in a table no other route or store module reads.
CREATE TABLE IF NOT EXISTS cross_fulfillments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    issuer_workload_id TEXT NOT NULL REFERENCES workloads(id),
    recipient_workload_id TEXT NOT NULL REFERENCES workloads(id),
    issuer_node_id TEXT NOT NULL REFERENCES nodes(id),
    recipient_node_id TEXT NOT NULL REFERENCES nodes(id),
    issuer_credential TEXT NOT NULL,
    recipient_credential TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode = 'reencrypt'),
    requested_by TEXT NOT NULL,
    purpose TEXT NOT NULL,
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    rule_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'pending_approval', 'deny')),
    approver_ids_json TEXT NOT NULL,
    approval_status TEXT NOT NULL CHECK (approval_status IN ('not_required', 'pending', 'approved', 'rejected')),
    decided_by TEXT,
    decided_at BIGINT,
    prior_fulfillment_id TEXT,
    ttl_seconds BIGINT NOT NULL CHECK (ttl_seconds BETWEEN 1 AND 600),
    terms_json TEXT,
    terms_digest TEXT,
    offer_json TEXT,
    issuer_key_version BIGINT,
    recipient_key_version BIGINT,
    issuer_registration_version BIGINT,
    recipient_registration_version BIGINT,
    status TEXT NOT NULL CHECK (status IN ('awaiting_approval', 'approved', 'offered', 'available', 'recipient_consumed', 'completed', 'denied', 'revoked', 'expired', 'failed', 'uncertain')),
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    failure_code TEXT,
    revocation_reason TEXT,
    delivery_revoked_at BIGINT,
    provider_revocation TEXT NOT NULL DEFAULT 'unsupported' CHECK (provider_revocation IN ('not_attempted', 'unsupported', 'confirmed', 'failed')),
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    approved_at BIGINT,
    offered_at BIGINT,
    issuer_consumed_at BIGINT,
    recipient_consumed_at BIGINT,
    completed_at BIGINT,
    closed_at BIGINT,
    version BIGINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, requested_by, idempotency_key)
);

CREATE TABLE IF NOT EXISTS cross_fulfillment_payloads (
    fulfillment_id TEXT PRIMARY KEY REFERENCES cross_fulfillments(id),
    tenant_id TEXT NOT NULL,
    submit_json TEXT NOT NULL,
    ciphertext_digest TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

-- One live fulfillment per recipient workload; an `uncertain` one holds the
-- slot until an operator reconciles it.
CREATE UNIQUE INDEX IF NOT EXISTS cross_fulfillments_active_recipient_idx
    ON cross_fulfillments (tenant_id, recipient_workload_id)
    WHERE status IN ('awaiting_approval', 'approved', 'offered', 'available', 'recipient_consumed', 'uncertain');
CREATE INDEX IF NOT EXISTS cross_fulfillments_status_idx
    ON cross_fulfillments (tenant_id, status, expires_at, id);
