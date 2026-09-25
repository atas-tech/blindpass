-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE IF NOT EXISTS node_challenges (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    nonce_hash TEXT NOT NULL UNIQUE,
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    issuer_epoch BIGINT NOT NULL CHECK (issuer_epoch > 0),
    protocol_version TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    capabilities_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT
);

CREATE INDEX IF NOT EXISTS node_challenges_expiry_idx
    ON node_challenges (expires_at, node_id);
