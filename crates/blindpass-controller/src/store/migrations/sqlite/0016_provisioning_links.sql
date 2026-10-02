-- SPDX-License-Identifier: AGPL-3.0-only
-- Scoped Source collection. A link belongs to one named operator and one
-- original grant; a receipt holds only a ciphertext digest and the digest of
-- the controller-signed delivery. Source plaintext and recipient private keys
-- never reach the controller. Neither table references the other or the
-- offers table so each prunes independently seven days after expiry.
CREATE TABLE IF NOT EXISTS fleet_provisioning_links (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    operation_id TEXT NOT NULL REFERENCES operations(id),
    grant_id TEXT NOT NULL UNIQUE REFERENCES grants(id),
    offer_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    idempotency_hash TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    CHECK (expires_at > created_at),
    UNIQUE (tenant_id, operator_id, idempotency_hash)
);
CREATE TABLE IF NOT EXISTS fleet_provisioning_receipts (
    link_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL UNIQUE REFERENCES grants(id),
    offer_id TEXT NOT NULL UNIQUE,
    operator_id TEXT NOT NULL,
    ciphertext_digest TEXT NOT NULL,
    delivery_digest TEXT NOT NULL,
    submitted_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS fleet_provisioning_links_expiry_idx
    ON fleet_provisioning_links (tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS fleet_provisioning_receipts_expiry_idx
    ON fleet_provisioning_receipts (tenant_id, expires_at);
