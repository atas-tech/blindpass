-- SPDX-License-Identifier: AGPL-3.0-only
-- Public metadata only: recipient private keys and Source stay on the broker.
CREATE TABLE IF NOT EXISTS fleet_source_bindings (
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    resource_id TEXT NOT NULL,
    source_unit TEXT NOT NULL,
    credential TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at BIGINT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (tenant_id, node_id, resource_id)
);
CREATE TABLE IF NOT EXISTS fleet_provisioning_offers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    operation_id TEXT NOT NULL REFERENCES operations(id),
    grant_id TEXT NOT NULL UNIQUE REFERENCES grants(id),
    source_binding_version BIGINT NOT NULL CHECK (source_binding_version > 0),
    offer_json TEXT NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    CHECK (expires_at > issued_at)
);
