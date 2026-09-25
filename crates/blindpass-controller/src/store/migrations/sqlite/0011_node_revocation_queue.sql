-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE IF NOT EXISTS node_revocation_queue (
    node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL
);
