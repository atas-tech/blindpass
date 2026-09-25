-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE IF NOT EXISTS node_key_rotations (
    node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    rotation_id TEXT NOT NULL UNIQUE,
    from_key_version BIGINT NOT NULL CHECK (from_key_version > 0),
    to_key_version BIGINT NOT NULL CHECK (to_key_version = from_key_version + 1),
    signing_pub TEXT NOT NULL,
    recipient_pub TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
