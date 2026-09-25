-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE operations ADD COLUMN resource_id TEXT NOT NULL DEFAULT '';
ALTER TABLE operations ADD COLUMN requested_ttl_seconds BIGINT NOT NULL DEFAULT 1;
ALTER TABLE operations ADD COLUMN broker_event_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS operations_broker_event_idx
    ON operations (tenant_id, node_id, broker_event_key)
    WHERE broker_event_key IS NOT NULL;
