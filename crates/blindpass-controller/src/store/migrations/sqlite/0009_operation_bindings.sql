-- SPDX-License-Identifier: AGPL-3.0-only

CREATE UNIQUE INDEX IF NOT EXISTS operations_broker_event_idx
    ON operations (tenant_id, node_id, broker_event_key)
    WHERE broker_event_key IS NOT NULL;
