-- SPDX-License-Identifier: AGPL-3.0-only

-- Columns are added by the Rust migration helper because SQLite has no
-- ADD COLUMN IF NOT EXISTS; the node name constraint is removed by a one-time
-- table rebuild before this file runs.

-- A revoked node's name may be enrolled again; only active names are unique.
CREATE UNIQUE INDEX IF NOT EXISTS nodes_active_name_idx
    ON nodes (tenant_id, name) WHERE status = 'active';

-- At most one active workload registration per node system unit.
CREATE UNIQUE INDEX IF NOT EXISTS workloads_active_unit_idx
    ON workloads (tenant_id, node_id, unit) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS operation_approvals_group_idx
    ON operation_approvals (tenant_id, group_scope_hash, status, expires_at);
CREATE INDEX IF NOT EXISTS operations_approval_idx
    ON operations (tenant_id, approval_id);
CREATE INDEX IF NOT EXISTS operations_workload_status_idx
    ON operations (tenant_id, workload_id, status);
CREATE INDEX IF NOT EXISTS node_inbox_acked_idx
    ON node_inbox (acked_at);
CREATE INDEX IF NOT EXISTS node_events_received_idx
    ON node_events (received_at);
CREATE INDEX IF NOT EXISTS node_sessions_expiry_idx
    ON node_sessions (expires_at);
CREATE INDEX IF NOT EXISTS grant_tombstones_node_idx
    ON grant_tombstones (node_id, retain_until);
