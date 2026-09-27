-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE operation_approvals ADD COLUMN IF NOT EXISTS approver_ids_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE operation_approvals ADD COLUMN IF NOT EXISTS group_scope_hash TEXT;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS broker_revocation_outcome TEXT;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS revoked_by TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS revoked_by TEXT;
ALTER TABLE node_sessions ADD COLUMN IF NOT EXISTS delivered_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE grant_tombstones ADD COLUMN IF NOT EXISTS envelope_json TEXT;

-- A revoked node's name may be enrolled again; only active names are unique.
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS nodes_tenant_id_name_key;
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
