-- SPDX-License-Identifier: AGPL-3.0-only

CREATE INDEX IF NOT EXISTS operations_tenant_created_idx
    ON operations (tenant_id, created_at, id);
CREATE INDEX IF NOT EXISTS operation_approvals_tenant_created_idx
    ON operation_approvals (tenant_id, created_at, id);
