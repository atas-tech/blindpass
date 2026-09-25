-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE controller_clock ADD COLUMN IF NOT EXISTS boot_id TEXT;
ALTER TABLE controller_clock ADD COLUMN IF NOT EXISTS boottime_ms BIGINT;
ALTER TABLE controller_clock ADD COLUMN IF NOT EXISTS host_wall_ms BIGINT;
ALTER TABLE controller_clock ADD COLUMN IF NOT EXISTS fenced_at BIGINT;
