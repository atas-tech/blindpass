-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE enrollment_requests
    ADD COLUMN IF NOT EXISTS requested_name TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollment_requests
    ADD COLUMN IF NOT EXISTS protocol_version TEXT;
ALTER TABLE enrollment_requests
    ADD COLUMN IF NOT EXISTS capabilities_json TEXT;
