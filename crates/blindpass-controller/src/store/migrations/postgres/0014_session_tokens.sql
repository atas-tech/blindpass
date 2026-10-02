-- SPDX-License-Identifier: AGPL-3.0-only
-- Existing cookie and desktop access tokens were stored as session IDs.
-- Revoke them at the schema boundary; new sessions store only token hashes.
DELETE FROM operator_sessions
WHERE EXISTS (SELECT 1 FROM controller_meta WHERE id = 1 AND schema_version < 14);
