-- SPDX-License-Identifier: AGPL-3.0-only
-- Grants the controller ONE start. Run as the independent authority
-- administrator each time the controller must be started (first start and
-- every restart): a started process consumes its active revision and a used
-- revision is never replayed, even after the process dies.
--
--   psql -v ON_ERROR_STOP=1 -v tenant=TENANT -v owner=OWNER \
--        -v issuer=ISSUER_KEY_ID -f authority-activate.sql
--
-- The ledger itself refuses while another process still holds the tenant
-- guard (live holder, or a backend PostgreSQL has not yet noticed is gone), so
-- run it only after the previous controller on any host is stopped. A
-- `recovering` record (restored snapshot) is never activated here: use the
-- protected procedure (`authority-recover-attest.sql`, then
-- `authority-recover-activate.sql`; see docs/deploy/recovery-activation.md).
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '2s';
WITH moved AS (
    UPDATE blindpass_authority.recovery_authority
    SET phase = 'active', revision = revision + 1
    WHERE tenant_id = :'tenant' AND issuer_key_id = :'issuer' AND owner_id = :'owner'
      AND phase IN ('fenced', 'active')
    RETURNING epoch, revision
)
SELECT count(*) = 1 AS activated, coalesce(max(revision), 0) AS activated_revision FROM moved \gset
\if :activated
    \echo activated revision :activated_revision
    COMMIT;
\else
    -- No matching fenced/active record (wrong identifiers or a recovering
    -- record): fail with a non-zero exit status and change nothing.
    DO $refuse$ BEGIN RAISE EXCEPTION 'controller activation refused: no matching fenced or active authority record'; END $refuse$;
\endif
