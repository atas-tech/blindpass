-- SPDX-License-Identifier: AGPL-3.0-only
-- Fences the controller: stops issuance without changing the epoch. Run as the
-- independent authority administrator before maintenance that requires a fenced
-- record (`reconcile-clock`, upgrades) or to cut off a running controller. A
-- live holder's next ownership check detects the loss and its transports close.
--
--   psql -v ON_ERROR_STOP=1 -v tenant=TENANT -v owner=OWNER \
--        -v issuer=ISSUER_KEY_ID -f authority-fence.sql
--
-- Fencing is the only transition the ledger allows while a holder is live.
-- It does not prove the process has stopped; stop it before maintenance.
\set ON_ERROR_STOP on
BEGIN;
WITH moved AS (
    UPDATE blindpass_authority.recovery_authority
    SET phase = 'fenced', revision = revision + 1
    WHERE tenant_id = :'tenant' AND issuer_key_id = :'issuer' AND owner_id = :'owner'
      AND phase IN ('active', 'recovering')
    RETURNING revision
)
SELECT count(*) = 1 AS fenced, coalesce(max(revision), 0) AS fenced_revision FROM moved \gset
\if :fenced
    \echo fenced revision :fenced_revision
    COMMIT;
\else
    -- Already fenced, or no matching record: nothing to change.
    DO $refuse$ BEGIN RAISE EXCEPTION 'controller fence refused: no matching active or recovering authority record'; END $refuse$;
\endif
