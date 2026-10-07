-- SPDX-License-Identifier: AGPL-3.0-only
-- Activates a restored (`recovering`) authority record after every gate is met
-- (P06-D30..D32): source stop attested and no process holding the guard, every
-- broker covered or named-waived, the operator review complete. Run as the
-- independent authority administrator once the recovering controller is stopped.
--
--   psql -v ON_ERROR_STOP=1 -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER_KEY_ID \
--        -f authority-recover-activate.sql
--
-- Refusals name the open gates and change nothing. Success records the activation
-- proof the controller requires before it leaves recovery, then start the controller
-- normally (that start consumes the activated revision, like any other start).
-- `authority-activate.sql` still refuses a recovering record, and fencing a recovering
-- record to reach it leaves no proof: that controller stays recovery_required.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '2s';
SELECT revision AS current_revision FROM blindpass_authority.recovery_authority
WHERE tenant_id = :'tenant' AND issuer_key_id = :'issuer' AND owner_id = :'owner' AND phase = 'recovering' \gset
\if :{?current_revision}
    SELECT epoch AS activated_epoch, revision AS activated_revision
    FROM blindpass_authority.activate_recovery(:'tenant', :'issuer', :'owner', :current_revision) \gset
    \echo activated recovery epoch :activated_epoch at revision :activated_revision
    COMMIT;
\else
    DO $refuse$ BEGIN RAISE EXCEPTION 'recovery activation refused: no matching recovering authority record'; END $refuse$;
\endif
