-- SPDX-License-Identifier: AGPL-3.0-only
-- Run once per controller installation as the independent authority
-- administrator, after `blindpass keys init` and BEFORE the first `migrate`:
--
--   psql -v ON_ERROR_STOP=1 -v tenant=TENANT -v owner=OWNER \
--        -v issuer="$(blindpass keys issuer-id)" -f authority-register.sql
--
-- `tenant` and `owner` are names you choose ([A-Za-z0-9_-]{1,128}) and must
-- also set as BLINDPASS_CONTROLLER_TENANT_ID / BLINDPASS_CONTROLLER_OWNER_ID.
-- The record starts fenced at epoch 1, revision 1: `migrate` may then create
-- the controller database exactly once. A conflicting or repeated registration
-- refuses. This never activates the controller.
\set ON_ERROR_STOP on
BEGIN;
INSERT INTO blindpass_authority.recovery_authority (tenant_id, issuer_key_id, owner_id, epoch, revision, phase)
VALUES (:'tenant', :'issuer', :'owner', 1, 1, 'fenced');
COMMIT;
