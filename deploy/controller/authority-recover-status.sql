-- SPDX-License-Identifier: AGPL-3.0-only
-- Read-only precheck for protected recovery activation (P06-D31). Prints the record
-- and the gates still open by fixed name; an empty list means `authority-recover-activate.sql`
-- would be accepted by the ledger. Run as the authority administrator.
--
--   psql -v ON_ERROR_STOP=1 -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER_KEY_ID \
--        -f authority-recover-status.sql
--
-- Gates: source_stop_missing, source_process_live, review_incomplete, node_uncovered,
-- not_recovering. The controller-side review is `blindpass admin recovery status`.
\set ON_ERROR_STOP on
SELECT epoch, revision, phase FROM blindpass_authority.recovery_authority
WHERE tenant_id = :'tenant' AND issuer_key_id = :'issuer' AND owner_id = :'owner';
SELECT unnest(blindpass_authority.recovery_activation_gaps(:'tenant', :'issuer', :'owner', TRUE)) AS open_gate;
