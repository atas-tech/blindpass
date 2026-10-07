-- SPDX-License-Identifier: AGPL-3.0-only
-- Records the administrator's attestation that the SOURCE host of a restored
-- controller is stopped (P06-D30). Run as the independent authority administrator
-- after the recovering controller and the old source are both stopped. The ledger
-- itself refuses while any process still holds the tenant guard, and the record must
-- be `recovering`; neither check relies on this attestation.
--
--   psql -v ON_ERROR_STOP=1 -v tenant=TENANT -v owner=OWNER -v issuer=ISSUER_KEY_ID \
--        -v host=SOURCE_HOST_ID -v by=ADMIN_ID -v note='why you know it is stopped' \
--        -f authority-recover-attest.sql
--
-- The row (who, when, host id) is insert-only evidence; it activates nothing.
\set ON_ERROR_STOP on
SELECT blindpass_authority.attest_source_stop(:'tenant', :'issuer', :'owner', :'host', :'by', :'note') AS attested_epoch \gset
\echo source stop attested for recovery epoch :attested_epoch
