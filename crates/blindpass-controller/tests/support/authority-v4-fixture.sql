-- SPDX-License-Identifier: AGPL-3.0-only
-- Reconstruct v4 only in a driver-owned disposable database, before v3 tests: remove
-- the layout 5 additions (protected recovery activation) and nothing else. This is a
-- reconstructed migration input, not evidence of an installed v4 deployment.
BEGIN;
DROP FUNCTION blindpass_authority.activate_recovery(TEXT,TEXT,TEXT,BIGINT);
DROP FUNCTION blindpass_authority.attest_source_stop(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT);
DROP FUNCTION blindpass_authority.recovery_activation_gaps(TEXT,TEXT,TEXT,BOOLEAN);
DROP FUNCTION blindpass_authority.complete_recovery_review(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT);
DROP FUNCTION blindpass_authority.waive_recovery_node(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT);
DROP FUNCTION blindpass_authority.decide_recovery_item(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT);
DROP TABLE blindpass_authority.recovery_activations;
DROP TABLE blindpass_authority.recovery_review_complete;
DROP TABLE blindpass_authority.recovery_review_decisions;
DROP TABLE blindpass_authority.recovery_node_waivers;
DROP TABLE blindpass_authority.recovery_source_stop;
DROP FUNCTION blindpass_authority.protect_recovery_evidence();
ALTER TABLE blindpass_authority.authority_layout DROP CONSTRAINT authority_layout_version_check;
UPDATE blindpass_authority.authority_layout SET version=4;
ALTER TABLE blindpass_authority.authority_layout ADD CONSTRAINT authority_layout_version_check CHECK(version=4);
COMMIT;
