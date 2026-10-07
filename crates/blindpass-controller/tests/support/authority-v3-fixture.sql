-- SPDX-License-Identifier: AGPL-3.0-only
-- Reconstruct v3 only in a driver-owned disposable database, before v2 tests.
BEGIN;
DROP FUNCTION blindpass_authority.open_recovery_challenge(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,TEXT);
DROP FUNCTION blindpass_authority.stage_recovery_page(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT,TEXT);
DROP FUNCTION blindpass_authority.finish_recovery_challenge(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,BYTEA,BOOLEAN,BIGINT);
DROP FUNCTION blindpass_authority.recovering_receipt_proof(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA);
DROP TABLE blindpass_authority.recovery_pages;
DROP TABLE blindpass_authority.recovery_challenges;
DROP TABLE blindpass_authority.broker_observations;
DROP FUNCTION blindpass_authority.protect_recovery_challenge();
DROP FUNCTION blindpass_authority.protect_broker_observation();
CREATE OR REPLACE FUNCTION blindpass_authority.reserve_recovery(
    p_tenant TEXT, p_issuer TEXT, p_owner TEXT, p_revision BIGINT, p_observed BIGINT
) RETURNS TABLE(epoch BIGINT, revision BIGINT, phase TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $$
BEGIN
    RETURN QUERY
    UPDATE blindpass_authority.recovery_authority AS ledger
    SET epoch = GREATEST(ledger.epoch, p_observed) + 1,
        revision = ledger.revision + 1, phase = 'recovering'
    WHERE ledger.tenant_id = p_tenant AND ledger.issuer_key_id = p_issuer
        AND ledger.owner_id = p_owner AND ledger.revision = p_revision
        AND ledger.phase = 'fenced'
        AND ledger.epoch < 9007199254740991
        AND ledger.revision < 9007199254740991
        AND p_observed BETWEEN 1 AND 9007199254740990
    RETURNING ledger.epoch, ledger.revision, ledger.phase;
END;
$$;
ALTER TABLE blindpass_authority.authority_layout DROP CONSTRAINT authority_layout_version_check;
UPDATE blindpass_authority.authority_layout SET version=3;
ALTER TABLE blindpass_authority.authority_layout ADD CONSTRAINT authority_layout_version_check CHECK(version=3);
COMMIT;
