-- SPDX-License-Identifier: AGPL-3.0-only
-- Test-only conversion in a driver-owned disposable database. Preserve the v2
-- ledger, guards and immutable attempts; remove only the v3 additions. This is
-- a reconstructed migration input, not evidence of an installed v2 deployment.
BEGIN;
DROP FUNCTION blindpass_authority.publish_broker_trust(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT,TEXT,BIGINT,TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT);
DROP TABLE blindpass_authority.broker_key_history;
DROP TABLE blindpass_authority.broker_trust;
DROP FUNCTION blindpass_authority.protect_broker_trust();
DROP FUNCTION blindpass_authority.claim_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,BYTEA);
DROP FUNCTION blindpass_authority.register_active_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA);
DROP FUNCTION blindpass_authority.held_process_proof(TEXT,INTEGER,BYTEA);
DROP FUNCTION blindpass_authority.process_proof_words(BYTEA);
DROP FUNCTION blindpass_authority.process_guard_key(TEXT);
ALTER TABLE blindpass_authority.active_process DROP COLUMN holder_token_sha256;
CREATE FUNCTION blindpass_authority.register_active_process(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    INSERT INTO blindpass_authority.active_process (tenant_id,epoch,revision,backend_pid)
    SELECT tenant_id,epoch,revision,p_backend_pid FROM blindpass_authority.recovery_authority
    WHERE tenant_id=p_tenant AND issuer_key_id=p_issuer AND owner_id=p_owner
        AND epoch=p_epoch AND revision=p_revision AND phase='active' AND p_backend_pid>0
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;
CREATE FUNCTION blindpass_authority.claim_process(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_phase TEXT
) RETURNS TABLE(epoch BIGINT,revision BIGINT,phase TEXT,backend_pid INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM 1 FROM blindpass_authority.process_guard WHERE tenant_id=p_tenant FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RETURN; END IF;
    RETURN QUERY SELECT ledger.epoch,ledger.revision,ledger.phase,pg_backend_pid()
    FROM blindpass_authority.recovery_authority AS ledger
    WHERE tenant_id=p_tenant AND issuer_key_id=p_issuer AND owner_id=p_owner
        AND ledger.epoch=p_epoch AND ledger.revision=p_revision AND ledger.phase=p_phase;
END;
$$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA blindpass_authority FROM PUBLIC;
ALTER TABLE blindpass_authority.authority_layout DROP CONSTRAINT authority_layout_version_check;
UPDATE blindpass_authority.authority_layout SET version=2;
ALTER TABLE blindpass_authority.authority_layout ADD CONSTRAINT authority_layout_version_check CHECK(version=2);
COMMIT;
