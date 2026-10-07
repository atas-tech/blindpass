-- SPDX-License-Identifier: AGPL-3.0-only
-- Independent administrator only; authenticated previous issuer/server shutdown
-- is a prerequisite. Database exclusion alone is not source-stop evidence.
-- psql requires -v runtime_role=ROLE_NAME. Preserve existing trust/attempts.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='10s';
LOCK TABLE blindpass_authority.authority_layout IN ACCESS EXCLUSIVE MODE;
LOCK TABLE blindpass_authority.recovery_authority, blindpass_authority.process_guard,
    blindpass_authority.broker_trust, blindpass_authority.broker_key_history
    IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
    IF (SELECT version FROM blindpass_authority.authority_layout WHERE singleton=TRUE) IS DISTINCT FROM 3
        OR EXISTS(SELECT 1 FROM pg_class WHERE relname='controller_meta') THEN
        RAISE EXCEPTION 'unsupported authority migration source';
    END IF;
    IF EXISTS(SELECT 1 FROM blindpass_authority.recovery_authority WHERE phase<>'fenced') THEN
        RAISE EXCEPTION 'authority migration requires fenced tenants';
    END IF;
    PERFORM 1 FROM blindpass_authority.process_guard FOR UPDATE NOWAIT;
END;
$$;
-- BEGIN RECOVERY RECEIPTS V4
-- Public identity/uncertain-operation metadata only; outside controller backups.
CREATE TABLE blindpass_authority.broker_observations (
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    observed_epoch BIGINT NOT NULL CHECK (observed_epoch BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (tenant_id,node_id),
    FOREIGN KEY (tenant_id,node_id) REFERENCES blindpass_authority.broker_trust(tenant_id,node_id)
);
CREATE FUNCTION blindpass_authority.protect_broker_observation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') OR NEW.tenant_id<>OLD.tenant_id
        OR NEW.node_id<>OLD.node_id OR NEW.observed_epoch<OLD.observed_epoch THEN
        RAISE EXCEPTION 'broker observation regression is forbidden';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER protect_broker_observation_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.broker_observations FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_broker_observation();
CREATE TRIGGER protect_broker_observation_truncate BEFORE TRUNCATE
ON blindpass_authority.broker_observations FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_broker_observation();

CREATE TABLE blindpass_authority.recovery_challenges (
    tenant_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL CHECK (recovery_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    node_id TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 2 AND 9007199254740991),
    authority_revision BIGINT NOT NULL CHECK (authority_revision BETWEEN 1 AND 9007199254740991),
    trust_revision BIGINT NOT NULL CHECK (trust_revision BETWEEN 1 AND 9007199254740991),
    node_key_version BIGINT NOT NULL CHECK (node_key_version BETWEEN 1 AND 9007199254740991),
    signing_public TEXT NOT NULL CHECK (signing_public ~ '^[A-Za-z0-9_-]{43}$'),
    node_revoked BOOLEAN NOT NULL,
    snapshot_epoch BIGINT NOT NULL CHECK (snapshot_epoch BETWEEN 1 AND 9007199254740991 AND snapshot_epoch<epoch),
    snapshot_time_ms BIGINT NOT NULL CHECK (snapshot_time_ms BETWEEN 1 AND 9007199254740991),
    backup_digest TEXT NOT NULL CHECK (backup_digest ~ '^[A-Za-z0-9_-]{43}$'),
    nonce TEXT NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),
    minimum_observed_epoch BIGINT NOT NULL CHECK (minimum_observed_epoch BETWEEN 1 AND 9007199254740991),
    next_page BIGINT NOT NULL DEFAULT 0 CHECK (next_page BETWEEN 0 AND 7813),
    manifest_json TEXT CHECK (manifest_json IS NULL OR octet_length(manifest_json)<=4096),
    state TEXT NOT NULL DEFAULT 'collecting' CHECK (state IN ('collecting','covered','incomplete','rebase_required')),
    consumed BOOLEAN NOT NULL DEFAULT FALSE CHECK (consumed=(state='covered')),
    PRIMARY KEY (tenant_id,recovery_id,node_id),
    UNIQUE (tenant_id,nonce),
    FOREIGN KEY (tenant_id,node_id) REFERENCES blindpass_authority.broker_trust(tenant_id,node_id)
);
CREATE FUNCTION blindpass_authority.protect_recovery_challenge()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'challenge deletion is forbidden'; END IF;
    IF (to_jsonb(NEW)-ARRAY['next_page','manifest_json','state','consumed']) IS DISTINCT FROM
        (to_jsonb(OLD)-ARRAY['next_page','manifest_json','state','consumed'])
        OR OLD.state<>'collecting' OR NEW.next_page<OLD.next_page
        OR NEW.next_page>OLD.next_page+1
        OR (OLD.manifest_json IS NOT NULL AND NEW.manifest_json IS DISTINCT FROM OLD.manifest_json) THEN
        RAISE EXCEPTION 'invalid challenge transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER protect_recovery_challenge_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.recovery_challenges FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_recovery_challenge();
CREATE TRIGGER protect_recovery_challenge_truncate BEFORE TRUNCATE
ON blindpass_authority.recovery_challenges FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_recovery_challenge();
CREATE TABLE blindpass_authority.recovery_pages (
    tenant_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    page_index BIGINT NOT NULL CHECK (page_index BETWEEN 0 AND 7812),
    page_json TEXT NOT NULL CHECK (octet_length(page_json)<=65536),
    signature TEXT NOT NULL CHECK (signature ~ '^[A-Za-z0-9_-]{86}$'),
    PRIMARY KEY (tenant_id,recovery_id,node_id,page_index),
    FOREIGN KEY (tenant_id,recovery_id,node_id) REFERENCES blindpass_authority.recovery_challenges(tenant_id,recovery_id,node_id)
);
CREATE TRIGGER protect_recovery_pages_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.recovery_pages FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_process_guard();
CREATE TRIGGER protect_recovery_pages_truncate BEFORE TRUNCATE
ON blindpass_authority.recovery_pages FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_process_guard();

-- Private helper. A live recovering ledger lock serializes receipt work against
-- fencing/new reservations. No returned receipt supplies source-stop/activation.
CREATE FUNCTION blindpass_authority.recovering_receipt_proof(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER,p_token BYTEA
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT blindpass_authority.held_process_proof(p_tenant,p_backend_pid,p_token) THEN RETURN FALSE; END IF;
    PERFORM 1 FROM blindpass_authority.recovery_authority AS ledger
    WHERE tenant_id=p_tenant AND issuer_key_id=p_issuer AND owner_id=p_owner
        AND epoch=p_epoch AND revision=p_revision AND phase='recovering' FOR SHARE;
    RETURN FOUND;
END;
$$;
CREATE FUNCTION blindpass_authority.open_recovery_challenge(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER,p_token BYTEA,
    p_recovery TEXT,p_node TEXT,p_version BIGINT,p_snapshot_epoch BIGINT,p_snapshot_time BIGINT,p_backup TEXT,p_nonce TEXT
) RETURNS SETOF blindpass_authority.recovery_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    trusted blindpass_authority.broker_trust%ROWTYPE;
    prior blindpass_authority.recovery_challenges%ROWTYPE;
    public_key TEXT;
    minimum BIGINT;
BEGIN
    IF NOT blindpass_authority.recovering_receipt_proof(p_tenant,p_issuer,p_owner,p_epoch,p_revision,p_backend_pid,p_token) THEN RETURN; END IF;
    SELECT * INTO trusted FROM blindpass_authority.broker_trust WHERE tenant_id=p_tenant AND node_id=p_node AND issuer_key_id=p_issuer FOR SHARE;
    IF NOT FOUND THEN RETURN; END IF;
    IF trusted.key_version=p_version THEN public_key:=trusted.signing_public;
    ELSIF trusted.pending_key_version=p_version THEN public_key:=trusted.pending_signing_public;
    ELSE RETURN; END IF;
    SELECT * INTO prior FROM blindpass_authority.recovery_challenges WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node FOR UPDATE;
    IF FOUND THEN
        IF prior.issuer_key_id<>p_issuer OR prior.owner_id<>p_owner OR prior.epoch<>p_epoch
            OR prior.authority_revision<>p_revision OR prior.trust_revision<>trusted.revision
            OR prior.node_key_version<>p_version OR prior.signing_public<>public_key
            OR prior.node_revoked<>(trusted.state='revoked') OR prior.snapshot_epoch<>p_snapshot_epoch
            OR prior.snapshot_time_ms<>p_snapshot_time OR prior.backup_digest<>p_backup THEN RETURN; END IF;
        RETURN NEXT prior; RETURN;
    END IF;
    SELECT COALESCE(MAX(observed_epoch),1) INTO minimum FROM blindpass_authority.broker_observations WHERE tenant_id=p_tenant AND node_id=p_node;
    INSERT INTO blindpass_authority.recovery_challenges
        (tenant_id,recovery_id,node_id,issuer_key_id,owner_id,epoch,authority_revision,trust_revision,node_key_version,signing_public,node_revoked,snapshot_epoch,snapshot_time_ms,backup_digest,nonce,minimum_observed_epoch)
    VALUES (p_tenant,p_recovery,p_node,p_issuer,p_owner,p_epoch,p_revision,trusted.revision,p_version,public_key,trusted.state='revoked',p_snapshot_epoch,p_snapshot_time,p_backup,p_nonce,minimum)
    ON CONFLICT DO NOTHING;
    -- A concurrent creator wins one nonce. Caller reads/retries explicitly;
    -- never overwrite a nonce or infer success from an uncertain result.
    RETURN QUERY SELECT * FROM blindpass_authority.recovery_challenges WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node
        AND issuer_key_id=p_issuer AND owner_id=p_owner AND epoch=p_epoch AND authority_revision=p_revision
        AND trust_revision=trusted.revision AND node_key_version=p_version AND signing_public=public_key
        AND snapshot_epoch=p_snapshot_epoch AND snapshot_time_ms=p_snapshot_time AND backup_digest=p_backup;
END;
$$;
CREATE FUNCTION blindpass_authority.stage_recovery_page(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER,p_token BYTEA,
    p_recovery TEXT,p_node TEXT,p_nonce TEXT,p_trust_revision BIGINT,p_index BIGINT,p_manifest TEXT,p_page TEXT,p_signature TEXT
) RETURNS SETOF blindpass_authority.recovery_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    challenge blindpass_authority.recovery_challenges%ROWTYPE;
    header JSONB;
    page JSONB;
    observation BIGINT;
    maximum BIGINT;
BEGIN
    IF NOT blindpass_authority.recovering_receipt_proof(p_tenant,p_issuer,p_owner,p_epoch,p_revision,p_backend_pid,p_token) THEN RETURN; END IF;
    IF p_index IS NULL OR p_index<0 OR p_index>7812 OR p_manifest IS NULL OR octet_length(p_manifest)>4096
        OR p_page IS NULL OR octet_length(p_page)>65536 OR p_signature IS NULL OR p_signature!~'^[A-Za-z0-9_-]{86}$' THEN RETURN; END IF;
    SELECT * INTO challenge FROM blindpass_authority.recovery_challenges WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node FOR UPDATE;
    IF NOT FOUND OR challenge.state<>'collecting' OR challenge.issuer_key_id<>p_issuer OR challenge.owner_id<>p_owner
        OR challenge.epoch<>p_epoch OR challenge.authority_revision<>p_revision OR challenge.nonce<>p_nonce
        OR challenge.trust_revision<>p_trust_revision THEN RETURN; END IF;
    PERFORM 1 FROM blindpass_authority.broker_trust WHERE tenant_id=p_tenant AND node_id=p_node AND issuer_key_id=p_issuer
        AND revision=p_trust_revision AND (state='revoked')=challenge.node_revoked
        AND ((key_version=challenge.node_key_version AND signing_public=challenge.signing_public)
            OR (pending_key_version=challenge.node_key_version AND pending_signing_public=challenge.signing_public)) FOR SHARE;
    IF NOT FOUND THEN RETURN; END IF;
    IF p_index<challenge.next_page THEN
        IF EXISTS (SELECT 1 FROM blindpass_authority.recovery_pages WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node
            AND page_index=p_index AND page_json=p_page AND signature=p_signature) THEN RETURN NEXT challenge; END IF;
        RETURN;
    END IF;
    IF p_index<>challenge.next_page OR (challenge.manifest_json IS NOT NULL AND challenge.manifest_json<>p_manifest) THEN RETURN; END IF;
    header:=p_manifest::JSONB; page:=p_page::JSONB;
    IF (page-ARRAY['page_index','records'])<>header OR (page->>'page_index')::BIGINT<>p_index
        OR jsonb_array_length(page->'records')>128 OR header->>'tenant_id'<>p_tenant OR header->>'node_id'<>p_node
        OR header->>'issuer_key_id'<>p_issuer OR header->>'recovery_id'<>p_recovery OR header->>'challenge'<>p_nonce
        OR (header->>'node_key_version')::BIGINT<>challenge.node_key_version OR (header->>'recovery_generation')::BIGINT<>p_epoch
        OR (header->>'version')::BIGINT<>2 OR (header->>'total_records')::BIGINT NOT BETWEEN 0 AND 1000000 THEN RETURN; END IF;
    observation:=(header->>'observed_issuer_epoch')::BIGINT;
    SELECT COALESCE(MAX(observed_epoch),1) INTO maximum FROM blindpass_authority.broker_observations WHERE tenant_id=p_tenant AND node_id=p_node;
    IF observation IS NULL OR observation<maximum OR observation<challenge.minimum_observed_epoch OR observation>9007199254740991 THEN RETURN; END IF;
    INSERT INTO blindpass_authority.broker_observations VALUES (p_tenant,p_node,observation)
    ON CONFLICT (tenant_id,node_id) DO UPDATE SET observed_epoch=GREATEST(blindpass_authority.broker_observations.observed_epoch,EXCLUDED.observed_epoch);
    INSERT INTO blindpass_authority.recovery_pages VALUES (p_tenant,p_recovery,p_node,p_index,p_page,p_signature);
    UPDATE blindpass_authority.recovery_challenges SET next_page=next_page+1,manifest_json=p_manifest
    WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node;
    RETURN QUERY SELECT * FROM blindpass_authority.recovery_challenges WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node;
END;
$$;
CREATE FUNCTION blindpass_authority.finish_recovery_challenge(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER,p_token BYTEA,
    p_recovery TEXT,p_node TEXT,p_nonce TEXT,p_trust_revision BIGINT,p_count BIGINT,p_manifest_digest BYTEA,p_coverage BOOLEAN,p_observed BIGINT
) RETURNS SETOF blindpass_authority.recovery_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    challenge blindpass_authority.recovery_challenges%ROWTYPE;
    outcome TEXT;
    maximum BIGINT;
BEGIN
    IF NOT blindpass_authority.recovering_receipt_proof(p_tenant,p_issuer,p_owner,p_epoch,p_revision,p_backend_pid,p_token) THEN RETURN; END IF;
    SELECT * INTO challenge FROM blindpass_authority.recovery_challenges WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node FOR UPDATE;
    IF NOT FOUND OR challenge.state<>'collecting' OR challenge.issuer_key_id<>p_issuer OR challenge.owner_id<>p_owner
        OR challenge.epoch<>p_epoch OR challenge.authority_revision<>p_revision OR challenge.nonce<>p_nonce
        OR challenge.trust_revision<>p_trust_revision OR challenge.manifest_json IS NULL OR p_count<>challenge.next_page
        OR sha256(convert_to(challenge.manifest_json,'UTF8')) IS DISTINCT FROM p_manifest_digest
        OR (challenge.manifest_json::JSONB->>'observed_issuer_epoch')::BIGINT IS DISTINCT FROM p_observed
        OR p_coverage IS NULL THEN RETURN; END IF;
    IF p_count<>GREATEST(1,((challenge.manifest_json::JSONB->>'total_records')::BIGINT+127)/128)
        OR p_count<>(SELECT count(*) FROM blindpass_authority.recovery_pages WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node) THEN RETURN; END IF;
    PERFORM 1 FROM blindpass_authority.broker_trust WHERE tenant_id=p_tenant AND node_id=p_node AND issuer_key_id=p_issuer
        AND revision=p_trust_revision AND (state='revoked')=challenge.node_revoked
        AND ((key_version=challenge.node_key_version AND signing_public=challenge.signing_public)
            OR (pending_key_version=challenge.node_key_version AND pending_signing_public=challenge.signing_public)) FOR SHARE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT COALESCE(MAX(observed_epoch),1) INTO maximum FROM blindpass_authority.broker_observations WHERE tenant_id=p_tenant AND node_id=p_node;
    IF GREATEST(maximum,p_observed)>=p_epoch THEN outcome:='rebase_required';
    ELSIF NOT p_coverage THEN outcome:='incomplete'; ELSE outcome:='covered'; END IF;
    UPDATE blindpass_authority.recovery_challenges SET state=outcome,consumed=(outcome='covered')
    WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node;
    RETURN QUERY SELECT * FROM blindpass_authority.recovery_challenges WHERE tenant_id=p_tenant AND recovery_id=p_recovery AND node_id=p_node;
END;
$$;

-- Lock the ledger before taking a fresh observation snapshot. An in-flight
-- authenticated report cannot be hidden by stale caller input or a lock wait.
CREATE OR REPLACE FUNCTION blindpass_authority.reserve_recovery(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_revision BIGINT,p_observed BIGINT
) RETURNS TABLE(epoch BIGINT,revision BIGINT,phase TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    ledger blindpass_authority.recovery_authority%ROWTYPE;
    maximum BIGINT;
BEGIN
    IF p_observed IS NULL OR p_observed NOT BETWEEN 1 AND 9007199254740990 THEN RETURN; END IF;
    SELECT * INTO ledger FROM blindpass_authority.recovery_authority AS locked
    WHERE locked.tenant_id=p_tenant AND locked.issuer_key_id=p_issuer AND locked.owner_id=p_owner
        AND locked.revision=p_revision AND locked.phase='fenced' FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT GREATEST(ledger.epoch,p_observed,COALESCE(MAX(observed_epoch),1)) INTO maximum
    FROM blindpass_authority.broker_observations WHERE tenant_id=p_tenant;
    IF maximum>=9007199254740991 OR ledger.revision>=9007199254740991 THEN RETURN; END IF;
    RETURN QUERY UPDATE blindpass_authority.recovery_authority AS current
    SET epoch=maximum+1,revision=current.revision+1,phase='recovering'
    WHERE current.tenant_id=p_tenant AND current.revision=p_revision
    RETURNING current.epoch,current.revision,current.phase;
END;
$$;
-- END RECOVERY RECEIPTS V4

REVOKE ALL ON ALL TABLES IN SCHEMA blindpass_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA blindpass_authority FROM PUBLIC;
GRANT SELECT ON blindpass_authority.broker_observations, blindpass_authority.recovery_challenges, blindpass_authority.recovery_pages TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.open_recovery_challenge(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,TEXT),
    blindpass_authority.stage_recovery_page(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT,TEXT),
    blindpass_authority.finish_recovery_challenge(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,BYTEA,BOOLEAN,BIGINT)
    TO :"runtime_role";
ALTER TABLE blindpass_authority.authority_layout DROP CONSTRAINT authority_layout_version_check;
UPDATE blindpass_authority.authority_layout SET version=4 WHERE singleton=TRUE;
ALTER TABLE blindpass_authority.authority_layout ADD CONSTRAINT authority_layout_version_check CHECK(version=4);
COMMIT;
