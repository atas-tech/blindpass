-- SPDX-License-Identifier: AGPL-3.0-only
-- Independent administrator only. Authenticate previous issuer/server shutdown
-- before invoking this migration. The checks below establish database exclusion,
-- not host shutdown or activation. psql requires -v runtime_role=ROLE_NAME.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='10s';
LOCK TABLE blindpass_authority.authority_layout IN ACCESS EXCLUSIVE MODE;
-- Keep the fenced-tenant snapshot stable through the entire transaction,
-- including administrator inserts and transitions on other connections.
LOCK TABLE blindpass_authority.recovery_authority, blindpass_authority.process_guard
    IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
    IF (SELECT version FROM blindpass_authority.authority_layout WHERE singleton=TRUE) IS DISTINCT FROM 2
        OR EXISTS(SELECT 1 FROM pg_class WHERE relname='controller_meta') THEN
        RAISE EXCEPTION 'unsupported authority migration source';
    END IF;
    IF EXISTS(SELECT 1 FROM blindpass_authority.recovery_authority WHERE phase<>'fenced') THEN
        RAISE EXCEPTION 'authority migration requires fenced tenants';
    END IF;
    PERFORM 1 FROM blindpass_authority.process_guard FOR UPDATE NOWAIT;
END;
$$;
-- Historical attempts have no process proof; NULL preserves that fact. They
-- remain one-use attempts and cannot authenticate a new active process.
ALTER TABLE blindpass_authority.active_process ADD COLUMN holder_token_sha256 BYTEA
    CHECK (holder_token_sha256 IS NULL OR octet_length(holder_token_sha256)=32);
DROP FUNCTION blindpass_authority.claim_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT);
DROP FUNCTION blindpass_authority.register_active_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER);
CREATE FUNCTION blindpass_authority.process_guard_key(p_tenant TEXT)
RETURNS BIGINT LANGUAGE SQL IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT (get_byte(digest,0)::BIGINT<<56) | (get_byte(digest,1)::BIGINT<<48)
        | (get_byte(digest,2)::BIGINT<<40) | (get_byte(digest,3)::BIGINT<<32)
        | (get_byte(digest,4)::BIGINT<<24) | (get_byte(digest,5)::BIGINT<<16)
        | (get_byte(digest,6)::BIGINT<<8) | get_byte(digest,7)::BIGINT
    FROM (SELECT sha256(convert_to('blindpass:process-guard:v1:' || p_tenant,'UTF8')) AS digest) AS source;
$$;

CREATE FUNCTION blindpass_authority.process_proof_words(p_token BYTEA)
RETURNS INTEGER[] LANGUAGE SQL IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT ARRAY[
        (get_byte(digest,0)<<24) | (get_byte(digest,1)<<16) | (get_byte(digest,2)<<8) | get_byte(digest,3),
        (get_byte(digest,4)<<24) | (get_byte(digest,5)<<16) | (get_byte(digest,6)<<8) | get_byte(digest,7),
        (get_byte(digest,8)<<24) | (get_byte(digest,9)<<16) | (get_byte(digest,10)<<8) | get_byte(digest,11),
        (get_byte(digest,12)<<24) | (get_byte(digest,13)<<16) | (get_byte(digest,14)<<8) | get_byte(digest,15)
    ] FROM (SELECT sha256(p_token) AS digest) AS source;
$$;

-- Two disjoint 64-bit advisory keys derive from a fresh 256-bit process token.
-- The actual holder acquires both as transaction locks. Lock metadata exposes
-- only 128 digest bits, never the token. A caller-named PID alone is not proof.
CREATE FUNCTION blindpass_authority.held_process_proof(p_tenant TEXT, p_backend_pid INTEGER, p_token BYTEA)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    digest BYTEA;
    first_class BIGINT;
    first_object BIGINT;
    second_class BIGINT;
    second_object BIGINT;
    database_oid OID;
    guard_key BIGINT;
BEGIN
    IF p_backend_pid IS NULL OR p_backend_pid <= 0 OR p_token IS NULL
        OR octet_length(p_token) <> 32 THEN RETURN FALSE; END IF;
    digest := sha256(p_token);
    first_class := get_byte(digest,0)::BIGINT*16777216 + get_byte(digest,1)::BIGINT*65536 + get_byte(digest,2)::BIGINT*256 + get_byte(digest,3);
    first_object := get_byte(digest,4)::BIGINT*16777216 + get_byte(digest,5)::BIGINT*65536 + get_byte(digest,6)::BIGINT*256 + get_byte(digest,7);
    second_class := get_byte(digest,8)::BIGINT*16777216 + get_byte(digest,9)::BIGINT*65536 + get_byte(digest,10)::BIGINT*256 + get_byte(digest,11);
    second_object := get_byte(digest,12)::BIGINT*16777216 + get_byte(digest,13)::BIGINT*65536 + get_byte(digest,14)::BIGINT*256 + get_byte(digest,15);
    IF first_class = second_class AND first_object = second_object THEN RETURN FALSE; END IF;
    SELECT oid INTO database_oid FROM pg_database WHERE datname=current_database();
    guard_key := blindpass_authority.process_guard_key(p_tenant);
    RETURN EXISTS (SELECT 1 FROM pg_locks WHERE pid=p_backend_pid AND locktype='advisory'
        AND database=database_oid AND objsubid=1 AND mode='ExclusiveLock' AND granted
        AND classid=((guard_key>>32)&4294967295)::OID AND objid=(guard_key&4294967295)::OID)
        AND EXISTS (SELECT 1 FROM pg_locks WHERE pid=p_backend_pid AND locktype='advisory'
        AND database=database_oid AND objsubid=2 AND mode='ExclusiveLock' AND granted
        AND classid=first_class::OID AND objid=first_object::OID)
        AND EXISTS (SELECT 1 FROM pg_locks WHERE pid=p_backend_pid AND locktype='advisory'
        AND database=database_oid AND objsubid=2 AND mode='ExclusiveLock' AND granted
        AND classid=second_class::OID AND objid=second_object::OID);
END;
$$;

-- Run on a separate connection and commit BEFORE returning an active holder.
-- Ambiguous registration consumes the revision; never retry/reset its attempt.
CREATE FUNCTION blindpass_authority.register_active_process(
    p_tenant TEXT, p_issuer TEXT, p_owner TEXT,
    p_epoch BIGINT, p_revision BIGINT, p_backend_pid INTEGER, p_token BYTEA
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF NOT blindpass_authority.held_process_proof(p_tenant,p_backend_pid,p_token) THEN RETURN FALSE; END IF;
    INSERT INTO blindpass_authority.active_process (tenant_id, epoch, revision, backend_pid, holder_token_sha256)
    SELECT ledger.tenant_id, ledger.epoch, ledger.revision, p_backend_pid, sha256(p_token)
    FROM blindpass_authority.recovery_authority AS ledger
    WHERE ledger.tenant_id = p_tenant AND ledger.issuer_key_id = p_issuer
        AND ledger.owner_id = p_owner AND ledger.epoch = p_epoch
        AND ledger.revision = p_revision AND ledger.phase = 'active'
        AND p_backend_pid > 0
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION blindpass_authority.claim_process(
    p_tenant TEXT, p_issuer TEXT, p_owner TEXT,
    p_epoch BIGINT, p_revision BIGINT, p_phase TEXT, p_token BYTEA
) RETURNS TABLE(epoch BIGINT, revision BIGINT, phase TEXT, backend_pid INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    words INTEGER[];
BEGIN
    IF p_token IS NULL OR octet_length(p_token) <> 32 THEN RETURN; END IF;
    PERFORM 1 FROM blindpass_authority.process_guard
    WHERE tenant_id = p_tenant FOR UPDATE NOWAIT;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    -- Fixed tenant exclusion and both secret-derived locks belong to exactly
    -- the socket that holds the process guard row. Callers cannot borrow a PID.
    IF NOT pg_try_advisory_xact_lock(blindpass_authority.process_guard_key(p_tenant)) THEN RETURN; END IF;
    words := blindpass_authority.process_proof_words(p_token);
    IF words[1]=words[3] AND words[2]=words[4] THEN RETURN; END IF;
    IF NOT pg_try_advisory_xact_lock(words[1],words[2])
        OR NOT pg_try_advisory_xact_lock(words[3],words[4]) THEN RETURN; END IF;
    RETURN QUERY SELECT ledger.epoch, ledger.revision, ledger.phase, pg_backend_pid()
    FROM blindpass_authority.recovery_authority AS ledger
    WHERE ledger.tenant_id = p_tenant AND ledger.issuer_key_id = p_issuer
        AND ledger.owner_id = p_owner AND ledger.epoch = p_epoch
        AND ledger.revision = p_revision AND ledger.phase = p_phase;
END;
$$;
-- SPDX-License-Identifier: AGPL-3.0-only
-- Current broker trust is outside controller backups.
CREATE TABLE blindpass_authority.broker_trust (
    tenant_id TEXT NOT NULL REFERENCES blindpass_authority.recovery_authority(tenant_id),
    issuer_key_id TEXT NOT NULL CHECK (issuer_key_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    node_id TEXT NOT NULL CHECK (node_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    key_version BIGINT NOT NULL CHECK (key_version BETWEEN 1 AND 9007199254740991),
    signing_public TEXT NOT NULL CHECK (signing_public ~ '^[A-Za-z0-9_-]{43}$'),
    recipient_public TEXT NOT NULL CHECK (recipient_public ~ '^[A-Za-z0-9_-]{43}$'),
    state TEXT NOT NULL CHECK (state IN ('active','revoked')),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    pending_key_version BIGINT,
    pending_rotation_id TEXT,
    pending_signing_public TEXT,
    pending_recipient_public TEXT,
    PRIMARY KEY (tenant_id,node_id),
    CHECK ((pending_key_version IS NULL AND pending_rotation_id IS NULL
        AND pending_signing_public IS NULL AND pending_recipient_public IS NULL)
        OR (state='active' AND pending_key_version IS NOT NULL AND pending_rotation_id IS NOT NULL
            AND pending_signing_public IS NOT NULL AND pending_recipient_public IS NOT NULL
            AND pending_key_version=key_version+1
            AND pending_key_version<=9007199254740991
            AND pending_rotation_id ~ '^[A-Za-z0-9_-]{1,128}$'
            AND pending_signing_public ~ '^[A-Za-z0-9_-]{43}$'
            AND pending_recipient_public ~ '^[A-Za-z0-9_-]{43}$'))
);
CREATE TABLE blindpass_authority.broker_key_history (
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    key_version BIGINT NOT NULL CHECK (key_version BETWEEN 1 AND 9007199254740991),
    signing_public TEXT NOT NULL CHECK (signing_public ~ '^[A-Za-z0-9_-]{43}$'),
    recipient_public TEXT NOT NULL CHECK (recipient_public ~ '^[A-Za-z0-9_-]{43}$'),
    PRIMARY KEY (tenant_id,node_id,key_version),
    FOREIGN KEY (tenant_id,node_id) REFERENCES blindpass_authority.broker_trust(tenant_id,node_id),
    UNIQUE (tenant_id,signing_public),
    UNIQUE (tenant_id,recipient_public)
);
CREATE FUNCTION blindpass_authority.protect_broker_trust()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'broker trust deletion is forbidden'; END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.issuer_key_id<>OLD.issuer_key_id OR NEW.node_id<>OLD.node_id
        OR NEW.key_version<OLD.key_version OR NEW.revision<>OLD.revision+1
        OR (OLD.state='revoked' AND NEW.state<>'revoked') THEN
        RAISE EXCEPTION 'invalid broker trust transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER protect_broker_trust_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.broker_trust FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_broker_trust();
CREATE TRIGGER protect_broker_trust_truncate BEFORE TRUNCATE
ON blindpass_authority.broker_trust FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_broker_trust();
CREATE TRIGGER protect_broker_history_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.broker_key_history FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_process_guard();
CREATE TRIGGER protect_broker_history_truncate BEFORE TRUNCATE
ON blindpass_authority.broker_key_history FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_process_guard();

CREATE FUNCTION blindpass_authority.publish_broker_trust(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER,p_token BYTEA,
    p_expected BIGINT,p_node TEXT,p_version BIGINT,p_signing TEXT,p_recipient TEXT,p_state TEXT,
    p_pending_version BIGINT,p_rotation TEXT,p_pending_signing TEXT,p_pending_recipient TEXT
) RETURNS SETOF blindpass_authority.broker_trust
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    previous blindpass_authority.broker_trust%ROWTYPE;
    identical BOOLEAN;
BEGIN
    IF p_expected IS NULL OR p_expected<0 OR p_expected>=9007199254740991
        OR NOT blindpass_authority.held_process_proof(p_tenant,p_backend_pid,p_token) THEN RETURN; END IF;
    PERFORM 1 FROM blindpass_authority.recovery_authority AS ledger
    JOIN blindpass_authority.active_process AS attempt ON attempt.tenant_id=ledger.tenant_id
        AND attempt.epoch=ledger.epoch AND attempt.revision=ledger.revision
    WHERE ledger.tenant_id=p_tenant AND ledger.issuer_key_id=p_issuer AND ledger.owner_id=p_owner
        AND ledger.epoch=p_epoch AND ledger.revision=p_revision AND ledger.phase='active'
        AND attempt.backend_pid=p_backend_pid AND attempt.holder_token_sha256=sha256(p_token)
    FOR SHARE OF ledger;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT * INTO previous FROM blindpass_authority.broker_trust AS trusted
    WHERE trusted.tenant_id=p_tenant AND trusted.node_id=p_node FOR UPDATE;
    IF FOUND THEN
        IF previous.issuer_key_id<>p_issuer THEN RETURN; END IF;
        identical := previous.key_version=p_version AND previous.signing_public=p_signing
            AND previous.recipient_public=p_recipient AND previous.state=p_state
            AND previous.pending_key_version IS NOT DISTINCT FROM p_pending_version
            AND previous.pending_rotation_id IS NOT DISTINCT FROM p_rotation
            AND previous.pending_signing_public IS NOT DISTINCT FROM p_pending_signing
            AND previous.pending_recipient_public IS NOT DISTINCT FROM p_pending_recipient;
        IF identical AND previous.revision IN (p_expected,p_expected+1) THEN
            RETURN NEXT previous; RETURN;
        END IF;
        IF previous.revision<>p_expected THEN RETURN; END IF;
        IF previous.state='revoked' AND (p_state<>'revoked' OR p_pending_version IS NOT NULL) THEN RETURN; END IF;
        IF p_version=previous.key_version THEN
            IF previous.signing_public<>p_signing OR previous.recipient_public<>p_recipient THEN RETURN; END IF;
            IF p_state<>'revoked' AND previous.pending_key_version IS NOT NULL
                AND (previous.pending_key_version IS DISTINCT FROM p_pending_version
                    OR previous.pending_rotation_id IS DISTINCT FROM p_rotation
                    OR previous.pending_signing_public IS DISTINCT FROM p_pending_signing
                    OR previous.pending_recipient_public IS DISTINCT FROM p_pending_recipient) THEN RETURN; END IF;
        ELSIF p_version=previous.key_version+1 THEN
            IF previous.state='revoked' THEN
                -- A candidate approved before revocation may apply late. Its
                -- retained history proves approval, never renewed authority.
                IF NOT EXISTS (SELECT 1 FROM blindpass_authority.broker_key_history AS history
                    WHERE history.tenant_id=p_tenant AND history.node_id=p_node AND history.key_version=p_version
                        AND history.signing_public=p_signing AND history.recipient_public=p_recipient) THEN RETURN; END IF;
            ELSIF previous.pending_key_version IS DISTINCT FROM p_version
                OR previous.pending_signing_public IS DISTINCT FROM p_signing
                OR previous.pending_recipient_public IS DISTINCT FROM p_recipient THEN RETURN; END IF;
            IF p_pending_version IS NOT NULL THEN RETURN; END IF;
        ELSE RETURN;
        END IF;
        UPDATE blindpass_authority.broker_trust AS trusted
        SET key_version=p_version,signing_public=p_signing,recipient_public=p_recipient,state=p_state,
            revision=trusted.revision+1,pending_key_version=p_pending_version,pending_rotation_id=p_rotation,
            pending_signing_public=p_pending_signing,pending_recipient_public=p_pending_recipient
        WHERE trusted.tenant_id=p_tenant AND trusted.node_id=p_node;
    ELSE
        IF p_expected<>0 THEN RETURN; END IF;
        INSERT INTO blindpass_authority.broker_trust VALUES (
            p_tenant,p_issuer,p_node,p_version,p_signing,p_recipient,p_state,1,
            p_pending_version,p_rotation,p_pending_signing,p_pending_recipient);
    END IF;
    -- Approved candidates are retained too. Dropping or revoking a pending
    -- rotation cannot make its public keys reusable by another identity.
    INSERT INTO blindpass_authority.broker_key_history VALUES (p_tenant,p_node,p_version,p_signing,p_recipient)
    ON CONFLICT (tenant_id,node_id,key_version) DO NOTHING;
    IF NOT EXISTS (SELECT 1 FROM blindpass_authority.broker_key_history AS history
        WHERE history.tenant_id=p_tenant AND history.node_id=p_node AND history.key_version=p_version
            AND history.signing_public=p_signing AND history.recipient_public=p_recipient) THEN
        RAISE EXCEPTION 'broker key history conflict';
    END IF;
    IF p_pending_version IS NOT NULL THEN
        INSERT INTO blindpass_authority.broker_key_history VALUES (p_tenant,p_node,p_pending_version,p_pending_signing,p_pending_recipient)
        ON CONFLICT (tenant_id,node_id,key_version) DO NOTHING;
        IF NOT EXISTS (SELECT 1 FROM blindpass_authority.broker_key_history AS history
            WHERE history.tenant_id=p_tenant AND history.node_id=p_node AND history.key_version=p_pending_version
                AND history.signing_public=p_pending_signing AND history.recipient_public=p_pending_recipient) THEN
            RAISE EXCEPTION 'broker key history conflict';
        END IF;
    END IF;
    RETURN QUERY SELECT * FROM blindpass_authority.broker_trust AS trusted
        WHERE trusted.tenant_id=p_tenant AND trusted.node_id=p_node;
END;
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA blindpass_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA blindpass_authority FROM PUBLIC;
GRANT SELECT ON blindpass_authority.broker_trust,blindpass_authority.broker_key_history TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.claim_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,BYTEA),
    blindpass_authority.register_active_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA),
    blindpass_authority.publish_broker_trust(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT,TEXT,BIGINT,TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT)
    TO :"runtime_role";
ALTER TABLE blindpass_authority.authority_layout DROP CONSTRAINT authority_layout_version_check;
UPDATE blindpass_authority.authority_layout SET version=3 WHERE singleton=TRUE;
ALTER TABLE blindpass_authority.authority_layout ADD CONSTRAINT authority_layout_version_check CHECK (version=3);
COMMIT;
