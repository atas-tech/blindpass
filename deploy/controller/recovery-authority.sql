-- SPDX-License-Identifier: AGPL-3.0-only
-- Run once as the independent authority administrator in a SEPARATE database.
-- This schema and its credentials must never be in a controller backup.
-- Provision runtime grants explicitly; startup never executes this file.
BEGIN;
CREATE SCHEMA blindpass_authority;
REVOKE ALL ON SCHEMA blindpass_authority FROM PUBLIC;

CREATE TABLE blindpass_authority.authority_layout (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    version BIGINT NOT NULL CHECK (version = 5)
);
INSERT INTO blindpass_authority.authority_layout VALUES (TRUE, 5);

CREATE TABLE blindpass_authority.recovery_authority (
    tenant_id TEXT PRIMARY KEY CHECK (tenant_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    issuer_key_id TEXT NOT NULL CHECK (issuer_key_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    owner_id TEXT NOT NULL CHECK (owner_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 1 AND 9007199254740991),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    phase TEXT NOT NULL CHECK (phase IN ('fenced', 'recovering', 'active'))
);

-- No restored controller flag represents this lock. A dedicated connection
-- holds this row in an open transaction; a second connection must refuse.
CREATE TABLE blindpass_authority.process_guard (
    tenant_id TEXT PRIMARY KEY REFERENCES blindpass_authority.recovery_authority(tenant_id)
);
CREATE FUNCTION blindpass_authority.provision_process_guard()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    INSERT INTO blindpass_authority.process_guard VALUES (NEW.tenant_id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER provision_process_guard AFTER INSERT
ON blindpass_authority.recovery_authority FOR EACH ROW
EXECUTE FUNCTION blindpass_authority.provision_process_guard();
CREATE FUNCTION blindpass_authority.protect_process_guard()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'process guard mutation is forbidden';
END;
$$;
CREATE TRIGGER protect_process_guard_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.process_guard FOR EACH ROW
EXECUTE FUNCTION blindpass_authority.protect_process_guard();
CREATE TRIGGER protect_process_guard_truncate BEFORE TRUNCATE
ON blindpass_authority.process_guard FOR EACH STATEMENT
EXECUTE FUNCTION blindpass_authority.protect_process_guard();

-- Append-only, durable attempts prevent connection loss from allowing another
-- active process to reuse the same external revision. These rows are not locks
-- or proof that the previous issuer stopped, and cannot authorize activation.
CREATE TABLE blindpass_authority.active_process (
    tenant_id TEXT NOT NULL REFERENCES blindpass_authority.recovery_authority(tenant_id),
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 1 AND 9007199254740991),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    backend_pid INTEGER NOT NULL CHECK (backend_pid > 0),
    holder_token_sha256 BYTEA CHECK (holder_token_sha256 IS NULL OR octet_length(holder_token_sha256) = 32),
    PRIMARY KEY (tenant_id, epoch, revision)
);
CREATE TRIGGER protect_active_process_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.active_process FOR EACH ROW
EXECUTE FUNCTION blindpass_authority.protect_process_guard();
CREATE TRIGGER protect_active_process_truncate BEFORE TRUNCATE
ON blindpass_authority.active_process FOR EACH STATEMENT
EXECUTE FUNCTION blindpass_authority.protect_process_guard();

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

CREATE FUNCTION blindpass_authority.protect_recovery_authority()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'authority deletion is forbidden';
    END IF;
    IF NEW.tenant_id <> OLD.tenant_id OR NEW.issuer_key_id <> OLD.issuer_key_id
        OR NEW.epoch < OLD.epoch OR NEW.revision <> OLD.revision + 1
        OR (NEW.owner_id <> OLD.owner_id
            AND (OLD.phase <> 'fenced' OR NEW.phase <> 'fenced')) THEN
        RAISE EXCEPTION 'invalid authority transition';
    END IF;
    -- An administrator may fence an existing holder. Other transitions wait
    -- for explicit quiescence/release; transport loss alone proves no shutdown.
    IF NOT (NEW.phase = 'fenced' AND NEW.owner_id = OLD.owner_id
            AND NEW.epoch = OLD.epoch) THEN
        PERFORM 1 FROM blindpass_authority.process_guard
        WHERE tenant_id = OLD.tenant_id FOR UPDATE NOWAIT;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'process guard is missing';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

-- Caller MUST keep this transaction/connection open. A returned record is
-- neither durable activation nor proof that a disconnected issuer stopped.
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
CREATE TRIGGER protect_authority_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.recovery_authority FOR EACH ROW
EXECUTE FUNCTION blindpass_authority.protect_recovery_authority();
CREATE TRIGGER protect_authority_truncate BEFORE TRUNCATE
ON blindpass_authority.recovery_authority FOR EACH STATEMENT
EXECUTE FUNCTION blindpass_authority.protect_recovery_authority();

-- A reservation is durable metadata, never permission to activate an issuer.
-- The caller must use a trusted external/broker observed maximum, not a
-- snapshot's own epoch as its only evidence. Interrupted reservations persist.
CREATE FUNCTION blindpass_authority.reserve_recovery(
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

-- BEGIN BROKER TRUST V3
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
-- END BROKER TRUST V3

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

-- BEGIN RECOVERY ACTIVATION V5
-- Protected activation of a restored (`recovering`) record (P06-D30..D32). Everything
-- here lives outside controller backups. Attestations, waivers, decisions and the
-- completion row are insert-only evidence for one recovery epoch; none of them
-- activates anything by itself. `activate_recovery` is administrator-only.
CREATE TABLE blindpass_authority.recovery_source_stop (
    tenant_id TEXT NOT NULL REFERENCES blindpass_authority.recovery_authority(tenant_id),
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 2 AND 9007199254740991),
    host_id TEXT NOT NULL CHECK (host_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    attested_by TEXT NOT NULL CHECK (attested_by ~ '^[A-Za-z0-9_.@-]{1,128}$'),
    note TEXT NOT NULL CHECK (octet_length(note)<=512),
    attested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,epoch)
);
CREATE TABLE blindpass_authority.recovery_node_waivers (
    tenant_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 2 AND 9007199254740991),
    node_id TEXT NOT NULL,
    waived_by TEXT NOT NULL CHECK (waived_by ~ '^[A-Za-z0-9_.@-]{1,128}$'),
    note TEXT NOT NULL CHECK (octet_length(note)<=512),
    waived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,epoch,node_id),
    FOREIGN KEY (tenant_id,node_id) REFERENCES blindpass_authority.broker_trust(tenant_id,node_id)
);
CREATE TABLE blindpass_authority.recovery_review_decisions (
    tenant_id TEXT NOT NULL REFERENCES blindpass_authority.recovery_authority(tenant_id),
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 2 AND 9007199254740991),
    category TEXT NOT NULL CHECK (category IN ('operation','agent','operator','legacy_policy','fleet_policy','workload','source_binding','node_key_rotation','grant_intent')),
    subject_id TEXT NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 256),
    related_id TEXT NOT NULL CHECK (octet_length(related_id)<=256),
    decision TEXT NOT NULL CHECK (decision IN ('accept','reject','revoke')),
    operator_id TEXT NOT NULL CHECK (operator_id ~ '^[A-Za-z0-9_.@-]{1,128}$'),
    note TEXT NOT NULL CHECK (octet_length(note)<=512),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,epoch,category,subject_id,related_id)
);
CREATE TABLE blindpass_authority.recovery_review_complete (
    tenant_id TEXT NOT NULL REFERENCES blindpass_authority.recovery_authority(tenant_id),
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 2 AND 9007199254740991),
    item_count BIGINT NOT NULL CHECK (item_count BETWEEN 0 AND 9007199254740991),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,epoch)
);
CREATE TABLE blindpass_authority.recovery_activations (
    tenant_id TEXT NOT NULL REFERENCES blindpass_authority.recovery_authority(tenant_id),
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 2 AND 9007199254740991),
    activated_revision BIGINT NOT NULL CHECK (activated_revision BETWEEN 1 AND 9007199254740991),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,epoch)
);
CREATE FUNCTION blindpass_authority.protect_recovery_evidence()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'recovery evidence deletion is forbidden'; END IF;
    IF TG_TABLE_NAME='recovery_review_decisions' THEN
        IF NEW.tenant_id<>OLD.tenant_id OR NEW.epoch<>OLD.epoch OR NEW.category<>OLD.category
            OR NEW.subject_id<>OLD.subject_id OR NEW.related_id<>OLD.related_id
            OR EXISTS (SELECT 1 FROM blindpass_authority.recovery_review_complete AS done
                WHERE done.tenant_id=OLD.tenant_id AND done.epoch=OLD.epoch) THEN
            RAISE EXCEPTION 'recovery decisions are final after completion';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'recovery evidence is insert-only';
END;
$$;
CREATE TRIGGER protect_recovery_source_stop_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.recovery_source_stop FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_source_stop_truncate BEFORE TRUNCATE
ON blindpass_authority.recovery_source_stop FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_node_waivers_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.recovery_node_waivers FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_node_waivers_truncate BEFORE TRUNCATE
ON blindpass_authority.recovery_node_waivers FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_review_decisions_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.recovery_review_decisions FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_review_decisions_truncate BEFORE TRUNCATE
ON blindpass_authority.recovery_review_decisions FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_review_complete_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.recovery_review_complete FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_review_complete_truncate BEFORE TRUNCATE
ON blindpass_authority.recovery_review_complete FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_activations_rows BEFORE UPDATE OR DELETE
ON blindpass_authority.recovery_activations FOR EACH ROW EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();
CREATE TRIGGER protect_recovery_activations_truncate BEFORE TRUNCATE
ON blindpass_authority.recovery_activations FOR EACH STATEMENT EXECUTE FUNCTION blindpass_authority.protect_recovery_evidence();

-- Operator decision for one quarantined item. Only the live recovering holder may call it.
CREATE FUNCTION blindpass_authority.decide_recovery_item(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER,p_token BYTEA,
    p_category TEXT,p_subject TEXT,p_related TEXT,p_decision TEXT,p_operator TEXT,p_note TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT blindpass_authority.recovering_receipt_proof(p_tenant,p_issuer,p_owner,p_epoch,p_revision,p_backend_pid,p_token) THEN RETURN FALSE; END IF;
    IF EXISTS (SELECT 1 FROM blindpass_authority.recovery_review_complete WHERE tenant_id=p_tenant AND epoch=p_epoch) THEN RETURN FALSE; END IF;
    INSERT INTO blindpass_authority.recovery_review_decisions
        (tenant_id,epoch,category,subject_id,related_id,decision,operator_id,note)
    VALUES (p_tenant,p_epoch,p_category,p_subject,p_related,p_decision,p_operator,p_note)
    ON CONFLICT (tenant_id,epoch,category,subject_id,related_id) DO UPDATE
    SET decision=EXCLUDED.decision,operator_id=EXCLUDED.operator_id,note=EXCLUDED.note,decided_at=now();
    RETURN TRUE;
END;
$$;
-- Named waiver for a node that cannot report (offline or lost). The node's broker
-- trust is revoked in the same transaction, so a waived node can never be admitted
-- by a later activation. Refused once review completion is recorded.
CREATE FUNCTION blindpass_authority.waive_recovery_node(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER,p_token BYTEA,
    p_node TEXT,p_by TEXT,p_note TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT blindpass_authority.recovering_receipt_proof(p_tenant,p_issuer,p_owner,p_epoch,p_revision,p_backend_pid,p_token) THEN RETURN FALSE; END IF;
    IF EXISTS (SELECT 1 FROM blindpass_authority.recovery_review_complete WHERE tenant_id=p_tenant AND epoch=p_epoch) THEN RETURN FALSE; END IF;
    PERFORM 1 FROM blindpass_authority.broker_trust WHERE tenant_id=p_tenant AND node_id=p_node AND issuer_key_id=p_issuer FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    IF EXISTS (SELECT 1 FROM blindpass_authority.recovery_challenges
        WHERE tenant_id=p_tenant AND node_id=p_node AND epoch=p_epoch AND authority_revision=p_revision AND state='covered') THEN RETURN FALSE; END IF;
    INSERT INTO blindpass_authority.recovery_node_waivers (tenant_id,epoch,node_id,waived_by,note)
    VALUES (p_tenant,p_epoch,p_node,p_by,p_note) ON CONFLICT DO NOTHING;
    UPDATE blindpass_authority.broker_trust
    SET state='revoked',revision=revision+1,pending_key_version=NULL,pending_rotation_id=NULL,
        pending_signing_public=NULL,pending_recipient_public=NULL
    WHERE tenant_id=p_tenant AND node_id=p_node AND state='active';
    RETURN TRUE;
END;
$$;
-- The operator's review is complete: every item the controller enumerated has a
-- decision. The authority can only check the count it is given against the rows it
-- holds; item enumeration stays controller-side.
CREATE FUNCTION blindpass_authority.complete_recovery_review(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_epoch BIGINT,p_revision BIGINT,p_backend_pid INTEGER,p_token BYTEA,
    p_count BIGINT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    decided BIGINT;
BEGIN
    IF NOT blindpass_authority.recovering_receipt_proof(p_tenant,p_issuer,p_owner,p_epoch,p_revision,p_backend_pid,p_token) THEN RETURN FALSE; END IF;
    IF p_count IS NULL OR p_count<0 THEN RETURN FALSE; END IF;
    IF EXISTS (SELECT 1 FROM blindpass_authority.recovery_review_complete WHERE tenant_id=p_tenant AND epoch=p_epoch AND item_count=p_count) THEN RETURN TRUE; END IF;
    SELECT count(*) INTO decided FROM blindpass_authority.recovery_review_decisions WHERE tenant_id=p_tenant AND epoch=p_epoch;
    IF decided<>p_count THEN RETURN FALSE; END IF;
    INSERT INTO blindpass_authority.recovery_review_complete (tenant_id,epoch,item_count) VALUES (p_tenant,p_epoch,p_count) ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;
-- Fixed gate names only. The guard check is for the administrator path: the recovering
-- controller itself holds the guard, so its own precheck passes FALSE.
CREATE FUNCTION blindpass_authority.recovery_activation_gaps(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_check_guard BOOLEAN
) RETURNS TEXT[] LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    ledger blindpass_authority.recovery_authority%ROWTYPE;
    gaps TEXT[]:=ARRAY[]::TEXT[];
BEGIN
    SELECT * INTO ledger FROM blindpass_authority.recovery_authority
    WHERE tenant_id=p_tenant AND issuer_key_id=p_issuer AND owner_id=p_owner;
    IF NOT FOUND OR ledger.phase<>'recovering' THEN RETURN ARRAY['not_recovering']; END IF;
    IF NOT EXISTS (SELECT 1 FROM blindpass_authority.recovery_source_stop WHERE tenant_id=p_tenant AND epoch=ledger.epoch) THEN
        gaps:=array_append(gaps,'source_stop_missing'::TEXT);
    END IF;
    IF p_check_guard AND NOT EXISTS (SELECT 1 FROM blindpass_authority.process_guard WHERE tenant_id=p_tenant FOR UPDATE SKIP LOCKED) THEN
        gaps:=array_append(gaps,'source_process_live'::TEXT);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM blindpass_authority.recovery_review_complete WHERE tenant_id=p_tenant AND epoch=ledger.epoch) THEN
        gaps:=array_append(gaps,'review_incomplete'::TEXT);
    END IF;
    IF EXISTS (SELECT 1 FROM blindpass_authority.broker_trust AS trusted
        WHERE trusted.tenant_id=p_tenant AND trusted.state='active'
        AND NOT EXISTS (SELECT 1 FROM blindpass_authority.recovery_challenges AS receipt
            WHERE receipt.tenant_id=p_tenant AND receipt.node_id=trusted.node_id AND receipt.epoch=ledger.epoch
            AND receipt.authority_revision=ledger.revision AND receipt.state='covered')
        AND NOT EXISTS (SELECT 1 FROM blindpass_authority.recovery_node_waivers AS waiver
            WHERE waiver.tenant_id=p_tenant AND waiver.node_id=trusted.node_id AND waiver.epoch=ledger.epoch)) THEN
        gaps:=array_append(gaps,'node_uncovered'::TEXT);
    END IF;
    RETURN gaps;
END;
$$;
-- Administrator only (never granted to the runtime role). The live-process refusal is
-- raised by the lock, not inferred from a flag a restored database could carry.
CREATE FUNCTION blindpass_authority.attest_source_stop(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_host TEXT,p_by TEXT,p_note TEXT
) RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    ledger blindpass_authority.recovery_authority%ROWTYPE;
BEGIN
    SELECT * INTO ledger FROM blindpass_authority.recovery_authority
    WHERE tenant_id=p_tenant AND issuer_key_id=p_issuer AND owner_id=p_owner AND phase='recovering' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'source-stop attestation refused: no matching recovering record'; END IF;
    PERFORM 1 FROM blindpass_authority.process_guard WHERE tenant_id=p_tenant FOR UPDATE NOWAIT;
    INSERT INTO blindpass_authority.recovery_source_stop (tenant_id,epoch,host_id,attested_by,note)
    VALUES (p_tenant,ledger.epoch,p_host,p_by,p_note);
    RETURN ledger.epoch;
END;
$$;
CREATE FUNCTION blindpass_authority.activate_recovery(
    p_tenant TEXT,p_issuer TEXT,p_owner TEXT,p_revision BIGINT
) RETURNS TABLE(epoch BIGINT,revision BIGINT,phase TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    gaps TEXT[];
    activated_epoch BIGINT;
    activated_revision BIGINT;
BEGIN
    PERFORM 1 FROM blindpass_authority.recovery_authority AS locked
    WHERE locked.tenant_id=p_tenant AND locked.issuer_key_id=p_issuer AND locked.owner_id=p_owner
        AND locked.revision=p_revision AND locked.phase='recovering' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'recovery activation refused: not_recovering'; END IF;
    gaps:=blindpass_authority.recovery_activation_gaps(p_tenant,p_issuer,p_owner,TRUE);
    IF cardinality(gaps)>0 THEN
        RAISE EXCEPTION 'recovery activation refused: %',array_to_string(gaps,',');
    END IF;
    UPDATE blindpass_authority.recovery_authority AS current
    SET phase='active',revision=current.revision+1
    WHERE current.tenant_id=p_tenant AND current.revision=p_revision
    RETURNING current.epoch,current.revision INTO activated_epoch,activated_revision;
    -- The controller opens a recovered store for ordinary service only against this row;
    -- fencing a recovering record and re-activating it elsewhere does not create one.
    INSERT INTO blindpass_authority.recovery_activations (tenant_id,epoch,activated_revision)
    VALUES (p_tenant,activated_epoch,activated_revision);
    RETURN QUERY SELECT activated_epoch,activated_revision,'active'::TEXT;
END;
$$;
-- END RECOVERY ACTIVATION V5


REVOKE ALL ON ALL TABLES IN SCHEMA blindpass_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA blindpass_authority FROM PUBLIC;
COMMIT;

-- Independently insert the initial fenced tenant/key/owner row, once. Refuse
-- a conflicting row; never use ON CONFLICT UPDATE to reinitialize an identity.
-- For a dedicated runtime role grant ONLY schema USAGE, table SELECT and
-- EXECUTE on reserve_recovery, claim_process, register_active_process,
-- publish_broker_trust, open_recovery_challenge, stage_recovery_page and
-- finish_recovery_challenge using the exact signatures in ADR 0012. Never grant
-- the private proof/trigger helpers. No table writes, schema CREATE, administrator
-- role membership or superuser permission. Runtime connection audits these grants.
