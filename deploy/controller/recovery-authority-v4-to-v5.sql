-- SPDX-License-Identifier: AGPL-3.0-only
-- Independent administrator only. Layout 4 -> 5 adds protected recovery activation
-- (P06-D30..D32): source-stop attestation, node waivers, operator review decisions,
-- the review-complete barrier and administrator-only activation of a `recovering`
-- record. psql requires -v runtime_role=ROLE_NAME. Existing trust, receipts and
-- tenants are preserved; every tenant must be fenced and no process may hold a guard.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='10s';
LOCK TABLE blindpass_authority.authority_layout IN ACCESS EXCLUSIVE MODE;
LOCK TABLE blindpass_authority.recovery_authority, blindpass_authority.process_guard,
    blindpass_authority.broker_trust, blindpass_authority.recovery_challenges
    IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
    IF (SELECT version FROM blindpass_authority.authority_layout WHERE singleton=TRUE) IS DISTINCT FROM 4 THEN
        RAISE EXCEPTION 'unsupported authority migration source';
    END IF;
    IF EXISTS(SELECT 1 FROM blindpass_authority.recovery_authority WHERE phase<>'fenced') THEN
        RAISE EXCEPTION 'authority migration requires fenced tenants';
    END IF;
    PERFORM 1 FROM blindpass_authority.process_guard FOR UPDATE NOWAIT;
END;
$$;
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
GRANT SELECT ON blindpass_authority.recovery_source_stop, blindpass_authority.recovery_node_waivers,
    blindpass_authority.recovery_review_decisions, blindpass_authority.recovery_review_complete,
    blindpass_authority.recovery_activations TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.decide_recovery_item(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT),
    blindpass_authority.waive_recovery_node(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT),
    blindpass_authority.complete_recovery_review(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT),
    blindpass_authority.recovery_activation_gaps(TEXT,TEXT,TEXT,BOOLEAN)
    TO :"runtime_role";
ALTER TABLE blindpass_authority.authority_layout DROP CONSTRAINT authority_layout_version_check;
UPDATE blindpass_authority.authority_layout SET version=5 WHERE singleton=TRUE;
ALTER TABLE blindpass_authority.authority_layout ADD CONSTRAINT authority_layout_version_check CHECK(version=5);
COMMIT;
