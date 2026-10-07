-- SPDX-License-Identifier: AGPL-3.0-only
-- Run as the independent authority administrator AFTER recovery-authority.sql,
-- in the SEPARATE authority database. Create the runtime LOGIN role yourself
-- (no SUPERUSER/CREATEROLE/CREATEDB, not a member of the owner or any
-- privileged role, password stored only in the controller's authority URL file):
--
--   CREATE ROLE blindpass_runtime LOGIN PASSWORD '...';
--   psql -v ON_ERROR_STOP=1 -v runtime_role=blindpass_runtime -f authority-runtime-role.sql
--
-- The role gets read access and EXECUTE on the eleven reviewed functions only:
-- no table writes, no schema CREATE. The controller refuses a credential with
-- more than this.
\set ON_ERROR_STOP on
BEGIN;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA blindpass_authority TO :"runtime_role";
GRANT SELECT ON ALL TABLES IN SCHEMA blindpass_authority TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.reserve_recovery(TEXT,TEXT,TEXT,BIGINT,BIGINT) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.claim_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,BYTEA) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.register_active_process(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.publish_broker_trust(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT,TEXT,BIGINT,TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.open_recovery_challenge(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,TEXT) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.stage_recovery_page(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT,TEXT) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.finish_recovery_challenge(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,BYTEA,BOOLEAN,BIGINT) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.decide_recovery_item(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.waive_recovery_node(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.complete_recovery_review(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT) TO :"runtime_role";
GRANT EXECUTE ON FUNCTION blindpass_authority.recovery_activation_gaps(TEXT,TEXT,TEXT,BOOLEAN) TO :"runtime_role";
COMMIT;
