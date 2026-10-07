#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Test authority metadata on the existing PG fixture; own every created resource."""

import argparse
import os
from pathlib import Path
import secrets
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-container", default="blindpass-postgres")
    parser.add_argument("--admin-user", default="blindpass")
    parser.add_argument("--admin-database", default="blindpass")
    parser.add_argument("--port", type=int, default=5433)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--filter", default="", help="optional Cargo test name filter")
    parser.add_argument("--test-target", choices=["recovery_authority", "recovery_authority_migration", "recovery_receipts", "recovery_invalidation", "legacy_authority", "fleet_provisioning_submit", "production_ownership", "deployment_startup", "store_quiescence", "restore_stage", "restore_postgres", "recovery_activation"], default="recovery_authority")
    parser.add_argument("--test-features", choices=["p02-test-failpoints"], help="dedicated controller crash-test build only")
    parser.add_argument("--controller-backend", choices=["sqlite", "postgres"], default="sqlite")
    parser.add_argument("--in-image", action="store_true", help="run the Cargo target inside the pinned-toolkit test image (host networking) instead of on the host")
    args = parser.parse_args()
    if args.test_target == "deployment_startup" and args.controller_backend != "sqlite":
        parser.error("deployment_startup command fixtures use SQLite; PostgreSQL source cases run normally")
    if args.test_target == "restore_postgres" and args.controller_backend != "sqlite":
        parser.error("restore_postgres runs in the pinned-toolkit test image with its own private source cluster")
    if args.test_target == "store_quiescence" and args.controller_backend != "postgres":
        parser.error("store_quiescence requires the separate PostgreSQL controller fixture")
    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    repo = Path(__file__).resolve().parents[2]
    name = "p06_authority_" + secrets.token_hex(12)
    runtime = name + "_runtime"
    controller_database = name + "_controller"
    controller_owner = name + "_controller_owner"
    member = name + "_member"
    password = "P06-DUMMY-" + secrets.token_hex(24)
    runtime_password = "P06-DUMMY-" + secrets.token_hex(24)
    member_password = "P06-DUMMY-" + secrets.token_hex(24)
    controller_password = "P06-DUMMY-" + secrets.token_hex(24)
    created_owner = created_runtime = created_member = created_database = False
    created_controller = False
    created_controller_owner = False
    log_fd = os.open(args.log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

    def sql(statement, database=None):
        result = subprocess.run(
            ["docker", "exec", "-i", "-e", "PGOPTIONS=-c lock_timeout=5000 -c statement_timeout=10000",
             args.admin_container, "psql", "-X", "-U", args.admin_user,
             "-d", database or args.admin_database, "-v", "ON_ERROR_STOP=1"],
            input=statement, text=True, capture_output=True, timeout=30,
        )
        if result.returncode:
            # PostgreSQL/tool output can contain protected setup statements.
            raise RuntimeError("disposable authority administration failed")

    result = None
    cleanup_errors = 0
    try:
        # Register cleanup intent first: a timed-out Docker client does not
        # prove its server-side CREATE failed. Names are unique to this run.
        created_owner = True
        sql(f"CREATE ROLE {name} LOGIN PASSWORD '{password}';")
        created_runtime = True
        sql(f"CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}';")
        created_member = True
        sql(f"CREATE ROLE {member} LOGIN NOINHERIT PASSWORD '{member_password}'; GRANT {name} TO {member};")
        created_database = True
        sql(f"CREATE DATABASE {name} OWNER {name};")
        if args.test_target in {"recovery_authority", "recovery_invalidation", "legacy_authority", "fleet_provisioning_submit", "production_ownership", "store_quiescence", "restore_stage", "restore_postgres", "recovery_activation"} and (args.controller_backend == "postgres" or args.test_target in {"restore_stage", "restore_postgres"}):
            created_controller_owner = True
            sql(f"CREATE ROLE {controller_owner} LOGIN PASSWORD '{controller_password}';")
            created_controller = True
            sql(f"CREATE DATABASE {controller_database} OWNER {controller_owner};")
            if args.test_target == "restore_postgres":
                # Mirrors the shipped first-init hook: the controller store lives in `controller`.
                sql(f"ALTER ROLE {controller_owner} SET search_path = controller;")
        provision = (repo / "deploy/controller/recovery-authority.sql").read_text()
        sql(f"SET ROLE {name};\n" + provision + f"\n"
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC; "
            f"GRANT USAGE ON SCHEMA blindpass_authority TO {runtime}, {member}; "
            f"GRANT SELECT ON ALL TABLES IN SCHEMA blindpass_authority TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.reserve_recovery"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.claim_process"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,BYTEA) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.register_active_process"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.publish_broker_trust"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT,TEXT,BIGINT,TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.open_recovery_challenge"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,TEXT) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.stage_recovery_page"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT,TEXT) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.finish_recovery_challenge"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,BIGINT,BIGINT,BYTEA,BOOLEAN,BIGINT) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.decide_recovery_item"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.waive_recovery_node"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,TEXT,TEXT,TEXT) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.complete_recovery_review"
            f"(TEXT,TEXT,TEXT,BIGINT,BIGINT,INTEGER,BYTEA,BIGINT) TO {runtime}, {member}; "
            "GRANT EXECUTE ON FUNCTION blindpass_authority.recovery_activation_gaps"
            f"(TEXT,TEXT,TEXT,BOOLEAN) TO {runtime}, {member};", name)
        env = dict(os.environ,
                   P06_TEST_AUTHORITY_PORT=str(args.port),
                   P06_TEST_AUTHORITY_ADMIN_URL=f"postgresql://{name}:{password}@127.0.0.1:{args.port}/{name}",
                   P06_TEST_AUTHORITY_MEMBER_URL=f"postgresql://{member}:{member_password}@127.0.0.1:{args.port}/{name}",
                   P06_TEST_AUTHORITY_URL=f"postgresql://{runtime}:{runtime_password}@127.0.0.1:{args.port}/{name}")
        if args.test_target in {"recovery_authority", "recovery_invalidation", "legacy_authority", "fleet_provisioning_submit", "production_ownership", "store_quiescence", "restore_stage", "recovery_activation"}:
            env.pop("P06_TEST_CONTROLLER_AUTHORITY_PROBE_URL", None)
            env.pop("P02_TEST_POSTGRES_URL", None)
            env["P02_TEST_BACKEND"] = args.controller_backend
            if args.controller_backend == "postgres" or args.test_target == "restore_stage":
                env["P02_TEST_POSTGRES_URL"] = f"postgresql://{controller_owner}:{controller_password}@127.0.0.1:{args.port}/{controller_database}"
                env["P06_TEST_CONTROLLER_AUTHORITY_PROBE_URL"] = f"postgresql://{controller_owner}:{controller_password}@127.0.0.1:{args.port}/{name}"
        if args.test_target == "restore_postgres" or args.in_image:
            if args.test_target == "restore_postgres":
                env["P06_TEST_RESTORE_TARGET_URL"] = f"postgresql://{controller_owner}:{controller_password}@127.0.0.1:{args.port}/{controller_database}"
            exported = [key for key in ["P06_TEST_AUTHORITY_PORT", "P06_TEST_AUTHORITY_ADMIN_URL", "P06_TEST_AUTHORITY_MEMBER_URL", "P06_TEST_AUTHORITY_URL", "P06_TEST_RESTORE_TARGET_URL",
                                        "P02_TEST_BACKEND", "P02_TEST_POSTGRES_URL", "P06_TEST_CONTROLLER_AUTHORITY_PROBE_URL"] if key in env]
            image = "blindpass-p06-pgtest:local"
            subprocess.run(["docker", "build", "--file", "deploy/controller/Dockerfile", "--target", "pgtest", "--tag", image, "."],
                           cwd=repo, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3600)
            # Host networking reaches the published disposable authority; values travel by environment name only.
            command = ["docker", "run", "--rm", "--network", "host", "--user", "10001:10001", "--cap-drop", "ALL",
                       "--security-opt", "no-new-privileges"] + [arg for name in exported for arg in ("-e", name)] + [
                       image, "cargo", "test", "-p", "blindpass-controller", "--locked", "--offline", "--test", args.test_target,
                       args.filter, "--", "--ignored", "--test-threads=1", "--nocapture"]
            timeout = 3600
        else:
            command = (["cargo", "test", "-p", "blindpass-controller", "--locked", "--offline",
                        "--test", args.test_target]
                       + (["--features", args.test_features] if args.test_features else [])
                       + [args.filter, "--"]
                       + ([] if args.test_target == "fleet_provisioning_submit" else ["--ignored"])
                       + ["--test-threads=1", "--nocapture"])
            timeout = 300
        with os.fdopen(log_fd, "w") as log:
            log_fd = None
            result = subprocess.run(
                command, cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout,
            )
        print(f"authority_postgres_gate_exit={result.returncode}")
        if args.test_target in {"recovery_authority", "recovery_invalidation", "legacy_authority", "fleet_provisioning_submit", "production_ownership", "deployment_startup", "store_quiescence"}:
            print(f"recovery_invalidation_backend={args.controller_backend}")
            print(f"controller_test_target={args.test_target}")
    finally:
        if log_fd is not None:
            os.close(log_fd)
        for created, statement in [
            (created_controller, f"DROP DATABASE IF EXISTS {controller_database} WITH (FORCE);"),
            (created_database, f"DROP DATABASE IF EXISTS {name} WITH (FORCE);"),
            (created_controller_owner, f"DROP ROLE IF EXISTS {controller_owner};"),
            (created_runtime, f"DROP ROLE IF EXISTS {runtime};"),
            (created_member, f"DROP ROLE IF EXISTS {member};"),
            (created_owner, f"DROP ROLE IF EXISTS {name};"),
        ]:
            if created:
                try:
                    sql(statement)
                except (RuntimeError, subprocess.TimeoutExpired):
                    cleanup_errors += 1
        print(f"owned_authority_cleanup_errors={cleanup_errors}")
    if cleanup_errors:
        return 1
    return result.returncode if result else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        raise SystemExit("authority fixture setup/execution failed; inspect public test log")
