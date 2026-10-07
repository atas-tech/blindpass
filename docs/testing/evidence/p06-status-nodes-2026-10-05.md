# P06 `blindpass status --nodes` — 2026-10-05

**Status:** CLI component evidence on the uncommitted tree above `8a595ad`. It delivers the `status --nodes` half of slice 8. The migration scripts, interrupted-transfer tests and P06-E02 are **not** done. P06 acceptance remains false.

## Built

`blindpass status --nodes [--require-online]` with the operator HTTP options (`--controller-url`, `--origin`, `--username`, `--password-stdin`). It logs in through the same CSRF session as `admin node`, pages `GET /api/v3/nodes?limit=100` until the cursor ends, logs out, and prints `total`, `online`, `stale`, `offline`, `revoked`, `all_active_online` and one row per node (id, status, key version, last seen, pending flags). Fingerprints, capabilities and names are not printed. `--require-online` additionally fails unless at least one node is active and every active node is online (stale counts as not online; zero active nodes fails). The session wrapper was factored out of `run_fleet_admin` into `with_operator_session`; behavior for `admin` is unchanged. Runbook: [upgrade](../../deploy/upgrade.md).

## Tests

`crates/blindpass-cli/tests/fleet_admin.rs`, written first and red (`unrecognized subcommand 'status'`), then green: pagination and summary with no key-material leak; the `--require-online` gate (all online with a revoked node ignored passes; a stale node fails but still prints; no active node fails); `--nodes` required and `--password-stdin` required before any request. Mutation check: counting `stale` as online made the gate test fail. `cargo test -p blindpass-cli` 10+10+6 passed; clippy clean for the package.

## Gates on the combined tree (status, REPEATABLE READ, slow-body test)

`cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` clean; `cargo test --workspace --locked --offline`: 754 passed, 0 failed, 124 ignored (the two new ignored cases ran through the authority driver: `recovery_invalidation` 7 on PostgreSQL and 7 on SQLite, `restore_stage` 23+23, `recovery_receipts` 6, `restore_postgres` 5 in the toolkit image). Compose, native VM and the in-image `production_ownership` runs were not repeated for these changes.

## Limits

- The command reads controller-observed `last_seen_at` through the existing operator API against a scripted mock server. It was not run against a real controller or real nodes, so the 120 s reconnect bound is unmeasured.
- Online/stale thresholds are the controller's existing 45 s/120 s; the command does not choose them.
- Requires operator credentials over HTTPS; it has no local admin-socket mode, so it cannot report while the controller is fenced or recovering (ordinary routes return 503 then).
