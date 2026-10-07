# P06 packaged recovery-authority provisioning — 2026-10-04

**Status:** component and packaging evidence on the uncommitted tree above `8a595ad`. Complete P06 acceptance remains **false**. This record lists only what was run.

## What changed

- `blindpass keys issuer-id` prints the issuer key id from the initialized private keys (`blindpass_core::deployment::issuer_key_id`, shared with the controller's configuration).
- `deploy/controller/authority-{runtime-role,register,activate,fence}.sql` give the administrator the full operator sequence: init keys → issuer id → register (fenced, epoch 1, revision 1) → `migrate` → activate → serve. Every start needs a fresh one-use activation; maintenance runs between `fence` and `activate`.
- Native: `controller-install.py` provisions the authority drop-in and credential; `blindpass-controller.service` uses `Restart=no`. Compose profiles use `restart: "no"`, require tenant/owner variables and mount the authority directory read-only at `/authority`.
- `reconcile_clock` treats a changed boot ID as a clock regression (found by the VM reboot step, which returned `recovery_required` after reboot).
- Compose, native and Unraid quickstarts document the sequence and the restart-needs-activation rule.

## Decisions taken (vault plan, 2026-10-04)

- One activation per process start; no automatic restart (`Restart=no`, Compose `restart: "no"`).
- Two-stage initialization (keys, then registration/`migrate`); `migrate` refuses an unregistered or non-fenced issuer.
- A changed boot ID is a clock regression.
- **Operational consequence (P06-D12 as built):** an epoch check that cannot be answered (store outage or timeout) fences the owner. A PostgreSQL controller-store outage therefore costs readiness until the administrator re-activates, even after the store returns. O07 was changed to assert exactly this.

## Gates run (this tree)

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`: clean.
- `cargo test --workspace --locked --offline`: **734 passed, 0 failed, 101 ignored** (the ignored cases need the authority driver).
- Authority driver (disposable PostgreSQL): default target on SQLite controller; `production_ownership` on SQLite and PostgreSQL; `deployment_startup` (SQLite); `store_quiescence` and `restore_stage` (PostgreSQL controller). All exit 0. A stale lock-query string in PW05 (`SELECT last_observed_ms, fenced_at …`) was updated to the `boot_id` query after it failed red.
- `tests/deployment/authority-operator-flow.py` AO00–AO09: all passed against a disposable PostgreSQL authority.
- Deployment unit tests (`release-artifacts-test`, `native-package-test`, `container-config-test`, `controller-sbom-test`, `native-authority-test`): pass.
- `npm run build`, `npm test`: exit 0. `git diff --check`: clean.
- Native VM (real systemd guests, KVM, packaged archive sha256 `cefabf8bacacfb9f50a613be0286019633ea3dff5ea697daeae0bd1e34c510f1`, built with `--allow-dirty` from this uncommitted tree): Ubuntu 24.04 and Debian 12 default (N01–N09, B08, B10), `--power-loss`, `--tool-faults` and `--credential-faults` on both OSes — 7 matrix runs plus the Ubuntu default, all rc 0, no FAIL lines.
- Compose (`controller` image rebuilt from this tree, `blindpass-p06-controller:local`): `compose-up.py` on the SQLite and PostgreSQL profiles (O01–O08 including nginx and Caddy edges, real TLS to a separate TLS authority container with `verify-full`, activation-per-start, recreate refused without activation, key-refusal cases); `compose-backup.py` CB02–CB04.
- Harness fixes made during this run: authority readiness probe used a not-yet-created database; authority directory was chowned before the harness wrote into it; the SQLite read-only metadata probe needed an immutable fallback on a cleanly stopped WAL database; O07 expectation (above).

## Limits

- **The native guest's authority is an in-guest PostgreSQL**, not an independent host. It proves the installer sequence, not authority independence from the controller host.
- Compose authority is a disposable container on the project's network, not a remote administered database.
- Not run: aarch64 execution, GHCR/Unraid, restic, stock clients, two-host transfer, the recovery request/page relay on real nodes (RC09-RR03..RR05), PostgreSQL custom dump/full restore (ADR 0011 approved, not built), locked upgrade (slice 7), migration (slice 8), parity rehearsal (slice 9).
- Authority drop-in/credential files are host-readable by the service and administrator; custody of the authority password is unaudited here.
