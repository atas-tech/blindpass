# P06 PostgreSQL backup creation and isolated-restore verification — 2026-10-04

**Status:** component, in-image and Compose evidence on the uncommitted tree above `8a595ad`. The image, SBOM and gate figures below were refreshed against the final tree of the [restore and upgrade record](p06-postgres-restore-2026-10-05.md), which also lists the later PostgreSQL restore/upgrade work. This implements [ADR 0011](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md) (approved by the project owner 2026-10-04) for **backup creation and verification only**. Restoring a PostgreSQL archive and upgrading a PostgreSQL controller were added afterwards (see the restore record). P06 acceptance remains false.

## Built

- The controller image's runtime stage installs the pinned PGDG packages (`postgresql-16`/`postgresql-client-16` 16.15-1.pgdg12+2, `postgresql-common`/`-client-common` 293.pgdg12+1, `libpq5` 18.6-1.pgdg12+2). The repository key is checked against fingerprint `B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8`, cluster creation is disabled, and the PGDG list and key are removed from the final image. Image size is 422,895,844 bytes (about 423 MB). The Dockerfile stages are `ui`, `binaries`, `pgdg`, `pgtest`, `runtime`; `runtime` must stay last.
- `backup create` on a PostgreSQL controller exports one snapshot, runs `pg_dump --format=custom --no-owner --no-privileges --no-sync --schema=X --snapshot=ID` by absolute path under `/usr/lib/postgresql/16/bin` (no override), and seals the dump with the existing authenticated archive.
- Credentials: the password reaches tools only through a private `PGPASSFILE`; libpq settings pass through a cleared environment; nothing secret appears in argv.
- Verification restores the whole dump into a private, socket-only, unprivileged cluster (`initdb`, then `postgres` with `listen_addresses=` and a socket inside its data directory addressed as `/proc/<pid>/cwd/s` to stay under the 107-byte Unix socket limit), re-measures `SnapshotInfo` there and compares it with the authenticated manifest. Listing archive members is not accepted as verification.
- Child hardening: parent-death SIGKILL, `no_new_privs`, core limit 0, a file-size ceiling for bounded tools.
- `deploy/controller/compose.backup-postgres.yml`: opt-in `backup` profile job on the internal `database` network only, database URL from a private file, same recovery custody as the SQLite job.
- Native profile unchanged: SQLite only, no toolkit on the host.

## Test-first record

The unit tests `p06_pg01`–`p06_pg04` (URL parsing, socket aliases, unsafe URL refusal, dump arguments) were written first and failed red. **The integration tests PGT01–PGT05 and the Compose harness PGC01–PGC05 were written after the implementation** and so are not red/green proofs; they were run against the built image and corrected where they exposed bugs (the long socket path, the staged-cluster failure and stale harness strings). The Compose config tests CB02 and UP12 passed on first run; CB02 was mutation-checked (adding the `edge` network made it fail).

## Gates run

- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`: clean.
- `cargo test --workspace --locked --offline`: **741 passed, 0 failed, 115 ignored** (ignored cases run through the authority driver or the in-image script). An earlier run on this tree failed once in `fleet_browser_intents` (see Corrections).
- In-image PGT01–PGT05 (`tests/deployment/pg-toolkit-test.sh`, UID 10001, `pgtest` stage): 5 passed.
  - PGT01: full backup and verify; no credential in argv or environ (a `/proc` watcher ran through the whole job); sealed archive has no plaintext; no leftover cluster.
  - PGT02: concurrent writes during capture; restored snapshot equals the exported snapshot.
  - PGT03: flipped, truncated and forged-manifest dumps refused.
  - PGT04: wrong password and stopped database fail closed.
  - PGT05: SIGKILL during capture and during verification leaves no child processes; `backup cleanup` removes residue.
- `python3 tests/deployment/compose-backup-postgres.py --image blindpass-p06-controller:pg-sbom`: PGC01–PGC05 pass.
  - PGC01 backup created and fully verified in the shipped image; PGC02 non-root, read-only, internal network only, no credential in env/args/logs, no residue; PGC03 operator `backup verify` of both archives, wrong recovery key refused; PGC04 unreachable database fails closed with no published files and source unchanged; PGC05 tmpfs output quota of 2 MiB and 40 MiB fails closed with archives and source unchanged.
- Attested SBOM: the image was rebuilt (after the snakeoil fix below) with the approved scanner expression (`docker/buildkit-syft-scanner:stable-1@sha256:ae4f3b55…d6a9`, the same cataloger set as the CI workflow) and loaded as `blindpass-p06-controller:pg-sbom` (config ID `sha256:95e1d931eb3038c278126e3a394b77a1e12e7060526dd40b5bb45e29a579eb04`). `controller-sbom.py` passes O10 (1,681 unique package names) and SB01 (exact 125 runtime Debian package/version pairs, including the five PGDG packages): [output](p06-postgres-backup-2026-10-04/sbom-verify.txt), [package list](p06-postgres-backup-2026-10-04/runtime-packages.tsv). The OCI archive itself (about 199 MB) is not committed.
- Compose gates on that exact image: `compose-up.py --profile sqlite` and `--profile postgres` pass (8 PASS lines each, including the O01 all-layer private-key scan); `compose-backup.py --payload-bytes 100000000 --faults` passes CB02–CB05 (creation 10.239 s with 492 concurrent console requests and zero failures; ENOSPC at capture, encryption and verification); `compose-backup-postgres.py` PGC01–PGC05 and `pg-toolkit-test.sh` PGT01–PGT05 pass; `npm run build` and `npm test` exit 0.
- Authority driver matrix, all exit 0: default target 34; `production_ownership` 20 on SQLite and 20 on PostgreSQL controller; `recovery_invalidation` 6+6; `legacy_authority` 4+4; `restore_stage` 22+22; `recovery_authority_migration` 1; `recovery_receipts` 6; `store_quiescence` 4; `deployment_startup` 5.
- `python3 tests/deployment/{container-config-test,controller-sbom-test,native-package-test,release-artifacts-test}.py`: pass (container config now 6 tests).

## Corrections made during the work

- **Private key shipped in the image (found by the O01 gate).** `postgresql-common` depends on `ssl-cert`, whose post-install step generates `/etc/ssl/private/ssl-cert-snakeoil.key`, one private key shared by every container of the image. `compose-up.py` failed with "private PEM added to image". The Dockerfile now removes the key and certificate in the same `RUN` as the install (a later layer would leave it in the exported lower layer, which O01 scans), and the gate passes. The attested image and SBOM were rebuilt afterwards.
- `compose-backup.py` was stale against the packaged authority (`migrate` and serving need an authority record, and it failed at `migrate` on this image; whether it passed on the earlier authority-provisioning tree was not rechecked). It now runs the serving controller as an isolated test-mode fixture through a harness-only Compose override that replaces the controller environment; authority provisioning stays covered by `compose-up.py` and the authority drivers.

- Docker build: APT needed `ca-certificates` before the PGDG repository (two-stage install); stage ordering for `COPY --from=pgdg`.
- Verification server exited on the over-long socket path; fixed with the `/proc/<pid>/cwd/s` form.
- `fleet_browser_intents::intent_event_operation_approval_and_audit_failure_roll_back_together` flaked about 28% of the time under load (7 of 25 runs; one test, no source change involved). Cause: a pooled SQLite connection could still hold the schema from before the previous disposable trigger was dropped on another connection, and SQLite checks "already exists" at prepare time. The helper now refreshes the schema on the same connection before creating the trigger; 0 failures in 40 subsequent runs of the whole file. Whether HEAD flakes the same way was not measured (the comparison build was abandoned).

## Limits

- This record covers backup creation and verification. Restore and upgrade are in the restore record.
- Verification staging needs room for the restored cluster: more than 40 MiB beyond the dump and archive. No upper bound was measured, and no large-database timing run was done (PGC uses a small fixture).
- Tests ran on x86-64 only. The toolkit packages for aarch64 were not exercised.
- The `PGDG_KEY_FINGERPRINT` build argument triggers Docker's `SecretsUsedInArgOrEnv` lint; it is a public fingerprint, not a secret.
- The attested OCI archive was built locally; GHCR publication and the CI workflow were not run.
- PostgreSQL recovery transactions still use READ COMMITTED, which matters once PostgreSQL restore exists. ADR 0010's key-custody split (single recovery credential signs and decrypts) is unchanged.
