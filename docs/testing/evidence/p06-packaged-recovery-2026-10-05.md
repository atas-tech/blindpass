# P06 recovery on the packaged profiles — 2026-10-05

**Status:** execution evidence on the uncommitted tree above `8a595ad`. It closes the gap "recovery activation (RR05) was only exercised with host controllers and QEMU guests" for the packaged Compose SQLite, Compose PostgreSQL and native SQLite profiles. **No real node exists in any of these runs.** Each run seeds one active broker-trust row into the authority and covers it only by an explicit, named waiver, so the relay (`recovery-relay`) and a node reconnecting to a recovered packaged controller are **not** proven here. P06 acceptance remains false.

## Built

- `deploy/controller/compose.restore-sqlite.yml` and `compose.restore-postgres.yml`: opt-in `restore` profile with two jobs.
  - `controller-restore`: `blindpass restore` with the **offline** recipient key and the signer certificate (ADR 0013), memory-backed 1 GiB staging mount (`BLINDPASS_RESTORE_TMPFS_SIZE`), authority URL file, tenant/owner/recovery id, destination `/staging/root` (must not exist). PostgreSQL adds `--database-url-file` and the `database` network.
  - `controller-restore-install`: `network_mode: none`, read-only staging, copies the restored `keys` (and `data` for SQLite) into **empty** volumes and refuses non-empty ones.
  - Both run as UID 10001, read-only root, `cap_drop: [ALL]`, `no-new-privileges`, `restart: "no"`. Both are never part of ordinary `up`.
- `tests/deployment/compose-up.py --scenario recovery` (`recovery_gate`), both profiles.
- `tests/deployment/native-guest.py` `native_recovery` and `native-install.sh --recovery` (disk grown to 8 GiB for headroom). The native restore is a **documented hardened `systemd-run` recipe** (not a packaged unit): [native quickstart](../../deploy/native-quickstart.md#restore-and-recovery-activation-on-the-native-package). Layout decision: the authority is the guest's PostgreSQL (not independent); the restore runs as `blindpass` with `StateDirectory=blindpass-controller-restore` as its only writable path and tmpfs staging under `/run`, and the operator swaps `data` and `keys` into place with `cp -a`.
- `container-config-test.py` `test_p06_rc_config_restore_jobs_are_opt_in_private_and_use_offline_custody` (both profiles, including that each required variable is required to render).
- The five authority scripts (`authority-activate/fence/recover-attest/recover-status/recover-activate.sql`) are in the native archive (checked with `tar -t` on the archive below and by `release-artifacts-test.py`).

## Scenarios

| ID | Compose (each profile) | Native (each OS) |
|---|---|---|
| RC1 / (B08) | authenticated split-custody backup through the shipped `controller-backup` job of a running controller | shipped `blindpass-controller-backup.service` after `admin bootstrap`; archive verified with the offline key |
| RC2 / NR01 | fence, reserve the recovery epoch, delete **all** keys and state, the backup host's custody directory (no `recipient.pem`) cannot restore (the job fails because the offline key is not there; this is a custody check, not a cryptographic refusal), offline custody restores, receipt `recovery_required`/`activation_permitted:false`, keys byte-identical, the install job refuses non-empty volumes | same, with the host's own signing credential refused as recipient key |
| RC3 | restored controller starts fenced: `/readyz` never 200, precheck lists `node_uncovered, review_incomplete, review_undecided, source_stop_missing` | NR02 start, same refusals |
| RC4 | ordinary `authority-activate.sql`, early `authority-recover-activate.sql` (names all three open gates) and a premature attestation are refused with the ledger **unchanged**; completion refused while undecided and while the node is uncovered; unknown node waiver refused; named waiver; completion | same |
| RC5 / NR02 | stop, activation without attestation names only `source_stop_missing`, attest (who/host recorded), recovery activation, a second recovery activation refused, controller serves; tenant, schema and key bytes preserved | same, plus the late decision after completion is refused |
| NR03 | — (in-place restore; see Limits) | the pre-restore state (old keys and data) is swapped back under an activation and fails to start; the restored state is swapped back and serves again |
| RC6 / NR04 | restore-based rollback: fence, reserve a **higher** epoch, restore the same archive again, controller recovering again with `source_stop_missing`, activation table still holds only the first epoch | same, then the second epoch's own review, waiver, attestation and activation (activations `2,3`) |
| RC7 / NR05 | no authority password, private-key armor or canary in any container log | no authority password, key armor or recipient key in the service journal; restore staging gone from `/run`; reference identity refreshed |

## Gates run (this session, in order, sequential)

- Image: `blindpass-p06-controller:pkgrec` = tag of the attested-SBOM build `final-sbom` (config ID `sha256:f88404523a4dfab8b963dbfd1b510d60daf7536c4afa46c82534256f345f303f`, created 10:57 UTC). It was **not rebuilt** for this work: no `crates/`, `packages/`, `scripts/`, `Cargo.*`, `package*.json` or Dockerfile file is newer than the image (`find -newer`), and the new files are Compose overlays and test code outside the image.
- Native archive: bookworm baseline route, built with `--allow-dirty`, sha256 `73062d8174e96d3a5c346a00453a55cc077eb76a27ad30ba6f436dee7ca795f1`. Guest images: Ubuntu 24.04 `612b2c0c…ad7354` (pinned), Debian 12 `7b3faf64…bdecad` (computed from the local file; the harness pins by the value passed).
- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`: clean.
- `cargo test --workspace --locked --offline`: **774 passed, 0 failed, 149 ignored** (ignored cases run through the authority driver; unchanged by this work, which touched no Rust).
- `tests/deployment/{release-artifacts-test,native-package-test,container-config-test,controller-sbom-test}.py`: pass (container config now 10 tests).
- `compose-up.py` profile gates: sqlite 11 PASS, postgres 12 PASS; `--scenario handoff` 8 PASS.
- **`compose-up.py --scenario recovery`:** sqlite twice (10 PASS lines each, clean runs after the harness fix below) and postgres twice (10 PASS each).
- `compose-backup.py --payload-bytes 100000000 --faults` (8 PASS) and `compose-backup-postgres.py` (6 PASS).
- Native matrix, Debian 12 and Ubuntu 24.04 × {default 13 PASS, `--tool-faults` 15, `--credential-faults` 28, `--power-loss` 14 (`BLINDPASS_NATIVE_RUN_ROOT=/dev/shm`)}: **8 of 8 rc 0**.
- **`native-install.sh --recovery`:** Ubuntu 24.04 and Debian 12 rc 0. The run includes N01–N10 (backup, upgrade with a pre-upgrade backup, purge) after NR01–NR05, so the restored controller also survives upgrade and purge.
- QEMU harnesses re-run on the same tree: `p06-relay-vm.py` 15 PASS, `p06-handoff-vm.py` rc 0 with 22 PASS and **2 SKIPPED** (H1a and H7a need `BLINDPASS_P06_FAILPOINT_CONTROLLER`, a failpoint build that was not supplied), `p06-recovery-activation-vm.py --scenario main` 28 PASS and `--scenario waiver` 11 PASS, all rc 0.
- `git diff --check` on `docs`, `tests`, `deploy`: clean. No container, volume or QEMU process from these runs remains (the harnesses assert their own teardown).

## Bugs and corrections found

- Harness only (no product defect found): the second restore into the same staging directory failed because the destination `root` must not exist; the operator step is now explicit (clear `root` first) and documented.
- Harness only: the first native version assumed a review item exists; a fresh native controller has **no operator account**, so its review list is empty and `review complete` succeeds with zero items. The scenario now bootstraps an admin and takes a fresh backup so there is something to decide. This is a documented property of the procedure, not a defect.
- Documented behaviour confirmed by the native run: a **waiver revokes the node's trust row in the authority** (`state='revoked'`), so a rollback recovery after a waiver has no uncovered node until a node is trusted again. The rollback rehearsal therefore seeds a second node. A waived node must be re-enrolled.
- Documented behaviour: `review decide` without `--subject` after completion is a no-op success (there is nothing undecided); a late decision is refused only when it names a subject. `authority-activate.sql` of an **active** record with no holder is legitimately accepted, so the harness does not assert its refusal after a recovery activation.
- PostgreSQL profile: the init hook creates an empty `controller` schema, but restore needs an empty target database schema, so the operator drops it first (`DROP SCHEMA controller CASCADE`). Documented in the Compose quickstart; this is a usability rough edge, not a defect.

## Limits (state these in any acceptance claim)

- **No real node on any packaged profile.** One seeded authority broker-trust row is covered only by a named waiver. The relay path, `covered` receipts, grant reconciliation and a node reconnecting to a recovered packaged controller are proven only by the QEMU harnesses with host controllers.
- The Compose restore replaces state in place under the same project, so "the old source is refused" is not shown for Compose (native NR03 shows it for the pre-restore state files). No live second source host was run.
- The native restore is a documented recipe, not a packaged unit; it was not run on aarch64. The authority in the native run is the guest's own PostgreSQL (not independent).
- The Compose PostgreSQL scenario restores into the database of the same project; PostgreSQL controller recovery in a VM and a two-broker/multi-node recovery are still open (see the activation record). **Update 2026-10-05 (later):** two-guest and PostgreSQL-controller runs now exist, see the [recovery matrix record](p06-recovery-matrix-2026-10-05.md).
- The image was reused from the attested-SBOM build rather than rebuilt; a hosted-CI build and publication were not run.
- Operator review is metadata only (no provider API). Owner acceptance review of P06 is not done.
