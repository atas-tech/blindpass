# P06-D29 backup key custody split and tmpfs restore staging — 2026-10-05

**Status:** implemented and gated on the uncommitted tree above `8a595ad`. Decision: [ADR 0013](../../product/decisions/0013-p06-backup-key-custody-split.md) (amends the custody rules of [ADR 0010](../../product/decisions/0010-p06-authenticated-backup-format.md); the archive format is unchanged). This does **not** establish P06 acceptance, RC09-RR05, activation of a restored issuer, or independent cryptographic review.

## Built

- **Roles.** `backup key-init --role signing|recipient --output F --certificate-output C` (RSA-3072, `digitalSignature` / `keyEncipherment`, both files in one private directory, never overwritten). `create` takes `--signing-credential-file` + `--recipient-certificate-file` (certificate only, no private key, differing from the signer, refused otherwise). `verify`, `restore`, `handoff import` take `--recipient-key-file` + `--signing-certificate-file`. `--recovery-key-file` (single credential) is still accepted everywhere; a mixture, one half of a pair or a repeated option refuses.
- **Create-time verification without a standing decrypt key.** The bundle is encrypted to the offline recipient certificate **and** a throwaway recipient generated in private staging; the existing full verification (pinned signer, authenticated decrypt, extraction, isolated restore) runs with the throwaway key, which is destroyed with the stage. It does not prove that the offline recipient entry decrypts (documented; operators run `backup verify`).
- **Digest pin.** `create` prints `archive_sha256`; `--expected-archive-sha256` on `verify`/`restore` refuses any other file before decryption.
- **tmpfs staging.** `restore` and `handoff import` stage the decrypted tar, members and keys on a private tmpfs/ramfs directory (`--staging-directory`, `BLINDPASS_RESTORE_STAGING_DIR`, `$XDG_RUNTIME_DIR/blindpass-restore`, `/dev/shm/blindpass-restore-<uid>`): owner, mode 0700, no links, `fstatfs` magic, free space ≥ 2× archive + 8 MiB, else refuse (a named directory never falls back). The database is copied to the destination stage; keys are copied there last, just before publication. No dependency was added (`fstatfs` is a raw extern like the existing `prctl`/`setrlimit`).
- **Packaging switched to split custody:** `deploy/controller/compose.{backup,upgrade}-{sqlite,postgres}.yml`, `compose.handoff-sqlite.yml` (import mounts the offline files and an in-memory `/restore-staging`), native `controller-backup-signing-credential` + `controller-backup-recipient-certificate` (installer, credential check, backup/upgrade units, purge). Upgrade skips the second verify in split mode (create already measured the sealed bytes).
- Docs: `docs/deploy/{recovery-stage,handoff,upgrade,compose-quickstart,native-quickstart}.md`, ADR 0013 and the ADR 0010 amendment.

## Test-first record

Written before the implementation they cover (compile-red, not captured as run output): `backup_envelope::custody_split` (5), `backup_command::p06_d29_*`. **Written alongside or after:** `backup_staging` (5 + 1 unit), CLI `custody` (3), `p06_d29_r01`, `p06_ho08`, `p06_up17`, `container-config-test` and `native-authority-test` assertions, the split Compose/VM harness changes, the extended `p06_st05`. Mutation checks (each made its target fail, then the code was restored and diffed): `memory_backed_free_bytes` accepting any filesystem (`p06_d29_s01`), free-space comparison disabled (`s04`), recipient-private-key refusal disabled and recipient-equals-signer refusal disabled (`p06_d29_split_credentials_…`).

## Findings and fixes

1. Flaky "recovery key directory busy" when two key-inits ran back to back: a concurrent fork briefly holds the directory descriptor. Bounded lock retry (40 × 50 ms) in the credential generator; 15/15 loops pass.
2. Test-host defect: `/tmp` is tmpfs here, so "persistent disk" fixtures under `temp_dir()` were accepted (the code was right). Disk cases now use `CARGO_TARGET_TMPDIR`.
3. Harness assertion counted one `PRIVATE KEY` line per key; a PEM has two armor lines.
4. **Native power-loss assertion was alignment-dependent.** `NB05-prepare` asserted the frozen `encrypted.der` is smaller than the plaintext tar. openssl writes the ciphertext in one large `write(2)` and the freezer lands on the last whole page, so the frozen size is `floor((plain + envelope) / 4096) * 4096`. The second `RecipientInfo` (+~490 bytes) moved this fixture across a page boundary (tar 202,099,712 B, frozen 202,100,736 B) and failed on both OSes. Reproduced with SIGSTOP on the host (one and two recipients both stop at the last whole page). The assertion now allows `plain + 8192` and relies on the live frozen `openssl -encrypt` child, which was already asserted, to prove incomplete encryption; the observed sizes are printed.
5. Clippy: `from_ref` and `is_multiple_of`.

## Gates

All on the final tree (the last source change is the controller help text; afterwards only tests, harness scripts and docs changed). No dependency or manifest changed (`git status` shows no `Cargo.*`/`package*.json` edit); no Socket review was needed.

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`, `git diff --check`: clean. `cargo test --workspace --locked --offline`: **773 passed, 0 failed, 135 ignored** (ignored cases run through the authority driver or in-image).
- Deployment unit tests, all OK: `container-config-test`, `native-authority-test`, `native-package-test`, `release-artifacts-test`, `controller-sbom-test`.
- Authority driver, all exit 0: `restore_stage` 24 on SQLite and 24 on the PostgreSQL controller backend (includes `p06_d29_r01`); failpoint build `restore_stage` 26 on SQLite and 26 on PostgreSQL (includes the extended `p06_st05`: no controller key on persistent disk before the last step, tmpfs residue removed by `backup cleanup`); `production_ownership` 32 on both backends (includes `p06_ho08`, `p06_up17`); failpoint `--filter p06_ho` 8; `recovery_invalidation` 7 + 7; `restore_postgres` 5; `production_ownership --in-image --filter p06_up` 13; in-image `backup_postgres_toolkit` 5 (legacy credential path).
- Fresh image `blindpass-p06-controller:custody` (config `sha256:f4be07e8d93037383f93036c106d325ecdd059d6c27528cbd0d9eb6009550394`): `compose-backup.py --payload-bytes 100000000 --faults` (CB02–CB05; creation 3.4 s, 169–171 concurrent requests, zero failures; wrong offline key, host signing credential, exposed and missing custody refused), `compose-backup-postgres.py` (PGC01–PGC05), `compose-up.py --profile sqlite` and `--profile postgres` (O01–O08, P06-U with a verify that the job's own custody cannot open the archive, F1–F3), `compose-up.py --profile sqlite --scenario handoff` (H1–H5; import refused with host custody, accepted with the offline files and in-memory staging).
- Native archive rebuilt through the bookworm-baseline route (sha256 `f8e04c8d7a9308d3cd738edb5a56aedf745ffc5342bae3602d4d4222fa7b735c`; built with `--allow-dirty`). VM matrix, Debian 12 and Ubuntu 24.04 × {default, `--power-loss`, `--tool-faults`, `--credential-faults`}: **all 8 rc 0**, including N10 (upgrade with a split-custody pre-upgrade backup) and NB07 custody checks on both installed files. The six non-power-loss modes ran before the two harness edits below; both power-loss modes ran after them.
- `tests/fleet/p06-relay-vm.py` (S1–R3, 15 PASS) and `tests/fleet/p06-handoff-vm.py` with the failpoint controller (H0–H13, including H1a and H7a) pass.

## Harness findings (not product defects)

- `/tmp` and `/dev/shm` on this host are tmpfs with a **per-user quota of about 24 GiB** and other users' data in it. Power-loss guests failed with guest `Buffer I/O error` writes and then `backup flush failed` once the overlay needed more space; a probe wrote 600 MiB of fresh data in the guest but failed at 1200 MiB, `qemu-img check` was clean and host `/tmp` still showed free blocks. `tests/deployment/native-install.sh` now honors `BLINDPASS_NATIVE_RUN_ROOT`; the passing power-loss runs used `/dev/shm`. This is why N10 under `--power-loss` had never been run before (earlier runs ended at NB05).
- `native-install.sh` failure diagnostics now also print capacity, kernel block-device lines, QEMU stderr, the upgrade unit's static refusal strings and a `qemu-img check` line after the hard kill (no file contents).
- The VM harnesses and killed restores leave tmpfs residue under `/dev/shm/blindpass-restore-<uid>` (the H7a failpoint run left 1.1 MiB of decrypted test material); `backup cleanup --work-directory` removed it.

## Limits

- The offline recipient entry is only proven by an operator `backup verify` or restore drill, never by `create`.
- A stolen signing credential still forges archives (not decryption). Controls are the recorded digest, authority binding at restore and rotation; there is no rollback counter.
- A SIGKILLed restore leaves its tmpfs stage until reboot or `backup cleanup --work-directory <staging dir>` (tested for the three failpoints). tmpfs is not swap or forensic protection.
- `backup verify` (operator check, not restore) still stages under its `--work-directory`. The throwaway private key sits in the create stage for the length of one run.
- `backup-disk-full.py`, `backup-interruption.py` and `backup-size-limit.py` still use the legacy single credential (supported path), not the split one.
- Tests ran on x86-64, OpenSSL 3.6.4 on the host and the pinned distribution OpenSSL in guests/images. aarch64, PostgreSQL controllers in the native profile and native-to-Compose handoff were not run. No independent cryptographic audit.
