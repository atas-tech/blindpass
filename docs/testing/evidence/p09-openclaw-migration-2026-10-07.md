# P09 execution record — OpenClaw credential migration (2026-10-07)

**Scope:** `blindpass-openclaw-migrate` for OpenClaw **2026.8.35** only. **Result:** hermetic suites 93/93, root `npm run build` and `npm test`
exit 0, and the nine real-runtime scenarios below 9/9 on a clean committed tree (`3e40636`). **Not accepted:** the operator need that
the phase requires was never named (activation was an owner instruction), hosted CI has not run, and nothing is pushed or published.
See [Not executed and limits](#not-executed-and-limits).

Contract and findings: [openclaw-migration.md](../../product/openclaw-migration.md). Operator procedure:
[openclaw-migration guide](../../guides/openclaw-migration.md).

## Commits

| Slice | Commit |
|---|---|
| 0 real-sops store fix | `506b2d8` |
| 1 contract, matrix, fixtures, registry/classifier/dotenv | `b440d59` |
| 2-3 safe filesystem layer, dry run, journaled apply and rollback | `be03c9a` |
| 4 key backup acknowledgement, store checks | `8d5b615` |
| 5 real-runtime scenarios and the findings they forced | `7cde899` |
| 6 packaging and operator guide | `5ce4ee9` |
| review fixes (large residual file, resolver alias) | `3e40636` |

## Environment

The scenarios run **only inside a disposable QEMU/KVM guest** built by `tests/openclaw/vm.sh`. OpenClaw `2026.8.35`, `sops` v3.13.3
and `age` v1.3.2 failed Socket review (`openclaw` block, `sops` block, `age` block pending human review); the owner approved them for use
inside the disposable guest only on 2026-10-07. They are not installed on the host and no manifest or lockfile lists them. `sops`/`age`
are hash-checked against `tests/openclaw/tools.lock` before they are copied into the guest.

## Commands

```bash
# Hermetic (host): fake sops/age/openclaw, SIGKILL of a child process at every stage boundary
npm test --workspace=@blindpass/openclaw-plugin        # migrate suites: 93 tests, 0 failed, 0 skipped
npm run build                                          # exit 0
npm test                                               # exit 0 (the opt-in candidate-install test is skipped)
# Real runtime (guest), on a clean committed tree
BLINDPASS_FLEET_RUNNER_OWNER=<name> tests/openclaw/run-activation.sh --release 2026.8.35 --evidence <file>
```

The same nine scenarios also passed on `5ce4ee9` (the commit before the review fixes); the log below is the run on `3e40636`.

## Real-runtime results

| ID | Scenario | Result | What it proves |
|---|---|---|---|
| A01 / P09-I01 | `a01-dry-run` (3) | pass | Dry run of a real installation changes no file, mode or timestamp, creates no `state/` directory, is deterministic, discloses no value, equals `openclaw secrets audit` for `openclaw.json`, reads a named store read-only through real sops, and refuses a symlinked directory and a loose-permission file |
| A02 / P09-E01 | `e01-migrate-reload-use` | pass | A running real gateway migrated to references restarts itself and authenticates the original token resolved from the encrypted store; a store-only rotation is **not** live before reload (old accepted, new rejected) and is after it (new accepted, old rejected); a fresh gateway authenticates from the store; no canary in gateway logs, tool output, journal or store ciphertext |
| A02 / P09-E02 | `e02-rollback-original-task` | pass | Rollback restores `openclaw.json` byte for byte; the real gateway authenticates with the original token again; the backup, `openclaw.json.bak` and the store are kept; plaintext exists only in the restored config, `.env`, the protected backup, `.bak` and OpenClaw's `last-good` copy |
| A03 / P09-I03 | `a03-key-recovery` | pass | Pending flag blocks `--apply`; a stranger's key, a group-readable file, the live key and a missing file are refused by `--ack-backup`; a valid backup is proven by decrypting the real store with only that key; key loss and a wrong key are refused with no change; restoring the key completes the migration and the gateway authenticates |
| P09-I02 | `i02-interrupt-real` (2) | pass | SIGKILL at all ten journal boundaries (intent and effect of each of the five stages) against the real `openclaw`, sops and age: every rerun resumes the same migration with one backup and the gateway authenticates; every rollback restores the original config and the gateway authenticates with the original token |
| registry | `x01-registry-sweep` | pass | Of 112 matrix targets, 22 are accepted by the installed runtime, 73 are rejected as unknown to it, 17 cannot be tested in isolation; the accepted set equals the reviewed fixture |

Log of the run (generated dummy canaries only; the log contains no canary value, which the scenarios also assert):

```text
P09-HOST-ENV runner_owner=hvo qemu=QEMU emulator version 11.1.1 kvm=crw-rw-rw-:666 release=2026.8.35 date=2026-10-07T07:44:05Z
P09-HOST-REPO commit=3e40636 dirty=0
P09-VM-UP dir=/tmp/blindpass-p09.KmmOOhmA ssh_port=22291
P09-GUEST-ENV node v26.10.0
P09-GUEST-ENV npm 11.19.1
P09-GUEST-ENV sops sops 3.13.3 (latest)
P09-GUEST-ENV age v1.3.2
P09-GUEST-ENV age-keygen v1.3.2
P09-GUEST-ENV openclaw OpenClaw 2026.8.35 (713ba57)
P09-GUEST-ENV 6.8.0-139-generic
P09-GUEST-ENV kvm
P09-EVIDENCE A01 dry run of a real installation: 4 migratable, 2 residual, tree unchanged, no state/ directory created, output value-free
P09-EVIDENCE A01 dry-run inventory equals the native audit's plaintext findings for openclaw.json (4 fields)
✔ A01 dry run on a real installation is read-only, deterministic and value-free (2319.898738ms)
P09-EVIDENCE A01 dry run with --store reports store-missing, then bootstrap-backup-pending against a real sops/age store without changing it
✔ A01 dry run with a named store reports key and backup state through real sops, read-only (977.105547ms)
P09-EVIDENCE P09-I01 symlinked config directory and group/other-writable config file refused with exit 3 on the real installation
✔ P09-I01 the real dry run refuses a symlinked config directory and loose permissions (113.598347ms)
P09-EVIDENCE A03 bootstrap_backup_pending blocks --apply (exit 3) and leaves openclaw.json untouched
P09-EVIDENCE A03 a stranger's key, a group-readable file, the live key and a missing file are all refused by --ack-backup; the flag stays pending
P09-EVIDENCE A03 --ack-backup decrypted the real sops store with only the backup key, then cleared the flag; key material never printed
P09-EVIDENCE A03 with the key file deleted --apply refuses (exit 3, key-unavailable) with no change; the dry run reports the store unavailable
P09-EVIDENCE A03 a different (wrong) age key at the store's key path is refused as key-unavailable
P09-EVIDENCE A03 after restoring the correct key from the backup the migration completed and the real gateway authenticated with the store-resolved token
✔ A03 key loss, wrong key, backup acknowledgement and recovery with real sops/age (21190.470511ms)
P09-EVIDENCE E01 real apply: openclaw.json holds exec references for gateway, model and skill credentials; the resolver was run by OpenClaw's own dry run
P09-EVIDENCE E01 migration of a running gateway: the runtime detected the config change, restarted itself and then authenticated the original token resolved from the encrypted store
P09-EVIDENCE E01 after rotating the store entry (no config change) and before reload: old token accepted, new token rejected
P09-EVIDENCE E01 native reload returned code 1 (the 4001 close the contract documents)
P09-EVIDENCE E01 after reload: new token accepted and old token rejected (authenticated use proven, not the reload exit code)
P09-EVIDENCE E01 a gateway started on the migrated config authenticates with the token resolved from the store
P09-EVIDENCE E01 blindpass-openclaw-migrate --reload exit 0: Reload accepted by the gateway. Confirm with an authenticated request: the migra
P09-EVIDENCE E01 no canary in gateway logs, tool output, journal or store ciphertext; plaintext remains only in the protected backup, openclaw.json.bak and the untouched .env (reported as residual)
✔ E01 migrate, reload and use: the real gateway authenticates with a token resolved from the encrypted store (35322.925995ms)
P09-EVIDENCE E02 rollback restored openclaw.json byte for byte (byte-for-byte restore)
P09-EVIDENCE E02 after rollback the real gateway authenticates with the original plaintext token again
P09-EVIDENCE E02 after rollback the protected backup, openclaw.json.bak and the encrypted store are all still present; removal is a separate operator action
P09-EVIDENCE E02 artifact scan: plaintext exists only in the restored openclaw.json, the untouched .env, the protected backup, OpenClaw's .bak and its last-good copy; none in the journal, the store ciphertext, the plan, tool output or logs
✔ E02 rollback restores the original behaviour on the real gateway and exposes nothing new (24427.118917ms)
P09-EVIDENCE I02 real kill at inventory:after-intent: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at inventory:after-effect: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at backup:after-intent: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at backup:after-effect: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at import:after-intent: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at import:after-effect: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at rewrite:after-intent: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at rewrite:after-effect: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at commit:after-intent: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
P09-EVIDENCE I02 real kill at commit:after-effect: rerun resumed the same migration, one backup, real gateway authenticated with the store-resolved token
✔ I02 real runtime: a kill at every stage boundary is completed by a rerun and the gateway authenticates (172294.195375ms)
P09-EVIDENCE I02 real kill at inventory:after-intent: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at inventory:after-effect: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at backup:after-intent: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at backup:after-effect: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at import:after-intent: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at import:after-effect: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at rewrite:after-intent: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at rewrite:after-effect: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at commit:after-intent: rollback restored the original config; the real gateway authenticated with the original plaintext token
P09-EVIDENCE I02 real kill at commit:after-effect: rollback restored the original config; the real gateway authenticated with the original plaintext token
✔ I02 real runtime: rollback after a kill at every stage boundary restores the original task (94285.270518ms)
P09-EVIDENCE X01 matrix 112 config targets vs the real runtime: 22 accepted, 73 rejected as unknown to the installed runtime/plugins, 17 not testable in isolation (minimal config invalid); plugin root openclaw-plugin
✔ X01 which matrix targets the installed OpenClaw accepts (per-target native dry run) (122794.495414ms)
ℹ tests 9
ℹ suites 0
ℹ pass 9
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 474082.355985
P09-RUN-EXIT 0
```

## Findings made by real-runtime execution

These were invisible to the hermetic suites and are fixed or documented (contract table F-8 to F-14):

1. A running gateway restarts itself when `gateway.auth.token` changes in `openclaw.json`, so migrating a watching gateway needs no manual reload; store-only changes still do.
2. `openclaw.json.last-good` is another plaintext residue file, in addition to `.bak`.
3. `openclaw secrets apply` itself creates `state/openclaw.sqlite`; only the dry run is creation-free.
4. `--reload` returned 0 when the reload failed (`gateway token mismatch` after the gateway token was rotated); it now exits 1 with the instruction to pass the active token.
5. A provider added by the native apply was reported as `config-changed-outside-plan` (false positive); fixed.
6. A synthetic config populating all 112 matrix paths is rejected by OpenClaw as invalid (`native-config-invalid`), reported cleanly.
7. Hermetic tests caught a data-loss design flaw before it shipped: a byte-for-byte rollback would have discarded an unrelated edit made between the backup and the rewrite. The restore is now byte for byte only if the rewrite started from the backed-up bytes.

## Not executed and limits

- **Operator need unnamed.** The phase requires one; activation was an owner instruction. P09 is not accepted.
- **Hosted CI has not run; nothing is pushed or published.** The staged bundle now carries a third bin but no release was cut.
- **One release, one guest image, one host:** OpenClaw 2026.8.35, Ubuntu 24.04 (kernel 6.8.0-139), x86-64, QEMU 11.1.1 with KVM. No other release, distribution, architecture, Windows or macOS (path safety is Linux-only and fails closed).
- **Authenticated use was proven for `gateway.auth.token` only.** Model-provider and skill credentials were resolved by OpenClaw's own resolvability dry run and migrated, but no task consumed them. The Telegram channel was not started.
- **SQLite auth profiles are not supported** and were not tested with real profiles; `.env` and `models.json` are reported, never migrated.
- **The real native `apply` was never killed mid-write.** Native crashes before and after the config rename are covered with the fake tool only; the real runs interrupt our process at every journal boundary.
- **`--reload` through the CLI was exercised against the real gateway only for the success case** (a non-gateway rotation). The failure and 4001 branches are hermetic.
- **Concurrency between two real migrations** (lock contention) is hermetic only.
- **`npm run build` and `npm test` pass; Rust gates were not run** because no Rust code changed.
- **Packaging:** the clean-host candidate verifier (opt-in `BLINDPASS_PACKAGE_INSTALL_TEST=1`) passes for the new bin, but that test still fails at `HEAD` without this work on an unrelated, pre-existing expectation of 19 SBOM components against the 10 the bundle has. It was not changed.
- **Dependency guard:** no dependency was added or upgraded; the lockfile gained one `bin` field for the workspace package. The Socket-blocked tools exist only in the guest.
- Removing plaintext originals (backup, `.bak*`, `last-good`, `.env`) remains a separate operator action; erasure of historical copies is not claimed.
