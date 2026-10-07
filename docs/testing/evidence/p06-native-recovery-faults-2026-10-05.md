# P06 native restore unit, native fault scenarios and Compose stale-source refusal — 2026-10-05

**Status:** execution evidence on the uncommitted tree above `8a595ad`. It closes three gaps left by the [packaged recovery record](p06-packaged-recovery-2026-10-05.md): the native restore was a documented recipe, the native profile had no fault scenarios, and the Compose recovery scenario never proved that the original stack stays refused once a restored stack is active. P06 acceptance remains false (see Limits).

## Built

- `deploy/native/blindpass-controller-restore.service` (new, packaged and installed by `controller-install.py`, listed in `release-artifacts.py`). `Type=oneshot` as `blindpass`, never enabled or started by the installer, `Conflicts=blindpass-controller.service`. It is skipped (condition failed) unless `/etc/blindpass/controller-initialized`, `/etc/blindpass/controller-restore.env` and the two offline custody files `/etc/blindpass/controller-restore/{recipient-key,signing-certificate}` exist. Custody and the authority URL arrive as `LoadCredential`; staging is the tmpfs `RuntimeDirectory=blindpass-controller-restore`; the only writable persistent path is `/var/lib/blindpass/controller-restore`. Hardening: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectHome`, kernel/clock/hostname/proc protections, `MemoryDenyWriteExecute`, empty capability sets, `SystemCallFilter=@system-service`, `LimitCORE=0`, `UMask=0077`.
- `tests/deployment/native-guest.py`: `native_recovery()` now restores through that unit (NR01–NR05); new `native_faults()` (NF1–NF3) and the `--faults` mode of `native-install.sh`.
- `tests/deployment/compose-up.py --scenario recovery`: new stage **P06-RC8** (stale source), both profiles.
- Docs: [native quickstart](../../deploy/native-quickstart.md#restore-and-recovery-activation-on-the-native-package), [Compose quickstart](../../deploy/compose-quickstart.md), [recovery activation runbook](../../deploy/recovery-activation.md), README rows.

## Test-first record

`test_p06_na11_the_restore_unit_is_managed_hardened_and_holds_only_offline_custody` was written first and confirmed red, then the unit was shipped (`native-authority-test` 11, `native-package-test` 7, `release-artifacts-test` 8 tests pass). **The guest scenarios (NR01–NR05, NF1–NF3) and RC8 were written after the unit and the existing recovery code, so they are not red/green proofs.** They were run and corrected where they exposed defects (below).

## What ran

All runs on the same tree, sequentially, x86-64. The native archive was rebuilt from the tree on the bookworm baseline (`libc` symbol floor `GLIBC_2.34`, so Debian 12 runs it) and contains the restore unit (`blindpass-controller-0.1.0-linux-x86_64.tar.zst`, sha256 `7843cf14305711548e13d510640aec18b9fba5f9dd63a541b5305be8fc20d682`). Compose runs use the attested `blindpass-p06-controller:final-sbom` image (built after the last Rust edit).

| Gate | Result |
|---|---|
| `native-install.sh --recovery`, Debian 12 and Ubuntu 24.04 | NR01–NR05 pass on both (restore through the packaged unit; host custody refused; unit skipped without operator inputs; hardening properties asserted; keys byte-identical; review, waiver, attestation, activation, rollback) |
| `native-install.sh --faults`, Debian 12 / Ubuntu 24.04 | NF1 SIGKILL: not ready without a fresh activation, then ready in 0.344 s / 0.392 s (bound 15 s). NF2 20 s SIGSTOP: controller still ready, 0.011 s / 0.007 s after resume. NF3 database loss with an activation in place: refused with reason `state_missing` in 0.3 s / 0.2 s, never recreated, restored state serves again. Identity, keys and state unchanged in all |
| Native matrix (default, `--power-loss`, `--tool-faults`, `--credential-faults`) on both OSes with the new archive | 8 of 8 pass |
| `compose-up.py --profile sqlite` and `--profile postgres` | pass |
| `compose-up.py --scenario handoff` (SQLite), twice | both pass |
| `compose-up.py --scenario recovery`, SQLite and PostgreSQL, twice each | 4 of 4 pass (RC1–RC8) |
| `compose-backup.py --payload-bytes 100000000 --faults`, `compose-backup-postgres.py` | pass |
| `native-authority-test` 11, `native-package-test` 7, `release-artifacts-test` 8, `container-config-test` 10 | pass |
| `tests/fleet/p06-relay-vm.py`, `p06-recovery-activation-vm.py --scenario main` (host SQLite controller, real broker and node in QEMU) | both exit 0 on the final tree; the activation run ends with ordinary grant consumption through the activated controller, source refusal and a rollback under epoch 3 |

### P06-RC8 (stale source, Compose)

After RC5 the source stack is stopped with its volumes intact. The harness fences the record, reserves a higher recovery epoch, creates a **second Compose project** with fresh volumes and its own network (the one authority container is attached to both), restores the same archive with the offline custody, runs review, a named node waiver, attestation and recovery activation, and starts the restored stack, which becomes ready. Then:

1. With the restored stack holding the guard, an ordinary `authority-activate.sql` for the original is refused, and the original controller starts as `startup_failed` with reason `fenced`; it is never ready while the restored stack stays ready.
2. After the restored stack is stopped, an ordinary activation **is accepted by the authority** (the owner and tenant identifiers are the same), but the original controller still never becomes ready: `startup_failed`, reason `recovery_required`, because its database is at the older epoch. Epoch comparison in the controller is what blocks it here, not the authority.
3. The restored stack is activated again and serves. On SQLite the original `controller.db` is byte-identical before and after the probes. The second project and its volumes are removed (checked: no container or volume of either project remains).

This is a stopped source on one Docker host. A source still running on another machine is covered only by the authority's guard (no second holder) and the operator's attestation.

## Defects found and fixed

- **Harness (three occurrences):** `native-guest.py` used `run(..., success=False)` and `activate(success=False)` as "ignore the result", but those helpers assert failure. `reset-failed` on a healthy unit and the NF1 retry loop therefore failed on success. Replaced with tolerant calls. The scenarios had never run before this session.
- **Receipt location (documentation bug):** the restore receipt printed by the unit never appeared in the unit's journal in the guests (0 lines for the invocation, after `journalctl --sync`); I did not find out why. The guest scenario and the quickstart now read `<destination>/restore.json`, which the command writes itself. The quickstart says not to rely on the journal.
- **Opaque PostgreSQL restore refusal:** a restore into a fresh Compose PostgreSQL project is refused (`authenticated fenced restore refused`) because the init hook's empty `controller` schema counts as a user schema. This was already a documented operator step (quickstart step 4) but the refusal gives no reason, so a first-time operator will not see why. RC8 performs the documented `DROP SCHEMA controller CASCADE`. Not changed in code: allowing an empty schema would alter the "never merge or replace" restore rule and needs a decision and tests.
- **Stale binaries:** the first native attempt packaged binaries older than source edits made the same day; they were rebuilt (bookworm baseline) before the runs recorded above.

## Limits

- No real node on the packaged profiles: one seeded broker trust row is covered only by a named waiver. The relay and a node reconnecting to a packaged recovered controller are proven only by the QEMU harnesses with host controllers.
- Native restore and faults ran on x86-64 only; the native authority is the guest's own PostgreSQL (not independent). The native stale-source case (restore on a second guest while the first stays stopped) was not run; only Compose has RC8.
- RC8 uses one Docker host and one authority container attached to two networks.
- NF2: a 20 s suspend left the controller ready and unfenced in these runs; the scenario accepts either outcome (ready, or fenced then one fresh activation) and does not say which one is guaranteed.
- No Rust code changed in this work: `cargo fmt`, `clippy` and the workspace tests were not rerun for it (the earlier records cover the Rust tree; the binaries used here were built from it).
- Still open for P06: the full slice 9 matrix (remote and stock-client runs, loaded bounds), multi-version upgrade chains, native aarch64 hardware, hosted CI and image publication, an independent cryptographic review of the custody split, and the owner's acceptance review.
