# P06 recovery matrix: PostgreSQL controller and two real nodes — 2026-10-05

**Status:** QEMU/KVM execution evidence on the uncommitted tree above `8a595ad`. It closes two gaps the [activation record](p06-recovery-activation-2026-10-05.md) listed as unexercised: recovery of a **PostgreSQL-backed controller** in a VM, and recovery with **two real broker+node pairs** (covered, waived and refused). **P06 acceptance remains false.** No product defect was found by these runs; the defects below were in the harness.

Raw run output (the `P06-*` result lines only, timestamps stripped, nothing secret) is in [p06-recovery-matrix-2026-10-05/](p06-recovery-matrix-2026-10-05/).

## What ran

All runs: x86-64 KVM guests (the pinned P01 Ubuntu 24.04 cloud image), a production-mode (authority-backed, built-in TLS) controller **process on the host**, an independent throwaway authority database in the `blindpass-postgres` fixture, the release binaries of this tree, one run at a time.

### PostgreSQL controller

`--backend postgres` on [`p06-relay-vm.py`](../../../tests/fleet/p06-relay-vm.py) and [`p06-recovery-activation-vm.py`](../../../tests/fleet/p06-recovery-activation-vm.py). The controller store is the dedicated `controller` schema of a fresh database owned by a fresh role; the host has no PGDG toolkit, so `backup create`, `backup verify` and `restore` run the product binary inside the controller image (`blindpass-p06-controller:pkgrec`, id `f88404523a4d`, which carries the pinned PGDG toolkit) against the same database and files. Restore targets an empty database; the schema is created by `pg_restore`.

| Harness | Stages / scenario | Result |
|---------|-------------------|--------|
| `p06-relay-vm.py --backend postgres` | enroll, one consumed grant, backup, fence, restore into an empty PostgreSQL target, relay → covered, one quarantined report, grant mapped `matched`, ordinary routes 503, repeat relay idempotent, no secret in any log | 7 PASS, then 7 PASS (rerun) |
| `p06-recovery-activation-vm.py --backend postgres --scenario main` | gates and refusals (G1–G5), relay, review, attestation, activation, serve with the unchanged node online, ordinary grant consumed, **stale source refused (start and migrate) before and after activation**, restore-based rollback (a second recovery epoch needing its own review, attestation and activation) | 28 PASS, then 28 PASS |
| `p06-recovery-activation-vm.py --backend postgres --scenario waiver` | node waived by name, stays revoked, activation succeeds | 11 PASS, then 11 PASS |

### Two real nodes

[`p06-recovery-matrix-vm.py`](../../../tests/fleet/p06-recovery-matrix-vm.py): guest A (SSH 22231) and guest B (SSH 22232), each with its own overlay, SSH key, broker and node; both enrolled over the same verified-HTTPS controller (the authority holds active broker trust for each). A consumes one grant before the backup; B has no consumed grant.

| Scenario | Proven | Result |
|----------|--------|--------|
| `refusal` | A relays (covered); B never relays and is not waived. The authority and the precheck show B uncovered. With **every review item decided**, `review complete` is refused (`blindpass: refused`); `authority-recover-activate.sql` is refused naming `node_uncovered` (and the other two open gates); the restored controller is not fenced and stays 503; the authority record reads `recovering:2:4` before and after (phase, epoch and revision) | 11 PASS, then 11 PASS |
| `waiver` | Completion refused while B is neither covered nor waived; an unknown node cannot be waived; B waived by name (authority trust revoked, operator and note recorded, A untouched); completion revokes exactly B locally; attestation and activation succeed; the controller is ready, **A online** (`status --nodes --require-online`), **B stays revoked** after 15 s with its `last_seen_at` unchanged while its guest services keep retrying; an ordinary grant is approved and **consumed on A**; the same workload registration is accepted for A (201) and refused for B (409 `node_unavailable`); old source refused; no secret in the controller or either guest's journals | 19 PASS, then 19 PASS |
| `both` | A relays; activation is refused naming `node_uncovered` while only A is covered; B relays after A (both covered, neither waived, A's repeat relay still covered); review, attestation, activation; **both nodes online**; an ordinary grant consumed on A and another on B; old source refused; no secret in any log | 23 PASS, then 23 PASS |

Runs that did not pass first time: the `both` scenario's first run failed in the harness (it asserted `pages=1` on A's repeat relay; the repeat reports `pages=0`); it was corrected and run twice more. The `waiver` first run predates the added `node_unavailable` assertion; both recorded runs of that scenario's final form pass (second run). The first PostgreSQL relay attempts failed in the harness: the toolkit container inherited the image's `BLINDPASS_PROXY_REQUIRED=1` and `BLINDPASS_DATA_DIR=/data` defaults ("backup controller configuration invalid"), now overridden.

### Regression (unchanged SQLite harnesses, after the refactor)

`p06-relay-vm.py` 15 PASS; `p06-handoff-vm.py` 20 PASS and 2 SKIPPED (H1a and H7a need the failpoint build, as before); `p06-recovery-activation-vm.py --scenario main` 28 PASS and `--scenario waiver` 11 PASS. Run sequentially after the final harness edit. The matrix `both`, `refusal` and `waiver` rows above are the post-edit second runs.

## Harness changes

- `p06-relay-vm.py`: a `GuestVM` class (own overlay, key and port) replaces the single-guest fields; `Rehearsal.vm` stays the default guest so the existing stages are unchanged and `add_vm` boots another. A `PgStore` creates the controller-store roles and databases; `Controller` takes a database or a data directory; `toolkit_command` runs backup, verify and restore in the image; `db_rows` reads either store; `--backend` and `BLINDPASS_P06_BACKEND` select the backend; the PostgreSQL run executes the `source`, `enroll`, `grant`, `restore`, `relay` stages only.
- `p06-recovery-activation-vm.py`: `--backend`; the stale-source check passes the original database.
- `p06-recovery-matrix-vm.py`: new.

## Test order

These harnesses were written **after** the product behavior they exercise (the recovery code, review commands and authority scripts were already in place and component-tested); they are not a red/green record, and no product code changed. The assertions were not mutation-checked, except that the refusal scenario shows each gate refusing and the waiver and both scenarios show the same state passing after the gate is met, which is the control. The first failures listed above were harness defects found by running.

## Limits

- The controller runs on the host. PostgreSQL recovery here is **not** a packaged recovery: no Compose or native PostgreSQL profile restore, no remote controller, no TLS edge. The backup and restore binary is the image's build and the serving binary is the host's `target/release` build of the same tree; they were not compared bit for bit.
- The PostgreSQL relay harness does not run the fault and rebase stages (nonce expiry, TLS errors, lost page); those stay SQLite-only. No PostgreSQL handoff (the planned handoff is SQLite-only).
- The toolkit run temporarily hands the run directory (except the guest disk directories) to UID 10001; the controller process and open guest files are unaffected, but the harness cannot read its own files during that window.
- Two nodes means two guests on one host and one clock, one controller and one authority. Relays ran sequentially (A then B) within the 30 s nonce; B-then-A, concurrent relays and a node reporting records the other lacks were not run. B had no consumed grant before the backup, so its report mapped nothing. The waiver variant leaves B's guest running; a node that is actually lost is simulated only by never relaying.
- x86-64 only; no aarch64 hardware; no loaded or large-database timing; no multi-version upgrade in the loop.
- The refusal and waiver gates are proven for the named gates; the provider-side effect of an accepted, rejected or revoked item is metadata only (no provider API is called).
- Still open for P06: the Compose stale-source refusal (Compose restores in place), a packaged native restore unit, the full slice 9 matrix (native, remote controller, stock client, loaded bounds), native aarch64 hardware, multi-version upgrade chains, hosted CI and image publication, an independent review of the custody split and the owner's acceptance review.
