# P06 protected recovery activation (RC09-RR05) — 2026-10-05

**Status:** component, process and QEMU end-to-end evidence on the uncommitted tree above `8a595ad`. It implements [ADR 0014](../../product/decisions/0014-p06-recovery-activation.md) (owner decisions P06-D30, D31, D32) so that a restored `recovering` controller can reach a serving state. The operator procedure is the [activation runbook](../../deploy/recovery-activation.md). **P06 acceptance is not claimed**; the blockers are listed at the end.

## What was built

- **Authority layout 5** (`deploy/controller/recovery-authority.sql`, migration `recovery-authority-v4-to-v5.sql`): insert-only `recovery_source_stop`, `recovery_node_waivers`, `recovery_review_decisions` (replaceable until completion), `recovery_review_complete`, `recovery_activations`. Runtime-role functions `decide_recovery_item`, `waive_recovery_node`, `complete_recovery_review`, `recovery_activation_gaps`; administrator-only `attest_source_stop` and `activate_recovery` (never granted to the runtime role; the controller's start-time role audit refuses a credential that can call them or write the tables).
- **Scripts:** `authority-recover-attest.sql`, `authority-recover-status.sql`, `authority-recover-activate.sql`. `authority-activate.sql` still refuses `recovering`. All four plus the migration are in the native release archive list.
- **Controller:** `blindpass admin recovery status | review list | review decide | review complete | waive-node` (CLI over the recovering controller's local socket; the admin socket now receives the signer-bearing store). Review items come from the existing recovery tables (operations, agents, operator accounts, workloads, policies, source bindings, node key rotations) plus `grant_intent` items for node-reported grants the controller could not reconcile. Completion applies the local effects first (re-enable accepted accounts the invalidation disabled; revoke waived nodes), then records the authority completion.
- **Latch release:** the permanent local recovery latch is released at start only when the authority holds `recovery_activations` for the exact target epoch and the process holds the active record at that epoch.

## Test-first record (honest)

The authority SQL and the Rust plumbing were written **before** the component tests, so those are not a red-then-green record. What the tests did do: the first `recovery_activation` run was red on a real SQL bug (`gaps || 'name'` is an array-literal parse error, found by RA01/RA06/RA07 and fixed with `array_append(..., 'name'::TEXT)`). RV03 failed once on SQLite with `RecoveryRequired` on the first run after a cold build (host under load) and passed on the next five runs and on PostgreSQL; the cause was not isolated, so treat it as an unexplained one-off. The admin-socket bug (signer-less store) was found only by the QEMU run, then covered by a unit test for the refusal path. The VM harness itself was corrected three times against real behaviour (wrong operation id after a second grant, a two-row attestation query, an operator-account decision that left no login in the waiver scenario).

## Component scenarios

| ID | Where | What it shows |
| --- | --- | --- |
| RA01 | `recovery_activation` | Fresh recovering record names `source_stop_missing`, `review_incomplete`, `node_uncovered`; activation refused naming them; with the holder live also `source_process_live`; nothing changes |
| RA02 | same | The runtime role cannot `attest_source_stop`, `activate_recovery`, or write/delete any of the five tables |
| RA03/RA03b | same | Attestation needs a free guard (lock error with a live holder), is insert-only (update/delete refused), and is refused for fenced or active records; activation refused as `not_recovering` |
| RA04 | same | Decisions replaceable until completion, then final (even for the administrator); invalid category/decision/operator refused; completion count must equal the decisions |
| RA05 | same | Only the live recovering holder can write decisions, waivers or completion |
| RA06 | same | Success activates once (`recovering` to `active`, revision +1, activation row); a second activation and a claim by a pre-activation reservation holder are refused |
| RA07 | same | Three nodes: one covered, two waived by name (each revoked in the authority); a covered node cannot be waived; an unknown node cannot be waived; waivers close at completion; an uncovered node blocks activation |
| RA08 | same | Review incomplete blocks activation even when everything else is met |
| RA09 | same | Fencing a recovering record and activating it with the ordinary scripts leaves no activation row |
| RV01 | `recovery_invalidation` | 19 items enumerated from the real invalidation (10 operations, 3 accounts, 6 others); precheck names open gates; refusals (unknown item, bad decision, bad operator, complete while undecided) do not fence the controller |
| RV02 | same | Completion re-enables only accepted accounts that the invalidation disabled (a previously disabled viewer stays disabled); rejected items stay invalidated; decisions close |
| RV03 | same | An unreported node blocks completion; a waiver revokes it in the authority and completion revokes it locally with the operator recorded |
| RV04 | same | Protected activation releases the latch at the next start; the fence-then-activate bypass does not |
| `p06_pt05` | `recovery_authority_migration` | v4→v5 migration: refuses an active tenant, a held guard, the runtime role and a replay; preserves the record and broker trust; new tables start empty; startup refuses layout 4 |
| admin socket | `admin_socket` | Every recovery command answers `recovery_not_active` on a non-recovering controller |

## QEMU/KVM end to end

Harness `tests/fleet/p06-recovery-activation-vm.py` (reuses the relay harness: production authority-backed controller with built-in TLS on the host, real broker and node in a disposable guest, throwaway authority database, verified HTTPS). Outputs: [main runs](p06-recovery-activation-2026-10-05/run-main-1.txt) (three in the gates list), [waiver](p06-recovery-activation-2026-10-05/run-waiver.txt).

`--scenario main`:

| ID | Shows |
| --- | --- |
| G1–G5 | Before any gate is met: `authority-activate.sql` refuses the recovering record; `authority-recover-activate.sql` names all four gates; an attestation while a controller holds the guard is refused with no row; the controller precheck lists the fixed gate names; the old source refuses to start |
| R1 | Real relay: `state=covered pages=1 activation_permitted=false`; authority and precheck show the node covered |
| V1–V2 | Items listed; complete refused while undecided; unknown item refused; controller not fenced; every item decided with operator ids, a decision changed once, review completed (5 items, 2 accounts re-enabled); decisions closed; only `source_stop_missing` remains |
| A1–A2 | With the controller stopped only the missing attestation blocks; attested (who and host recorded); ordinary script still refuses; activated `recovering:2:4` to `active:2:5`; a second activation refused |
| S4 | The restored controller starts, is ready 0.3 s after start; the unchanged node (key version 1, no re-enrolment) passes `blindpass status --nodes --require-online` about 2 s after start; operator login works; the recovered operation stays `uncertain` |
| S5 | An ordinary grant, approved by a second operator, delivered to the node and consumed by a workload in the guest through the activated controller |
| S6 | The old source refuses to serve and to migrate after activation; the activated controller stays ready and the record unchanged |
| B1–B2 | Restore-based rollback rehearsal on the same real host: fence and stop the activated controller, reserve epoch 3, restore the **original archive** again, relay, review (6 items: the grant the node consumed after the archive appears as an unknown `grant_intent` to decide), attest and activate separately (epochs 2 and 3 each have their own attestation and activation row), serve with the node online |
| L1 | No operator, approver or bootstrap password, enrolment token, authority password or PEM private key in any controller or guest log |

`--scenario waiver` (the node never reports): completion refused while the node is neither covered nor waived; a waiver for an unknown node refused; both without fencing the controller (W1). The node is waived by name (broker trust revoked in the authority, who and why recorded) and completion revokes it locally (W2). After activation the controller is ready, the node stays revoked, `status --nodes --require-online` fails, its broker trust stays revoked in the authority (W3), and no log carries a credential (L1).

## Gates

All run sequentially on the final tree (shared ports and fixtures). Outputs: [drivers](p06-recovery-activation-2026-10-05/drivers.txt), [native matrix](p06-recovery-activation-2026-10-05/native-matrix.txt).

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`: clean. `cargo test --workspace --locked --offline`: **774 passed, 0 failed, 149 ignored** (ignored cases run through the authority driver or in-image scripts).
- Authority driver, every target exit 0 with no skipped cases: `recovery_authority` 34 (SQLite and PostgreSQL controller), `production_ownership` 32+32, `legacy_authority` 4+4, `recovery_invalidation` 11+11, `recovery_activation` 10+10, `restore_stage` 24+24, `recovery_authority_migration` 1, `recovery_receipts` 6, `restore_postgres` 5, `deployment_startup` 5, `store_quiescence` 4 (PostgreSQL only).
- `tests/deployment/{release-artifacts-test,native-package-test,container-config-test,controller-sbom-test}.py`: pass.
- Image `blindpass-p06-controller:act` (id `daccd5a97e8b`, plain build, not the attested SBOM build) built from the tree: `compose-up.py --profile sqlite` (11 PASS), `--profile postgres` (12 PASS), `--profile sqlite --scenario handoff` (8 PASS), `compose-backup.py --payload-bytes 100000000 --faults` (8 PASS) and `compose-backup-postgres.py` (6 PASS), all exit 0. These exercise layout 5 install, the runtime-role audit and the packaged scripts' presence; they do not run a Compose recovery.
- Native matrix on the archive built through the bookworm-baseline route (`scripts/release/Dockerfile --target export`, `build-tarballs.sh --allow-dirty`), Debian 12 and Ubuntu 24.04 guests, 8 modes: default (13 PASS each), `--power-loss` (14), `--tool-faults` (15), `--credential-faults` (28), all exit 0 (power-loss runs used `BLINDPASS_NATIVE_RUN_ROOT=/dev/shm`).
- QEMU harnesses on the final binaries: `p06-relay-vm.py` exit 0 (15 PASS), `p06-handoff-vm.py` exit 0 (22 PASS; the two failpoint cases H1a and H7a were skipped because no failpoint controller was supplied), `p06-recovery-activation-vm.py --scenario main` **three consecutive green runs** ([1](p06-recovery-activation-2026-10-05/run-main-1.txt), [2](p06-recovery-activation-2026-10-05/run-main-2.txt), [3](p06-recovery-activation-2026-10-05/run-main-3.txt), 28 PASS lines each, including the rollback rehearsal) and `--scenario waiver` green (11 PASS). Earlier runs on the way failed for the harness and admin-socket defects listed below.
- Not run: `npm run build`/`npm test` (no JavaScript changed), the attested SBOM image build, `aarch64`, hosted CI.

Mutation check: removing the `node_uncovered` gate from the SQL made `recovery_activation` fail 2 of 10 (RA01, RA07); restored and rerun green (the file was verified byte-identical afterwards). No other mutation checks were run.

## Bugs found and fixed here

- `recovery_activation_gaps`: `gaps || 'text'` parsed as an array literal (component test).
- Admin socket handed recovery commands a store without the issuer signer, so every review command failed with a missing-state error and the controller logged it (VM run only; now covered by a refusal unit test, and the failure path logs the error text).
- Design flaw caught before implementation was finished: with the latch permanent no restored controller could ever serve, and releasing it on any active record would have let `authority-fence.sql` plus `authority-activate.sql` bypass every gate; the activation proof row and RA09/RV04 close that.

## Limits and what still blocks P06 acceptance

- One controller (SQLite) on the host and one real broker and node. A two-broker or multi-node recovery against real nodes was **not** run: it needs a second guest or broker identity, which the single-guest harness does not provide. Multi-node covered/waived logic is component level only (RA07, RV03). **Update 2026-10-05 (later):** two-guest and PostgreSQL-controller runs now exist, see the [recovery matrix record](p06-recovery-matrix-2026-10-05.md).
- Compose and native-package recovery (restore plus activation) were not exercised; the packaged profiles were gated for install, run and backup only. A PostgreSQL controller was covered by the component tests on both backends, not in a VM. **Update 2026-10-05 (later):** two-guest and PostgreSQL-controller runs now exist, see the [recovery matrix record](p06-recovery-matrix-2026-10-05.md).
- Review decisions are metadata. Nothing calls a provider and nothing proves a provider-side effect did or did not happen. The authority can only count decisions; item enumeration is controller-side.
- The attestation is the administrator's statement. The guard lock sees only processes that can reach the authority database, so a source on a partitioned network is not proven dead; the runbook says to fence it from the authority database first.
- Completion is final; a missed item means restoring again under a higher reservation. A waived node must be re-enrolled; there is no un-waive.
- Key-version pinning (D27), D12 fail-closed behaviour and ADR 0010 follow-ups are unchanged. Hosted CI, a fresh-clone run, aarch64 native and the owner's acceptance review were not performed.
- RV03's one-off SQLite failure (above) was not root-caused.
