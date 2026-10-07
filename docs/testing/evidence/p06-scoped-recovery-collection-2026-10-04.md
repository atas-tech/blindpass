# P06 scoped recovering Store collection — 2026-10-04

**Partial implementation; all nine slices remain active and unaccepted.**
Store open/stage/finish now use the [signed authenticated local snapshot](p06-authenticated-recovery-snapshot-2026-10-04.md)
and actual bound live recovering holder. The independently protected challenge's
complete snapshot scope must match before page mutation or one-use completion;
local/protected scope is checked again before returning metadata. A valid broker
signature alone cannot authorize another snapshot context.

The external schema4 collector verifies independently current/approved-pending
keys, signatures, page order/digest and history coverage. Restored node rows do
not become trust. The Store supplies no caller-chosen time/digest/epoch/ID to
collection. Definite malformed/conflicting input refuses without hidden retries;
actual authority loss preserves fencing/uncertainty. Status remains metadata:
no local record application, grant revival, provider completion, node quarantine
release, ordinary route, HTTPS node relay or protected activation is enabled.

Reports, signatures, digests and nonces are reconciliation metadata. No source
plaintext or broker private key enters collection. The existing private issuer
signer and authority process proof retain their reviewed runtime/library/OS copy
lifetimes. No new dependency, erasure guarantee or previous-host stop proof exists.

## Actual test-first execution

The first test attempt had an incorrect coverage type import and did not execute
behavior. After correction, an actual encrypted restore and protected broker
publication reached the valid-scope collection assertion and failed while the
entry points still refused. That is the behavioral red result (exit101).
Two initial cases passed before the later expanded refusal/socket cases and
independent administrator progress assertion. The current four cases pass:

- Earlier actual active7 holder publishes broker key41, then quiesces before an
  explicit fence/reservation8 and actual encrypted restore. Scoped collection
  verifies that protected key despite stale invalid restored node key strings;
  forged signatures refuse, exact pending pages retry, finish consumes once and
  replay refuses. Local operations remain uncertain, grants revoked and node
  reconciliation quarantined; actual production restart remains fenced.
- Protected challenges created with different valid snapshot time/digest refuse
  before page progress or nonce consumption, despite valid current-node signatures
  and identical other identity bindings. Administrator reads independently prove
  zero page mutation; the legitimate holder retains metadata access.
- Unknown node/version, other recovery ID/generation/nonce/node, gap and incomplete
  finish refuse; challenge/nonce/progress remain unchanged and ordinary work closed.
- Real scoped stage waits on a held authority row; terminate only its owned held
  backend, observe fencing/uncertainty and quiescence refusal, release the blocker
  and wait for owned server work to end. Nonce stays identical, unconsumed, with
  progress conservatively0or1. Cancellation is not rollback or SourceStopProof.

The private-copy control removes only the pre-write scope comparison. The later
check still refuses delivery/fences, but an actual page has already mutated:
`foreign scope page mutated before refusal`, actual1 vs expected0 (exit101).
This proves a final response check cannot replace authorization before mutation.
Production hashes match, private tree removed and normal-source gates follow.

| Current selected integration run | Passed |
|---|---:|
| [store-expanded](p06-scoped-recovery-collection-2026-10-04/store-expanded.log) | 4 |
| [authority-full-sqlite](p06-scoped-recovery-collection-2026-10-04/authority-full-sqlite.log) | 33 |
| [authority-full-postgres](p06-scoped-recovery-collection-2026-10-04/authority-full-postgres.log) | 33 |
| [invalidation-sqlite](p06-scoped-recovery-collection-2026-10-04/invalidation-sqlite.log) | 6 |
| [invalidation-postgres](p06-scoped-recovery-collection-2026-10-04/invalidation-postgres.log) | 6 |
| [legacy-sqlite](p06-scoped-recovery-collection-2026-10-04/legacy-sqlite.log) | 4 |
| [legacy-postgres](p06-scoped-recovery-collection-2026-10-04/legacy-postgres.log) | 4 |
| [production-sqlite](p06-scoped-recovery-collection-2026-10-04/production-sqlite.log) | 10 |
| [production-postgres](p06-scoped-recovery-collection-2026-10-04/production-postgres.log) | 10 |
| [startup-sqlite](p06-scoped-recovery-collection-2026-10-04/startup-sqlite.log) | 5 |
| [quiescence-postgres](p06-scoped-recovery-collection-2026-10-04/quiescence-postgres.log) | 4 |
| [restore-sqlite](p06-scoped-recovery-collection-2026-10-04/restore-sqlite.log) | 13 |
| [migration-regression](p06-scoped-recovery-collection-2026-10-04/migration-regression.log) | 1 |
| [restore-failpoints](p06-scoped-recovery-collection-2026-10-04/restore-failpoints.log) | 15 |
| [receipts-regression](p06-scoped-recovery-collection-2026-10-04/receipts-regression.log) | 6 |

**154 overlapping case executions across 15 runs**,
zero selected failures/ignores and zero owned cleanup errors. Both-store surrounding
schema18 authority/invalidation/legacy/production, startup, PostgreSQL quiescence,
ordinary/dedicated-fault restore, authority migrations and protected receipt cases
pass. The new scoped Store flow executes on actual SQLite restores. Its generic
read/collection branches compile for PostgreSQL, but full PostgreSQL archive
restore/scoped application remains unexecuted and tied to its separate toolkit.
These cases manually sign report fixtures; they do not establish actual broker
control/HTTPS relay/stock-client delivery or complete producer resource bounds.

Node26 build/tests, Rust workspace, Clippy, format, OpenAPI and diff pass.
Workspace Rust: **726 passed, 0 failed, 90 ignored**.
SPS retains17skippedfiles/101skippedtests; other ignores are not new runtime proof.
No new real VM, stock-client, full-profile parity, GUI or publishing execution.
[Gates](p06-scoped-recovery-collection-2026-10-04/gates.json), [counts](p06-scoped-recovery-collection-2026-10-04/counts.json),
[source pins](p06-scoped-recovery-collection-2026-10-04/source-pins.json), [control](p06-scoped-recovery-collection-2026-10-04/controls.json)
and raw logs retain scope. User P03 remains unstaged66additions/0deletions; index
empty, dependency manifests unchanged and no completion commit for slices5/6.

## Remaining acceptance

RC08c retains full higher-epoch/missing-history/cancellation/final-commit/resource
scenarios; selected passing tests do not complete it. RC08d needs actual protected
page re-verification/application with exact node/grant/operation/epoch mapping,
uncertain providers and offline/post-backup unknown quarantine. RC09 needs actual
unprivileged private-broker/verified-HTTPS relay with signed requests and replay/
expiry/malformed/transport faults. Persistent roles/session/provider review,
authenticated prior-host/server stop and explicit protected activation remain open.

All nine slices remain required: PostgreSQL custom dump/full isolated restore and
pending toolkit review; automatic verified pre-upgrade backup/locked migrations/
retention3; both native SQLite↔Compose directions, interrupted rollback/status
--nodes; three profiles/remote controller/two-broker real VM/stock-client fault
parity and inherited P02.6/P03/P05. GHCR/ARM/Unraid GUI and restic remain separate.
No SourceStopProof or unfence exists; full phase acceptance false.
