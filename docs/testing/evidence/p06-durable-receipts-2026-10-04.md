# P06 durable protected recovery receipts — 2026-10-04

**Partial implementation; the full nine-slice phase remains active and unaccepted.**
No completion commit exists for slices 5/6. The protected PostgreSQL authority
uses the already reviewed SQLx stack and remains outside controller backups.
This adds an external collector primitive; local recovering application and actual
node HTTPS relay (RC08/RC09), source-stop proof and protected activation remain open.

Schema 4 adds immutable challenge/page context and monotonic broker observations.
Fresh public 32-byte nonces bind exact tenant, issuer, owner, recovery ID, current
external epoch/revision, independently current or explicitly approved pending
broker key, snapshot epoch/time and backup digest. Exact pending retries resume
one durable challenge; reacquisition cannot reset it, including consumed receipts.
The actual held backend/process token proves writes in the recovering phase.

The Rust collector verifies Ed25519 over canonical pages using protected current
keys, then checks sequential pages, fixed manifest and complete ordered digest.
It reads at most eight 64-KiB pages per batch with a 30-second completion deadline;
individual authority operations retain the three-second bound and fencing.
Only complete authenticated history covering the backup timestamp consumes the
challenge atomically. Unknown/pruned/unmapped coverage remains incomplete; an
observed epoch at or above the reservation requires rebase. Protected observations
survive partial collection and require a higher reservation despite stale caller
input. Receipts do not acknowledge rotation, revive revoked nodes, resolve
provider effects, release quarantine or grant admission.

SQL functions enforce live context, holder proof, bounds and atomic publication;
they do not independently implement Ed25519 verification. Runtime credentials and
authority administrators remain in the deployment trust boundary. Returned rows
are metadata, not an admission capability. A local consumer must reverify protected
pages before applying them. Page contents are reconciliation metadata; no source
secret or broker private key enters the authority. Runtime process proof remains
private memory with the previously documented SQLx/server/OS copy lifetimes.

The administrator-only v3→v4 migration executes after the v2→v3 fixture migration.
It refuses active tenants, runtime administration, held guards and replay,
preserves prior epochs/revisions/key history/revocation/attempts, and permits a
subsequent actual schema-4 claim/publication. Its embedded component exactly
matches initial provisioning. Test-only reconstructed schemas do not establish
an installed deployment migration or authenticated prior-host shutdown.

## Actual execution

All six expanded receipt cases passed on the disposable PostgreSQL authority:
0/1/128/129/384 records and reacquisition between pages; wrong signatures, gaps,
conflicting headers and digest corruption; unknown/pruned/unmapped history and
higher-epoch rebase; approved pending and rotated revoked keys with retired-key
refusal; actual blocked stage/socket loss with irreversible uncertainty; and
runtime DML/reset/write-capable-credential refusal. The authority socket-loss test
terminates only its owned held backend while an actual page write is blocked.
It allows server-side work to finish after caller loss, retains nonce/progress and
uncertainty, and never interprets cancellation as rollback or source-stop proof.

Workspace credit exhaustion prevented one approval-review attempt from executing.
After the user restored credits, normal approval review authorized the expanded
run and following host checks. It is no longer a current host-test blocker.
Initial three-case and migration logs predate expanded key/socket/privilege cases
and the read-only cancellation adjustment; the expanded and regression logs below
are the current execution evidence. Initial missing-API/private-parser/generic
assertion compile failures are retained and are not behavioral red-test proof.

| Current integration run | Passed |
|---|---:|
| [receipt-expanded](p06-durable-receipts-2026-10-04/receipt-expanded.log) | 6 |
| [authority-full-sqlite](p06-durable-receipts-2026-10-04/authority-full-sqlite.log) | 33 |
| [authority-full-postgres](p06-durable-receipts-2026-10-04/authority-full-postgres.log) | 33 |
| [invalidation-sqlite](p06-durable-receipts-2026-10-04/invalidation-sqlite.log) | 6 |
| [invalidation-postgres](p06-durable-receipts-2026-10-04/invalidation-postgres.log) | 6 |
| [legacy-sqlite](p06-durable-receipts-2026-10-04/legacy-sqlite.log) | 4 |
| [legacy-postgres](p06-durable-receipts-2026-10-04/legacy-postgres.log) | 4 |
| [production-sqlite](p06-durable-receipts-2026-10-04/production-sqlite.log) | 10 |
| [production-postgres](p06-durable-receipts-2026-10-04/production-postgres.log) | 10 |
| [startup-sqlite](p06-durable-receipts-2026-10-04/startup-sqlite.log) | 5 |
| [quiescence-postgres](p06-durable-receipts-2026-10-04/quiescence-postgres.log) | 4 |
| [restore-sqlite](p06-durable-receipts-2026-10-04/restore-sqlite.log) | 7 |
| [migration-regression](p06-durable-receipts-2026-10-04/migration-regression.log) | 1 |
| [restore-failpoints](p06-durable-receipts-2026-10-04/restore-failpoints.log) | 9 |

These are **138 overlapping case executions across
14 runs**, all with zero failures and no ignored cases in those
selected runs. Every driver summary reports zero owned cleanup errors. They cover
both controller stores, invalidation, retained legacy authority, production startup,
quiescence, ordinary restore and dedicated crash-test restore. No new real VM,
stock-client, Unraid GUI, GHCR/ARM or full-profile parity execution occurred here.

Two private-copy controls actually fail RC05 assertions: treating unknown coverage
as covered produces `Covered` instead of `Incomplete`; omitting protected observed
epochs reserves 9 instead of required 10. Both exit 101 at the intended assertions,
The first observation mutation failed during empty-table fixture setup and is
retained separately; it is not the intended epoch assertion or a passing control.
The corrected mutation preserves aggregate behavior. Production source hashes
are unchanged and private trees are removed. Final gates
run afterward against ordinary sources. See [control results](p06-durable-receipts-2026-10-04/controls.json).

Node 26 build/tests, workspace Rust, Clippy, format, OpenAPI and diff pass.
Workspace Rust: **726 passed, 0 failed, 84 ignored**.
The default SPS run retains 17 skipped files/101 skipped tests. Ordinary ignores
are not new runtime acceptance evidence; selected authority tests execute through
the explicit driver above. [Gate results](p06-durable-receipts-2026-10-04/gates.json),
[counts](p06-durable-receipts-2026-10-04/counts.json), [source pins](p06-durable-receipts-2026-10-04/source-pins.json)
and raw logs retain actual scope. The user P03 file remains unstaged with
66 additions/0 deletions; index empty, dependency manifests unchanged, no commit.

## Remaining acceptance

RC01–RC07 retain their complete scenario requirements: passing selected cases
alone does not prove every power-loss/final-commit/resource boundary. RC08/RC09
require authenticated local snapshot metadata, actual application report staging
and protected page re-verification/application, a signed request/HTTPS node relay,
uncertain operation mapping, post-backup unknown/offline node quarantine and
persistent role/session/provider review. Actual previous-host/server stop and
explicit protected activation are mandatory and absent.

The nine-slice goal still includes PostgreSQL custom dump/full isolated restore
and its pending toolkit review; automatic verified pre-upgrade backups/locked
migration/retention 3; both native SQLite↔Compose transfers, interrupted rollback
and status --nodes; and all three profiles, remote controller, two-broker real
VM/stock-client faults and inherited P02.6/P03/P05 acceptance. Restic and broader
release/platform claims remain separately unaccepted.
