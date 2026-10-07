# P06 local protected receipt application — 2026-10-04

**Partial implementation; all nine slices remain active and unaccepted.**
Local schema19 retains reverified consumed intent reports as quarantine metadata.
It uses [signed archive scope](p06-authenticated-recovery-snapshot-2026-10-04.md),
[scoped collection](p06-scoped-recovery-collection-2026-10-04.md) and the actual bound
live recovering holder. External schema4 stays unchanged. Every persisted page is
reparsed and verified against independently current/approved-pending trust; the
complete ordered digest and unchanged challenge/trust are checked before one local
transaction commits. The reader retains at most eight bounded pages and one digest,
not a full in-memory history. Whole application uses the existing30second boundary.

Exact tenant/node/grant/operation/issuer-epoch/expiry bindings, matching operation
backreference/workload and existing uncertain/quarantined recovery queues become
`matched` metadata. Missing grants become `unknown`; other bindings `conflicting`.
No grant/operation is manufactured. Incomplete/unmapped/higher reports cannot
become application proof. Grants stay revoked, operations uncertain, nodes/reviews
quarantined and ordinary HTTP/issuance fenced. Consumed intent never proves an
effect completed or a provider session was removed. No SourceStopProof/unfence.

Application and external nonce consumption are separate commits. Replay/restart
reverifies the consumed receipt, checks exact durable local intent/report markers
and refuses damaged markers. Semantic failure after earlier page writes explicitly
awaits local rollback. Database failure/cancellation conservatively retains the
existing uncertainty latch; a cancelled future is not server rollback proof. This
Store API is not yet wired to a production admin command, HTTP route or node relay.

Reports/intents/signatures are metadata. No source plaintext or broker private key
enters collection/application. Existing issuer signer/process-proof library/OS
copy lifetimes remain unchanged; no dependency or erasure guarantee is added.
Migration19 is additive; SQLite authenticated schemas16/17/18 migrate only inside
isolated staging and the encrypted source archive remains unchanged. Earlier
binaries need pre-migration state for rollback. PostgreSQL migration compiles and
executes in local fixtures; full custom-dump archive restore is still unexecuted.

## Test-first execution and controls

The actual encrypted SQLite restore/current broker publication/covered receipt
reached the intended application assertion while the temporary entry point refused
(exit101). Initial three cases passed, then five expanded cases passed; the current
six cover:

- Exact match, durable metadata, replay and actual holder reacquisition/restart;
  production HTTP remains fenced and revoked/uncertain/quarantined state retained.
- Wrong node/operation/epoch/expiry and post-backup unknown grant records become
  conflict/unknown metadata without creating grants or completing operations.
- A real129record/twopage covered report has its second persisted signature altered
  only through the disposable administrator fixture. Application rejects it and
  rolls back the earlier128pending intents and report marker.
- Actual final SQLite transaction trigger failure preserves zero committed rows,
  original independently consumed nonce and irreversible fencing/uncertainty.
- Selected signed SQLite stage metadata is manually copied into a separate
  disposable PostgreSQL local schema: actual mapping/replay and final-trigger
  failure/rollback pass. This is deliberately not PostgreSQL archive restore proof.
- Collecting, unmapped/incomplete, higher/rebase, damaged local count markers
  and local controller epoch disagreement
  refuse application; prior markers remain unchanged and admission stays closed.

A further test-first corruption case failed when a changed local controller epoch
was initially accepted (exit101). Application now locks/checks current schema,
tenant and target epoch before writes. Both controls rerun against this final code.

Two actual private-copy controls fail intended assertions (exit101): replacing the
persisted signature with a fixture-key signature lets the tampered covered page
through; committing pending writes instead of rollback leaves128rows when0is
required. The first control retains an unused-shadowed-variable compiler warning;
its behavioral assertion executes. Controls are fixture-only; production hashes
match and private trees are removed before normal-source regression/gates.

| Selected current integration run | Passed |
|---|---:|
| [current](p06-recovery-application-2026-10-04/current.log) | 6 |
| [authority-full-sqlite](p06-recovery-application-2026-10-04/authority-full-sqlite.log) | 33 |
| [authority-full-postgres](p06-recovery-application-2026-10-04/authority-full-postgres.log) | 33 |
| [invalidation-sqlite](p06-recovery-application-2026-10-04/invalidation-sqlite.log) | 6 |
| [invalidation-postgres](p06-recovery-application-2026-10-04/invalidation-postgres.log) | 6 |
| [legacy-sqlite](p06-recovery-application-2026-10-04/legacy-sqlite.log) | 4 |
| [legacy-postgres](p06-recovery-application-2026-10-04/legacy-postgres.log) | 4 |
| [production-sqlite](p06-recovery-application-2026-10-04/production-sqlite.log) | 10 |
| [production-postgres](p06-recovery-application-2026-10-04/production-postgres.log) | 10 |
| [startup-sqlite](p06-recovery-application-2026-10-04/startup-sqlite.log) | 5 |
| [quiescence-postgres](p06-recovery-application-2026-10-04/quiescence-postgres.log) | 4 |
| [restore-sqlite](p06-recovery-application-2026-10-04/restore-sqlite.log) | 19 |
| [migration-regression](p06-recovery-application-2026-10-04/migration-regression.log) | 1 |
| [restore-failpoints](p06-recovery-application-2026-10-04/restore-failpoints.log) | 21 |
| [receipts-regression](p06-recovery-application-2026-10-04/receipts-regression.log) | 6 |

**168 overlapping executions across 15 runs**,
zero selected failures/ignores and zero owned cleanup errors. Surrounding both-store
authority/invalidation/legacy/production, startup, PostgreSQL quiescence, ordinary/
dedicated-fault restore, administrator migration and protected receipt cases pass.
Node26 build/tests, Rust workspace, Clippy, format, OpenAPI and diff pass.
Workspace Rust: **726 passed, 0 failed, 96 ignored**.
SPS retains17skippedfiles/101skippedtests; ignores do not establish runtime proof.
No new VM/stock-client/full-profile/GUI/publishing execution. [Gates](p06-recovery-application-2026-10-04/gates.json),
[counts](p06-recovery-application-2026-10-04/counts.json), [source pins](p06-recovery-application-2026-10-04/source-pins.json),
[controls](p06-recovery-application-2026-10-04/controls.json) and raw logs preserve the boundary.
User P03 remains unstaged66additions/0deletions, index empty, manifests unchanged,
HEAD8a595ad and no completion commit for incomplete slices5/6.

## Remaining acceptance

RC08d retains full cancellation/authority-loss/commit-ambiguity/resource, offline
and independently enumerated post-backup unknown-node scenarios. Selected local
mapping is not complete recovering-controller orchestration. RC09 still needs
actual signed requests and unprivileged private-broker/verified-HTTPS relay with
replay/expiry/malformed/rotation/transport faults. Provider/roles/session review,
authenticated old-host/server stop and explicit protected activation remain open.

All nine slices remain required: PostgreSQL custom dump/full isolated restore and
pending toolkit review; automatic verified pre-upgrade backup/locked migration/
retention3; both nativeSQLite↔Compose directions with interruption/rollback/status
--nodes; three profiles/remote/twobroker realVM/stock-client parity and inherited
P02.6/P03/P05. GHCR/ARM/Unraid GUI/restic remain separately unaccepted. Full phase
acceptance false; goal active; no receipt status creates admission.
