# P06 authenticated local recovery snapshot binding — 2026-10-04

**Partial implementation; all nine slices remain active and unaccepted.**
Local controller schema18 now records authenticated snapshot metadata before
invalidation and destination publication. This is distinct from the external
schema4 protected [receipt collector](p06-durable-receipts-2026-10-04.md).
Actual recovering report application, node HTTPS relay, source-stop proof,
provider/role/session review and protected activation remain open.

Only the private authenticated verified archive stage can bind a snapshot.
Its epoch/time and SHA256 digest of the format's deterministic serialized manifest
are stored with the prepared recovery. A domain-separated Ed25519 signature binds
version, tenant, issuer, owner, recovery ID, protected target epoch/revision and
snapshot epoch/time/digest. The existing issuer signer creates it under the actual
recovering holder; it cannot act as a generic ordinary document signature.
Historical recoveries receive no guessed archive context in the 17→18 migration.

The local reader requires the exact bound live recovering holder, current schema,
invalidated local generation, matching parent/snapshot epoch, safe canonical
metadata and the issuer signature. Unbound/foreign holders refuse before reading
or disturbing the legitimate holder. Failed authenticated reads fence; they count
for guard lifetime but do not invent uncertain database mutation for cancelled
SELECT work. Scope rows/signatures are metadata, not coverage receipts or admission
capabilities. Ordinary routes remain fenced. The external collector still verifies
independently current broker keys and immutable pages; this local metadata alone
cannot acknowledge rotation, revive nodes, complete providers or activate issuance.

No new dependency or secret delivery is introduced. Digests/signatures are public
reconciliation metadata; archive members remain in the existing private verified
stage, and signing uses the existing protected runtime issuer key and documented
memory/library/OS lifetimes. There is no new erasure guarantee or source-stop proof.

## Test-first and actual execution

RC08a first failed at the exact real encrypted-restore assertion: no durable
`controller_recovery_snapshots` table existed before publication. This was an
actual behavioral failure (exit101), not missing-API compilation. The implemented
case passes on actual encrypted schema16 and schema17 archives, checks epoch/time/
manifest digest, retains the source bytes, starts/stops the fenced production
controller and verifies unchanged metadata after restart.

RC08b passes eight actual cases: missing row, altered snapshot epoch, altered valid
timestamp, replaced digest, replaced signature, altered owner context, unbound
Store and a real other-tenant holder. Legitimate holder metadata survives the
unbound/wrong-holder probes; no case clears quarantine or admits ordinary work.
A private-copy control removes signature verification and actually fails at
`tampered time supplied authenticated collection scope` (exit101). Production
hashes match, the private tree is removed and ordinary-source gates run afterward.
The initial unsealed RC08a log is retained as a narrower intermediate result;
expanded signed-context and current regression logs are the current proof.

| Current selected integration run | Passed |
|---|---:|
| [rc08ab-first](p06-authenticated-recovery-snapshot-2026-10-04/rc08ab-first.log) | 2 |
| [authority-full-sqlite](p06-authenticated-recovery-snapshot-2026-10-04/authority-full-sqlite.log) | 33 |
| [authority-full-postgres](p06-authenticated-recovery-snapshot-2026-10-04/authority-full-postgres.log) | 33 |
| [invalidation-sqlite](p06-authenticated-recovery-snapshot-2026-10-04/invalidation-sqlite.log) | 6 |
| [invalidation-postgres](p06-authenticated-recovery-snapshot-2026-10-04/invalidation-postgres.log) | 6 |
| [legacy-sqlite](p06-authenticated-recovery-snapshot-2026-10-04/legacy-sqlite.log) | 4 |
| [legacy-postgres](p06-authenticated-recovery-snapshot-2026-10-04/legacy-postgres.log) | 4 |
| [production-sqlite](p06-authenticated-recovery-snapshot-2026-10-04/production-sqlite.log) | 10 |
| [production-postgres](p06-authenticated-recovery-snapshot-2026-10-04/production-postgres.log) | 10 |
| [startup-sqlite](p06-authenticated-recovery-snapshot-2026-10-04/startup-sqlite.log) | 5 |
| [quiescence-postgres](p06-authenticated-recovery-snapshot-2026-10-04/quiescence-postgres.log) | 4 |
| [restore-sqlite](p06-authenticated-recovery-snapshot-2026-10-04/restore-sqlite.log) | 9 |
| [migration-regression](p06-authenticated-recovery-snapshot-2026-10-04/migration-regression.log) | 1 |
| [restore-failpoints](p06-authenticated-recovery-snapshot-2026-10-04/restore-failpoints.log) | 11 |
| [receipts-regression](p06-authenticated-recovery-snapshot-2026-10-04/receipts-regression.log) | 6 |

**144 overlapping case executions across 15 runs**,
zero selected failures/ignores and zero owned fixture cleanup errors. Both-store
schema18 ownership/invalidation/legacy/production suites, startup, PostgreSQL
quiescence, ordinary/failpoint restore, external migration and all six protected
receipt cases pass. PostgreSQL receives the new local table and state validation,
but the private archive binder and signed-scope lookup execute here on SQLite.
The PostgreSQL binding/read branches have compilation and surrounding-store
regressions, not full PostgreSQL archive-restore acceptance.

The first OpenAPI gate caught the stale readiness schema constant (17 vs 18).
The contract and generated declarations were updated; affected Node build/tests,
OpenAPI and diff checks then reran. Rust sources were unchanged after their
passing workspace/Clippy/format checks. The failed log remains separate.
A subsequent sandboxed Node rerun hit a native InternalCallbackScope assertion
and MCP child-process failures. No matching core or recent kernel OOM message
was available; no core was extracted or system setting changed. The same Node26
and sources passed the normal approved host rerun. Root cause is unconfirmed;
the failed sandbox log and limited diagnostics are retained separately.

Node26 build/tests, Rust workspace, Clippy, format, OpenAPI and diff pass.
Workspace Rust: **726 passed, 0 failed, 86 ignored**.
Default SPS:17 skipped files/101 skipped tests. Other ignored cases are not new
runtime proof. No new real VM, stock-client, full-profile parity, Unraid GUI or
GHCR/ARM execution occurred. [Gates](p06-authenticated-recovery-snapshot-2026-10-04/gates.json),
[counts](p06-authenticated-recovery-snapshot-2026-10-04/counts.json), [source pins](p06-authenticated-recovery-snapshot-2026-10-04/source-pins.json),
[control results](p06-authenticated-recovery-snapshot-2026-10-04/controls.json) and raw logs retain scope.
The protected user P03 file remains unstaged66 additions/0 deletions; index empty,
no manifest changes and no new completion commit for slices5/6.

## Remaining work

RC08c/d need actual local collection and protected-page re-verification/application
with exact grant/operation/node/epoch mapping, uncertain provider state and offline/
post-backup unknown node quarantine. RC09 requires the actual unprivileged relay,
controller-signed requests, private broker peer checks and verified HTTPS with
transport/malformed/replay/expiry faults. Complete crash/final-commit/resource
coverage, persistent role/session/provider review, authenticated previous-host/
server stop and explicit protected activation remain mandatory.

All nine slices remain required: PostgreSQL custom dump/full isolated restore and
pending toolkit review; verified automatic pre-upgrade backups/locked migrations/
retention3; both native SQLite↔Compose migrations, interrupted rollback/status
--nodes; all three profiles/remote controller/two-broker real VM/stock-client fault
parity and inherited P02.6/P03/P05. Restic, broader publishing and GUI acceptance
remain separate. No SourceStopProof or unfence exists; full phase acceptance false.
