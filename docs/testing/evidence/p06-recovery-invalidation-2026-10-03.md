# P06 durable recovery intent and atomic invalidation — 2026-10-03

This record covers a local schema 17 recovery candidate. It does not accept P06,
a deployment profile, restore activation or source ownership transfer. The
[product](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
recorded RI01–RI06 before implementation. All nine slices remain required. No
new dependency, manifest, lockfile or package boundary changed; the external
PostgreSQL authority uses the previously approved SQLx stack.

## Implemented behavior

A live bound `recovering` holder commits a durable prepared intent before bulk
invalidation. Schema17 adds the intent and quarantined node, operation and
persistent-authority review tables on both stores. The shared local latch gates
ordinary Store work and signing immediately; opening a persisted intent restores
that latch. Both HTTP builders return fixed 503/no-store responses for ordinary
API, UI and fallback paths. Only exact `/healthz` and `/readyz` remain diagnostic;
readiness reports `recovery_required`. No method clears the fence or activates a
recovery generation.

A separate atomic transaction removes restored requests, exchanges, approvals,
enrollments, sessions, challenges, inbox documents, idempotency responses and
Source links/offers. It preserves consumed grants, revokes other grants and
retains all grant tombstones to the safe-integer maximum while quarantined. All
ten operation states become uncertain; prior status/result/completion metadata
is retained in the recovery queue. Agents and workloads are revoked with one
version increment; operators are disabled while retaining their roles. Nodes,
policies, source bindings and staged node rotations are recorded for review.
Ciphertext receipt digests and policy documents remain forensic metadata.

The transaction advances only to the exact protected reservation, requiring it
to exceed both local state and prior recorded recovery generations. Matching
replay returns the committed summary without further mutation. Errors fence the
holder; there is no hidden retry. A failed bulk transaction preserves the
separately committed prepared intent. A 30-second recovery-future bound and live
ownership checks do not prove rollback of arbitrary ambiguous server-side work.

SQLite authenticated schema 16 backups remain verifiable inputs for explicit
protected forward migration. Verification checks the complete archive without
upgrading or activating the source. New capture uses schema 17; PostgreSQL
custom-dump/full isolated restore remains unfinished.

Authority credentials exist only in private SQLx/process memory and remain
outside controller backups. Tests generate private dummy keys/credentials.
Recovery metadata uses existing database storage and is retained indefinitely
while fenced; old operation result JSON remains in that same storage. No new
secret plaintext consumer or memory/media erasure guarantee is added. Deleting
transient payload rows does not erase database/WAL/storage remnants.

## Actual scenarios

| Scenario | Observed behavior |
|---|---|
| RI01 | Exact external epoch 10 replaces snapshot 1; all transient authority is removed atomically; ten grants are tombstoned, ten operations uncertain, one node quarantined and nine persistent reviews recorded; replay leaves versions 2 and no duplicate queues |
| RI02 | Owned mid-grant trigger abort rolls back payload deletion, queues, versions and epoch; durable prepared intent survives original-builder restart; explicit current reacquisition and retry succeeds once |
| RI03 | Reopened prepared intent refuses 88 requests (eight methods × eleven API/UI/fallback/diagnostic-lookalike paths), including old admin cookies; exact health succeeds and readiness reports recovery required |
| RI04 | Invalid identifiers, missing binding, live fenced/active holders, independent external fencing and targets not above local epoch refuse without transient deletion or recovery mutation; PostgreSQL controller-only credential cannot SELECT/DML/call authority functions |
| RI05 | Missing current recovery table and future schema refuse without repair through both open paths and recovery; the normal test verifies an actual complete authenticated schema 16 archive while its source remains schema 16 |
| RI06 | Independent authority fencing cancels a pending recovery future and preserves prepared intent, epoch 1 and original rows after pool drainage. PostgreSQL cancellation is observed while the owned grant-row UPDATE waits on a lock; SQLite uses an owned write lock without claiming exact statement position |

These fixtures seed controller metadata and dummy ciphertext; they are not actual
signed grant admission, broker recovery reports, provider cleanup or native/OCI
restore rehearsals. RI02 covers explicit retry after reacquisition. RI06 covers
selected cancellation, not a successful ambiguous-COMMIT/network-loss recovery.

The final [SQLite run](p06-recovery-invalidation-2026-10-03/sqlite-current.txt)
passed six cases in 9.33 seconds; the [PostgreSQL run](p06-recovery-invalidation-2026-10-03/postgres-current.txt)
passed six in 18.99 seconds. Both driver summaries report exit 0 and zero owned
cleanup errors. The [existing ownership suite](p06-recovery-invalidation-2026-10-03/authority-current.txt)
passed all 25 cases in 23.23 seconds under schema 17, including its real CORS
preflight and 144-request coverage. These are separate from RI03's 88 requests.

The [compile-first log](p06-recovery-invalidation-2026-10-03/first-red.txt)
failed before the new API existed and also contained incorrect fixture names;
it is not runtime failure proof. Initial SQLite runs failed on missing fixture
approval reason and node-challenge protocol fields. The first PostgreSQL run
passed five and failed RI05 because its fixture decoded an INT4 schema column
as i64; casting it to BIGINT corrected the test. The first Clippy run reported
two test-style findings, corrected before the final gates. Earlier logs remain
alongside the final runs.

Two private source controls produced actual assertion failures. Splitting the
invalidation transaction after transient deletion made
[RI02 fail](p06-recovery-invalidation-2026-10-03/partial-commit-control-red.txt)
with zero original requests where one must survive rollback. Removing only the
local HTTP gate made [RI03 fail](p06-recovery-invalidation-2026-10-03/http-bypass-control-red.txt)
at GET /api/v3/admin/session: 401 instead of 503. A first control checker incorrectly
expected capabilities: 200; the corrected final checker uses the observed admin
route assertion. [Final control cleanup](p06-recovery-invalidation-2026-10-03/controls-final-summary.txt)
confirms both exit 101, production source hashes unchanged and temporary trees
removed. These controls altered only private copies, not production expectations.

## Workspace gates and provenance

- [Node 26.10.0 build](p06-recovery-invalidation-2026-10-03/node26-build.txt): exit 0.
- [First Node tests](p06-recovery-invalidation-2026-10-03/node26-test-first.txt): exit 1,
  including ten existing MCP test-file failures and a native Node assertion in
  InternalCallbackScope::Close. No systemd core was available even in the host
  check. Cause is unconfirmed; no source or dependency was changed for it.
  The [same gate outside restricted execution](p06-recovery-invalidation-2026-10-03/node26-test-final.txt)
  passed, exit 0. SPS still reports 80 passes and 101 skips in 17 files; skips are
  not execution evidence.
- [Full Rust workspace](p06-recovery-invalidation-2026-10-03/rust-workspace.txt):
  exit 0, 690 passes,zero failures, 39 ignores across 72 result targets, including
  the complete authenticated schema 16 compatibility test.
- [Clippy](p06-recovery-invalidation-2026-10-03/clippy-final.txt): workspace/all
  targets, locked/offline, warnings denied, exit 0. [Formatting](p06-recovery-invalidation-2026-10-03/format.txt)
  and [OpenAPI contract](p06-recovery-invalidation-2026-10-03/openapi.txt):exit 0.
  Capabilities and both generated TypeScript clients now report schema 17. The
  prior provisioning migration test uses current SCHEMA_VERSION and a future
  marker of current+1, retaining its additive-migration and refusal assertions.
- The [three PostgreSQL snapshot cases](p06-recovery-invalidation-2026-10-03/pgs-integration.txt)
  and [read-only/schema unit case](p06-recovery-invalidation-2026-10-03/pgs-unit.txt)
  all passed under schema 17. [Cleanup](p06-recovery-invalidation-2026-10-03/pgs-summary.txt)
  reports zero errors. They use existing SQLx and the existing fixture, without
  installing or invoking the proposed custom-dump/isolated-restore toolkit.

Of the 39 ordinary Rust ignores, 25 authority cases, 6 recovery cases (on both
backends) and 4 exported-snapshot cases were actually executed above. Three
Quickshell cases and one optional PostgreSQL outage case were not run. Node 24,
actual native/systemd or OCI/profile restore, packaged image/archive rebuilding,
separate cloned hosts, full stock-client/browser parity and successful ambiguous
COMMIT fault tests were not run here. Historical artifacts remain schema 16 and
retain their own pins; no behavior is attributed to them from these source tests.

[Current source pins](p06-recovery-invalidation-2026-10-03/source-pins.json)
cover 29 files, including store/authority boundaries, both migrations, backup
compatibility, HTTP, tests/driver, OpenAPI and generated clients. The final
[catalog check](p06-recovery-invalidation-2026-10-03/authority-final-cleanup.txt)
found zero generated authority/snapshot databases and roles. The final QA also
checks links, pin matches, credential markers, vault checkpoints and clean diff
formatting. The unrelated user P03 evidence edit remains 66 additions/0 deletions,
unstaged; no dependency manifests changed and no commit was made.

## Still required for full P06

Mandatory external production serve/configuration/maintenance/local-admin wiring,
previous-source stop proof, complete server/body quiescence, authenticated complete
broker challenges/current keys/coverage, legacy or pruned history mapping,
provider cleanup, offline quarantine and legacy JWT/HMAC authority versioning
must precede unfence. No current API activates or clears this candidate. Slice 5
PostgreSQL custom-dump/full isolated restore and artifact faults await the
separate [toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md).
The authority choice does not approve that dependency change. Verified locked
upgrades, bidirectional native↔Compose transfer and all nine slices' full
three-profile parity gates remain required. The goal stays active; slices 5/6
are not accepted or committed.
