# P06 database cancellation and uncertain completion — 2026-10-04

QF07-A–D were recorded in both vault plans before further implementation. This
continues slice 6 and retains all nine slices. It adds no dependency, manifest,
lockfile, database schema or package boundary change.

## Behavior and limits

Admitted ordinary Store, owned startup/maintenance and recovery boundaries now
retain a database-work guard until acknowledgement. Cancellation, timeout or a
failed database/authority acknowledgement latches uncertainty before the operation
permit drops. The shared owner fences admission and retains its separate authority
connection even after all local operation counts reach zero. `quiesce` returns an
error while uncertainty remains. A local pool close or independent outcome read
cannot clear it; no reset, retry, activation or unfence method is added. Completed
semantic validation errors still allow ordinary work; healthy completed work can
drain. A known signing-epoch input mismatch is rejected before any database
admission, preserving the existing same-owner binding test without falsely
latching uncertainty. Unbound test-mode and snapshot-only behavior remain as before.

This is conservative local accounting, not proof that a database mutation rolled
back. It can fence after a cancelled read that made no mutation. Uncertainty lasts
for this owner in memory. Process/host/socket loss can still release its authority
transaction; this latch does not become a durable source-stop receipt. External
source-stop/database proof, protected reconciliation and activation remain required
before transfer. A live retained guard prevents the tested reservation; this is
not a claim that a new epoch stays blocked after the process disappears.

The earlier SQLite blocked one-use retrieval consumes its coalesced setup clock
notification before observing the new admission, and still independently proves its
transaction leaves the request submitted. It now also requires uncertainty to
remain after that read; the test administrator cannot reset production ownership.
An intermediate production matrix also exposed a competing guard probe that
could win the maintenance lock before the child. Its replacement observes the
held transaction read-only in the isolated authority database, and retains the
actual loss/cancellation/unchanged-clock checks. This is not evidence of SQLite
statement position.

The recovery rollback/restart fixture now requires uncertainty refusal and
disposes its entire old immutable owner before obtaining a new test holder.
Rollback, durable intent and denied readiness assertions are preserved. This is
fixture administration, not a protected production source-stop/restart procedure.

The production clone fixture now uses a consistent `VACUUM INTO` snapshot before
any issuer starts, instead of assuming a closed pool has already emptied the WAL.
The original cloned-state/two-writer/one-use-restart assertions remain.

Production QF01/QF04/QF05 preserve actual accepted input, five-second stop, TLS/FD
and no-issued-row checks. An interrupted background database boundary can produce
exit one with the exact static local-drain error. Tests now classify only exit
zero or that exact refusal; arbitrary failures remain failures. A refusal is not
successful quiescence or source-stop proof.

## Actual server faults

The wrapper creates separate controller and authority databases/roles. Each test
uses a private controller schema, dummy metadata and a test-only trigger/barrier.
Observers inspect the owned controller database, role and exact observed backend
PID/query/advisory-wait/transaction state. No other sessions or host processes are
faulted. Fault setup is not a production source-stop or activation procedure.

| ID | Actual scenario and outcome |
|---|---|
| QF07-A | Ordinary Store insert blocks inside a trigger; local fencing cancels its caller; server remains in its transaction and later commits one dummy request after barrier release |
| QF07-B | Real `prepare_recovery` transaction blocks at COMMIT in a deferred trigger; caller receives an error, but the server later commits the prepared recovery row |
| QF07-C | Caller aborts an admitted Store task with its insert still blocked; cancellation itself fences the owner and retains uncertainty; the server later commits |
| QF07-D | Completed invalid-input decision leaves the owner active; healthy Store insertion and pool close drain normally, after which the fixture reservation succeeds |

A first fixture attempt failed compilation by reading a private signer field; it
is not behavioral red evidence. An initial outcome read saw zero ordinary rows
immediately after pool close. Adding an exact server-completion observer exposed
one late committed row instead. Both intermediate oracle failures are retained.
The final pre-implementation run fails all three fault assertions because local
quiescence succeeded while PostgreSQL still ran; its healthy case passes.

Every fault releases its owned barrier, waits independently for the exact server
command to stop running and reads its persisted outcome. Neither the task result
nor pool closure supplies that proof. The fixed cases still observe the late
commits; the fix refuses local quiescence and keeps reservation blocked while the
original owner lives. Complete source-stop and durable recovery proof are not
implemented by these tests.

Plaintext consists of dummy strings consumed only by the test process/database.
The real controller retains its existing runtime/encrypted-storage/service/browser
limits. Private fixture URLs are passed in memory, never recorded. No user secret,
key, token, live capability or authority credential enters the evidence.

## Results and controls

The final [regression matrix](p06-database-uncertainty-2026-10-04/verified-regressions-summary.txt)
passes 127 actual cases: production ten per backend, legacy four per backend,
Source 25 per backend, recovery six per backend, startup five, ownership/transport
28 and four server-side QF07 cases. All driver cleanup errors are zero.
[Production SQLite](p06-database-uncertainty-2026-10-04/verified-production_ownership-sqlite.txt)
classifies 3 local drains completed and 0 refused;
[production PostgreSQL](p06-database-uncertainty-2026-10-04/verified-production_ownership-postgres.txt)
classifies 2 completed and 1 refused.
Refusals passed their exact error classification, five-second stop and no-issued-row
assertions; they are not successful quiescence evidence.

[Final behavioral red](p06-database-uncertainty-2026-10-04/final-red.txt) records one
healthy pass and three real quiescence assertion failures before implementation.
The [fixed server cases](p06-database-uncertainty-2026-10-04/verified-store-quiescence.txt)
pass all four, including the stronger server transaction-completion observer.
[Private controls](p06-database-uncertainty-2026-10-04/controls-summary.txt) forget
uncertainty or release the guard while it remains: both fail at real assertions,
with four unchanged runtime source pins and removed temporary trees. Intermediate
compile/oracle/WAL/probe/shutdown-classification failures remain separate logs.

- [Node 26 build](p06-database-uncertainty-2026-10-04/node26-build.txt) and
  [npm tests](p06-database-uncertainty-2026-10-04/node26-test.txt): exit zero;
  SPS retains 80 passes and 101 skips in 17 files.
- [Rust workspace](p06-database-uncertainty-2026-10-04/rust-workspace.txt):
  696 passed, zero failed, 65 ignored across 75 result targets.
- [Clippy](p06-database-uncertainty-2026-10-04/clippy.txt),
  [formatting](p06-database-uncertainty-2026-10-04/format.txt) and
  [OpenAPI](p06-database-uncertainty-2026-10-04/openapi.txt): exit zero.
- [PostgreSQL snapshot regression](p06-database-uncertainty-2026-10-04/postgres-snapshot-summary.txt):
  three integration and one unit pass, zero cleanup errors. Combined focused and
  snapshot coverage is 131 cases; normal workspace passes are counted separately.

Of 65 Rust ignores, ownership/transport 28, production ten, startup five, recovery
six, legacy four, snapshot four and server-side four were executed separately.
Three Quickshell and one optional PostgreSQL outage case remain unexecuted.
Source's 25 normal tests also ran on both adapters. Skips are not working behavior.
[Final catalog](p06-database-uncertainty-2026-10-04/authority-final-cleanup.txt) has
zero generated authority/snapshot databases or roles. [Current source pins](p06-database-uncertainty-2026-10-04/source-pins.json)
cover 61 boundaries; historical records keep their original pins.
[Final QA](p06-database-uncertainty-2026-10-04/final-qa.txt) verifies results, links,
credential markers, hashes, cleanup and both vault checkpoints. The user P03 file
remains 66 additions/zero deletions, unstaged and untouched; index empty; no commit.


## Remaining work

QF08 authenticated old-host stop/disable/reboot and durable database/source-stop
proof remain open, as does worst-case synchronous/blocking crypto shutdown.
Protected restore/unfence/activation, complete broker/current-key/challenge/history
coverage, provider cleanup and offline quarantine remain required. PostgreSQL
custom-dump/full isolated restore retains its separate
[toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md).
Packaged migration/startup sequencing, verified locked upgrades/retention, both
native↔Compose directions and the real three-profile/browser/stock-client parity
matrix remain mandatory. No new VM, browser, packaged artifact or profile transfer
run occurs here. P06 and slices 5/6 remain unaccepted; no slice commit.
