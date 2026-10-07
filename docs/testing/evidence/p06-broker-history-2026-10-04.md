# P06 broker consumption history — 2026-10-04

**Status:** Durable broker history foundation implemented and host-tested. Full
nine-slice P06 remains active and unaccepted; slices5/6 are incomplete and no
commit is made. The [product plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
retain BR01–BR10, paginated reports and the complete protected activation workflow.

Fresh node identity creation in an empty private directory fsyncs an exclusive
0600 consumption-history genesis after canonical key publication. Failure or
interruption never authorizes recreating genesis for an existing identity. Imports,
existing/missing journals and legacy two/four-field rows retain unknown provenance.
The first issuer pin binds known empty history to its tenant, node and issuer key.
Wrong scope refuses without changing the pin or journal; current node key rotation
preserves history identity and scope. A higher trusted epoch is retained durably.

Authenticated-time pruning preserves a monotonic maximum removed expiry and the
maximum trusted/recorded epoch, including when all rows disappear. The coverage
boundary is conservative: effects may precede expiry. It does not attest to effect
completion, provider cleanup or protection from restoring an old broker backup.
Bound consume records retain original operation/epoch correlation. Torn known
provenance, malformed or duplicate headers, unsafe ownership/mode/link state and
unbound history containing consumes fail closed. Legacy torn-tail repair remains
compatible without assigning invented provenance.

A private single-link 0600 lock inode with nonblocking flock serializes read/repair,
append, pin binding and compaction. Contention denies the request without waiting.
Changed inode/length/mtime/ctime refreshes the bounded durable replay map under that
lock before mutation; this prevents a stale compactor dropping another writer's
intent and prevents a stale writer consuming the same grant again. Compaction
retains existing size/record limits and private fsync/rename publication. Hostile
Root mutation and broader power-loss/profile behavior are outside these checks.

Plaintext is grant/operation/expiry/epoch/history-scope metadata in broker runtime
maps and private persistent journals; no credential or session payload is added.
The current consumed intent remains an uncertain effect boundary. Earlier brokers
cannot read a new genesis header; rollback needs matching pre-upgrade state and
recovery review, as described in [the deployment guide](../../deploy/recovery-stage.md).

## Test-first and regressions

[Initial red](p06-broker-history-2026-10-04/test-first.log) executes two new tests
and fails because fresh identity history is absent. [Initial green](p06-broker-history-2026-10-04/genesis-pass.log)
confirms durable genesis/reopen and no reconstruction after deletion.
[Concurrency red](p06-broker-history-2026-10-04/concurrency-test-first.log) reproduces
lost durable intent on stale compaction and double consumption by a stale writer.
[Concurrency green](p06-broker-history-2026-10-04/concurrency-pass.log) passes both
with the synchronization/locking changes.

Eleven new BR01–BR04 cases cover stable private genesis, missing history, imported
legacy seeds/rows, actual GrantVerifier consume after first-pin binding, original
correlation/replay denial, prune-all coverage/epoch retention, wrong tenant/node/
issuer, torn/duplicate/unbound headers and unsafe/busy locks, and both stale-writer
regressions. The existing actual node rotation test now asserts unchanged history
through key replacement and restart. The [final broker reset](p06-broker-history-2026-10-04/broker-normal-reset.log)
passes 316 library tests plus broker binary/probe/doc tests under normal production
sources. Counts overlap the workspace run; they are not additional distinct passes.

The first [sandbox suite](p06-broker-history-2026-10-04/broker-suite.log) contains
socket failures/stalls and was interrupted through its live tool session (exit130).
It is incomplete evidence. A scoped host process lookup found no matching process
and killed none; the session interrupt ended that exact sandbox run. The subsequent
[host suite](p06-broker-history-2026-10-04/broker-host-suite.log) passes all 315 tests
present at that point, with real socket/subprocess access. The later legacy-import
case and strict history checks are included in the final 316-test run.

The initial private copy [did not compile](p06-broker-history-2026-10-04/incomplete-lost-intent-control.log)
because two included public service templates were absent. A [second setup attempt](p06-broker-history-2026-10-04/incomplete2-controls-summary.log)
used the wrong helper template name. Both incomplete attempts removed their
private trees; neither is a behavioral control. Correcting the copy to include
the actual helper/browser service templates enables the following controls.

Two private-copy controls produce real assertion failures: [retain a stale map](p06-broker-history-2026-10-04/lost-intent-control.log)
loses a durable consume and exits101; [erase coverage](p06-broker-history-2026-10-04/coverage-control.log)
reports zero instead of the retained boundary and exits101. [Control results](p06-broker-history-2026-10-04/controls.json)
verify unchanged production sources and removal of the private copied tree.
[Control source pins](p06-broker-history-2026-10-04/controls-source-pins.json) match
the final source pins. After controls, the normal broker suite and
[production binary build](p06-broker-history-2026-10-04/broker-normal-build.log) pass.

## Required gates and current limits

[Gate results](p06-broker-history-2026-10-04/gates.json) record sequential execution
with Node26.10.0 and Cargo jobs2, locked/offline Rust resolution:

- [npm run build](p06-broker-history-2026-10-04/node-build.log) and [npm test](p06-broker-history-2026-10-04/node-test.log): exit0. Default SPS runs 80 cases and skips 101 across17 files; skipped service/profile checks are not new runtime proof.
- [Rust workspace](p06-broker-history-2026-10-04/rust-workspace.log): 709 passed, 0 failed, 72 ignored across 77 result targets. Ignored controller authority/backend/restore/snapshot/profile cases remain separate; earlier records describe their executed scope. Three Quickshell GUI cases and optional PostgreSQL outage remain unexecuted.
- [Workspace Clippy](p06-broker-history-2026-10-04/clippy-workspace.log), [final Clippy after controls](p06-broker-history-2026-10-04/clippy-final.log), [format](p06-broker-history-2026-10-04/format.log), [OpenAPI](p06-broker-history-2026-10-04/openapi.log) and [diff check](p06-broker-history-2026-10-04/diff-check.log): exit0.

[Current source pins](p06-broker-history-2026-10-04/source-pins.json) cover 69
selected runtime/test/schema/deployment sources. Historical records retain their
original hashes. No manifest or lockfile changes; protected user P03 evidence
remains unstaged at66 additions/0 deletions; index empty, no commit.

This turn does not execute a new VM, broker/client/profile recovery transfer,
power-loss or full-filesystem history fault. Earlier CJ06 VM evidence stays
historical and does not establish this new header/lock behavior. BR01–BR04 have
selected component evidence; complete BR01–BR10 and all nine slices remain required.
Next work is strict immutable paginated export from the real journal, signed
controller challenges, actual node relay and independently current-key-trusted
controller receipt/nonce consumption on both backends. Generic consumed_report
admission remains closed. No broker report, quarantine release, provider cleanup,
authenticated old-host stop or protected activation is claimed.

PostgreSQL custom dump/full isolated restore still requires the separate pinned
[toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md).
Locked automatic-backup upgrades/retention, both migration directions, all three
supported profile/stock-client/VM parity and inherited phase gates remain required.

[Final QA](p06-broker-history-2026-10-04/final-qa.log) also verifies both authoritative vault checkpoint hashes and preserves the full nine-slice scope.
