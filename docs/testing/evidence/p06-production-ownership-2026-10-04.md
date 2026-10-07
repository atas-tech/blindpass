# P06 mandatory production ownership — 2026-10-04

PW01–PW06 were recorded before implementation in the
[product plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md).
This is a source candidate within slice 6. All nine slices remain required;
P06 and the deployment profiles remain unaccepted. No dependency, manifest,
lockfile, package boundary or schema change accompanies this work.

## Implemented behavior and custody

Production `check-config`, `serve`, `migrate` and `reconcile-clock` require the
protected `BLINDPASS_AUTHORITY_URL_FILE`, explicit tenant and owner IDs and actual
issuer key. Inline authority URLs, partial settings, unsafe files, invalid IDs
and unrecognized PostgreSQL URL options refuse without echoing credentials.
Configuration parsing for offline backup/key operations is distinct from admission
to production issuance; supplied authority settings are still validated.

Production `serve` claims the exact separate PostgreSQL record before any local
clock write. The local tenant, issuer key ID, epoch and current schema must match.
The immutable bound Store reaches HTTP, clock/retention tasks, the local admin
socket and signing clones. Fenced/recovering owners serve diagnostics without
startup clock mutation or ordinary admission. The public unowned production
router refuses ordinary requests and readiness without touching the clock.
Health remains available. Active revisions remain one-use: losing a process or
copying its state does not permit another process to reclaim that revision.

Production maintenance requires a live externally fenced holder and operation
permit. Fresh initialization requires epoch one and a pristine schema, preserves
the explicit tenant and refuses existing user objects, damaged state and older
versions. Current-schema maintenance is a guarded validation/no-op. Older upgrades
refuse until the verified automatic pre-upgrade backup and locked migration gates
exist. Clock reconciliation checks exact current metadata and refuses active,
recovering or persisted recovery state; it cannot clear a recovery intent or
activate state. Authority loss cancels a waiting local future.

Offline SQLite archive capture now opens a private snapshot-only Store without
clock updates, authority connection or an ownership claim. Its immutable snapshot
mode refuses ordinary Store work and signing even after adding a signer. Backup
verification still needs only the archive and recovery key. The authenticated
bundle retains exactly the database and three existing controller key members;
external authority credentials and its protected database remain outside
controller backups. The archive retains local tenant/epoch lineage, which cannot
reset the external high-watermark.

Authority URLs and master keys are consumed by configuration, SQLx and the
controller process for their existing lifetimes. They are not logged or archived;
no allocator, library-copy or OS memory erasure guarantee is added. Archive
plaintext lives in the existing protected staging/verification work area for
that operation and is removed by the existing cleanup paths. Tests use private
dummy credentials and key files, and keep bearer/bootstrap tokens in test memory
and private IPC. The controller accepts encrypted Source payloads, not their
browser-equivalent fixture plaintext.

## Actual entrypoint scenarios

| Scenario | Executed coverage |
|---|---|
| PW01 | Missing authority refuses four production commands before database/admin socket creation; inline, partial, unsafe file, invalid URI options/tenant/owner refuse without echo |
| PW02 | Real production process, complete quiescent fixture copy and second process exclusion; original remains healthy; SIGKILL then same-revision restart refuses; explicit fixture-admin revision advance permits a new process; owned production test-seed route stays absent |
| PW03 | Real agent mint/request and local admin bootstrap token precede independent external fencing; readiness and ordinary HTTP/UI/node routes refuse within five seconds, health remains available; valid agent bearer and admin bootstrap cannot create/consume additional state |
| PW04 | Fenced/recovering real processes expose diagnostics without clock mutation; changed local epoch, schema or tenant refuses before listeners/admin state |
| PW05 | Protected fresh initialization preserves selected identity; fenced clock repair succeeds, active repair/migrate refuse without clock changes; older schema refuses; authority loss cancels repair waiting on an owned database lock; nonpristine table/view schemas refuse |
| PW06 | Public unowned production builder refuses readiness and ordinary routes without clock changes; snapshot-only Store refuses time/mutation/signing; actual offline archive capture preserves the clock, makes no authority connection, excludes its credential and verifies exactly four members |

PW02 copies a closed SQLite database with no live WAL, or copies all tables from
a quiescent initialized PostgreSQL fixture into a separate schema. These are
complete initial fixture copies on one host, not the pending PostgreSQL custom-dump
restore tool, host-identity proof or protected recovery activation. PW05's PostgreSQL
lock observer watches the actual `SELECT ... FOR UPDATE`; SQLite observes holder
exclusion while its write lock is held. Neither establishes rollback of an
ambiguous commit or whole HTTP/body quiescence. Explicit fixture-admin record
changes isolate ownership behavior and are not a production activation runbook.

Original S01–S05 startup scenarios now run real production commands with genuine
separate authority fixtures. Fresh migration uses a fenced record; subsequent
starts explicitly advance active revisions in fixture administration. Missing,
empty, unsupported and damaged state still refuses, and identity/epoch survive
restart. These five are SQLite-controller cases with PostgreSQL authority;
PW's seven cases run on each controller backend.

The shared router, admin-session, proxy, enrollment and optional-outage component
fixtures now explicitly use isolated test mode. RBAC, CSRF, replay, expiry and
proxy assertions are preserved. The unowned shell test asserts fencing; PW02
retains the absent test-seed-route assertion on an owned production process.
Component test mode does not establish production entrypoint acceptance. Older
negative CLI fixtures without authority stop at configuration admission; the
actual S/PW cases provide the current local-state refusal evidence.

## Red tests, corrections and negative controls

The first sandboxed configuration run failed on denied local listener access,
not implementation assertions. Its host rerun failed at two real missing/invalid
configuration assertions. The first five process cases failed on duplicate
ownership admission, absent fencing, nonactive clock mutation, altered identity
admission and replacement of the selected fresh tenant. The public builder red
returned readiness 200 instead of 503. The offline backup red changed the clock.
Nonpristine initialization reds admitted a SQLite name matched incorrectly by
LIKE's underscore wildcard and a PostgreSQL view omitted by a table-only count.
Each feature assertion preceded its fix.

Retained intermediate failures distinguish a mistaken snapshot test method name
(compile error), the wrong PostgreSQL lock observer (fixture failure), and S04's
old exact readiness expectation (missing the new authority check) from feature
failures. The first two workspace attempts exposed unowned admin-session/shared
router fixtures; those were made explicitly isolated while production tests
remain actual subprocess cases. The strengthened process test initially used the wrong agent API-key header
and stopped at minting (401 instead of 200), before any fencing assertion. That
fixture was corrected to the existing x-agent-api-key contract. The complete
normal Rust gate preceded that ignored-case-only correction; the final backend
matrix executes the corrected case and Clippy/formatting run again afterward.
Private negative
controls and all final results are recorded below.

Three private source controls failed at actual assertions: disabling required
production authority admitted `check-config`; restoring the unowned startup Store
changed a nonactive controller clock; bypassing fenced maintenance and its guarded
clock repair admitted repair under an active record. Each exited 101. The
[control summary](p06-production-ownership-2026-10-04/controls-summary.txt) records
unchanged production hashes and removal of private trees. Four protected source
pins match the current candidate. No production source was modified for controls.

The final post-control [integration matrix](p06-production-ownership-2026-10-04/verified-regressions-summary.txt)
passed 114 actual cases: seven PW cases on each backend, five original startup
cases on SQLite, four legacy cases on each backend, 25 Source cases on each
backend, six recovery cases on each backend and 25 ownership cases. Each driver
summary records exit 0 and zero owned cleanup errors. Four additional current
[PostgreSQL snapshot cases](p06-production-ownership-2026-10-04/postgres-snapshot-summary.txt)
passed (three integration and one unit); their separate controller role/database
were removed. The final [catalog check](p06-production-ownership-2026-10-04/authority-final-cleanup.txt)
reports zero generated authority/snapshot databases and roles.

- [Node26 build](p06-production-ownership-2026-10-04/node26-build.txt) and
  [npm tests](p06-production-ownership-2026-10-04/node26-test.txt): exit 0;
  SPS reports 80 passes and 101 skips in 17 files. Skips are not execution evidence.
- [Rust workspace](p06-production-ownership-2026-10-04/rust-workspace.txt):
  693 passes, zero failures, 55 ignores across 74 result targets.
  The three normal PW configuration/router cases, snapshot-only unit case and
  strengthened offline archive CLI case passed. Existing generation-one crypto
  golden vectors and authenticated schema16 archive compatibility passed.
- [Clippy](p06-production-ownership-2026-10-04/clippy.txt),
  [formatting](p06-production-ownership-2026-10-04/format.txt) and
  [OpenAPI](p06-production-ownership-2026-10-04/openapi.txt): exit 0.

Of the 55 ordinary Rust ignores, 25 ownership, six recovery, four legacy,
seven production, five startup and four PostgreSQL snapshot cases were executed
separately. Three Quickshell and one optional PostgreSQL outage case remain
unexecuted in this checkpoint. Source's 25 cases are normal tests repeated on
both databases. All gates use the existing reviewed dependency stack; Rust runs
locked/offline. Local listeners/PostgreSQL/Docker fixture administration ran
outside restricted execution. The sandbox listener failure is retained separately.

[Source pins](p06-production-ownership-2026-10-04/source-pins.json) cover 52
current runtime/config/Store/crypto, fixtures/driver, authority DDL and contract
boundaries. Historical records keep their original source pins. [Final QA](p06-production-ownership-2026-10-04/final-qa.txt)
checks results, relative links, credential markers, pins, cleanup and both vault
checkpoints. The unrelated user P03 evidence remains 66 additions/0 deletions,
unstaged and untouched. The index is empty and no slice 5/6 commit was made.

## Remaining phase gates

The native service/container automatic `migrate`-then-`serve` sequence is not yet
integrated with fenced maintenance and one-use active ownership. This candidate
must not be attributed to an accepted current packaged startup profile. Earlier
published native/OCI artifacts remain schema16 and do not contain these changes.

Complete server/body quiescence and ambiguous server-side transaction rollback,
previous-source stop proof, protected restore/activation/unfence, complete
broker challenges/current keys/report coverage, legacy/pruned-history mapping,
provider cleanup, offline quarantine and persistent-authority review remain open.
PostgreSQL custom-dump/full isolated restore retains its separate
[toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md).
Locked verified upgrades with retained backups, both native↔Compose transfer
directions, current artifact rebuilds and all three profiles' real broker,
stock-client and browser parity remain required. Node24, real systemd/VM/broker/
browser tests, separate cloned hosts and native/OCI restore were not run here.
The full goal remains active; no slice 5/6 commit or acceptance is claimed.
