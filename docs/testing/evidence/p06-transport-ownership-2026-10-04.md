# P06 transport ownership and shutdown — 2026-10-04

QF01–QF08 were recorded before implementation in the
[product plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired testing plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md).
This is additional source/process evidence within slice 6. All nine slices remain
required; P06 and the current deployment profiles remain unaccepted. There is no
schema, dependency, manifest, lockfile or package-boundary change.

## Behavior and limits

Active accepted HTTP/TLS/admin transports now retain an ownership operation until
local IO closes. The wrapper closes IO before dropping its permit, including when
the handler has returned but the response is blocked by its reader. Fencing wakes
pending reads/writes and closes those transports. New nonactive connections reach
the existing diagnostic/ordinary admission gates: health 200, readiness 503 and
ordinary 503. A connection accepted before the latch can instead close during the
transition; it cannot deliver a newly permitted response. Original SocketAddr
information reaches handlers through Axum's maintained listener adapter.

HTTP/TLS connections have an absolute 60-second accepted lifetime and reconnect;
the existing ordinary 10-second and node 35-second handler bounds remain. Local
admin connections last at most 10 seconds; the listener tracks at most 64 children
and queues further acceptance. Dropping the admin parent stops/cancels its children.
The immutable Store binding supplies its owner; no alternative owner can be
selected by the admin handler. Snapshot-only stores cannot supply an issuing
administrative binding.

SIGTERM/Ctrl-C fences before graceful waiting and stops all transports, including
diagnostic connections accepted after an earlier ownership latch. Main drops the
listener/server future, aborts and awaits known clock/sweep/admin/monitor tasks,
closes pools and waits for counted local operations. A four-second cleanup timeout
returns an error rather than a complete-quiescence claim. The new constructor
also arms fence notification when admission wins immediately before fencing;
it cannot leave that admitted socket waiting only for its lifetime timer.

This accounts for local IO and selected known asynchronous work. It does not
prove ambiguous PostgreSQL COMMIT rollback, complete server transaction absence,
authenticated old-host stop/disable/reboot, worst-case synchronous/blocking crypto
shutdown, broker coverage, protected restore/unfence or deployed profile transfer.
No complete-quiescence, activation or old-source-stop API/claim is added. Bytes
already written to a socket/kernel or received remotely cannot be recalled.
Delivered authority retains its existing independent expiry/revocation contract.

Master keys, TLS configuration and SQLx credentials retain their existing process/
connection lifetimes. This adds no allocator/library/OS erasure guarantee. Local
admin plaintext replies are consumed by their private client during the bounded
connection; hashes remain in the database. The large response is dummy test
plaintext consumed only by the test process in memory, not user secret delivery.
Test private keys/URLs remain temporary 600 files in 700 directories; tokens and
capabilities are not recorded. Controller Source traffic remains ciphertext.

## Executed scenarios

| ID | Actual scope |
|---|---|
| QF01 | Real production process per controller backend; 100 Continue proves admitted incomplete JSON input; SIGTERM exits within five seconds and no request row appears |
| QF02 | Actual 8MiB response with unread tail and real restricted authority; exact accepted socket FD closes before local quiescence returns; tail absent, previously written bytes accounted separately; original peer address retained |
| QF03 | Actual accepted idle socket closes before guard release; recovery reservation succeeds only afterward; separate actual 60-second idle expiry leaves the issuer active |
| QF04 | Real built-in TLS process per backend; explicit dummy trust root, correct hostname/readiness 200, wrong hostname refusal; admitted TLS body stops on SIGTERM within five seconds |
| QF05 | Actual accepted admin child cannot issue after parent stop; exact path/inode/FD observer excludes unrelated parallel clients; measured 10-second incomplete-input lifetime; 64 accepted children with the 65th queued; real production partial admin shutdown per backend creates no token |
| QF06 | Selected production HTTP/TLS/admin process stops exercise the new local shutdown sequence; complete blocked/ambiguous server-side or worst-case crypto work remains unproven |
| QF07/QF08 | Not executed here; server-side transaction/COMMIT proof and authenticated old-host stop/reboot/transfer remain mandatory |

Proc observations read only the test process or its exact owned controller child.
They distinguish a closed local socket from a handler finishing, but are not host
identity, remote packet recall or database server completion evidence. Fixture
administration of phase/revision remains test setup, not protected activation.
The response fixture uses the same owned listener API as production, but is a
standalone socket handler, not a real broker/browser/secret delivery workflow.

The existing seven PW process cases, S01–S05 startup cases, ownership/Source/
legacy/recovery matrix and PostgreSQL snapshot regressions are preserved. The PW
transition probe now allows an already accepted transport to close while it
observes loss, then requires a fresh readiness 503 and every existing ordinary
HTTP/admin denial, valid-bearer denial and unchanged mutation count. It also
requires the diagnostic process to remain alive. This is a protocol transition
change, not omission of those authorization assertions.

## Test-first failures and controls

The admitted HTTP SIGTERM red failed after 5.27 seconds: graceful waiting left its
body pending beyond five seconds. The admin red proved acceptance by an owned FD
and then received a token reply after its listener stopped. The first ten-case
production run passed nine but its old transition probe failed on an empty HTTP
response when a pre-latch connection closed. The corrected transition assertions
preserve all subsequent fresh 503 and no-mutation checks. Later admin observers
match exact Unix socket path/inode/FD so unrelated parallel tests cannot provide
false acceptance evidence.

Three private source controls fail at real assertions: deferring fencing until
after graceful wait recreates the five-second body hang; removing transport
ownership allows local quiescence with its response socket still open; restoring
detached admin children delivers reply bytes after listener stop. Production
runtime sources remain unchanged and temporary control trees are removed.

The post-control [integration matrix](p06-transport-ownership-2026-10-04/verified-regressions-summary.txt)
passes 123 actual cases: ten production cases on each controller backend, five
original startup cases, four legacy cases on each backend, 25 Source cases on
each backend, six recovery cases on each backend and 28 ownership/transport cases.
Four current [PostgreSQL snapshot cases](p06-transport-ownership-2026-10-04/postgres-snapshot-summary.txt)
add three integration and one unit pass. All driver cleanup errors are zero and
[the final catalog](p06-transport-ownership-2026-10-04/authority-final-cleanup.txt)
contains zero generated authority/snapshot databases or roles.

- [Node 26 build](p06-transport-ownership-2026-10-04/node26-build.txt) and
  [npm tests](p06-transport-ownership-2026-10-04/node26-test.txt): exit 0;
  SPS retains 80 passes and 101 skips in 17 files. Skips are not execution evidence.
- [Rust workspace](p06-transport-ownership-2026-10-04/rust-workspace.txt):
  696 passes, zero failures, 61 ignores across 74 result targets.
  All five normal admin tests passed, including the measured deadline/admission
  bounds; generation-one crypto golden vectors and schema 16 backup verification
  compatibility remain green.
- [Clippy](p06-transport-ownership-2026-10-04/clippy.txt),
  [formatting](p06-transport-ownership-2026-10-04/format.txt) and
  [OpenAPI](p06-transport-ownership-2026-10-04/openapi.txt): exit 0.

Of 61 ordinary Rust ignores, 28 ownership/transport, ten production, five startup,
six recovery, four legacy and four PostgreSQL snapshot cases were separately
executed; three Quickshell and one optional PostgreSQL outage case remain
unexecuted. Source's 25 normal cases run again on both adapters. Rust uses the
existing locked/offline graph. Required listener/Docker fixture runs occur outside
restricted execution. Normal tests do not substitute for unexecuted QF07/QF08.

[Control summary](p06-transport-ownership-2026-10-04/controls-summary.txt) records
three actual exit 101 assertion failures, unchanged five runtime source pins and
removed private trees. [Current source pins](p06-transport-ownership-2026-10-04/source-pins.json)
cover 60 runtime/config/fixtures/DDL/contract/manifest/license boundaries.
Historical records retain their original pins. [Final QA](p06-transport-ownership-2026-10-04/final-qa.txt)
checks actual results, credential markers, links, hashes, cleanup and both vault
checkpoints. The unrelated user P03 evidence stays 66 additions/0 deletions,
unstaged and untouched. The index is empty; no slice 5/6 commit was made.

## Dependency review and remaining acceptance

A direct http-body edge was proposed and reviewed before any manifest change.
Its exact 1.1.0 root scores 100 and its broad deep minimum 89 with no alerts, but
broader reports for resolved dependency versions include development/optional
packages with medium native/build/shell alerts and a minimum supply-chain 36.
The regular resolved graph contains only http-body 1.1.0, bytes 1.12.1, http 1.5.0
and itoa 1.0.18, already present. All four exact root-package scores are 100 with
no root alerts; local manifests have no build hooks. Runtime unsafe buffer/pin
operations remain existing reviewed library behavior. Those facts do not turn
broad scores into full graph approval. The proposed edge was not added: existing
Tokio/axum transport APIs implement the lifetime tracking. Reports and the exact
unchanged regular graph are retained with the evidence.

Complete QF07/QF08 and unexecuted QF06 worst-case work remain required. Protected
restore/activation/unfence, complete broker challenge/current-key/coverage and
legacy/pruned-history reconciliation, provider cleanup/offline quarantine and
persistent-authority review remain open. PostgreSQL custom-dump/full isolated
restore retains its separate [toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md).
Packaged migration/serve sequencing, locked verified upgrades/retained backups,
both native↔Compose transfer directions, current artifacts and all three profiles'
real brokers/browser/stock-client parity remain mandatory. Earlier published
artifacts remain schema 16 and do not contain these source changes. No current
Node 24, VM/systemd, separate-host, real browser/stock-client or packaged restore
run occurred here. No slice 5/6 commit or acceptance; the full goal stays active.
