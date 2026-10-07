# P06 protected current broker trust — 2026-10-04

**Status:** Schema-3 external process proof/current-key foundations and actual
owned HTTP publication implemented and tested on SQLite and PostgreSQL.
Full nine-slice P06 remains active and unaccepted; slices 5/6 are incomplete and
no commit is made. The [product plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
retain PT01–PT06, BR01–BR10 and the original complete deployment/recovery scope.

A caller-named PostgreSQL PID is no longer sufficient to register an active
attempt. The held connection acquires the immutable tenant row, a fixed tenant
advisory lock and two distinct secret-derived advisory locks. Registration and
trust publication require that same backend/database's complete proof and exact
live tenant/issuer/owner/epoch/revision. The separate committed immutable attempt
stores only a SHA-256 digest. Arbitrary token locks cannot replace tenant
exclusion. This is tested process ownership under the reviewed deployment
assumptions, not hostile Root/database-administrator resistance or proof that a
previous host/server stopped.

The separate authority stores current public keys, approved pending candidates,
immutable prior keys and irreversible revocation. Only an actual active holder
can publish; a recovering holder reads current trust but cannot publish active
transitions. Same-version key replacement, stale versions, conflicting pending
candidates and reactivation refuse. The actual owned controller publishes each
validated enrollment, staged rotation, signed acknowledgement and revocation
before committing local controller state. An approved late rotation acknowledgement
can advance a revoked identity's key while preserving its revoked state. A local
commit failure leaves conservative external revocation, rolls back local state,
and permanently fences uncertain controller work.

Proof plaintext is a fresh 32-byte runtime buffer and private SQLx/PostgreSQL
parameter memory. Its owned buffer has a best-effort wipe on release; SQLx,
server and OS copies have separate lifetimes. It has no archive, environment,
argument, public API or adapter diagnostic representation. Protect server
logging/transport configuration. Broker registry plaintext contains only identity,
public key/version, rotation and revocation metadata. The authority database and
credentials remain outside controller backups. Existing nodes absent from this
registry stay unresolved; restored rows never automatically establish trust.

## Test-first observations and actual checks

The first [PID impersonation red](p06-protected-node-trust-2026-10-04/process-proof-red.log)
reproduces registration without held-connection proof. A first token-only fix
passes its limited test, but [unrelated-token red](p06-protected-node-trust-2026-10-04/tenant-proof-red.log)
reproduces a runtime role acquiring arbitrary locks and registering itself.
[Fixed-tenant green](p06-protected-node-trust-2026-10-04/tenant-proof-green.log)
and the final suites reject both. The [missing registry API](p06-protected-node-trust-2026-10-04/trust-api-absent.log)
is a compilation failure, not behavior evidence.

[Actual owned enrollment red](p06-protected-node-trust-2026-10-04/controller-publication-red.log)
shows approval without independently published trust. The final lifecycle uses
real HTTP enrollment/operator approval, staged keys, a candidate-key session,
signed rotation audit and DELETE revocation. The [late revoked rotation red](p06-protected-node-trust-2026-10-04/late-rotation-red.log)
returns 503 before the monotonic late-ack fix. Final [SQLite](p06-protected-node-trust-2026-10-04/authority-full-sqlite.log)
and [PostgreSQL](p06-protected-node-trust-2026-10-04/authority-full-postgres.log)
suites each pass 32 authority/process/socket/publication cases, including that
late acknowledgement and a real deferred foreign-key commit failure. The additional
[registry socket-loss case](p06-protected-node-trust-2026-10-04/trust-socket-loss-first.log)
passes without a production change: it observes an actual PostgreSQL lock wait,
terminates only the owned held backend, and checks cancelled publication, irreversible
uncertainty, no later read/write admission and one-use revision refusal. Its
post-server-work observation permits either retained active metadata or conservative
revocation; it does not turn an uncertain outcome into rollback or success. These use
actual owned controller HTTP and signed node fixtures; they are not a native
broker/HTTPS relay or VM acceptance result. Intermediate fixture route/status,
compile and cleanup-permission failures remain in the logs and are corrected;
they do not establish production behavior.

The [administrator migration](../../../deploy/controller/recovery-authority-v2-to-v3.sql)
executes in its [dedicated fixture](p06-protected-node-trust-2026-10-04/migration-final.log).
A reconstructed version-2 input removes only schema-3 additions from the owned
fixture. It is not evidence of an installed deployment migration. Active tenants,
runtime administration, a held old process guard and replay refuse. Success
preserves epoch/revision and immutable attempts with NULL historical proof, then
permits a real schema-3 claim and trust publication. Seven copied SQL function
bodies match initial provisioning exactly; stable ledger/guard table locks prevent
concurrent tenant mutation during the transaction. Startup also refuses versions
1, 2 and 4 without repairing them; existing role/write-grant refusal checks run.
Database exclusion does not supply authenticated source-stop proof.

Two actual private-copy controls fail the intended assertions: removing the
[fixed tenant proof check](p06-protected-node-trust-2026-10-04/tenant-proof-control.log)
and publishing [active instead of revoked](p06-protected-node-trust-2026-10-04/revocation-publication-control.log).
Both exit 101. The first control checker guessed enum-name output for a database
string assertion; final verification checks the actual active/revoked strings
and the intended failure. Private copies are removed, production source hashes match, and
normal workspace build/tests/Clippy run afterwards. No production fault hook or
dependency/manifest change is introduced.

## Regression gates and remaining acceptance

Node26 build/tests, workspace Rust, Clippy, format, OpenAPI and diff checks exit 0.
The first workspace run fails a copied CLI executable fixture with OS ETXTBSY
(`Text file busy`). The exact [isolated check](p06-protected-node-trust-2026-10-04/cli-clock-isolated.log)
passes; no concurrent Cargo process remains. The complete workspace rerun uses
four test threads, preserving the [first failure](p06-protected-node-trust-2026-10-04/rust-workspace-first.log)
and [first gate results](p06-protected-node-trust-2026-10-04/gates-first.json).
Workspace: 726 passed, 0 failed, 78 ignored across 79
result targets. Node SPS Vitest retains 17 skipped files/101 skipped tests; these
remain unexecuted and do not establish acceptance. Rust ignores are listed in
[ignored cases](p06-protected-node-trust-2026-10-04/ignored-cases.json). The ignored authority/migration cases are executed through the
separate driver above. This turn also executes both-backend invalidation and
legacy-auth suites, both-backend actual production ownership, production startup,
PostgreSQL quiescence, ordinary restore and nine dedicated restore crash/authority
loss cases. There are 131 integration test executions
across 14 logged runs; counts overlap. Raw [gates](p06-protected-node-trust-2026-10-04/gates.json),
[regressions](p06-protected-node-trust-2026-10-04/regressions.json),
[counts](p06-protected-node-trust-2026-10-04/counts.json),
[controls](p06-protected-node-trust-2026-10-04/controls.json) and
[81 current source pins](p06-protected-node-trust-2026-10-04/source-pins.json)
retain the boundary. The protected user P03 record remains unstaged at 66 additions,
0 deletions; index remains empty and HEAD remains slice-4 commit `8a595ad`.

The independently current-key recovering consumer, actual HTTPS node relay,
durable one-use challenges/page receipts, complete live/offline broker coverage,
post-backup unknown-node quarantine, higher-epoch reservation/rebase, provider
credential/trust cleanup, role/session review, authenticated old host/server stop
and explicit protected activation remain required. No SourceStopProof or unfence
is implemented. PostgreSQL custom dump/full restore still awaits the separate
toolkit review; the approved external PostgreSQL authority uses only the existing
SQLx stack. Locked upgrade, interrupted bidirectional native/Compose migration,
full three-profile/remote workflow/fault acceptance and inherited P02.6/P03/P05
remain open. GHCR/ARM/Unraid GUI and restic remain separately unaccepted.
