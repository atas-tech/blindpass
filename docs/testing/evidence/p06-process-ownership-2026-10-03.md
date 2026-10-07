# P06 process ownership and router candidate — 2026-10-03

P06 remains active and unaccepted. This work adds real connection exclusion,
a durable one-use active revision and a tested HTTP gate candidate using the
user-selected separate PostgreSQL authority and existing reviewed SQLx.
Production `serve`, signing/store/maintenance, local administration, full restore,
source-stop proof and activation are not integrated. No dependency or package
boundary changed, and no slice 6 commit precedes incomplete slice 5.

## Executed outcomes

The [test-first paired plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
recorded OP01–OP09 before implementation, then OP10's durable attempt and OP11's
local context/epoch binding before their respective code changes. [ADR 0012](../../product/decisions/0012-p06-external-recovery-authority.md)
describes the candidate boundary and missing production integration.

| Gate | Actual result | Evidence |
|---|---|---|
| First process API tests | Expected compile failure: missing claim API, exit 101 | [First red](p06-process-ownership-2026-10-03/first-red.txt) |
| Initial implementation compile | SQLx raw-SQL callback lifetime/Send error, then fixed single-query setup compiles | [Compile error](p06-process-ownership-2026-10-03/compile.txt), [compile green](p06-process-ownership-2026-10-03/compile-retry.txt) |
| Initial process guard | Six OA metadata + eight process cases: 14 pass; cleanup 0 | [14 cases](p06-process-ownership-2026-10-03/postgres-first.txt), [summary](p06-process-ownership-2026-10-03/postgres-first-summary.txt) |
| Router test first red | Expected missing builder/gate compile failure, exit 101 | [Router red](p06-process-ownership-2026-10-03/http-first-red.txt) |
| Actual router and expanded deadlines | 16, then 18 cases pass; owned cleanup 0 | [16 cases](p06-process-ownership-2026-10-03/http-postgres-first.txt), [18 cases](p06-process-ownership-2026-10-03/postgres-expanded.txt) |
| Active-revision reuse, before fix | Real backend termination followed by same active record is wrongly admitted: 0 pass/1 fail, exit 101 | [OP10 red](p06-process-ownership-2026-10-03/active-first-red.txt) |
| Durable active attempt | 19 cases pass, no failure; cleanup 0 | [19 cases](p06-process-ownership-2026-10-03/postgres-active-green.txt) |
| Local identity/epoch, before fix | Wrong local tenant remains unfenced; stale epoch serves capabilities 200: 0 pass/2 fail, exit 101 | [OP11 red](p06-process-ownership-2026-10-03/binding-first-red.txt) |
| Local identity/epoch, after fix | 21 cases pass; cleanup 0 | [Binding green](p06-process-ownership-2026-10-03/postgres-binding-green.txt) |
| Final real authority/router suite | 21 pass/0 fail in 16.77s; OA08 filtered because it runs normally; exit 0 and cleanup 0 | [Final cases](p06-process-ownership-2026-10-03/postgres-final.txt), [summary](p06-process-ownership-2026-10-03/postgres-final-summary.txt) |
| Private weakened final schema | Removing only the claim row lock admits two holders: OP01 0 pass/1 fail, exit 101; production schema unchanged; private tree removed; cleanup 0 | [Control failure](p06-process-ownership-2026-10-03/lock-control-final-red.txt), [control summary](p06-process-ownership-2026-10-03/lock-control-final-summary.txt) |
| Complete locked offline Rust workspace | 689 pass/0 fail/29 ignores across 71 result targets, exit 0 | [Workspace gate](p06-process-ownership-2026-10-03/rust-workspace.txt) |
| Final all-target Clippy | Pass, warnings denied, exit 0 | [Clippy](p06-process-ownership-2026-10-03/final-clippy.txt) |
| Node26 build | Pass, exit 0 | [Build](p06-process-ownership-2026-10-03/node26-build.txt) |
| First Node26 workspace tests | One console DR-E08 overview assertion cannot find stat-pending; other workspaces pass; exit 1 | [First test gate](p06-process-ownership-2026-10-03/node26-test.txt) |
| Unchanged isolated overview | Five pass, exit 0 | [Isolated file](p06-process-ownership-2026-10-03/node26-overview-isolated.txt) |
| Unchanged full Node26 retry | Pass, exit 0; console 108/MCP 108/helper 147; SPS 80 pass/101 skip in 17 files | [Workspace retry](p06-process-ownership-2026-10-03/node26-test-retry.txt) |
| Independent final PostgreSQL catalog check | Server 16.15; zero generated authority databases and owner/runtime/member roles | [Cleanup](p06-process-ownership-2026-10-03/authority-cleanup.txt) |

The first Node failure occurred while the Rust workspace compiled/ran. The
unchanged isolated/full retries pass; its exact cause is not established. No
JavaScript source, test timeout or fixture changed to make it pass. The full
Rust gate ran after the final production code change. Only authority test URL
samples/CORS control were refined afterward; final scoped execution and Clippy
validate those current tests. No broad check is substituted for actual authority
execution: its 21 normal ignores execute above. Four snapshot ignores have
separate earlier execution; three Quickshell and one opt-in PostgreSQL outage
remain unexecuted by this workspace gate. Node24, new native/OCI artifacts,
separate-host VM ownership and full client/browser/profile gates were not run.

## What the actual cases establish

Schema version 2 is explicitly provisioned in a new independently administered
database. Runtime credentials cannot write protected tables or acquire hidden
administrator membership; missing grants/layout refuse without migration.
A dedicated detached socket owns a READ COMMITTED transaction and an immutable
per-tenant row lock. Two independent matching connections admit exactly one;
other tenants remain independent. Wrong contexts/revisions/epochs/phases refuse,
failed claims release their guard and ordinary deletion/reset refuses.
Reservation/owner transfer refuses while held; independent fencing increments
revision and the old holder latches closed.

Active claims also durably append one tenant/epoch/revision/backend attempt
through a separate connection. After backend termination the same active record
cannot be claimed again, although its protected epoch/revision persist. Runtime
and ordinary owner updates/deletion/truncation cannot erase that attempt. A new
explicit fence/recovery reserves a higher epoch; its candidate cannot issue.
The test sets active phase through an independent administrator fixture; this
is not evidence of a real source-stop/reconciliation/activation procedure.

Owned TCP proxies blackhole only this run's PostgreSQL connections. Constructor,
read and reservation measure 3001ms each in final execution; checks also respect
the configured three-second deadline and five-second test bound. Timed-out and
externally cancelled checks close/latch permanently; restored transport does
not reclaim them. A one-second monitor detects idle backend loss and stops.
Timings use the running host's monotonic clock; they do not prove suspend-inclusive
or VM wall-time behavior. The reservation deadline test uses a wrong owner to
prevent a late commit, and does not prove the successful ambiguous-commit fault.

The actual Axum candidate first denies a valid fenced holder while retaining
health and database-up/authority-fenced readiness. With an explicitly active
fixture it serves matching capabilities/readiness and accepts a real allowed
CORS preflight with 204. After exact backend loss it denies 144 combinations
(8 methods × 18 selected actual legacy/fleet/admin/UI/fallback paths), including
preflight with 503; health remains 200 and readiness reports database-up and
authority-down. A pending test handler is dropped before its canary response
is delivered. Wrong actual local tenant/key or missing store fences. Stale,
future and unreadable local epochs also fence without rewriting local/external
metadata. The pending-handler fixture tests middleware cancellation; it does
not execute an actual in-flight node mutation or streamed secret body.

## Reproduce and custody

Run from the repository root after other Cargo jobs release the build lock:

```sh
cargo test -p blindpass-controller --test recovery_authority --locked --offline
python3 tests/deployment/recovery-authority-postgres.py --log /tmp/p06-process-test.txt
```

The existing reviewed PostgreSQL fixture is required. The driver creates its
own unique database and three roles, uses private psql stdin and generated
passwords/URLs only in private Python/child SQLx memory/environment, captures
public test logs exclusively as 0600 and drops only its resources. Credentials
remain in those processes/configuration for their lifetime and are revoked by
role removal; this does not establish allocator zeroization. Dummy controller
keys/local metadata use disposable private directories and are deleted. Runtime
logs contain opaque identifiers/status and canaries, not private keys, credential
URLs, live links, bearer headers or payload/provider cleanup handles. No host
service, shared PostgreSQL server, other controller or guest was stopped.

The [final QA record](p06-process-ownership-2026-10-03/final-qa.txt) confirms format,
Python parsing, whitespace, 141 relative links, five source pins, 33 runtime log
scans and unchanged manifests/empty index/protected user evidence.

## Current source identity and remaining acceptance

| Source | SHA-256 |
|---|---|
| [`crates/blindpass-controller/src/recovery_authority.rs`](../../../crates/blindpass-controller/src/recovery_authority.rs) | `c85164168f39fc2830748304e370c310987ef00caa462ec045b085ab6ff1b8fb` |
| [`crates/blindpass-controller/src/app.rs`](../../../crates/blindpass-controller/src/app.rs) | `ec805b8270e930a6d78d43349d3e0070c30467da835276c4661ecd0a5f234b0e` |
| [`crates/blindpass-controller/tests/recovery_authority.rs`](../../../crates/blindpass-controller/tests/recovery_authority.rs) | `b7163bbf5c54b935182142f63cb6c8c01879f42dcf142754c80b6e2bf2edc7fc` |
| [`deploy/controller/recovery-authority.sql`](../../../deploy/controller/recovery-authority.sql) | `d97bcc1c3c1085a9ecd82fa951ff08bcd11f919dc1eb605e253e9c3699b47411` |
| [`tests/deployment/recovery-authority-postgres.py`](../../../tests/deployment/recovery-authority-postgres.py) | `be0a39ead431ed4bd8ed09c5aacba66faab18cf56f6d86541cf559ad0b815d20` |

Source pins were taken after final implementation and route/preflight refinement.
The final weakened-schema control preserves production schema/source. Historical
[metadata](p06-recovery-authority-ledger-2026-10-03.md), [bound journal](p06-consumption-journal-2026-10-03.md)
and [report contract](p06-consumed-report-contract-2026-10-03.md) retain their own
source/artifact pins; no current native/OCI rebuild or two-host acceptance is
implied. Protected P03 user evidence stays 66 additions/zero removals and unstaged.

Preserve all nine slices: matching PostgreSQL custom dump/full isolated restore
and shipped faults; mandatory production ownership/startup/store/signing/
maintenance/all-route fence and full quiescence/source-stop proof; transactional
legacy/fleet invalidation; complete signed broker coverage/pagination/challenges/
current keys, provider cleanup and offline quarantine; locked upgrades;
interrupted native↔Compose transfer; all three shipped, remote, browser/native
and inherited acceptance gates. Generic consumed_report admission remains closed.
The PostgreSQL dump/restore-toolkit human dependency review remains pending;
TLS/scanner approvals and the authority architecture choice do not approve it.
