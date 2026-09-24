# P02 Rust controller implementation and test evidence

**Date:** 2026-09-24

**Scope:** P02 controller/API implementation through provisioning, exchanges, approvals, local administration, generated OpenAPI types, browser-status CT19, I03 process crash/restart recovery and the 2026-09-24 CLI, clock, schema and administration follow-up. Every local P02.6 gate passes on both stores; hosted clean-checkout CI has not run, so this is not a P02 acceptance or cutover record.

## Environment and contract matrix

- Linux, Node.js 26.x, Vitest 4.1.11, Rust workspace toolchain, Chromium.
- Rust contract runs start a disposable controller process. SQLite uses a temporary database; PostgreSQL uses a uniquely named schema that the adapter drops on teardown.
- All fixtures use generated dummy keys/tokens and synthetic ciphertext. No live secret material is included here.

The TypeScript SPS baseline was rerun against the local PostgreSQL and Redis test services: 36/36 tests passed with no skips. This confirms the P00 contract baseline used by P02 remains green on the current working tree.

The Rust contract suite ran against both stores. The PostgreSQL run set `CONTRACT_DATABASE_URL` to the repository's disposable local test database; the adapter created and dropped a uniquely named schema:

```bash
SUT=rust CONTRACT_RUST_BACKEND=sqlite npm run test --workspace=@blindpass/contract-tests -- --reporter=dot
SUT=rust CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=<disposable-test-database-url> npm run test --workspace=@blindpass/contract-tests -- --reporter=dot
```

The 2026-09-24 rerun executed 34 Vitest tests with no skipped tests on each backend. Each run had 33 passes and one failure: CT14, because `POST /api/v2/auth/refresh` returns 404. The exact TypeScript snapshot comparison passed on both backends. CI-style JSON reports also passed `assert-no-vitest-skips` and `assert-contract-progress`, which reported 18/19 required cases passed and CT14 as the sole explicitly pending case. This remains incomplete while P02-D4 is unresolved; it is not a green full-parity result. The `rust-pending.json` manifest documents the reason. CT12 currently accepts the configured issuer's tenant-scoped `admin` claim and passes its positive and negative assertions, but P02-D11 still needs explicit product acceptance.

### Hosted-user scope correction and rerun

The subsequent route-identity review separated hosted workspace-user refresh (`/api/v2/auth/refresh`, CT14) from local operator refresh (`/api/v3/admin/session/refresh`). The current roadmap excludes hosted user auth from the Rust controller. CT14 therefore remains in the TypeScript SPS regression suite, is listed as an explicit Rust exclusion, and the Rust controller OpenAPI omits the hosted route. The Rust test-only compatibility session stored in the operator table was removed. The historical 18/19 result above records the earlier gate, not the current scope.

At this earlier corrected-scope stage, the TypeScript contract suite passed 37/37 with no skips against disposable PostgreSQL and Redis; CT14 executed and passed. Rust SQLite and PostgreSQL each passed 35/35 with no skips. Each JSON report passed `assert-no-vitest-skips` and `assert-contract-progress`: 18/18 required Rust cases passed with zero pending. The Rust suite also asserted that the hosted route returns 404. That stage used a narrowed shared snapshot, which the later baseline audit replaced with explicit Rust projections derived from the restored, full P00 TypeScript baseline. The Rust PostgreSQL adapter created and dropped an isolated schema.

`npm run generate:api`, the generated-type drift check, and `npm run test:controller-openapi` (6/6) passed with 12 retained machine routes plus two adopted browser-status routes. `npm run build`, `cargo fmt --all -- --check`, `cargo check --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and the host-access `cargo test --workspace --locked` passed. The PostgreSQL store transition suite passed 14/14 after removal of the hosted compatibility-session test; the local operator refresh/replay test remains. `npm test` passed with 80 SPS tests passed and 101 default database-gated skips, plus the other workspace suites. A sandboxed HTTP attempt failed before server startup with localhost `EPERM`; a sandboxed Rust workspace run failed Unix-socket broker tests and was interrupted after a hang. The host-access reruns above passed.

The corrected-tree CC02 real-client runner passed on SQLite and PostgreSQL: gateway request, OpenClaw polling/decryption, agent exchange and OpenClaw fulfillment. The browser suite passed 3/3 on each backend: the CC02 human-input script and both CC03 signed-link/expiry cases. These runs use the controller seed response after the hosted refresh field was removed. They do not exercise the legacy hosted-user refresh branch or the packaged CSP.

The failpoint-enabled controller was rebuilt from the corrected tree. P02-I03 passed its eight process crash/restart scenarios again on SQLite and PostgreSQL, including one-use retrieval, policy compare-and-set, and approval/audit commit boundaries.

The browser suite was then rerun with CSP enforced. The first targeted CC03 run failed as expected when the Rust adapter used an ephemeral API port blocked by the page's `connect-src` policy. The browser suite now binds the controller to the page's standard local API port 3100, does not use Playwright `bypassCSP`, and asserts that the loaded page carries the expected CSP meta directive. Full CC02/CC03 browser runs passed 3/3 on SQLite and 3/3 on PostgreSQL with CORS still active. `npm run build` and the host-access `npm test` rerun passed after this adapter change; the sandboxed `npm test` run failed the OpenClaw subprocess suite before the host-access rerun. This verifies the local development page policy and flow; packaged nginx delivery remains untested.

P02-I07 failure-path coverage was extended. A new store test first demonstrated that an unsupported `controller_meta.schema_version` was accepted; startup now rejects it before migration. The test removes a schema table and confirms that neither backend recreates it on the rejected connection. The SQLite and PostgreSQL store suites each pass 18/18 after later race, tenant and lock-wait cases were added. Production-mode shell/config tests pass 6/6: missing, truncated and unsafe key files fail without revealing or regenerating key material; an inaccessible database prevents startup with a sanitized error; the test seed route is absent; test timing overrides are rejected; and readiness reports an unavailable store without sensitive details. The full Rust workspace tests, format, check and Clippy gates passed after the schema change. Rust HTTP contract suites now pass 36/36 on each backend. A live database disconnect after startup and packaged deployment remain separate checks.

The admin HTTP integration test now races two first-run bootstrap requests using one capability: exactly one succeeds, the other receives 409, and a subsequent replay also receives 409. Missing-capability and foreign-origin bootstrap attempts fail. A cross-origin operator login fails, while an assigned operator can approve its own request and cannot list agents; viewer operator-list denial, admin policy/agent actions, session CSRF/refresh replay and last-admin protections remain covered. The same test passes on SQLite and an isolated PostgreSQL schema. Store expiry tests now assert visibility before the deadline and rejection before sweep and after restart on both backends. A submit-versus-revoke race cannot restore ciphertext, matching agent IDs cannot read, reserve or revoke a foreign-tenant exchange, and an exchange expiring while a database lock blocks reservation stays unavailable after lock release; SQLite and PostgreSQL store suites pass 18/18. These additions strengthen P02-I01, I02 and I04–I06 without establishing every HTTP race or role permutation in the plan.

The admin HTTP test then added simultaneous approve/reject requests for one pending approval. SQLite first returned 200 and 503 because two deferred transactions read the same pending state before either held its writer lock. The approval decision now begins with `BEGIN IMMEDIATE` on SQLite, so the requests serialize and the losing decision returns 409. The test passes on both SQLite and PostgreSQL with one final approved or rejected state. This is real HTTP evidence for the P02-I01 approval race; it does not replace the other transition tests.

A Rust-only P02-I01 HTTP case now races exchange submission against requester revocation and verifies the final requester status is revoked with no retrievable ciphertext. The full HTTP contract suite, including all required snapshots, passes 36/36 on SQLite and 36/36 on PostgreSQL. Fresh CI-style JSON reports for both stores pass `assert-no-vitest-skips` (36 executed, none skipped) and `assert-contract-progress` (18/18 required, zero pending). A targeted single-case run passed the race itself but failed the suite-wide snapshot assertion because the other contract cases were intentionally skipped; the full-suite results are the valid contract evidence. After the SQLite approval writer-lock correction, `cargo test --workspace --locked` passed, the controller integration suite passed on PostgreSQL (including 18/18 store transitions), and the full 36-case Rust HTTP suite passed again on each store. The failpoint controller was rebuilt and all eight P02-I03 process crash/restart scenarios passed again on each backend. P02-I07 shell/config now passes 7/7 on SQLite and 7/7 on PostgreSQL: after a live store pool closes, `/readyz` changes from 200 to sanitized 503 while `/healthz` remains 200. This tests pool disconnection; a network outage and reconnection are still open.

The configured audit retention now runs independently of the short ciphertext expiry sweep. A new test first failed because `sweep_audit` did not exist, then passed on SQLite and PostgreSQL after implementation: a three-day-old event is removed at a one-day limit, a fresh event remains, and a repeated sweep removes nothing. Rust formatting, Clippy and workspace tests passed, with 19/19 store-transition and 7/7 shell tests on SQLite; the PostgreSQL controller integration suite also passed 19/19 and 7/7. The pre-projection live Rust HTTP rerun passed 36/36 on each store with no skips and 18/18 required cases. The optional native TLS dependency review blocked `axum-server@0.8.0` under dependency-guard (deep score 12; high transitive alerts), so built-in TLS is not implemented; the reverse-proxy HTTP profile is the current path.

The tested runtime and contract harness landed together in commit `3c41289`, after dependency and schema commits. This consolidates planned slices 3–8 into one integration commit because their route, administration and store interfaces were compiled and tested together. It deviates from the vault's one-commit-per-slice sequence; the executable state and the scope of the deviation are explicit here. The phase acceptance review remains open.

The final snapshot audit restored `packages/contract-tests/fixtures/snapshots/ts-baseline.json` byte-for-byte from the P00/schema commit. Rust now derives explicit CT01, CT16 and CT17 projections from that full baseline; every other retained case compares its full normalized response. A unit test rejects Rust attempts to rewrite the TypeScript baseline. The full TypeScript SPS suite passed 39/39 with no skips, including CT14. Rust SQLite and PostgreSQL each passed 38/38 with no skips, and the progress gate reports 18/18 required cases. `npm run build` and the host-access `npm test` passed after this correction; the default SPS test run still reports 80 passes and 101 database-gated skips.

The existing browser UI Dockerfile built successfully as `blindpass-p02-browser-csp:test` using the tagged Node 26 Alpine and nginx 1.29 Alpine stages. A disposable loopback nginx container served the built page. Playwright passed 4/4 against the Rust SQLite controller and 4/4 against PostgreSQL: delivered CSP, Permissions-Policy, Referrer-Policy, X-Content-Type-Options and X-Frame-Options headers; the CC02 human-input script; CC03 signed-link seal/submit/decrypt; and expired-link disablement. The page CSP remained enforced and the controller ran on port 3100. The normal development-page mode also passed 3/3 after adding packaged mode. The container was stopped and removed after testing. The packaged mode is wired into each Rust CI backend job. This establishes the packaged local browser flow and response headers on the development host; it does not establish a production reverse-proxy deployment or hosted CI execution.

After the lock-wait and PostgreSQL admin HTTP additions, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, the host-access `cargo test --workspace --locked`, `npm run build` and the host-access `npm test` all passed. The default SPS portion of `npm test` still has 101 database-gated skips; the separate TypeScript contract and Rust backend runs provide their own execution evidence.

The corrected-tree P02-I08 live failure probe ran on both stores. Injecting a wrong `CT01.healthz` status caused each Vitest run to exit nonzero. Each JSON report still contained 35 executed tests with no skips, and `assert-contract-progress` rejected CT01 as an unexpected failure. The clean reports above passed the same checker. Hosted CI execution remains unverified.

The adopted CT19 test passes on SQLite and PostgreSQL. It checks idempotent capability issuance; rejection of missing, wrong-scope and tampered source credentials; expiry bounded by the metadata signature and request deadline; status-only output; wrong-scope and foreign-request denial; submit/retrieve scope separation; one-use retrieval behavior; expiry; and status continuity after controller restart.

## Browser, store and schema checks

The CC02 client runner passed on SQLite and PostgreSQL. It drove the actual gateway request client, OpenClaw request/poll/decrypt flow, agent exchange client and OpenClaw fulfillment flow against the controller, then checked audit output for dummy canaries. The `scripts/e2e-human.mjs` flow also passed on both backends through a real Playwright page: the script's gateway client created a request, the browser submitted dummy input, the agent client decrypted it and confirmed second retrieval was unavailable.

The initial CC03 Playwright cases passed 2/2 on each backend: the existing browser page loaded a signed request, encrypted and submitted dummy input, and the requester decrypted it; an expired signed link disabled entry. That initial run used a dynamic API port and bypassed CSP. The later 3/3 reruns above use port 3100 with CSP enforced and CORS active; packaged nginx delivery and response headers remain unverified.

Rust format, clippy and workspace tests passed:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

An earlier SQLite and PostgreSQL store-transition run passed 18/18 on each backend, before the audit-retention case raised the count to 19/19. The tested transitions include concurrent submit/consume, one-use retrieval, expiry before cleanup and after database restart, retention cleanup, exchange submit/revoke races, foreign-tenant exchange isolation, expiry while blocked on a database lock, bootstrap/setup-token serialization, session rotation/replay, operator removal protections, policy compare-and-set and approval idempotency. Two store tests named with P02-I03 verify that a committed one-use retrieval remains consumed and a stale policy retry remains rejected after the store reconnects; those are reconnect tests, supplemented by the process-kill cases below. The HTTP admin-session test passed on both stores, and local Unix-socket tests passed in the workspace run.

P02-I03 process crash/restart scenarios passed on SQLite and PostgreSQL using a dedicated controller build with the `p02-test-failpoints` feature. Each scenario abruptly exits the controller at the selected transaction boundary and starts a new process against the same database:

- Compatibility secret-request and exchange retrievals killed before commit roll back; each payload is available after restart, then consumed once.
- Compatibility secret-request and exchange retrievals killed after commit but before the HTTP reply stay consumed; retry returns 410 and ciphertext is not resurrected.
- Policy mutation killed before commit rolls back; retry with the original version succeeds.
- Policy mutation killed after commit but before the reply survives; retrying the stale version returns 409.
- Approval decision killed after inserting its audit event but before commit leaves the approval pending and no decision audit; retry with the same idempotency key commits once.
- Approval decision killed after commit but before the reply remains approved; replaying the same idempotency key returns success without duplicating the audit event.

The first crash run exposed a stale Unix admin-socket path after abrupt exit. Startup now removes a stale socket path after confirming it has no live listener; normal Rust tests and both backend crash suites pass with this recovery behavior. CI builds the failpoint controller separately from the default binary and runs this matrix for both backends.

`npm run generate:api`, `npm run test:controller-openapi` (5/5), `npm run test:openapi-types --workspace=@blindpass/contract-tests` (1/1) and `node scripts/generate-controller-types.mjs --check` passed. `npm run build` passed. The host-access `npm test` rerun passed with 80 tests passed and 101 skipped; these skips are the default SPS database-gated suites and remain unexecuted by that command. The initial sandbox run could not start the three OpenClaw MCP subprocess cases; the host-access rerun passed all three. `cargo fmt --all -- --check`, `cargo check --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo test --workspace --locked` also passed on the final working tree.

P02-I08 failure-path probes passed locally for SQLite and PostgreSQL. In the latest run, each CI-style JSON suite had no skipped tests; the injected `CT01.healthz` status mismatch caused the progress checker to reject `CT01` as an unexpected failure. A separate generated-type probe appended a stale declaration marker and confirmed `node scripts/generate-controller-types.mjs --check` exited nonzero, then restored the generated file. These checks verify the local negative paths; the clean-checkout GitHub Actions workflow has not run in this task.

## 2026-09-24 follow-up: CLI, clock, schema and administration

The follow-up landed as eight commits on top of `a396b40`, one per slice:

| Commit | Change |
|---|---|
| `ab9a83e` | P02-D9 persisted database clock high-water mark (migration 0003) with per-statement regression guards; P02-I07 base-table verification before migration |
| `3030bde` | `blindpass migrate`, `blindpass admin seed --fixture <file>`, `blindpass admin reset-password <id>`; one shared HTTP/CLI fixture function with policy, rotated/revoked agents and an opt-in local administrator; OpenAPI test-seed response corrected to the exercised 200 shape |
| `e6b498f` | Forced password change: an operator holding a temporary password gets 403 `password_change_required` on every admin route except session read, refresh, logout and change-password |
| `76d1f56` | Schema version follows the migration files (now 3); per-version table verification, forward migration of older versions, fail-closed on damaged schemas; lock-free clock checkpoint that advances the mark at most once per second |
| `31ff537` | `blindpass admin reconcile-clock` recovery for a detected clock regression |
| `847603b` | P02-I07 PostgreSQL outage and reconnection test; the admin HTTP suite now runs per backend in CI |
| `1bc142e` | P02-I06 admin/operator/viewer role matrix over HTTP |
| `0196f80` | OpenAPI admin-session description of the forced password change gate |

Tests were written before each behavior change and failed first where the behavior was new. The forced password change case first saw a temporary-password session list agents with 200. The schema cases first reported version 1 after a forward migration and silently recreated a dropped clock table. The reconciliation shell and CLI cases first failed on an unknown subcommand. The outage and role-matrix cases pin behavior that already existed. A mutation that let operators list agents made the role-matrix case fail, and it passed again after the mutation was reverted.

Clock design (P02-D9). The checkpoint reads the database wall clock and the persisted mark without a write lock and fails closed on regression. It advances the mark with one guarded statement at most once per second. Every expiry predicate and transition timestamp still evaluates to NULL when the database clock is behind the mark. A regression larger than one second therefore fails closed. A smaller one can go undetected and extend a deadline by at most one second. After a larger regression the controller refuses to start. `reconcile-clock` then deletes secret requests, exchanges, pending and approved approvals, bootstrap tokens, rate windows and idempotency keys, because their deadlines came from the faster clock and expired rows would otherwise become readable again. It also revokes operator sessions, resets the mark and writes one `clock_reconciled` audit event. Operators, agents, policy, rejected approvals, lifecycle and audit history are kept.

## Final local execution on `0196f80`

All commands ran on the development host with host access, against the local PostgreSQL 16 service on port 5433 and Redis on port 6380. Only documentation files were uncommitted during the run.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check`, workspace Clippy with `-D warnings` | Pass |
| `cargo test --workspace --locked` (SQLite) | 98 passed, 0 failed; the PostgreSQL-only outage case reports ignored |
| Controller and CLI suites with `P02_TEST_BACKEND=postgres` | 56 passed, 0 failed |
| Store transitions | 24/24 on each store |
| Shell/config, including migrate, seed, damaged schema and `reconcile-clock` | 11/11 on each store |
| Admin HTTP: bootstrap race and sessions, forced password change, role matrix | 3/3 on each store |
| CLI dispatch and socket tests | 5/5 |
| P02-I07 PostgreSQL outage and reconnection (`--ignored`) | 1/1: sanitized 503 during the outage, fail-closed store calls, 200 and intact state after recovery without a restart |
| Rust HTTP contract, SQLite and PostgreSQL | 38/38 each with no skips; progress gate 18/18 required, zero pending |
| P02-I08 injected CT01 mismatch, both stores | Suite exits nonzero with 37/38 and no skips; progress gate rejects it with "Unexpected failure for CT01" |
| TypeScript SPS baseline | 39/39 with no skips; `ts-baseline.json` byte-identical to its committed version |
| `npm run build`; `npm test` | Pass; SPS 80 passed with 101 default database-gated skips |
| OpenAPI generation, drift and type checks | `generate:api` leaves no diff; `--check` passes; 8/8 schema tests, 1/1 generated-type test, 6/6 progress-script tests |
| CC02 client flows | Pass on both stores |
| P02-I03 failpoint crash/restart matrix | Pass on both stores |
| CC02/CC03 browser, development page | 3/3 on each store |
| CC02/CC03 browser, packaged nginx image | 4/4 on each store, including delivered security headers |

## Decisions recorded 2026-09-24

- **W0.** The user accepted W0 as NARROW for the tested Ubuntu 24.04/systemd 255, no-TPM profile only. This satisfies the W0 prerequisite for P02.6 and P03 within that profile. Details are in [P01 VM evidence](../p01-host-broker-evidence.md).
- **CT15 local quota scope.** The user closed CT15 at the accepted compatibility envelope: per-IP agent token mint and per-agent request/exchange rate windows. The `quota_counters` table stays reserved and unused. Paid-tier and daily quota behavior remains a P00 exclusion.
- **P02-D7 TLS.** The user accepted plain HTTP behind a reverse proxy as the only P02 profile. Built-in TLS stays unimplemented after `axum-server@0.8.0` was blocked by dependency review. P06 re-evaluates native TLS with a fresh dependency review.
- **Hosted CI.** The user chose not to push the branch in this session, so the clean-checkout GitHub Actions run is not available.
- CT14 remains a TypeScript-only hosted-user case, and P02-D11 issuer-admin authority stands as accepted earlier the same day.

## Remaining work and limits

- **Hosted clean-checkout CI is the last open P02.6 gate.** The workflow runs the TypeScript baseline, both Rust backends, the admin HTTP suite per backend, the PostgreSQL outage case, crash, client and browser flows and the mismatch probe. None of it has executed on GitHub Actions from this branch.
- Production reverse-proxy deployment is unverified and belongs to P06.1, together with native and container recovery and database migration support.
- Stateless agent JWTs and signed browser links are checked against the controller host clock, not the database clock. A host clock step back extends them by the step, bounded by their short lifetimes. Secret requests behind signed links are still checked and purged against the database clock.
- Test fixtures check agent IDs before writing, but two concurrent fixture writers can still race. Fixtures must use isolated test databases.
- HTTP race coverage includes first bootstrap, approve/reject and submit/revoke. Other concurrent permutations rely on store-level tests.
- Commit `3c41289` consolidated planned slices 3–8, which deviates from the one-commit-per-slice sequence. The follow-up above uses one commit per slice.
- Earlier attempts on this follow-up inside a restricted sandbox could not bind local sockets. The host-access run above supersedes them.

## Acceptance audit

| Plan item | Status on `0196f80` |
|---|---|
| CT01–CT13, CT15–CT19 | 18/18 required cases pass on both stores; CT14 excluded as hosted-user auth and green in the TypeScript run |
| CV01–CV06 | Pass in the Rust contract run on both stores; the Rust workspace also passes the cross-language HPKE vectors |
| CC01–CC03 | CC01 live-response client check runs in the contract suite; CC02 client and CC03 browser flows pass on both stores, including packaged nginx |
| P02-I01/I02 | Store races, expiry before sweep and after restart, and lock-wait expiry pass on both stores; HTTP races as listed above |
| P02-I03 | Eight process-kill scenarios pass on both stores |
| P02-I04–I06 | Bootstrap race and replay, session CSRF and refresh replay, forced password change, local reset and the full role matrix pass on both stores |
| P02-I07 | Key, database, schema-version, damaged-schema, seed/override, pool-loss, clock-regression and PostgreSQL outage/reconnection cases pass |
| P02-I08 | Local mismatch and drift probes reject correctly on both stores; hosted CI not run |
| P02-E01/E02 | Client and generated-type checks pass with no schema drift |
| P01 W0 | Accepted NARROW for the tested profile |
| Hosted clean-checkout CI | Not run; required before P02 acceptance |
