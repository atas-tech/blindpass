# P02 Rust controller implementation and test evidence

**Date:** 2026-09-25. This record supersedes the 2026-09-24 version; its path is condensed under [History](#history).

**Scope:** P02 controller/API implementation, the adopted CT19 browser-status routes, P02-I03 process crash recovery, the 2026-09-24 CLI, clock, schema and administration follow-up, and the 2026-09-25 review fixes.

**Status:** Every local P02.6 gate passes on SQLite and PostgreSQL on the tree below. Hosted clean-checkout CI has not run and several review findings need product decisions, so this is not a P02 acceptance or cutover record.

## Tested tree and environment

- Code: commit `86f3a59` plus the uncommitted 2026-09-25 review fixes in controller routes, store and tests, the contract harness and snapshot, the progress gate, the OpenAPI document and CI. Replace this line with the commit SHA once the fixes are committed.
- Linux development host with host access; Node.js 26.10.0, Vitest 4.1.11, Rust 1.98.1, Chromium; PostgreSQL 16 on port 5433 and Redis 7 on port 6380 from `docker-compose.test.yml`.
- Rust contract runs start a disposable controller. SQLite uses a temporary database; PostgreSQL uses a uniquely named schema that the adapter drops on teardown.
- Fixtures use generated dummy keys, tokens and canaries and synthetic ciphertext. No live secret material is included here.

## Results on 2026-09-25

The gates ran sequentially from the repository root, mirroring `.github/workflows/ci.yml`.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check`; workspace Clippy with `-D warnings` | Pass |
| `cargo test --workspace --locked` (SQLite) | 111 passed, 0 failed: controller unit 16, store transitions 28, shell/config 14, admin HTTP 4, admin socket 2, CLI 5 and the other workspace crates; the PostgreSQL-only outage case is ignored |
| Controller with `P02_TEST_BACKEND=postgres` | 64 passed, 35 of them on PostgreSQL. The variable selects the backend for all 28 store-transition tests, all 4 admin HTTP tests and 3 of the 14 shell/config tests (seed command, clock reconciliation, readiness after pool loss). The 16 unit tests, the other 11 shell/config tests and the 2 admin-socket tests always use SQLite or no database, so this run repeats them |
| CLI with `P02_TEST_BACKEND=postgres` | 5 passed. The CLI tests check dispatch to a stub controller and to a private socket and open no database, so this run adds no PostgreSQL coverage |
| P02-I07 PostgreSQL outage and reconnection (`--ignored`) | 1/1 |
| `npm run build`; `npm test` | Pass. SPS 80 passed with 101 default database-gated skips; agent-skill 22, dashboard 42 and gateway 8 passed; the browser-ui, i18n and OpenClaw node suites passed |
| OpenAPI generation and drift; route inventory and schema tests; type-checked generated types; stale-declaration probe | No drift; 10/10; 1/1; the injected stale declaration is rejected |
| Progress-gate unit tests | 8/8 |
| TypeScript SPS contract (`SUT=ts`) | 39/39 with no skips against the committed baseline, including CT14 |
| `SUT=base` contract | 19/19 |
| Rust contract, SQLite and PostgreSQL | 38/38 each with no skips; progress gate 18/18 required cases, CT14 excluded |
| P02-I08 injected CT01 mismatch, both stores | The suite fails with no skips and the gate reports "Unexpected failure for CT01" |
| P02-I03 failpoint crash/restart | Eight scenarios pass on each store |
| CC02 client flows | Pass on each store |
| CC02/CC03 browser: development page; packaged nginx image | 3/3 and 4/4 on each store, including delivered security headers |
| Landing; Redis integration; SPS PostgreSQL; SPS E2E; dashboard E2E | 7/7; 2/2; 179 passed with 2 Redis-gated skips across 18 executed files; 9/9; 31/31 |

## 2026-09-25 review

A code review of `86f3a59` confirmed 15 findings, and a test-by-test audit compared the suites with the vault acceptance plan. Fixes were written test-first: each new or changed test failed on the previous code, or on a mutant restoring it, and passes now.

### Behavior fixes

| Area | Change | Test evidence |
|---|---|---|
| External JWTs | Expiry has no leeway (jsonwebtoken defaulted to 60 s). `iss` and `aud` are required and pinned per provider, defaulting to `gateway` and `sps` as in SPS. A provider without a `jwks_file`, or with `jwks_url`, is refused at startup instead of being skipped | `bearer_and_fulfillment_tokens_are_rejected_once_exp_passes`; `external_providers_must_name_a_jwks_file`; CT03 just-expired, missing-issuer and missing-audience cases. A mutant making `iss`/`aud` optional fails CT03 |
| Startup policy | `BLINDPASS_SECRET_REGISTRY_JSON` and `BLINDPASS_EXCHANGE_POLICY_JSON` are validated like an administrator policy write; blank list entries are rejected; an unrecognized rule mode denies instead of allowing | `environment_policy_is_validated_like_an_administrator_write`; `an_unrecognized_rule_mode_fails_closed` |
| Workspace scope (P02-D11) | Exchange status, retrieve, revoke, approval read and decision, fulfill and submit refuse a token asserting another workspace, as the secret-request routes already did | CT11 colliding-subject case; without the check, status answers 200 to the foreign token |
| Fulfillment token | Header serialized as `{"alg","typ"}`, so tokens are byte-identical to SPS | CV03 fixture tokens in Rust and TypeScript |
| PostgreSQL transitions | Each of the eight expiring transitions locks its row first, so a deadline that passes during a lock wait is honored | Lock-wait store test |
| Metadata and CT19 | Metadata keeps answering after submission until the request deadline, as in SPS. A capability reissued after submission is clamped to the shorter submitted deadline instead of refused | `CT05.metadata.after-submit`; CT19 post-submit reissue |
| SQLite refresh rotation | Takes the writer lock first (`BEGIN IMMEDIATE`), so a replayed refresh token revokes the session family instead of failing with `SQLITE_BUSY` | `concurrent_refresh_replay_revokes_the_family_without_store_errors`; a deferred transaction fails it 3/3 |
| Sessions and passwords | Login creates a session only while the verified password hash is current. A password change applies only to the verified hash and from a live session, so an administrator reset in flight is not overwritten. PostgreSQL login and refresh lock the operator row before the session, in the order password change, reset and removal use | `sessions_and_password_changes_are_bound_to_the_verified_password`; `password_changes_revoke_sessions_created_or_rotated_concurrently`. Five mutants, including removing either PostgreSQL lock, fail 5/5 |
| Configuration | Removed the unused `BLINDPASS_TEST_RATE_LIMIT_WINDOW_MS` | `production_defaults_match_sps_and_test_overrides_are_bounded` |
| OpenAPI | Legacy route count 12, server `http://127.0.0.1:3200`, seed header `x-blindpass-seed-token`, capability expiry wording | Route inventory, server and seed-header tests |

### Test fact check

| Finding | Correction |
|---|---|
| CT18's 503 under `SUT=rust` came from an in-process TypeScript app and never exercised Rust | The Rust run moves the controller's clock mark an hour ahead and records the controller's own 503 through a reviewed projection; readiness returns 200 after the mark is restored |
| The acceptance audit said CV01–CV06 passed "in the Rust contract run", which executes only the TypeScript vectors. Rust had no CV03 or CV04 test and covered one of five CV05 rows | Controller unit tests now read the CV03–CV05 fixtures: both fulfillment tokens, 512 sampled confirmation codes, all five policy rows and three escaping hashes. CV01/CV02 were already pinned in `blindpass-core` and CV06 in `hpke_interop.rs` |
| The progress gate accepted reports in which a suite failed in a hook, at import or outside the CT cases | Such reports are rejected, and the gate's unit tests run in CI |
| The generated-type test was never type-checked | `test:openapi-types` runs `tsc` first |
| The OpenAPI legacy route count was hard-coded | The test derives it from the router and pins the nine mounted routes the schema does not document |
| The CC03 expired-link test depended on timing | It waits for the 410 metadata response |
| Concurrent store tests awaited each task before starting the next, on a single-thread runtime | Tasks start together on a multi-thread runtime. The refresh race asserts the real invariant: at most one rotation, no store errors and no live session left in the family |
| The PostgreSQL controller gate was reported as the whole suite passing per backend, but most shell/config, admin-socket, unit and CLI tests never read `P02_TEST_BACKEND` | The records name the 35 of 64 controller tests that run on PostgreSQL and list the SQLite-only cases under P02-I04–I07 |
| Several store tests checked only return values | They check persisted state: expiry, foreign-tenant isolation, approval expiry, idle sessions, the bootstrap race, reconciliation counts and the clock mark's advance interval and regression handling. Mutants setting the interval to 0 or `i64::MAX` fail |

## Coverage against the acceptance plan

| Plan item | Status |
|---|---|
| CT01–CT13, CT15–CT19 | 18/18 required cases pass on both stores; CT14 is excluded as hosted-user auth and passes in the TypeScript run. CT15 exercises only the per-IP token-mint limit; see the decisions below |
| CV01–CV06 | TypeScript side in `vectors.test.ts`; Rust side in `blindpass-core` and controller unit tests over the same fixtures |
| CC01–CC03 | CC01 runs in the contract suite; CC02 client and CC03 browser flows pass on both stores, including the packaged nginx page |
| P02-I01/I02 | Store races, expiry before sweep and after restart, lock-wait expiry, tenant isolation and session/password races pass on both stores. HTTP races cover first bootstrap, approve/reject and submit/revoke; other permutations rely on store tests |
| P02-I03 | Eight process-kill scenarios pass on both stores |
| P02-I04–I06 | Bootstrap race and replay, CSRF, refresh replay, forced password change, administrator reset and the full role matrix pass over HTTP on both stores. The admin-socket `bootstrap` and `reset-password` tests run on SQLite only; the contract adapter uses the socket's `bootstrap-token` command on both stores |
| P02-I07 | Key, database, schema-version, damaged-schema, seed/override, pool-loss, clock-regression and PostgreSQL outage/reconnection cases pass. Key and override cases validate configuration or use in-memory SQLite. Schema-version, clock-regression, seed and pool-loss cases run on both stores. The damaged-schema, inaccessible-database and `migrate` shell cases run on SQLite only |
| P02-I08 | Mismatch and drift probes reject on both stores locally; hosted CI has not run |
| P02-E01/E02 | Client flows and generated-type checks pass with no schema drift |
| P01 W0 | Accepted NARROW for the tested profile |
| Hosted clean-checkout CI | Not run; required before P02 acceptance |

## Design notes

**Clock (P02-D9).** Every expiry predicate and transition timestamp evaluates to NULL while the database clock is behind the persisted mark, so the controller fails closed and refuses to start until `blindpass admin reconcile-clock` runs. The mark advances only inside store calls, at most once per second; while `serve` runs, the 30-second retention sweep is also such a call. A regression is therefore detected only once the clock falls behind the last checkpoint. An idle running controller's mark lags by up to about 30 seconds, and across a restart it lags by the whole downtime; a step back smaller than the lag goes undetected and extends deadlines by the step. The previous record's one-second bound held only while requests arrived at least every second. `reconcile-clock` deletes secret requests, exchanges, pending and approved approvals, bootstrap tokens, rate windows and idempotency keys, revokes operator sessions, resets the mark and writes one `clock_reconciled` audit event. Operators, agents, policy, rejected approvals, lifecycle and audit history are kept.

**Rate limiting.** The controller limits agent token mints per client IP (default 5 per 60 seconds), matching self-hosted SPS. It has no per-agent request or exchange windows.

**Snapshots.** The committed TypeScript baseline stays authoritative. New cases are added from a TypeScript run, and the regenerated file must leave every existing record unchanged; this run added the two CT03 missing-claim records. Rust compares four reviewed projections (CT01 readiness, CT18 readiness 503, CT16 CORS and CT17 audit shape); every other case compares the full normalized response.

## Decisions

Recorded on 2026-09-24 and unchanged: W0 NARROW for the tested Ubuntu 24.04/systemd 255, no-TPM profile ([P01 evidence](../p01-host-broker-evidence.md)); P02-D7 plain HTTP behind a reverse proxy, after `axum-server@0.8.0` was blocked by dependency review; CT14 stays TypeScript-only; P02-D11 issuer-admin authority. The user chose not to push the branch, so hosted CI has not run.

Open for a decision:

1. **CT15 and P02-D12.** The recorded envelope names per-agent request/exchange rate windows, but neither self-hosted SPS nor the controller has them; SPS applies burst and daily quotas only in hosted mode. Amend the record to the per-IP token-mint limit, or implement per-agent windows.
2. **Approval authority.** As in SPS, the v2 agent route lets any tenant agent, including the requester, decide when a rule names no approvers. Unlike SPS, whose administrator route let any workspace operator decide, the v3 route decides only approvals whose `approverIds` name the operator's id or username, so an administrator cannot decide a rule without approvers. Because v2 matches the same `approverIds` against the token subject, an agent or external workload whose subject equals a listed operator name can decide without a session. Choose the intended rule before acceptance.
3. **Nine undocumented routes.** Agent revoke and key rotation, `GET /api/v2/audit/`, secret-request revoke and the v2 approval read/approve/reject routes are mounted and exercised by the contract suite but absent from the OpenAPI document. Document or remove them.
4. **Clock checkpoint.** Accept the lag above, or tighten it: a shorter checkpoint interval bounds the running case, while the restart case needs an external time reference.
5. **Security follow-ups.** Login throttling and Argon2 off the async workers; hashed session identifiers and CSRF secrets; audit events for secret requests and administrator changes; resetting the approval deadline at decision as SPS does; reporting store errors as 503 instead of 410/403; `prior_exchange_id` lineage for retrieved or expired exchanges.

## Limits

- Hosted clean-checkout CI is the last open P02.6 gate. The workflow runs the TypeScript baseline, both Rust backends, the store, shell and admin HTTP suites in each backend job, the PostgreSQL outage case, crash, client and browser flows, and the mismatch probe; none of it has run on GitHub Actions from this branch.
- Production reverse-proxy deployment is unverified and belongs to P06.1, with native and container recovery and database migration support.
- Agent JWTs and signed browser links use the controller host clock, not the database clock. A host clock step back extends them by the step, bounded by their short lifetimes.
- Test fixtures check agent IDs before writing, but concurrent fixture writers can race. Fixtures must use isolated test databases.
- The contract test files are transpiled without type checking; `tsc` reports existing type errors in `http-contract.test.ts` outside the cases changed here.
- Other review items remain open: revoked agent IDs cannot be re-enrolled; an admin-socket `accept()` error stops the controller; a kill during first-boot migration can leave an unusable database (124 of 300 SIGKILLs on SQLite); expired idempotency keys and rate windows are never swept; a trailing-slash CORS origin passes `check-config` but later breaks admin mutations; temporary passwords do not expire and admin-created operators are not forced to change theirs. In the tests, CLI runs hit `ETXTBSY` in 14 of 300 runs, the crash suite's 10-second admin session can expire under load, and the retention-grace test never checks inside the window.

## History

- The first local Rust run passed 18/19 cases with CT14 failing as a missing controller route. The route-identity review reclassified CT14 as hosted workspace-user auth; the user accepted the corrected 12-plus-2 route scope and P02-D11 on 2026-09-24.
- Integration commit `3c41289` consolidated planned slices 3–8, deviating from one commit per slice; the executable scope of that deviation was recorded at the time.
- A snapshot audit restored the P00 baseline byte-for-byte and introduced reviewed Rust projections; a unit test rejects Rust attempts to rewrite the baseline.
- Corrections along the way: the SQLite approval decision takes the writer lock before its idempotency read; startup removes a stale admin socket left by an abrupt exit; browser runs enforce the page CSP with the controller on port 3100; the packaged nginx gate was added; built-in TLS was blocked by dependency review (`axum-server@0.8.0`, deep score 12).
- The 2026-09-24 follow-up landed one commit per slice on top of `a396b40`:

| Commit | Change |
|---|---|
| `ab9a83e` | P02-D9 persisted database clock high-water mark (migration 0003) with per-statement regression guards; P02-I07 base-table verification before migration |
| `3030bde` | `blindpass migrate`, `blindpass admin seed --fixture <file>`, `blindpass admin reset-password <id>`; one shared HTTP/CLI fixture function; OpenAPI test-seed response corrected |
| `e6b498f` | Forced password change: a temporary-password session gets 403 `password_change_required` on every admin route except session read, refresh, logout and change-password |
| `76d1f56` | Schema version follows the migration files (now 3); per-version table verification and forward migration; fail-closed on damaged schemas; lock-free clock checkpoint |
| `31ff537` | `blindpass admin reconcile-clock` recovery for a detected clock regression |
| `847603b` | P02-I07 PostgreSQL outage and reconnection test; admin HTTP suite per backend in CI |
| `1bc142e` | P02-I06 admin/operator/viewer role matrix over HTTP |
| `0196f80` | OpenAPI description of the forced password change gate |

## Reproduce

Commands and prerequisites are in [test setup](../README.md). With the Compose services running and the CI dummy `SPS_*` secrets exported:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
P02_TEST_BACKEND=postgres P02_TEST_POSTGRES_URL=<disposable-url> cargo test -p blindpass-controller --locked
P02_TEST_POSTGRES_URL=<disposable-url> cargo test -p blindpass-controller --test postgres_outage --locked -- --ignored
npm run build && npm test
SUT=ts npm test --workspace=@blindpass/contract-tests
cargo build -p blindpass-controller --locked
SUT=rust CONTRACT_RUST_BACKEND=sqlite npm test --workspace=@blindpass/contract-tests -- --reporter=json --outputFile=<report>
node scripts/tests/assert-contract-progress.mjs <report> packages/contract-tests/fixtures/rust-pending.json
```
