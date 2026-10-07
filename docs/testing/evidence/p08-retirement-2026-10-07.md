# P08 execution record — 2026-10-07

**Scope.** Review of the [P08 plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/08-pilot-and-retirement.md)
and its [acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/08-pilot-and-retirement.md)
against the working tree, plus the retirement work that needs no pilot decision. **The pilot has not started and no
P08 scenario is passed.** Everything here is local, on the uncommitted tree at `8a595ad`, and nothing is pushed.

**Updated later the same day:** the owner answered the open decisions and then confirmed the deletion; see
[Owner decisions and follow-up](#owner-decisions-and-follow-up-same-day) and
[Removal](#removal-owner-confirmed-same-day). Where they differ from the sections above them, they supersede them: the
legacy code **is now deleted from the working tree** (uncommitted), the dependency manifests and lockfile **were
changed** (reviewed under the dependency guard, below), and the policy contract, accepted dispositions, Rust base
launcher and `required-cases.json` replace what the earlier sections describe.

## What this is not

- P08.1–P08.3 (recruit, observe, decide) cannot run: P07 is not published and has no go decision, the node package has no
  documented path to a first workload ([node status](../../deploy/node-candidate.md)), and none of the owner decisions
  in [the recruitment protocol](../../release/recruitment.md) is accepted. P08-E01, E02 and E03 are **not run**.
- P08.5 (removal) is gated by the pilot decision, the retirement gate and accepted dispositions. P08-I02, E04 and E05 are
  **not run**. The legacy archive (slice 7) was not built.
- Nothing here establishes that live SPS installations or backups do not exist. The plan says to check with the owner and
  not to infer none. That question is open (P08-I01).

## Plan facts that did not match the tree

| Plan statement (2026-09-23) | On 2026-10-07 |
|---|---|
| CI jobs `contract` (ts) and `base-contract` are in `ci.yml` | They are in `ci-full.yml`, which is `workflow_dispatch` only, together with `contract-rust`, the SPS PostgreSQL steps and the dashboard Playwright run. `ci.yml` (push and pull request) has neither, so no automatic gate runs the contract suite |
| "When the old dashboard was already removed after P04/D4, record that fact" | Not removed. `packages/dashboard` is present (85 files, 12 Playwright specs) and the manual CI still runs its E2E against SPS. P04 only relocated the CC02/CC03 runner and marked it removable |
| Five Unraid templates | Seven in `deploy/unraid`; two (`blindpass-controller-sqlite.xml`, `-postgres.xml`) belong to the controller |
| Consumers: dashboard, gateway, openclaw bridge, agent-skill, 17 migrations, `.env.example`, compose, Unraid, image workflow, `p00-base-contract.mjs`, `LICENSES.md`, openapi | Also: `scripts/e2e-human.mjs` (the CC02 runner statically imported `packages/sps-server/dist`), `packages/agent-skill/tests/exchange-runtime.test.ts` (builds an in-process SPS app), `packages/browser-ui/Dockerfile` (its `npm ci` stage copies the dashboard and sps-server manifests), the root `Makefile` and `package.json` scripts, 13 SPS demo, development and integration scripts, `scripts/tests/assert-pg-vitest-gate.mjs`, `docker-compose*.yml` Redis, 53 `SPS_` occurrences in `.env.example`, and the `ts-baseline` generator itself |
| "`rust-pending.json` must be empty and is deleted" in slice 5 | `pendingIds` is empty, but the file also holds `requiredIds` and the CT14 exclusion that `assert-contract-progress.mjs` reads. It can go only with the TS adapter |
| Verification: `native-install.sh --from-release "$REMOVAL_TAG"` | The script has no such flag (`--os`, `--archive`, `--rollback` …) |
| Verification: `rollback-legacy.sh --archive docs/legacy/sps-release/` | The script does not exist; it is a slice 9 deliverable |
| Verification: contract suite with `packages/sps-server` absent | Works only once the SPS parity test is deleted with SPS; until then run with `--exclude tests/ts-oracle-parity.test.ts` (done below) |
| "Slice 6: gateway and OpenClaw suites pointed at Rust in CC02" | Already done by P02 (`scripts/tests/p02-rust-client-flows.mjs`). The agent runtime exchange (`AgentSecretRuntime`) was not covered against Rust; it is now |
| Snapshot "loses its generator" | Reproduced from the current SPS tree: semantically identical (below) |

## Slice 4 — retirement inventory (P08-I01, partial)

`scripts/retirement/inventory.sh` (a wrapper over `inventory.mjs`, no dependencies) scans every tracked or untracked,
non-ignored file for the plan's patterns plus `sps-ref`, and lists every file inside the two legacy packages and the five
legacy templates by path, so SQL and binary assets cannot be missed. Decisions are the 82 ordered rules in
`scripts/retirement/dispositions.tsv`; the generator only reads that file. Output:
[retirement-inventory.md](../../release/retirement-inventory.md), 461 files with hits.

- `--check` fails on an undispositioned file, a stale or shadowed rule, **retained code that imports deleted code**, and
  invalid rule syntax. `--check --accepted` additionally fails while any rule is `proposed` or a `relocate` file still
  imports deleted code. This is the pre-deletion gate. Today `--check` passes; `--check --accepted` fails on 82 proposed
  rules and exactly two unfinished relocations (`scripts/e2e-human.mjs`'s legacy in-process mode and
  `packages/agent-skill/tests/exchange-runtime.test.ts`).
- Tests (`scripts/tests/retirement-inventory.test.mjs`): 11 pass, written before the generator. They cover determinism,
  pattern counts (`redistribution` is not Redis), exclusion of ignored, binary, own-output and deleted-in-tree files,
  rule validation, stale rules and the import guard. The default `npm test` runs them; `npm run test:retirement` also
  compares the committed inventory with a fresh run.
- **All 82 rules are `proposed`.** No reviewer has accepted a disposition, so the inventory is not a retirement decision.

## Slice 5 — contract harness independence (partial)

- **Oracles.** `packages/contract-tests/src/oracle` replaces the five direct SPS imports with clean-room code: link
  signing, a hand-built HS256 fulfillment token (`node:crypto` only) and the policy engine and hash. The CV fixtures stay
  the pins. `tests/vectors.test.ts` and `http-contract.test.ts` no longer import SPS; `tests/sps-independence.test.ts`
  fails if anything but the two comparison files does, or if `ts-sut.ts` is imported statically.
- **Parity while SPS exists.** `tests/ts-oracle-parity.test.ts`: byte-identical tokens for both kinds, 23 accept/reject
  token variants under two root secrets, about 1,400 link-verification cases and 8,000 generated policy cases (the test
  asserts more than 1,000 reach a rule, spread across allow, deny, pending and same-ring), all equal to the legacy
  implementation. Three deliberate mutations of the oracle
  (list semantics, token key order, expiry boundary) were each caught, then reverted.
- **Frozen matrix.** `fixtures/cv05-policy-matrix.json` (32 rule sets, 311 cases, 183 decisions) is minted by the
  legacy engine and read by the TypeScript oracle and the Rust controller (`exchanges.rs`). The Rust engine reproduces
  all 311, including hashes. Before this, only five policy cases were frozen, so SPS removal would have lost the
  empty-list, ring and workspace edge cases.
- **Snapshot provenance** (P08-D2): [snapshots/PROVENANCE.md](../../../packages/contract-tests/fixtures/snapshots/PROVENANCE.md).
  A fresh `SUT=ts` regeneration into a scratch path is semantically identical to the committed `ts-baseline.json`
  (116 records, same keys and values; only record order differs). The file was last changed by a Rust-side commit
  (`4dbb469`) and no generating command was recorded at the time. [fixtures/PROVENANCE.md](../../../packages/contract-tests/fixtures/PROVENANCE.md)
  maps each CV fixture to its TypeScript and Rust consumers.
- **Not done:** the Rust candidate launcher that replaces `p00-base-contract.mjs` (P08-D7). By reading the code, the
  existing `SUT=rust RUST_BASE_URL` path cannot pass CT18 (`BaseUrlAdapter` has no `withReadinessFailure`) or the two
  rate-limit cases (they start a second server with a limit of 2). It needs a readiness control and a second limited
  instance. The TS adapter, `SUT=base` job, `rust-pending.json` and the snapshot's SPS launcher stay until retirement
  approval.

## Findings for the owner

1. **Policy engines disagree on an empty identity list.** The Rust controller treats `requesterIds: []` or
   `fulfillerIds: []` as "any agent", and its validator accepts `[]` (it rejects blank entries, with a code comment
   that a blank entry could leave an empty list, "which matches every agent"). The legacy engine matched no agent.
   An allow-rule whose requester list was emptied therefore becomes open to every requester under Rust. The docs do not
   say which is intended. Recorded in `admin_policy.rs` and `exchanges.rs` tests (current behaviour, so a change is
   deliberate); the oracle refuses the shape. **Decision needed.**
2. **Smaller policy differences:** a blank `reason` falls back to the generated text and a padded one is trimmed in Rust (SPS
   kept both), so the decision hash differs for such rules; Rust trims rule ids and rule secret names, SPS compared
   verbatim; Rust denies an unrecognised or padded rule mode where SPS allowed it (intentional, documented in
   `docs/architecture/README.md`). The mode case is the legacy defect that retirement removes.
3. **Legacy-only defects, confirmed by running the SPS functions** (they leave with SPS): its link verifier throws a
   `RangeError` on a signature that has the right character count but more bytes (`timingSafeEqual` on unequal buffers),
   and its fulfillment-token verifier has no algorithm allow-list, so an HS512 token signed with the right key is
   accepted. The oracle returns "invalid" for the first and accepts only HS256.
4. **No automatic contract gate.** Every contract job, including `contract-rust`, is in the manual workflow. "Rust
   contract jobs green without SPS present" can be checked locally (below) but nothing runs it on push.

## Verification run (local, 2026-10-07)

| Check | Result |
|---|---|
| `SUT=rust` contract suite, SQLite and PostgreSQL, before the harness change | 40/40 and 40/40 |
| Same, after the change | 54/54 and 54/54; progress gate 20/20; no skipped tests |
| `SUT=ts`, before and after | 39/39 and 53/53 |
| `SUT=base` (`p00-base-contract.mjs`) | 19/19 before and after |
| Contract suite against Rust **with `packages/sps-server` renamed away** (parity test excluded) | 45/45 on SQLite |
| CC02 client flows against Rust, SQLite and PostgreSQL, with the new agent-runtime exchange | Pass on both; also passes with SPS absent |
| Retained client suites with SPS absent | agent-skill (minus the SPS-backed test) 22/22, gateway 9/9, openclaw-plugin exit 0 |
| `tsc --noEmit` for the contract package | Clean |
| New Rust tests (matrix, recorded divergences, validator) | 3 pass; `cargo fmt --check` clean |

Full gates, run once after the last change on the same tree (2026-10-07, host busy with other sessions' processes):

| Gate | Result |
|---|---|
| `npm run build` | Exit 0 |
| `npm test` | Exit 0. agent-skill 23, console 113, dashboard 42, gateway 9, SPS 80 passed with **101 skipped in 17 files** (the legacy suites that need PostgreSQL or Redis), root node suites 128 passed, **2 skipped** (opt-in P07 tests `BLINDPASS_PACKAGE_INSTALL_TEST` and `BLINDPASS_TEST_DOCKER_LOAD`). No failures |
| `npm run test:exposure` | Exit 0 (26, 11 and 7 tests in the three Python suites, plus the core-limit and log-scan checks) |
| `npm run test:retirement` | Exit 0: 11 tests, `--check` ok (461 files, 82 rules), committed inventory equals a fresh run |
| `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -D warnings` | Both exit 0 |
| `cargo test --workspace --locked --no-fail-fast` | Exit 0: **837 passed, 0 failed, 151 ignored** across 95 test binaries. The 151 ignored tests are gated on disposable PostgreSQL authority databases, a restricted runtime role, the owned deployment driver or the pinned PostgreSQL toolkit image (P06 backup, restore and authority suites); they were **not** executed here, so this run is not evidence for them |

The SPS-absent run renamed `packages/sps-server` for the duration and restored it by trap; the directory is identical
afterwards (no diff).

## Not run

The Playwright CC02/CC03 spec (needs Chromium and the browser-UI dev server) with SPS absent; a hosted CI run of any
workflow; the dashboard E2E; the SPS suites (unchanged); a live-installation or backup inventory; P08-E01–E05.

## Owner decisions and follow-up (same day)

**Decisions (product owner, 2026-10-07).**

1. An empty `requesterIds` or `fulfillerIds` list matches **every agent** (current Rust behaviour). I applied the same
   rule to the other differences (blank reason falls back to the generated text, padded reason, rule id and rule secret
   name are trimmed), because the Rust engine is now the contract; the owner has not ruled on those separately.
2. There are no live SPS installations or backups, so no transition period (P08-D5) applies, and the old code can be
   cleaned up.
3. The recommended values are accepted: 12 approval prompts per operator per active day, the roadmap baseline as the
   success measures, no incentives, and the evidence store described in [the protocol](../../release/recruitment.md).
4. All 82 dispositions are accepted. Unraid stays a supported controller path and the old versions need no care; x402
   is not needed for now.
5. The node first-workload operator path is the open prerequisite for recruitment (scoped in the session report; no
   document was written).

**Done after the decisions.**

- Policy: `fixtures/cv05-policy-decided.json` (7 rule sets, 11 cases, hashes computed with `hashPolicyDecision`) is replayed
  by the Rust controller (`cv05_decided_policy_semantics_match_the_oracle_fixture`) and by the TypeScript oracle, which
  no longer refuses these shapes. Documented in [the policy guide](../../guides/policy.md).
- Contract harness: the TypeScript adapter, Redis and SPS seeding, `ts-sut.ts`, the SPS parity test and the SPS import guard
  are removed; `http-contract.test.ts` has only the Rust path, and CT18's readiness failure is its own case
  (`CT18.error.503`). `scripts/tests/rust-base-contract.mjs` replaces `p00-base-contract.mjs` (P08-D7);
  `rust-pending.json` is now `required-cases.json`. The CV05 matrix generator was an untracked file that is gone with
  the parity test, so the frozen matrix is its own record ([provenance](../../../packages/contract-tests/fixtures/PROVENANCE.md)).
- `scripts/e2e-human.mjs` no longer has an in-process SPS mode; CC02 is unchanged.
- Dispositions: 79 rules, all `accepted`; `inventory.sh --check --accepted` passes and the committed inventory was
  regenerated.
- Docs: [controller on Unraid](../../deploy/unraid.md) (not run on an Unraid host), the recruitment values, the testing
  README rows for the contract commands.

**Verification after the decisions (local, uncommitted tree).**

| Check | Result |
|---|---|
| Spawned `SUT=rust` contract suite, SQLite and PostgreSQL | 43/43 and 43/43; progress gate 21/21; no skips |
| `scripts/tests/rust-base-contract.mjs`, SQLite and PostgreSQL | 20 passed, 4 excluded by name (CT15 limits, CT18 readiness, CT19), exit 0 |
| CC02 client flows against Rust (SQLite) | Pass, including the agent runtime exchange |
| `cargo test -p blindpass-controller --lib` policy tests, `cargo fmt --check`, `cargo clippy -D warnings` | Pass |
| `npm run build`, `npm test`, `npm run test:retirement`, `inventory.sh --check --accepted` | Exit 0 (SPS suites still 101 skipped) |

**Not done at that point** (superseded: the deletion, dependency decision and x402 removal were done afterwards, see
[Removal](#removal-owner-confirmed-same-day)). The permission classifier blocked the first bulk deletion on 2026-10-07 and
it was not retried in pieces; it ran only after the owner confirmed it explicitly.

## Removal (owner-confirmed, same day)

**Confirmations (product owner, 2026-10-07):** (A) delete the legacy code; (B) adding `pg` and `@types/pg` back to the
manifest is approved if needed; (C) x402 and viem can be removed. Nothing is committed or pushed. The only restore point
is git: the deletions are working-tree changes against `8a595ad`, so the parent of the removal commit is the rollback
point once the owner commits. No rollback script exists (slice 9 deliverable, not written).

**Deleted.** `packages/sps-server`, `packages/dashboard`, 13 legacy SPS demo, development and integration scripts,
`scripts/tests/assert-pg-vitest-gate.mjs`, `scripts/tests/legacy-images-workflow.test.mjs`,
`.github/workflows/build-and-push-images.yml`, five legacy Unraid templates (the two controller templates stay),
`packages/agent-skill/tests/exchange-runtime.test.ts`, `packages/agent-skill/src/x402.ts` with its test,
`packages/mcp-server/licenses/x402-Apache-LICENSE` and `docs/architecture/dashboard-maintainability.md`. Three
files that were created earlier the same day and never committed (`ts-sut.ts`, the SPS parity test and the SPS import
guard) went with it and are not in git; the parity test was also the CV05 matrix generator, so the matrix and decided
fixture are now the only record of those decisions
([provenance](../../../packages/contract-tests/fixtures/PROVENANCE.md)) and `ts-baseline.json` can no longer be
regenerated from SPS. Legacy documents were moved under `docs/legacy/`
with banners (quickstart, self-hosting, Unraid, manual demos, `openapi.yaml`); the dashboard and SPS wording in the
README, SECURITY, API, architecture, security, release and testing docs and in `landing/dist/llms.txt` was rewritten to
the controller. Subagents drafted part of that rewording; I spot-checked it and the link check passes, but I did not
read every changed sentence.

**x402 and viem (P08-D6).** `x402` and `viem` are removed from `packages/agent-skill/package.json`; a 402 response from
the controller is now an ordinary error in `sps-client.ts` (test updated). The MCP/OpenClaw bundle went from 19 to 10
components (only `zod` 4 and its own packages remain), and `THIRD_PARTY_NOTICES.md`, `docs/release/sbom/mcp-bundle.cdx.json`
(all MIT) and the bundle tests were regenerated or adapted.

**Dependency guard record (B).**

- *Why:* retained code (the contract adapter, the console E2E support and the CC02 scripts) imports `pg`, which only the
  two deleted workspaces declared. An undeclared import would only work through hoisting.
- *Alternative:* none that keeps PostgreSQL contract coverage; the harness reads and writes controller tables directly
  (clock anchors, schema isolation), so it needs a PostgreSQL client. I did not evaluate other client libraries.
- *Socket:* `pg@8.20.0` deep score 69–72, medium alert (`networkAccess`; native `libpq` is an optional peer);
  `@types/pg@8.18.0` has a `floatingDependency` alert. The decision matrix classes both `block_pending_human_review`.
  Not installed new: both versions were already in the lockfile and already used. The owner approved (B), which is the
  required human decision.
- *Result:* root `devDependencies` `pg ^8.20.0` and `@types/pg ^8.18.0`. `package-lock.json` differs from the previous
  lock by **removals only** (113, then 17 after x402/viem): no addition and no version change. `npm ci` in a clean copy
  succeeds, and `npm run build` and `npm test` pass there; that copy is not a clean checkout of a commit (the tree is
  uncommitted), so P08-I02 is satisfied only locally and must be repeated from the removal commit.
- *SBOM:* `docs/release/sbom/npm-workspaces.cdx.json` regenerated, 309 to 185 components.

**Contract harness flake found and fixed.** The final gate run failed `CT18 preserves route-specific error bodies…` once
per backend with `TypeError: fetch failed`. Cause: the 1 MiB `CT18.error.413` request streamed its whole body to a
controller that rejects an over-limit `Content-Length` immediately and closes the connection, so the client sometimes
saw EPIPE (2 of 60 on SQLite, 0 of 60 on PostgreSQL in a probe; load average was 15–20 from other sessions). It is not
PostgreSQL-specific and the request is in `HEAD`, so it predates this work; I first misread it as PostgreSQL-only
because an isolated `-t CT18` run cannot pass at all (CT18 reads results recorded by earlier cases). The check now
declares the oversized length and sends no body (`httpRejectedBeforeBody` in `packages/contract-tests/src/http.ts`),
which makes the controller's rejection deterministic and keeps the recorded 413 snapshot unchanged.

**Second flake found and fixed (Rust).** The first full `cargo test` run (host load average above 90 from other
processes) failed `admin_seed_dispatches_fixture_to_colocated_controller_binary` with `Text file busy` (ETXTBSY). The
tests in `crates/blindpass-cli/tests/migrate.rs` copy or write an executable and run it; a child forked by a concurrent
test holds the write descriptor until it execs. Four of the tests held the `EXEC` lock, but five others that spawn the
CLI did not. The three spawn sites (two tests and the shared `admin_against_fixture` helper) now take it too. The file
is part of the earlier uncommitted P07 work, not of the removal. After the fix the binary passed 40 of 40 consecutive
runs and the full workspace passed. A race cannot be proved gone by a pass count, so treat the lock as the cause, not the
loop.

**Verification on the final tree (local, uncommitted).**

| Check | Result |
|---|---|
| Spawned `SUT=rust` contract suite after the flake fix, 4 runs per backend | 43/43 every run, SQLite and PostgreSQL; progress gate 21/21; no skipped tests |
| `scripts/tests/rust-base-contract.mjs`, SQLite and PostgreSQL | 20 passed, 4 excluded by name, exit 0 |
| CC02 client flows against Rust, SQLite and PostgreSQL | Pass on both |
| Playwright CC02/CC03 with no SPS in the tree | 3 passed (SQLite) |
| `npm run build`, `npm run test:exposure`, `npm run test:retirement` | Exit 0; inventory `ok: 240 files with hits, 47 rules`; `--check --accepted` passes (the inventory was regenerated after this record's own edit, since this file is scanned) |
| `npm test` | Exit 0 with no failures: contract-tests package 18, console 113, gateway 9, agent-skill and node suites passing; root node suites 123 passed, **2 skipped** (the opt-in P07 tests `BLINDPASS_PACKAGE_INSTALL_TEST` and `BLINDPASS_TEST_DOCKER_LOAD`). No SPS or dashboard suites remain, so the earlier "101 skipped" legacy suites are gone |
| `cargo fmt --check`, `clippy --workspace --all-targets --locked -D warnings` | Both exit 0 (rerun for `blindpass-cli` after the test-lock fix below) |
| `cargo test --workspace --locked --no-fail-fast` | **838 passed, 0 failed, 151 ignored**, exit 0, on the second run. The first run failed one test (flake below). The 151 ignored tests need disposable PostgreSQL authority databases, a restricted runtime role, the owned deployment driver or the pinned toolkit image; they were **not** executed, so this is not evidence for them |

**Not done / limits.**

- Nothing is committed, tagged or pushed; hosted CI has not run on any of this. Every contract job is still in the
  manual `ci-full.yml`.
- P08-E01–E05 are not run. The pilot has not started: P07 is unpublished, the node package still has no documented first
  workload path, and the owner actions listed in P07 are open. P08-I02 is local only (above). E04 (removal rehearsal)
  and E05 are not run, there is no `rollback-legacy.sh`, and slice 7's legacy archive is not built, so the retained
  history is git only.
- The node first-workload operator path (decision 5) is scoped but not written.
- `landing/dist/script.js` still has two "SPS coordinates" strings, and some dead i18n strings remain: the file is
  hash-pinned, so editing it needs the landing hash regenerated. Not done.
- `docs/legacy/*` and the Unraid page were not run on a real Unraid host.
