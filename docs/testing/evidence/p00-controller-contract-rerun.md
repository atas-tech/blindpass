# P00 controller-contract prerequisite rerun

**Date:** 2026-09-23

**Base commit:** `2bd06ab8cbe78cfa921369d0c6ab9c9c844bdc3c`

**Scope:** TypeScript reference-server contract baseline, plus the CT18 readiness-failure case and snapshot and the CC01 live-client assertions added in the working tree.

## Environment

- Linux, Node.js 26.10.0, Vitest 4.1.11.
- PostgreSQL 16 and Redis 7 in the uniquely named `blindpass-p02-test` Compose project. Its disposable volume was removed after the run; the pre-existing `blindpass_pgdata` volume remained present.
- `SUT=ts`, isolated PostgreSQL schema, and namespaced Redis fixture state.
- The contract suite used the repository's local dummy test-service credentials. No test tokens or response bodies are included here.

## Result

`SUT=ts CONTRACT_DATABASE_URL=... CONTRACT_REDIS_URL=... npm test --workspace=@blindpass/contract-tests -- --reporter=json --outputFile=/tmp/p00-final-contract-results.json` passed 35/35 tests with zero failures and zero pending tests. `node scripts/tests/assert-no-vitest-skips.mjs /tmp/p00-final-contract-results.json` reported no skipped tests. A prior run with `UPDATE_CONTRACT_SNAPSHOTS=1` generated the CT18 baseline entry; inspection confirmed the final snapshot diff contains only that addition, and this final run passed against it without snapshot updates enabled.

The run included 19 HTTP cases (CT01–CT18 and CC01), six CV vectors, four adapter-isolation tests, two snapshot recorder tests including the intentional mismatch case, three normalization tests, and the explicit-SUT configuration check. The new CT18 case starts the reference app with failed database and Redis readiness checks, makes a real HTTP request to `/readyz`, asserts status 503 and the exact sanitized response, and records that response. CC01 now sends requests through the actual agent-skill and gateway clients and checks their mapped result shapes against the live SPS.

`npm run build` passed for the workspace. `npm test` passed; the default run reported 80 SPS tests passed and 101 skipped because the separate PostgreSQL/Redis integration gates were not enabled. Agent-skill, browser UI, dashboard, gateway, i18n, and OpenClaw plugin tests also passed.

`DATABASE_URL=... REDIS_URL=... node --import tsx scripts/tests/p00-base-contract.mjs` passed the harness-spawned `SUT=base` HTTP suite: 19/19 cases, including the CT18 readiness failure and CC01 typed client calls. Both contract runs used the uniquely named disposable project, which was removed afterward; `blindpass_pgdata` remained present.

## Remaining P00 review work

This passing run closes the automated CT18 503 snapshot and adds live CC01 client calls. It does not establish the remaining review items in the Obsidian phase plan:

- CT12 external-issuer revoke authority and CT14 refresh-token semantics still need approved controller contracts.
- CT15 currently exercises the token endpoint IP limit and reset only. P02 names local configurable quotas; the request/exchange limits and burst behavior/defaults need an explicit scope decision after hosted paid-tier behavior is excluded.
- P00-I06 was exercised locally: an intentionally mismatched CT18 snapshot made the contract job exit 1, and an unreachable PostgreSQL endpoint made adapter setup fail the job rather than pass. The HTTP suite had 19 pending cases after its setup failure. Hosted PR-CI failure injection and required-check evidence remain unverified.

Treat these as remaining coverage and review work, not as passing evidence from this run.

## P02 start-gate revalidation

**Date:** 2026-09-24

**Base commit:** `6d41a1f6df8d90d283b53b3c7241281937702ac2` plus the current P00/P02 working-tree changes

**Environment:** Linux, Node.js 26.10.0, Vitest 4.1.11, PostgreSQL 16 and Redis 7 from `docker-compose.test.yml`; isolated PostgreSQL schema and Redis database 15

**Result:** `SUT=ts CONTRACT_DATABASE_URL=... CONTRACT_REDIS_URL=... npm test --workspace=@blindpass/contract-tests -- --reporter=json --outputFile=/tmp/p02-ts-contract-results.json` passed 36/36 with zero failures or pending tests. `assert-no-vitest-skips.mjs` reported no skipped tests. Breakdown: 19 HTTP cases, six CV vectors, four adapter-isolation tests, two snapshot-recorder tests, three normalization tests, one generated OpenAPI type test, and one SUT-required test. No snapshots were updated during this run.

This revalidates the P02 start gate against the current working tree. It does not close the separate P00 CT12/CT14/CT15 product decisions or hosted PR-CI evidence.

The later P02 route-identity review reclassified CT14 as hosted workspace-user auth. It remains in the TypeScript SPS baseline and is explicitly excluded from the Rust controller's 12-route machine contract. The corrected-tree TypeScript contract run passed CT14; see the [P02 rerun evidence](p02-controller-api-migration-rerun.md). The historical review status above is preserved as recorded at the earlier run.

On 2026-09-24 the user accepted the corrected 12-plus-2 Rust route scope and CT12/P02-D11 configured-issuer admin authority. The earlier open-decision statements above record the state at the time of those runs; CT15 and hosted PR-CI evidence remain open.
