# Provenance of `ts-baseline.json`

**Frozen.** This file is the recorded behaviour of the TypeScript SPS (`packages/sps-server`) for the HTTP
contract CT01–CT18 and CC01. Once SPS is removed (P08 slice 8) it is never regenerated; the suite no longer has a TypeScript adapter that could do it; a change needs a decision
record. A Rust run can never rewrite it (`src/snapshots.ts` refuses `UPDATE_CONTRACT_SNAPSHOTS` with `SUT=rust`
against this path). When a Rust response differs on purpose, the reviewed projections in `src/snapshots.ts` say so.
This record is P08-D2.

## What it is

116 sanitized records (72,881 bytes): normalized status, headers and bodies with identifiers, timestamps, signed
links and tokens replaced by placeholders. Canary values are never written.

## History (from git)

| Commit | Date | Change |
|---|---|---|
| `f41d291` | 2026-09-22 | Created with the P00 contract suite |
| `8ad0dbd`, `d5aadd9` | 2026-09-23 | Extended with the fleet/contract gate hardening |
| `645da97` | 2026-09-24 | CT18 readiness 503 and the live client baseline |
| `4dbb469` | 2026-09-25 | Last change: 43 added lines for CT03 (just-expired external token, missing issuer, missing audience) and CT05 (metadata after submit). The commit touches no SPS source |

The commits do not record the exact command or environment of each regeneration. The reproduction below is the
evidence instead of a recollection.

## Reproduction (2026-10-07)

SPS has changed since the last snapshot edit: `packages/sps-server` last changed in `9aa2f7b` on 2026-10-02. So the
current tree was used to regenerate the snapshot into a scratch path, and the result was compared with the
committed file.

```bash
# Disposable PostgreSQL 16 and Redis 7 (the repository compose services); the Redis database is flushed.
UPDATE_CONTRACT_SNAPSHOTS=1 SUT=ts \
  CONTRACT_SNAPSHOT_FILE=/path/outside/the/repository/regen-ts-baseline.json \
  CONTRACT_DATABASE_URL=postgresql://blindpass:localdev@127.0.0.1:5433/blindpass \
  CONTRACT_REDIS_URL=redis://127.0.0.1:6380 \
  SPS_HMAC_SECRET=ci-only-hmac-canary SPS_USER_JWT_SECRET=ci-only-user-jwt-canary SPS_AGENT_JWT_SECRET=ci-only-agent-jwt-canary \
  npm test --workspace=@blindpass/contract-tests
```

| Item | Value |
|---|---|
| Repository | `8a595ad` with `packages/sps-server` unchanged from that commit |
| Runtime | Node 26.10.0, Vitest 4.1.11, `postgres:16-alpine`, `redis:7-alpine` |
| Result | 39 of 39 tests passed |
| Comparison | **Semantically identical**: 116 records, the same key set, equal values after sorting keys. The byte order differs because records are written in test-execution order |

The harness that ran this command (its `SUT=ts` adapter) and the SPS source are in git history, in the last commit
before the removal. That section is the last word once they are gone: do not reproduce; investigate any mismatch
against this history.
