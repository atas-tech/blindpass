# Controller contract tests

This package is the black-box TypeScript baseline for the machine-facing SPS
contract. It uses `fetch` against a TCP server, not Fastify `inject`, and can
target a locally spawned SPS process (`SUT=ts`), an already running server
(`SUT=base`) or a spawned Rust controller (`SUT=rust`).

The package intentionally declares no new npm dependencies. It reuses the
workspace's existing Vitest, `tsx`, PostgreSQL, Redis, `jose` and `hpke-js`
installations; it is a private test package and is not independently
published. This keeps P00 from introducing an unreviewed dependency or lockfile
resolution.

## Required TypeScript run

Start disposable services first, export the test database URL, then run:

```bash
SUT=ts npm test --workspace=packages/contract-tests
```

The adapter creates a unique PostgreSQL schema, selects a dedicated Redis
logical database, starts SPS over HTTP, provisions a test workspace and agents,
and cleans both stores on exit. Set `CONTRACT_REDIS_DB` explicitly when
parallel runs share a Redis instance. The selected Redis database is flushed
at the beginning and end of a run; use only a disposable test Redis.

To target an existing server, use `SUT=base CONTRACT_BASE_URL=...` and provide
the same seed configuration (`CONTRACT_SEED_TOKEN`) or a fixture file through
`CONTRACT_FIXTURE_FILE`. The committed base job uses a harness-spawned SPS
with the generated JWKS issuer/audience, CORS origin, hosted test mode, seeded
policy and secret registry, test TTL/rate overrides, and disposable PostgreSQL
and Redis stores. An arbitrary external server will not meet that profile.
The base server must enable the matching test-only seed route and must not be
a production deployment.

`UPDATE_CONTRACT_SNAPSHOTS=1` records sanitized HTTP snapshots under
`fixtures/snapshots/`. Snapshot files contain normalized identifiers,
timestamps, signed links and tokens only; canary values and credentials are
never written.

## Rust controller run

```bash
cargo build -p blindpass-controller --locked
SUT=rust CONTRACT_RUST_BACKEND=sqlite npm test --workspace=packages/contract-tests
SUT=rust CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=... npm test --workspace=packages/contract-tests
```

The adapter starts the controller in test mode with an isolated SQLite file or
PostgreSQL schema and seeds it through the test seed route. The run compares
the committed TypeScript snapshot; four reviewed projections in
`src/snapshots.ts` cover responses where Rust intentionally differs (CT01 and
CT18 readiness, CT16 CORS, CT17 audit). A Rust run can never rewrite the
TypeScript snapshot. `fixtures/rust-pending.json` lists the required cases and
the CT14 exclusion; `scripts/tests/assert-contract-progress.mjs` checks a JSON
report against it.
