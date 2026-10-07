# Controller contract tests

This package is the black-box contract suite for the machine-facing API of the Rust controller. It uses `fetch`
against a TCP server, not an in-process `inject`, and runs against a controller it spawns itself (`SUT=rust`) or,
through a base URL, against one it did not start.

The TypeScript SPS that originally defined the contract is no longer part of the suite (its adapter, comparison tests and SPS-backed CT18 readiness case were removed). What it defined is kept as frozen data: the
HTTP snapshot `fixtures/snapshots/ts-baseline.json` and the CV fixtures. Their provenance and consumers are in
[fixtures/PROVENANCE.md](fixtures/PROVENANCE.md) and [fixtures/snapshots/PROVENANCE.md](fixtures/snapshots/PROVENANCE.md).
Never regenerate either after the SPS removal; a change needs a decision record.

The package declares no npm dependencies of its own. It reuses the workspace's Vitest, `tsx`, `pg`, `jose` and
`hpke-js` installations; the signing, fulfillment-token and policy oracles in `src/oracle` need only `node:crypto`. It
is a private test package and is not published.

## Oracles

`src/oracle` holds clean-room oracles for the signed link (CV01/CV02), the HS256 fulfillment token (CV03) and the
exchange-policy engine and decision hash (CV05). The fixtures in `fixtures/` pin them, and the Rust controller reads
the same files, so neither runtime is the only oracle for itself:

- `cv05-policy-matrix.json` holds 311 decisions the legacy engine produced for 32 seeded rule sets, frozen.
- `cv05-policy-decided.json` holds the shapes the legacy engine and the controller handled differently, with the
  controller's behaviour the owner chose on 2026-10-07 (an empty identity list matches every agent; blank reasons,
  padded reasons, rule ids and rule secret names). See [the policy guide](../../docs/guides/policy.md).

## Rust controller run

```bash
cargo build -p blindpass-controller --locked
SUT=rust CONTRACT_RUST_BACKEND=sqlite npm test --workspace=packages/contract-tests
SUT=rust CONTRACT_RUST_BACKEND=postgres CONTRACT_DATABASE_URL=... npm test --workspace=packages/contract-tests
```

The adapter starts the controller in test mode with an isolated SQLite file or PostgreSQL schema and seeds it through
the test seed route. The run compares the committed snapshot; reviewed semantic projections in `src/snapshots.ts`
cover the v3 administration outcomes where the controller intentionally differs from the legacy server (CT01
readiness, CT02 key rotation/revocation, CT13 approval decisions, CT16 CORS, CT17 audit, and CT18 readiness). A Rust
run can never rewrite the snapshot. `fixtures/required-cases.json` lists the required cases and the CT14 exclusion;
`scripts/tests/assert-contract-progress.mjs` checks a JSON report against it.

## Against a controller the suite does not own

```bash
node --import tsx scripts/tests/rust-base-contract.mjs
```

The launcher starts the controller exactly as `SUT=rust` does, writes the fixture and runs the suite with
`RUST_BASE_URL` and `CONTRACT_FIXTURE_FILE`, so the suite holds only an address. To aim it at another controller,
provide the same fixture file (administrator session, agent credentials and the external JWT key) with
`SUT=rust RUST_BASE_URL=... CONTRACT_FIXTURE_FILE=...`. Four cases need harness control of the server (CT15 request
and exchange limits, CT18 readiness failure, CT19 restart) and are excluded by name in the launcher; the spawned run
covers them. The base run compares only the snapshots it recorded (`CONTRACT_SNAPSHOT_SUBSET=1`).
