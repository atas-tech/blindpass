# P06 upgrade through a chain of previous releases — 2026-10-06

**Status:** host-process SQLite and PostgreSQL controller tests on the uncommitted tree above `8a595ad`. Extends [the single-release upgrade record](p06-previous-release-upgrade-2026-10-05.md). It is not a packaged-release, VM or Compose upgrade. P06 acceptance remains false.

## What ran

`p06_up17_database_walked_through_several_releases_upgrades` (`crates/blindpass-controller/tests/production_ownership.rs`, ignored, authority driver). The shared body is now `upgrade_from_release_chain`; `p06_up16` calls it with one binary.

1. `P06_TEST_RELEASE_CHAIN` names release binaries, oldest first. Built from source commits (debug, host): **`da79c15`** (schema 13) and **`8a595ad`** (schema 16). Nothing is vendored.
2. The oldest binary initializes the database (schema 13) and a canary operator row is added under it. Each later binary runs `migrate` and must advance the schema (13 to 16).
3. A fenced authority record and recovery key are registered, then the current binary refuses `migrate` without backup arguments, and with them takes one verified `-v16` backup and migrates to schema 19. Both the origin canary (created under schema 13) and the `-v16` backup survive.

Result: SQLite 6 passed, PostgreSQL controller 6 passed (the filter also runs `p06_up16` and the four other `p06_up` cases). Log lines `P06-UP17 release 0 left schema 13`, `release 1 left schema 16`.

**Mutation check:** the reversed chain (`8a595ad` then `da79c15`) fails the test at the first initializer step, so the test cannot pass without genuinely older initializers in ascending order. The chain test was written after the binaries existed, not red first.

Without the variable the test prints `P06-UP17 SKIPPED` and returns; check the log before treating a `production_ownership` pass as covering it.

## Gates

`cargo fmt --all -- --check` clean; `cargo clippy -p blindpass-controller --tests --locked --offline -- -D warnings` clean.

## Limits

- Two older source-commit builds, not published releases. Schemas 14, 15, 17 and 18 have no committed binary (17 and 18 exist only in the uncommitted tree), so they remain covered by the rewound-schema tests.
- Older binaries ran without the packaged authority, so authority migration across releases is not exercised.
- Host process only. Packaged archive, Compose and native VM upgrades from an older release are not run.
