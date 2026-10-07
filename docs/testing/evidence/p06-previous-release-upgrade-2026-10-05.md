# P06 upgrade from a database created by a previous release — 2026-10-05

**Status:** one SQLite host-process test on the uncommitted tree above `8a595ad`. It replaces the "rewound schema" stand-in for one case with a database a real earlier binary created. It is not a packaged-release, VM, Compose or PostgreSQL upgrade, and not a multi-version chain. P06 acceptance remains false.

## What ran

`p06_up16_database_created_by_a_previous_release_upgrades` (`crates/blindpass-controller/tests/production_ownership.rs`, ignored; runs under the authority driver):

1. A controller binary built from `git worktree` at **`8a595ad`** (schema 16, before the packaged authority and locked-upgrade work) initializes an empty SQLite database with its own `migrate`. Its path comes from `P06_TEST_PREVIOUS_RELEASE_CONTROLLER`; nothing is vendored.
2. The test adds a canary operator row, registers a **fenced** authority record for the database's own tenant and issuer key, and creates a recovery key.
3. The current binary's `migrate` without backup arguments refuses and leaves the schema at 16. With `--pre-upgrade-backup-dir` and `--recovery-key-file` it takes one verified encrypted `-v16` backup, migrates to schema 19, reports `from_schema` 16 and `backup_taken: true`, and the canary row survives.

Without the variable the test prints `P06-UP16 SKIPPED` and returns, so a plain driver run counts it among the passed cases: look for that line in the log before treating a `production_ownership` result as covering this case.

Run:

```sh
git worktree add --detach /path/to/prev-src 8a595ad
(cd /path/to/prev-src && CARGO_TARGET_DIR=/path/to/prev-target cargo build -p blindpass-controller --locked --offline)
P06_TEST_PREVIOUS_RELEASE_CONTROLLER=/path/to/prev-target/debug/blindpass-controller \
  python3 tests/deployment/recovery-authority-postgres.py --test-target production_ownership \
  --controller-backend sqlite --filter p06_up16 --log /new/log
```

Result: 1 passed. **Mutation check:** pointing the variable at the current tree's binary fails the test (the current binary refuses to initialize without an authority record), so the test cannot pass without a genuinely older initializer. The test was written after the binary existed, not red first.

## Limits

- `8a595ad` is a source commit, not a published release: it was built as a debug binary on the host, not from a release archive or container.
- Only schema 16 to 19. Intermediate releases (17, 18) were not available as binaries; those schemas are covered only by the rewound-schema tests and the VM and Compose gates.
- SQLite only. A PostgreSQL store created by the older binary, the Compose and native VM upgrade paths, and a chain of more than one upgrade were not run with an older binary.
- The older binary ran without the packaged authority, so authority migration across releases is not exercised.
