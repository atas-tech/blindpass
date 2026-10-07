# P06 PostgreSQL exported snapshot — 2026-10-03

The existing SQLx stack now exports a guarded PostgreSQL snapshot. Four actual
PostgreSQL checks and the SQLite backend refusal pass. This prepares P06-B02/B09;
it does not create a custom dump, perform an isolated restore, or enable the
PostgreSQL backup command. The separately proposed
[toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md)
remains pending.

## Source behavior

`backup::begin_postgres_snapshot` opens a repeatable-read, read-only transaction.
It requires one effective controller schema, checks all required tables and
provisioning columns, and holds access-share table locks through the eventual
dump. These locks permit ordinary writes. Qualified table queries capture
tenant, schema version, snapshot issuer epoch, clock mark and every table count
from that transaction before exporting its identifier. The snapshot issuer epoch
is not an external recovery high-watermark.

Capture has a 60-second caller deadline. SQL statement/idle timeouts are 60 seconds
and lock timeout is five seconds. The identifier accessor refuses a guard aged
60 seconds; explicit close awaits rollback with a five-second deadline. Drop
queues SQLx rollback. The eventual dump still needs to honor the remaining guard
lifetime and keep the guard alive until it finishes. Configured timeouts do not
establish behavior under uninterruptible host I/O.

Database credentials remain in the private test-process environment and SQLx
runtime memory. They never enter command arguments or captured diagnostics.
PostgreSQL and SQLx consume source plaintext for the transaction; this preparation
creates no plaintext dump or encrypted archive. No dependencies, manifests,
lockfiles or runtime image packages changed.

## Executed scenarios

The paired vault testing plan defines P06-PGS01–PGS04 before implementation. An
unprivileged, generated disposable login and database on the existing PostgreSQL
16.15 test service isolate these runs. Each case uses a separate schema; the
wrapper removes its database and role afterward. Shared databases and services
remain running.

| Scenario | Actual result |
|---|---|
| PGS01 | Two initial committed rows are exported; another transaction adds a complete pair and changes tenant/epoch/clock. Imported metadata and every table count match the original snapshot; live queries see four rows. |
| PGS02 | Explicit close and drop both invalidate fresh imports; asynchronous drop rollback must complete within two seconds. |
| PGS03 | Zero issuer epoch, a missing provisioning column, and a dropped required table fail without repair. |
| PGS04 | Server reports read-only/repeatable-read and configured timeouts; an actual UPDATE fails with SQLSTATE 25006 and preserves epoch. Multiple effective schemas and SQLite are refused. An aged guard refuses its identifier. |

The [first-red output](p06-postgres-snapshot-2026-10-03/first-red.txt) reports the
missing API. Final [PostgreSQL integration](p06-postgres-snapshot-2026-10-03/postgres-integration.txt)
passes three cases and [transaction checks](p06-postgres-snapshot-2026-10-03/postgres-transaction.txt)
pass one. The [ordinary target](p06-postgres-snapshot-2026-10-03/default-integration.txt)
passes the SQLite refusal and explicitly ignores its three PostgreSQL cases.
The transaction case is also opt-in. All four opt-in cases were actually run.

From the repository root, with a disposable `P02_TEST_POSTGRES_URL` supplied
privately, run:

```bash
cargo test -p blindpass-controller --test backup_postgres_snapshot --locked -- --ignored --test-threads=1
cargo test -p blindpass-controller --lib postgres_snapshot --locked -- --ignored --test-threads=1
cargo test -p blindpass-controller --test backup_postgres_snapshot --locked
```

All-target [Clippy](p06-postgres-snapshot-2026-10-03/clippy.txt) passes with warnings
denied. Pinned Node26 [build](p06-postgres-snapshot-2026-10-03/node26-build.txt) and
[workspace tests](p06-postgres-snapshot-2026-10-03/node26-workspace.txt) pass:
108 MCP and 147 helper/channel cases; SPS 80 pass/101 service-gated skips across 17
skipped files. Node24 was not rerun.

The locked [Rust workspace](p06-postgres-snapshot-2026-10-03/workspace-rust.txt)
passes 673 cases with zero failures across 68 targets. Eight ordinary ignores
comprise these four separately executed PostgreSQL snapshot cases, three
Quickshell cases and one opt-in PostgreSQL outage case. The latter four remain
unexecuted by this workspace run; the earlier image record has separate actual
Compose outage evidence. Format and diff whitespace pass.

## Remaining scope

The earlier [exact attached-SBOM image record](p06-backup-sbom-container-faults-2026-10-03.md)
remains evidence for its recorded artifact, before this SQLx preparation. No
replacement native/OCI artifact was built in this step.

Full slice 5 remains uncommitted: matching custom dump, credential transport,
complete isolated PostgreSQL restore and artifact fault checks remain required.
Actual maximum-size and sudden-power-loss gates, protected external recovery
authority and ownership, stale-state fencing, locked upgrades, transfers and
complete three-profile/native/browser acceptance also remain open. Preserve all
nine slices. Verification never authorizes restored issuance.

Transaction semantics follow [PostgreSQL 16 SET TRANSACTION](https://www.postgresql.org/docs/16/sql-set-transaction.html)
and [snapshot synchronization](https://www.postgresql.org/docs/16/functions-admin.html#FUNCTIONS-SNAPSHOT-SYNCHRONIZATION).
