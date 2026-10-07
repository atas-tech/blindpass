# P06 PostgreSQL connection-option diagnostics — 2026-10-03

PGQ01–PGQ03 pass against the current source controller. Unknown or malformed
PostgreSQL URL query-option names now fail configuration before SQLx parsing,
network setup or state creation, with a fixed error that reflects no input.
Supported names, aliases and percent encoding remain accepted. This closes a
source diagnostic leak while the separate PostgreSQL backup toolkit review is
pending; it does not create a dump or perform an isolated restore.

## First-red control and fix

The locked SQLx 0.8.6 PostgreSQL parser logs unrecognized query names and values
in a warning. A protected URL file therefore did not prevent an unsupported
option from copying its contents into controller logs. The
[first-red run](p06-postgres-config-diagnostics-2026-10-03/first-red.txt) fails all
three new cases. Actual production startup in JSON mode records only the public
control `dummy_canary_logged=true` and `startup_timed_out=true`: the child logs
the generated option canary, then waits for a private dummy database endpoint.
The owned child is killed/reaped and fixtures are removed. Raw diagnostic bytes
and the URL remain in test memory; they are not retained in this output.

Configuration now validates only PostgreSQL query names before any SQLx parser
is invoked. It decodes URL-form percent escapes and `+`, ignores empty segments
and excludes fragments. It admits the existing SQLx TLS/connection options and
well-formed `options[setting]`; unknown names, malformed escapes or malformed
settings return `invalid configuration: BLINDPASS_DATABASE_URL options`.
It does not parse or print query values. SQLite configuration is unchanged.
The [configuration contract](../../architecture/README.md#controller-configuration)
documents the supported-option rule.

The paired vault plan defines PGQ01–PGQ03 before tests or production changes.
The [first green](p06-postgres-config-diagnostics-2026-10-03/first-green.txt)
passes all three cases. The
[final green](p06-postgres-config-diagnostics-2026-10-03/final-green.txt) repeats
them after tightening the fixture's parent directory to 0700 and assigning a
unique PGQ directory prefix. No scoped fixture directory remains after the run.

| Executed source case | Result |
|---|---|
| PGQ01 actual production startup, JSON and text modes | No password/option-name/value/URL canary in stdout or stderr; bounded static refusal; reserved listener has no connection |
| PGQ01 state and input | Protected input bytes unchanged; empty data directory; no admin socket; owned child reaped |
| PGQ02 accepted configuration | Supported TLS/connection names and aliases, encoded names, general/settings options and empty query segments accepted |
| PGQ02 refused configuration | Unknown/encoded unknown names, malformed escapes/settings, control-byte name and unsupported uppercase name refused without reflection |
| PGQ03 credential transport | Same denial through a production URL file and explicit test-mode inline URL; valid PostgreSQL and SQLite still validate |

All three final cases complete in 0.03 seconds. The loopback listener is a private
dummy fixture, not a PostgreSQL server; it accepts no connection in the green
startup check and retains no payload. Final fixtures use generated keys, a
0700 parent/data/key directory and a 0600 URL file. No host service, shared
database, dependency manifest or lockfile changes.

## Required checks and scope

The working tree is dirty at base `8a595ad18783634da59e046595942e729b56147b`.
Final configuration source SHA256 is
`67a3e8f1095bebfed9150ecbf945b021fe742acf81042af942f054f714581c8f`;
final PGQ test source SHA256 is
`f8f47d394cb0300e21fc5a600e9f112c4db5ca0053fdebdc3b0e8bef07ce90af`.

The fresh [locked Rust workspace](p06-postgres-config-diagnostics-2026-10-03/rust-workspace.txt)
passes 676 cases with zero failures across 69 targets, including PGQ01–PGQ03.
Eight ordinary ignores remain: four SQLx snapshot cases executed separately in
the [snapshot record](p06-postgres-snapshot-2026-10-03.md), three Quickshell cases
and one opt-in PostgreSQL outage case. The latter four are not executed by this
workspace run; earlier container evidence covers a separate actual PG outage.
[All-target Clippy](p06-postgres-config-diagnostics-2026-10-03/clippy.txt) and
[final target Clippy](p06-postgres-config-diagnostics-2026-10-03/target-clippy.txt)
pass with warnings denied. Formatting passes.

Pinned Node 26.10.0 [build](p06-postgres-config-diagnostics-2026-10-03/node26-build.txt)
and [workspace tests](p06-postgres-config-diagnostics-2026-10-03/node26-test.txt)
pass: MCP 108/helper 147; SPS 80 passes and 101 service-gated skips in 17 files.
Node 24 and inherited full workflow acceptance are not inferred. The final PGQ
target rerun covers the private fixture directory and scoped prefix after the full workspace
run; production code is unchanged between these green runs.

Run from the repository root with existing locked dependencies:

```bash
cargo test -p blindpass-controller --test postgres_config_diagnostics --locked -- --test-threads=1
```

The input URL and decoded option names consume controller validation memory;
the URL remains in configuration for the process lifetime. The protected fixture
file lasts only for its test, and captured child diagnostics remain in test
memory until discarded. The red control intentionally uses dummy canaries,
never real credentials. Normal deletion/drop is not a secure-erasure claim.

No replacement native archive or OCI image was built for this source fix. The
[previous native artifact checkpoint](p06-native-recovery-custody-2026-10-03.md)
remains pinned to its earlier working tree and does not claim this newer guard.
Include the fix in the next candidate and rerun its relevant profile gates.
Slice 5 remains uncommitted: separately approved matching custom dump/full
isolated PostgreSQL restore and artifact fault gates are still required.
Protected external HWM/ownership, stale restore/all-route fencing, locked
upgrades, interrupted transfer and full three-profile/remote/browser/native/
inherited acceptance remain required across all nine slices. P06 is not accepted.
