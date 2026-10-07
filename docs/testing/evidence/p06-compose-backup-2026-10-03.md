# P06 SQLite Compose backup and tool faults — 2026-10-03

**Status:** Selected CB01–CB04/B08, I02 and B06/B10 checks pass on an
uncommitted slice 5 candidate above `8a595ad`. PostgreSQL backup and complete
P06 acceptance remain open. Ordinary PostgreSQL serving is a separate check.

The current Dockerfile builds both embedded web surfaces and the co-located CLI
with the existing reviewed dependencies. Actual serving and backup containers
are bound to config ID
`sha256:1b6f4083a4755f67a96cb8b0060bd6f328b66c4deb9800f2c8d3ccb7d397aab2`.
Version is 0.1.0, schema 16. No npm/Cargo manifest, lockfile or proposed
PostgreSQL runtime-package change accompanies this follow-up. OpenSSL command
and library are 3.0.22; `openssl`/`libssl3` packages are `3.0.22-1~deb12u1`.
The [91-package runtime inventory](p06-compose-backup-2026-10-03/runtime-packages.tsv)
is public installed-package evidence, not an attached release SBOM. This new
candidate's hash is historical to this checkpoint; the later
[attested image/fault record](p06-backup-sbom-container-faults-2026-10-03.md) binds
the newly built image to its actual SBOM and container faults. The earlier
slice 4 SBOM does not bind either slice 5 candidate.

## Shipped Compose job

The optional [SQLite backup overlay](../../../deploy/controller/compose.backup-sqlite.yml)
defines only an opt-in backup service. It mounts dedicated UID10001 recovery
custody read-only, without automatic source-directory creation. The ordinary
controller has no recovery mount or key. The job has no network/ports, host
socket, host PID namespace, capabilities or core dumps. Its filesystem is
read-only except data and private runtime staging. Actual Docker inspection
checks UID10001, mount modes, no-new-privileges and the applied zero core limit.

| Scenario | Actual result |
|---|---|
| CB01 | Tests-first configuration fails while the overlay is absent; final three configuration tests pass. Missing recovery configuration refuses rendering; ordinary serving custody stays separate |
| CB02 / B08 | Explicit recovery generation; live SQLite capture, authenticated encrypted publication and full protected verification. Output directory 0700, archives 0600/UID10001; source payload/integrity/identity unchanged; no staging residue |
| CB03 | Wrong key reaches the actual fixed cryptographic failure; missing or mode-0644 recovery key reaches the unsafe-custody failure. No extra archive/residue. Controller logs contain no private key material |
| CB04 | Controller recreation retains identity and old archive verification. Repeated backup publishes a distinct complete archive and preserves controller keys; scoped teardown removes all test resources |
| I02 selected | A 100,000,000-byte fixture is captured and verified in 2.104 s; after recreation, 5.735 s. Both stay below the 30-second bound. Continuous actual console-page HTTP requests record 109/280 attempts with zero failures |

The request probe is the configured trusted bridge peer and sends the exact
forwarded HTTPS authority. It requests the embedded console while the separate
offline backup process runs. Actual nginx/Caddy HTTPS, certificate/header/peer
checks run separately on both SQLite and PostgreSQL with this image; PostgreSQL
outage preserves liveness, denies readiness and recovers without identity change.
These checks do not establish browser sessions, broker workflows or PostgreSQL
backup. An earlier 8-MiB rehearsal also passed; final numerical results above
bind the final driver and exact serving/backup image equality.

The job's timeout wrapper is configured for 15 minutes, TERM then KILL after
10 seconds. Individual tools remain bounded to 60 seconds. Small measured
fixtures do not establish the maximum archive size, full-job timeout under
stalled storage or uninterruptible-I/O bounds. Generation/job/OpenSSL processes
consume plaintext while running; private staging lasts through cleanup. The
protected host recovery file persists after container exit; operators need a
separately protected offline copy. Ordinary cleanup is not secure erasure.
See [operator commands and lifetime limits](../../deploy/compose-quickstart.md#explicit-sqlite-backup).

## Actual failure and large-fixture gates

The same bookworm controller binary used by the [native artifact](p06-native-backup-2026-10-03.md)
passes actual capture/encryption/decryption ENOSPC in private mapped-user/mount
namespaces. The 1/20/12-MiB tmpfs quotas exhaust the named phases. The test
observes `database.sqlite`, `encrypted.der` and `verified.tar` growth before
accepting their fixed failures. These host tool gates use patched OpenSSL
command/library 3.6.4, rather than the guest/container 3.0.22. Ordinary errors publish nothing, clean all
staging and preserve the original 8-MiB payload/integrity. No global host mount
is changed. This is a binary/tool gate, not a container disk-exhaustion test.

Separate SIGKILL tests observe over 1 MiB of actual encryption/decryption
output and the corresponding live OpenSSL child. After killing the controller,
the parent-death signal kills that child; a private test subreaper actually
reaps it. Only private 0700/0600 staging remains; explicit custody-locked cleanup
removes it. Controller keys, source database/identity and the original complete
encrypted archive remain intact. Between interruptions, a complete 192-MiB
fixture backup verifies in 2.524 s. This is below the archive limit and does not
establish 512-MiB behavior or a total-memory bound. Sudden power loss is untested.

## Evidence and limits

| Gate | Recorded output |
|---|---|
| Configuration first red / final green | [red](p06-compose-backup-2026-10-03/config-red.txt), [green](p06-compose-backup-2026-10-03/config-green.txt) |
| Earlier image refuses missing backup CLI | [refusal](p06-compose-backup-2026-10-03/old-image-refusal.txt) |
| Actual SQLite backup | [8 MiB](p06-compose-backup-2026-10-03/sqlite-backup-8mib.txt), [final 100 MB](p06-compose-backup-2026-10-03/sqlite-backup-100mb.txt) |
| Actual baseline image/profile regressions | [SQLite](p06-compose-backup-2026-10-03/sqlite-profile.txt), [PostgreSQL serving](p06-compose-backup-2026-10-03/postgres-serving-profile.txt) |
| Observed ENOSPC / SIGKILL | [ENOSPC](p06-compose-backup-2026-10-03/enospc-observed.txt), [SIGKILL and large fixture](p06-compose-backup-2026-10-03/crypto-interruption.txt) |

Python/shell syntax, local repository links, native preflight (seven passes),
Compose configuration (three passes) and diff whitespace pass. This Docker build
executes `npm run build` and locked release compilation. Prior complete source
gates are in the [component record](p06-backup-components-2026-10-03.md): 672 Rust
passes/four inherited ignores, final ten affected backup checks, Clippy/format
and Node26 workspace tests with 101 SPS skips. Rust/JS source is unchanged during
this follow-up; those broad suites were not repeated. Existing user P03 evidence
is untouched and un-staged. All disposable containers, volumes, private fixtures
and namespace mounts are removed. No keys or protected output are recorded.

PostgreSQL exported snapshot/custom dump/full isolated restore remains pending
the separate [toolkit review](../../product/decisions/0011-p06-postgresql-backup-toolkit-review.md).
Remaining power-loss/maximum-size checks,
external non-restored authority/ownership, stale restore/fencing, upgrades,
interrupted transfer, complete three-profile/remote workflows and inherited
acceptance are still required. Full slice 5 remains uncommitted; all nine slices
are retained. Archive verification never authorizes restored issuance.


The later [attested image/container-fault follow-up](p06-backup-sbom-container-faults-2026-10-03.md)
supersedes this checkpoint's unrun current-image SBOM and container ENOSPC
status. The exact attached-SBOM image passes final 100-MB backup/custody and all
three actual container ENOSPC phases plus both baseline HTTPS profiles. Eight
SB01–SB04 regressions strengthen artifact, named-inventory and runtime-package
binding. All other full-phase gates above remain required.
