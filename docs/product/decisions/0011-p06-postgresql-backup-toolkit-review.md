# 0011 — P06 PostgreSQL backup toolkit review

**Status:** Approved by the project owner 2026-10-04 and implemented for backup
creation, isolated-restore verification ([backup record](../../testing/evidence/p06-postgres-backup-2026-10-04.md)),
full restore into an empty target database and the PostgreSQL upgrade
([restore record](../../testing/evidence/p06-postgres-restore-2026-10-05.md)).
The complete recovery workflow remains open. This does not accept P06.

The existing SQLx stack now has tested
[exported-snapshot guards](../../testing/evidence/p06-postgres-snapshot-2026-10-03.md).
That separate component preparation installs or invokes none of this proposed
toolkit and does not establish custom dump or isolated restore behavior.

P06-B02/B08/B09 require a PostgreSQL custom-format dump and a complete isolated
restore. SQLx can hold an exported snapshot and inspect its metadata, but cannot
produce the standard `pg_dump -Fc` archive or supply the server needed to verify
that archive. Listing archive members is insufficient. The native controller-store profile remains SQLite and gains no Docker or
PostgreSQL dump/server toolkit prerequisite on its controller host. Its separately
protected external authority remains required by [ADR0012](0012-p06-external-recovery-authority.md).

The proposed OCI runtime addition is the signed PostgreSQL Debian repository's
`postgresql-16` and `postgresql-client-16`, exactly `16.15-1.pgdg12+2`, with
`postgresql-common`/`postgresql-client-common` `293.pgdg12+1` and `libpq5`
`18.6-1.pgdg12+2`. Debian bookworm dependencies are resolved through APT and must
be inventoried and checked in the resulting release SBOM before committing.
The PostgreSQL repository public signing key must match fingerprint
`B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8`; unsigned repositories and downloads
are prohibited. Disable automatic cluster creation during the build. Package
maintainer scripts execute as root in the disposable build stage, never on the
operator's host. No new Cargo/npm dependency is proposed.

The immutable official reference image
`postgres:16.15-bookworm@sha256:efedf3595f1d6f415c08568ba171029bf54052e754cc9f030e3f2412b21f3d67`
was inspected with networking disabled, a read-only root filesystem, UID10001,
all capabilities dropped, no-new-privileges and no mounted credentials or host
socket. Its x86_64 platform digest is
`sha256:efdf07c2f9d4df592783dcc8ea5f6db02efbf5f6452b527225ff5e58364570e9`.
The [installed inventory](../../testing/evidence/p06-backup-components-2026-10-03/postgresql-toolkit-reference-packages.tsv)
contains 144 Debian packages, including the exact
PostgreSQL versions above, OpenSSL/libssl3 `3.0.20-1~deb12u2`, ICU72 and LLVM19.
This is reference inventory, not a claim that the eventual controller image
contains only these packages or that all packages are vulnerability-free.
Do not inherit the reference image's gosu, database entrypoint, database volume
or server startup behavior into the controller profile.

Socket publishes no full-health package review for these Debian/APT packages;
its C/C++ support is CVE-only. No Socket category score or supply-chain approval
is inferred from the Docker official-image designation. Missing full scores and
native code/package install hooks require **block_pending_human_review** under
the global dependency-guard policy. PostgreSQL's current security table includes
fixes in 16.15/18.6; this targeted upstream review does not audit every transitive
OS package or establish absence of vulnerabilities.

Expected capabilities are filesystem access, native code, database network I/O
during capture, and SQL execution during restore. Production credentials must
never enter arguments or diagnostic output. Verification uses a private local
cluster, no TCP listener, a private Unix socket and an unprivileged restore
database role. The temporary cluster is never an activated controller store.
The implementation must bound child lifetimes, suppress core dumps, reap
children and remove private plaintext staging after normal success/failure.
Interruption and disk-exhaustion tests remain mandatory; these are proposed
constraints, not executed evidence.

The final package graph, matching server/client major versions, complete
concurrent snapshot, isolated restore, damaged-dump denial, actual non-root
Compose operation and updated image SBOM must pass before the slice commit.
Changing the pinned toolkit or its scope requires another review.

Sources: [official image Dockerfile at the reviewed revision](https://github.com/docker-library/postgres/blob/9d15534160ade17f2b6c455a39ee967c49b1937d/16/bookworm/Dockerfile),
[PostgreSQL 16 pg_dump](https://www.postgresql.org/docs/16/app-pgdump.html),
[PostgreSQL security table](https://www.postgresql.org/support/security/),
[Socket ecosystem coverage](https://docs.socket.dev/docs/language-support).
