# P06 OCI and Compose candidate execution — 2026-10-02

**Scope:** Slice 4 on the working tree after `fa7fcb1`. Actual x86_64 OCI,
SQLite/PostgreSQL Compose and both shipped HTTPS edges; no P06 acceptance.
The [vault phase](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
retain all nine slices and the complete common-workflow/profile matrix.

## Implemented behavior and artifact

The multi-stage [Dockerfile](../../../deploy/controller/Dockerfile) builds on
pinned Node 26.10.0/Rust 1.98.1 bookworm bases. The pinned official bookworm-slim
runtime contains the controller/CLI, both embedded browser surfaces, libssl3,
CA certificates, project/font licenses and 294 npm/389 Cargo available upstream
notice files with path/hash inventories. It has UID/GID 10001, private 0700
keys/data roots and a bundled bounded loopback readiness probe. No Node,
browser, broker or Redis runtime is installed.

Both [Compose profiles](../../deploy/compose-quickstart.md) require explicit
key initialization and migration, existing private state, read-only root/keys,
writable data, private runtime tmpfs, dropped capabilities, no-new-privileges,
core dumps disabled and required trusted-peer HTTPS proxy mode. PostgreSQL 16
is pinned, unpublished and health-gated, with password and URL file inputs.
The guide states plaintext consumers and process/file lifetimes. No silently
regenerated keys, database, tenant or migrations are part of normal startup.
Locked upgrades remain slice 7 work.

The manual image workflow adds a versioned controller/SHA job, default disabled,
using existing Docker Actions; all three legacy image jobs are unchanged.
New SQLite/PostgreSQL Unraid XML templates preserve the legacy templates and
mirror the controller UID/mount/ingress/credential contract. XML/Compose parsing
is verified; no Unraid GUI/pool/lifecycle claim is made.

Tested local image config ID:
`sha256:e00a281d26001f0f0f0e3f29f104395bd1227561f2ac3c9c104ca041a62ac24a`.
The final named OCI export has runtime manifest
`sha256:87566e415fde2f1e750bec0429de9d98cf2f5c3ff970d8e3fdbf927129960395`,
index `sha256:04754d4556a274c71ebcc48e89e07e169bbae52b77c9a0fd1411a43bd6441dc4`
and archive SHA-256
`8fd98242bef48fee97263cf5349a62deb6c674ec0828201f3989f9eef470f147`.
These are local working-tree candidates; the revision label explicitly says
`fa7fcb1-working`, not an invented clean committed build.

## Actual scenario execution

| Gate | Evidence |
|---|---|
| H01/H02 | Three final subprocess/socket tests pass: healthy CT01 envelope without keys/config access; false/down/malformed/redirect/oversized/stalled responses; unavailable listener under one second with fixed diagnostic. Probe total transport deadline is two seconds |
| H03/T01–T04 | Real verified HTTPS/CSP/HSTS and distinct embedded surfaces; CA/name mismatch refuses; saturation drains in 5.002 s and SIGTERM in 0.006 s. No verification bypass |
| O01 | Actual image config/UID/layout, runtime tools/libraries/notices and all exported layers checked. Final build with generated dummy `.env` canary retains the identical tested runtime config; canary excluded |
| O02/O03 | Both actual profiles refuse uninitialized serve/repeated key init and missing/exposed/linked keys. Explicit init/migrate succeeds. Docker reports healthy in 5.350 s SQLite / 5.971 s PostgreSQL (<15 s) |
| O04 | Actual PID 1 UID/GID, zero effective capabilities, NoNewPrivileges, 0600 private socket; data/run writes succeed, root/keys writes fail |
| O05/O06/O08, X07 profile scope | Actual nginx 1.22.1 and Caddy 2.6.2 on each profile: trusted TLS; fixed authorities; forged forwarded headers overwritten; untrusted same-network peer denied; mismatched authority denied; stopped backend returns bounded 502/504; URI/header canaries absent from logs; controller recreation preserves key digest/tenant/epoch/schema and existing administrator |
| O07 | Actual PostgreSQL stop: controller liveness remains 200, bounded readiness fails; database recreation recovers readiness within 30 s and preserves identity/keys |
| O09 | Actual Compose JSON rendering and two XML templates pass. Exact UID, mounts, tmpfs, proxy configuration and password/URL-file semantics checked |
| O10 local | OCI descriptor hashes, in-toto image subjects, three attached SPDX documents and tested-runtime config binding pass. 1671 unique package names; every Cargo registry lock entry and every non-optional npm lock entry is present |

No real Source/provider/browser/native-backup workflow is consumed by these
profile checks. HTML/CSP success and persistent administrator creation do not
prove browser/operator session or complete common-workflow acceptance.

## First failures and fixes

The [first probe tests](p06-container-profiles-2026-10-02/health-first-red.txt)
fail because no health command exists. The
[real TLS regression](p06-container-profiles-2026-10-02/health-tls-first-red.txt)
then catches the probe expecting `database: ok` instead of CT01's `up`.
The fixture now uses a proper end-entity certificate rather than a CA certificate
as the TLS leaf; wrong trust/name still fail safely.

The [initial configuration gate](p06-container-profiles-2026-10-02/config-first-red.txt)
fails before the profiles/templates exist. Actual volume population verifies
private UID 10001 ownership without a root/chown startup adapter.

The first layer check correctly detects an encoded private-PEM pattern in
Debian's GnuTLS library. It is a public built-in self-test fixture, byte-identical
to the binary in the pinned official base. The gate binds that one exact binary
exception by digest; it still scans every layer and rejects added private PEMs.
Library marker constants alone are not classified as private credentials.

[Caddy's actual first failure](p06-container-profiles-2026-10-02/caddy-first-red.txt)
is a sanitized 403 `proxy_required`: Debian's Caddy 2.6 does not expand newer
`{args[0]}` import syntax. Literal authority headers plus strict SNI/Host checks
now pass on both profiles. The nginx backend fault may return 504 after its
five-second connect timeout, so the gate checks bounded 502/504 rather than
requiring an incorrect single status.

The user explicitly approved the pinned build-time scanner after the Socket
reports and exact inventory comparison in
[decision 0009](../../product/decisions/0009-p06-sbom-scanner-dependency-review.md).
The default Docker driver refuses attestations; a separately named disposable
Buildx container/cache was used, leaving host daemon/default-builder settings
unchanged. The [default scanner output](p06-container-profiles-2026-10-02/sbom-default-first-red.txt)
omits Cargo. The exact scanner's supported additive cataloger parameter adds
Cargo, installed npm and Debian discovery. The final verifier checks complete
locked graphs, not only a few sample package names. Build-stage inventories
also include public source/fixture/declared dependencies; they do not claim
that every listed package executes in the runtime. No new npm/Cargo dependency
or another scanner binary was substituted.

Executing the workflow's version-extraction command caught an empty result
because the controller inherits `version.workspace`. The corrected command
reads `workspace.package.version` from the root Cargo manifest and actually
returns 0.1.0. Scanner CSV/YAML parsing and byte-equivalent legacy job bodies
are checked; remote job execution remains unverified.

## Gates and retained limits

Node26 `npm run build` / `npm test` pass. SPS still skips 101 service-gated tests
across 17 files. Locked Rust workspace passes 661 cases with four inherited
ignores; after the test-only extension, the final probe target passes three
cases. Clippy/format, Python/shell/Node syntax, Compose/workflow YAML, local docs
links and diff whitespace checks pass. The three ignored Quickshell cases and
default PostgreSQL outage ignore were not invoked by that workspace run; this
slice separately executes the actual Compose PostgreSQL outage/recovery.
No Rust/Cargo/npm version changed.

[Sanitized execution logs](p06-container-profiles-2026-10-02/) preserve first
failures, final profile/TLS/probe/SBOM outputs, dependency reports and workspace
result summaries. Bootstrap/password/key values and private fixture contents
were never replayed. Scoped projects, volumes, networks, temporary credentials
and the Buildx builder/cache were removed; existing shared test services remain.

Still required: remote GHCR job/publication and aarch64 evidence; actual Unraid
GUI/pool lifecycle; authenticated complete backups and verified restores;
protected external ownership/high-watermark, stale restore reconciliation and
fencing; locked upgrades/pre-upgrade backups/restore-only rollback; interrupted
native↔Compose migration; disk-full/other profile faults; full native/Compose/
remote-controller browser/native-backup and inherited common-workflow gates.
Native PostgreSQL is not advertised by this bounded P06 profile proposal.
SQLite↔PostgreSQL conversion remains unsupported (P06-E05). P06 remains active.
