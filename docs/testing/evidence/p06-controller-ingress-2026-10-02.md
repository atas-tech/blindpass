# P06 controller startup and HTTPS execution — 2026-10-02

P06 remains **in progress and unaccepted**. This slice is based on `a088313`
and continues the [release-layout evidence](p06-release-layout-2026-10-02.md).
The full nine-slice [phase plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired scenarios](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
remain authoritative. The pre-existing P03 evidence edit is excluded.

## Implemented and tested scope

Production `serve` opens only existing current-schema state; it does not create
or migrate a database or fill in missing controller/clock metadata. Explicit
`migrate` remains the initialization/upgrade entry point. Test fixture mode
retains its initialization behavior. Readiness preserves the accepted `ok` and
`checks.database` fields and adds a fixed failure reason, with structured
sanitized database-startup failures. No driver errors, database URLs, credential
paths or secret values enter those diagnostics.

Required proxy mode checks actual TCP peers against explicit IPs/canonical
IPv4/IPv6 CIDRs before API, UI or preflight processing. It validates exactly one
reviewed Host/forwarded-host, HTTPS protocol and client IP; alternative,
duplicated and appended headers are refused. Only local health/readiness probes
bypass it. Trusted client addresses determine rate-limit windows; untrusted
forwarding never changes that identity. Packaged proxy settings enable it;
legacy settings retain the explicit optional mode. HSTS is added.

The user separately approved the exact ring-only `tokio-rustls@0.26.6` addition
after Socket review in [decision 0008](../../product/decisions/0008-p06-controller-tls-dependency-review.md).
It adds one locked package, changes/removes no existing version and compiles no
AWS-LC provider. Built-in TLS validates bounded private certificate/key PEMs
before state/listener access and uses the existing rustls/ring implementation.
At most 64 parallel handshakes are admitted; each has a five-second timeout.
PEM read buffers are wiped on drop; rustls retains server key state in memory
until the TLS configuration is released at shutdown. Files remain plaintext
under private filesystem custody. No Source is consumed by the TLS tests, and
this is not encrypted recovery-backup custody.

## Test-first execution and results

| Gate | Actual result | Scope/evidence |
|---|---|---|
| P06-S01–S06 first red | 1 pass, 5 failures | Production accepted absent/empty/older state; fixed reasons were absent. [First run](p06-controller-ingress-2026-10-02/startup-red.txt) |
| P06-X01–X06 first red | 6 failures | CIDR/required-proxy handling absent. [First run](p06-controller-ingress-2026-10-02/proxy-red.txt) |
| P06-T01–T04 first red | Invalid-config refusal passed; valid TLS config failed | Built-in TLS was absent. [First run](p06-controller-ingress-2026-10-02/tls-red.txt) |
| Rust workspace | 656 passed, 4 default ignores | [Complete output](p06-controller-ingress-2026-10-02/rust-workspace.txt); three Quickshell application tests remain unrun; the ignored PG outage case was run separately below |
| PostgreSQL focused component/store gates | 74 passed | Layout 7, proxy 6, startup 10, shell 16, clock/store transitions 35; disposable role/database removed. [Output](p06-controller-ingress-2026-10-02/postgres.txt) |
| PostgreSQL forced disconnect/recovery | 1 passed | New login blocked and live test-role connections terminated; actual readiness 503, store refusal, reconnect and retained state verified. [Output](p06-controller-ingress-2026-10-02/postgres-outage.txt) |
| `npm run build` / `npm test` | Passed | [Output](p06-controller-ingress-2026-10-02/npm-workspace.txt); SPS has 80 passed/101 skipped, not a live SPS acceptance claim |
| Rust retained HTTP contract, SQLite | 40 passed | [Output](p06-controller-ingress-2026-10-02/contract-sqlite.txt); shared CT01/CT18 snapshots remain unchanged |
| Rust retained HTTP contract, PostgreSQL | 40 passed | [Output](p06-controller-ingress-2026-10-02/contract-postgres.txt); disposable database removed |
| Embedded browser E2E | 3 passed, 1 skipped | [Output](p06-controller-ingress-2026-10-02/embedded-e2e.txt); real Chromium deep links/CSP, asset/miss behavior and encrypted input one-use retrieval. Prior-binary rollback skipped without that artifact |
| Host and bookworm-built TLS runtime | T01–T04 passed | Verified certificate trust, distinct embedded console/input HTML and CSP/HSTS, peer rate limiting, plaintext rejection, stalled-peer isolation/saturation, shutdown. [Artifact output](p06-controller-ingress-2026-10-02/bookworm-tls.txt) |
| Pinned bookworm build and archive | Passed | [Build](p06-controller-ingress-2026-10-02/bookworm-build.txt) and [actual R01–R04 archive](p06-controller-ingress-2026-10-02/controller-archive.txt); final archive includes the ingress guide/proxy examples. Eight archive unit cases also pass |
| Final JSON startup output | 26 passed | [Startup/shell output](p06-controller-ingress-2026-10-02/structured-startup.txt); production failures are complete JSON lines, with no CLI text prefix |
| Clippy / fmt / diff / relative links | Passed | [Clippy](p06-controller-ingress-2026-10-02/clippy.txt); touched-document link checks also repaired a pre-existing relative broker-evidence link |

Measured handshake saturation recovery was 5.000 seconds on the debug binary
and 5.000 seconds on the final bookworm artifact (test bound <7 seconds, including
scheduling allowance). SIGTERM with a stalled handshake completed in 0.007 and
0.003 seconds respectively (bound <10 seconds). These measurements use local
disposable sockets/certificates; they are not VM or supported-profile evidence.

The first SQLite contract run hit EPIPE while transmitting CT18's oversized
body. A retry proceeded to an obsolete exact readiness-body assertion; the
PostgreSQL run reached the same assertion. That assertion now explicitly checks
the reviewed `recovery_required` extension; the unchanged semantic snapshots
and both final 40-case runs pass. The TLS test initially used `/input` rather
than the established signed-link root route; corrected tests require distinct
input/console HTML. The separately invoked PG outage test first failed during
schema setup because its CREATEROLE account lacked SET membership on the new
role. The harness now grants that exact disposable role before schema creation,
following PostgreSQL's [role grant semantics](https://www.postgresql.org/docs/18/sql-grant.html).
The abandoned generated role was removed, and the corrected test passes without
a superuser test login. One final archive invocation ran before its build export
finished and correctly refused the missing CLI binary; the completed export
was then checked. These first failures are not counted as acceptance.

## Remaining phase work

No full P06-I/E profile scenario is counted passed. Required Caddy/nginx examples
are included as candidates; neither edge is installed locally, so their parser,
real TLS forwarding and sanitized error-log behavior remain unverified. Native
Debian/Ubuntu installation and OCI/Compose lifecycle tests are next. Readiness
still needs actual durable migration, external ownership/recovery and intentional
fence states, rather than placeholder flags. Disk-full classification exists
but real capacity fault injection remains open. Consistent authenticated
encrypted backups, stale recovery against online/offline brokers, pre-upgrade
backup/locks/retention, both native↔Compose migrations, three-profile and remote
controller workflow matrices, numerical fault bounds and inherited phase gates
remain required. SQLite↔PostgreSQL conversion remains explicitly unsupported.
