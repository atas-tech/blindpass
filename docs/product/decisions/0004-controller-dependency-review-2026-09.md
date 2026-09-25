# 0004: P02 controller dependency review, September 2026

**Status:** The user approved the proposed P02 Cargo dependency set on 2026-09-24 after reviewing the findings below. The accepted baseline is limited to the controller and CLI crates; shared core remains dependency-free. P02 behavior and cutover remain gated by the phase acceptance plan.

**Companions:** [P02 migration plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/02-controller-api-migration.md) · [P02 test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/02-controller-api-migration.md) · [Dependency baseline](0003-dependency-baseline-2026-09.md) · [Repository dependency policy](../../../AGENTS.md)

## Decision

Proceed with the proposed, maintained Rust dependency set for the P02 controller and CLI. The user reviewed the Socket findings and approved installing these packages on 2026-09-24. Keep the shared core dependency-free, pin the resolved graph in `Cargo.lock`, and retain the contract and phase gates for implementation and cutover. Do not replace HTTP, JSON, database, JWT, or password-hashing implementations with bespoke code to avoid the reported dependency alerts.

## Finding

Small helpers may use the standard library or existing OpenSSL boundary when that is the accepted implementation; protocol parsers and cryptographic algorithms must use maintained implementations. The approved crate set avoids creating a new security-sensitive parsing or cryptography surface.

The current checkout already links to OpenSSL through a narrow FFI for HPKE in `blindpass-core`. The development host also has SQLite, libpq, libargon2, libevent, json-c, and yyjson libraries and headers. Those are host observations, not proof they are installed on supported fleet images or hosted CI. The Rust CI job currently installs only `libsystemd-dev` and `libssl-dev`; it would need explicit package and runtime-linkage checks before any additional native library becomes a supported dependency.

## Socket review results

Socket CLI deep package scores collected for the P02 proposal:

| Crate and proposed version | Result | Decision under dependency-guard policy |
|---|---|---|
| `tokio@1.47.0` | Score 79; medium capability alerts | `block_pending_human_review` |
| `axum@0.8.4` | Score 79; medium capability alerts | `block_pending_human_review` |
| `tower-http@0.6.6` | Score 46; transitive `zstd-sys` score 46 and other alerts | `block` |
| `serde@1.0.229` | Score 79; proc-macro build/install and capability alerts | `block_pending_human_review` |
| `serde_json@1.0.151` | Score 79; medium alerts through transitive `object` | `block_pending_human_review` |
| `sqlx@0.8.6` | Score 12 | `block` |
| `tracing-subscriber@0.3.19` | Score 12 | `block` |
| `argon2` (unversioned lookup resolved to `0.6.0-rc.0`) | Shallow score 100; deep score 12 from `r-efi@5.2.0`, with medium install-script, native-code, network and shell alerts | `block` for this pre-release |

Earlier lookups for `jsonwebtoken`, `argon2`, `base64`, `rand`, `tracing`, and `clap` returned rate-limit errors. A 2026-09-24 retry for `argon2` succeeded but resolved to the pre-release `0.6.0-rc.0`; that version is blocked and its score does not establish the status of a stable version. The other five remain `block_pending_human_review`; a failed lookup is not a clean result. `rust-embed` is a P04.8 concern and should not enter P02.

## Replacement assessment

| Capability | Recommended path | Reason and conditions |
|---|---|---|
| CLI argument parsing (`clap`) | `std::env::args` | P02 needs a small fixed command surface. Validate flags and values directly; keep help/version output explicit. |
| Basic sanitized logging (`tracing`, subscriber) | A small `std::io::Write` logger | Emit fixed event names and non-secret fields. Do not serialize request bodies, credentials, tokens, or plaintext. Add structured spans only if the accepted deployment contract requires them. |
| Random bytes (`rand`) | Existing OpenSSL `RAND_bytes` FFI | Reuse the repository's existing `libcrypto` boundary; check return values and fail closed. Do not implement a PRNG. |
| Base64url (`base64`) | Reuse OpenSSL's base64 primitives behind a strict, tested wrapper | The wrapper must reject invalid alphabet, padding, lengths, and non-canonical encodings required by the token contract. Do not implement an ad hoc JWT decoder. |
| SQLite access (`sqlx`) | Small RAII FFI wrapper over stable SQLite C APIs | Feasible for the planned schema using prepared statements, bound parameters, explicit transactions, WAL setup, and finalization on every path. Requires a reviewed package/runtime baseline and CI plus fleet integration tests. |
| PostgreSQL access (`sqlx`) | Small RAII FFI wrapper over libpq | Feasible with parameterized `PQexecParams`, explicit transaction handling, result cleanup, connection error handling, and integration tests. Do not interpolate values into SQL. Requires libpq headers/libraries in CI and supported images. |
| HTTP server/runtime (`tokio`, `axum`, `tower-http`) | Do not handwrite an HTTP parser or a general async runtime | Review system `libevent`/`evhttp` as a maintained HTTP server option, or use a reviewed Rust HTTP implementation. A hand-built `std::net` request parser would increase risk around framing, limits, timeouts, and malformed requests. Basic CORS, request IDs, and response headers are small; that does not remove the parser/runtime requirement. `libevent` would become a Linux runtime and development-package dependency. |
| JSON types/parser (`serde`, `serde_json`) | Do not replace with a general handwritten JSON parser | Review system `json-c` or `yyjson` through a narrow FFI boundary, or use a reviewed Rust parser. P02 accepts externally supplied JSON, so parser depth, duplicate-key, number, Unicode, and size handling need a maintained parser. An exact schema codec is only viable if it rejects all unsupported forms and receives independent hostile-input review; it is not the default recommendation. The system-library path would require pinned minimum versions and runtime/development packages on supported images. |
| JWT verification (`jsonwebtoken`) | Do not add until Socket review; do not write a general JWT library | A narrow verifier could use existing OpenSSL primitives only after P02 fixes the exact accepted algorithms, issuer/audience rules, key rotation and failure behavior. Algorithm confusion and claim-validation mistakes are security boundary failures. |
| Bootstrap password hashing (`argon2`) | Use a reviewed Argon2id implementation; do not implement Argon2 | The host's current OpenSSL exposes Argon2 through EVP, but the documented API was added in OpenSSL 3.2. Do not assume that capability exists on every supported image. Otherwise use a reviewed `libargon2` system package or an explicitly approved crate. |

SQLite's official C API defines a prepared-statement lifecycle (prepare, bind, step, finalize); libpq provides parameterized command execution. That makes narrow storage wrappers plausible, but it does not make their FFI bindings automatically safe. OpenSSL documents that its Argon2 KDF first appeared in version 3.2, so the host's OpenSSL 3.6 result is insufficient evidence for the Ubuntu fleet target.

## Implementation path

1. Use the resolved Cargo baseline in the controller and CLI manifests; keep `blindpass-core` dependency-free as specified by P02-D2.
2. `Cargo.lock` pins the actual versions selected for this build. `LICENSES.md` records their direct licenses. The Socket results above cover the exact proposal versions shown in that table; versions selected by Cargo can be newer semver-compatible releases, and the `argon2` result is for a prerelease rather than the stable version selected below.
3. Use stable `argon2@0.5.3`; do not use the rescanned `0.6.0-rc.0`. The user approved the stable package choice even though the available Socket report did not score that exact stable version.
4. Keep the P02 port behind its HTTP contract gate. At the time of dependency approval, CT12, CT14 and CT15 still required separate scope review; later decisions are recorded below.

## Evidence and limits

- Socket source: CLI deep package-score checks for the versions above; unresolved names were rate-limited and are recorded as unreviewed, not passed.
- Socket follow-up on 2026-09-24: Socket resolved the unversioned Cargo `argon2` query to `argon2@0.6.0-rc.0`, shallow 100 and deep 12; the pre-release is blocked under the repository policy. One attempted `jsonwebtoken` request failed DNS before Socket returned a score; no other package received a score in this follow-up.
- User approval on 2026-09-24: proceed with the P02 Rust crate baseline despite the listed `block`/`block_pending_human_review` results and unscored packages. This is the required explicit human review for the proposed dependency set; no other packages were scanned at the user's request.
- User decision on 2026-09-24: adopt CT19 before freezing the controller OpenAPI contract. The two browser-status routes and their expiry, idempotency, response and scope rules are recorded in the [Controller Contract Suite](../../testing/Controller%20Contract%20Suite.md).
- Resolved controller dependencies: `argon2@0.5.3`, `axum@0.8.9`, `base64@0.22.1`, `jsonwebtoken@9.3.1`, `rand@0.8.8`, `serde@1.0.229`, `serde_json@1.0.151`, `sqlx@0.8.6`, `tokio@1.53.1`, `tower-http@0.6.11`, `tracing@0.1.44`, `tracing-subscriber@0.3.23`; CLI dependencies: `clap@4.6.7`, `serde@1.0.229`, and `serde_json@1.0.151`. Direct licenses are recorded in `LICENSES.md`.
- Initial dependency-slice checks: `cargo check --workspace` and `cargo fmt --all -- --check` passed with Rust 1.98.1. The locked dependency graph contains 255 packages.
- P02 slice 1 gates on 2026-09-24: `cargo build --workspace --locked` and `cargo clippy --workspace --all-targets --locked -- -D warnings` both passed with Rust 1.98.1.
- P02 OpenAPI tooling on 2026-09-24: the deep Socket request for `openapi-typescript@7.13.0` failed DNS (`api.socket.dev`). Auto-review rejected adding this unreviewed package. P02 therefore uses a small repository-owned Node generator over JSON-compatible YAML 1.2 syntax; no package or lockfile change was made for code generation.
- P02 OpenAPI contract on 2026-09-24: CT19 is adopted; `docs/api/controller.openapi.yaml` retains the 13 legacy machine routes and adds the two browser-status routes before the API schema is frozen.
- P02 scope correction after review of the route identities: `/api/v2/auth/refresh` is hosted workspace-user auth, while `/api/v3/admin/session/refresh` is local operator auth. The current Rust schema retains 12 machine routes plus the two CT19 routes; CT14 remains in the TypeScript SPS regression suite. The earlier 13-route count is preserved above as the original review record.
- P02 product acceptance on 2026-09-24: the user approved the corrected 14-route Rust scope and accepted CT12/P02-D11 authority for a configured external issuer's tenant-scoped `admin: true` claim. This does not grant local or fleet administration. The prior dependency-approval statement above remains a record of its earlier scope.
- Optional built-in TLS review on 2026-09-24: Socket CLI scored `axum-server@0.8.0` shallow 100 but deep 12 across 147 dependencies, with high transitive alerts including `rustls-webpki` and `openssl`. Dependency-guard classifies this addition as `block`; it was not added to the manifest or lockfile. The controller currently serves HTTP behind a reverse proxy. P02-D7's optional native TLS path remains unimplemented pending a separately reviewed dependency or an explicit scope correction.
- Host inspection on 2026-09-24: SQLite 3.53.4, libpq 18.6, OpenSSL 3.6.4, libargon2 20190702, libevent 2.1.13, json-c 0.19, and yyjson 0.12.0 were available through `pkg-config`; this is development-host evidence only.
- Ubuntu 24.04 package index inspection: development packages are available for `libevent` 2.1.12, `json-c` 0.17, SQLite 3.45.1, libpq 16.14, and libargon2 20190702. Their presence in the archive does not mean they are installed in the fleet base image; supported package versions and runtime linkage still need to be pinned and tested.
- CI inspection: [manual full Rust workflow](../../../.github/workflows/ci-full.yml) installs `libsystemd-dev` and `libssl-dev`, not SQLite, libpq, or libargon2 development packages.
- Build surface on 2026-09-25 (`cargo tree`): the controller links no system SQLite, libpq or libargon2. sqlx compiles a bundled SQLite through `libsqlite3-sys` 0.30.1 with its `bundled` feature, speaks the PostgreSQL protocol natively, and uses `rustls` 0.23 with `ring` 0.17 and `rustls-webpki` 0.103 for PostgreSQL TLS; `argon2` is pure Rust. `rustls-webpki` is therefore already in the graph that the `axum-server` review above blocked partly for its transitive alerts. `Cargo.lock` also carries `rsa` and `sqlx-mysql` entries from sqlx default features that the controller does not compile; removing them needs its own dependency-guard review. The host and Ubuntu package inspections above predate this and do not describe the controller's linkage.
- Primary API references: [SQLite prepared statements](https://www.sqlite.org/c3ref/stmt.html), [PostgreSQL parameterized execution](https://www.postgresql.org/docs/16/libpq-exec.html), and [OpenSSL Argon2 KDF](https://docs.openssl.org/3.6/man7/EVP_KDF-ARGON2/). Ubuntu package references: [libevent-dev](https://packages.ubuntu.com/noble/libevent-dev), [json-c-dev](https://packages.ubuntu.com/noble/libjson-c-dev), [libsqlite3-dev](https://packages.ubuntu.com/noble/libsqlite3-dev), [libpq-dev](https://packages.ubuntu.com/noble/libpq-dev), and [libargon2-dev](https://packages.ubuntu.com/noble/libargon2-dev).
