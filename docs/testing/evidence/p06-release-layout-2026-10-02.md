# P06 release layout and implementation start — 2026-10-02

P06 remains **in progress and unaccepted**. This record covers slice 1 candidates
on the working tree based on `9aa2f7b`; it does not close the nine-slice
[phase plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
or [paired acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md).
Existing changes to the P03 execution record were present at the start and were
left outside this implementation slice.

## Verified starting state and implemented scope

The starting checkout had an embedded Rust controller, SQLite/PostgreSQL stores,
file-backed configuration, CT01 health/readiness and capabilities already carrying
package/schema versions. It had no P06 installer, controller image/Compose
profiles, tarball builder, encrypted backup/restore, external ownership/recovery
record, migration/upgrade automation or deployment acceptance harness. The vault's
2026-09-23 inventory is historical; capabilities version/schema is already implemented.

This slice adds explicit private key/data roots, `blindpass keys init|check`,
bounded descriptor-based credential reads, version inspection, controller build
metadata, pinned bookworm builds and versioned controller/node archives. The
[release-layout guide](../../deploy/release-layout.md) owns commands and limits.
No Cargo/npm dependency or lockfile changed. The dependency-guard skill was read;
standard library/current dependencies suffice. Official Node/Rust build-image
platform digests were verified and pinned; distro development libraries are
build prerequisites, with observed ABI checks rather than a Socket health claim.

Keys are raw private credential files, not encrypted backup material. Explicit
initialization holds random bytes briefly in CLI memory and wipes each buffer;
the controller holds keys in runtime memory until shutdown. No Source plaintext
is provisioned or backed up by these artifact tests. Missing or incomplete keys
are never silently replaced. Directory/key symlinks, hardlinks, exposed modes,
foreign ownership and unbounded/nonregular reads are refused. Incomplete
initialization needs explicit operator recovery. New data-root configuration
is an opt-in layout; full missing-state startup/recovery refusal belongs to the
next deployment slices and is not established by config validation.

## Test-first and fresh execution

First-red CLI execution had six failures because `keys` was absent; two negative
cases also passed through command rejection and did not establish key guards.
First-red layout execution had three failures (layout default/override/version)
and four negative checks; archive tests initially failed because the module did
not exist. Implementation followed these failures. Later node archive review
found unused npm launcher symlinks and missing executables for example units;
only the two exact reviewed launchers are omitted, and required probes are now
included. An initial runtime test incorrectly checked the full Chromium path;
the selected profile ships headless shell. The corrected test still requires an
actual packaged sandboxed launch and page interaction.

| Check | Result / authoritative output |
|---|---|
| `cargo test -p blindpass-cli --test keys --locked` | 8/8; P06-K01–K08, also included in the [full Rust output](p06-release-layout-2026-10-02/rust-workspace.txt) |
| `cargo test -p blindpass-controller --test deployment_layout --test shell_config --locked` | 7/7 layout/version and 16/16 inherited shell cases. Sandbox blocked three loopback tests; approved host rerun passed. Full Rust output contains the SQLite results |
| Same shell/layout command with `P02_TEST_BACKEND=postgres` | 7/7 + 16/16; fresh local disposable database/role, both removed. [PostgreSQL output](p06-release-layout-2026-10-02/postgres-shell.txt) |
| `python3 tests/deployment/release-artifacts-test.py` | 8/8: actual ELF inspection, architecture/ABI denial, bounded input rejection, inventory, no overwrite/partial publication and exact unused-launcher review |
| `python3 tests/deployment/release-archive.py --arch x86_64 --bin-dir <bookworm binaries>` | P06-R01–R04 actual controller archive/CLI/controller/UI startup passed; [output](p06-release-layout-2026-10-02/controller-archive.txt) |
| `python3 tests/deployment/release-node-archive.py` with selected x86_64 Node26/cache roots | P06-R05 actual archive/member/unit/license checks, helper/MCP resolution and packaged sandboxed Chromium launch passed; [output](p06-release-layout-2026-10-02/node-archive.txt) |
| Pinned bookworm Docker build | Passed; controller/CLI/node/broker also execute version/build inspection inside bookworm. UI embedded, schema 16, protocol `blindpass-broker/0.1`, version 0.1.0. [Build output](p06-release-layout-2026-10-02/bookworm-build.txt) |
| `npm run build` | Passed on Node26.10.0; same workspace build passed inside the pinned builder. Existing bundler/Browserslist warnings, no dependency updates |
| `npm test` | Approved host pass. 57 browser UI, 108 console, 108 MCP, 147 helper/channel; SPS 80 passed/101 skipped. [Workspace output](p06-release-layout-2026-10-02/npm-workspace.txt). Initial sandbox MCP socket failures are not behavior evidence |
| `cargo test --workspace --locked -- --test-threads=1` | 640 passed, 0 failed, four inherited ignores; [output](p06-release-layout-2026-10-02/rust-workspace.txt). Three Quickshell E2E ignores and one PostgreSQL outage ignore remain unexecuted |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed; [output](p06-release-layout-2026-10-02/clippy.txt) |
| `SUT=rust CONTRACT_RUST_BACKEND=sqlite npm test --workspace=@blindpass/contract-tests` | 40/40 retained HTTP contracts; [output](p06-release-layout-2026-10-02/contract-sqlite.txt) |
| `./tests/fleet/p01-vm.sh` | Actual pinned Ubuntu systemd VM passed 27 PASS records; guest sockets/units removed and overlay/QEMU/disposable key removed. [Output](p06-release-layout-2026-10-02/p01-vm.txt) |
| Formatting, Python/shell syntax, relative document links, `git diff --check` | Passed |

The P01 run used approved host read/write `/dev/kvm`, QEMU 11.1.1 and the pinned
Ubuntu image digest from [fleet setup](../../../tests/fleet/README.md), with a
fresh disposable key. It reports the selected native credential, HPKE, identity,
restart/expiry and canary cases. Its retained credential material was encrypted
inside the destroyed guest overlay. It used host-built P01 probe binaries and
is prerequisite evidence, not native-install acceptance of the bookworm archive.
No new Debian/systemd, physical-TPM or broader broker support claim follows.

Both final x86_64 archives were built and checksum inventories verified in local
disposable output storage. They were not published. Candidate manifests flag the
dirty source tree; this is not signed release provenance. Controller's maximum
required glibc symbol was 2.34, below the bookworm 2.36 ceiling. Every Rust/Node
ELF is checked for direct libraries, architecture and glibc/C++/OpenSSL/systemd
symbol limits; bundled browser ELFs receive their explicit library checks too.
The node bundle includes complete upstream licenses. P01 probe units/binaries
are disabled examples, never a production backup claim.

## Completion audit and remaining work

| Requirement | Current conclusion |
|---|---|
| P06.1 release/config foundations, D1/D2 | Implemented/tested candidates on x86_64; native aarch64 CI job defined but not executed remotely; host/architecture support remains unaccepted |
| P06.1 readiness/diagnostics/proxy trust, D3/D10 | Existing capabilities version/schema verified; new sanitized deployment states, proxy examples/direct ingress refusal and native/container listen/TLS contract still required |
| P06.2 native account/service/install/uninstall/timer | Missing. D01/D03/E14 and native P06-E01 must run in real systemd VMs |
| P06.3 OCI/Compose/Unraid/release workflows, D8/D9 | Missing. Controller image layers/UID/mounts, both database profiles and release SBOM/provenance still require execution; legacy assets retained |
| P06.4 complete authenticated backups, D5/I02 | Missing. Archive hashes here do not authenticate or encrypt backups; choose reviewed format and recovery-key handling, capture coherent keys/state on both stores |
| P06.4/5 recovery and source fencing, D4/D7/I03/I05 | Missing. External ownership/high-watermark, all transient/legacy authority invalidation, consumed reports, current/offline broker reconciliation and two-writer/interruption tests are required |
| P06.5 upgrades/rollback, D6/E03 | Missing migration locking, verified automatic pre-upgrade backups/retention, interrupted upgrade and restore-only rollback runbook |
| P06.5 both migration directions/E02/D06–D08 | Missing durable ownership transfer, interrupted/rollback tests, exact node/workflow verification and runbooks |
| P06.6 three profiles/remote controller, E01/E04/E15/D09–D11 | Unexecuted. Full two-host browser/native backup workflows, shutdown/disk/database/UI/suspend faults and all named bounds remain open |
| P06-E05 / D11 decision | SQLite/PostgreSQL conversion explicitly unsupported, never counted passed |
| Inherited P02/P03/P05 gates | Remain as stated in their evidence; component/archive/VM checks here do not close prior full workflow/cutover acceptance |

Continue with readiness/proxy/startup tests and implementation (slice 2), then
native and OCI packaging. P06 remains active until every phase/profile/migration
requirement and inherited release gate has authoritative execution evidence.
