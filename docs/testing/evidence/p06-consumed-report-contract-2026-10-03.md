# P06 consumed-report contract — 2026-10-03

CR01–CR05 pass for the dependency-free core recovery metadata contract.
Canonical signatures bind every record and recovery context field; strict
parsing rejects malformed, ambiguous, oversized and stale input. This is a
source contract component, not a broker journal export, live node-event
consumer, external ownership service, restore or authorization to activate
restored state. Generic consumed_report event admission remains closed.

## Executed contract scenarios

The paired vault testing plan defines CR01–CR05 before implementation. The
[first-red control](p06-consumed-report-contract-2026-10-03/first-red.txt) is an
expected compile failure for the missing recovery module, not evidence that a
previous live restore path admitted unsafe reports. After implementation, the
[final target run](p06-consumed-report-contract-2026-10-03/final-green.txt) passes
all five cases in 0.01 seconds using generated dummy metadata and deterministic
dummy Ed25519 seeds.

| ID | Actual result |
|---|---|
| CR01 | Exact typed/canonical round trip, existing node-event domain and complete outer envelope, authentic signature, all three outcomes and empty report |
| CR02 | Tenant, node/key version, issuer key, recovery ID/generation, challenge, event key, record mutation, wrong signing key and short signature refuse |
| CR03 | Missing/unknown/duplicate fields, malformed identifiers/challenge, unsafe numbers, bad records, duplicate/unsorted grants and excess input refuse; exact 128-record boundary round trips without truncation |
| CR04 | Observation below trusted minimum, zero/future epochs, records above observed epoch and a report replayed into a later recovery context refuse |
| CR05 | Reserved report bytes can be constructed for signature verification; generic live node-event admission still refuses consumed_report |

The body binds tenant, node and node key version; current controller issuer key
ID, recovery ID/generation and challenge; broker-observed issuer epoch; and
strictly sorted grant/operation IDs, their epochs and consumed/revoked/uncertain
outcomes. Integers stay within canonical JSON's safe range. Input and complete
signed event are bounded at 64 KiB; the record limit is 128. Too many records
refuse rather than silently truncating a journal. Unknown payload fields are
not admitted. Errors have fixed diagnostics and reflect no input.

The signing implementation shares the existing node-event encoder while its
public kind whitelist remains unchanged. Uncertain stays uncertain; a signed
consumed or revoked record does not establish provider/session cleanup. An
empty signed report does not remove quarantine. Expected context and the
verification key must come from current trusted authority/enrollment, never a
stale database snapshot alone.

## Tests that detect weakened checks

A private, dependency-free copy of the core/test is exercised before cleanup.
The [unmodified baseline](p06-consumed-report-contract-2026-10-03/control-baseline.txt)
passes five cases. Disabling only signature enforcement makes
[CR02 fail](p06-consumed-report-contract-2026-10-03/signature-control.txt), with
four cases still passing. Removing only the trusted minimum-epoch check makes
[CR04 fail](p06-consumed-report-contract-2026-10-03/epoch-control.txt), again with
four passing. Both controls terminate with exit 101. No mutation is applied to
the repository; the owned temporary tree is removed and zero scoped control
trees remain.

## Required checks and environment limits

The required [host Rust workspace](p06-consumed-report-contract-2026-10-03/rust-host.txt)
terminates with exit 0: 681 passes, zero failures and eight ignores across 70
targets, including all five CR cases and the three PGQ cases. The four SQLx
PostgreSQL snapshot cases remain ordinary ignores and have their earlier
separate [actual snapshot execution](p06-postgres-snapshot-2026-10-03.md).
Three Quickshell cases and one opt-in PostgreSQL outage case are not executed
by this workspace run; previous container evidence covers a separate actual
PostgreSQL outage. Source tests do not establish complete profile acceptance.

[All-target workspace Clippy](p06-consumed-report-contract-2026-10-03/clippy.txt)
passes with warnings denied; formatting and diff checks pass. Final validation
checks 260 relative links across changed repository docs and both paired plans,
with zero broken links. Twenty-one retained CR/PGQ logs contain no private-key,
credential-bearing PostgreSQL URL or bearer-header markers; all six final
CR/PGQ source hashes match their evidence records. This marker scan is scoped,
not a proof about arbitrary secret contents. The index is empty. Pinned Node
26.10.0 [build](p06-consumed-report-contract-2026-10-03/node26-build.txt) and
[host workspace tests](p06-consumed-report-contract-2026-10-03/node26-host.txt)
pass: MCP 108, helper 147; SPS 80 passes/101 service-gated skips in 17 files.
Node 24 and full inherited workflow acceptance are not inferred.

The first [sandbox Rust attempt](p06-consumed-report-contract-2026-10-03/rust-sandbox.txt)
fails socket cases and leaves helper waits. A
[scoped socket control](p06-consumed-report-contract-2026-10-03/socket-control.txt)
proves PermissionDenied / Operation not permitted. Only the two identified owned
failed-test processes are signalled; the job terminates with exit 143 before
the required host gate completes. This attempt is not a passing workspace gate.
The first [sandbox Node attempt](p06-consumed-report-contract-2026-10-03/node26-sandbox.txt)
fails with a native InternalCallbackScope assertion and MCP launch failures.
The host retry passes without an application change for this retry.
[Diagnostic metadata](p06-consumed-report-contract-2026-10-03/environment.txt)
records no accessible matching core, no extracted core, and an unsuccessful
kernel OOM query. The assertion is observed; its exact cause is not established.
A later memory snapshot is not crash-time evidence. No host configuration is
changed.

Run from the repository root with existing locked dependencies:

```bash
cargo test -p blindpass-core --test consumed_report --locked
```

The working tree remains dirty at base
`8a595ad18783634da59e046595942e729b56147b`; no slice-6 commit precedes incomplete
slice 5. Exact final source inputs:

| Source | SHA256 |
|---|---|
| `crates/blindpass-core/src/recovery.rs` | `894dbe16b0d7ea6441d2acca2e52062974778851be6551fb3158648a62084dbd` |
| `crates/blindpass-core/src/fleet.rs` | `09937bfa1ef3428337f2d4e70ae526e39b4aec41edd41b3ce86861876714ba3f` |
| `crates/blindpass-core/src/lib.rs` | `f73f1019115ae8b9c6e0e78af9bde46a3410e3918a9b09492215e9eacea8e64e` |
| `crates/blindpass-core/tests/consumed_report.rs` | `f04f6e40fed6a44b9e0d3b764f35e52f39acd773828d2228919ec0634691a388` |

## Plaintext lifetime and remaining acceptance

Report fields are recovery metadata in test/validator memory, not secret
payloads, live links or session bearers. Dummy signing seeds are consumed by
the existing in-memory Ed25519 key holder and dropped with it; no seed/key
file or host credential is created for the report tests. Ordinary test output
contains case outcomes; no raw broker journal or real secret is retained.

No replacement native archive or OCI image is built for this contract. Earlier
candidates keep their earlier source pins. No dependency manifest/lockfile or
package boundary changes, and no proposed PostgreSQL toolkit is installed or
invoked. The protected P03 evidence remains 66 additions/zero removals, unstaged.

Broker journal completeness/pagination and durable export; current enrolled-key
trust; fresh one-use challenge storage; protected non-restored HWM/ownership;
all-route fencing; transactional stale authority invalidation and provider
cleanup; offline-node quarantine; locked upgrades; interrupted native↔Compose
transfer; full PostgreSQL backup/isolated restore; and complete three-profile,
remote, browser, native and inherited acceptance remain open across all nine
slices. Cryptographic report verification cannot substitute for any of them.
P06 remains active and unaccepted.
