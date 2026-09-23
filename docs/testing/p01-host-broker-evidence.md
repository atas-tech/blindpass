# P01 execution record

**Recorded:** 2026-09-23

This is the repository-side execution record for the P01 plan in the docs
vault. It does not replace the required W0 review; disposable VM artifacts
remain runner-local and are not committed.

## Portable checks

| Check | Result | Evidence |
|---|---|---|
| `cargo fmt --all -- --check` | Pass | Pinned workspace formatting gate |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass | Rust 1.98.1 toolchain; no third-party Cargo dependencies |
| `cargo test --workspace --locked` | Pass outside the development sandbox | Broker socket-mode/path-boundary tests, bounded frame tests, identity/delivery/custody units, and the Rust ↔ `hpke-js` vector |
| HPKE suite | Pass | DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305; exact `enc` and ciphertext match the generated `hpke-js` fixture |
| Socket dependency scan | Partial / access-limited | Outside the sandbox, Socket reached `api.socket.dev` and discovered 20 files in read-only mode. Creating the full report returned HTTP 403 because the logged-in `SocketDemo` token lacks `full-scans:create`. No dependency was added on that basis. |

The sandbox denied Unix socket operations with `EPERM`; the transport tests
were therefore rerun outside it. No test fixture contains a live credential.

The exact non-alerting commands were:

```text
socket scan create --cwd . --read-only --no-set-as-alerts-page --markdown .
# API reachable; 20 files discovered; [ReadOnly] Bailing now

socket scan create --cwd . --no-set-as-alerts-page --report --markdown .
# HTTP 403: required scope full-scans:create
```

This is evidence that the scan can reach the Socket service outside the
sandbox, not a completed full-scan result. A token with the required scope is
still needed for the full repository report.

## Implemented portable boundary

- The root broker has separate loader and workload Unix sockets. The loader
  requires UID 0, `SO_PEERPIDFD`, systemd unit lookup, invocation lookup, an
  exact claimed-unit match, and a fixed unit-to-credential mapping.
- The workload path rejects UID 0 and requires a registered non-root account,
  node, workload, unit, and current invocation tuple.
- Credential bytes are held in wipe-on-drop buffers, delivered once per
  connection, and bounded by policy. The sample consumer rejects missing,
  empty, partial, malformed, and oversized files.
- Custody is ephemeral and one-use. No persistent encrypted custody profile is
  claimed before the unlock/recovery and TPM review.
- Native unit files define root ownership, socket modes, systemd hardening, a
  registered workload probe, and a separate `LoadCredentialEncrypted=`
  comparison baseline. The guest harness provisions an explicit systemd
  host-key profile and exercises initial delivery plus controlled rotation. A
  disposable backup/restore probe consumes credentials through the same loader
  path and persists only a checksum; it is a test fixture, not a production
  backup implementation. TPM protection is not claimed.

## VM and W0 status

The live disposable run completed on 2026-09-23 using the explicitly named
`local-kvm-p01-loader-final2` runner owner. Host evidence was QEMU 11.1.1, `qemu-img` 11.1.1,
read/write `/dev/kvm`, and `cloud-localds`; the pinned Ubuntu cloud image had
SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
Guest evidence was Ubuntu 24.04, kernel 6.8.0-139-generic, systemd 255 as
PID 1. The guest recorded directory `0751` root-owned, loader socket `0600`
root-owned, and workload socket `0660` with the dedicated workload group.
The guest measured stalled-loader rejection at about 2.05 seconds, exercised
the broker empty/partial/malformed/oversized/corrupt delivery matrix, ran the
two-round root-loader and three-round workload pidfd-to-invocation restart
races, a real user-manager denial, and a `DynamicUser` profile, stopped QEMU,
removed the broker units/binaries and sockets, and retained only text evidence
on the host; the guest disk overlay and seed media were removed. Separate
failure-injection and cancellation runs passed the bounded teardown checks and
also removed QEMU and guest disk artifacts. The protected dummy material
remained root-owned mode `0600`. No live credential was used.

| Scenario | Current evidence | Acceptance status |
|---|---|---|
| P01-I01 | Guest restarted the root consumer and re-resolved its invocation; it rejected a stale workload invocation, exercised two root-loader restart races and three workload restart races, and re-registered each replacement before delivery | VM pass for exercised restart paths; broader fault-injection matrix remains open |
| P01-I02 | Root loader delivery, non-root and real user-manager socket access, forged loader routing, registered fixed-account and `DynamicUser` workloads, and an unregistered workload were exercised; user-manager/shared-UID execution remains denied/out of scope | VM pass for supported system-unit profile and explicit user-manager denial |
| P01-I03 | Guest hid the system bus socket inside the broker service namespace; an otherwise authorized native consumer failed closed and produced no credential file | VM pass for exercised API-removal profile; kernel API-removal matrix remains open |
| P01-I04 | Guest measured a stalled root-system-unit loader denial at about 2.05 seconds, rejected malformed consumer material, and injected empty, partial, malformed, oversized and corrupt broker responses against the real native consumer | VM pass for exercised cases; additional transport/fault profiles remain open |
| P01-I05 | Ephemeral one-use custody, expiry, wrong-key/tamper/AAD rejection, process-restart absent-key behavior, and Rust ↔ `hpke-js` ciphertext parity pass | VM pass for the selected ephemeral profile; persistent custody/recovery profile remains open |
| P01-I06 | Guest found both canaries absent from process arguments, selected service journals and runtime artifacts; `LimitCORE=0` is applied and the systemd TPM capability command is unavailable on this profile | VM partial pass; TPM, crash-review, and broader exposure/custody review remain open |
| P01-I07 | Rust format/lint/test checks pass; the named local runner booted the pinned guest, collected metadata, and removed QEMU/guest disks. Injected failure and SIGTERM cancellation teardown both pass | Runner/harness pass for the exercised profile; guest-version and broader matrix coverage remain open |
| P01-E01 | Guest delivered the dummy value, validated the native consumer, wrote/restored a checksum-only backup before and after controlled broker restart rotation, removed installed units/binaries and retained protected material | VM pass for exercised path; production recovery procedure remains out of scope |
| P01-E02 | Guest harness used an explicit host-key `LoadCredentialEncrypted=` profile and exercised initial delivery plus controlled rotation | VM pass for host-key profile; no TPM or superiority claim |

The live run does not close every W0 scenario: the persistent custody/unlock
profile, TPM-required profile, crash-artifact review, kernel API-removal
matrix, and guest-version matrix remain open. On this Ubuntu/systemd profile,
`systemd-analyze has-tpm2` is an unsupported command, so no TPM result is
inferred from the host-key comparison. W0 therefore remains **open for
go/narrow/stop review**, rather than being represented as a full acceptance
pass. The executable harness records unsupported prerequisites with exit 78 and
must not convert those profiles into skips or passes.
