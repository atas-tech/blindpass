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
  host-key profile and exercises initial delivery plus controlled rotation;
  TPM protection is not claimed.

## VM and W0 status

The live disposable run completed on 2026-09-23 using the explicitly named
`local-kvm-followup` runner owner. Host evidence was QEMU 11.1.1, `qemu-img` 11.1.1,
read/write `/dev/kvm`, and `cloud-localds`; the pinned Ubuntu cloud image had
SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
Guest evidence was Ubuntu 24.04, kernel 6.8.0-139-generic, systemd 255 as
PID 1. The guest recorded directory `0751` root-owned, loader socket `0600`
root-owned, and workload socket `0660` with the dedicated workload group.
The guest measured stalled-loader rejection at 2.025 seconds, stopped QEMU,
removed the broker units/binaries and sockets, and retained only text evidence
on the host; the guest disk overlay and seed media were removed. The protected
dummy material remained root-owned mode `0600`. No live credential was used.

| Scenario | Current evidence | Acceptance status |
|---|---|---|
| P01-I01 | Guest restarted the root consumer and re-resolved its invocation; it rejected a stale workload invocation and re-registered the currently running replacement before delivery | VM pass for exercised restart paths; repeated fault-injection loop remains open |
| P01-I02 | Root loader delivery, non-root loader socket access, forged loader routing, registered non-root workload and unregistered workload were exercised in the guest; user-manager/shared-UID profiles remain out of scope | VM pass for supported system-unit profile |
| P01-I03 | Guest hid the system bus socket inside the broker service namespace; an otherwise authorized native consumer failed closed and produced no credential file | VM pass for exercised API-removal profile; kernel API-removal matrix remains open |
| P01-I04 | Guest measured a stalled root-system-unit loader denial at 2.025 seconds and rejected empty, partial, malformed and oversized consumer material; broker truncate/corrupt delivery is not separately injected | VM pass for exercised cases; remaining fault profiles open |
| P01-I05 | Ephemeral one-use custody and Rust ↔ `hpke-js` ciphertext parity pass | Portable pass; VM restart/absent-key evidence open |
| P01-I06 | Guest found both canaries absent from process arguments and service journals; TPM, crash-artifact and deeper temporary-file inspection profiles are not run | VM partial pass; custody-mode/exposure review remains open |
| P01-I07 | Rust format/lint/test checks pass; the named local runner booted the pinned guest, collected metadata, removed QEMU/guest disks and retained text logs | Runner/harness pass; failure/cancel and matrix coverage remain open |
| P01-E01 | Guest delivered the dummy value, validated the native consumer, performed controlled broker restart rotation, removed installed units/binaries and retained protected material | VM pass for exercised path; recovery procedure remains open |
| P01-E02 | Guest harness used an explicit host-key `LoadCredentialEncrypted=` profile and exercised initial delivery plus controlled rotation | VM pass for host-key profile; no TPM or superiority claim |

The live run does not close every W0 scenario: the VM half of P01-I05 and the
unrun portions of P01-I06 still require explicit absent/wrong-key recovery,
TPM, crash-artifact and deeper exposure-review profiles; the kernel API-removal
matrix also remains open. W0 therefore remains **open for go/narrow/stop
review**, rather than being represented as a full acceptance pass. The
executable harness records unsupported prerequisites with exit 78 and must
not convert those profiles into skips or passes.
