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
`local-kvm` runner owner. Host evidence was QEMU 11.1.1, `qemu-img` 11.1.1,
read/write `/dev/kvm`, and `cloud-localds`; the pinned Ubuntu cloud image had
SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
Guest evidence was Ubuntu 24.04, kernel 6.8.0-139-generic, systemd 255 as
PID 1. The guest recorded directory `0751` root-owned, loader socket `0600`
root-owned, and workload socket `0660` with the dedicated workload group.
The runner stopped QEMU and the guest reported both broker sockets removed;
the protected dummy material remained root-owned mode `0600`. No live
credential was used.

| Scenario | Current evidence | Acceptance status |
|---|---|---|
| P01-I01 | Portable invocation-bound model exists; the current guest run did not include repeated pidfd/unit fault injection | Not run; VM gate open |
| P01-I02 | Root loader delivery, forged loader routing, registered non-root workload and unregistered workload were exercised in the guest; user-manager/shared-UID profiles remain out of scope | VM partial pass; inherited user-manager evidence open |
| P01-I03 | Unsupported pidfd/systemd results fail closed in the implementation; API-removal boot profile is not available here | Not run; VM gate open |
| P01-I04 | Bounded frame/delivery tests and the guest consumer reject empty, partial, malformed and oversized material; broker stall/truncate timing is not separately injected | VM partial pass; timing/stall evidence open |
| P01-I05 | Ephemeral one-use custody and Rust ↔ `hpke-js` ciphertext parity pass | Portable pass; VM restart/absent-key evidence open |
| P01-I06 | Wipe-on-drop and metadata-only debug behavior are tested; TPM/temp/argv/journal inspection is not run | Not run; VM gate open |
| P01-I07 | Rust format/lint/test checks pass; the named local runner booted the pinned guest, collected metadata and removed QEMU/guest sockets after the run | Runner/harness pass; failure/cancel and matrix coverage remain open |
| P01-E01 | Guest harness delivered the dummy value, validated the native consumer, performed controlled broker restart rotation and retained protected material | VM pass for exercised path; uninstall/recovery path remains open |
| P01-E02 | Guest harness used an explicit host-key `LoadCredentialEncrypted=` profile and exercised initial delivery plus controlled rotation | VM pass for host-key profile; no TPM or superiority claim |

The live run does not close every W0 scenario: P01-I01, P01-I03, the VM half
of P01-I05, and P01-I06 still require explicit fault-injection, API-removal,
recovery, TPM, and exposure-review profiles. W0 therefore remains **open for
go/narrow/stop review**, rather than being represented as a full acceptance
pass. The executable harness records unsupported prerequisites with exit 78
and must not convert those profiles into skips or passes.
