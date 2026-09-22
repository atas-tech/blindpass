# P01 execution record

**Recorded:** 2026-09-23

This is the repository-side execution record for the P01 plan in the docs
vault. It does not replace the required W0 review or the real-systemd VM
artifacts.

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
socket scan create --cwd /home/hvo/Projects/blindpass --read-only --no-set-as-alerts-page --markdown .
# API reachable; 20 files discovered; [ReadOnly] Bailing now

socket scan create --cwd /home/hvo/Projects/blindpass --no-set-as-alerts-page --report --markdown .
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
  comparison baseline.

## VM and W0 status

| Scenario | Current evidence | Acceptance status |
|---|---|---|
| P01-I01 | Portable invocation-bound model exists; repeated pidfd/unit restart injection is not available here | Not run; VM gate open |
| P01-I02 | Root loader, forged routing, registered non-root workload and unregistered workload boundaries are covered by portable tests and the guest harness | Portable pass; system/user-manager VM evidence open |
| P01-I03 | Unsupported pidfd/systemd results fail closed in the implementation; API-removal boot profile is not available here | Not run; VM gate open |
| P01-I04 | Bounded frame/delivery tests and consumer rejection cover empty, partial, malformed and oversized material | Portable pass; VM timing/stall evidence open |
| P01-I05 | Ephemeral one-use custody and Rust ↔ `hpke-js` ciphertext parity pass | Portable pass; VM restart/absent-key evidence open |
| P01-I06 | Wipe-on-drop and metadata-only debug behavior are tested; TPM/temp/argv/journal inspection is not run | Not run; VM gate open |
| P01-I07 | Rust format/lint/test checks pass; the manual runner and cleanup traps are implemented | CI pass; named guest runner missing |
| P01-E01 | Native unit definitions, consumer validation and controlled rotation are implemented in the guest harness | Not accepted until VM execution |
| P01-E02 | `LoadCredentialEncrypted=` comparison unit is present | Not run; no comparison claim |

The real VM scenarios are **not run** in this environment. The development
host now has QEMU 11.1.1 and `qemu-img` 11.1.1, but `cloud-localds` is
unavailable and `/dev/kvm` is absent; no named
`[self-hosted, linux, x64, blindpass-kvm]` runner or owner has been supplied.
The harness was invoked after QEMU installation and returned exit 78 with
`P01-UNSUPPORTED /dev/kvm is unavailable or inaccessible`. Consequently
P01-I01, P01-I03, P01-I06, P01-I07, P01-E01 and P01-E02 are not accepted as
full VM evidence. The executable harness is in `tests/fleet/` and exits 78
with an unsupported record when those prerequisites are absent.

W0 remains **blocked pending runner provisioning and review**. The current
portable implementation is suitable for review and for the next disposable
VM run, but it does not establish system-scope identity races, TPM behavior,
guest cleanup, or superiority over the native encrypted credential store.
