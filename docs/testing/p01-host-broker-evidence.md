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
| `cargo build --release --workspace --locked` | Pass outside the development sandbox | Release probes copied into the disposable guest, including the core-artifact probe |
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
`local-kvm-p01-final` runner owner. Host evidence was QEMU 11.1.1, `qemu-img` 11.1.1,
read/write `/dev/kvm`, and `cloud-localds`; the pinned Ubuntu cloud image had
SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
The disposable provisioning packages were pinned by SHA-256: cloud-image-utils
`a00e8f6b694167e155b4c427206a4c931844c5f4e2985b101a5b2a57f4e20ff1` and
genisoimage `19a0a26e83ea97a18c7d8388f554ceb46b364f6c00ff419acfe9e753ca4a9d2d`.
Guest evidence was Ubuntu 24.04, kernel 6.8.0-139-generic, systemd 255 as
PID 1. The guest recorded directory `0751` root-owned, loader socket `0600`
root-owned, and workload socket `0660` with the dedicated workload group.
The guest recorded successful loader/workload peer traces with UID/GID,
`pidfd=true`, system unit and 32-hex systemd invocation values. It measured
stalled-loader rejection at about 2.05 seconds, exercised
the broker empty/partial/malformed/oversized/corrupt delivery matrix, ran the
two-round root-loader and three-round workload pidfd-to-invocation restart
races, a real user-manager denial, and a `DynamicUser` profile, stopped QEMU,
removed the broker units/binaries and sockets, and retained only text evidence
on the host; the guest disk overlay and seed media were removed. Separate
failure-injection and cancellation runs passed the bounded teardown checks and
also removed QEMU and guest disk artifacts. The protected dummy material
remained root-owned mode `0600`. No live credential was used.

A separate Debian 12 candidate-minimum attempt used kernel 6.1.0-53-amd64,
systemd 252 and image SHA-256
`5b842b549629637613f1770ad749b868b08c6e16c437a5940f21178816f3d7e9`.
It stopped at broker startup with the dynamic-linker error that the guest
`libsystemd` lacked `LIBSYSTEMD_253`; the harness recorded
`P01-UNSUPPORTED` and delivered no credential. This is an explicit
fail-closed version result, not a skipped or passing Debian profile.

| Scenario | Current evidence | Acceptance status |
|---|---|---|
| P01-I01 | Guest restarted the root consumer and re-resolved its invocation; it rejected a stale workload invocation, exercised two root-loader restart races and three workload restart races, and re-registered each replacement before delivery | VM pass for exercised restart paths; broader fault-injection matrix remains open |
| P01-I02 | Root loader delivery, non-root and real user-manager socket access, forged loader routing, registered fixed-account and `DynamicUser` workloads, and an unregistered workload were exercised; the broker journal recorded actual UID/GID, pidfd, unit and invocation values; user-manager/shared-UID execution remains denied/out of scope | VM pass for supported system-unit profile and explicit user-manager denial |
| P01-I03 | Guest hid the system bus socket and blocked `getsockopt` inside the broker service namespace; an otherwise authorized native consumer failed closed in both profiles and produced no credential file | VM pass for exercised API-removal profiles; broader kernel API-removal matrix remains open |
| P01-I04 | Guest measured a stalled root-system-unit loader denial at about 2.05 seconds, rejected malformed consumer material, and injected empty, partial, malformed, oversized and corrupt broker responses against the real native consumer | VM pass for exercised cases; additional transport/fault profiles remain open |
| P01-I05 | Ephemeral one-use custody, expiry, wrong-key/tamper/AAD rejection, process-restart absent-key behavior, and Rust ↔ `hpke-js` ciphertext parity pass | VM pass for the selected ephemeral profile; persistent custody/recovery profile remains open |
| P01-I06 | Guest found canaries absent from process arguments, selected service journals, runtime artifacts and the apport crash report; `LimitCORE=0` was applied, one crash report was inspected and removed without the canary, and explicit `tpm2` encryption was rejected after the capability probe was unavailable | VM pass for the selected no-plaintext profile; TPM-present and broader exposure/custody review remain open |
| P01-I07 | Rust format/lint/test checks pass; the named local runner booted the pinned guest, collected metadata, and removed QEMU/guest disks. Injected failure and SIGTERM cancellation teardown both pass | Runner/harness pass for the exercised profile; guest-version and broader matrix coverage remain open |
| P01-E01 | Guest delivered the dummy value, validated the native consumer, wrote/restored a checksum-only backup before and after controlled broker restart rotation, removed installed units/binaries and retained protected material | VM pass for exercised path; production recovery procedure remains out of scope |
| P01-E02 | Guest harness used an explicit host-key `LoadCredentialEncrypted=` profile, exercised initial delivery plus controlled rotation, and denied decrypt when the protected host key was temporarily absent | VM pass for host-key profile; no TPM or superiority claim |

## W0 go/narrow/stop review

**Recorded:** 2026-09-23. **Disposition:** NARROW for the evidenced profile;
this is not a full-matrix go decision.

The selected P01 profile is x86_64 Linux with system-scope systemd, kernel
6.8.0-139-generic, systemd 255, root-only loader socket `0600`, workload socket
`0660`, `SO_PEERPIDFD`, `GetUnitByPIDFD` plus `InvocationID` lookup, dedicated
fixed-account or `DynamicUser` workloads, a 2-second broker read/write bound,
4096-byte request frames, 64 KiB credentials, and ephemeral one-use broker
custody. Native `LoadCredentialEncrypted=` host-key mode is a comparison
profile only; it is not a claim that broker custody survives restart.

The narrow disposition explicitly excludes user-manager execution and shared
desktop-UID isolation, TPM-present custody, persistent broker custody/unlock or
recovery, unsupported alternate kernel/systemd guest versions, and a complete
crash-dump collector matrix. The Ubuntu guest's `systemd-analyze has-tpm2` command was
unavailable and its explicit `--with-key=tpm2` operation rejected the request;
the test therefore makes no TPM-present claim. The harness records missing
prerequisites as unsupported (exit 78) and does not turn them into passes.
The tested minimum for this built binary is therefore systemd 255 on the
selected Ubuntu profile; a systemd-252-compatible build remains unclaimed.
P03/P02.6 fleet cutover must not broaden beyond this profile without a new
review of the named exclusions.
