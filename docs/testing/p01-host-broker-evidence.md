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
- Custody is ephemeral and one-use. No persistent encrypted broker-custody
  profile is claimed before the unlock/recovery review. The optional native
  systemd TPM profile is comparison/acceptance evidence, not broker custody.
- Native unit files define root ownership, socket modes, systemd hardening, a
  registered workload probe, and a separate `LoadCredentialEncrypted=`
  comparison baseline. The guest harness provisions an explicit systemd
  host-key profile and exercises initial delivery plus controlled rotation. A
  disposable backup/restore probe consumes credentials through the same loader
  path and persists only a checksum; it is a test fixture, not a production
  backup implementation. The default guest has no TPM device; the optional
  QEMU/swtpm profile exercises native systemd TPM2 credential protection with
  a pinned tpm2-tss runtime bundle.

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

The optional emulated-TPM run completed with owner
`local-kvm-p01-tpm-pass`. It used the same pinned Ubuntu image and attached a
QEMU `tpm-tis` device backed by Ubuntu `swtpm` 0.7.3. The guest reported a
TPM device, installed the Ubuntu noble-updates tpm2-tss runtime bundle
`4.0.1-7.1ubuntu5.1` plus `tpm-udev` `0.6ubuntu1`, and passed explicit
`systemd-creds --with-key=tpm2` encryption, decryption, and plaintext
comparison. `systemd-creds has-tpm2` reported `partial` with firmware absent
but driver, system, subsystem, and library support present; this is expected
for the emulated profile and is not a measured-boot claim. The host harness
recorded the runner-side Ubuntu package hashes below; `swtpm` was extracted
on the host and not installed into the guest:

```text
swtpm_0.7.3-0ubuntu5.24.04.1_amd64.deb cd1164c8ab70080ca4e93095ee1bdcdc94c8297eed29caf098ca2afd0fbbb540
swtpm-tools_0.7.3-0ubuntu5.24.04.1_amd64.deb 309d6ac8486d0113368c984b83f1f5e442d811e9b06e0dc6da1818ad8bc2e5be
libtpms0_0.9.3-0ubuntu4.24.04.1_amd64.deb 83bd2f4f57189d6d0b8f019252b95c3034fd41dd00b9f2dddb67321537b4ed55
```

The host harness recorded these 13 guest-package hashes:

```text
libtss2-esys-3.0.2-0t64_4.0.1-7.1ubuntu5.1_amd64.deb 7ae4f9fdfd7b5221a294dd91b4f595f426b3c8aa7dc39be3e65824971e916fe2
libtss2-mu-4.0.1-0t64_4.0.1-7.1ubuntu5.1_amd64.deb 9940a4de987536b357fde7a3137f7dc00a188ad744905af061b437ae22f7012b
libtss2-rc0t64_4.0.1-7.1ubuntu5.1_amd64.deb 85f725b1cfa57e782a2ac30cd0f9befbf7a7fdc836ff304032add41b210fc2df
libtss2-sys1t64_4.0.1-7.1ubuntu5.1_amd64.deb 0590ff8e5126ed3de8e8588ac3b538f4d32e3174c5480722d1e9f6389acf3c0d
libtss2-tcti-cmd0t64_4.0.1-7.1ubuntu5.1_amd64.deb fc53beb421a94bba344d2fd37c6cf524c604aac18382ce0f9c2ffe5564f1b7ac
libtss2-tcti-device0t64_4.0.1-7.1ubuntu5.1_amd64.deb d55ce053c026de094b9129438548141ab9b623f33edd62c756ed6df601e6e7ca
libtss2-tcti-libtpms0t64_4.0.1-7.1ubuntu5.1_amd64.deb b227e9574025f847097dd6bce2444561c92e28206e18a834ad422bcd169ee2aa
libtss2-tcti-mssim0t64_4.0.1-7.1ubuntu5.1_amd64.deb 5d4caaa0881695c17c5d864d12ff25f42b5da8bb702b4e790da92f463782475f
libtss2-tcti-pcap0t64_4.0.1-7.1ubuntu5.1_amd64.deb f9bb76bd601b6391e3f60eff48b0336ea6855ff1c9a7e53a739fa4972967fed2
libtss2-tcti-spi-helper0t64_4.0.1-7.1ubuntu5.1_amd64.deb 400b3cb5ac6abca9053db09c694d78d27cd7feb81eff36f0131754dce9082cb8
libtss2-tcti-swtpm0t64_4.0.1-7.1ubuntu5.1_amd64.deb 23da903b6baf636d264b7739360392baf3e01e3459fc4f5dddd60518bec9e2a3
libtss2-tctildr0t64_4.0.1-7.1ubuntu5.1_amd64.deb a1a82302972894447398b3dfcee3a4d01273f615b2c11fb90de4323e8c4bc12f
tpm-udev_0.6ubuntu1_all.deb 7ff6b02368f0db0589a509209383e8a875934bc92f3cca737633dbffaf186023
```

| Scenario | Current evidence | Acceptance status |
|---|---|---|
| P01-I01 | Guest restarted the root consumer and re-resolved its invocation; it rejected a stale workload invocation, exercised two root-loader restart races and three workload restart races, and re-registered each replacement before delivery | VM pass for exercised restart paths; broader fault-injection matrix remains open |
| P01-I02 | Root loader delivery, non-root and real user-manager socket access, forged loader routing, registered fixed-account and `DynamicUser` workloads, and an unregistered workload were exercised; the broker journal recorded actual UID/GID, pidfd, unit and invocation values; user-manager/shared-UID execution remains denied/out of scope | VM pass for supported system-unit profile and explicit user-manager denial |
| P01-I03 | Guest hid the system bus socket and blocked `getsockopt` inside the broker service namespace; an otherwise authorized native consumer failed closed in both profiles and produced no credential file | VM pass for exercised API-removal profiles; broader kernel API-removal matrix remains open |
| P01-I04 | Guest measured a stalled root-system-unit loader denial at about 2.05 seconds, rejected malformed consumer material, and injected empty, partial, malformed, oversized and corrupt broker responses against the real native consumer | VM pass for exercised cases; additional transport/fault profiles remain open |
| P01-I05 | Ephemeral one-use custody, expiry, wrong-key/tamper/AAD rejection, process-restart absent-key behavior, and Rust ↔ `hpke-js` ciphertext parity pass | VM pass for the selected ephemeral profile; persistent custody/recovery profile remains open |
| P01-I06 | Guest found canaries absent from process arguments, selected service journals, runtime artifacts and the apport crash report; `LimitCORE=0` was applied, one crash report was inspected and removed without the canary. The default no-TPM path rejected explicit `tpm2` mode. The opt-in QEMU/swtpm path reported a real TPM device and passed `systemd-creds has-tpm2` library support plus explicit tpm2 encrypt/decrypt/compare | VM pass for the selected no-plaintext profile and emulated TPM-present profile; physical TPM/firmware-measured and broader exposure/custody review remain open |
| P01-I07 | Rust format/lint/test checks pass; the named local runner booted the pinned guest, collected metadata, and removed QEMU/guest disks. Injected failure and SIGTERM cancellation teardown both pass | Runner/harness pass for the exercised profile; guest-version and broader matrix coverage remain open |
| P01-E01 | Guest delivered the dummy value, validated the native consumer, wrote/restored a checksum-only backup before and after controlled broker restart rotation, removed installed units/binaries and retained protected material | VM pass for exercised path; production recovery procedure remains out of scope |
| P01-E02 | Guest harness used an explicit host-key `LoadCredentialEncrypted=` profile, exercised initial delivery plus controlled rotation, and denied decrypt when the protected host key was temporarily absent | VM pass for host-key comparison profile; no broker-custody superiority claim |

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
desktop-UID isolation, physical TPM/firmware-measured boot, persistent broker
custody/unlock or recovery, unsupported alternate kernel/systemd guest
versions, and a complete crash-dump collector matrix. The default Ubuntu
guest profile has no TPM device and rejects explicit `--with-key=tpm2`; the
opt-in QEMU/swtpm profile passes the TPM-present native systemd round-trip but
reports firmware as absent. The harness records missing prerequisites as
unsupported (exit 78) and does not turn them into passes.
The tested minimum for this built binary is therefore systemd 255 on the
selected Ubuntu profile; a systemd-252-compatible build remains unclaimed.
P03/P02.6 fleet cutover must not broaden beyond this profile without a new
review of the named exclusions.
