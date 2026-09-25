# P01 execution record

**Recorded:** 2026-09-24

This is the repository-side execution record for the P01 plan in the docs
vault. The live-HPKE/non-root profile, including stock systemd
`LoadCredential=` delivery, passed on commit
`a45c3d027f27fcaf5a870c6f2ca3b334c2d16a57`. Earlier root-consumer/file-loaded
evidence and the pre-commit run below are historical context. Disposable VM
artifacts remain runner-local and are not committed.

**2026-09-23 review correction:** The cited VM exit is historical evidence for
that exact source and harness. It does not establish P01-I01 workload race
rejection: those three rounds checked recovery after a broker restart, without
asserting denial of the old invocation. It also does not establish P01-I06
absence: the scanner had no positive control, could treat scan errors as
absence, skipped large files and ended before the final scenarios. Both rows
were **not established** for W0 acceptance at that point. The working-tree
run below tested the revised scanner and loader denial; the revised
committed-SHA run on `6d41a1f` later closed both rows, and the user accepted
W0 as NARROW on 2026-09-24.

## Review working-tree VM run, 2026-09-23 (not acceptance evidence)

On 2026-09-23, `./tests/fleet/p01-vm.sh` exited 0 with runner owner
`local-kvm-p01-review-20260923-r6` on dirty HEAD
`03503390d39ff04efd81752ebea811b51058b1ee`. Host QEMU 11.1.1 used
read/write `/dev/kvm`; the pinned Ubuntu 24.04 image matched SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
The guest reported kernel 6.8.0-139-generic and systemd 255. Runner-local
sanitized logs were retained; this run used generated dummy canaries.

The revised scanner rejected an injected canary in a runtime artifact, then
completed initial, post-rotation, and final scans after the restart and
short-TTL cases. It inspected one crash report; `coredumpctl` was unavailable,
and the guest had no TPM device. The loader lookup-after-exit test denied the
old captured peer twice with `os_identity:peer_exited before unit lookup` and
delivered to each replacement. The stale workload invocation was denied after
restart and re-registration was required, but the three workload rounds still
assert only recovery. They do not establish rejection of a stale peer captured
before process exit. Thus P01-I01 and full P01-I06 acceptance remain open even
though this selected VM run passed. The sandbox had hidden `/dev/kvm`; the
approved host run confirmed the device was usable.

## Historical committed-SHA VM run (2026-09-23)

| Source SHA | Runner owner | Guest and host profile | Outcome |
|---|---|---|---|
| `a45c3d027f27fcaf5a870c6f2ca3b334c2d16a57` | `local-kvm-p01-final-a45c3d0-20260923` | QEMU 11.1.1 with KVM; pinned Ubuntu 24.04 image SHA-256 `612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`; guest kernel 6.8.0-139-generic; systemd 255; no TPM device | `./tests/fleet/p01-vm.sh` exited 0 on 2026-09-23; sanitized serial and guest logs retained runner-local |

The selected profile passed the provision socket negatives, HPKE
wrong-key/tamper/AAD/replay probes, non-root and user-manager denial, bounded
stall check (2012 ms against a 2500 ms limit), stock `LoadCredential=`
delivery, broker restart and expiry cases, and native encrypted credstore
comparison. The lookup-after-exit race ran twice: after the broker logged
pidfd capture and systemd reaped the old process, `GetUnitByPIDFD` denied the
old peer; the replacement invocation delivered successfully. Both generated
canaries were absent from scanned runtime artifacts. Native backup bytes
changed after rotation and restored successfully. The emulated TPM profile
was not run on this no-TPM guest; the harness explicitly reported that mode
unsupported.

The complete P01 scenario output is retained as sanitized text on the named
runner; VM disk and seed artifacts were removed. No live credential was used.

## Revised committed-SHA VM run (2026-09-24)

| Source SHA | Runner owner | Guest and host profile | Outcome |
|---|---|---|---|
| `6d41a1f6df8d90d283b53b3c7241281937702ac2` | `local-kvm-p02-commit-6d41a1f-20260924` | Clean detached checkout; QEMU 11.1.1 with read/write KVM; pinned Ubuntu 24.04 image SHA-256 `612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`; guest kernel 6.8.0-139-generic; systemd 255; no TPM device | `./tests/fleet/p01-vm.sh` exited 0; release workspace build passed; guest overlay and seed were removed |

The run used generated canaries and a disposable SSH key. P01-I01 checks
denied both captured loader peers after process exit and delivered to each
replacement; the stale workload invocation was denied and required
reregistration. Three additional workload rounds verified restart recovery.
Forced numeric PID reuse remains untested.

P01-I06's scanner positive control passed. Initial, rotated and final scans
reported no canary in process arguments, journals or scanned runtime/core
artifacts. One core report was inspected; `coredumpctl` was unavailable in the
guest. The no-TPM profile explicitly rejected required-TPM mode. Guest cleanup
reported units and sockets removed while retaining only the protected dummy
material required by the fixture. The host removed the temporary SSH key,
overlay and seed after the successful exit; `BLINDPASS_FLEET_KEEP_ARTIFACTS=0`
was used.

This closes the revised P01-I01 and P01-I06 checks on the named committed
SHA. The user accepted W0 as NARROW on 2026-09-24 for this tested profile
only. Forced PID reuse, `coredumpctl`-backed metadata inspection, alternate
host versions, TPM/firmware profiles and a shared self-hosted runner remain
outside this run and outside the accepted W0 scope.

## Pre-commit verification (not final acceptance evidence)

| Check | Result | Limit |
|---|---|---|
| `cargo fmt`, locked Clippy, locked workspace tests | Passed before commit | Includes route-to-pidfd authorization, binary credentials, RFC 9180 HPKE vector, live-state destination binding and bounded request deadlines; final committed-SHA checks are recorded below |
| `cargo check --workspace --locked` | Passed before commit | Does not execute systemd identity or service handoff |
| `bash -n tests/fleet/p01-guest.sh tests/fleet/p01-vm.sh tests/fleet/p01-teardown.sh` | Passed before commit | Syntax checked on the pre-commit harness revision |
| Live provisioning + native and direct delivery in QEMU guest | Pre-commit run passed | The final committed-SHA run on `a45c3d027f27fcaf5a870c6f2ca3b334c2d16a57` is recorded above |
| `p01-teardown.sh failure` and `cancel` | Passed before commit | Injected guest failure and SIGTERM cancellation removed QEMU and guest disks; rerun evidence must cite a committed SHA |

The selected ephemeral profile now has a root-only `provision.sock` at mode
`0600`. `blindpass-provision` reads administrator input from stdin, seals it to
the broker's fresh X25519 recipient key with unit/credential AAD, and sends
only encapsulation plus ciphertext. Each mapped destination has its own
in-memory credential entry. Pending recipient keys expire after 30 seconds;
accepted credentials expire after one hour and are purged, or disappear on
broker restart. Loader delivery retains the root/pidfd/systemd invocation
authorization. The direct helper writes a mode-`0600` runtime file and hands
its ownership to the dedicated service account. Stock `LoadCredential=` sends
no request frame, so the broker parses the abstract route as an untrusted hint
and requires root UID, a pidfd-derived unit equal to the route unit, a present
invocation, and the protected unit/credential mapping. On the tested
systemd 255 guest, the credential-setup peer resolved to the target consumer
unit and invocation, not `init.scope`. The current guest verified both
dedicated service accounts and mode-`0600` credential ownership.

The revised guest harness provisions dummy bytes from a root-only tmpfs source,
tests absent-key failure after restart, then reprovisions and retries. It
also checks both dedicated service accounts, credential-file ownership and a
backup restore run as the backup account. The persistent plaintext
`--credential NAME=/root-owned/file` broker option was removed. The source
tmpfs file is a disposable guest fixture, not persistent broker custody.

## Pre-commit disposable VM run (not final acceptance evidence)

The passing run used owner `local-kvm-p01-full-final-20260923`, QEMU
11.1.1, writable `/dev/kvm`, a locally extracted `cloud-localds` 0.33-3 and
`xorriso` for the seed ISO. The Ubuntu 24.04 cloud image matched SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
The guest reported kernel 6.8.0-139-generic and systemd 255 as PID 1.
`./tests/fleet/p01-vm.sh` exited 0. Separate runs with owner
`local-kvm-p01-teardown-final-20260923` made `./tests/fleet/p01-teardown.sh
failure` and `cancel` each report `P01-I07 ... teardown: PASS`. The cancellation
check binds its marker to the current guest, so retained logs from earlier
runs cannot satisfy it. The guest overlay and seed were removed. Retained
serial logs redact the ephemeral SSH host private-key block. No live
credential was used.
The verified base image is now retained under the local user's XDG data
directory at `blindpass/vm-images/noble-server-cloudimg-amd64.img`, with
`.sha256` and `.source.txt` sidecars. `cloud-localds` 0.33-3 and its
`genisoimage` compatibility wrapper are also retained in the local user's
`~/.local/bin` and passed a seed-ISO smoke check. The repository VM setup guide
includes the reusable environment settings; no image bytes are stored in Git.

| Scenario | Pre-commit VM observation | Profile limit |
|---|---|---|
| P01-I01 | Original harness printed pass for two direct-loader and three workload restart rounds | Workload rounds asserted recovery after broker restart, not race rejection; acceptance not established. Forced PID reuse remains untested. |
| P01-I02 | Pass: native `LoadCredential=` traced UID 0 plus exact target unit/invocation, direct loader, user-manager and non-root denial, forged/unregistered routing, `DynamicUser` and fixed-account workloads | User-manager execution remains unsupported |
| P01-I03 | Pass: system-bus removal and `getsockopt` seccomp removal fail closed without credential delivery; broker remains active | Broader kernel/systemd API matrix open; systemd 252 not rerun on this build |
| P01-I04 | Pass: 2023 ms stalled-frame denial and empty/partial/malformed/oversized/corrupt delivery rejection | Selected transport profile only |
| P01-I05 | Pass: live HPKE wrong-key/tamper/AAD/replay, mapped destination, one-use lifecycle, shortened-TTL expiry, restart absent-key denial and explicit reprovisioning | Ephemeral custody only; shortened test TTLs exercise expiry branches, not a full 30-second/one-hour wait |
| P01-I06 | Original harness printed pass for the no-TPM profile | Scanner had no positive control, could fail open, skipped large files and ended before final scenarios; acceptance not established. |
| P01-I07 | Pass: pinned guest boot, metadata, uninstall, injected failure and cancellation teardown; serial private keys redacted before retention | Shared self-hosted CI runner and alternate guest versions remain open |
| P01-E01 | Pass: dedicated non-root consumer and backup restore, controlled rotation, runtime ownership and uninstall cleanup | Backup probe stores a checksum only |
| P01-E02 | Runtime pass: native host-key encrypted credstore initial delivery, rotation and missing-key denial | Operational approval/audit benefit not demonstrated in P01; no superiority claim |

For the operational comparison, the broker profile requires a root-only HPKE
provision operation, consumer start, and explicit reprovisioning after broker
memory loss. Rotation uses a new provision operation and controlled service
restart. The native host-key profile requires `systemd-creds setup`, encrypting
and installing the credential file, then starting or restarting the consumer;
rotation repeats encryption and file replacement. Removing the host key denied
native recovery. Neither P01 profile includes a controller approval or audit
workflow, so an approval/audit benefit and operational superiority remain
unmeasured pending later phases and product review.

The initial native-delivery attempt exposed an incorrect assumption that the
socket peer was PID 1; the live systemd 255 trace showed the root credential
setup process resolves to the target unit and invocation. The broker now
compares that pidfd identity with the abstract route. Further runs corrected
the `ExecStart` argument syntax, invocation-trace assertion, API-removal
drop-in ordering, and teardown process matcher. The final complete guest and
both teardown runs passed. The sandbox had hidden `/dev/kvm` during the
initial availability check, while the host device was present and usable.

## Portable checks on committed SHA `a45c3d027f27fcaf5a870c6f2ca3b334c2d16a57`

| Check | Result | Evidence |
|---|---|---|
| `cargo fmt --all -- --check` | Pass on committed SHA | Formatting gate |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass on committed SHA | Rust 1.98.1 toolchain; no third-party Cargo dependencies |
| `cargo test --workspace --locked` | Pass on committed SHA | Broker 18, broker main 1, credential loader 2, core 12, HPKE interoperability 2; no failures |
| `cargo build --release --workspace --locked` | Pass on committed SHA | Release probes copied into the disposable guest, including the core-artifact probe |
| `bash -n tests/fleet/p01-guest.sh tests/fleet/p01-vm.sh tests/fleet/p01-teardown.sh` | Pass on committed SHA | Fleet harness syntax |
| HPKE suite | Pass on committed SHA | DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305; exact `enc` and ciphertext match the generated `hpke-js` fixture |
| Socket dependency scan | Pass on manifest/lockfile SHA `a18ecb1e26e576c8475f0e68d7e538278a5f4e0e` | Pre-upgrade scan `0d2bc0fb-57d3-41ce-bea7-ed4ac29703ee` failed on Vitest 3.2.4. After the user-approved four-package npm upgrade, scan `2f43843e-a3d2-4aee-90bd-0eac5eb0e731` covered 20 manifests/lockfiles and passed organization policy. No Cargo dependency was added. |

The sandbox denied Unix socket operations with `EPERM`; the transport tests
were therefore rerun outside it. No test fixture contains a live credential.

The exact non-alerting commands were:

```text
socket scan create --cwd . --read-only --no-set-as-alerts-page --markdown .
# API reachable; 20 files discovered; [ReadOnly] Bailing now

socket scan create --cwd . --no-set-as-alerts-page --report --markdown .
# HTTP 403: required scope full-scans:create
```

Those commands document the earlier access-limited attempt. The authenticated
full scan listed above supersedes that access limitation.

## Earlier portable boundary (historical)

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

## Earlier VM run and W0 status (historical)

The runs in this historical section are retained for context only. The final
acceptance evidence is the committed-SHA run recorded at the top of this file;
these older observations do not widen that selected profile.

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
`5b842b549629637613f1770ad749b868b08c6e16c437a5940f21178816f3d7e9` with an
earlier binary that imported `sd_pidfd_get_unit`; that build failed to load
`LIBSYSTEMD_253` and delivered no credential. This result is historical and
does not describe the current binary, which no longer imports that symbol.
The current systemd-252 unsupported-host path has not been exercised on that
guest image, so the version matrix remains unclaimed.

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

| Scenario | Earlier VM evidence | Status for that earlier profile |
|---|---|---|
| P01-I01 | Guest restarted the root consumer, exercised two lookup-after-exit rounds and three workload recovery rounds, then re-registered replacements | Historical output only; workload race rejection was not asserted and acceptance is not established |
| P01-I02 | Root loader delivery, non-root and real user-manager socket access, forged loader routing, registered fixed-account and `DynamicUser` workloads, and an unregistered workload were exercised; the broker journal recorded actual UID/GID, pidfd, unit and invocation values; user-manager/shared-UID execution remains denied/out of scope | VM pass for supported system-unit profile and explicit user-manager denial |
| P01-I03 | Guest hid the system bus socket and blocked `getsockopt` inside the broker service namespace; an otherwise authorized native consumer failed closed in both profiles and produced no credential file | VM pass for exercised API-removal profiles; broader kernel API-removal matrix remains open |
| P01-I04 | Guest measured a stalled root-system-unit loader denial at about 2.05 seconds, rejected malformed consumer material, and injected empty, partial, malformed, oversized and corrupt broker responses against the real native consumer | VM pass for exercised cases; additional transport/fault profiles remain open |
| P01-I05 | Ephemeral one-use custody, expiry, wrong-key/tamper/AAD rejection, process-restart absent-key behavior, and Rust ↔ `hpke-js` ciphertext parity pass | VM pass for the selected ephemeral profile; persistent custody/recovery profile remains open |
| P01-I06 | Original scanner printed absence in selected artifacts; no-TPM and emulated TPM feature probes ran | Historical output only; detector coverage and final scan were insufficient, so absence acceptance is not established |
| P01-I07 | Rust format/lint/test checks pass; the named local runner booted the pinned guest, collected metadata, and removed QEMU/guest disks. Injected failure and SIGTERM cancellation teardown both pass | Runner/harness pass for the exercised profile; guest-version and broader matrix coverage remain open |
| P01-E01 | Guest delivered the dummy value, validated the native consumer, wrote/restored a checksum-only backup before and after controlled broker restart rotation, removed installed units/binaries and retained protected material | VM pass for exercised path; production recovery procedure remains out of scope |
| P01-E02 | Guest harness used an explicit host-key `LoadCredentialEncrypted=` profile, exercised initial delivery plus controlled rotation, and denied decrypt when the protected host key was temporarily absent | VM pass for host-key comparison profile; no broker-custody superiority claim |

## W0 go/narrow/stop review

**2026-09-24 product decision:** The user accepted **NARROW** for the clean
committed-SHA Ubuntu 24.04, x86_64, kernel 6.8.0-139-generic, systemd 255,
no-TPM, dedicated non-root, ephemeral-custody profile above. This satisfies
the W0 product-review prerequisite for P02.6 and P03 only within that exact
profile and the tested invocation/cleanup path. It does not supply hosted CI
evidence or expand the supported host matrix. The exclusions and unmeasured
checks below remain explicit limitations and require new evidence before a
broader rollout.

**2026-09-23 record, superseded by the decision above:** NARROW for the
earlier profile. P01-I01 and P01-I06 were not established at that time. The
live HPKE, dedicated non-root, Ubuntu 24.04/systemd 255 run on
`a45c3d027f27fcaf5a870c6f2ca3b334c2d16a57` passed its original harness, but
those two gaps prevented using it as complete W0 evidence until the revised
run on `6d41a1f` closed them.

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
versions, a forced same-numeric-PID reuse scenario, and a complete crash-dump
collector matrix. The default Ubuntu
guest profile has no TPM device and rejects explicit `--with-key=tpm2`; the
opt-in QEMU/swtpm profile passes the TPM-present native systemd round-trip but
reports firmware as absent. The harness records missing prerequisites as
unsupported (exit 78) and does not turn them into passes.
The selected units now set `KillMode=control-group`; deployments with lingering
processes from an earlier invocation, including `KillMode=process`, are outside
this profile. The consumer units set `TimeoutStartSec=5s`, but a stalled real
`LoadCredential=` handoff has not yet been measured against that bound.
The broker deliberately fails closed if a handler panics while holding its
state mutex: later requests report `broker state poisoned` until systemd
restarts the service. This is an availability limit, not recovered state.
The inherited C02 abstract-route forgery, C03, C05, C12 and C13 scenarios
do not have independent VM rows, and P01-E02 records functional native
credstore parity without timing or operator-effort measurements. Those gaps
remain open even after a scanner rerun.
The old non-root and user-manager probes reached filesystem permission denial,
not the broker's own identity checks. The historical unregistered-workload log
assertion was run-wide and could match an earlier round; the revised harness
scopes it to the test start but has not run in a VM. Loader lookup-after-exit did
not force numeric PID reuse or assert descriptor closure. QEMU teardown after
an untrappable runner `SIGKILL` has not been demonstrated. These limits must
be addressed in a subsequent VM harness revision or kept out of the W0 claim.
The tested minimum for this built binary is therefore systemd 255 on the
selected Ubuntu profile; a systemd-252-compatible build remains unclaimed.
P03/P02.6 fleet cutover must not broaden beyond this profile without a new
review of the named exclusions.
