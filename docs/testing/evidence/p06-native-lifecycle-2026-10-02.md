# P06 native controller lifecycle — 2026-10-02

Slice 3 implements the native controller candidate and verifies P06-N01–N09
on **real disposable Debian 12 and Ubuntu 24.04 QEMU/KVM guests**. This is
selected native SQLite lifecycle evidence, not complete P06 acceptance.
The authoritative [product phase](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/06-deployment-and-recovery.md)
and [paired scenarios](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/06-deployment-and-recovery.md)
retain the full nine-slice scope and inherited P02/P03/P05 gates.

## Implementation and custody

[The installer](../../../deploy/native/controller-install.py) verifies the
bounded complete member inventory, architecture, embedded-UI metadata, modes
and hashes before creating an account or trust. Linked/extra/missing members,
unmanaged accounts/groups/units/drop-ins/state/program paths, modified installed
units and artifact changes are refused. It validates a captured TLS PEM pair
with maintained OpenSSL parsers before account/key creation. A protected root
record binds the managed UID and exact artifact; it is **not** an external
ownership or recovery-generation anchor.

Explicit `--initialize` creates independent raw keys and the initial database.
Starting or reinstalling an established installation cannot replace lost keys,
database or identity. A same-content reinstall preserves config/state; other
versions/content are refused until the verified upgrade path exists. Normal
uninstall removes managed programs/units and retains trust/data/config/account.
Exact confirmed purge validates state custody and refuses symlinks before
stopping/removing the controller; unrelated broker-probe and protected canary
files remain. It retains a locked account and a purged root custody record so
an explicit later fresh initialization can create a new tenant.

The hardened non-root [unit](../../../deploy/native/blindpass-controller.service)
loads credentials from the private key root; its filesystem permits data/run
writes and refuses key/config/program writes. Initialization and clock recovery
are separately explicit one-shot units. The controller backup service/timer
are installed disabled/inactive, conditional on a protected recovery key and
enable marker that the installer never creates. Their future backup command
is not functional or accepted before slice 5. The names
`blindpass-controller-backup.*` preserve the existing broker backup probes.
The [quickstart](../../deploy/native-quickstart.md) documents the current limits.

Plaintext key material remains in controller runtime memory for its lifetime;
systemd credential copies last for the unit. During explicit TLS installation,
the installer and short-lived OpenSSL process consume PEMs in memory until exit
and publish root-only copies. They print no PEM/parser diagnostics. Generated
test keys and guest disks/SSH keys were discarded; recorded logs contain fixed
status, metadata and dummy canaries only.

## First failures and corrections

The initial preflight run failed its positive test because the installer was
absent; negative subprocess tests consequently also returned failure. This
initial result does not establish rejection behavior. The implemented final
seven-test suite separately exercises valid inventory, tampering, omitted/extra
members, file/directory links, profile/architecture/version mismatch, traversal,
modes, missing native units, duplicate metadata and absent UI flags.

The first VM harness incorrectly expanded a private extraction glob before
sudo; corrected guest-root expansion allowed installation. Its initial plaintext
TLS probe also needed to accept the expected HTTP parser exception. Lost-state
tests now observe `Type=exec` application/pre-start failure and auto-restart
status rather than assuming `systemctl start` waits for readiness.

Ubuntu systemd 255 exposed a real compatibility failure: root-owned credentials
use read-only named-user ACLs and appear as mode 0440. The old reader refused
them. [The failing guest record](p06-native-lifecycle-2026-10-02/ubuntu-before-acl.txt)
shows the fixed credential-field error and ownership/modes, without content.
The shared reader now checks the opened descriptor's exact Linux version-2 ACL:
root owner read, exactly the effective service UID read, owning group/other
none, read-only mask, no extra entries. It retains link, owner, bounds and
nofollow checks; ordinary group-readable files remain refused. Three tests
were written first (one failed), then passed after implementation. Both real
units passed afterward; an actual root-owned ACL granting an additional reader
was refused. The compatibility basis is [systemd 255 credential construction](https://github.com/systemd/systemd/blob/v255/src/core/exec-credential.c)
and the [Linux ACL syscall ABI](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/posix_acl_xattr.h).
No dependency or library was added for this check.

The sandboxed npm run aborted a Node test process with an internal callback
assertion and failed MCP subprocess cases. A bounded host core/OOM audit found
no retrievable Node core record or OOM entry; no core memory was extracted.
The same Node 26.10.0 workspace gate outside the socket-restricted sandbox
passed. This establishes that run's result, not a diagnosis of an upstream
Node bug.

## Actual execution

Both VMs installed the same final bookworm-built controller archive and the
same guest test script:

```text
archive SHA256: 254649dcd1d824d2f548de44deae5b84f69993f0d984cf1af891240c43b78c83
guest test SHA256: 74c602e84511f3e41e68eb4d7ef6094378df42c32df9150cd85a6f948e6451fa
```

| Guest | Pinned image SHA256 | Observed runtime | Result |
|---|---|---|---|
| Debian 12 genericcloud 20260923-2610 | `7b3faf645268d65f91676b11cda5ab18294b1f0ac0062238f00d279551bdecad` | kernel 6.1.0-53-cloud-amd64; systemd 252.39-1~deb12u2 | N01–N09 passed; stop 0.012 s |
| Ubuntu 24.04 cloud image | `612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354` | kernel 6.8.0-139-generic; systemd 255.4-1ubuntu8.17 | N01–N09 passed; stop 0.015 s |

The Debian image was downloaded from the immutable official build and matched
its published SHA512 before its SHA256 pin was used. The harness installs only
OS prerequisites inside the disposable overlay, generates an ephemeral SSH key,
uses `p06runner` rather than adopting a privileged `blindpass` SSH account,
checks actual OS identity, reboots and destroys the overlay/process/key. No
controller installation or package operation was performed on the host.

N01 rejects tampered inventory, malformed/mismatched TLS and unmanaged account/
unit collisions before trust creation. N02 serves verified HTTPS readiness,
capabilities and both embedded HTML surfaces. N03 checks the real process UID,
NoNewPrivileges, empty capabilities, private admin socket, credential custody
and actual mount-namespace write denials. N04 verifies stop/start, enabled
service, changed boot ID, explicit clock reconciliation and unchanged identity.
N05 refuses newer/older/changed artifacts and reinitialization while preserving
same-content installs. N06 removes key/data roots, observes service failure,
refuses installer replacement and restores the preserved originals. Systemd
can recreate an empty StateDirectory; **no replacement database or tenant** is
created. N07 verifies the disabled timer and skipped unconfigured backup.
N08 covers repeated default uninstall and retained-identity reinstall. N09
rejects incorrect purge confirmation and linked state before stopping, preserves
unrelated canaries, purges the controller, then requires explicit fresh keys/
tenant creation.

| Gate | Actual result / recorded output |
|---|---|
| Native preflight / archive component tests | 7 / 8 passed; [preflight](p06-native-lifecycle-2026-10-02/preflight-final.txt), [release tests](p06-native-lifecycle-2026-10-02/release-tests.txt) |
| Real VM lifecycle | [Debian](p06-native-lifecycle-2026-10-02/debian-12-vm.txt), [Ubuntu](p06-native-lifecycle-2026-10-02/ubuntu-24.04-vm.txt), N01–N09 passed each |
| Bookworm build and extracted archive | Passed; [build](p06-native-lifecycle-2026-10-02/bookworm-build.txt), [R01–R04](p06-native-lifecycle-2026-10-02/archive-runtime.txt); manifest/checksum, dummy-canary exclusion, no overwrite, packaged guide links and extracted CLI/controller/UI |
| HTTPS runtime T01–T04 | Passed; [output](p06-native-lifecycle-2026-10-02/https-runtime.txt), 64 stalled peers drained in 5.010 s (<7 s), stalled-handshake SIGTERM 0.016 s (<10 s) |
| Rust workspace | 659 passed, 4 ignored; [output](p06-native-lifecycle-2026-10-02/rust-workspace.txt) |
| Final ACL and layout/startup/proxy gates | ACL 3 passed; selected components 23 passed each on SQLite/PostgreSQL; [ACL](p06-native-lifecycle-2026-10-02/acl-final.txt), [SQLite](p06-native-lifecycle-2026-10-02/sqlite-components.txt), [PostgreSQL](p06-native-lifecycle-2026-10-02/postgres-components.txt); temporary PostgreSQL role/database removed |
| Clippy, formatting, shell/Python syntax, link checks and diff whitespace | Passed; [Clippy](p06-native-lifecycle-2026-10-02/clippy.txt); no new dependency/lockfile change |
| Node 26.10.0 build/workspace | Passed; [build](p06-native-lifecycle-2026-10-02/npm-build.txt), [tests](p06-native-lifecycle-2026-10-02/npm-test.txt); 101 default service-gated SPS skips |

Observed installer message (both guests):

```json
{"backup_timer":"disabled unless separately configured","initialized":true,"ok":true,"version":"0.1.0"}
```

## Limits

Native tests use SQLite and built-in TLS with a disposable trusted certificate;
they are not actual operator browser/backup workflows or native PostgreSQL
deployment evidence. The new unit does existing-state validation, not the future
`migrate --lock`/verified pre-upgrade backup path. Its backup timer remains disabled.
Caddy/nginx real-edge X07, aarch64, remote CI, OCI profiles, complete encrypted
backups, external ownership/stale-restore reconciliation, fenced migration,
protected upgrades, all three-profile/remote workflow parity and inherited
acceptance gates remain open. No broker support claim is inferred on Debian 12.

Three Quickshell tests and the default ignored PostgreSQL outage test were not
run in this slice; the latter has separate slice-2 evidence. The 101 SPS skips
are unexecuted checks. Full HTTP contract/browser suites were not rerun for this
native slice; no API/UI implementation changed. P06 is not marked complete.
