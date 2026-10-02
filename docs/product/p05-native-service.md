# P05.5 native service: broker-delivered restic password

**Updated:** 2026-10-02. **Status:** repository-side implementation and host tests
only. Real restic backup/restore acceptance (P05-I05, P05-E02) is **open and
blocked**: the restic and rest-server artifacts are `block_pending_human_review`
in [ADR 0007](decisions/0007-p05-native-backup-dependency-review.md). No restic,
rest-server or Go toolchain was downloaded, built, installed or run, and no
dependency was added. The [phase plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/05-workflows-and-clients.md)
owns acceptance (row P05.5, decisions P05-D5 and P05-D6).

The execution record is
[p05-native-service-2026-10-02](../testing/evidence/p05-native-service-2026-10-02.md).

## What exists

| Piece | Where | State |
|---|---|---|
| `password-file` credential profile and strict validator | [`ops/file_credential.rs`](../../crates/blindpass-broker/src/ops/file_credential.rs) | Implemented, host-tested |
| `--credential-profile CREDENTIAL=password-file` broker flag | [`main.rs`](../../crates/blindpass-broker/src/main.rs) | Implemented, host-tested |
| Enforcement at `provision_sealed` and at both loader delivery routes | [`lib.rs`](../../crates/blindpass-broker/src/lib.rs) | Implemented, host-tested |
| `example-backup.service`, `example-backup.timer` | [`deploy/examples`](../../deploy/examples) | `systemd-analyze verify` only |
| Broker drop-in `native-backup-broker.conf` | [`deploy/examples`](../../deploy/examples/native-backup-broker.conf) | `systemd-analyze verify` only |
| Two-host harness `p05-backup.sh` + `p05-backup-guest.sh` | [`tests/fleet`](../../tests/fleet) | **Never run**; `bash -n`, gate paths and scanner self-test only |

## Credential profile `password-file` (P05-D6)

The profile is raw password bytes for an application that reads a password file
(restic `RESTIC_PASSWORD_FILE`). The broker accepts a value only when all of these
hold:

- non-empty and at most 1024 bytes (stricter than the generic 64 KiB delivery cap);
- valid UTF-8;
- no Unicode control character anywhere (`Cc`: NUL, CR, LF, TAB, DEL, C1). A
  trailing newline is therefore rejected, reported as
  `password_file_control_character`;
- no leading U+FEFF and no leading or trailing Unicode white space.

Rejections are fixed codes (`password_file_empty`, `_too_long`, `_invalid_utf8`,
`_control_character`, `_byte_order_mark`, `_edge_whitespace`) that never contain or
reflect input bytes.

**Why this strict.** restic reads the file and, to the best of our knowledge of its
upstream source, trims surrounding white space and decodes a byte-order mark. A
trailing newline would then make the repository password differ from the bytes the
operator typed. This is knowledge of upstream behaviour, **not verified against a
pinned binary**: P05-I05 must confirm it with the real restic once approved. The
rules are a safe superset of "trailing CR/LF is stripped".

**No decoding adapter exists.** A JSON envelope, base64 or any other wrapper is
never unwrapped. A JSON-looking value that passes the character rules is accepted
and delivered **as literal password text**, so feeding an envelope to restic fails
repository authentication rather than silently using a different password. An
unkeyed SHA-256 envelope would be only a corruption check anyway (P05-D6).

## Selection and enforcement

`--credential-profile CREDENTIAL=password-file` is repeatable and keyed by
credential name. Startup fails for an unknown profile name, a malformed value, a
duplicate, or a credential no `--map UNIT=CREDENTIAL` names (option order does
not matter). With no flag the behaviour is byte-for-byte the previous one. The
profile applies to every unit mapped to that credential name; do not use a
credential name that a browser-session resource also uses.

| Point | Behaviour |
|---|---|
| `provision_sealed` | Runs after the HPKE open and before any insertion. An invalid value returns the fixed code over the provisioning socket and **nothing is stored**. The one-use recipient key **is still spent** by the open, so the operator needs a fresh `blindpass-provision` run. The destination's existing value and its expiry are unchanged. |
| Delivery (`process_loader`, systemd-credential route) | The stored value is re-validated before any byte is returned. A value that fails (in-memory damage) is purged and the loader connection is closed without bytes. |
| Expiry | The credential lifetime (default 1 h; `--credential-lifetime-seconds` sets 60 s to 7 days) denies delivery after expiry and removes the bytes. |

`blindpass-provision` reads stdin raw, so use `printf '%s'`, not `echo`:

```
printf '%s' "$REPOSITORY_PASSWORD" | blindpass-provision \
    --unit example-backup.service --credential restic-password
```

## Who consumes the plaintext and for how long

| Holder | Lifetime and limits |
|---|---|
| Operator/provisioner | The pipeline above; the value is read from stdin and is not placed in argv. |
| Broker custody (root, memory only) | From a successful provisioning until the credential lifetime (default 1 h, at most 7 days by `--credential-lifetime-seconds`), broker restart or reboot. Never written to disk by the broker. |
| systemd credential file | Copied into a private tmpfs for the unit's lifetime (`%d`, readable by `User=`). The unit may read, copy or retain it. |
| restic | Reads the file and keeps the repository password in process memory for the run. The service is a trusted plaintext recipient; the broker cannot limit what it does with the value. |

## Startup, rotation and restart contract

- **No unattended restart is claimed.** The broker holds credentials in memory
  only. After a broker restart or reboot `LoadCredential=` fails closed (systemd
  aborts the start before any `ExecStartPre`) until the operator re-provisions.
  The default lifetime is one hour, so a daily timer run finds a credential only
  when the operator provisioned within the preceding hour. `--credential-lifetime-seconds`
  (60 s to 7 days, default 3600) lets an operator choose a longer window; that keeps
  a plaintext copy in broker memory for as long as the window lasts, so it is an
  explicit risk decision and the credential still vanishes at every broker restart or
  reboot. The timer is a trigger for an attended window, not an unattended backup claim.
  Unattended operation needs the selected persistent custody/unlock/recovery path
  with reboot tests, which is not implemented here.
- **Bound.** The plan's "consumer credential availability within 5 s of unit
  start" applies to a **pre-provisioned** credential. A host test measures the
  production handler over a real Unix socket (identity step replaced by a fixed
  root peer) and bounds it at 5 s; observed time is in the evidence file. The real
  systemd and kernel identity path is covered only by the unrun VM harness.
- **Controlled rotation.** Provision the new bytes (the destination keeps exactly
  the latest value), then start the unit again; a new invocation reads the new
  value. Repository password rotation under test is `restic key passwd` on the
  existing repository followed by re-provisioning (no re-init); a stale credential
  must be refused by the unit's own `restic cat config` check.
- **Recovery.** Re-provision, then `systemctl start example-backup.service`.
  Operator logout does not affect a running job (the unit belongs to the system
  manager); this is asserted only by the unrun harness.

## Rollback of `--credential-profile`

Remove `--credential-profile restic-password=password-file` from the broker
drop-in (or delete the drop-in) and restart the broker. The credential then loads
without validation as before, and the in-memory value must be re-provisioned
because a restart discards it. No data or manifest migration exists.

## What is not claimed

- No real restic or rest-server run of any kind: P05-I05 and P05-E02 do not pass,
  and the harness's assumptions about restic output (`wrong password`,
  `key passwd --new-password-file`, `--limit-upload`) are unverified.
- `MemoryDenyWriteExecute` is deliberately not set in the example unit: it is not
  proven compatible with the Go runtime of the reviewed binary, and a denial
  appears as a runtime crash that static verification cannot predict.
- No unattended reboot or restart behaviour, no persistent custody, no TPM claim.
- No claim that the unit hardening works with restic; it is verified only by
  `systemd-analyze verify` with the binary path substituted.
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` permits any IP destination
  because the repository is remote; pin it with `IPAddressAllow=` locally.
- The loader-socket identity path (pidfd unit/invocation) and the profile are
  proven together only by host fixtures, not by a VM run.

## Blocked on ADR 0007

Approval of reviewed restic and rest-server artifacts (exact SHA-256 values),
then a run of `tests/fleet/p05-backup.sh` with `RESTIC_BIN`, `REST_SERVER_BIN`,
`RESTIC_SHA256` and `REST_SERVER_SHA256`, on the pinned guest image, recording OS,
kernel, systemd, restic and rest-server versions. Until then the script exits 77
with `blocked: reviewed restic/rest-server artifacts not provided (ADR 0007)`.
