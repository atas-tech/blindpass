# P05.5 native service: repository-side execution — 2026-10-02

## Scope and verdict

Working tree uncommitted on top of `1a37bbe`. Host: Linux 7.2.3-arch1-3, systemd 261
(`systemd-analyze`), rustc/cargo 1.98.1. This record covers the broker credential
profile, its enforcement and host tests, the example units, and a gated two-host
harness.

**P05-I05 and P05-E02 are NOT passed and have not been run.** The real restic and
rest-server artifacts are `block_pending_human_review`
([ADR 0007](../../product/decisions/0007-p05-native-backup-dependency-review.md)).
No restic, rest-server or Go toolchain was downloaded, built, installed or run, and
no manifest or lockfile changed (dependency-guard: no dependency was added,
upgraded or removed). No VM was started. The design and limits are in
[p05-native-service](../../product/p05-native-service.md).

## Commands and results

All cargo commands ran from the repository root with
`CARGO_TARGET_DIR=/home/hvo/Projects/blindpass/target/agent-f` outside the sandbox
(Unix socket tests).

| Command | Result |
|---|---|
| `cargo test -p blindpass-broker --locked -- --test-threads=1` | **310 passed, 0 failed** (297 library + 5 `main.rs` + 2 credential-loader + 6 other binary tests). Baseline before this work: 291. New: 17 library tests in `ops::file_credential::tests` and 2 in `main.rs` |
| `cargo clippy -p blindpass-broker --all-targets --locked -- -D warnings` | Clean, no warnings |
| `rustfmt --edition 2024 --check crates/blindpass-broker/src/ops/file_credential.rs crates/blindpass-broker/src/main.rs` | Clean (`lib.rs` was edited only with small targeted edits and not reformatted) |
| `cargo test -p blindpass-broker --locked --lib file_credential -- --test-threads=1 --nocapture` (three repeats) | 17 passed each time, 1.01 s |

### Tests first

The module, the `lib.rs` hooks and `main.rs` were first compiled with stubs that
accept everything. Result before implementation: library
`file_credential` **11 failed, 6 passed** (the 6 passing were tests of behaviour
the stubs did not change: rotation, expiry, restart, frame length, startup bound and
the plain-accept case); `main.rs` **2 failed, 3 passed**. After implementing the validator, option resolver and gates: all passed.

### Tests added

`ops::file_credential::tests` (library):
`password_file_accepts_plain_passwords_and_json_looking_text_literally`,
`password_file_rejects_empty_oversized_and_non_utf8`,
`password_file_length_boundary_is_exact`,
`password_file_rejects_every_control_character_including_a_trailing_newline`,
`password_file_rejects_leading_or_trailing_whitespace_and_a_leading_bom`,
`password_file_errors_are_fixed_codes_that_never_contain_bytes`,
`profile_options_accept_repeated_mapped_credentials`,
`profile_options_reject_unknown_unmapped_duplicate_and_malformed_values`,
`invalid_plaintext_is_rejected_after_open_with_a_fixed_code_and_nothing_stored`,
`rejected_provisioning_keeps_the_existing_credential_and_its_expiry`,
`rotation_delivers_exactly_the_latest_provisioned_value`,
`credential_lifetime_expiry_denies_delivery_and_leaves_no_bytes`,
`broker_restart_loses_custody_and_delivery_fails_closed_until_reprovisioned`,
`a_damaged_stored_value_fails_closed_without_bytes_and_is_purged`,
`delivered_frame_length_equals_the_credential_length`,
`the_profile_is_scoped_to_its_credential_and_legacy_delivery_is_unchanged`,
`a_preprovisioned_credential_is_available_within_the_five_second_startup_bound`.

`main.rs`: `credential_profiles_install_for_the_mapped_credential_only`,
`credential_profile_startup_errors_occur_before_the_broker_runs` (unknown profile,
unmapped credential and missing value all error before `run`).

What they establish (host, in process): the validator rules and fixed codes;
rejection happens after the HPKE open and before insertion; the one-use key is
spent; an existing value and its expiry survive a rejected provisioning; the latest
provision wins exactly; expiry denies delivery and leaves no bytes; a fresh broker
state (restart) delivers nothing until re-provisioned; a damaged value closes the
loader stream without bytes and is purged; delivered length equals credential
length for 1, 17, 512 and 1024 bytes; an unprofiled credential is delivered
byte-for-byte as before; a JSON-looking value is accepted only as literal text.

Startup bound: `P05-STARTUP-BOUND connect_to_eof_ms=0 bound_ms=5000` (three runs,
all under 1 ms). This is the production handler (`serve_connections`,
`handle_systemd_credential_connection`) over a real Unix socket created with
`bind_socket`, with the kernel pidfd/unit identity step replaced by a fixed root
peer fixture. It is not a measurement of systemd `LoadCredential=` or of real peer
identity resolution.

## Static verification of units

`systemd-analyze verify` on the committed files fails only because the referenced
`blindpass-broker.service` and `/usr/local/bin/restic` do not exist on this host:

```
example-backup.service: Failed to create example-backup.service/start: Unit blindpass-broker.service not found.
example-backup.service: Command /usr/local/bin/restic is not executable: No such file or directory
```

To check every directive, copies were verified in a scratch directory with the
restic path substituted by `/usr/bin/true`, the shipped `blindpass-broker.service`
(binary path substituted) and the drop-in beside it:
`systemd-analyze verify ./blindpass-broker.service ./example-backup.service ./example-backup.timer`
printed nothing and exited 0 (rerun after the final unit edits). The timer
calendar `daily` normalizes to `*-*-* 00:00:00`. This checks syntax and known
directives only; nothing about runtime behaviour, hardening compatibility with a Go
binary, or credential loading from the broker socket.

## Harness (never run)

| Check | Result |
|---|---|
| `bash -n tests/fleet/p05-backup.sh`, `bash -n tests/fleet/p05-backup-guest.sh` | Syntax OK |
| `shellcheck` | Not installed on this host; not run |
| `./tests/fleet/p05-backup.sh` with no environment | Exit 77, `blocked: reviewed restic/rest-server artifacts not provided (ADR 0007)` |
| `--check-artifacts` with one artifact unset, a wrong SHA-256 for either, a malformed or upper-case SHA-256, a missing file, a non-executable file | Exit 77 each, with a `P05-BLOCKED-DETAIL` reason |
| `--check-artifacts` with two dummy shell scripts and their correct SHA-256 values | Exit 0, `P05-ARTIFACTS-VERIFIED ... (hashed only, not executed)`; the gate only hashes files |
| Unknown option | Exit 2, usage |
| Offline canary-scanner self-test (host, non-root, temp directories, runtime-random canaries) | Clean tree passes with `control=detected`; a planted file fails with the file code; a canary in a live process argument and in a live process environment each fail with the process code; a canary only inside the excluded oracle directory passes; a missing root fails; a scanner that cannot see its planted control fails closed |

The scanner self-test sources `p05-backup-guest.sh` (its `main` is guarded) and runs
only `scan_canaries` against temp directories; no guest subcommand that executes
restic or rest-server ran.

## What the harness would cover once artifacts are approved

Provisioning through the real `blindpass-provision` HPKE path; the ordinary unit
without MCP; restore and byte comparison; four `password-file` rejections
(trailing newline, oversized, invalid UTF-8, empty) with the previous value
surviving; JSON text accepted literally and refused by repository authentication;
a native `LoadCredentialEncrypted=` unit derived from the same example (initial,
while the broker is empty, stale after rotation, re-encrypted); broker restart
causing a credential-step failure with no snapshot; operator logout during a
throttled job; rotation by `restic key passwd` with stale denial, re-provision,
restart and repeat; file, process and journal canary scans (the journal scan
reuses `assertScannedClean` from `tests/browser-handoff/journal-canary-scan.mjs`
with its positive controls); version records. None of it has executed.

## Open

- P05-I05 and P05-E02: real restic/rest-server runs, blocked on ADR 0007.
- Real systemd `LoadCredential=` from the broker socket with the profile, real
  peer identity, real fixed-account and DynamicUser denials for this unit.
- Confirmation of restic's password-file handling (white space trimming, BOM) and
  of the `wrong password` message, `key passwd --new-password-file` and
  `--limit-upload` assumptions against the pinned binary.
- Selected persistent custody and reboot behaviour; no unattended claim.
- `MemoryDenyWriteExecute` compatibility with the Go binary.
- `shellcheck` of both scripts.

## Files

New: `crates/blindpass-broker/src/ops/file_credential.rs`,
`deploy/examples/example-backup.service`, `deploy/examples/example-backup.timer`,
`deploy/examples/native-backup-broker.conf`, `tests/fleet/p05-backup.sh`,
`tests/fleet/p05-backup-guest.sh`, `docs/product/p05-native-service.md`, this file.
Edited: `crates/blindpass-broker/src/ops/mod.rs`, `crates/blindpass-broker/src/main.rs`,
`crates/blindpass-broker/src/lib.rs` (re-export, one state field and initializer, one
call at provisioning and one at each of two delivery routes), `tests/fleet/README.md`.
