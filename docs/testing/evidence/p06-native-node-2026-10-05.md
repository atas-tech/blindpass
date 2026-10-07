# P06 real broker and node against the packaged native controller, and the native stale source — 2026-10-05/06

**Status:** actual end-to-end evidence on the uncommitted tree above `8a595ad`; P06 acceptance remains false. This closes the gap the native records listed ("the native recovery run has no real node: one seeded broker trust row is covered only by a named waiver"): a real `blindpass-broker` and `blindpass-node` in one QEMU/KVM guest enrolled to, were recovered into, and were reactivated against the **packaged native controller** in a second QEMU/KVM guest, and the original native controller was refused while the restored one served. The authority is the controller guest's own PostgreSQL (not independent of the controller host); one host, x86-64 only.

## One product bug found and fixed (test first)

**The packaged backup unit refused a remote direct-TLS configuration.** `docs/deploy/native-quickstart.md` tells an operator who wants a remote direct-TLS controller to set `BLINDPASS_LISTEN` (a wildcard address) in `/etc/blindpass/controller.env`. `blindpass-controller-backup.service` loads that file but, unlike the serving units, receives no TLS credential (it should not hold the private key). `Config::from_env` then applied the serve-time rule "no unrestricted bind without TLS or a proxy" and the backup job exited 1 with `backup controller configuration invalid`. A natively packaged remote controller therefore could not take a backup. The harness found it: runs 1 and 2 failed at stage `backup` with that string and the unit's `Result=exit-code`.

- Fix: `Config::from_env_offline()` / `from_variables_offline()` pin the bind to loopback before validating (every other rule still applies) and are used by `backup create` (`backup.rs`) and the handoff export and abort commands (`handoff.rs`), which never listen and never receive the certificate. Serving, `check-config`, migrate, upgrade and reconcile-clock keep the full rule.
- Test first: `deployment_proxy::p06_x02b_offline_tools_do_not_inherit_the_serve_time_bind_rule` was written first and failed red (no such constructor: compile error E0599); after the change it passes, and it also asserts that serving without TLS or a proxy on a wildcard bind stays refused and that bad origins are still refused offline. `p06_x02` (the existing wildcard rule) still passes.
- Not covered by a unit test: the handoff commands' use of the new constructor (only the Rust change and the existing handoff VM run exercise it).

## The harness

`tests/fleet/p06-native-node-vm.py --archive FILE [--bin-dir DIR] [--os ubuntu-24.04|debian-12] [--controller-image PATH --controller-image-sha256 HEX] [--scenario main|waiver]`, with the controller-guest driver `tests/deployment/native-node-guest.py` (imports the helpers of `native-guest.py`, which gained a `main()` guard so it can be imported). It reuses the node guest, enrollment, grant and relay code of `p06-relay-vm.py` unchanged and adopts the stage structure of `p06-compose-node-vm.py`. How to run: [tests/fleet/README.md](../../../tests/fleet/README.md).

- **Guest C (controller).** The pinned image (Ubuntu 24.04 `noble-server-cloudimg-amd64.img`, sha256 `612b2c0c…`; Debian 12 `genericcloud-amd64-20260923-2610.qcow2`, sha256 `7b3faf64…`, sha512 matches the `SHA512SUMS` entry), a grown 8 GB overlay, 2 GB RAM, 2 vCPUs. The packaged native controller is installed from the **freshly built bookworm-baseline archive** (`docker build --file scripts/release/Dockerfile --target export`, then `scripts/release/build-tarballs.sh --profile controller --arch x86_64 --allow-dirty`; final archive sha256 `345510f0…`, built after the fix above) by `controller-install.py` exactly as the native lifecycle gate does: `--public-url https://p03-controller:8443`, `--initialize-keys` with `--tls-cert/--tls-key`, authority registration, `--initialize`, `--start`, one authority activation.
- **TLS (the shipped way, built-in TLS, not proxy mode).** A throwaway test CA (its key never leaves the host and is deleted after signing) signs a leaf for `p03-controller` and `localhost`; the installer copies the leaf pair into `/etc/blindpass/controller-tls` and systemd delivers it with `LoadCredential`. The one documented operator step for a remote direct-TLS deployment is applied: `BLINDPASS_LISTEN=0.0.0.0:3200` in the protected config (the installer starts on loopback). Nothing else in the config or units is edited.
- **Authority.** The guest's own PostgreSQL 16 (database `p06_authority`, runtime role, the shipped SQL scripts), as in `native-install.sh`. It is not independent of the controller host.
- **Network.** Both guests use QEMU user networking. C forwards host `127.0.0.1:8443` to its listener (guest port 3200) with `hostfwd`. Guest N resolves `p03-controller` to the QEMU gateway `10.0.2.2`, which reaches that forwarded host port; N's system trust store holds the test CA. The operator's API calls come from the host through the same forward. A QEMU socket netdev was not used: the host forward needs no guest network configuration and keeps both guests on the P01 provisioning path.
- **Guest N (node).** The unmodified `blindpass-broker`, `blindpass-node` and `blindpass-workload-client` from the same bookworm export directory as the archive, under the P03 systemd units, Ubuntu 24.04 in every run (the packaged node archive from `release-node-archive.py` was **not** used). `blindpass status --nodes --require-online` runs in N over verified HTTPS.
- **Operator actions are the shipped ones:** `blindpass-controller-backup.service`, `blindpass-controller-restore.service` (operator-written environment file and offline custody, removed after the run of the unit), `blindpass admin bootstrap` and `blindpass admin recovery …` as the service account on the admin socket, and the authority administrator scripts through `psql`.
- **Restore location: a second private path on C, not a second controller guest.** The unit restores into `/var/lib/blindpass/controller-restore/root`; the harness then installs the restored `data` and `keys` into the service paths after parking the original state and keys (`/var/lib/blindpass/p06-source-data`, `/etc/blindpass/p06-source-keys`, byte-intact), because the packaged unit has one fixed set of paths.

## Results

All exit 0. Run output is in the session scratchpad and is not committed. "PASS lines" count every `PASS` line the run printed including the final summary line.

| Run | Result |
|-----|--------|
| Ubuntu 24.04 `--scenario main`, twice (`main3`, `main4`) | 19 PASS lines each |
| Ubuntu 24.04 `--scenario waiver`, once | 12 PASS lines |
| Debian 12 controller guest, `--scenario main`, once | 19 PASS lines |

The first `main` pass (`main3`) and the second (`main4`) differ in one harness line only (how the activation-script refusal text is printed after `main3`); the guest stages are identical. Two earlier runs (one full, one `--until backup`) failed at `backup` because of the product bug above and are not counted.

Scenario IDs (`main`): S1 controller serving over verified HTTPS through the host forward with an operator session; S2/S2c real broker and node enrolled over verified HTTPS, the authority holds its broker trust, `status --nodes --require-online` passes from N; S2b one real grant approved by a second operator and consumed by a workload; B1 the packaged backup unit sealed one split-custody archive (574,395 bytes, 0.8–1.3 s) while the controller kept serving and the node stayed online, and the host's own signing credential cannot open it; F1 the source fenced in the authority (`fenced:1:3`), stopped, its state and keys parked, recovery reserved (`recovering:2:4`); S3 restore through the packaged unit (host custody refused, no-operator-input skipped, receipt `recovery_required`, keys byte-identical, staging and credential copy gone), installed and started: 503 on the same name, port and certificate; G1 ordinary activation, early recovery activation (names `source_stop_missing`, `review_incomplete`, `node_uncovered`) and a premature attestation refused with the record unchanged; V1 four review categories decided, completion refused while the real node is neither covered nor waived; R1 `blindpass-node recovery-relay` from N prints `recovery_relay state=covered pages=1 activation_permitted=false`, the authority and precheck show the node covered, ordinary routes still 503; V2 completion succeeds once covered (`nodes_revoked: 0`); A1 only `source_stop_missing` remained, attestation after stopping the service, activation `recovering:2:4 -> active:2:5`, ordinary script and second activation refused; S4 node online (below); S5 an ordinary grant approved by a second operator and consumed by a workload after activation; S6a/S6b the stale source (below); L1 log scan.

`waiver`: W1 completion refused while the node is neither covered nor waived, unknown waiver refused, a waiver by name revokes its broker trust and completion revokes it locally (`nodes_revoked: 1`); A1 as above; W2 the controller activates without the node, which stays `revoked` (its reconnect attempts for 15 s do not bring it back), the online gate fails for it and its broker trust stays revoked.

**Refusal variants with the real node:** uncovered is refused (V1: completion refused with the node neither covered nor waived, `node_uncovered` stays in the precheck); covered succeeds (V2 after R1); waived succeeds and leaves the node revoked (W1/W2).

### Reconnect after activation (S4)

Time from `systemctl start` of the activated controller until `status --nodes --require-online` passes from N with `last_seen_at` newer than the start (the P06 plan's 120 s bound), the start time and `last_seen_at` both taken from guest C's clock:

| Controller guest | Runs | Time to node online |
|---|---|---|
| Ubuntu 24.04 | `main3`, `main4` | 3.1 s, 3.1 s |
| Debian 12 | `debian1` | 4.3 s |

The controller reported ready 0.3 s after start in every run. After the stale-source drill the restored controller was re-activated once and the node was online 0.6 s after start (all three runs). Three samples on one host with a loopback-forwarded guest say nothing about WAN reconnect or a loaded host.

### Native stale source (S6a, S6b): exact refusals

While the restored controller serves (S6a), recorded as printed:

- the ordinary activation script was refused by the authority with `could not obtain lock on row in relation "process_guard"` (the live restored holder owns the guard row; the first Ubuntu run saw the trigger context line `blindpass_authority.protect_recovery_authority() line 16 at PERFORM`, the same refusal);
- the ORIGINAL state and keys, started as a second instance of the packaged unit (a copy of the effective unit text from `systemctl cat`, with only the state, key, runtime, environment-file and listen paths changed and the original state in `/var/lib/blindpass/p06-source-data`), never ran: unit result `exit-code`, exit status 1, and the controller's JSON startup failure `{"event":"startup_failed","reason":"fenced"}` (the generic authority-claim refusal of `ownership_session.rs`: this process holds no usable activation while the record's activation is consumed by the serving holder); it bound no listener on its port;
- the serving controller stayed ready, the authority record `active:2:5` did not change and the node stayed online (`status --nodes --require-online` from N).

With the restored controller stopped (S6b): the original state and keys swapped into the service paths and an **ordinary** authority activation granted, the packaged service was refused with `startup_failed` reason `recovery_required` (the original state carries no activation of the recovered epoch), and its SQLite database file (sha256 recorded at fence time) was byte-unchanged. The restored state was swapped back and re-activated once (P06-D12: one activation per start); the node came back online in 0.6 s. The original controller therefore cannot be activated or served again by an authority record that has moved to the recovered epoch, either alongside the restored controller (authority guard) or in its place (state refused).

### Log scan (L1)

A scan of the packaged controller, backup, restore, initialize and stale-instance journals (about 106 kB, 6 canaries: bootstrap, operator and approver passwords, the enrollment token, the authority password) and of the node guest's broker and node journals found no canary and no `PRIVATE KEY-----`.

## Gates

On the tree above, one at a time:

- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`: clean.
- `cargo test --workspace --locked --offline`: **775 passed, 0 failed, 150 ignored** (the new test is the one added over the previous 774; the ignored cases run through the authority driver or in-image scripts and were **not** rerun for this change).
- `tests/deployment/{container-config-test,controller-sbom-test,native-package-test,release-artifacts-test,native-authority-test}.py`: pass.
- Native matrix and host harnesses on the rebuilt archive: see the table in the next section.

## Gate matrix after the Rust change

Run by the same session on an archive and node binaries rebuilt from the tree after the Rust change (bookworm-baseline export, `build-tarballs.sh --allow-dirty`, sha256 recorded by the build), one at a time with `BLINDPASS_NATIVE_RUN_ROOT=/dev/shm`, all exit 0. "PASS" counts every `PASS` line including the final summary line:

| Run | Debian 12 | Ubuntu 24.04 |
| --- | --- | --- |
| default (N01–N10 incl. forward upgrade) | 13 | 13 |
| `--power-loss` | 14 | 14 |
| `--tool-faults` | 15 | 15 |
| `--credential-faults` | 28 | 28 |
| `--recovery` (NR01–NR05 through the shipped restore unit) | 18 | 18 |
| `--faults` (NF1–NF3) | 16 | 16 |

Two-guest scenarios on that archive (controller guest Ubuntu 24.04, node guest Ubuntu 24.04): `p06-native-node-vm.py --scenario main` 19 PASS lines, `--scenario waiver` 12 PASS lines, both exit 0. The Debian 12 controller-guest `main` run recorded above predates this archive and was not repeated after the Rust change. The Compose, relay, handoff, activation and matrix harnesses were not rerun after the offline-configuration change (it touches `backup create` and the handoff export/abort commands only).

## Test order and honesty

- The bug fix is test-first (red compile failure, then green). The harness and the guest driver were written **after** the packaging code existed and were run against the packaged archive until they passed, so they are not red/green proofs; the harness failed first on the product bug above and, before that, only on harness details that were fixed before any scenario step that matters.
- The `main` pass counts above include the final summary line.
- The harness reuses the shared relay stages unchanged; nothing in `p06-relay-vm.py` was edited, so its other consumers were only rerun as listed in the gate matrix.

## Limits

- One host, x86-64 only; the aarch64 native package was not exercised.
- The authority is the controller guest's own PostgreSQL. The controller host can therefore rewrite it; the "independent authority" property is not shown here (the Compose runs use a separate container, still not a separate trust domain).
- The stale-source evidence covers a stopped source on the same machine: the second instance runs on the same guest and the swap uses the same service paths. A source still running on another machine is covered only by the authority guard and the operator's attestation (unchanged from the Compose record).
- One controller guest and one node guest, Ubuntu on the node side every time; Debian 12 was run for the controller guest only, once.
- Network: QEMU user networking with a host forward; no firewall, NAT traversal or WAN latency. Reconnect times are three samples.
- The node binaries are the bookworm export, not the packaged node archive, and the node units are the P03 test units, not the packaged native node profile.
- The native node is not enrolled through the packaged `blindpass-node` service environment (`blindpass-node.env.example`); it is the P03 harness's enrollment.
- PostgreSQL controller backends are not part of the native package (SQLite only).
- The test CA is a self-contained throwaway chain; no public CA or ACME renewal was exercised.
- The handoff export/abort use of the offline constructor has no dedicated unit test.
- No hosted CI, image publication or independent cryptographic review was run. P06 acceptance is not claimed.
