# P06 real broker and node on the shipped Compose profiles — 2026-10-05

**Status:** actual end-to-end evidence on the uncommitted tree above `8a595ad`; P06 acceptance remains false. This closes the gap the earlier Compose records listed ("the packaged-profile runs have no real node"): a real `blindpass-broker` and `blindpass-node` in a QEMU/KVM guest enrolled to, were recovered into, and were reactivated against the **shipped Compose stack** (SQLite and PostgreSQL profiles), through the shipped backup and restore jobs, with the recovery relay, review, attestation and activation. It also records the small PostgreSQL-restore hardening (A1) made first.

## A1: distinguishable refusal for the Compose init hook's empty schema

The Compose PostgreSQL profile creates an empty `controller` schema on first start (`postgres-init/10-controller-schema.sql`). Restoring into that database used to be refused with the same static `authenticated fenced restore refused` as any other non-empty target, so an operator could not tell what to do. Restore still never merges into or replaces anything; only the reason differs.

- `store/backup.rs::require_empty_restore_target` now separates "exactly one non-system, non-public schema holding no objects" from every other non-empty state. `backup/postgres.rs` maps it to one fixed string (`PostgreSQL restore target holds an empty schema: drop it first (docs/deploy/recovery-stage.md)`); `restore.rs` passes only that string through and keeps the static refusal for everything else. The string contains no identifier, path, credential or database text.
- Test first: `restore_postgres::p06_rp06_an_empty_init_schema_is_refused_with_a_distinct_fixed_reason` failed red before the change and passes after (`restore_postgres` 6 of 6 in the pinned-toolkit image). A schema with a table, and a database with two schemas, still get the static refusal.
- Documented in [compose-quickstart.md](../../deploy/compose-quickstart.md) (restore step 4) and [recovery-stage.md](../../deploy/recovery-stage.md) with the operator step `DROP SCHEMA controller CASCADE`.
- Packaged confirmation: the PostgreSQL scenarios below restore into a fresh Compose project's init-hook schema, first see the fixed refusal through the shipped `controller-restore` job, then drop the schema and restore.

## The harness

`tests/fleet/p06-compose-node-vm.py --profile sqlite|postgres [--scenario main|waiver]` ([how to run](../../../tests/fleet/README.md)). It reuses the guest, broker/node enrollment, grant and relay code of `p06-relay-vm.py` and replaces the host controller with two real Compose projects:

- Project A and project B each use `compose.<profile>.yml` plus the shipped initialize, backup and restore overlays, with the controller image built from this tree (`blindpass-p06-controller:node`, `sha256:3d2a5f35…`, 423,335,572 bytes) and `BLINDPASS_PROXY_REQUIRED=1`, so a request that does not come through the trusted edge is refused by the controller itself.
- The authority is one `postgres:16-alpine` container with TLS, the controller connects with `sslmode=verify-full` to `authority.p06.invalid` (the same construction as the Compose gates), and it is attached to both projects' networks.
- The edge is one nginx container on `127.0.0.1:8443` generated from `deploy/proxy/nginx.conf.example`. The harness changes only the two names (`p03-controller`, the guest harness's fixed name, and `p03-input`), the `:8443` suffix of the `Host`/`X-Forwarded-Host` headers (the controller compares them with the authority part of `BLINDPASS_PUBLIC_URL`, port included) and the upstream address. For recovery the **same container** keeps its name, port and certificate; it is attached to project B's network and its upstream is reloaded. The guest trusts the edge's self-signed leaf and reaches it as `https://p03-controller:8443` through QEMU user networking.
- The guest runs the unmodified native `blindpass-broker` and `blindpass-node` binaries from `target/release` under the P03 systemd units.
- Operator actions are the shipped ones: `docker compose` jobs and services, `blindpass admin bootstrap` and `blindpass admin recovery …` inside the controller container, and the authority administrator scripts (`authority-register/activate/fence/recover-attest/recover-activate.sql`) through `psql`. The node-side check is `blindpass status --nodes --require-online` run in the guest over verified HTTPS.

## Results

Six runs, all exit 0 (logs in the session scratchpad; run output only, not committed):

| Run | Result |
|-----|--------|
| `--profile sqlite --scenario main`, twice | 15 PASS lines each |
| `--profile postgres --scenario main`, twice | 15 PASS lines each |
| `--profile sqlite --scenario waiver`, once | 9 PASS lines |
| `--profile postgres --scenario waiver`, once | 9 PASS lines |

Scenario IDs (`main`): S1 stack serving through the edge with an operator session over verified HTTPS; S2/S2c real broker and node enrolled over verified HTTPS, the authority holds its broker trust, the node passes `status --nodes --require-online`; S2b one real grant approved by a second operator and consumed by a workload; B1 the shipped backup job sealed one split-custody archive (574,395 bytes SQLite, 202,171 bytes PostgreSQL) while the controller kept serving and the node stayed online, and the host custody directory holds no decrypt key; F1 the authority fenced the source (`fenced:1:3`) and the source stopped, volumes intact; S3 restore into a SECOND project under a reserved recovery epoch (host custody directory refused; offline custody required; install refuses non-empty volumes; PostgreSQL: the init hook's empty schema refused with the fixed reason, then dropped), edge repointed, `/readyz` 503; G1 ordinary activation, early recovery activation (names `source_stop_missing`, `review_incomplete`, `node_uncovered`) and a premature attestation refused with the record unchanged; G2 the original stack refuses to start while the record is recovering; V1 completion refused while undecided and while the node is neither covered nor waived; R1 the guest's `blindpass-node recovery-relay` reports `state=covered pages=1 activation_permitted=false` through the edge and ordinary routes stay 503; V2 review completed; A1 attested (who and host recorded), activated, ordinary script and second activation refused; S4 the unchanged node returns online (same key version, no re-enrollment) and the recovered operation stays `uncertain`; S5 an ordinary grant after activation is approved and consumed through the activated stack; S6 ordinary authority activation of the original stack refused, the original stack not ready (`startup_failed`, reason `fenced`), the activated controller undisturbed, the original SQLite database byte-identical; L1 no operator, approver, bootstrap or enrollment secret, database or authority password or PEM private key in any Compose, edge or guest broker/node log.

`waiver`: W1 completion refused while the node is neither covered nor waived, a waiver for an unknown node refused, a waiver by name revokes its broker trust and completion revokes it locally; W2 the controller activates and serves without the node, which stays `revoked` (its own reconnect attempts do not bring it back), the online gate fails for it and its broker trust stays revoked.

### Reconnect after activation (S4)

Time from `compose up` of the activated controller until `status --nodes --require-online` passes with `last_seen_at` newer than the start (the P06 plan's 120 s bound for reconnect after activation):

| Profile | Run 1 | Run 2 |
|---------|-------|-------|
| SQLite | 3.1 s | 5.7 s |
| PostgreSQL | 1.6 s | 2.9 s |

The controller reported ready 0.3 s (SQLite) and 1.3 s (PostgreSQL) after `compose up` returned. The harness also prints the time since the source was fenced (18–28 s); that includes scripted operator steps and is not a recovery-time objective. Four samples on one host with a loopback guest say nothing about WAN reconnect.

## Corrections made while building the harness

No product bug surfaced. Harness-only: the first run failed in the edge-configuration self-check (it matched `127.0.0.1` in the example's header comment, not an upstream); the relay grant helper expected a `source` attribute; the port probe failed on TIME-WAIT sockets from the previous run until it set `SO_REUSEADDR`. Each failed before any scenario step that mattered and was rerun from scratch.

## Gates

All run on this tree with the image `blindpass-p06-controller:node` built from it (the driver gates use their own `pgtest` build of the same tree), one at a time:

- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`: clean.
- `cargo test --workspace --locked --offline`: **774 passed, 0 failed, 150 ignored** (the earlier full run had 773 passed; the new test is the A1 case, and the ignored cases are the authority-driver and in-image tests below).
- Authority driver (`recovery-authority-postgres.py`), exit 0 with every test passing: `recovery_authority` 34+34 (SQLite and PostgreSQL controller), `production_ownership` 32+32, `legacy_authority` 4+4, `recovery_invalidation` 11+11, `recovery_activation` 10+10, `restore_stage` 24+24 (the A1 gate on both backends), `recovery_authority_migration` 1, `recovery_receipts` 6, `restore_postgres` 6 (in the pinned-toolkit image, including RP06), `deployment_startup` 5. `store_quiescence` (PostgreSQL controller) exited **1 in the sequence although its four tests passed** and the log has no cleanup trailer; two isolated reruns exited 0 with four passing tests and `owned_authority_cleanup_errors=0`. The failure did not reproduce and its cause is unknown; the aborted run left disposable `p06_authority_*` databases and roles in the fixture container, which I dropped.
- `python3 tests/deployment/{native-authority-test,native-package-test,release-artifacts-test,container-config-test,controller-sbom-test}.py`: pass.
- Compose gates on the new image: `compose-up.py --profile sqlite` and `--profile postgres` (O01–O08, P06-U, F1–F3), `--scenario handoff`, `--scenario recovery` on both profiles, `compose-backup.py --payload-bytes 100000000 --faults` and `compose-backup-postgres.py`: all exit 0.
- Existing QEMU harnesses once each against freshly built release binaries: `p06-relay-vm.py` (SQLite and `--backend postgres`), `p06-recovery-activation-vm.py --scenario main` (both backends) and `--scenario waiver` (SQLite), `p06-handoff-vm.py`, `p06-recovery-matrix-vm.py --scenario both` (SQLite) and `--backend postgres --scenario refusal`: all exit 0.

Not rerun for this change: the native Debian/Ubuntu install matrix, the attested SBOM build (O10/SB01), the aarch64 emulated build, and the remaining PostgreSQL matrix and waiver variants of the host-controller harnesses. The A1 change touches the PostgreSQL restore path, not the native package or the image's package set.

## Limits

- The edge is a test fixture: nginx with the shipped example's directives under test names on a fixed port. Edge access logs are off by design, so the request path is shown indirectly (the controller refuses non-proxied requests, the guest verifies the edge certificate, and nothing else listens on 8443), not by an edge log. Caddy was not used here.
- One Docker host runs both projects, the authority container, the edge and QEMU; the authority is a container, not a managed remote service. No network partition, no slow link, no edge restart during the relay.
- One node, one grant in the archive, none between the backup and the loss: the `unknown` grant mapping and the restore-based rollback were exercised only in the host-controller harness ([activation record](p06-recovery-activation-2026-10-05.md)), not on Compose with a real node. The two-node matrix is likewise host-controller only.
- The node binaries are the native release build, not a packaged node archive installed from the release layout; the controller image is a local build, not a published image.
- amd64 only. The guest image is the pinned Ubuntu 24.04 cloud image. No aarch64 hardware.
- Review decisions were made by a script acting as one operator (`p06cn-operator`); no provider API call, no independent human review, no independent cryptographic review of the relay or attestation design.
- The single-credential legacy custody mode and the SQLite-handoff path were not exercised here.
- P06 acceptance, hosted CI and image publication are untouched.
