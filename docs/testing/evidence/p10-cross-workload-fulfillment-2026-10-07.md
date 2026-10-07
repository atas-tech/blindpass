# P10 execution record — cross-workload fulfillment (2026-10-07)

**Scope:** mode `reencrypt` only: one operator-approved, one-use re-encryption of a credential from an issuer workload's broker to a
recipient workload's broker on another node. No provider adapter, no scoped-credential issuance, no brokered action. Off by default
(controller `BLINDPASS_FULFILLMENTS_ENABLED=1`; brokers `--fulfillment-source` / `--fulfillment-destination`).
**Result:** workspace gates green (Rust 914 passed / 0 failed; console 171; `npm test` exit 0), the controller suite green on SQLite and
PostgreSQL, the authority-database suites that touch the changed fixtures green, and the real two-guest scenarios below passed on both
controller stores. **Not accepted:** no operator named the need (activation was an owner instruction, the P09 precedent), hosted CI has not
run, and nothing is pushed or published. See [Not executed and limits](#not-executed-and-limits).

Contract: [cross-workload-fulfillment.md](../../product/cross-workload-fulfillment.md). Harness:
[fleet README](../../../tests/fleet/README.md#p10-cross-workload-fulfillment).

## Commits

Baseline `6caa684` (P09). All local; none pushed.

| Slice | Commit |
|---|---|
| 1 contract and plan verification | `4fa9739` |
| 2 core terms, one-use offer, signed documents | `4716dfc` |
| 3 controller schema 20, store state machine, recovery invalidation | `4ff8783` |
| 3 controller API, `cross_workload` policy, node events, sweeps | `e326583` |
| 3 controller suite and schema-20 fixtures | `ff0f0db` |
| 3 broker fulfillment book, control surface, rotation | `79bb90c`, `e813bb9`, `5eec90a` |
| 3 node relay | `cbf756a` |
| 4 console | `8c34f23` |
| 5 VM harness | `aefc3ec` |
| fixture repair, formatting, lint exception, docs | `a41354f`, `0ff0d46`, `32b897e`, `9bd258c` |

## Rust and console gates

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 (after formatting three P10 files, `0ff0d46`) |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | the first run failed on one `result_large_err` in `routes/fulfillments.rs`; fixed with the project's standard exception (`9bd258c`); the rerun finished with no diagnostics |
| `cargo test --workspace --locked --no-fail-fast -- --test-threads=2` | 97 binaries: **914 passed, 0 failed, 151 ignored** (the ignored cases need the owned PostgreSQL authority driver; the ones this change touches are below) |
| P10 binaries in that run | `fulfillment_contract` 16, `fleet_fulfillments` 25, broker 353 + 8, node 40 + 6, core 60 |
| `npm run build` | exit 0 |
| `npm test` | exit 0 across agent-skill (18), browser-ui (64), console (171 in 14 files), gateway (9), i18n key validation, MCP server (108), openclaw-plugin (123 passed, 2 skipped) and the remaining workspace suites; the `contract-tests` HTTP suite needs `SUT=rust` and was not part of this command |

The workspace run is the SQLite default. The doctest step failed once while the console `dist` was being rebuilt in parallel
(embedded asset names changed under a cached build script); the rerun passed with 0 doctests.

### PostgreSQL controller pass

`P02_TEST_BACKEND=postgres` against a disposable `postgres:16-alpine` container, whole `blindpass-controller` package:

| Run | Result |
|---|---|
| First whole-package pass | 60 binaries ok; `store_transitions` 34 passed, **2 failed** |
| Cause | The migration fixture's drop list stopped at migration 0016, so `DROP TABLE operations` was refused by the foreign key from the 0017 recovery tables (and migration 0020's tables add more). The fixture file was not touched by P10 and fails in its PostgreSQL branch only. I did not run it at the baseline, so that it predates P10 rests on the unchanged drop list and the 0017 migration, not on a baseline run |
| Fix | `a41354f` drops the later-migration tables first (all later migrations are `IF NOT EXISTS`, so the migration under test recreates them) |
| `store_transitions` rerun | 36 passed, 0 failed |
| `fleet_fulfillments` on PostgreSQL | 25 passed |

### Authority-database suites (`tests/deployment/recovery-authority-postgres.py`)

Run on the changed schema-20 fixtures, each against its own generated authority database and roles:

| Target | Backend | Result |
|---|---|---|
| `recovery_invalidation` | SQLite, PostgreSQL | 11 passed each |
| `production_ownership` | SQLite, PostgreSQL | 33 passed each |
| `restore_stage` | SQLite | 24 passed |
| `restore_postgres` | PostgreSQL | 6 passed |
| `store_quiescence` | PostgreSQL | 4 passed (the first call omitted `--controller-backend postgres` and exited 2 on the driver's own argument check) |
| `recovery_activation` | SQLite, PostgreSQL | 10 passed each |
| `recovery_authority`, `recovery_authority_migration`, `recovery_receipts` | PostgreSQL authority | exit 0 each |
| `legacy_authority` | SQLite, PostgreSQL | exit 0 each |
| `deployment_startup` | n/a | exit 0 |
| `fleet_provisioning_submit --filter p06_la05` | PostgreSQL | exit 0 |

The last six rows were run after the first version of this record, as exit codes of the driver (each log is private to the run).

## Console browser journeys (`packages/console/e2e/fulfillments.spec.ts`)

Chromium against the real controller started by the e2e stack with `BLINDPASS_FULFILLMENTS_ENABLED=1`; both nodes are the JavaScript `FleetNode` fixture, so nothing is sealed, delivered or read in these runs (the VM harness covers that). 4 tests passed on the `vite preview` profile on SQLite, on the embedded-console profile on SQLite, and on the preview profile on PostgreSQL (a throwaway schema in the existing fixture):

| Test | What it showed |
|---|---|
| P10-E01 GUI | The requester sends a request with an HTML-looking purpose; the requester's own review shows why they cannot decide and the approve and reject buttons are disabled; the named approver sees both enrolled fingerprints (compared without the console's grouping), the policy rule and the purpose as plain text (no injected element), approval is disabled until the confirmation is ticked, then the recipient node's inbox holds a `fulfillment_authorization` and the issuer node's does not (it waits for the recipient's offer) |
| P10-E01 GUI revoke | Revoking asks for confirmation, states that anything already read cannot be recalled, ends the fulfillment, and the row makes no provider claim because nothing was stored yet |
| P10-I01 GUI | The reversed pair is refused with the policy explanation; a viewer has no Fulfillments link, page or buttons |
| P10-E02 GUI | With the controller flag off the console shows no Fulfillments link or request button |

The spec's first runs failed twice on the spec's own assumptions (a disabled button asserted as absent; a grouped fingerprint and a provider note that is only shown after storage); the console code was not changed.

## Two-guest VM scenarios (`tests/fleet/p10-vm.py`)

Host: a production-mode, authority-backed controller with built-in TLS and `BLINDPASS_FULFILLMENTS_ENABLED=1`. Two disposable QEMU/KVM guests
from the pinned Ubuntu image (A: issuer broker and node holding a generated dummy credential; B: recipient broker and node with eight
recipient units). Brokers run the shipped units with a drop-in adding `--map`, `--fulfillment-source` and `--fulfillment-destination`. A
recipient unit loads the credential through `LoadCredential=` from the root-only loader and presents it to a dummy provider on the host.
The harness ran as the runner owner with the sandbox disabled for those commands; `/dev/kvm` was readable and writable and QEMU 11.1.1 was present.
Run on the working tree at `8c34f23` plus the then-uncommitted harness files, which were committed unchanged as `aefc3ec` and not edited
after the final runs. Both runs executed every scenario (no `--only`):

| ID | SQLite | PostgreSQL | What it showed |
|---|---|---|---|
| S1–S3 | pass | pass | Capability advertised with the flag on; two real brokers and nodes enrolled over verified HTTPS and online; the issuer broker holds the credential; workloads registered; explicit cross-workload rules applied by both brokers |
| P10-I01 | pass | pass | Unruled pair, reversed pair and self-fulfillment denied; unknown body fields (`mode`, a recipient key, `tenant_id`) refused; the requester cannot approve (`approval_scope_denied`); a substituted node fingerprint is `409 authorization_changed` and changes nothing |
| P10-E01a | pass | pass | Approve, offer, seal, deliver, store; the unit loads the credential and the dummy provider accepts it; `completed`; `provider_revocation: unsupported` |
| P10-E01b | pass | pass | A repeat without `prior_fulfillment_id` fails at the broker (`destination_busy`) and leaves the first credential readable; with it the repeat completes |
| P10-I01b | pass | pass | An `allow` rule needs no approval and completes the same path |
| P10-E01c | pass | pass | A `deny` rule refuses before any node is contacted; the recipient unit loads nothing |
| P10-E01d | pass | pass | Revoked after delivery and before the read: the recipient broker removed the unread credential; `delivery_revoked_at` set, `provider_revocation: unsupported` |
| P10-I03 | pass | pass | Revoking a completed fulfillment changes nothing; the unit still loads the credential and the provider still accepts it. No remote erasure is claimed |
| P10-I04a | pass | pass | Issuer node partitioned after approval (held `offered` 8 s), reconnected, controller restarted in flight: one legal completion; controller ciphertext deleted |
| P10-I04b | pass | pass | Recipient broker restarted after delivery: the unit could not read; closed `expired` within its 60 s bound; never resumed |
| P10-E02 | pass | pass | Feature disabled with a pending fulfillment: revoked at startup (`feature_disabled`), `features.fleet_fulfillments: false`, new issuance `404 fulfillments_disabled`, the recipient broker holds nothing; re-enabled on restart |
| P10-S | pass | pass | The dummy credential (raw, base64, base64url, hex) is in no audit row, controller store row, controller log, and on both guests no file under the state, runtime, unit and temp directories, no argv or environment, no journal line. Each scan first found a planted value |

Earlier attempts while building the harness failed for harness reasons and changed no product code: a refused loader read reaches the unit as
an *empty* credential (the unit now reports that instead of contacting the provider); the first revoke check read the credential before the
revocation was applied (a read credential cannot be recalled, as the contract says; it now waits for the node inbox acknowledgement); a
production-mode controller fences its authority on stop, so restarts reactivate it with `authority-activate.sql`; and the capability flag is
`features.fleet_fulfillments`.

## Mapping to the acceptance plan

| Plan ID | Evidence | Gap |
|---|---|---|
| P10-I01 | Controller tests (`p10_i01_*`) on both stores; VM P10-I01, I01b, E01c | Mode and tenant substitution are refused as unknown fields; there is no separate recipient-key field to substitute |
| P10-I02 | Controller tests (`p10_i02_*`) and broker/core tests: offer and submit substitution, digest, HPKE context and signature alterations, rotation, policy/workload/node changes | Not repeated in a VM: ciphertext copied to another node, a race between retrieval and fulfillment, rotation of the recipient key mid-flow |
| P10-I03 | VM P10-I03, E01d; `provider_revocation` is `unsupported` everywhere | No provider adapter exists, so no real provider credential was issued or revoked |
| P10-I04 | Controller tests (`p10_i04_*`), recovery invalidation (authority suites), VM P10-I04a/b | A reply lost on a live connection and a stale restore were not run in a VM |
| P10-E01 | VM P10-E01a–E01d, I01b | The "actual task" is a dummy provider call, not a real provider |
| P10-E02 | Controller `p10_e02_*`; VM P10-E02 | |
| Pilot X01 / X02 / X03 | As P10-I01+E01 / I02 / I04 above | X02 and X03 are only partly VM-backed, as listed |

## Not executed and limits

- **Need and acceptance.** No operator named a cross-workload need; the reference task uses dummy data. The phase is **not accepted**. Hosted CI has not run. Nothing is pushed or published.
- **Not run:** the rest of the Playwright console suite (only the new `fulfillments.spec.ts` ran; the stack option it needed is additive); the Compose profiles and the packaged native controller with the flag on (the shipped Compose files do not pass `BLINDPASS_FULFILLMENTS_ENABLED` through); node key rotation in flight, a reply lost on a live connection and a stale-state restore inside a VM; a browser run against real brokers (the console journeys use fixture nodes).
- **Provider limits.** There is no provider adapter. A credential read by a unit cannot be recalled and stays valid at its provider after every BlindPass revocation; the API reports `provider_revocation: unsupported`. A broker or node outage delays revocation until the node reconnects or the 10-minute expiry.
- **Trust.** The controller can substitute node keys; the issuer broker trusts the controller-signed terms that carry the node fingerprints the approver bound. The isolation of the fulfillment tables from the v2 code is a convention enforced by a source-scan test, not a database-role boundary.
- **Dependencies.** No dependency, manifest or lockfile changed. The console work ran `npx eslint`, which fetched eslint into the npx cache without a Socket review; nothing from it is in the repository. Run `socket` review before adding any such tool to a manifest.
- **Localization.** The Vietnamese strings for the Fulfillments page were written without a Vietnamese reviewer and need one before release.
- **Hosts.** One host, one OS image. The dummy provider is reachable over cleartext loopback; the credential in those runs is a generated dummy.
