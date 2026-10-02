# BlindPass documentation

**Aligned:** 2026-09-26. Source-bound guides, contracts and execution evidence remain here. Product direction, implementation plans, design and history are maintained in the [Obsidian docs vault](https://github.com/tuthan/docs-vault/tree/main/blindpass/docs). P01 includes live HPKE provisioning and dedicated non-root consumers. Revised P01-I01 and P01-I06 checks passed in a clean committed-SHA Ubuntu 24.04/QEMU-KVM run. The user accepted W0 as NARROW for that tested systemd 255, no-TPM profile only; other profiles and named evidence gaps remain open.

## Product direction

| Document | Owns |
|---|---|
| [Roadmap](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md) | Milestone order, freeze register, release/adoption gates and open product choices |
| [Specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md) | Proposed broker, workload identity, browser handoff, native credential delivery and controller contracts |
| [Linux Fleet Pilot](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md) | E2E/integration scenarios and evidence requirements for the proposed work |
| [Decision records](product/decisions/README.md) | Vault-owned forward design decisions and the repository-bound dependency baseline |
| [Controller Contract Suite](testing/Controller%20Contract%20Suite.md) | Test-first HTTP compatibility scenarios (CT/CV/CC) that gate the Rust controller port |
| [P00 baseline manifest](product/p00-baseline-manifest.json) | Source/package/data inventory and dependency/licensing review boundary |
| [P00 compatibility matrix](product/p00-compatibility-matrix.md) | Retained 12-route machine envelope, hosted-auth exclusion, identity mapping and executed baseline evidence |

The implementation-phase plans and their paired acceptance plans are in the Obsidian vault under `blindpass/docs/product/phases/` and `blindpass/docs/testing/phases/`. The dashboard and secret-input redesign plans are under `blindpass/docs/product/`, `blindpass/docs/design/` and `blindpass/docs/testing/`. The P00 baseline artifacts and P01 execution record stay here because they describe this checkout and its executed tests.

The Rust controller implements the P02 API locally on SQLite and PostgreSQL but is not yet accepted or packaged. P03 adds signed fleet contracts, one-use enrollment, an outbound node channel, administrator-managed workloads and policy, operation approval, one-use grant consumption, durable event acknowledgement, node key rotation, and node revocation/recovery. The two-guest VM run passed phase-local key rotation, E01/E02, partition/restart/replay, protocol-mismatch recovery, bounded reconnect recovery, rejection of a replayed signed time reply after broker restart, rejection of a still-live unconsumed grant after full guest reboot, suspend-aware grant expiry under guest wall-clock rollback, a delayed expired-grant rejection with exactly one audit event, denial after an older signed policy was replayed, and durable idempotent grant revocation replay through the TLS proxy on SQLite and PostgreSQL. Focused broker control-socket tests also cover stale policy and grant/node revocation replay across restart. [The execution record](testing/evidence/p03-fleet-authorization-execution.md) lists the scope and limits. The administrator CLI covers enrollment decisions and node revoke/rotate; controller clock rollback, other reboot cases, further transport-level policy and node-revocation replay, broad backpressure and concurrency, the inherited P02.6 cutover gate, and the broader pilot matrix remain open, so P03 is not accepted. Selected protected browser handoff now has component and actual fixture/managed controller-node lifecycle evidence; full client/browser acceptance and native/container parity remain open. Existing encrypted provisioning, OpenClaw storage and application container files are foundations for that work.

## Existing implementation and operation

| Document | Contents |
|---|---|
| [Code architecture](architecture/README.md) | Components, the Rust workspace and controller configuration, existing data flows, auth/persistence and limits |
| [Quick start](guides/quickstart.md) | Local source environment and application startup |
| [Self-hosting](guides/self-hosting.md) | Configuration, TLS, state and current deployment limitations |
| [Exchange policy](guides/policy.md) | Implemented workspace policy format, API and RBAC |
| [API reference](api/README.md) | Manual SPS OpenAPI snapshot, the Rust controller contract, scope and mode-specific auth behavior |
| [OpenClaw integration](plugins/openclaw-capability-extension.md) | Existing transport, storage and resolver contracts; MCP limitations |
| [Unraid templates](deployment/Unraid.md) | Repository container/template configuration and release prerequisites |
| [Dashboard maintenance](architecture/dashboard-maintainability.md) | Existing style and shared translation conventions |
| Dashboard redesign proposal | Maintained in the Obsidian vault; implemented by `packages/console` (P04). The old `packages/dashboard` is eligible for removal |
| [Test setup](testing/README.md) | Actual scripts, service requirements and skipped-suite behavior |
| [P01 execution record](testing/p01-host-broker-evidence.md) | Portable broker checks, selected real-VM profile, teardown evidence and dated open/unsupported status |
| [P02 execution record](testing/evidence/p02-controller-api-migration-rerun.md) | Rust controller gates on SQLite and PostgreSQL, the 2026-09-25 review fixes, coverage and open decisions |
| [P03 execution record](testing/evidence/p03-fleet-authorization-execution.md) | Two-guest SQLite/PostgreSQL key rotation, reconnect and policy-cursor recovery, delayed-grant expiry audit, authorization, revocation and recovery evidence, with unrun scenarios stated explicitly |
| [P04 execution record](testing/evidence/p04-ui-ux-redesign-execution.md) | Console, secret-input page, desktop approval app and widget, and embedded serving: gates on SQLite and PostgreSQL, scenario coverage, deviations, unrun cases and owner decisions |
| [P05 execution record](testing/evidence/p05-workflows-and-clients-execution.md) | Fixture/managed Grafana prerequisites, actual private worker/systemd checks, both actual stock AI tasks in the selected Node26 API operator/local HPKE profile, ordered delivery component/SDK and fleet crypto interoperability evidence, and open GUI/native/inherited gates; [support matrix](product/p05-support-matrix.md) |
| [P05 coordinator execution](testing/evidence/p05-coordinator-2026-10-01.md) | Opt-in signed-grant coordinator, Source expiry and closure retry checks; complete signed-fixture and actual SQLite controller/node systemd lifecycle evidence and recovery test corrections; full phase acceptance remains open |
| [P05 completion review and gate record](testing/evidence/p05-completion-review-2026-10-02.md) | Final 2026-10-02 gate results on the working tree, VM findings and fixes, intermittent Claude result, PostgreSQL shared-memory failures, and what is not established |
| [P05 broker hardening (2026-10-02)](testing/evidence/p05-broker-hardening-2026-10-02.md) | Review fixes to the session coordinator, journal, request parsing and owner retention; host unit evidence only |
| [P05 broker offer and Source admission](testing/evidence/p05-broker-provisioning-2026-10-02.md) | Broker recipient offer, Source admission and control-socket offer event |
| [P05 signed recipient offer](testing/evidence/p05-signed-offer-2026-10-02.md) | Shared Rust signing and Rust/browser verification of the recipient offer |
| [P05 controller offers](testing/evidence/p05-controller-offers-2026-10-02.md) | Controller offer ingestion and administrator-managed source bindings |
| [P05 scoped Source link and submit](testing/evidence/p05-scoped-submit-2026-10-02.md) | Operator-scoped provisioning link, submit route, delivery signing and node relay on SQLite and PostgreSQL |
| [P05 provisioning binding](testing/evidence/p05-provisioning-2026-10-02.md) | Browser-source binding and cryptographic interoperability |
| [P05 provisioning UI](testing/evidence/p05-provisioning-ui-2026-10-02.md) | Operator Source provisioning state, console and input-page flow |
| [P05 ordered delivery](testing/evidence/p05-delivery-2026-10-02.md) | Protocol package router and SDK URL-mode adapter; component evidence |
| [P05 harness hardening](testing/evidence/p05-harness-hardening-2026-10-02.md) | MCP packages, private helper, VM harness, CI workflows and support-matrix fixes; host-test record |
| [P05 native service](testing/evidence/p05-native-service-2026-10-02.md) | `password-file` credential profile and backup unit examples; real restic acceptance blocked on [ADR 0007](product/decisions/0007-p05-native-backup-dependency-review.md) |
| [Demos](testing/Manual%20Demos.md) | Dummy-data exchange exercises and known helper limitations |
| [Security status](security/README.md) | Current threat model, selected source checks and historical audits |

## History and document maintenance

[Archive](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/archive/README.md) is maintained in the Obsidian vault under `blindpass/docs/archive/`; it holds earlier phase plans, test plans, audits and design notes. Their original dates and results remain historical evidence, not an active backlog or fresh validation. Old planned-file references may name features that were never built. The current roadmap supersedes their sequencing and expansion proposals.

When behavior changes, update the relevant operational guide and API/security contract, then its test evidence. Update the vault roadmap/spec only for forward product decisions. Keep links relative within a repository, use stable URLs across repositories, and repair inbound links on moves. [Repository instructions](../AGENTS.md) govern development; [licenses](../LICENSES.md) govern package licensing.

The 2026-09-22 cleanup archived historical plans, consolidated setup guidance, removed the duplicate Telegram plan and obsolete pre-HPKE essay, and replaced the old OpenClaw brainstorm and threat model with source-aligned references. The earlier review findings remain traceable in the product specification and the vault's archived reports.
