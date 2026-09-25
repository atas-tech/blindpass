# BlindPass documentation

**Aligned:** 2026-09-25. Source-bound guides, contracts and execution evidence remain here. Product direction, implementation plans, design and history are maintained in the [Obsidian docs vault](https://github.com/tuthan/docs-vault/tree/main/blindpass/docs). P01 includes live HPKE provisioning and dedicated non-root consumers. Revised P01-I01 and P01-I06 checks passed in a clean committed-SHA Ubuntu 24.04/QEMU-KVM run. The user accepted W0 as NARROW for that tested systemd 255, no-TPM profile only; other profiles and named evidence gaps remain open.

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

The Rust controller implements the P02 API locally on SQLite and PostgreSQL but is not yet accepted or packaged. P03 now has signed fleet contracts, one-use enrollment and an outbound node channel under implementation; workload authorization, grant consumption, operations, audit buffering and two-host acceptance remain incomplete. Protected browser session handoff and native/container parity are not implemented. Existing encrypted provisioning, OpenClaw storage and application container files are foundations for that work.

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
| Dashboard redesign proposal | Maintained in the Obsidian vault; the existing `packages/dashboard` remains the project-tied implementation |
| [Test setup](testing/README.md) | Actual scripts, service requirements and skipped-suite behavior |
| [P01 execution record](testing/p01-host-broker-evidence.md) | Portable broker checks, selected real-VM profile, teardown evidence and dated open/unsupported status |
| [P02 execution record](testing/evidence/p02-controller-api-migration-rerun.md) | Rust controller gates on SQLite and PostgreSQL, the 2026-09-25 review fixes, coverage and open decisions |
| [Demos](testing/Manual%20Demos.md) | Dummy-data exchange exercises and known helper limitations |
| [Security status](security/README.md) | Current threat model, selected source checks and historical audits |

## History and document maintenance

[Archive](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/archive/README.md) is maintained in the Obsidian vault under `blindpass/docs/archive/`; it holds earlier phase plans, test plans, audits and design notes. Their original dates and results remain historical evidence, not an active backlog or fresh validation. Old planned-file references may name features that were never built. The current roadmap supersedes their sequencing and expansion proposals.

When behavior changes, update the relevant operational guide and API/security contract, then its test evidence. Update the vault roadmap/spec only for forward product decisions. Keep links relative within a repository, use stable URLs across repositories, and repair inbound links on moves. [Repository instructions](../AGENTS.md) govern development; [licenses](../LICENSES.md) govern package licensing.

The 2026-09-22 cleanup archived historical plans, consolidated setup guidance, removed the duplicate Telegram plan and obsolete pre-HPKE essay, and replaced the old OpenClaw brainstorm and threat model with source-aligned references. The earlier review findings remain traceable in the product specification and the vault's archived reports.
