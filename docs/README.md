# BlindPass documentation

**Aligned:** 2026-09-22. Current guides describe source behavior; the product documents describe proposed forward work. No deployment or pilot test pass is established by this documentation update.

## Product direction

| Document | Owns |
|---|---|
| [Roadmap](product/Roadmap.md) | Milestone order, freeze register, release/adoption gates and open product choices |
| [Specification](product/Specification.md) | Proposed broker, workload identity, browser handoff, native credential delivery and controller contracts |
| [Linux Fleet Pilot](testing/Linux%20Fleet%20Pilot.md) | E2E/integration scenarios and evidence requirements for the proposed work |

The controller/broker fleet, protected browser session handoff and native/container parity are not implemented by the existing SPS stack. Existing encrypted provisioning, OpenClaw storage and application container files are foundations for that work.

## Existing implementation and operation

| Document | Contents |
|---|---|
| [Code architecture](architecture/README.md) | Components, existing data flows, auth/persistence and limits |
| [Quick start](guides/quickstart.md) | Local source environment and application startup |
| [Self-hosting](guides/self-hosting.md) | Configuration, TLS, state and current deployment limitations |
| [Exchange policy](guides/policy.md) | Implemented workspace policy format, API and RBAC |
| [API reference](api/README.md) | Manual OpenAPI snapshot, scope and mode-specific auth behavior |
| [OpenClaw integration](plugins/openclaw-capability-extension.md) | Existing transport, storage and resolver contracts; MCP limitations |
| [Unraid templates](deployment/Unraid.md) | Repository container/template configuration and release prerequisites |
| [Dashboard maintenance](architecture/dashboard-maintainability.md) | Existing style and shared translation conventions |
| [Test setup](testing/README.md) | Actual scripts, service requirements and skipped-suite behavior |
| [Demos](testing/Manual%20Demos.md) | Dummy-data exchange exercises and known helper limitations |
| [Security status](security/README.md) | Current threat model, selected source checks and historical audits |

## History and document maintenance

[Archive](archive/README.md) holds the earlier phase plans, test plans, audits and design notes. Their original dates and results remain historical evidence, not an active backlog or fresh validation. Old planned-file references may name features that were never built. The current roadmap supersedes their sequencing and expansion proposals.

When behavior changes, update the relevant operational guide and API/security contract, then its test evidence. Update the roadmap/spec only for forward product decisions. Keep links relative and repair inbound links on moves. [Repository instructions](../AGENTS.md) govern development; [licenses](../LICENSES.md) govern package licensing.

The 2026-09-22 cleanup archived historical plans, consolidated setup guidance, removed the duplicate Telegram plan and obsolete pre-HPKE essay, and replaced the old OpenClaw brainstorm and threat model with source-aligned references. The earlier review findings remain traceable in the product specification and archived reports.
