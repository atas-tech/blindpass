# BlindPass

BlindPass provides encrypted human-to-agent credential provisioning and policy-controlled agent-to-agent exchange. The operator's browser encrypts a submitted secret with HPKE; the controller coordinates ciphertext delivery, and the recipient runtime decrypts it. Plaintext exists at the input and consumer endpoints, and encrypted delivery alone does not isolate a runtime from the secret it receives.

The next product direction is an Omarchy-first Linux access pilot: one controller, two hosts, a brokered browser task, and a native service job. Host workload authentication, browser session handoff, and native/container fleet-controller parity remain proposed. See the [roadmap](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md) and [specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md).

## Start here

- [Documentation index](docs/README.md): repository-bound guides, contracts and evidence, with pointers to planning and history in the docs vault.
- [Landing page](landing/README.md): human-to-agent secret provisioning, agent-to-agent exchange, and a separately labeled browser-pilot illustration.
- [Deployment](docs/deploy/README.md): install the controller natively (Debian 12, Ubuntu 24.04) or with Docker Compose, then upgrade, back up and recover it. [Controller on Unraid](docs/deploy/unraid.md) maps the Compose sequence onto the two Unraid templates.
- [Testing](docs/testing/README.md): Rust, PostgreSQL-backed controller, console E2E, HTTP contract and packaging commands.
- [Legacy documents](docs/legacy/README.md): archived documents of the retired SPS hosted stack. The stack (`packages/sps-server`, `packages/dashboard`, Redis and its five Unraid templates) was removed on 2026-10-07 and is in git history before the removal commit.
- [Linux fleet pilot test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md): proposed acceptance gates, distinct from existing tests.

## Current implementation

| Area | In this repository |
|---|---|
| Provisioning | Signed browser-input links, X25519/HKDF-SHA256/ChaCha20-Poly1305 HPKE and one-use ciphertext retrieval |
| Exchange | Authenticated requester/fulfiller flows, workspace policy, approvals, reservation/retrieval lifecycle and metadata audit |
| Administration | Operator console (`packages/console`): local operator sessions, agents, policy, approvals, fleet and audit, embedded in the controller |
| Runtime integration | OpenClaw transport adapters, optional SOPS storage and an exec resolver |
| MCP | An entry point exists, but its framing, input transport and stock-client consumption gaps remain W1 work; do not assume clean-client compatibility |
| Rust workspace | P01 host broker, and the P02 controller and `blindpass` CLI on SQLite or PostgreSQL. The controller passes the HTTP contract suite locally on both stores but is not yet accepted |
| Deployment | Native (Debian 12, Ubuntu 24.04) and Docker Compose controller profiles, the controller and input-page Dockerfiles and two controller Unraid templates; release availability and deployment validation are separate from files existing in the repo |

The client packages (`packages/agent-skill`, `packages/gateway`, `packages/openclaw-plugin`) keep their SPS-era names and settings (`SPS_BASE_URL`, `SPS_AGENT_API_KEY`, `VITE_SPS_API_URL`), but talk to the Rust controller. The published MCP bundle has no default endpoint: its tools refuse to run until `SPS_BASE_URL` names your controller. The unbundled OpenClaw plugin still carries a default URL that must be overridden with the intended `SPS_BASE_URL` until the endpoint/distribution gate is completed. Previously documented `atas.tech` hosts are deployment history, not a service-availability guarantee. The hosted billing and guest-intake surfaces went with the SPS stack, and the x402 payment client code was removed from `packages/agent-skill` and the MCP bundle. Integration expansion follows the [freeze register](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md#freeze-register).

## Repository layout

```text
docs/
  product/       P00 source evidence and dependency decision
  api/           Rust controller contract
  architecture/  Current code architecture
  deploy/        Controller installation, upgrade, backup and recovery
  guides/        Exchange policy
  legacy/        Archived documents of the retired SPS stack
  security/      Current threat model and dated evidence
  testing/       Test setup, HTTP contract and execution evidence
packages/
  gateway/       Interception, link routing and identity helpers
  agent-skill/   HPKE and runtime/exchange clients
  openclaw-plugin/  Integration, encrypted store, resolver and MCP
  browser-ui/    Vite secret-input page
  console/       React operator console
  i18n/          Shared translations
  contract-tests/  Black-box HTTP contract harness for the Rust controller
crates/
  blindpass-core/        Shared signing, policy, HPKE and protocol primitives
  blindpass-broker/      P01 host broker
  blindpass-controller/  P02 controller
  blindpass-cli/         Local administration CLI
scripts/         Tests and packaging
tests/fleet/     P01 disposable-VM harness
deploy/          Controller profiles and Unraid templates
```

Product direction, phase plans, design work and historical records are in the [Obsidian docs vault](https://github.com/tuthan/docs-vault/tree/main/blindpass/docs).

## Development and licensing

Use Node.js 26.x and the committed npm lockfile. Follow the [test setup](docs/testing/README.md) for environment setup before starting workspace scripts. `npm run build` builds the workspaces; `npm test` runs their default suites. Integration suites have additional service and environment prerequisites.

[AGENTS.md](AGENTS.md) contains repository contribution instructions. [LICENSES.md](LICENSES.md) records package licensing; the roadmap does not change licenses or establish a commercial entitlement.
