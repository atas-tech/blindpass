# BlindPass

BlindPass provides encrypted human-to-agent credential provisioning and policy-controlled agent-to-agent exchange. The operator's browser encrypts a submitted secret with HPKE; SPS coordinates ciphertext delivery, and the recipient runtime decrypts it. Plaintext exists at the input and consumer endpoints, and encrypted delivery alone does not isolate a runtime from the secret it receives.

The next product direction is an Omarchy-first Linux access pilot: one controller, two hosts, a brokered browser task, and a native service job. Host workload authentication, browser session handoff, and native/container fleet-controller parity remain proposed. See the [roadmap](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md) and [specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md).

## Start here

- [Documentation index](docs/README.md): repository-bound guides, contracts and evidence, with pointers to planning and history in the docs vault.
- [Landing page](landing/README.md): human-to-agent secret provisioning, agent-to-agent exchange, and a separately labeled browser-pilot illustration.
- [Quick start](docs/guides/quickstart.md): run the existing source-based development stack.
- [Self-hosting](docs/guides/self-hosting.md): configuration and operational limits of the current SPS stack.
- [Testing](docs/testing/README.md): unit, Redis, PostgreSQL and dashboard E2E commands.
- [Linux fleet pilot test plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md): proposed acceptance gates, distinct from existing tests.

## Current implementation

| Area | In this repository |
|---|---|
| Provisioning | Signed browser-input links, X25519/HKDF-SHA256/ChaCha20-Poly1305 HPKE and one-use ciphertext retrieval |
| Exchange | Authenticated requester/fulfiller flows, workspace policy, approvals, reservation/retrieval lifecycle and metadata audit |
| Administration | Dashboard authentication, agent/member management, policy, audit and existing billing/guest surfaces |
| Runtime integration | OpenClaw transport adapters, optional SOPS storage and an exec resolver |
| MCP | An entry point exists, but its framing, input transport and stock-client consumption gaps remain W1 work; do not assume clean-client compatibility |
| Deployment | Source configuration, application Dockerfiles and Unraid templates; release availability and deployment validation are separate from files existing in the repo |

Default plugin URLs must be overridden with the intended `SPS_BASE_URL` until the endpoint/distribution gate is completed. Previously documented `atas.tech` hosts are deployment history, not a service-availability guarantee. Billing, x402, guest intake and integration expansion follow the [freeze register](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md#freeze-register).

## Repository layout

```text
docs/
  product/       P00 source evidence and dependency decision
  api/           Current SPS API snapshot
  architecture/  Current code architecture
  guides/        Source setup, self-hosting and exchange policy
  security/      Current threat model and dated evidence
  testing/       Test setup, HTTP contract and execution evidence
packages/
  sps-server/    Fastify API and persistence
  gateway/       Interception, link routing and identity helpers
  agent-skill/   HPKE and runtime/exchange clients
  openclaw-plugin/  Integration, encrypted store, resolver and MCP
  browser-ui/    Vite secret-input page
  dashboard/     React/Vite administration
  i18n/          Shared translations
scripts/         Tests, demos and packaging
deploy/          Platform templates
```

Product direction, phase plans, design work and historical records are in the [Obsidian docs vault](https://github.com/tuthan/docs-vault/tree/main/blindpass/docs).

## Development and licensing

Use Node.js 26.x and the committed npm lockfile. Follow the [quick start](docs/guides/quickstart.md) for environment setup before starting workspace scripts. `npm run build` builds the workspaces; `npm test` runs their default suites. Integration suites have additional service and environment prerequisites.

[AGENTS.md](AGENTS.md) contains repository contribution instructions. [LICENSES.md](LICENSES.md) records package licensing; the roadmap does not change licenses or establish a commercial entitlement.
