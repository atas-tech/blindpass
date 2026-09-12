# BlindPass (Agent Secrets)

BlindPass is a secure, zero-knowledge secret provisioning system designed to let humans and AI agents exchange sensitive credentials through one coordinating SPS server without exposing plaintext to the LLM or the server.

This repository contains the architecture, implementation plans, and source code for the Secret Provisioning System (SPS), including gateway-level anti-phishing, in-memory-only secret storage, and HPKE (Hybrid Public Key Encryption) encryption.

## Table of Contents
- [Overview](#overview)
- [Hosted Services](#hosted-services)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Documentation](#documentation)
- [Features](#features)
- [Getting Started](#getting-started)

## Overview

When an AI Agent needs a secret to complete a task (e.g., "Deploy my website to AWS"), it should **never ask for the secret in plain text over chat**, nor should the secret ever be visible to the LLM.

BlindPass solves this by using SPS as the trust anchor and coordinator. For Human -> Agent flow, the gateway generates a secure, single-use, out-of-band link for the user. The user encrypts the secret in their browser, and only the agent's constrained execution environment can decrypt and hold it in memory. For Agent -> Agent flow, SPS coordinates a pull-based exchange between stable agent identities, enforcing policy, approvals, and one-time retrieval without requiring Kubernetes or a cluster control plane.

## Hosted Services

Access the live BlindPass platform:
- **Landing Page**: [blindpass.atas.tech](https://blindpass.atas.tech/)
- **Operator Dashboard**: [app.atas.tech](https://app.atas.tech/)
- **SPS API Server**: [sps.atas.tech](https://sps.atas.tech/)
- **Secure Secret Input**: [secret.atas.tech](https://secret.atas.tech/)

## Architecture

The system consists of 5 main components:
1. **SPS Server:** A Fastify backend with Redis-backed storage for handling encrypted payload submission and retrieval. All data has a strict TTL.
2. **Operator Dashboard:** A Vite + React application providing a persistent human-facing interface for workspace management, audit logging, and agent enrollment.
3. **Browser UI:** A zero-dependency, static HTML/JS page served to the user. It handles client-side HPKE encryption so the plaintext secret never traverses the network.
4. **Agent Skill:** A package that gives agents the `request_secret` tool, handles keypair generation, and securely manages the in-memory `SecretStore`.
5. **Gateway Middleware / Runtime Integration:** Intercepts LLM tool calls, replaces them with secure out-of-band links, enforces outbound URL filtering, and can mint or forward SPS-trusted agent tokens for coordinated agent-to-agent exchange.

## Directory Structure

```text
blindpass/
├── docs/                 # System architecture, security audits, and test plans
│   ├── architecture/     # Implementation plans and system design docs
│   ├── security/         # Security audit documentation
│   └── testing/          # E2E and component test plans
├── packages/             # Monorepo packages (TypeScript)
│   ├── agent-skill/      # Agent-side secret management skill
│   ├── browser-ui/       # Secure client-side encryption interface
│   ├── dashboard/        # Operator Dashboard (Vite + React SPA)
│   ├── gateway/          # Gateway security middleware
│   ├── openclaw-plugin/  # OpenClaw specific integration
│   └── sps-server/       # Secret Provisioning Service backend
└── scripts/              # Integration tests and E2E demonstration scripts
```

## Documentation

Detailed documentation and planning can be found in the `docs/` folder:
- **Core Strategy**: [Implementation Plan](docs/architecture/Implementation%20Plan.md) | [Security Audit](docs/security/Security%20Audit%20v2.md) | [Licensing Proposal](docs/archive/Licensing_Proposal.md)
- **Getting Started**: [Quick Start](docs/guides/quickstart.md) | [Self-Hosting](docs/guides/self-hosting.md) | [API Reference](docs/api/README.md) | [Policy Guide](docs/guides/policy.md) | [Unraid Deployment](docs/deployment/Unraid.md)
- **Roadmap & Phases**:
    - [Phase 1: Core MVP](docs/architecture/Phase%201%20-%20Core%20MVP.md)
    - [Phase 2A: Agent to Agent Exchange](docs/architecture/Phase%202A%20-%20Agent%20to%20Agent%20Exchange.md)
    - [Phase 2B: Production A2A](docs/architecture/Phase%202B%20-%20Production%20A2A.md)
    - [Phase 3A: Hosted Platform](docs/architecture/Phase%203A%20-%20Hosted%20Platform.md)
    - [Phase 3B: UI & Operations](docs/architecture/Phase%203B%20-%20UI%20&%20Operations.md)
    - [Phase 3C: Paid Guest Secret Exchange](docs/architecture/Phase%203C%20-%20Paid%20Guest%20Secret%20Exchange.md)
    - [Phase 3D: Autonomous Payments & Crypto Billing](docs/architecture/Phase%203D%20-%20Autonomous%20Payments%20%26%20Crypto%20Billing.md)
    - [Phase 3E: Hosted Hardening, Ecosystem & Launch](docs/architecture/Phase%203E%20-%20Hosted%20Hardening,%20Ecosystem%20%26%20Launch.md)
- **Maintenance**: [Dashboard Maintainability](docs/architecture/dashboard-maintainability.md)
- **Product Review (Sept 2026)**: [Review Index](docs/product/README.md) | [Product Review](docs/product/Product%20Review%202026-09.md) | [Repo State Findings](docs/product/Repo%20State%20Findings%202026-09.md) | [Roadmap Reset](docs/product/Roadmap%20Reset%202026-09.md)

## Licensing

This repository uses a mixed-license model:
- `packages/sps-server` and `packages/dashboard` are licensed under `AGPL-3.0-only`.
- `packages/agent-skill`, `packages/browser-ui`, `packages/gateway`, and `packages/openclaw-plugin` are licensed under `MIT`.

See `LICENSES.md` for the package licensing matrix and rollout notes.

## Features

- **Zero-Knowledge Encryption:** Secrets are encrypted in the user's browser using HPKE before transmission. The server only sees ciphertext.
- **Short-Lived Keys:** Agent keypairs and encrypted payloads are ephemeral and strictly TTL-bound.
- **Phishing Prevention:** Gateway egress filtering redacts unexpected URLs, and requests are protected by cryptographically secure confirmation codes.
- **Atomic Single-Use Retrieval:** Secrets are retrieved and deleted atomically via Redis Lua scripts, ensuring they can only be read once.
- **No LLM Exposure:** The LLM orchestration layer never comes in contact with plaintext secrets.
- **Single Coordinator Model:** One SPS server can coordinate secret exchange across multiple agents and hosts using stable agent IDs and SPS-trusted JWT/JWKS validation.

## Auth Modes

- **Hosted / local plugin default:** Prefer agent API keys. Enrolled agents exchange `BLINDPASS_API_KEY` / `SPS_AGENT_API_KEY` for short-lived SPS bearer tokens, so plugin users do not need to manage JWKS files.
- **Self-hosted / workload identity:** Use `SPS_AGENT_AUTH_PROVIDERS_JSON` to trust external workload JWT issuers via `jwks_url` or `jwks_file`.
- **Legacy note:** `SPS_GATEWAY_JWKS_FILE` and `SPS_GATEWAY_JWKS_URL` are no longer direct SPS server config. If you keep a local `jwks.json`, reference it from `SPS_AGENT_AUTH_PROVIDERS_JSON`.

## Getting Started

Start with [docs/guides/quickstart.md](docs/guides/quickstart.md) for a local source-based run, or [docs/guides/self-hosting.md](docs/guides/self-hosting.md) for the supported self-hosted setup. The packaged Unraid path is documented in [docs/deployment/Unraid.md](docs/deployment/Unraid.md).

The local developer baseline now includes:

- [`.env.example`](.env.example) for source-based local and self-hosted configuration
- [`docker-compose.test.yml`](docker-compose.test.yml) for PostgreSQL and Redis
- [`Makefile`](Makefile) for `up`, `down`, `logs`, `migrate`, and dev workflows
- [docs/api/openapi.yaml](docs/api/openapi.yaml) as the maintained OpenAPI snapshot for the stable hosted/dev API surface
