# BlindPass Roadmap Reset — September 2026

> **Date:** 2026-09-10  
> **Updated:** 2026-09-12 — Linux fleet pilot and native/container control-plane requirements  
> **Status:** Direction and deployment requirements recorded; milestone implementation remains proposed  
> **Basis:** [Product Review 2026-09](Product%20Review%202026-09.md) · [Repo State Findings 2026-09](Repo%20State%20Findings%202026-09.md)

This document retains the scope cut and updates the sequence around the [Linux fleet pilot](Native%20Linux%20Fleet%20Research%202026-09.md). Native-service and container deployments of the control plane are both required. The existing phase documents remain a historical record; no feature or deployment capability is marked implemented here.

## Table of Contents

- [1. The One-Sentence Reset](#1-the-one-sentence-reset)
- [2. What Changes](#2-what-changes)
- [3. Milestone W1: Make MCP Mode Work](#3-milestone-w1-make-mcp-mode-work)
- [4. Milestone W2: Native and Container Control Plane](#4-milestone-w2-native-and-container-control-plane)
- [5. Milestone W3: Ship It Where People Can Find It](#5-milestone-w3-ship-it-where-people-can-find-it)
- [6. Milestone W4: The OpenClaw Wedge](#6-milestone-w4-the-openclaw-wedge)
- [7. Milestone W5: Credibility Pass](#7-milestone-w5-credibility-pass)
- [8. Milestone W6: A2A, Later](#8-milestone-w6-a2a-later)
- [9. Freeze Register](#9-freeze-register)
- [10. Pricing Change](#10-pricing-change)
- [11. Sequencing And Effort](#11-sequencing-and-effort)
- [12. Success Metrics And Kill Criteria](#12-success-metrics-and-kill-criteria)

---

## 1. The One-Sentence Reset

> **An operator deploys one control plane natively or in a container, approves a workload from Omarchy, and an AI worker or Linux service completes an authenticated task through its host broker.**

Everything that does not serve that sentence is frozen until it does.

Start with two Linux hosts, one brokered AI operation, and one ordinary systemd service. The controller and brokers must also work headlessly. An MCP handoff is one integration path; successful credential collection alone does not satisfy the pilot.

---

## 2. What Changes

| Dimension | Today | Proposed |
|---|---|---|
| Primary user | Hosted workspace admin | Operator of a small mixed Linux fleet |
| Primary client | OpenClaw | Omarchy operator UI, tested AI adapters, and native Linux services |
| First-run requirement | Hosted registration and agent API key | Local admin setup, node enrollment, and workload registration; no mandatory hosted account |
| Controller deployment | Source/self-hosted and hosted stack | First-class native systemd service and container/Compose packages with the same API and policy contracts |
| Trust requirement | Hosted SPS and runtime endpoints | Explicit controller, recipient-key, host-broker, and consumer boundaries |
| Billing | Stripe subscription + x402 per request | Freeze expansion; validate willingness to pay after repeat operator use |
| Differentiator sold | "Zero-knowledge secret platform" | Approved access that completes real work across agents and services |

The strategic bet is that the combined approval and consumption workflow earns repeat use. Existing identity, policy, and audit code can help, but host attestation, a runtime-independent broker, and deployment parity are new work. The pilot excludes general job scheduling and arbitrary remote execution. Its [test plan](../testing/Native%20Linux%20Fleet%20Pilot.md) covers the new security boundaries.

---

## 3. Milestone W1: Make MCP Mode Work

**Resolves:** [F-1](Repo%20State%20Findings%202026-09.md#f-1-request_secret-cannot-complete-in-plain-mcp-mode), [F-2](Repo%20State%20Findings%202026-09.md#f-2-mcp-server-pins-an-obsolete-protocol-version-and-implements-no-elicitation)  
**Role in the pilot:** prove one stock AI client can complete a brokered authenticated operation. Workload identity and the broker contract must be established alongside this adapter.

### 3.1 Upgrade the MCP server

#### [MODIFY] `packages/openclaw-plugin/mcp-server.mjs`

- Replace `Content-Length` framing with standard newline-delimited JSON and keep stdout limited to valid MCP messages.
- Implement and test explicitly supported protocol versions instead of changing only the advertised version string.
- Check the client's URL-mode elicitation capability; it is not a server capability to declare alongside `tools`. An empty elicitation capability does not establish URL-mode support.
- Implement version-appropriate `elicitation/create` handling. For `2026-07-28`, use `InputRequiredResult`, request capability metadata, `requestState`, and Multi Round-Trip Requests rather than the removed completion notification. [MCP elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)

### 3.2 Add an elicitation delivery transport

#### [MODIFY] `packages/openclaw-plugin/blindpass-core.mjs`

Insert URL-mode elicitation as the **first** transport in `onSecretLink`, ahead of the existing chat transports, and add a local fallback chain after them:

| Order | Transport | Condition |
|---|---|---|
| 1 | MCP URL-mode elicitation | Client advertises URL-mode support for the implemented protocol version |
| 2 | OpenClaw chat API | Existing behaviour, unchanged |
| 3 | OpenClaw runtime channel / CLI | Existing behaviour, unchanged |
| 4 | Telegram | Existing behaviour, unchanged |
| 5 | **Open local browser** | Human and agent share a machine, `BLINDPASS_LOCAL_OPEN=true` |
| 6 | **Authenticated operator application** | Headless or remote worker; operator connects to the controller |

Transports 5 and 6 are proposed additions for clients without elicitation support. Do not use MCP stderr as a default secret-link channel: clients may capture or forward it. An optional QR/terminal view requires an explicitly trusted operator surface and a link reachable from that operator's machine.

### 3.3 Preserve LLM blindness

The URL must not enter the model-visible tool result by default. Verify actual client handling rather than assuming every user-facing channel bypasses model context or logs.

- Elicitation delivers the URL to the client for human interaction; test that supported clients keep it out of model-visible results.
- Local-open and operator-app transports require explicit routing and logging checks.
- The existing `raw_link` parameter and `OPENCLAW_SECRETS_RAW_LINK` escape hatch stay opt-in.

### 3.4 Acceptance criteria

- [ ] A stock Claude Code client initializes over standard MCP stdio, prompts for out-of-band input, and completes the selected authenticated operation through the broker with no OpenClaw or Telegram requirement.
- [ ] Plaintext is retained in the trusted broker for that operation and is absent from model-visible inputs/results and broker-managed logs; plugin memory alone is not accepted as task completion.
- [ ] Same flow verified in at least one additional client (VS Code or Codex CLI).
- [ ] With elicitation unavailable, transport 5 or 6 completes the flow.
- [ ] The secure URL and confirmation code appear in **no** tool result, transcript, or log at default settings. Add a regression test asserting this.
- [ ] Client capability negotiation degrades cleanly instead of throwing.

---

## 4. Milestone W2: Native and Container Control Plane

**Why:** operators must be able to deploy the same controller through their preferred Linux service or container workflow. Self-hosting requires local setup and trust configuration, but no mandatory hosted signup.

### 4.1 Two supported deployment packages

| Package | Required behavior |
|---|---|
| Native Linux service | Versioned release, dedicated service account, systemd lifecycle, protected configuration/keys, durable state, health/readiness, backup and upgrade procedures; works without a container runtime |
| Container | Versioned OCI image and documented Docker Compose profile, non-root controller, persistent volumes/database connections, runtime-injected keys, and equivalent health, backup, and upgrade behavior |

Both packages use the same configuration schema, APIs, identity model, policy semantics, and data migrations. Preserve controller signing/trust material across restarts and upgrades. Database and key backup must cover supported recovery and migration between packages in both directions.

The host broker is a separate native service. The controller container requires no privileged mode, host PID namespace, host service-manager socket, or Docker socket. The controller may run on Omarchy or a separate always-on Linux host. The desktop UI uses the same authenticated endpoint in either deployment.

### 4.2 Local and fleet topology

| Topology | Controller | Consumers |
|---|---|---|
| Single host | Native service or container on the operator's Linux machine | Registered local workloads through the host broker |
| Fleet | Native service or container on the operator's machine or a separate server | Authenticated brokers on two or more hosts |
| Managed hosted, later | Hosted controller implementing the same contracts | Enrolled brokers; commercial packaging remains unvalidated |

Start with a single-controller topology and expand the pilot to two hosts. New grants fail closed when the controller is unavailable. An ephemeral embedded coordinator remains a possible convenience experiment after the broker contract works; it does not replace the durable fleet controller or create a trust-free mode.

### 4.3 Acceptance criteria

- [ ] Native and container controllers each pass the same two-host workflow, including approval, denial, revocation, and disconnection.
- [ ] An ordinary systemd service completes a real test job using broker-supplied credentials without an AI platform or MCP client.
- [ ] Container replacement and native upgrade preserve identity, policy, and durable state.
- [ ] Backup/restore and migration in both directions preserve enrolled nodes where endpoint/trust are retained, reject stale grants, and prevent concurrent independent controllers.
- [ ] A separate controller host works with the Omarchy UI; desktop logout does not stop control-plane services.
- [ ] Native installation has no container-runtime prerequisite; the Compose profile declares its persistent state and backing services.
- [ ] E2E and integration scenarios are implemented from the [fleet pilot test plan](../testing/Native%20Linux%20Fleet%20Pilot.md), including the deployment matrix.

---

## 5. Milestone W3: Ship It Where People Can Find It

**Resolves:** [F-3](Repo%20State%20Findings%202026-09.md#f-3-default-sps-hostname-does-not-resolve), [F-4](Repo%20State%20Findings%202026-09.md#f-4-nothing-is-published-to-npm)

### 5.1 Fix the defaults

Decide the canonical hostname and apply it consistently. Either register `blindpass.dev`, or switch every default to `sps.atas.tech`.

Locations to update:

- `packages/openclaw-plugin/openclaw.plugin.json:16`
- `packages/openclaw-plugin/blindpass-core.mjs:628`
- `packages/openclaw-plugin/blindpass-core.mjs:764`
- `packages/openclaw-plugin/blindpass-core.mjs:928`
- `CLAUDE.md:35`
- `README.md` hosted services section

Validate configured endpoint consistency in package checks and verify public endpoint resolution in release smoke checks; avoid making deterministic builds depend on live DNS availability.

### 5.2 Publish

| Artifact | Channel | Notes |
|---|---|---|
| Native controller and host broker | Versioned Linux release with service definitions | Primary pilot packaging; controller is unprivileged and broker privilege boundaries are explicit |
| Controller OCI image and Compose profile | Container registry and release bundle | Same controller version/API contracts and tested lifecycle as the native package |
| Omarchy UI integration | Reviewed plugin/application release | Metadata widget plus dedicated approval application; no credential custody in the shell plugin |
| `@blindpass/mcp-server` | npm | AI adapter. Must work under `npx` against a configured broker |
| BlindPass | MCP Registry | Preview API, but it is where MCP clients look |
| `blindpass` | ClawHub | Existing `scripts/publish_clawhub.sh` |
| `@blindpass/sdk` | npm | From `packages/agent-skill`, after the above |

Drop `"private": true` only on packages actually being published, and keep the pre-publish security validation in `scripts/publish_clawhub.sh` — no `.env`, no keys, no local hostnames.

### 5.3 Acceptance criteria

- [ ] Every default hostname resolves and serves `/healthz`.
- [ ] `npx @blindpass/mcp-server` works from a clean machine.
- [ ] Listed in the MCP Registry and on ClawHub.
- [ ] README quickstart is executable start to finish by someone who has never seen the repo.
- [ ] Native and container controller quickstarts each complete the pilot on clean hosts, with health, backup, restore, and upgrade instructions.
- [ ] Pilot identity, consumption, and deployment security checks pass before publication. MCP Registry and ClawHub breadth follow the first working adapter and are not substitutes for this gate.

---

## 6. Milestone W4: The OpenClaw Wedge

**Sequence:** adapter-specific expansion after the Linux pilot shows repeat use. This does not change the fleet-wide product identity or make OpenClaw a broker prerequisite.

**Why:** OpenClaw stores credentials in plaintext, its `store` secret provider is unencrypted at rest, and the maintainers closed Doppler, 1Password, and Vault integration requests as *not planned*. That is an unserved audience with a documented problem and an existing, mostly-built solution in `packages/openclaw-plugin/encrypted-store.mjs`.

### 6.1 Reposition

Lead with **"encrypted secrets for OpenClaw"**, not "zero-knowledge provisioning platform." The provisioning flow becomes the thing that makes the encrypted store easy to fill, rather than the headline.

### 6.2 [NEW] Migration command

`blindpass migrate-openclaw` should:

1. Scan `openclaw.json`, `auth-profiles.json`, and `.env` for plaintext credentials
2. Show what it found, with values masked
3. Import into the SOPS-backed encrypted store
4. Rewrite the config to SecretRefs pointing at the `blindpass` exec provider
5. Back up originals, then offer to shred them
6. Print exactly what to run next, including `openclaw secrets reload`

### 6.3 Honest constraints to document

- The exec provider materializes at activation, not lazily. A freshly provisioned secret is not visible to other consumers until reload. This is already documented in [openclaw-capability-extension](../plugins/openclaw-capability-extension.md) and must stay prominent.
- Losing `.age-key.txt` makes the store unrecoverable. The existing `bootstrap_backup_pending` warning should stay loud.

### 6.4 Acceptance criteria

- [ ] Migration command runs against a real OpenClaw install and leaves it working.
- [ ] Dry-run mode that changes nothing.
- [ ] Documented rollback.
- [ ] ClawHub listing leads with the encrypted-store benefit.

---

## 7. Milestone W5: Credibility Pass

**Why:** the buyer for this product reads the security documentation before the README. Open findings in your own published audit are read as a statement about the project's standards.

### 7.1 Cheap code fixes

| Item | Change |
|---|---|
| M-7 / M-1 | Replace `Math.random()` in the gateway with `crypto.randomInt` |
| H-3 / L-4 | Widen confirmation-code entropy well beyond 6,400 combinations |
| M-2 / M-3 | Hash verification tokens at rest and add expiry |
| M-5 | Password validation beyond length |
| L-1 / L-2 | `.gitignore` sensitive generated files, remove committed logs |
| L-5 | Account-level lockout in addition to IP rate limiting |

### 7.2 Deployment fixes

**Resolves:** [F-9](Repo%20State%20Findings%202026-09.md#f-9-permissive-connect-src-in-production-csp), [F-10](Repo%20State%20Findings%202026-09.md#f-10-no-hsts-on-any-hosted-origin), [F-11](Repo%20State%20Findings%202026-09.md#f-11-localhost-origins-in-the-production-browser-ui-csp)

| Item | Change |
|---|---|
| CSP `connect-src` on `app.atas.tech` | Replace bare `http:`/`https:`/`ws:`/`wss:` with the explicit API origin |
| CSP on `secret.atas.tech` | Remove localhost origins and the trailing `https:` wildcard from the production build |
| HSTS | Add `max-age=31536000; includeSubDomains` on all origins |
| `blindpass.atas.tech` | Add the baseline header set |

### 7.3 Documentation fixes

**Resolves:** [F-7](Repo%20State%20Findings%202026-09.md#f-7-aead-cipher-documented-incorrectly), [F-8](Repo%20State%20Findings%202026-09.md#f-8-refresh-token-storage-status-contradicts-across-documents)

- Correct the AEAD row in the design document to ChaCha20-Poly1305.
- Read the dashboard auth code, determine the actual refresh-token storage, and state it in one authoritative place. Correct the other two documents.
- Refresh or date-stamp the phase status snapshots.

### 7.4 Optional: publish interoperability findings

After the pilot works across actual clients, document interoperability gaps and consider a narrowly scoped MCP proposal if a protocol change is necessary. This is not a pilot release gate or evidence of unique ownership of the credential-handling pattern.

---

## 8. Milestone W6: A2A, Later

Deferred until the Linux pilot shows repeat use and an operator needs cross-workload fulfillment. Documented here so existing work is not lost.

The existing exchange policy, approval, and audit work may support a future issuer-to-workload flow. Workload identity and credential brokers already provide competing approaches; an absence of an identical flow in the original search does not establish a moat. Evaluate whether the user needs secret transfer, a provider-issued scoped credential, or a brokered operation.

**When to activate:** once the developer wedge has measurable adoption, or if a regulated design partner appears first — in which case W6 can jump the queue for that engagement specifically.

**Internal dogfooding is the cheapest validation available.** Running BlindPass against internal MCP servers exercises the hosted path, the policy engine, and the audit trail with a real workload and zero customer risk.

---

## 9. Freeze Register

Frozen means: keep the code, keep the tests green, put it behind a flag, stop investing. Nothing below gets deleted.

| Area | Rationale | Un-freeze trigger |
|---|---|---|
| **x402 payments** | ~$28K/day of real commerce ecosystem-wide, ~50% of transactions farmed, median call ~$0.02. No precedent for billing secret exchange this way | A paying customer asks for autonomous machine payment specifically |
| **Guest paid intake (3C)** | An entire public product surface — offers, guest identities, separate ledgers, abuse controls — for a flow with no demonstrated demand | A design partner needs external-requester intake |
| **Hosted crypto checkout (3D)** | Stripe already covers plan purchase | Stripe proves insufficient for a real buyer |
| **Python and Go SDKs (3E)** | Node covers the current agent runtimes. Two more SDKs is two more maintenance surfaces for one maintainer | A user requests one in a language they actually ship in |
| **Further i18n** | Localizing a product with no users | Non-English users exist |
| **Telegram / WhatsApp expansion (Phase 4)** | Chat-adapter breadth before the core flow works | The OpenClaw channel proves the pattern |
| **Human-to-human sharing (Phase 4)** | Crowded market, weak differentiation, unrelated buyer | Never, most likely |
| **Enterprise federation (Phase 5)** | Correct eventually, unaffordable now | A named enterprise contract |

**Total frozen:** roughly half the current server codebase and most of the forward roadmap.

---

## 10. Pricing Change

| Tier | Price | Notes |
|---|---|---|
| **Local / pilot** | Free evaluation; no mandatory hosted account | Native and container controller packaging are both part of validation |
| **Self-hosted** | Commercial packaging unvalidated; existing licenses apply | Deployment mode does not change functionality or licensing |
| **Hosted team** | Existing workspace price and per-workload pricing remain hypotheses | Validate the buyer across AI workers and ordinary services before adding billing |
| **Brokered A2A / enterprise support** | Deferred | Require a named user need before choosing metering or contract terms |

Remove x402 from the billing story. It can stay as a demonstrable capability; it should not be a plan.

---

## 11. Sequencing And Effort

| Order | Milestone | Relative effort | Unblocks |
|---|---|---|---|
| 1 | Host identity and broker-consumption spike from the [fleet research](Native%20Linux%20Fleet%20Research%202026-09.md) | Must be measured | Establish the new security boundary and SPIRE fit |
| 2 | [W1 — Stock AI operation](#3-milestone-w1-make-mcp-mode-work) plus native service delivery | Medium/uncertain until spike | One authenticated AI task and one service job |
| 3 | [W2 — Native and container controller](#4-milestone-w2-native-and-container-control-plane) | Medium/uncertain until spike | Two-host deployment parity, persistence, and recovery |
| 4 | [W5 — Fixes affecting the pilot](#7-milestone-w5-credibility-pass) | Depends on findings | Security and deployment evidence before publishing |
| 5 | [W3 — Publish and recruit pilot operators](#5-milestone-w3-ship-it-where-people-can-find-it) | Measured after packaging | Independent setup and repeat usage |
| 6 | [W4 — OpenClaw expansion](#6-milestone-w4-the-openclaw-wedge), remaining W5 work | Demand-driven | Additional integrations |
| 7 | [W6 — A2A and enterprise](#8-milestone-w6-a2a-later) | Large | Deferred |

The minimum viable pilot includes both controller deployment modes and a completed authenticated workflow. Collecting a secret or accumulating package downloads is insufficient. Pilot-specific security fixes precede publication; do not restore unrelated SaaS or orchestration scope to complete this sequence.

Per the repository testing rule in [AGENTS.md](../../AGENTS.md), each milestone needs E2E and integration scenarios defined in `docs/testing/` alongside the implementation. W1 in particular needs a client-matrix test covering elicitation-capable and elicitation-incapable clients.

---

## 12. Success Metrics And Kill Criteria

### Validation window, first 90 days after pilot publication

| Metric | Target |
|---|---|
| External operators attempting setup | At least three, recruited deliberately |
| Repeat real workflow use | At least two operators repeat use without maintainer intervention |
| Deployment evidence | Native and container modes pass the same acceptance suite; record setup failures and preferred deployment mode |
| Actual task completion | One authenticated AI operation and one ordinary service job across two hosts |
| Buyer evidence | Record why existing secret managers do not meet the need and whether the operator would pay for ongoing support or hosting |

These are proposed experiment targets, not current demand. Stars and downloads may provide context but are not the primary gate.

### Kill criteria

Reassess seriously if repeat use is absent after 90 days of deliberate recruitment, regardless of whether a competitor launches a new feature. Also narrow the supported profile if trustworthy workload isolation is impractical or operators mainly need existing secret templating. Preserve useful reference code and integrations without expanding the platform to justify sunk effort.

### The case for continuing anyway

Even in the pessimistic branch, the work retains value:

- The protocol argument is sound and now citable in the specification.
- The exchange implementation can remain useful reference code without claiming exclusive differentiation.
- The regulated-finance angle has a concrete framework to align to in SAFR.
- The code is well tested and the security work is honest, which makes it a credible reference implementation regardless of commercial outcome.
