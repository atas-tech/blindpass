# BlindPass Product Review — September 2026

> **Date:** 2026-09-10  
> **Updated:** 2026-09-12 — Linux fleet direction, review corrections, and native/container control-plane deployment requirements  
> **Reviewer:** Engineering/product review pass  
> **Scope:** Is BlindPass worth continuing, and how should it extend to AI agents and native Linux services?  
> **Verdict:** **Continue with a bounded Linux fleet pilot, starting with Omarchy. Support native and container control-plane deployments.**  
> **Status:** Product direction and deployment requirements recorded at the user's request; implementation and release readiness remain unproven.

## Table of Contents

- [1. Verdict](#1-verdict)
- [2. Why The Thesis Holds Up](#2-why-the-thesis-holds-up)
  - [2.4 Linux fleet direction](#24-linux-fleet-direction)
  - [2.5 Native and container control-plane deployment](#25-native-and-container-control-plane-deployment)
- [3. Competitive Landscape](#3-competitive-landscape)
- [4. Demand Evidence](#4-demand-evidence)
- [5. Regulatory And Standards Tailwind](#5-regulatory-and-standards-tailwind)
- [6. Where The Build Went Wrong](#6-where-the-build-went-wrong)
- [7. Pricing Reality Check](#7-pricing-reality-check)
- [8. Risks To The Thesis](#8-risks-to-the-thesis)
- [9. Sources](#9-sources)

Companion documents:

- [Repo State Findings 2026-09](Repo%20State%20Findings%202026-09.md) — concrete defects found in the code and live services
- [Roadmap Reset 2026-09](Roadmap%20Reset%202026-09.md) — the proposed scope cut and milestone order
- [Native Linux Fleet Research 2026-09](Native%20Linux%20Fleet%20Research%202026-09.md) — architecture, trust boundaries, and Linux integration research
- [Native Linux Fleet Pilot](../testing/Native%20Linux%20Fleet%20Pilot.md) — proposed E2E, integration, and deployment-parity scenarios

The September 10 market, pricing, and incident tables remain a dated research snapshot. The September 12 revision corrects selected claims and changes product direction; it is not a fresh verification of every original source.

---

## 1. Verdict

**The problem supports another focused experiment; product demand and defensibility remain unproven.** MCP specifies out-of-band handling for sensitive elicitation, and existing secret managers and workload-identity systems confirm that controlled credential access is an established need. Those facts do not establish demand for BlindPass or the absence of adequate alternatives.

**The execution went sideways.** Effort concentrated on hosted SaaS packaging, guest paid intake, and crypto payments before the developer-facing wedge worked in any mainstream MCP client. The single most important distribution path — a developer running `npx` against Claude Code — currently fails on the headline flow.

**Recommendation:** keep the scope cut and validate a runtime-independent Linux access layer. One control plane should govern a small fleet of AI workers and ordinary Linux services through per-host brokers, with Omarchy providing the first operator experience. The control plane must support both a native Linux service and a container deployment, using the same policy, identity, and API contracts.

The first useful outcome is an approved workload completing an authenticated task. Securely collecting a credential into plugin memory is insufficient. The pilot should prove one brokered AI operation and one native service credential flow across two hosts. Scheduling and general fleet orchestration remain outside the initial access-control scope.

| Question | Answer |
|---|---|
| Is the problem real? | Yes — documented, repeatedly, throughout 2025–2026 |
| Is the solution differentiated? | A hypothesis: fresh credential provisioning plus operator approval and useful execution across a mixed Linux fleet |
| Is the protocol moving toward it? | MCP URL-mode elicitation supports the AI adapter; Linux services need a native interface without MCP |
| Is the current build shippable to a new user? | **No** — see [Repo State Findings](Repo%20State%20Findings%202026-09.md) |
| Where can the control plane run? | Required target: native Linux service or container, on the operator machine or an always-on host; parity still needs implementation and testing |
| Is the monetization model validated? | **No** — freeze x402 investment and test willingness to pay after repeat usage |

---

## 2. Why The Thesis Holds Up

### 2.1 The protocol caught up to the design

The MCP specification (version `2026-07-28`, unchanged on this point since `2025-11-25`) states:

- Servers **MUST NOT** use form-mode elicitation to request sensitive information such as passwords, API keys, access tokens, or payment credentials.
- Servers **MUST** use **URL mode** for interactions involving such information.
- Rationale in the spec: credentials "never pass through the LLM context, MCP client or any intermediate MCP servers."
- Clients MUST display the full URL, obtain consent, and MUST NOT pre-fetch it. Servers MUST bind the link to the initiating user.

This supports BlindPass's out-of-band input design. HPKE can additionally keep plaintext out of the coordinating relay, subject to correct recipient-key binding and trusted endpoint code. The existing MCP implementation does not yet implement this protocol flow, so describing the current product as a compliant strict superset would be premature. [MCP elicitation specification](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)

URL-mode elicitation was introduced by SEP-1036. The `2026-07-28` release also removed server-initiated `notifications/elicitation/complete` in favour of Multi Round-Trip Requests and `requestState` correlation, which maps cleanly onto a "link issued → poll until fulfilled" server.

**Implication:** use the standardized interaction where clients support it, with version-specific capability handling. The specification establishes an integration route, not exclusive product differentiation. MCP remains one adapter for the proposed Linux broker.

### 2.2 The differentiation hypothesis

The original review compared roughly 30 vendors (see [3. Competitive Landscape](#3-competitive-landscape)). Three relevant patterns are:

| Pattern | Who | What it solves |
|---|---|---|
| Vault injection | 1Password, Doppler, Infisical, Akeyless | Credential the org already stores, injected into a process |
| OAuth token exchange | Auth0, Okta, Aembit, Arcade, Keycard | Delegated access to APIs the org already federates |
| Workload identity | Vault, Teleport, SPIFFE, Entra, AgentCore | Proving *which* agent is calling |

The proposed entry point is: **a human has a new third-party credential, and an approved workload needs to complete a task now without that credential entering the agent transcript.** Validate that combined workflow against existing vault, approval, and credential-request products. An exact cryptographic combination that competitors do not advertise is not evidence of a durable moat.

### 2.3 The failure record keeps growing

The incident examples in the original research motivate reducing credential exposure through context, configuration, and transcripts. They do not establish that encrypted delivery prevents every subsequent misuse. A recipient process can read a delivered secret; one-time retrieval does not shorten the underlying API key's lifetime. The product must distinguish brokered operations from credential delivery.

### 2.4 Linux fleet direction

**Primary operator:** someone running a small mixed fleet of AI workers, development tools, and Linux services. Omarchy is the first desktop integration; the controller and brokers must also function on headless Linux.

| Layer | Responsibility |
|---|---|
| Control plane | Node enrollment, workload registrations, policy, approvals, grants, revocation state, health, and metadata audit |
| Host broker | Authenticate local callers from OS context, enforce access decisions and a local authority ceiling, handle credentials, and perform approved operations |
| AI adapters | CLI/MCP or runtime-specific integration for OpenClaw, Claude, Codex, and other tested clients |
| Native service interface | Deliver credentials to registered Linux services through systemd or an explicit application adapter |
| Omarchy interface | Show fleet status and open a dedicated approval view; keep custody keys and secret values outside the shared shell plugin process |

There are two explicit consumption modes:

- **Brokered operation:** the trusted broker retains the credential, performs a permitted action, and returns a constrained result to the AI workload.
- **Service credential delivery:** an approved service receives plaintext through a credential file or supported adapter. That consumer can read the credential; this mode does not promise model blindness or containment of a malicious consumer.

Systemd already supports credential delivery, and SPIRE provides node/workload identity primitives. Reuse or integrate these where appropriate before building equivalents. Identity must be derived from protected OS execution context, not a self-reported agent name. Same-user desktop processes do not automatically provide isolation. [Systemd credentials](https://systemd.io/CREDENTIALS/), [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/)

### 2.5 Native and container control-plane deployment

Both modes are first-class product requirements. They describe how the controller is packaged, not different trust models, billing tiers, or fleet APIs.

| Mode | Required deployment experience |
|---|---|
| **Native Linux service** | Run under a dedicated service account with systemd lifecycle management; explicit configuration, durable state, protected signing material, health checks, and upgrade/backup/restore procedures |
| **Container** | Ship a versioned OCI image and a documented Compose deployment; non-root application process, declared persistent state/database connections, injected configuration and signing material, health checks, and equivalent upgrade/backup/restore procedures |

Either controller can run on Omarchy, a separate Linux server, or a VM. The Omarchy UI connects through the authenticated API in both cases. Docker/Compose is the initial container validation target; other OCI runtimes require separate compatibility evidence. Native deployment must be possible with natively managed or external database services, without requiring a container runtime.

**The host broker remains a separate host service in the initial design.** It needs local OS identity and service integration; the controller container should need no privileged mode, host PID namespace, host service-manager sockets, or container-engine socket. Containers running workloads are a separate future integration concern.

Both controller modes must pass the same fleet acceptance scenarios. Preserve the controller identity, trust configuration, policy, audit history, and relevant durable state when migrating between modes. A stable endpoint and supported backup/restore path should avoid unnecessary node reenrollment. Prevent two independently restored instances from issuing conflicting decisions; high availability is outside the pilot.

Controller outages must produce the same bounded behavior in either mode. New grants fail closed while disconnected, and existing grants have an explicit expiry. A running service may still retain a credential already delivered to it; provider revocation is a separate operation. Container deployment does not solve host suspension or controller availability.

---

## 3. Competitive Landscape

### 3.1 Nearest analogues to Human → Agent

| Product | What it ships | Gap vs BlindPass |
|---|---|---|
| **AgentLair** (Apr 2026) | Agent generates RFC 8628 device code + approval URL; operator pastes credential in browser; deleted within ~60s | **Server sees plaintext in transit.** Not end-to-end. Closest direct competitor |
| **agent-secret** (OSS) | Browser AES-GCM, key in URL fragment, burn-on-claim | Decryption key is pasted into agent chat, so it transits the LLM context |
| **Vaulted** | MCP one-time links, "agent-blind" via `env:`/`file:` refs | Agent → human direction, not human → agent bootstrap |
| **Bitwarden Agent Access SDK** (Mar 2026, alpha) | Noise-framework E2E tunnel, CLI human approval, env injection into child process | Closest on crypto model; no out-of-band browser capture of a new secret |
| **AuthLoop** (waitlist) | Pauses agent at auth wall, E2E link to human device | Web logins, not arbitrary secrets |
| **Password Pusher / onetimesecret** | Human-to-human secret-sharing alternatives | Compare their individual trust and consumption models; sharing alone does not establish AI task integration |
| **Yopass** | Browser public-key encryption, secret-request links, and atomic one-time retrieval | Significant overlap in provisioning; the cited flow does not establish the proposed agent-operation and fleet integration. [Yopass secret requests](https://yopass.se/docs/secret-requests/) |

**Conclusion:** compare completed customer workflows, not only cryptographic ingredients. The original search did not establish an identical implementation, but does not justify a categorical claim of no equivalent competitor.

### 3.2 Agent → Agent brokered exchange

The original review found related IETF drafts (`draft-klrc-aiagent-auth-03`, July 2026; `draft-hartman-credential-broker-4-agents`). The absence of an identical shipped flow in that search does not establish a moat. Existing workload identity and credential-broker products are alternatives, and some users should authorize operations or obtain scoped credentials instead of transferring long-lived secrets between agents. Defer broader A2A investment until the pilot demonstrates a concrete need.

### 3.3 Incumbents worth tracking

| Vendor | Relevant 2026 shipment | Threat level |
|---|---|---|
| **1Password** | Environments + MCP server (values never returned, names only); 1Password for Claude (Jul 2026) — "secret values never enter Claude's context window" | **High** — same message, far more distribution |
| **Doppler** | `doppler run` injection + read-only MCP; explicitly lists OpenClaw, Claude, Codex | **High** — direct overlap on the OpenClaw plugin channel |
| **HashiCorp Vault** | Agentic IAM, agent registry, RFC 9396 authorization details; public beta summer 2026, GA targeted fall 2026 | Medium — enterprise lane |
| **Akeyless** | "SecretlessAI" / Agentic Runtime Authority (Sep 2026) | Medium |
| **Infisical / Keeper** | Secret management and runtime integrations; assess each integration's exposure model | Infisical's Linux agent is a direct alternative for the service-delivery use case; one MCP tool's behavior does not characterize the entire product |
| **Arcade.dev** | Authenticated tool calling; $60M Series A (Jun 2026) | Medium — owns the "auth for agent actions" narrative |
| **Composio** | Managed OAuth; **May 2026 breach exposed ~5,241 API keys and ~5,001 GitHub OAuth tokens** | Low — and the breach is the single best argument for zero-knowledge storage |

### 3.4 Market consolidation

The original research records acquisitions and funding in agent identity. This is category context, not evidence of BlindPass demand, acquisition prospects, or a deadline to expand scope.

| Event | Value | Date |
|---|---|---|
| Cyera acquires Oasis Security | ~$1B | 2026-07-28 |
| CrowdStrike acquires SGNL | ~$740M | 2026-01-08 |
| Cisco acquires Astrix | ~$400M | announced 2026-05-05 |
| SailPoint acquires Entro | ~$200M reported | closed 2026-06-29 |
| Snowflake acquires Natoma | ~$110M | 2026-05-27 |
| Arcade.dev Series A | $60M | 2026-06-15 |
| Keycard seed/Series A | $38M | 2025-10-21 |
| Hush Security Series A | $30M | 2026-07 |

### 3.5 Name check

No competitor uses the BlindPass name. The only collision is `jlamothe/blindpass`, an unrelated legacy CLI password-prompt tool. `blindpass.dev` is not indexed and **does not currently resolve** — see [Repo State Findings](Repo%20State%20Findings%202026-09.md).

---

## 4. Demand Evidence

### 4.1 Explicit developer requests

| Signal | Detail |
|---|---|
| **Claude Code issue #29910** | "Built-in secrets management" — asks for a secure input UI that never exposes secrets to chat, plus runtime injection. Open, ~45 reactions |
| **Claude Code #44868 / #58043** | `.env` and settings contents leak into transcripts despite instructions. Community conclusion: *"model adherence to instructions is unreliable; tool-level enforcement is not"* |
| **OpenClaw #7916** | Encrypted secrets request → SecretRef shipped 2026-04-24, but #28359 / #37512 show refs re-materialised as plaintext |
| **OpenClaw #10033 / #13610** | Doppler / 1Password / Vault integration requests **closed as "not planned"** — an open lane for a third-party plugin |
| **Cursor forum #156486 et al.** | Privacy Mode does not stop `.env` reaching the backend; `.cursorignore` is best-effort |
| **Codex #30971 / #32327** | Shell snapshots persist `OPENAI_API_KEY` in plaintext under `CODEX_HOME` |

An "Ask HN" thread on managing secrets with AI agents (Feb 2026) shows the current state of practice: environment variables that respondents admit are insecure, localhost proxies, keychain helper scripts, and CLI wrappers. The recurring complaint is the absence of a standardized, production-ready solution.

**Caveat:** consumer-developer pull is weak. Comparable Show HN launches in this category scored in the single digits to high teens. Demand here is **security- and ops-led, not virally developer-led**. Distribution should assume push, not pull.

### 4.2 What runtimes do today

| Runtime | Mid-task credential handling |
|---|---|
| Claude Code | Env expansion in `.mcp.json`, `apiKeyHelper`, OS keychain; 1Password shell plugin; `op://` in settings still an open request |
| Codex cloud | Secrets injected only into setup scripts, removed before the agent phase |
| Copilot coding agent | Dedicated Agents secrets in GitHub Actions (May 2026) |
| Cursor Cloud | KMS-encrypted, "Runtime Secret" redacted in transcripts |
| Devin | Docs state it "may ask you to provide credentials within the current conversation" |
| Gemini / Antigravity CLI | Env var, redaction of `*KEY/TOKEN/SECRET` names during tool execution |

These dated examples illustrate different provisioning paths; they do not establish a universal exposure model across all runtimes. Evaluate where plaintext exists in each supported integration, including its subprocesses and tool results.

### 4.3 Validate the mixed-fleet workflow

Developer issues establish pain, not willingness to adopt another daemon or pay for a control plane. Omarchy is a practical dogfooding environment; demand from its users is still a hypothesis.

The proposed gate is one controller, two Linux hosts, one AI worker completing a brokered authenticated operation, and one ordinary systemd service using credential delivery. Run this with both native and container controllers, then test a second AI adapter. Recruit at least three external operators and seek repeat real usage from at least two. These are experiment targets, not current traction.

Reassess after the validation window if repeat use is absent despite deliberate recruitment. This does not depend on a competitor shipping an equivalent feature. Downloads and stars are secondary signals. See the [roadmap validation gate](Roadmap%20Reset%202026-09.md#12-success-metrics-and-kill-criteria).

---

## 5. Regulatory And Standards Tailwind

Relevant mainly to the later enterprise motion, not to the developer wedge.

- **MAS / industry SAFR white paper (2026-07-03)** — participants include HSBC, JPMorgan, OCBC, Circle, Ant, Mastercard, Visa. Defines a runtime layer of Agent Identity, Controls Repository, Disposition Engine, and Audit Log, with every agent action resolving to Deny / Escalate / Auto-Execute / Observe. **BlindPass's exchange policy engine, approval workflow, and audit log map onto this directly.** Not supervisory guidance, but a strong signal for the regulated-enterprise story.
- **MAS AI Risk Guidelines** — consulted 2025-11-13 to 2026-01-31, explicitly covering agentic AI, with a proposed 12-month transition. Not finalised at time of review. The AI Risk Management Toolkit was published 2026-03-20.
- **MAS TRM Notices amendment consultation** (2026-06-10, closed 07-31) — proposes a mandatory inventory of cryptographic assets. Existing TRM Guidelines already require key management and privileged-access controls. No MAS statement found that names LLMs handling credentials specifically (*unverified gap*).
- **OWASP Top 10 for Agentic Applications 2026** (2025-12-09) — ASI03 Identity & Privilege Abuse: "Broad, long-lived tokens convert minor hijacks into major data breaches."
- **OWASP Agentic Skills Top 10 v1.0** (2026-08-17) — AST03 Over-Privileged Skills; prescribes per-skill scoped credentials rather than ambient agent authority.
- **CISA and Five Eyes, "Careful Adoption of Agentic AI Services"** (2026-04-30) — per-agent cryptographic identity and short-lived credentials as baseline.
- **NIST AI Agent Standards Initiative** (2026-02-17) and NCCoE concept paper (2026-02-05) — names "agents inherit user permissions" and "generic service accounts" as anti-patterns.

No standard yet names "secret pasted into agent chat" verbatim. The MCP specification's "never pass through the LLM context" is the closest normative statement, and it is a positioning gap BlindPass can own.

---

## 6. Where The Build Went Wrong

Detail in [Repo State Findings 2026-09](Repo%20State%20Findings%202026-09.md). Summary:

| Symptom | Evidence |
|---|---|
| **Project is dormant** | 126 commits between 2026-03-05 and 2026-04-18, single author, nothing since |
| **No distribution** | Nothing published to npm under the `@blindpass` scope; default server hostname does not resolve |
| **Headline flow broken off-OpenClaw** | `request_secret` throws in plain MCP mode because it has no channel to deliver the link |
| **Stale protocol** | MCP server pins `2024-11-05`, declares tools only, implements no elicitation |
| **MCP framing mismatch** | September 12 probe: standard newline-delimited initialization received no response; the server expects `Content-Length` framing. See [MCP server](../../packages/openclaw-plugin/mcp-server.mjs) and the [stdio specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) |
| **Credential consumption gap** | Plugin-local storage does not automatically make a received credential usable by a stock client's shell or other tools; the pilot must implement the authenticated operation |
| **Scope skew** | Payments, guest intake, and billing code outweighs core secret and exchange code roughly 1.7 : 1 |
| **Adoption assumptions untested** | Hosted multi-tenant SaaS, Stripe, x402, i18n, and analytics all built before a single external user |

Existing test suites and security documentation are reusable assets. They do not establish stock-client interoperability, OS workload isolation, or native/container deployment parity. Address defects in the selected execution path before publishing it; keep unrelated billing and platform expansion frozen. The [fleet test plan](../testing/Native%20Linux%20Fleet%20Pilot.md) defines the additional proposed evidence.

---

## 7. Pricing Reality Check

### 7.1 What the market actually charges

| Model | Examples | Rate |
|---|---|---|
| Per seat | 1Password Teams / Business | $3.99 / $7.99–8.99 per user per month |
| Per seat | Doppler Team | ~$21 per user per month |
| **Per machine identity** | **Infisical Pro / Advanced** | **$20 / $40 per identity per month** |
| Per auth event | **Arcade.dev** | $25/mo + $0.10 per auth event + $0.01 per tool call |
| Per secret + calls | AWS Secrets Manager | $0.40 per secret per month + $0.05 per 10k calls |
| Add-on percentage | Auth0 for AI Agents | +50% of base plan |

Infisical's per-identity pricing is the closest precedent for charging per agent. Arcade's per-auth-event pricing is the only live precedent for charging per exchange.

### 7.2 The x402 problem

x402 is a real standard with real governance — Linux Foundation operational launch 2026-07-14 with 40 members including Coinbase, Circle, Visa, Mastercard, Stripe, Google, and AWS. v2 shipped January 2026.

But the commerce is thin:

| Metric | Value |
|---|---|
| Cumulative transactions (Coinbase, late Apr 2026) | 165M |
| Estimated share gamified / farmed | ~50% |
| Real commerce volume | ~$28K per day |
| Median call price | ~$0.02–0.028 |
| Priced endpoints publishing a price | ~25% |

**Nobody sells secret exchange over x402.** Building guest paid intake, a separate guest ledger, allowances, facilitator abstractions, and crypto checkout on this rail was premature. The rail is not wrong, the timing is.

### 7.3 Proposed model

| Tier | Price | Rationale |
|---|---|---|
| **Local / pilot** | Free evaluation, no mandatory hosted signup | Prove the operation and service-delivery workflows |
| **Self-hosted control plane** | Commercial packaging remains to be validated under the existing repository licenses | Native and container are deployment choices, not separate functionality tiers; self-hosting is part of the initial pilot |
| **Managed hosted teams** | Existing $29 workspace entry and per-workload pricing are hypotheses | Validate the buyer and repeat usage before adding billing machinery; account for both agents and ordinary services |
| **Brokered A2A / enterprise support** | Deferred | Require a named customer need before choosing metering or contract terms |

Do not infer BlindPass's price from another product's identity count. Freeze x402 billing investment. Deployment packaging does not alter the repository's current licenses or establish a new commercial entitlement.

---

## 8. Risks To The Thesis

| Risk | Severity | Mitigation |
|---|---|---|
| **Existing products meet the user's need** | High | Compare the whole workflow with 1Password, Vault Agent, Infisical Agent, and credential-request products; avoid claiming the crypto alone is a moat |
| **MCP clients build secure input natively** | High | Measure whether cross-runtime and native-service access still adds value; this is not a reason to expand A2A preemptively |
| **OpenClaw dependency** | Medium | Governance is unsettled (creator joined OpenAI Feb 2026; foundation funded by OpenAI). ~385K stars but a poor security record. Treat as one channel, never the only one |
| **Solo maintainer, dormant 5 months** | High | Scope cut is the only realistic mitigation. The current surface area cannot be maintained by one person |
| **Security guarantees are overstated** | High | Name plaintext endpoints, same-user isolation limits, recipient-key trust, and the difference between grant revocation and provider revocation |
| **Host broker becomes a broad privilege boundary** | High | Keep privileged functions small, use protected workload registration, and test impersonation and output leakage before distribution |
| **Deployment modes diverge or lose state** | High | One API/configuration contract; run the same tests in native and container modes and validate migration, backup, and restore |
| **Controller is unavailable** | Medium | Support an always-on deployment, expose disconnection, and define expiry behavior without promising recall of delivered credentials |
| **Linux support recreates scope sprawl** | High | Limit the first pilot to two hosts, one API operation, and one service; keep scheduling, arbitrary remote execution, and general vault replacement out of scope |
| **Category consolidates before traction** | Medium | Validate operator use directly; acquisitions do not establish this product's prospects |

---

## 9. Sources

Specification and standards:

- MCP elicitation, spec 2026-07-28 — <https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation>
- SEP-1036, URL-mode elicitation — <https://modelcontextprotocol.io/seps/1036-url-mode-elicitation-for-secure-out-of-band-intera>
- MCP 2026-07-28 release notes — <https://blog.modelcontextprotocol.io/posts/2026-07-28/>
- MCP 2026 roadmap — <https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/>
- OWASP Top 10 for Agentic Applications 2026 — <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- CISA, Careful Adoption of Agentic AI Services — <https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services>
- NIST AI Agent Standards Initiative — <https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure>
- MAS SAFR white paper — <https://www.mas.gov.sg/-/media/mas-media-library/development/fintech/ai-safr/safr.pdf>
- MAS TRM amendment consultation — <https://www.mas.gov.sg/publications/consultations/2026/consultation-paper-on-proposed-amendments-to-notices-on-technology-risk-management>

Competitors:

- [Yopass secret requests](https://yopass.se/docs/secret-requests/) — September 12 correction to the original encryption comparison
- [Vault Agent](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent) — Linux credential-delivery alternative
- [Infisical Agent](https://infisical.com/docs/integrations/platforms/infisical-agent) — Linux credential-delivery alternative

- 1Password for Claude — <https://1password.com/press/2026/july/1password-for-claude>
- 1Password secure AI access — <https://www.1password.dev/get-started/secure-ai-access>
- Doppler for agents — <https://www.doppler.com/agents>
- HashiCorp native AI agent support in Vault — <https://www.hashicorp.com/en/blog/announcing-native-ai-agent-support-in-hashicorp-vault>
- Bitwarden Agent Access SDK — <https://bitwarden.com/blog/introducing-agent-access-sdk/>
- AgentLair, how should agents get credentials — <https://agentlair.dev/blog/how-should-agents-get-credentials>
- Composio May 2026 security incident — <https://composio.dev/blog/composio-may-2026-security-incident>
- Arcade pricing — <https://www.arcade.dev/pricing>
- Infisical pricing — <https://infisical.com/blog/secrets-manager-pricing>

Demand and incidents:

- Claude Code issue 29910 — <https://github.com/anthropics/claude-code/issues/29910>
- Claude Code issue 58043 — <https://github.com/anthropics/claude-code/issues/58043>
- OpenClaw issue 7916 — <https://github.com/openclaw/openclaw/issues/7916>
- OpenClaw secrets documentation — <https://docs.openclaw.ai/gateway/secrets>
- GitGuardian State of Secrets Sprawl 2026 — <https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/>
- Malicious ClawHub skills — <https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html>
- Autonomous agents compromising credentials — <https://thehackernews.com/2026/09/autonomous-ai-agents-compromise.html>

Market:

- Cyera to acquire Oasis — <https://techcrunch.com/2026/07/28/cyera-agrees-to-acquire-oasis-security-for-1b-to-safeguard-proliferating-ai-agents/>
- Cisco to acquire Astrix — <https://blogs.cisco.com/news/cisco-announces-intent-to-acquire-astrix-security>
- Arcade $60M — <https://www.businesswire.com/news/home/20260615229631/en/Arcade-Raises-$60M-to-Become-the-Secure-Action-Layer-Behind-Every-Production-AI-Agent>
- x402 Foundation operational launch — <https://www.linuxfoundation.org/press/linux-foundation-announces-operational-launch-of-x402-foundation-to-standardize-internet-native-payments-for-ai-agents-and-applications>
- x402 adoption tracker — <https://presenc.ai/research/x402-protocol-adoption-tracker-2026>

Linux fleet research:

- [Systemd credentials](https://systemd.io/CREDENTIALS/) — native service consumption
- [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/) — node and workload identity
- [Omarchy shell documentation](https://github.com/omacom/omarchy/blob/quattro/docs/omarchy-shell.md) — plugin integration and shared-process boundary
- [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) — September 12 interoperability correction

> **Verification note:** the original September 10 market and incident claims are a dated snapshot; selected protocol, competitor, and Linux integration sources were checked on September 12. Native/container deployment parity is a requirement, not an implemented capability. Third-party aggregate statistics remain directional and should be re-checked before external use.
