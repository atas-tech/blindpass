# BlindPass Roadmap

**Consolidated:** 2026-09-22

**Status:** Proposed implementation plan. The Linux fleet direction and native/container controller requirements were previously requested; browser session handoff remains the proposed W1 operation, pending selection of the application and integration. No milestone is marked implemented by this consolidation.

**Companions:** [Specification](Specification.md) · [Pilot and milestone test plan](../testing/Linux%20Fleet%20Pilot.md)

## Product outcome

An operator deploys one controller natively or in a container, approves a registered workload from Omarchy, and that workload completes an authenticated task through its Linux host broker. The pilot must demonstrate an AI browser task and an ordinary systemd service job across two hosts.

Start with one staging application, one dedicated restricted account, one browser integration, and one backup service. A second static account tests separation. The controller and brokers work headlessly; Omarchy supplies the first operator interface. Self-hosting requires local administration and enrollment, with no mandatory hosted signup.

The browser proposal protects the source password against accidental exposure. The agent intentionally receives a bounded application session and can inspect that session through its browser tools. Native service delivery gives plaintext to a trusted consumer. Neither flow supports a blanket claim that an agent or consumer can never hold credentials. See the [mode contracts](Specification.md#consumption-modes).

## Why this scope

The September review found a gap between collecting a secret and completing useful work in a stock AI client. Existing HPKE, exchange policy, approval, audit, and persistence code are foundations, while host workload authentication, runtime-independent consumption, and deployment parity need new implementation and evidence. The [finding register](Specification.md#repository-findings) retains all F-1–F-13 items.

The product hypothesis is that operators value approval tied to a verified local workload, fresh credential provisioning, and actual consumption across agents and Linux services. Encryption, secret-request links, and credential injection alone are insufficient differentiation. Compare the complete workflow against native encrypted systemd credentials and existing managers before expanding the platform.

The research recorded alternatives in several groups; these are dated research leads, not a refreshed comparison of current features or prices:

| Alternative | Pilot question | Retained research sources |
|---|---|---|
| Native encrypted credentials, Vault Agent, Infisical Agent | Does approval and audit justify another daemon over file delivery or templates? | [Systemd credentials](https://systemd.io/CREDENTIALS/), [Vault Agent](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent), [Infisical Agent](https://infisical.com/docs/integrations/platforms/infisical-agent) |
| Secret-request and human approval tools | Is a completed, approved workload operation more useful than a secure handoff alone? | [Yopass requests](https://yopass.se/docs/secret-requests/), [Bitwarden Agent Access SDK](https://bitwarden.com/blog/introducing-agent-access-sdk/), [1Password remote-approval request](https://www.1password.community/developers-69/feature-request-remote-approval-for-op-cli-desktop-prompts-to-support-agentic-workflows-24119) |
| Credential proxies and agent sandboxes | What value remains beyond keeping a source token out of the agent? | [nono](https://github.com/nolabs-ai/nono), [Infisical agent-vault](https://github.com/Infisical/agent-vault), [Aembit](https://docs.aembit.io/ai-guide/mcp/identity-gateway/), [Riptides](https://riptides.io/blog/when-ebpf-isnt-enough-why-we-went-with-a-kernel-module/) |
| Workload identity and federation | Can an existing identity system meet the need without a BlindPass-specific deployment? | [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/), [Teleport workload attestation](https://goteleport.com/docs/reference/machine-workload-identity/workload-identity/workload-identity-api-and-workload-attestation/), [1Password Credential Broker](https://1password.com/product/credential-broker) |

Developer credential-handling requests and incident reports motivated the original review; they do not prove adoption or willingness to pay. Omarchy is a practical starting environment because of existing operator familiarity and plugin experience. Platform downloads, stars, funding, and acquisitions are not evidence of BlindPass demand. No exclusivity, regulatory compliance, or market-size claim is carried into the acceptance criteria.

## Sequence and gates

W1–W6 retain the earlier roadmap identifiers. W0 names the prerequisite identity spike that previously appeared only in the sequencing table. W5 work affecting the pilot starts with W0 and must finish before W3; its number does not place security work after publication. Effort and dates must be estimated from the spike, not treated as commitments.

| Order | Milestone | Exit evidence | Test-plan section |
|---|---|---|---|
| 1 | W0: Host identity and custody | Real system-unit authentication, denied impersonation, bounded failed delivery, explicit custody profile | [Fleet integration](../testing/Linux%20Fleet%20Pilot.md#identity-and-authorization-integration) |
| 2 | W1: Complete the AI and service workflows | Stock-client browser task plus backup/restore job; safe transport and tested session revocation | [Browser](../testing/Linux%20Fleet%20Pilot.md#browser-session-handoff), [MCP](../testing/Linux%20Fleet%20Pilot.md#mcp-and-release-integration) |
| 3 | W2: Two-host native/container parity | Both controller packages pass common workflows, lifecycle, recovery, and migration in both directions | [Deployment](../testing/Linux%20Fleet%20Pilot.md#controller-packaging-persistence-and-migration) |
| Before release | W5: Pilot security and documentation | Selected-path findings resolved or explicitly block release; accurate evidence and product claims | [Security and later milestones](../testing/Linux%20Fleet%20Pilot.md#security-and-later-milestones) |
| 4 | W3: Package, publish, recruit | Clean installation, supported client matrix, external setup and repeat-use evidence | [Release](../testing/Linux%20Fleet%20Pilot.md#mcp-and-release-integration) |
| After repeat use | W4: OpenClaw expansion | Reversible migration and actual runtime consumption | [Deferred milestone scenarios](../testing/Linux%20Fleet%20Pilot.md#security-and-later-milestones) |
| Named demand | W6: Cross-workload fulfillment | A specific operator need and tested authorization/lifecycle contract | [Deferred milestone scenarios](../testing/Linux%20Fleet%20Pilot.md#security-and-later-milestones) |

### W0: Host identity and custody

Implement the smallest privileged host boundary needed for protected system-unit registration, peer authentication, custody, and service delivery. Keep the TypeScript controller unprivileged; select a broker implementation language only after checking the OS APIs required. Use direct pidfd-based local identity as the proposed baseline; SPIRE adoption is deferred pending an independent need and security evaluation.

The gate requires root-only credential-loader sockets, OS-derived unit and invocation binding, denial of user-manager clients and forged abstract socket names, PID-reuse handling, and startup validation by each credential-consuming service. Distinct service accounts isolate workers from the operator, broker, and private login helper. Missing pidfd support must produce an unsupported-host result, not a weaker authentication fallback.

System-scope loader behavior, `DynamicUser=`, encrypted socket behavior, cross-account permissions, and broker timeout semantics remain real-VM verification obligations. Compare the broker against a `LoadCredentialEncrypted=` baseline. Choose an explicit ephemeral or encrypted persistent custody/recovery profile before claiming unattended restart support.

### W1: Complete the AI and service workflows

Use browser login with session handoff as the proposed concrete AI operation. Confirm the staging application, restricted account, browser integration, and useful UI task before implementing the application-specific handler. If the application cannot enforce session lifetime, revocation, and disabled durable-credential creation, choose another application; do not relax the contract.

The broker authenticates privately, transfers only approved session cookies through a trusted runtime channel into a fresh workload-bound context, and returns a context reference plus a fixed safe status. The agent then completes the UI task. Completion, cancellation, expiry, and crash recovery must revoke the server session and clean up contexts. CI, strong browser confinement, generic form filling, and extensions are outside W1.

Repair the [MCP server](../../packages/openclaw-plugin/mcp-server.mjs) and [delivery routing](../../packages/openclaw-plugin/blindpass-core.mjs): standard newline-delimited stdio, version-specific negotiation, URL-mode client capability checks, and an out-of-band fallback. Full requirements live in the [specification](Specification.md#mcp-and-human-input-transport).

W1 passes only when:

- A stock Claude Code client and at least one additional stock client, VS Code or Codex CLI, complete the operation through the same broker contract. Record actual versions and unsupported combinations.
- An elicitation-capable flow and an elicitation-unavailable flow succeed without requiring OpenClaw or Telegram. Secure URLs, confirmation codes, source passwords, and raw cookies stay out of default model-visible results and ordinary logs.
- The application enforces its restricted account role, bounded non-renewable session authority, and server-side revocation; replay tests demonstrate both intended session access and loss of access after revocation.
- An ordinary systemd backup service uses a pre-provisioned credential to write and restore a disposable artifact, without an AI client. Rotation requires a tested reload/refresh integration or controlled restart.
- The [browser first gate](../testing/Linux%20Fleet%20Pilot.md#browser-first-gate), fleet identity/isolation scenarios, and client scenarios are implemented and pass. Secret collection into plugin memory alone does not pass.

### W2: Two-host native/container parity

Ship one controller API/configuration/policy model in a dedicated-account native systemd package and a non-root OCI image with Docker Compose. Native installation has no container-runtime prerequisite. Host brokers remain native services in both profiles.

Run the same two-host approval, operation, service-delivery, denial, revocation, and disconnection workflows for both packages. Repeat with a separate controller host; Omarchy logout must not stop control-plane services. Verify container replacement, native upgrade, schema migration, rollback or restore, backups including keys, and native-to-container/container-to-native migration without unnecessary reenrollment when endpoint and trust are preserved.

A migration must stop or fence the source controller. Neither backup restoration nor container deployment implies high availability. The [deployment contract](Specification.md#controller-deployment-and-recovery) and full D-series tests determine support; passing one package cannot establish support for the other.

### W5: Pilot security and documentation

Triage the [retained findings and audit backlog](Specification.md#repository-findings) against the selected pilot path. Address exposure, authorization, and deployment defects before publishing that path. Frozen paid/guest functionality retains its backlog and existing tests; it is not silently declared fixed or required to expand the pilot.

Required review areas include secure confirmation-code generation and entropy; hashed, expiring verification tokens where used; account authentication controls; generated-key/log hygiene; request timeouts; production origin allowlists; HSTS after HTTPS readiness is verified; and accurate endpoint configuration. The September 22 documentation alignment resolved the cipher/auth descriptions and found verification-token hashing/expiry already implemented; retain their regression checks and address the remaining storage/cleanup risks recorded in the [current threat model](../security/blindpass-threat-model.md). Document real plaintext endpoints, isolation limits, and revocation semantics in user-facing claims.

Run relevant security regressions and deployment smoke checks. Publishing interoperability findings is optional and follows demonstrated client behavior, not assumptions about a protocol version.

### W3: Package, publish, recruit

Choose and verify canonical public endpoints before changing defaults. The September review found `sps.blindpass.dev` unavailable while the `atas.tech` deployment responded; those are historical observations, not current health checks. Validate configuration consistency deterministically in package checks and live endpoint resolution/readiness in release smoke checks.

| Artifact | Intended channel | Gate |
|---|---|---|
| Controller and host broker | Versioned Linux release with service definitions | Clean native setup, explicit privilege boundaries, lifecycle/recovery docs |
| Controller image and Compose profile | Container registry and release bundle | Same controller version/contracts and passing D-CONTAINER evidence |
| Omarchy widget and approval application | Reviewed application/plugin release | Metadata-only widget, separate authenticated approval path |
| `@blindpass/mcp-server` | npm | Clean-machine `npx` flow against a configured broker |
| MCP listing and OpenClaw package | MCP Registry and ClawHub | Follow a working adapter; listing breadth does not replace the pilot gate |
| `@blindpass/sdk` | npm, after the above | Needed consumer integration and tested published contents |

Only remove `private: true` from packages intentionally released. Retain the credential/package checks in [publish_clawhub.sh](../../scripts/publish_clawhub.sh). Quickstarts must take an unfamiliar operator through completed work, with health, upgrade, backup, restore, and uninstall instructions. Record supported backing-service topologies and actual client versions.

Choose numerical timeout, revocation, and approval-frequency bounds from measured pilot behavior and record them before external recruitment. Missing bounds block the associated release claim. Collect the [90-day validation evidence](#validation-and-stopping-criteria).

### W4: OpenClaw expansion

Activate after repeat fleet use or a named adapter-specific need. Position this integration around encrypted secrets and practical migration, while keeping OpenClaw optional for the broker.

The proposed `blindpass migrate-openclaw` command scans `openclaw.json`, `auth-profiles.json`, and `.env`, displays masked findings, imports into the encrypted store, and rewrites references to the BlindPass exec provider. Require a non-mutating dry run, protected backups, explicit rollback, and successful runtime reload/consumption. Any removal of plaintext originals is an explicit operator action with storage-erasure limitations documented.

Preserve the [activation-time resolver constraint](../plugins/openclaw-capability-extension.md): newly provisioned secrets require reload before other consumers see them. Loss of `.age-key.txt` makes the encrypted store unrecoverable without a valid backup; retain `bootstrap_backup_pending` reporting. Packaging or this roadmap does not change licenses.

### W6: Cross-workload fulfillment

Activate only after repeat use and a named need, or a specific design-partner engagement. Determine whether the operator needs secret transfer, a provider-issued scoped credential, or a brokered operation. Existing A2A policy, approval, audit, tombstones, and rotation lineage are reusable foundations; operation grants require separate types and tests.

Internal dogfooding can validate the chosen need. It does not authorize broad enterprise federation, autonomous billing, or a general scheduler. Before implementation, extend the corresponding scenario detail in the [test plan](../testing/Linux%20Fleet%20Pilot.md#security-and-later-milestones).

## Freeze register

Frozen means retain existing code and regression coverage, keep optional surfaces disabled where appropriate, and stop expansion. This documentation cleanup removes superseded documents, not the implementations below.

| Area | Condition for reconsideration |
|---|---|
| x402 payments | A paying customer specifically requires autonomous machine payment |
| Guest paid intake, Phase 3C | A design partner needs external-requester intake |
| Hosted crypto checkout, Phase 3D | An actual buyer cannot be served by the existing payment path |
| Python/Go SDK expansion, Phase 3E | A user needs an SDK for a language they deploy |
| Further localization | Actual non-English users need it |
| Telegram/WhatsApp breadth, Phase 4 | A working integration demonstrates recurring channel-specific demand |
| Human-to-human sharing | A separately justified product decision; not part of this pilot |
| Enterprise and CI identity federation, Phase 5 | A named customer need and a separate identity/threat-model review |
| Browser strong mode | A separate decision to constrain all protected-session tools and alternate access paths |
| Generic login-form testing or Chrome extension | A real workflow needing those modes; separate compatibility and security evidence |
| Account pools, CI runners, sharding | A selected concurrency/CI use case; no W1 scheduler or account-leasing service |
| Containerized brokers/workloads, arbitrary remote execution, scheduling, eBPF, Kubernetes, full vault replacement | Separate scope decisions; not required for initial Linux access control |

## Pricing and licensing

The pilot is a free evaluation without mandatory hosted signup. Native and container deployment are equivalent functionality choices. Existing [repository licenses](../../LICENSES.md) remain authoritative.

The earlier $29 hosted-workspace entry, per-workload pricing, and the round-two suggestion of a free small fleet followed by roughly $99/year are competing hypotheses, not approved prices or entitlements. A free, open-source Omarchy widget is the research recommendation; new component licensing still requires an explicit decision. Validate repeat use and buyer preference before choosing self-hosted support or managed-hosting packaging. Keep x402 out of the active pricing plan.

## Validation and stopping criteria

Measure the first 90 days after pilot publication:

| Measure | Required evidence or target |
|---|---|
| External setup | At least three deliberately recruited operators attempt installation; record failures and preferred deployment mode |
| Repeat use | At least two repeat real workflows without maintainer intervention |
| Completed work | Authenticated AI task and native backup/restore job across two hosts |
| Deployment | Passing common/package suites and migration evidence in both directions |
| Approval fatigue | Prompts per operator per active day, dismissals, and overrides against a numerical ceiling agreed before recruitment; batching and scoped time-bounded grants are first-version requirements |
| Added value | Compare the encrypted-credstore baseline and existing managers; record which workflow operators would keep and why |
| Buyer evidence | Willingness to pay for support or hosting, and whether an existing tool would suffice |

These are experiment targets, not traction. Reassess after 90 days if repeat use is absent despite deliberate recruitment, if approvals exceed the agreed ceiling, or if operators mainly want existing credential templates. Narrow the supported profile if acceptable isolation cannot be demonstrated. Preserve useful integrations without enlarging the platform to justify earlier work.

## Consolidation record

This roadmap and the specification replace the September product review, roadmap reset, repository findings, native fleet research, round-two fleet research, and browser credential-injection research. The two pilot test plans are merged in [Linux Fleet Pilot](../testing/Linux%20Fleet%20Pilot.md), with original scenario identities retained by namespace.

The September 10 review examined commit `5b233c3`; September 12 added protocol/fleet corrections and a user-scope socket probe; September 21 proposed browser session handoff. This consolidation preserves their requirements, findings, boundaries, and open decisions, while dropping duplicate prose and volatile market tables. It does not rerun their live-service, market, or OS experiments. [Architecture phase documents](../archive/architecture/Implementation%20Plan.md) remain historical implementation records; this roadmap governs proposed forward scope.
