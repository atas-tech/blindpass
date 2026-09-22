# OpenClaw integration and current MCP limits

**Source inspection:** 2026-09-22. This replaces the April capability brainstorm as the current integration reference. The original design and historical test plan retain their original context in the Obsidian vault. Release availability and compatibility require their own evidence.

## Components and tools

[blindpass-core.mjs](../../packages/openclaw-plugin/blindpass-core.mjs) implements provisioning, transport routing and tools. [encrypted-store.mjs](../../packages/openclaw-plugin/encrypted-store.mjs) provides the SOPS backend. [blindpass-resolver.mjs](../../packages/openclaw-plugin/blindpass-resolver.mjs) implements the exec-provider JSON protocol. [mcp-server.mjs](../../packages/openclaw-plugin/mcp-server.mjs) is the separate MCP entry point.

| Tool | Contract |
|---|---|
| `request_secret` | Human-provided secret through an encrypted browser-input flow; requires a description and a configured delivery path |
| `request_secret_exchange` | Request an SPS-mediated exchange with a named fulfiller/purpose |
| `fulfill_secret_exchange` | Fulfill a scoped exchange token |
| `store_secret` | Optional runtime-owned value import; enabled only with `BLINDPASS_ENABLE_STORE_TOOL=true`; do not send a real secret as model-authored input |
| `list_secrets` | Managed-store names/metadata, not values |
| `delete_secret`, `confirm_delete_secret` | Two-step deletion using a short-lived confirmation token |

Use `secret_name` when requesting managed persistence. `persist=false` explicitly requests runtime-only storage. In the current handler, an omitted `persist` follows `BLINDPASS_AUTO_PERSIST`, whose default is false; some existing tool-schema prose says it defaults to true, so use an explicit value instead of depending on that inconsistent description.

The core tries OpenClaw chat API, runtime/CLI routing and Telegram fallback for input-link delivery. Configure `SPS_BASE_URL` explicitly; the old `sps.blindpass.dev` default has not passed the distribution gate. Links/confirmation codes must stay in an intended human channel, and plaintext exposure/raw-link flags are outside default secrecy claims.

## Custody and activation

The built-in managed backend is **SOPS only**. An arbitrary vault-adapter setting is not a shipped integration. SOPS/age bootstrap requires the corresponding local executables when creating a new encrypted store. Runtime-only memory is volatile; configured managed writes must not be presented as durable if the backend fails.

The store location is selected by explicit `BLINDPASS_STORE_PATH` or the runtime convention: the OpenClaw gateway's `blindpass` directory, otherwise the user's `.blindpass` directory on POSIX, or the configured Windows local application data directory. See the implementation for gateway-directory precedence. Resolver `--store` overrides its input path.

Bootstrap maintains encrypted data, `.sops.yaml` and `.age-key.txt`, with `bootstrap_backup_pending` guidance. Loss of the decryption key can make data unrecoverable; back up the selected encrypted-store recovery material and acknowledge through the supported `BLINDPASS_BACKUP_ACKNOWLEDGED` behavior. Do not advertise a standalone acknowledgement command merely because it appeared in the old brainstorm.

The resolver reads protocol-v1 JSON from stdin and returns `values`/`errors` JSON to its caller. Its default overall timeout is 10 seconds, configurable through `BLINDPASS_RESOLVER_TIMEOUT_MS`. That stdout intentionally contains plaintext values for the trusted consumer; it is not a model-facing result or proof of model blindness.

OpenClaw's exec-provider integration materializes credentials at activation/reload. A newly provisioned value is not automatically visible to other consumers until their runtime reloads. The [activation harness](../../scripts/tests/openclaw_activation.test.mjs) records the repository's tested contract; verify the actual OpenClaw version and consuming integration before claiming compatibility. At-rest encryption does not constrain a process that has already received the value.

## MCP and browser scope

The MCP entry point still advertises `2024-11-05`, expects `Content-Length` framing, and has no URL-mode elicitation. Its registration hooks do not create a general bridge from the secret map to a stock client's shell or browser. A config file, generated entry point or package manifest is not evidence that the full flow works in Claude Code, Codex or another client.

W1 must implement standard framing, negotiated human-input transport and actual credential consumption through the proposed host broker. Browser session handoff protects the source password against accidental exposure while intentionally giving the agent session authority. It is a new operation, not an existing OpenClaw storage capability. See [the specification](../product/Specification.md#mcp-and-human-input-transport).

## Packaging and maintenance

The repository has scripts for [building](../../scripts/build_bundle.sh), [staging distribution](../../scripts/publish_dist.sh), [ClawHub publication](../../scripts/publish_clawhub.sh) and [installation](../../scripts/install_skill.sh). Treat npm/registry listings as W3 release work until verified; do not copy historic `npx`/registry installation claims into a current quickstart.

The retained repository instruction file is [AGENTS.md](../../AGENTS.md); integration tool guidance lives with the packaged skill. Distribution metadata must list only retained artifacts. Run the relevant [packaging tests](../testing/README.md#test-matrix) when those files change.

The proposed plaintext-config migration command and broader OpenClaw expansion remain W4 work, with [A-series scenarios](../testing/Linux%20Fleet%20Pilot.md#security-and-later-milestones). No generic migration, new backend, additional client support or release readiness is established by this documentation cleanup.
