# OpenClaw Plugin: Capability Extension Brainstorm

> Historical design/review snapshot. Superseded for current behavior by the [documentation index](../../README.md); forward scope is in the [roadmap](../../product/Roadmap.md). Original decisions and status claims are retained as dated history.

> **Status:** Final · All decisions resolved\
> **Date:** 2026-04-02\
> **Scope:** ClawHub publishing + Secrets Manager integration + Multi-agent compatibility

---

## Table of Contents

- [1. Context & Current State](#1-context--current-state)
- [2. Capability A: Publish to ClawHub + npm](#2-capability-a-publish-to-clawhub--npm)
- [3. Capability B: OpenClaw Secrets Manager Integration](#3-capability-b-openclaw-secrets-manager-integration)
- [4. Capability C: Multi-Agent Compatibility via MCP](#4-capability-c-multi-agent-compatibility-via-mcp)
- [5. Distribution Strategy](#5-distribution-strategy)
- [6. Architecture Overview](#6-architecture-overview)
- [7. Implementation Phases](#7-implementation-phases)
- [8. Resolved Decisions](#8-resolved-decisions)
- [9. Additional Considerations](#9-additional-considerations-all-resolved)

---

## 1. Context & Current State

### What we have today

The `packages/openclaw-plugin` is a native OpenClaw plugin that registers three tools:

| Tool | Purpose |
|---|---|
| `request_secret` | Request a secret from a human via encrypted browser link |
| `request_secret_exchange` | Request a secret from another agent via SPS pull protocol |
| `fulfill_secret_exchange` | Fulfill an incoming agent-to-agent exchange |

**Current secret storage** is entirely **in-memory** (`_inMemorySecrets` Map of `Buffer` objects). The plugin attempts to delegate to runtime `setSecret`/`storeSecret` if available, but falls back to its own volatile Map. Secrets are lost on restart and never persisted to disk or an external vault.

### Key files

| File | Role |
|---|---|
| `index.mjs` | Plugin entry — tool registration, in-memory store, message routing |
| `sps-bridge.mjs` | SPS client wrapper — HPKE, JWT auth, poll/retrieve flows |
| `agent-transport.mjs` | Agent-to-agent delivery — session resolution, message formatting |
| `openclaw.plugin.json` | Plugin manifest (id, config schema, skill refs) |
| `skills/blindpass/SKILL.md` | Agent skill instructions |
| `package.json` | NPM package metadata |

---

## 2. Capability A: Publish to ClawHub + npm

### Distribution channels

BlindPass should ship through **two primary channels** plus manual fallbacks:

| Channel | Install command | Audience | Role |
|---|---|---|---|
| **ClawHub** | `openclaw skills install blindpass` | OpenClaw users | Primary OpenClaw distribution |
| **npm (MCP)** | `npm install -g @blindpass/mcp-server` | Codex, Claude Code, Antigravity, other MCP clients | Primary cross-agent distribution |
| **npx (MCP)** | `npx @blindpass/mcp-server` | Any MCP-compatible agent | Zero-install evaluation path |
| **Git dist repo** | `./scripts/install_skill.sh --mode global --agent all` | Offline/manual installs | Fallback/manual channel |

Recommendation for Phase 1 packaging:

- Publish the OpenClaw plugin through **ClawHub**
- Publish the MCP server plus `blindpass-resolver` through **npm** as `@blindpass/mcp-server`
- Use the dist repo to mirror compiled artifacts and installers, not as the primary package boundary

### Reference: How dependency-guard does it

The [atas-tech/dependency-guard](https://github.com/atas-tech/dependency-guard) repo is a working model:

- `SKILL.md` frontmatter with `metadata` as single-line JSON (OpenClaw parser requirement)
- `metadata.openclaw.requires.bins` for CLI dependency filtering
- `version` in frontmatter as single source of truth for ClawHub
- `scripts/publish_clawhub.sh` builds a clean staging bundle
- `scripts/install_skill.sh` supports multi-agent install modes

### What we need to build

#### 2.1 Compiled bundle

The current `index.mjs` dynamically imports sibling monorepo packages (`packages/gateway/dist/`, `packages/agent-skill/dist/`). For distribution, we need to **compile into a self-contained ESM bundle** using esbuild or rollup.

```
src/                          dist/ (published)
├── index.mjs          ──►    ├── blindpass.mjs             (OpenClaw plugin bundle)
├── sps-bridge.mjs             ├── mcp-server.mjs            (MCP server bundle)
├── agent-transport.mjs        ├── blindpass-resolver.mjs     (exec provider CLI)
├── encrypted-store.mjs        ├── openclaw.plugin.json
├── blindpass-resolver.mjs     ├── skills/blindpass/SKILL.md
└── mcp-server.mjs             └── LICENSE
```

The bundle inlines the needed exports from `@blindpass/gateway` and `@blindpass/agent-skill` so the distributed plugin has **zero monorepo dependencies**. The SPS server remains a separate service (hosted or self-hosted).

#### 2.2 Update `SKILL.md` frontmatter

```yaml
---
name: "blindpass"
version: "0.1.0"
description: "Zero-knowledge secret provisioning via HPKE encryption. Request secrets from humans or other agents without exposing plaintext."
metadata: {"openclaw":{"emoji":"🔐","requires":{"bins":[]}}}
---
```

> `sops` is not a hard install dependency. BlindPass should detect and use a supported managed-store backend at bootstrap. SOPS is the default encrypted-file backend when available, and operators may override it with another external vault adapter.

#### 2.3 Scripts

| Script | Purpose |
|---|---|
| `scripts/build_bundle.sh` | esbuild compile → `dist/` |
| `scripts/publish_clawhub.sh` | Validate, bump version, stage, `clawhub publish` |
| `scripts/install_skill.sh` | Multi-agent installer (codex, claude, antigravity, openclaw, clawhub, all) |

#### 2.4 Security validation in publish

`publish_clawhub.sh` must verify before staging:
- No `.env` files in bundle
- No private keys or identity files
- No `node_modules/` or monorepo-specific paths
- No hardcoded SPS URLs pointing to local/dev instances

#### 2.5 Version synchronization

Three version fields exist: `SKILL.md` frontmatter, `openclaw.plugin.json`, and `package.json`. Strategy:

- **`SKILL.md` version** is the single source of truth (ClawHub convention)
- `scripts/publish_clawhub.sh --bump patch|minor|major` increments SKILL.md and syncs to `package.json` + `openclaw.plugin.json`

---

## 3. Capability B: OpenClaw Secrets Manager Integration

### Two separate secret planes

BlindPass has two distinct secret concerns that should stay separate in the design:

| Concern | Purpose | Required config |
|---|---|---|
| **SPS bootstrap auth** | Authenticate BlindPass to SPS so it can request or fulfill secret flows | `BLINDPASS_API_KEY` or gateway JWT-based auth |
| **Managed secret persistence** | Store received secrets for later SecretRef or MCP resolution | A configured managed-store backend (default SOPS when available, or another operator-selected vault adapter) |

`BLINDPASS_API_KEY` is only for connecting BlindPass to the SPS service. It is **not** the same thing as the encrypted store backend for secrets received afterward.

### How OpenClaw Secrets Management Works

OpenClaw has a robust secrets system built around the **SecretRef** contract:

```jsonc
{ "source": "env" | "file" | "exec", "provider": "default", "id": "..." }
```

| Source | How it works |
|---|---|
| `env` | Reads from environment variables |
| `file` | Reads from a local JSON file |
| `exec` | Runs an external binary that returns values via JSON protocol |

OpenClaw already has **built-in SOPS support** in its exec integration examples, making SOPS the natural default backend for BlindPass. But BlindPass should keep the managed-store layer pluggable so operators can point it at another external vault implementation when needed.

### The `exec` provider protocol

**Request (stdin):**
```json
{ "protocolVersion": 1, "provider": "blindpass", "ids": ["stripe.api_key.prod"] }
```

**Success (stdout):**
```json
{ "protocolVersion": 1, "values": { "stripe.api_key.prod": "<secret-value>" } }
```

**Error (stdout):**
```json
{ "protocolVersion": 1, "values": {}, "errors": { "stripe.api_key.prod": { "message": "not found" } } }
```

### Integration strategy: BlindPass as an `exec` provider backed by a managed-store adapter

#### 3.1 `blindpass-resolver` CLI

A compiled Node.js CLI binary that:

1. Reads the exec protocol request from stdin
2. Reads and decrypts the managed secret store using the configured backend (default: SOPS)
3. Resolves each requested ID from the decrypted data
4. Returns values via stdout (never logs plaintext)

**Key constraint:** The exec provider runs at **activation time** (startup/reload), not lazily. Secrets must be pre-provisioned before the gateway starts or before the next secrets reload.

#### 3.2 Write serialization

The managed store is a single encrypted file. Concurrent writes (e.g., two `request_secret` calls completing at the same time) must be serialized to prevent data loss. The write path uses:

1. **Advisory lockfile with PID ownership** — acquire `secrets.enc.json.lock` before any write operation. The lockfile records the owning PID and a timestamp
2. **Atomic rename** — decrypt → modify in memory → encrypt to `secrets.enc.json.tmp` → `rename()` to `secrets.enc.json`
3. **In-process write queue** — the plugin serializes concurrent write calls through an async queue so only one decrypt→modify→encrypt cycle runs at a time

If the lockfile is already held and cannot be acquired within 5 seconds, the write fails with an actionable error. The lockfile is released in a `finally` block to prevent stale locks. A stale lockfile is only broken if the recorded PID is no longer running (checked via `kill(pid, 0)`). If the PID check is inconclusive (e.g., permission denied), the lock is treated as live and the write fails rather than risking a race.

#### 3.3 Managed store path resolution

```
<gateway-config-dir>/blindpass/  (or platform-specific default for MCP)
├── secrets.enc.json    # encrypted secret store (default backend: SOPS)
└── .sops.yaml          # SOPS config (age key, KMS refs, etc.) — only when using the default SOPS backend
```

Default store locations:
- **OpenClaw**: `<gateway-config-dir>/blindpass/secrets.enc.json` (per gateway)
- **MCP Agents (Linux/macOS)**: `~/.blindpass/secrets.enc.json` (user home directory)
- **MCP Agents (Windows)**: `%LOCALAPPDATA%\blindpass\secrets.enc.json`

Bootstrap path resolution order:
- Follow the OpenClaw gateway config directory convention by default when running as an OpenClaw plugin
- Use the platform-aware MCP convention path when running outside OpenClaw
- Respect explicit operator overrides last-mile via config

The plugin detects the platform at runtime and resolves the convention path accordingly (using `process.env.LOCALAPPDATA` on Windows, `$HOME/.blindpass/` on POSIX). The location is fully configurable via:
- `BLINDPASS_STORE_PATH` env var (overrides platform detection)
- `--store` CLI flag on the resolver

**Why per-gateway?** OpenClaw supports [multiple gateways](https://docs.openclaw.ai/gateway/multiple-gateways). Each gateway has its own config directory, so secrets are naturally scoped per-gateway. This avoids concurrent read/write issues and follows the OpenClaw convention.

#### 3.4 Managed-store backend selection and SOPS bootstrapping

BlindPass should select the managed-store backend in this order:

1. An explicit operator-configured backend (for example, a future external vault adapter)
2. The default SOPS file backend if the environment and platform support it
3. Runtime-only memory mode if persistence is not required

On first use of the default SOPS backend (when no store exists), BlindPass:
1. Verifies the `sops` CLI is available
2. Generates or writes an **age-compatible** identity at `<store-dir>/.age-key.txt`
3. Creates a `.sops.yaml` config pointing to that identity
4. Initializes an empty encrypted store
5. **Prints loud recovery guidance** to stderr: the store path, the age public key, and an explicit warning that loss of `.age-key.txt` makes all stored secrets unrecoverable
6. Records a `bootstrap_backup_pending` flag in the store metadata until the operator runs `blindpass acknowledge-backup` (or sets `BLINDPASS_BACKUP_ACKNOWLEDGED=true`)

The pending-backup flag does **not** block operation — secrets can still be stored and resolved. It causes a reminder warning on every plugin startup until acknowledged. This balances usability (auto-bootstrap "just works") with safety (operators cannot silently miss the backup requirement).

This removes manual key bootstrapping for the default backend, but it does **not** make `sops` universal. If operators choose another supported vault adapter, BlindPass should use that backend's bootstrap and access rules instead.

#### 3.5 OpenClaw configuration example

```jsonc
{
  "secrets": {
    "providers": {
      "blindpass": {
        "source": "exec",
        // 💡 Note: If installed via npm, "blindpass-resolver" may be on your PATH.
        // If installed via ClawHub, use the absolute path to the script using node:
        "command": "node",
        "args": [
          "~/.openclaw/skills/blindpass/dist/blindpass-resolver.mjs",
          "--store",
          "~/.openclaw/blindpass/secrets.enc.json"
        ],
        "passEnv": [],
        "jsonOnly": true
      }
    }
  },
  "models": {
    "providers": {
      "openai": {
        "apiKey": {
          "source": "exec",
          "provider": "blindpass",
          "id": "openai.api_key"
        }
      }
    }
  }
}
```

Resolver behavior:

- If `--store` points at the default SOPS backend, `blindpass-resolver` should derive sibling bootstrap files such as `.sops.yaml` and `.age-key.txt` automatically from that store location
- Operators can still override that behavior with backend-specific environment variables when using an alternate backend
- OpenClaw installs should work with the convention path by default and only need explicit overrides when the operator chooses a custom location
- If OpenClaw is configured for managed persistence and the default SOPS backend is available, BlindPass should start with that backend automatically

#### 3.6 Simplified onboarding flow

For **interactive secret delivery only**, the minimum BlindPass configuration is:

| Config | Default | Notes |
|---|---|---|
| `SPS_BASE_URL` | `https://sps.blindpass.dev` | Hosted service by default |
| `BLINDPASS_AGENT_ID` | `blindpass-agent` | Stable agent identity |
| `BLINDPASS_API_KEY` | *(required unless gateway JWT auth is used)* | BlindPass bootstrap credential for talking to SPS |

Interactive-only usage rule:
- Keep the deployment installed normally, but call `request_secret` with `persist=false` for one-off secrets that should not enter the managed store

For **managed SecretRef persistence**, add:

| Config | Default | Notes |
|---|---|---|
| `BLINDPASS_STORE_PATH` | convention path | Optional override for encrypted store location |
| `BLINDPASS_AUTO_PERSIST` | `true` | Managed-store mode by default |
| Managed-store backend | auto-detected | Default SOPS backend if available, or operator-selected external vault adapter |

`BLINDPASS_API_KEY` can itself be a SecretRef or env var, keeping SPS bootstrap simple. Secrets received afterward are a separate concern and are persisted through the managed store only when a supported backend is configured or detected.

**Onboarding in 4 steps:**
1. `openclaw skills install blindpass`
2. Configure SPS auth via `BLINDPASS_API_KEY` or gateway JWT-based auth
3. If OpenClaw is configured for managed persistence and SOPS is available, BlindPass uses that backend by default; otherwise operators can configure another supported external vault backend
4. The agent calls `request_secret` with a `secret_name` when it needs a managed secret → user enters via browser → BlindPass stores it in the encrypted store

> **Note on Runtime Propagation:** When a new secret is provisioned, BlindPass can cache it in its own runtime for immediate local follow-up work. However, OpenClaw SecretRef consumers do **not** see that new value immediately. The `exec` provider materializes values into the gateway's active snapshot on startup, config reload, or `openclaw secrets reload`. Writing the SOPS file alone is not enough for other plugins or core model providers to observe the change.

#### 3.7 Secret lifecycle with OpenClaw integration

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SECRET LIFECYCLE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. PROVISION (interactive, via agent)                              │
│     Agent calls request_secret → User enters via browser            │
│     → HPKE decrypt → plaintext in memory                           │
│                                                                     │
│  2. PERSIST (automatic, configurable)                               │
│     If persist=true, plugin writes via selected managed backend     │
│     Default OpenClaw path uses SOPS when available/configured       │
│     Config: BLINDPASS_AUTO_PERSIST=true (default)                   │
│                                                                     │
│  3. REFERENCE (at gateway activation / reload)                      │
│     OpenClaw gateway starts or reloads secrets                      │
│     → calls blindpass-resolver                                      │
│     → resolver reads managed backend → returns to gateway           │
│     → gateway holds in active snapshot                               │
│                                                                     │
│  4. ROTATE                                                          │
│     Agent calls request_secret (re_request: true)                   │
│     → new value replaces old in managed store                       │
│     → openclaw secrets reload (or restart/config reload) refreshes snapshot │
│                                                                     │
│  5. AUDIT                                                           │
│     openclaw secrets audit → verifies all refs resolve              │
│     No plaintext at rest in the selected managed backend            │
│                                                                     │
│  6. DISPOSE                                                         │
│     Gateway shutdown hook zeros in-memory buffers                   │
│     Managed store persists across restarts                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 3.8 Changes to existing plugin code

**`persistSecret()` — managed store becomes the source of truth for shared secrets:**

```javascript
async function persistSecret(api, context, name, value) {
    // 1. Persist to the managed encrypted store when enabled
    if (isAutoPersistEnabled()) {
        const store = await requireManagedStore();
        await store.write(name, value);
    }

    // 2. Also keep a short-lived runtime copy for plugin-local follow-up work
    setInMemorySecret(name, value);
    return isAutoPersistEnabled() ? "managed-store" : "runtime-only";
}
```

**Config flag:** `BLINDPASS_AUTO_PERSIST` (default: `true`)
- `true`: Managed-secret mode. Every secret received for persistence must be written to the encrypted store. If the store backend is unavailable, the tool fails closed.
- `false`: Explicit ephemeral mode. Secrets live only in runtime memory for plugin-local use and are **not** available to OpenClaw SecretRef consumers.

#### 3.9 Tool changes

**`request_secret`** — extend it to support secure persistence without exposing plaintext to the model:

```javascript
api.registerTool({
    name: "request_secret",
    description: "Request a secret through BlindPass and optionally persist it to the managed encrypted store.",
    parameters: {
        type: "object",
        properties: {
            description: { type: "string" },
            secret_name: { type: "string" },
            persist: { type: "boolean", default: true },
        },
        required: ["description"],
        allOf: [
            {
                if: {
                    properties: { persist: { const: true } },
                },
                then: {
                    required: ["secret_name"],
                },
            },
        ],
    },
});
```

> **Handler-side validation is authoritative.** The `allOf`/`if-then` conditional schema above is best-effort — not all MCP clients evaluate conditional JSON Schema correctly. The tool handler **must** independently validate that `secret_name` is present when `persist=true` and return a clear error if it is missing. Client-side schema validation is a convenience, not a guarantee.

Managed-mode behavior:

- Default managed flow: `secret_name` + `persist=true`
- Interactive-only flow: `persist=false` for one-off use without managed persistence
- BlindPass decrypts the secret, writes it to the encrypted store, and returns **metadata only** (storage status, reload guidance)
- If `persist=true` and the managed store is unavailable, the tool fails closed
- If the deployment sets `BLINDPASS_ALLOW_EXPOSE_PLAINTEXT=true`, the tool returns the decrypted value alongside metadata. Default is `false` — only the operator can enable this, not the model

> **Deployment-level plaintext control:** Whether decrypted secret values are ever returned to the model is controlled exclusively by the `BLINDPASS_ALLOW_EXPOSE_PLAINTEXT` environment variable (default: `false`). This cannot be overridden per-call by the model. Operators who need the "use it now" flow (e.g., agent writes an API key into a config file) enable this at the deployment level and accept that the secret passes through model context.

**`request_secret_exchange`** should support the same `secret_name` / `persist` / metadata-only return path so agent-to-agent delivery can also avoid exposing plaintext to the model.

**`store_secret`** — Explicitly store a secret the runtime already has:

```javascript
api.registerTool({
    name: "store_secret",
    description: "Store a secret in the BlindPass managed store for SecretRef or MCP resolution.",
    parameters: {
        type: "object",
        properties: {
            secret_name: { type: "string" },
            secret_value: { type: "string" },
        },
        required: ["secret_name", "secret_value"],
    },
});
```

> **Deployment-gated tool.** `store_secret` is **only registered** when `BLINDPASS_ENABLE_STORE_TOOL=true` (default: `false`). This is not advisory — the tool literally does not appear in `tools/list` unless the operator enables it. It exists for runtime-owned secrets that already exist inside the agent process boundary, such as generated tokens, issued credentials, or secrets returned by non-BlindPass systems. For human-originated secrets, `request_secret` remains the preferred path because it keeps plaintext out of model context. Returns metadata only.

**`list_secrets`** — List available secret names (never values):

```javascript
api.registerTool({
    name: "list_secrets",
    description: "List secret names in the BlindPass store (values never shown).",
    parameters: { type: "object", properties: {} },
});
```

**`delete_secret`** — Remove a secret from the BlindPass managed store (two-step confirmation):

```javascript
// Step 1: Request deletion — returns a confirmation token
api.registerTool({
    name: "delete_secret",
    description: "Request deletion of a secret from the BlindPass managed store. Returns a confirmation token that must be passed to confirm_delete_secret to complete the deletion.",
    parameters: {
        type: "object",
        properties: {
            secret_name: { type: "string" },
        },
        required: ["secret_name"],
    },
});

// Step 2: Confirm deletion — requires the token from step 1
api.registerTool({
    name: "confirm_delete_secret",
    description: "Confirm and execute a pending secret deletion using the token from delete_secret.",
    parameters: {
        type: "object",
        properties: {
            secret_name: { type: "string" },
            confirmation_token: { type: "string" },
        },
        required: ["secret_name", "confirmation_token"],
    },
});
```

> **Two-step deletion.** `delete_secret` never performs immediate deletion. It returns a short-lived confirmation token (valid for 60 seconds). The model or a human must call `confirm_delete_secret` with the matching token to complete the operation. This prevents a single model hallucination from destroying a production credential. Confirmation tokens are single-use and scoped to the exact `secret_name`.

---

## 4. Capability C: Multi-Agent Compatibility via MCP

### The problem

Today **BlindPass only works with OpenClaw** via its native plugin API. But the same zero-knowledge secret provisioning is valuable for **any** coding agent — Codex, Claude Code, Antigravity/Gemini, and future MCP-compatible agents.

These agents don't support OpenClaw's plugin system, but they all speak **MCP** (Model Context Protocol) over stdio.

### Solution: Standalone MCP server

Build a **BlindPass MCP server** that exposes the same tools over the MCP stdio transport. Same compiled core (`sps-bridge`, `encrypted-store`), different wrapper.

| Component | OpenClaw path | MCP path |
|---|---|---|
| Tool registration | `openclaw.plugin.json` + plugin API | MCP `tools/list` + `tools/call` |
| Transport | OpenClaw runtime | stdio (JSON-RPC) |
| Secret store | Same `encrypted-store.mjs` | Same `encrypted-store.mjs` |
| SPS bridge | Same `sps-bridge.mjs` | Same `sps-bridge.mjs` |

### MCP server entry point

```javascript
// mcp-server.mjs — BlindPass MCP server
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({
    name: "blindpass",
    version: "0.1.0"
}, {
    capabilities: { tools: {} }
});

server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools = [
        { name: "request_secret", description: "...", inputSchema: { ... } },
        { name: "request_secret_exchange", description: "...", inputSchema: { ... } },
        { name: "fulfill_secret_exchange", description: "...", inputSchema: { ... } },
        { name: "list_secrets",   description: "...", inputSchema: { ... } },
        { name: "delete_secret",  description: "...", inputSchema: { ... } },
        { name: "confirm_delete_secret", description: "...", inputSchema: { ... } },
    ];

    // store_secret is deployment-gated — only registered when explicitly enabled
    if (process.env.BLINDPASS_ENABLE_STORE_TOOL === "true") {
        tools.push({ name: "store_secret", description: "...", inputSchema: { ... } });
    }

    return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    // Same tool logic as OpenClaw plugin, shared core
});

const transport = new StdioServerTransport();
await server.connect(transport);
```

### Agent-specific skill files

Each agent needs instructions that reference the MCP tools:

| File | Agent | Format |
|---|---|---|
| `SKILL.md` | OpenClaw / ClawHub | YAML frontmatter + markdown instructions |
| `AGENTS.md` | Codex / Antigravity | Markdown skill instructions |
| `CLAUDE.md` | Claude Code | Markdown (imported via `@` directive) |
| `agents/openai.yaml` | OpenAI Codex | YAML agent definition |
| `agents/claude_desktop_config.json` | Claude Code | MCP config template |
| `agents/codex_mcp_config.json` | Codex/OpenAI | MCP config template |
| `agents/antigravity_settings.json` | Antigravity/Gemini | MCP config template |

All files share the same core instructions but differ in:
- How to reference the tools (native plugin vs MCP)
- Installation instructions specific to each agent's config format

### Agent configuration examples

**Claude Code** (`~/.claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "blindpass": {
      "command": "node",
      "args": ["~/.claude/skills/blindpass/dist/mcp-server.mjs"],
      "env": {
        "SPS_BASE_URL": "https://sps.blindpass.dev",
        "BLINDPASS_API_KEY": "your-api-key"
      }
    }
  }
}
```

**Antigravity/Gemini** (`~/.gemini/settings.json`):
```json
{
  "mcpServers": {
    "blindpass": {
      "command": "node",
      "args": ["~/.gemini/skills/blindpass/dist/mcp-server.mjs"],
      "env": {
        "SPS_BASE_URL": "https://sps.blindpass.dev",
        "BLINDPASS_API_KEY": "your-api-key"
      }
    }
  }
}
```

**npm global** (any agent):
```json
{
  "mcpServers": {
    "blindpass": {
      "command": "npx",
      "args": ["-y", "@blindpass/mcp-server"]
    }
  }
}
```

### Shared core architecture

The key insight is that both the OpenClaw plugin and MCP server are **thin wrappers** around the same core:

```
┌─────────────────────────────────────────────────┐
│              Shared Core Modules                │
│                                                 │
│  sps-bridge.mjs      HPKE, JWT, SPS protocol    │
│  encrypted-store.mjs SOPS read/write/bootstrap  │
│  agent-transport.mjs Agent-to-agent exchange     │
│  blindpass-core.mjs  Tool logic (shared)         │
└───────────┬─────────────────┬───────────────────┘
            │                 │
   ┌────────▼──────┐  ┌───────▼────────┐
   │ index.mjs     │  │ mcp-server.mjs │
   │ (OpenClaw     │  │ (MCP stdio     │
   │  plugin API)  │  │  transport)    │
   └───────────────┘  └────────────────┘
```

The refactor extracts tool logic into `blindpass-core.mjs`, and both entry points call into it.

---

## 5. Distribution Strategy

### Monorepo development → distribution repo

**Decision:** Build in the `blindpass` monorepo, publish to a separate **distribution repo** (`atas-tech/blindpass-skill`).

This is the proven `dependency-guard` model:

| Repo | Purpose | Contents |
|---|---|---|
| `atas-tech/blindpass` | Development monorepo | Source code, tests, SPS server, browser UI |
| `atas-tech/blindpass-skill` | Distribution repo | Compiled bundles, skill files, installer |

### Distribution repo structure

```
atas-tech/blindpass-skill/
├── SKILL.md                        ← OpenClaw / ClawHub
├── AGENTS.md                       ← Codex / Antigravity
├── CLAUDE.md                       ← Claude Code
├── agents/
│   └── openai.yaml                 ← OpenAI Codex agent definition
├── openclaw.plugin.json            ← OpenClaw manifest
├── dist/
│   ├── blindpass.mjs               ← compiled OpenClaw plugin
│   ├── mcp-server.mjs              ← compiled MCP server
│   └── blindpass-resolver.mjs      ← compiled exec provider
├── scripts/
│   └── install_skill.sh            ← multi-agent installer
├── package.json                    ← npm publish config
├── LICENSE
└── README.md
```

### Build & publish pipeline

CI in the monorepo builds and pushes to the dist repo:

```
atas-tech/blindpass (monorepo)
│
│  npm run build:skill
│  ├── esbuild → dist/blindpass.mjs
│  ├── esbuild → dist/mcp-server.mjs
│  ├── esbuild → dist/blindpass-resolver.mjs
│  └── copy SKILL.md, AGENTS.md, CLAUDE.md, agents/, scripts/
│
│  scripts/publish_dist.sh
│  ├── git push → atas-tech/blindpass-skill
│  ├── clawhub publish
│  └── npm publish @blindpass/mcp-server
│
▼

atas-tech/blindpass-skill (dist repo)
```

### All installation paths

```bash
# ClawHub (OpenClaw users)
openclaw skills install blindpass

# npm (any agent, global)
npm install -g @blindpass/mcp-server

# Git clone + install (any agent, workspace)
git clone https://github.com/atas-tech/blindpass-skill.git
./blindpass-skill/scripts/install_skill.sh --mode project --agent all

# Git clone + install (Claude Code, global)
./scripts/install_skill.sh --mode global --agent claude

# Git clone + install (Antigravity, global)
./scripts/install_skill.sh --mode global --agent antigravity

# Git clone + install (Codex, global)
./scripts/install_skill.sh --mode global --agent codex

# npx (zero-install MCP, any agent)
npx @blindpass/mcp-server
```

---

## 6. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                     AGENT INTEGRATION LAYER                          │
│                                                                      │
│  ┌────────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  OpenClaw       │  │  Claude Code │  │  Codex / Antigravity    │  │
│  │  (native plugin)│  │  (MCP stdio) │  │  (MCP stdio)            │  │
│  └───────┬────────┘  └──────┬───────┘  └────────────┬─────────── ┘  │
│          │                  │                       │                │
│          ▼                  ▼                       ▼                │
│  ┌──────────────┐  ┌────────────────┐                                │
│  │ blindpass.mjs │  │ mcp-server.mjs │   (thin wrappers)             │
│  │ (plugin API)  │  │ (MCP transport)│                                │
│  └──────┬───────┘  └───────┬────────┘                                │
│         └─────────┬────────┘                                         │
│                   ▼                                                  │
│  ┌─────────────────────────────────┐                                 │
│  │       blindpass-core.mjs        │  (shared tool logic)            │
│  │  request_secret | request_secret_exchange                         │
│  │  fulfill_secret_exchange | list_secrets                           │
│  │  delete_secret | confirm_delete_secret                            │
│  │  store_secret (deployment-gated)                                  │
│  └────────┬──────────────┬─────────┘                                 │
│           │              │                                           │
│  ┌────────▼─────┐  ┌─────▼───────────┐                               │
│  │ sps-bridge   │  │ encrypted-store │                               │
│  │ (HPKE, JWT)  │  │ (pluggable r/w) │                               │
│  └────────┬─────┘  └─────┬───────────┘                               │
│           │              │                                           │
│           ▼              ▼                                           │
│  ┌──────────────┐  ┌─────────────────────┐                           │
│  │  SPS Server   │  │  Managed Store      │                          │
│  │  (hosted or   │  │  secrets.enc.json   │ (per-gateway/per-agent)  │
│  │   self-host)  │  │  (default: SOPS)    │                          │
│  └──────────────┘  └─────────────────────┘                           │
│                              ▲                                       │
│                              │ reads (activation / reload)           │
│                    ┌─────────┴───────────┐                           │
│                    │ blindpass-resolver   │  (exec provider CLI)     │
│                    │ stdin → decrypt via  │                          │
│                    │ backend → stdout JSON│                          │
│                    └─────────────────────┘                           │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 7. Implementation Phases

### Phase 1: Core refactor & build system (~2 days)

| Task | Effort |
|---|---|
| Extract shared tool logic into `blindpass-core.mjs` | M |
| Set up esbuild bundle pipeline (3 entry points) | M |
| Create `scripts/build_bundle.sh` | M |
| Update `SKILL.md` frontmatter with ClawHub metadata | S |
| Prepare npm packaging for cross-agent distribution (`@blindpass/mcp-server`) | S |
| Security validation in publish pipeline | S |

### Phase 2: Managed encrypted store (~3 days)

| Task | Effort |
|---|---|
| Implement `encrypted-store.mjs` module with pluggable backend interface (default: SOPS read/write) | M |
| Auto-bootstrap: create age-compatible identity + `.sops.yaml` for the default SOPS backend | M |
| Managed mode contract: fail closed if persistence is enabled but store backend is unavailable | S |
| Write serialization: lockfile with PID ownership + atomic rename + async write queue | M |
| Modify `persistSecret()` with `BLINDPASS_AUTO_PERSIST` flag | S |
| Extend `request_secret` / `request_secret_exchange` with metadata-only managed-store mode | M |
| Add `store_secret` (deployment-gated), `list_secrets`, `delete_secret` + `confirm_delete_secret` (two-step) | M |
| Unit tests for encrypted-store module and write serialization | M |
| Metadata-only audit logging (provision/rotation events) with size-based rotation | S |

### Phase 3: BlindPass exec resolver (~2 days)

| Task | Effort |
|---|---|
| Create `blindpass-resolver` CLI entry point | M |
| Implement exec protocol v1 (stdin/stdout JSON) | S |
| Handle batch resolution (multiple IDs per call) | S |
| Error handling + timeout support (default: 10s self-imposed timeout) | S |
| Add `bin` field to `package.json` for npm global install | S |
| Integration test with `openclaw secrets audit --allow-exec` | M |

### Phase 4: MCP server & multi-agent support (~2 days)

| Task | Effort |
|---|---|
| Create `mcp-server.mjs` wrapping `blindpass-core.mjs` | M |
| Wire MCP `tools/list` + `tools/call` handlers | S |
| Create `AGENTS.md` (Codex / Antigravity instructions) | S |
| Create `CLAUDE.md` (Claude Code instructions) | S |
| Create `agents/openai.yaml` (OpenAI agent definition) | S |
| Test MCP server with Claude Code and Antigravity | M |

### Phase 5: Distribution & end-to-end integration (~2 days)

| Task | Effort |
|---|---|
| Create `scripts/install_skill.sh` (multi-agent installer) | M |
| Create `scripts/publish_clawhub.sh` with version sync | M |
| Create `scripts/publish_dist.sh` (push to dist repo) | M |
| Set up `atas-tech/blindpass-skill` dist repo | S |
| Full lifecycle test: provision → SOPS persist → restart → resolve | L |
| `openclaw secrets reload` after rotation test | M |
| Onboarding guide (per-agent setup instructions) | S |
| Optional: TTL / forced re-provision config | S |

**Total estimated effort:** ~11 days

### Testing plan linkage

The required E2E and integration scenarios for these phases are tracked in [../testing/OpenClaw Capability Extension.md](../testing/OpenClaw%20Capability%20Extension.md).

---

## 8. Resolved Decisions

| # | Question | Decision | Rationale |
|---|---|---|---|
| Q1 | Plugin vs. Skill? | **Full compiled plugin** | Published as compiled bundle — no source-code risk, no split install confusion |
| Q2 | SPS bundling? | **SPS is separate** | SPS runs as hosted service (`sps.blindpass.dev`) or self-hosted. Plugin only needs the URL |
| Q3 | npm too? | **Yes, but audience-specific** | ClawHub is primary for OpenClaw. npm `@blindpass/mcp-server` is primary for MCP agents |
| Q4 | Encryption? | **SOPS** | Built-in OpenClaw support, multiple KMS backends, widely adopted |
| Q5 | Store location? | **Follow gateway config, configurable** | Default: `<gateway-config-dir>/blindpass/`. Override via env var or `--store` flag |
| Q6 | Pre-provision UX? | **Minimal for SPS bootstrap** | Users need `BLINDPASS_API_KEY` for SPS access. Managed SecretRef persistence additionally needs the encrypted-store backend |
| Q7 | Auto-persist on rotation? | **Yes by default, fail closed if unavailable** | `BLINDPASS_AUTO_PERSIST=true` means managed-store mode. `false` is explicit runtime-only mode |
| Q8 | Multi-gateway? | **Per-gateway store** | Each gateway has its own config dir → its own SOPS store. No shared-state conflicts |
| Q9 | Multi-agent? | **MCP server** | Standalone MCP server wrapping same core. Works with Codex, Claude, Antigravity |
| Q10 | Repo split? | **Monorepo dev → dist repo publish** | Build in `atas-tech/blindpass`, publish compiled to `atas-tech/blindpass-skill` |
| Q11 | Git install? | **Yes, via dist repo** | `git clone atas-tech/blindpass-skill` + `install_skill.sh` |

---

## 9. Additional Considerations (All Resolved)

### 9.1 Compiled bundle dependencies ✅

**Decision:** Inline monorepo dependencies via esbuild.

The current `sps-bridge.mjs` uses dynamic imports from sibling packages:

```javascript
const identity = await import(path.join(base, "packages/gateway/dist/identity.js"));
const keyManager = await import(path.join(base, "packages/agent-skill/dist/key-manager.js"));
```

For the compiled bundle:
- Extract the specific exports used (`loadOrCreateGatewayIdentity`, `issueJwt`, `generateKeyPair`, `decrypt`, etc.)
- Bundle them into a single-file ESM output via esbuild
- Ensure the HPKE/crypto code works with `node:crypto` (no browser polyfills)
- **Test risk:** `@blindpass/agent-skill` key-manager uses `crypto.subtle` for HPKE — should bundle cleanly but needs validation

### 9.2 Managed store contract ✅

**Decision:** Make persistence behavior explicit and predictable. Managed mode persists through the selected backend or fails closed. Runtime-only mode is opt-in.

Storage resolution order:

```
1. If BLINDPASS_AUTO_PERSIST=true
   ├── Resolve store path (operator override or OpenClaw/platform convention)
   ├── Select managed-store backend
   │   ├── Explicit operator-selected backend if configured
   │   └── Else default SOPS backend if available
   ├── Bootstrap the selected backend if needed
   └── If no usable backend is available → fail the managed-secret request with an actionable error

2. If BLINDPASS_AUTO_PERSIST=false
   └── Use runtime-only memory mode
      (ephemeral, plugin-local, not shared with SecretRef consumers)
```

Managed store detection logic:
- Check for `BLINDPASS_STORE_PATH` env var → explicit store path
- Else check for `<gateway-config-dir>/blindpass/secrets.enc.json` when running in OpenClaw
- Else check the platform convention path for MCP mode
- Check for an explicit operator-selected backend
- Else check for the default SOPS backend and `sops` CLI on `PATH`
- If managed mode requirements are not met → fail closed

> **Important Limitation:** The `blindpass-resolver` CLI reads exclusively from the selected managed-store backend. If the plugin falls back to in-memory storage (or `BLINDPASS_AUTO_PERSIST=false`), the `exec` provider will NOT be able to resolve those secrets for other OpenClaw gateway components. In-memory mode is strictly for immediate plugin use.

When auto-bootstrapping the default SOPS backend:
1. First `request_secret` call triggers store initialization
2. Plugin generates age identity → `<store>/.age-key.txt`
3. Plugin creates `.sops.yaml` → `creation_rules: [{ age: "<public-key>" }]`
4. User should be warned: **back up `.age-key.txt`** — loss means all stored secrets become unrecoverable
5. Bootstrap prints the public key, store path, and recovery guidance to stderr
6. A `bootstrap_backup_pending` flag is recorded until explicitly acknowledged

For advanced users:
- Reconfigure `.sops.yaml` to point to AWS KMS, GCP KMS, etc.
- Use SOPS's built-in key rotation (`sops updatekeys`)
- Or configure another supported managed-store adapter instead of the default SOPS backend

### 9.3 Secret scoping ✅

**Decision:** Flat namespace per-gateway. Use descriptive names for multi-agent differentiation.

Secrets are scoped **per-gateway** (each gateway has its own store). Within a gateway, secrets are **flat-namespaced** — no per-agent scoping.

If two agents on the same gateway need different Stripe keys, use descriptive names:
- `stripe.api_key.payment-bot`
- `stripe.api_key.billing-bot`

Keeps the store simple. Per-agent namespacing can be added later if needed.

### 9.4 Audit trail ✅

**Decision:** Add metadata-only logging (never values) when secrets are provisioned or rotated.

```
<store>/audit.log
```

```json
{"ts": "2026-04-02T09:00:00Z", "event": "provision", "secret_name": "openai.api_key", "source": "request_secret"}
{"ts": "2026-04-03T15:30:00Z", "event": "rotate", "secret_name": "openai.api_key", "source": "request_secret", "re_request": true}
```

Useful for compliance without sacrificing zero-knowledge.

**Log rotation:** Default policy is size-based: rotate at 10 MB, keep 5 rotated files (`audit.log`, `audit.log.1` … `audit.log.5`). Operators who prefer centralized logging should ship audit events to their own log aggregator and can disable local rotation via `BLINDPASS_AUDIT_LOG=off`.

### 9.5 Hosted SPS ✅

**Decision:** Default to BlindPass hosted SPS at `https://sps.blindpass.dev`.

| Config | Default |
|---|---|
| `SPS_BASE_URL` | `https://sps.blindpass.dev` |
| Free tier | Rate-limited, suitable for individual use |
| Self-host | Users set `SPS_BASE_URL` to their own instance |

### 9.6 TTL / forced re-provision ✅

**Decision:** Optional, user-configurable. Phase 5 nice-to-have.

Add optional TTL metadata to stored secrets:

```json
{
  "openai.api_key": {
    "value": "sk-...",
    "provisioned_at": "2026-04-02T09:00:00Z",
    "ttl_days": 90
  }
}
```

When `blindpass-resolver` encounters an expired secret, it returns an error — forcing OpenClaw to fail-fast and the agent to re-provision.

User configures TTL via:
- Per-secret: `request_secret` with `ttl_days` param (optional)
- Global default: `BLINDPASS_DEFAULT_TTL_DAYS` env var (optional, no default = no expiry)

### 9.7 Resolver timeout ✅

**Decision:** `blindpass-resolver` self-imposes a **10-second timeout** on the entire decrypt→resolve→respond cycle. This is generous for local SOPS file operations but short enough to fail cleanly if the store is corrupted or unexpectedly large. Configurable via `BLINDPASS_RESOLVER_TIMEOUT_MS` env var.

OpenClaw's exec provider may impose its own timeout independently. The resolver's self-imposed timeout ensures deterministic behavior regardless of the calling environment.

### 9.8 Windows support scope ✅

**Decision:** Windows support in v1 is scoped to **convention path resolution only** — `%LOCALAPPDATA%\blindpass\` resolves correctly, and the resolver can read a SOPS store at that path. Full Windows lifecycle E2E (bootstrap, multi-agent install, audit logging) is **not** in scope for v1. The test plan covers path resolution; full Windows E2E would be a separate effort if demand warrants it.

### 9.9 Upgrade from in-memory-only versions ✅

**Decision:** No migration is needed. Previous BlindPass versions used in-memory-only storage, which is volatile by design — secrets do not survive restart. There is no persisted state to migrate. The upgrade path is simply: install the new version, configure managed persistence, and re-provision secrets through the normal `request_secret` flow. This should be documented in the onboarding guide so operators do not expect old runtime secrets to carry over.

---

## 10. Summary of all resolved decisions

| # | Topic | Decision |
|---|---|---|
| Q1 | Plugin vs. Skill? | Full compiled plugin — no source-code risk |
| Q2 | SPS bundling? | SPS is separate (hosted `sps.blindpass.dev` or self-hosted) |
| Q3 | npm too? | Yes, but split by audience: ClawHub for OpenClaw, npm for MCP agents |
| Q4 | Encryption? | SOPS (built-in OpenClaw support) |
| Q5 | Store location? | Follow gateway config dir, configurable via env |
| Q6 | Pre-provision UX? | Minimal for SPS bootstrap; managed persistence also needs the encrypted-store backend |
| Q7 | Auto-persist? | Default on for managed mode, fail closed if unavailable; `false` enables explicit runtime-only mode |
| Q8 | Multi-gateway? | Per-gateway store, no shared state |
| Q9 | Multi-agent? | MCP server wrapping shared core |
| Q10 | Repo split? | Monorepo dev → dist repo publish |
| Q11 | Git install? | Yes, via dist repo + install_skill.sh |
| 9.1 | Bundle deps? | Inline via esbuild into single-file ESM |
| 9.2 | SOPS vs. in-memory? | **Explicit contract** — managed mode persists or fails closed; runtime-only mode is explicit. Write serialization via lockfile + atomic rename |
| 9.3 | Secret scoping? | Flat namespace per-gateway, descriptive names |
| 9.4 | Audit trail? | Yes — metadata-only, never values. Size-based rotation (10 MB × 5 files) |
| 9.5 | Hosted SPS? | Yes — `sps.blindpass.dev` as default |
| 9.6 | TTL? | Optional, user-configurable, Phase 5 |
| 9.7 | Resolver timeout? | 10s self-imposed default, configurable |
| 9.8 | Windows scope? | Path conventions only in v1; full lifecycle deferred |
| 9.9 | Upgrade path? | No migration needed — old versions were in-memory only |

---

## References

- [OpenClaw Secrets Management](https://docs.openclaw.ai/gateway/secrets) — SecretRef contract, exec protocol, SOPS examples
- [OpenClaw SecretRef Credential Surface](https://docs.openclaw.ai/reference/secretref-credential-surface)
- [OpenClaw Gateway Runbook](https://docs.openclaw.ai/gateway/index) — runtime snapshot model, restart/reload behavior, `openclaw secrets reload`
- [atas-tech/dependency-guard](https://github.com/atas-tech/dependency-guard) — ClawHub publishing reference
- [SOPS](https://github.com/getsops/sops) — Encrypted secrets at rest (Mozilla)
- [Age](https://github.com/FiloSottile/age) — Modern encryption CLI (default SOPS backend)
