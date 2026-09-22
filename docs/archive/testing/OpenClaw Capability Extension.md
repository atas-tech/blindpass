# OpenClaw Capability Extension Test Plan

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This document defines the End-to-End (E2E), integration, packaging, and operational verification scenarios for the OpenClaw capability-extension roadmap in `docs/plugins/openclaw-capability-extension.md`.

## Scope

This plan covers:

- OpenClaw packaging and ClawHub distribution
- Managed secret persistence through the BlindPass encrypted store
- `blindpass-resolver` exec-provider integration with OpenClaw SecretRefs
- MCP server support for Codex, Claude Code, Antigravity, and other MCP-compatible agents
- Dist-repo and npm release integrity

## Implementation Snapshot (April 18, 2026)

Current implemented baseline in this repository:

- Phase 1 scaffolding is in place:
  - shared plugin core (`blindpass-core.mjs`)
  - bundled `build:skill` pipeline producing `blindpass.mjs`, `mcp-server.mjs`, and `blindpass-resolver.mjs`
  - packaging scripts: `build_bundle.sh`, `install_skill.sh`, `publish_clawhub.sh`, and `publish_dist.sh`
  - ClawHub frontmatter metadata + version synchronization wiring
- Phase 2 managed-store slice is in place:
  - `encrypted-store.mjs` introduced with managed-store config resolution
  - `BLINDPASS_AUTO_PERSIST` fail-closed behavior wired into plugin persistence
  - SOPS auto-bootstrap creates `.age-key.txt` + `.sops.yaml`, writes initial encrypted store metadata, and emits recovery guidance
  - startup reminder + `BLINDPASS_BACKUP_ACKNOWLEDGED=true` flow are implemented for `bootstrap_backup_pending`
  - write serialization uses lockfile + PID ownership checks + in-process queue + atomic rename
  - managed-store maintenance APIs now include `store_secret` (deployment-gated), `list_secrets`, and two-step `delete_secret`/`confirm_delete_secret`
  - `request_secret`/`request_secret_exchange` support `persist=false` for interactive runtime-only mode
  - deployment-level plaintext control is enforced via `BLINDPASS_ALLOW_EXPOSE_PLAINTEXT` (model parameters cannot override)
  - OpenClaw vs MCP default store-path selection is covered (`gateway-config-dir` convention for OpenClaw, user convention for MCP)
  - unit tests cover bootstrap, reminder/ack, concurrent writes, lock timeout, stale-lock break, and inconclusive PID handling
  - unit tests cover store-tool gating, metadata-only store/list responses, and delete confirmation-token expiry/mismatch/single-use protections
  - unit tests cover invalid-path fail-closed behavior, rotation replacement, atomic-rename safety under failed writes, and metadata-only audit logging
- Phase 3 initial resolver slice is in place:
  - `blindpass-resolver.mjs` now implements exec-provider protocol v1 over stdin/stdout
  - batch ID resolution returns `values` + per-ID `errors` without leaking plaintext through logs
  - resolver timeout (`BLINDPASS_RESOLVER_TIMEOUT_MS`, default 10s) and malformed-input protocol-safe error responses are covered by unit tests
- Phase 4 initial MCP slice is in place:
  - `mcp-server.mjs` now implements MCP JSON-RPC request handling for `initialize`, `tools/list`, and `tools/call`
  - MCP tools are registered from the shared `blindpass-core.mjs` implementation to preserve OpenClaw/MCP parity
  - `store_secret` remains deployment-gated (`BLINDPASS_ENABLE_STORE_TOOL=true`) in MCP the same way as OpenClaw
  - managed-mode MCP responses are metadata-only by default and handler-side `persist=true` validation is enforced in core handlers
  - profile config fixtures now exist for Claude/Codex/Antigravity and process-level launch smoke tests validate MCP stdio `initialize` handshakes
- Phase 5 installer integrity slice is in place:
  - `scripts/tests/install_skill.test.mjs` validates global installer behavior for `codex`, `claude`, `antigravity`, and `all`
  - the installer tests verify backup-on-replace behavior and confirmation prompts when `--yes` is not provided
- Phase 1 release metadata hardening slice is in place:
  - `scripts/tests/release_metadata.test.mjs` validates SKILL/manifest version sync and staged npm metadata (`name`, `bin`, and required `files`)
  - `scripts/publish_dist.sh` now fails fast if `SKILL.md` and `openclaw.plugin.json` versions drift
  - ClawHub frontmatter metadata continues to assert no required backend binaries (`metadata.openclaw.requires.bins: []`)
- Phase 1 audience-packaging slice is in place:
  - `scripts/tests/audience_packaging.test.mjs` exercises ClawHub dry-run validation, npm packaging/runtime handshake, and dist-repo installer fallback
  - `npm pack --dry-run` is validated from staged release output to ensure MCP server and resolver binaries are present
- Phase 3 activation-behavior slice is in place:
  - `scripts/tests/openclaw_activation.test.mjs` validates resolver-backed gateway snapshot semantics for restart/reload flows
  - provisioning and rotation are verified to remain snapshot-bound until an explicit restart or `openclaw secrets reload`
- Remaining Phase 2/3/4/5 items below are still authoritative and mostly pending.

## Milestone 1: Build, Bundle, and Package Boundaries

- [x] **Bundle outputs are self-contained**
  - [x] `npm run build:skill` emits `blindpass.mjs`, `mcp-server.mjs`, and `blindpass-resolver.mjs`
  - [x] Published bundle output contains no monorepo-relative import paths such as `packages/gateway/dist` or `packages/agent-skill/dist`
  - [x] Bundle output contains no `.env` files, private keys, workspace paths, or local SPS URLs

- [x] **Release metadata stays synchronized**
  - [x] `SKILL.md`, `openclaw.plugin.json`, and dist `package.json` report the same release version
  - [x] ClawHub-facing metadata includes the expected OpenClaw installable skill metadata without incorrectly forcing optional backends
  - [x] npm package metadata correctly exposes the MCP server and resolver entry points

- [x] **Audience-specific packaging works**
  - [x] OpenClaw users can install via ClawHub without needing the MCP-only packaging path
  - [x] MCP users can install via npm or run via `npx` without needing OpenClaw-specific config files
  - [x] Git dist-repo installer remains a functional fallback for manual or offline installs

## Milestone 2: Managed Secret Storage

- [x] **SOPS auto-bootstrap on first use**
  - [x] First `request_secret` call with no existing store triggers age key generation, `.sops.yaml` creation, and empty store initialization
  - [x] Bootstrap prints the store path, age public key, and recovery guidance to stderr
  - [x] A `bootstrap_backup_pending` flag is recorded in store metadata
  - [x] Plugin startup with `bootstrap_backup_pending=true` emits a reminder warning
  - [x] Running `blindpass acknowledge-backup` (or setting `BLINDPASS_BACKUP_ACKNOWLEDGED=true`) clears the pending flag and suppresses the warning
  - [x] Subsequent `request_secret` calls reuse the existing key and config without re-bootstrapping

- [x] **Managed mode persists without exposing plaintext**
  - [x] `request_secret` with `secret_name` and default managed settings stores the secret in the encrypted store
  - [x] Tool output returns metadata only and never includes the secret value
  - [x] Audit entries record metadata only and never include plaintext, ciphertext, tokens, or key material

- [x] **Managed mode fails closed when persistence is unavailable**
  - [x] If `BLINDPASS_AUTO_PERSIST=true` and no usable managed-store backend is available, the request fails with an actionable error
  - [x] If the configured store path is invalid or unwritable, the request fails without downgrading silently to runtime-only mode
  - [x] The plugin does not claim the secret is stored when persistence failed

- [x] **Explicit runtime-only mode is isolated**
  - [x] If `BLINDPASS_AUTO_PERSIST=false`, the secret is kept only in runtime memory
  - [x] Runtime-only secrets are not listed by the managed-store listing tool
  - [x] Runtime-only secrets are not resolvable by `blindpass-resolver`
  - [x] `request_secret` with `persist=false` supports the interactive-only path without requiring managed persistence

- [x] **Managed-store maintenance operations**
  - [x] `store_secret` is not registered when `BLINDPASS_ENABLE_STORE_TOOL=false` (default) — tool does not appear in `tools/list`
  - [x] `store_secret` is registered and functional when `BLINDPASS_ENABLE_STORE_TOOL=true`
  - [x] `store_secret` writes to the managed store and returns metadata only (never echoes the value)
  - [x] `store_secret` fails closed if managed store is unavailable
  - [x] `list_secrets` returns names only
  - [x] `delete_secret` returns a pending confirmation token without performing deletion
  - [x] `confirm_delete_secret` with a valid token completes the deletion and records a metadata-only audit event
  - [x] `confirm_delete_secret` with an expired token (>60s) fails with a clear error
  - [x] `confirm_delete_secret` with a mismatched `secret_name` fails without deleting anything
  - [x] Confirmation tokens are single-use — reusing a consumed token fails
  - [x] Rotation via `request_secret` with `re_request=true` replaces the stored value atomically

- [x] **Write serialization under concurrency**
  - [x] Two simultaneous `request_secret` calls complete without data loss — both secrets are present in the store
  - [x] A write that cannot acquire the lockfile within 5 seconds fails with an actionable error
  - [x] A stale lockfile whose owning PID is no longer running is automatically broken and does not block subsequent writes
  - [x] A lockfile whose owning PID is still running is treated as live — the write fails rather than breaking the lock
  - [x] If PID ownership check is inconclusive (e.g., permission denied), the lock is treated as live
  - [x] The store file is updated via atomic rename — a crash mid-write does not corrupt the store

- [x] **Managed-store backend selection**
  - [x] OpenClaw plugin mode prefers the gateway config directory convention by default
  - [x] MCP mode prefers the platform-aware user convention path by default
  - [x] An explicit operator-selected backend overrides the default backend choice
  - [x] The default SOPS backend is selected automatically when available, OpenClaw is configured for managed persistence, and no override is present

- [x] **Deployment-level plaintext control**
  - [x] With `BLINDPASS_ALLOW_EXPOSE_PLAINTEXT=false` (default), `request_secret` returns metadata only
  - [x] With `BLINDPASS_ALLOW_EXPOSE_PLAINTEXT=true`, `request_secret` returns the decrypted value alongside metadata
  - [x] The model cannot override this setting via tool parameters
  - [x] `store_secret` never echoes the value back regardless of the plaintext control setting

- [x] **Platform-aware store path resolution**
  - [x] On Linux/macOS, convention path resolves to `$HOME/.blindpass/`
  - [x] On Windows, convention path resolves to `%LOCALAPPDATA%\blindpass\`
  - [x] `BLINDPASS_STORE_PATH` overrides platform detection on all platforms
  - [x] Resolver can derive sibling bootstrap files automatically from the selected store path for the default SOPS backend
  - [x] Windows support in v1 is scoped to path resolution correctness only — full Windows lifecycle E2E is out of scope

## Milestone 3: Resolver and OpenClaw SecretRef Integration

- [x] **Resolver protocol compliance**
  - [x] `blindpass-resolver` accepts exec-provider protocol v1 requests on stdin
  - [x] Successful batch lookup returns a `values` object keyed by requested IDs
  - [x] Missing, expired, or deleted secrets return `errors` entries without leaking store internals

- [x] **OpenClaw activation behavior is correct**
  - [x] Provision secret → restart gateway → SecretRef resolves successfully
  - [x] Provision secret → run `openclaw secrets reload` → SecretRef resolves successfully
  - [x] Provision secret without reload or restart does not update already-materialized SecretRef consumers
  - [x] Update existing secret value on disk and verify the old snapshot remains active until reload/restart

- [x] **TTL and error handling**
  - [x] Expired secrets fail closed at resolver time with a deterministic error
  - [x] Corrupt store contents fail closed without emitting plaintext or key material
  - [x] Resolver self-imposes a 10-second timeout — exceeding it returns a protocol-safe error
  - [x] Malformed stdin input returns a protocol-safe error without hanging

## Milestone 4: MCP Multi-Agent Support

- [x] **Tool parity across OpenClaw and MCP**
  - [x] MCP server exposes `request_secret`
  - [x] MCP server exposes `request_secret_exchange`
  - [x] MCP server exposes `fulfill_secret_exchange`
  - [x] MCP server exposes `store_secret` only when `BLINDPASS_ENABLE_STORE_TOOL=true`
  - [x] MCP server exposes `list_secrets`
  - [x] MCP server exposes `delete_secret`
  - [x] MCP server exposes `confirm_delete_secret`

- [x] **Managed mode remains metadata-only over MCP**
  - [x] `request_secret` in managed mode returns storage metadata and reload guidance, not plaintext
  - [x] `request_secret_exchange` in managed mode behaves the same way
  - [x] Logs and MCP responses never echo secret values
  - [x] `secret_name` is required whenever persistence is requested

- [x] **Agent compatibility smoke coverage**
  - [x] Claude Code config launches the MCP server successfully
  - [x] Codex/OpenAI agent config launches the MCP server successfully
  - [x] Antigravity/Gemini config launches the MCP server successfully
  - [x] Shared skill instructions remain consistent with the actual tool contracts

- [x] **Handler-side validation is authoritative**
  - [x] `request_secret` with `persist=true` and no `secret_name` fails with a clear error from the handler, regardless of client-side schema enforcement
  - [x] `request_secret_exchange` applies the same handler-side validation for `secret_name` when `persist=true`

## Milestone 5: Distribution and Operational Readiness

- [ ] **ClawHub and npm publishing**
  - [ ] ClawHub publish path succeeds from the staged dist output
  - [ ] npm publish path succeeds for `@blindpass/mcp-server`
  - [ ] Published tarballs contain only intended release artifacts

- [x] **Installer and dist-repo integrity**
  - [x] `scripts/install_skill.sh --mode global --agent codex` installs the expected files
  - [x] `scripts/install_skill.sh --mode global --agent claude` installs the expected files
  - [x] `scripts/install_skill.sh --mode global --agent antigravity` installs the expected files
  - [x] `scripts/install_skill.sh --mode global --agent all` does not overwrite unrelated user config without confirmation or backup

- [ ] **End-to-end managed secret lifecycle**
  - [ ] Request from human via SPS → persist to store → reload OpenClaw secrets → SecretRef consumer resolves
  - [ ] Request from another agent via exchange → persist to store → reload → SecretRef consumer resolves
  - [ ] Delete secret → reload → SecretRef consumer fails closed
  - [ ] Rotate secret → reload → SecretRef consumer resolves the new value only after reload

## Exit Criteria

- Managed-secret mode never returns plaintext to the model by default (`BLINDPASS_ALLOW_EXPOSE_PLAINTEXT=false`)
- Plaintext exposure is exclusively operator-controlled via deployment environment variable
- OpenClaw SecretRef behavior is documented and validated as reload-based, not live-updating
- Cross-agent MCP support ships from the same shared core without regressing the OpenClaw plugin path
- Platform-aware store path resolution works on Linux, macOS, and Windows
- Optional managed-store backends do not become accidental hard install dependencies
- Release artifacts are bounded, auditable, and free from local development leakage
- `store_secret` is gated behind `BLINDPASS_ENABLE_STORE_TOOL` and never exposed by default
- `delete_secret` requires two-step confirmation — no single model call can delete a production credential
- Concurrent writes to the managed store are serialized and cannot corrupt or lose data
- Windows v1 scope is limited to path resolution; full lifecycle is explicitly deferred
