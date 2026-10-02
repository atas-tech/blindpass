# 0006: P05 private and workload browser runtime review

**Date:** 2026-09-30. **Status:** Accepted by the user for implementation and
testing. The exact private and stock browser profiles below are approved; all
sandbox, isolation, notice and actual VM/client gates remain required. Existing
fixture tests use locked Playwright 1.58.2.

## Approved use

- Exact `playwright@1.58.2` for the separate trusted Node login-helper runtime.
  It launches a sandboxed Chromium with capture disabled before navigation,
  fixed approved origins and selectors, safe errors, bounded private IPC and
  strict session-cookie selection. Its private profile/source password never
  enters the workload browser. Helper tests may inject a launch function; the
  deployed process must use the pinned runtime selected by its supervisor.
- Exact `@playwright/mcp@0.0.83` as the actual stock browser tool for the Claude
  Code/Codex context-channel feasibility and task gate. Its published package
  pins Playwright/core `1.64.0-alpha-1790635538000`; that alpha runtime is an
  explicitly approved test profile, not a stable runtime/support claim. Keep it
  isolated from the private helper's 1.58.2 dependency. Prove actual connection,
  reconnection, cookie import and sandbox behavior before accepting the channel.

The existing `@playwright/test` development dependency runs application tests;
it is not the proposed production helper installation. The requirement for an
actual stock browser task excludes replacing the browser tool with a mock.
No source/password/session values may appear on argv, MCP results or managed
logs. The handed-off website session is intentionally extractable by its browser
owner; no source-password or private-profile access is granted.

## Full Socket reviews

| Exact package | Graph | Scores/alerts | Guard decision |
|---|---|---|---|
| `playwright@1.58.2` | 2 direct/transitive dependencies, core 1.58.2 and optional macOS fsevents 2.3.2 | Deep overall/supply chain 65, maintenance 81, quality 77, vulnerability/license 100; medium security/network/shell/eval alerts; environment/filesystem/network/shell/eval/unsafe capabilities | `block_pending_human_review`; [report](../../testing/evidence/p05-playwright-1.58.2-socket.md) |
| `@playwright/mcp@0.0.83` | 2 direct/transitive dependencies, both exact 1.64.0 alpha above | Deep overall/quality 78, maintenance 98, supply chain 99, vulnerability 100, license 80; medium security and low debug/environment/anomaly/URL alerts | `block_pending_human_review`; [report](../../testing/evidence/p05-playwright-mcp-0.0.83-socket.md) |

Launching/controlling a browser explains process, filesystem, network and script
capabilities, but the skill's medium-alert/score rules still require human review.
Scores are signals, not proof of safety. Current npm metadata reports no
preinstall/install/postinstall hooks for these packages; downloading browser
binaries is a separate explicit operation with an exact profile, not an
unrestricted postinstall. Preserve upstream Apache-2.0 and dependency notices.

Pin and review the actual resolved lockfile before installing. Unexpected versions
or additional packages need another review. This proposal does not authorize
changing the Node support range, disabling browser sandbox/TLS checks, exposing
raw control endpoints, or accepting P05 without its full VM/client matrix.

## Review record

| Date | Reviewer | Result |
|---|---|---|
| 2026-09-30 | Automated preparation | Full reports collected; human review pending |

| 2026-09-30 | User | Approved these exact pinned browser profiles for implementation and testing; original sandbox, isolation, notice and acceptance gates retained |
