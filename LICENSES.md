# BlindPass Licensing Matrix

BlindPass uses a mixed-license monorepo model. The applicable license depends on the package you are using.

## Package Matrix

| Package | License | Notes |
| :--- | :--- | :--- |
| `packages/sps-server` | `AGPL-3.0-only` | Secret Provisioning Service / trust anchor |
| `packages/dashboard` | `AGPL-3.0-only` | Hosted control plane UI; eligible for removal since P04 slice 13, frozen tests kept until the package is deleted |
| `packages/console` | `AGPL-3.0-only` | P04 operator console for the Rust controller; declared in package metadata |
| `desktop/approval-app` | `AGPL-3.0-only` | P04 Quickshell approval app; SPDX headers, no package manifest |
| `desktop/omarchy-widget` | `AGPL-3.0-only` | P04 Omarchy bar widget; declared in its `manifest.json` |
| `packages/i18n` | `AGPL-3.0-only` | Declared in package metadata; no standalone package LICENSE file currently present |
| `packages/agent-skill` | `MIT` | Agent-side SDK / skill logic |
| `packages/browser-ui` | `MIT` | Client-side encryption sandbox |
| `packages/gateway` | `MIT` | Interception / delivery middleware |
| `packages/openclaw-plugin` | `MIT` | Runtime integration plugin |
| `packages/mcp-server` | `MIT` | Official MCP SDK integration; retain actual upstream Apache/MIT transition notices |
| `helpers/browser-tool` | `AGPL-3.0-only` | Private pinned stock Playwright MCP acceptance profile; upstream Apache notices retained |
| `helpers/login` | `AGPL-3.0-only` | Private login helper; Playwright and its upstream Apache notices remain applicable |
| `packages/contract-tests` | `AGPL-3.0-only` | Black-box compatibility and acceptance harness; private test package |
| `assets/ui` | `MIT` (Inter font: `OFL-1.1`) | Shared design tokens, icons and self-hosted font consumed by landing, input page and console; no application code or translated strings. See `assets/ui/ASSETS.md` |
| `crates/blindpass-core` | `AGPL-3.0-only` | Shared identity, delivery, custody, signing, policy and protocol primitives |
| `crates/blindpass-broker` | `AGPL-3.0-only` | Root host broker and native consumer probes |
| `crates/blindpass-controller` | `AGPL-3.0-only` | Rust controller (P02; implemented, not yet accepted) |
| `crates/blindpass-cli` | `AGPL-3.0-only` | Local controller administration CLI |
| `crates/blindpass-node` | `AGPL-3.0-only` | Unprivileged fleet channel relay; no broker key storage |

## Repository Notes

- The root workspace package is marked `private` and uses `SEE LICENSE IN LICENSES.md` because the repository contains packages under more than one license.
- The six original application/integration packages include `LICENSE` files. The shared i18n package currently declares its license in `package.json` only; this documentation update does not add or change licensing terms.
- The [original licensing proposal](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/archive/Licensing_Proposal.md) in the docs vault is historical rationale; the package metadata/license files and this matrix describe the current repository.

### P02 Rust controller dependencies

The user approved this controller/CLI dependency set on 2026-09-24 after reviewing the Socket findings in [decision 0004](docs/product/decisions/0004-controller-dependency-review-2026-09.md). Cargo.lock pins the resolved versions. The direct package licenses are:

| Crate | Locked version | License |
| :--- | :--- | :--- |
| `argon2` | 0.5.3 | MIT OR Apache-2.0 |
| `axum` | 0.8.9 | MIT |
| `base64` | 0.22.1 | MIT OR Apache-2.0 |
| `clap` | 4.6.7 | MIT OR Apache-2.0 |
| `jsonwebtoken` | 9.3.1 | MIT |
| `rand` | 0.8.8 | MIT OR Apache-2.0 |
| `serde` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 |
| `sqlx` | 0.8.6 | MIT OR Apache-2.0 |
| `tokio` | 1.53.1 | MIT |
| `tower-http` | 0.6.11 | MIT |
| `tracing` | 0.1.44 | MIT |
| `tracing-subscriber` | 0.3.23 | MIT |

This approval is for the P02 dependency proposal and its resolved Cargo graph. It does not change the license or dependency boundary of `blindpass-core`; that crate remains dependency-free.

## Boundary Expectations

- MIT packages are intended to remain separable integrations around the protocol and service.
- MIT packages should not vendor or embed AGPL application code.
- The Rust broker and `blindpass-core` use host `libsystemd` and `libcrypto`
  through a narrow FFI surface and have no third-party Cargo crypto or
  zeroization dependency. The controller and CLI use the reviewed crate set
  above; its graph includes `jsonwebtoken`, `argon2`, and sqlx with `rustls`,
  `ring` and a bundled SQLite.
- If package boundaries change materially, the licensing split should be reviewed again.


### P05 MCP distribution boundary

The MIT OpenClaw startup wrapper adapts its existing MIT legacy callbacks into
`packages/mcp-server`'s official SDK factory. The factory imports no OpenClaw or
AGPL application implementation; protocol interactions do not embed broker code.
The standalone MCP bundle preserves SDK/Zod notices and complete licenses for
all emitted third-party package versions. The compiler-input check is an allowlist:
only node_modules packages with an approved license and the MIT workspace packages
`packages/mcp-server`, `packages/openclaw-plugin`, `packages/gateway` and
`packages/agent-skill` may enter the bundle; any other workspace (including MIT),
helper, crate, script or root path, and any missing/unsupported license text, is
rejected. A generated version/hash inventory ships under
`dist/licenses/bundle-packages.json`.

The P05 work changes the npm manifests and `package-lock.json` against commit
`1a37bbe` (verified from `git diff 1a37bbe -- package-lock.json package.json`
and the workspace manifests; no locked package was removed and no previously
locked package changed version):

- New direct dependencies, exact pins approved in decisions 0005 and 0006:
  `@modelcontextprotocol/server` 2.2.0 and `zod` 4.6.5 (`packages/mcp-server`,
  MIT), `playwright` 1.58.2 (`helpers/login`, AGPL-3.0-only workspace) and
  `@playwright/mcp` 0.0.83 (`helpers/browser-tool`, AGPL-3.0-only workspace).
- New transitive packages: `@modelcontextprotocol/core` 2.2.0 (MIT) and `zod`
  4.6.5, installed three times (package, SDK server, SDK core); and
  `@playwright/mcp`'s own nested `playwright` and `playwright-core`
  1.64.0-alpha-1790635538000 (Apache-2.0), separate from the root 1.58.2 copies.
- `playwright` 1.58.2, `playwright-core` 1.58.2 and playwright's optional nested
  `fsevents` 2.3.2 keep their versions but are no longer dev-only, because
  `helpers/login` depends on Playwright at runtime. `@playwright/test` stays dev.
- Workspaces gain `helpers/*` (`helpers/login`, `helpers/browser-tool`) and
  `packages/mcp-server`; the root `engines.node` moves from `>=26 <27` to
  `^24.21.0 || ^26.10.0`, and every existing workspace package (agent-skill,
  browser-ui, console, contract-tests, dashboard, gateway, i18n, openclaw-plugin,
  sps-server), which declared no engines before, gains the same range.

The Cargo graph is outside this paragraph. The change does not extend frozen
payment features. Node 24.21.0/26.10.0 have local build/workspace and selected
real-systemd profile evidence. Engine declarations use the tested minimums, and
CI contains both pinned profiles; remote CI execution remains unverified. The private
runtime archive preserves the complete upstream Node license text as well as
the existing SDK/browser notices.
