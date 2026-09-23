# 0003: Dependency baseline, September 2026

**Status:** Partially implemented 2026-09-23. The user approved the reviewed Vitest 4.1.11, Vite 7.3.6, Fastify 5.12.5 and react-router-dom 7.18.4 upgrade slice; those four direct dependencies and their resolved lockfile entries are updated. Other proposed maintenance upgrades remain unapplied. P01 adds a dependency-free Cargo workspace. See the [P01 execution record](../../testing/p01-host-broker-evidence.md).

**Companions:** [Decision 0001](0001-dashboard-ui-stack.md) · [Decision 0002](0002-rust-controller-and-broker.md) · [Security documentation](../../security/README.md) · [Repository instructions](../../../AGENTS.md)

## Context

The pre-upgrade `package-lock.json` was last changed on 2026-03-31. `npm audit` against that lockfile on 2026-09-22 reported 17 advisories: 1 critical, 11 high, 3 moderate, 2 low. The original affected direct dependencies and where they are used:

| Advisory severity | Package | Pinned | Used by | Fixed in | Notes |
|---|---|---|---|---|---|
| Critical | vitest | 3.2.4 | dashboard, sps-server, agent-skill (dev) | 4.1.11 or 5.x | Fix requires a major bump; 3.2.7 remains vulnerable. Also clears the moderate `@vitest/mocker` advisory. Development-only exposure. |
| High | vite | 7.3.1 | dashboard, browser-ui (dev) | 7.3.6 | Within major. |
| High | react-router-dom / react-router | 7.13.1 | dashboard (runtime) | 7.18.4 | Includes an open redirect through `Link` and `useNavigate`, which applies to a single-page application. The SSR and RSC items do not apply. |
| High | postcss | 8.5.8 | dashboard (build) | 8.5.28 | Leaves with Tailwind in the rebuild; patch now. |
| High | fastify | 5.6.1 | sps-server (runtime) | 5.12.5 | Content-type validation bypass, forwarded-header spoofing, schema bypass. Also pulls patched `find-my-way` and `fast-uri`. |
| High | ws via viem | transitive | agent-skill (x402, frozen) | viem 2.49.4 or later | Frozen feature; patch within major, do not expand. |
| Moderate | viem | 2.x | agent-skill (x402, frozen) | 2.49.4 or later | As above. |
| High, moderate, low | nanoid, picomatch, browserslist, baseline-browser-mapping, esbuild, @babel/core | transitive | build tooling | lockfile refresh | Resolved by refreshing the lockfile after the direct bumps. |

The repository had no installed `node_modules` when checked, so `npm outdated` reported nothing; versions above are from the lockfile and the registry.

## Decision

**Tier A: security updates to existing packages, within major where a fix exists.** These are the only changes the maintenance-only packages receive.

| Package | From | To | Package(s) |
|---|---|---|---|
| fastify | ^5.6.1 | ^5.12.5 | sps-server; `@fastify/cors` 10.1.0 has no advisory and stays |
| vite | ^7.3.1 | ^7.3.6 | dashboard, browser-ui |
| vitest | ^3.2.4 | ^4.1.11 | dashboard, sps-server, agent-skill; check the dashboard `vite.config.ts` `test` block and setup files against the Vitest 4 migration notes |
| react-router-dom | ^7.13.1 | ^7.18.4 | dashboard |
| postcss | ^8.5.8 | ^8.5.28 | dashboard |
| viem | ^2.47.6 | ^2.49.4 | agent-skill |
| hpke-js | ^1.7.0 | ^1.8.0 | root, browser-ui, agent-skill; minor bump of the `@hpke/*` suite, re-run the HPKE round-trip tests |
| @playwright/test | ^1.58.2 | ^1.63.0 | dashboard; reinstall Chromium |
| react, react-dom, @types/react, @types/react-dom | 19.2.x | 19.3.0 | dashboard; optional, minor |
| i18next, react-i18next | 26.0.1, 17.0.1 | 26.4.2, 17.0.15 | dashboard; optional, minor |

`@vitejs/plugin-react` stays at 5.2.0 because 6.x requires Vite 8. TypeScript stays at 5.9.3. CI and the Node-based Docker build/runtime images use Node 26.x to match the recorded P00 runtime; the root `engines` field and `.npmrc` reject a different major during npm install.

**Tier B: baseline for the rebuilt dashboard package only** ([Decision 0001](0001-dashboard-ui-stack.md)).

| Package | Version | Notes |
|---|---|---|
| react, react-dom | 19.3 | |
| react-router | 7.18 | Import from `react-router`; `react-router-dom` is a re-export in v7 |
| vite | 8.3 | Rolldown-based; requires Node 20.19 or 22.12 and later |
| @vitejs/plugin-react | 6.1 | Requires Vite 8 |
| vitest | 5.0 | Requires Node 22.12 or later |
| @playwright/test | 1.63 | |
| i18next, react-i18next, i18next-browser-languagedetector | 26.4, 17.0, 8.2 | |
| lucide-react | 1.47 | Major bump from 0.577; icon names must be checked against the mockup |
| jsdom or happy-dom | jsdom 30.1 | jsdom 30 requires Node 22.22.2 or later |
| @testing-library/react, jest-dom, user-event | 16.3, 7.0, 14.6 | |
| typescript | 5.9.3 | TypeScript 7.0.2 (native compiler, published 2026-07-08) is evaluated separately; it ships as platform binaries and must prove `tsc --noEmit` and NodeNext emit parity across the workspace before adoption |
| tailwindcss, @tailwindcss/postcss, autoprefixer, postcss | not used | Removed by Decision 0001 |

**Tier C: not now.** Vite 8, Vitest 5, TypeScript 7, jsdom 30 and lucide 1.x are not applied to the existing dashboard, which is being replaced. Node 24 LTS becomes the toolchain target when the rebuilt package lands.

## Process

1. Authenticate the Socket CLI (`socket login`, interactive) or expose MCP `depscore`. The 2026-09-23 credential update enabled full scan creation; the current scan ID is `0d2bc0fb-57d3-41ce-bea7-ed4ac29703ee`.
2. For each Tier A package run the dependency-guard `check_dependency.sh` helper in `deep` mode with the target version, classify with the decision matrix, and record the outcome in the pull request. Version upgrades of previously allowed packages may use the fast path only if no new alerts appear.
3. Run the skill's `discover_scan_targets.sh` on the repository, then `socket scan create` over `package.json` and `package-lock.json` after the manifest edits, and carry forward any partial-coverage warning.
4. Edit the manifests, run `npm install` to refresh the lockfile, then `npm audit`.
5. Run `npm run build`, `npm test`, `npm run test:integration` with Redis, `npm run test:e2e --workspace=packages/sps-server` with PostgreSQL and `npm run test:e2e` for the dashboard. Vitest 4 and Playwright 1.63 are the two changes most likely to need configuration work.
6. Commit manifests and lockfile together with the review outcomes.

## Consequences

- The approved slice removes the pre-upgrade Vitest critical advisory and updates Fastify and react-router. Ten advisories remain in the lockfile, including PostCSS and viem; `npm audit` is a package advisory inventory, not proof that a deployed service is exploitable or safe.
- The rebuilt dashboard starts on Tier B and never inherits the Tailwind or PostCSS toolchain.
- New Rust crates for [Decision 0002](0002-rust-controller-and-broker.md) follow the same skill with the `cargo` ecosystem.

## Evidence

- `npm audit --json` and `npm view` against the public registry on 2026-09-22 with npm 11.19.1 and Node 26.9.0 on the development host.
- Lockfile history from `git log -- package-lock.json`.
- Socket full scan on 2026-09-23 covered 16 JS/Cargo manifests and lockfiles and failed policy for Vitest 3.2.4 `criticalCVE`. A previous read-only discovery found 20 candidate files; the earlier HTTP 403 was resolved by the credential update.
- Broad candidate deep scores: Vitest 4.1.11 has 399 direct/transitive packages, minimum overall 37, high CVE/obfuscation/ownership alerts and install-script warnings; Vite 7.3.6 has 203 packages, minimum overall 37 and a high upgrade alert plus installer/native-code warnings. Those broad graphs classify as `block`. Fastify 5.12.5 scores minimum 73 with medium network/eval alerts; react-router-dom 7.18.4 scores minimum 64 with medium network alerts. Broad package scores can include optional dependencies absent from this workspace.
- A temporary lockfile with only those four direct upgrades resolved 34 added, removed or changed package entries. Socket scan `32dd9991-31a0-4f0a-b381-4658299ea009` covered its 10 npm manifests/lockfiles and **passed organization policy**. None of the changed entries had an install script; their overall scores ranged from 64 to 99. The exact changed set still contains medium `usesEval`, `networkAccess`, `shellAccess` and related alerts, and `react-router-dom` scores 64. Under the repository's dependency-guard decision matrix this was `block_pending_human_review`, despite the organization-policy pass. The user approved this exact slice on 2026-09-23; the repository manifests and lockfile now contain it. No other direct upgrade was applied.
- `npm ci` on the updated lockfile succeeded. Final repository Socket scan `2f43843e-a3d2-4aee-90bd-0eac5eb0e731` covered 20 manifests/lockfiles and passed organization policy. `npm audit` now reports 10 advisories: 0 critical, 6 high, 2 moderate and 2 low. Remaining direct advisories include PostCSS and viem; their separate upgrades require fresh Socket review before manifest changes. Workspace build/tests, Redis integration, TypeScript contract (27), PostgreSQL SPS suite (177 enabled), SPS E2E (9) and dashboard browser E2E (31) passed after this slice.
