# 0001: Dashboard UI stack for the rebuild

**Status:** Accepted 2026-09-22. Applies to the rebuilt operator dashboard. The existing `packages/dashboard` application is not modified by this record beyond the maintenance rule in [Decision 0003](0003-dependency-baseline-2026-09.md).

**Companions:** Dashboard redesign and UI acceptance plan in the Obsidian vault · [Decision 0002](0002-rust-controller-and-broker.md) · [Current dashboard maintenance](../../architecture/dashboard-maintainability.md)

## Context

The [roadmap](../Roadmap.md) replaces the hosted secret-provisioning product with a Linux fleet controller, a privileged host broker and an Omarchy operator interface. The dashboard will be rebuilt for that product rather than refactored, so the stack question is open.

The existing dashboard (lockfile of 2026-03-31) is React 19.2, Vite 7.3, react-router 7.13, i18next 26 with two locales, Tailwind 4.2 used only through `@apply` inside a 1,500-line stylesheet, lucide-react icons, Vitest component tests (15 files) and a Playwright suite (14 spec files) that starts the API, dashboard and input page together. It loads Inter from Google Fonts at runtime, hard-codes "live" and "session active" status pills, ships a non-functional search field and leaves one component in untranslated English.

The secret-input page in `packages/browser-ui` is vanilla JavaScript with Vite and hpke-js under a `script-src 'self'` policy. The landing site is static HTML, CSS and JavaScript on GitHub Pages. Omarchy plugins, including the operator's own published plugins, are Quickshell QML, so the desktop widget and approval application will not share web code whatever stack the dashboard uses.

## Decision

Rebuild the dashboard in `packages/console` on **React 19, Vite, react-router 7, i18next and Playwright**, with these changes from the current application:

- **Plain CSS custom properties, no Tailwind.** One shared token file in `assets/ui`, sourced from the landing stylesheet palette recorded in the redesign plan in the Obsidian vault, is consumed by the landing site, the input page and the dashboard. Tailwind and the PostCSS pipeline are not carried over; today they only expand `@apply` rules.
- **Self-hosted Inter, no runtime font CDN.** The content security policy drops the Google Fonts origins.
- **Contract-first.** Write `docs/api/controller.openapi.yaml` first and generate TypeScript types from it with a generator selected through the dependency-guard skill. Screens are designed around the pilot nouns (node, workload, grant, operation, consumption mode) rather than the SPS nouns (workspace, offer, intent, billing). Building against SPS nouns would mean rebuilding twice.
- **Static assets served by the controller.** The built dashboard and input page are embedded in or served by the controller binary described in [Decision 0002](0002-rust-controller-and-broker.md). This removes the two nginx images and their Unraid templates.
- **Truthful status only.** Live indicators, session state and search exist only when backed by an endpoint. The `data-testid` inventory is pruned to what the acceptance plan uses.
- **Input page stays vanilla.** `packages/browser-ui` is part of the signed-link compatibility contract, is small and has a strict CSP. It adopts the shared tokens and the copy corrections from the redesign review but does not move to React.
- **Desktop surfaces are QML.** The Omarchy metadata widget and the operator approval application are Quickshell QML, in `desktop/omarchy-widget` and `desktop/approval-app` respectively, and talk to the controller over the same OpenAPI contract.

The repository layout is accepted with this record and Decision 0002. These directories are implementation targets, not existing packages; licensing and dependency review still precede scaffolding. The web package is called `console` and the QML application `approval-app` to keep build commands, test references and review discussion distinct.

## Alternatives considered

| Option | Why not |
|---|---|
| Svelte, Vue or Solid | No product gain over React for a queue, detail and form application. Smaller accessibility and i18n ecosystems for a one-person team, and a relearning cost during a product pivot. |
| Rust WASM UI (Leptos, Dioxus) | Single language with the Rust backend is attractive, but bundles are heavy, i18n and accessibility tooling are thin, iteration is slow and QML is still needed on the desktop. |
| HTMX with server-rendered templates | Fits tables, but the approvals queue with live detail, the policy editor and the one-time key reveal want client state, and i18n moves to the server. |
| Next.js or Remix with SSR | No server-rendering need. Static assets embed in the controller binary more simply. |
| Keep Tailwind | Used only as an `@apply` macro. It adds a PostCSS toolchain with two direct dependencies that currently carry security advisories and duplicates what CSS tokens already provide. |

## Consequences

- The current dashboard becomes maintenance-only. It receives security-driven dependency updates ([Decision 0003](0003-dependency-baseline-2026-09.md)) and nothing else, and is deleted when the rebuilt package passes the UI acceptance plan in the Obsidian vault.
- Playwright remains the acceptance driver. The new package reuses the existing pattern of starting the API and both web applications from one configuration, pointed at the controller from Decision 0002 with an equivalent of the seed-route test mode.
- The two locale bundles in `packages/i18n` carry over. Untranslated component strings are moved into them during the rebuild.
- Tokens must be published once and imported three times. Changing a color in the landing stylesheet without changing the token file is a defect.

## Evidence

- Versions are from `package-lock.json` (last changed 2026-03-31) and the npm registry on 2026-09-22.
- Omarchy plugin structure (`manifest.json`, `BarWidget.qml`, `Panel.qml`, `components/*.qml`) was inspected on a local Omarchy installation on 2026-09-22.
- The redesign mockup, current dashboard, input page and landing site were rendered at desktop and mobile widths on 2026-09-22. Screenshots were not committed.
- No user research or usage telemetry informed this record; the product has no adopted user base as recorded in [finding F-6](../Specification.md#repository-findings).
