# Dashboard maintenance

The existing dashboard is a React/Vite application using Tailwind and CSS custom properties. Theme and localization expansion follow the [roadmap freeze](../product/Roadmap.md#freeze-register); maintaining existing screens and translations remains part of normal changes. The replacement is specified in [Decision 0001](../product/decisions/0001-dashboard-ui-stack.md); until it lands, this application receives the security-driven dependency updates in [Decision 0003](../product/decisions/0003-dependency-baseline-2026-09.md) and no feature work.

## Styles

Use the tokens in [index.css](../../packages/dashboard/src/styles/index.css) and surrounding component conventions. Avoid duplicating raw color values when an existing token expresses the intent. A second theme requires an explicit design/change with visual checks; the presence of CSS variables alone does not establish theme support.

## Shared translations

- Locale JSON resources live in [packages/i18n/locales](../../packages/i18n/locales).
- [supported.ts](../../packages/i18n/src/supported.ts) declares supported locales.
- [dashboard configuration](../../packages/dashboard/src/i18n/config.ts) wires `react-i18next` and locale preferences.
- Components use namespace keys through `useTranslation()`; the browser-input and email code share the locale package.
- `npm run validate --workspace=packages/i18n` checks key parity and suspicious untranslated copies.

Update existing locales when changing user-visible strings. Do not add locales or redesign theme architecture merely to complete a small screen change.

## Auth and verification

Do not copy token-storage assumptions from old phase plans. [Current auth storage](../security/blindpass-threat-model.md#authentication-storage) documents hosted cookies and remaining `localStorage` paths. Keep secret values and bootstrap credentials out of screenshots, component snapshots and ordinary diagnostics.

Use component tests for screen behavior and [dashboard Playwright E2E](../testing/README.md#test-matrix) for backend-connected flows. Historical phase tests retain original scenarios in the Obsidian vault without implying present-day execution.
