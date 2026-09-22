# Brainstorm: Internationalization (i18n)

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This document captures the design rationale, trade-off analysis, and future expansion patterns for multi-language support in the BlindPass ecosystem.

## Current Status

As of 2026-03-29, the first EN/VI rollout is shipped across the main user-facing surfaces:

- `preferred_locale` is persisted on `users`, returned in auth payloads, and updated via `PATCH /api/v2/auth/locale`
- The dashboard auth shell and workspace pages render from shared EN/VI locale resources
- The browser UI resolves locale from `blindpass_locale` or browser settings and sets `<html lang>` accordingly
- Transactional verification and password-reset emails render from locale-aware templates
- `packages/i18n` validation now checks both key parity and suspicious untranslated English-copy drift, with a small explicit allowlist for product names and schema examples

## Why i18n Now?

BlindPass targets operators and enterprise users across Southeast Asia and globally. Vietnamese is the first non-English locale because the founding team and early adopters are Vietnamese-speaking. The architecture must support adding new languages with minimal code changes.

## Design Decisions

### 1. Shared `packages/i18n` vs. Inline Translations

**Decision**: Shared workspace package with JSON locale files.

**Rationale**: All three UI surfaces (dashboard, browser-ui, email templates) need the same translated strings for shared concepts like "Save", "Cancel", "Workspace", "Agent", etc. A shared package ensures:

- Single source of truth for all translations
- One validation script catches missing keys and suspicious untranslated locale copies across all locales
- Adding a new language is primarily a locale-resource change, with small registration updates in the dashboard and browser-ui loaders
- TypeScript types can be generated from the English JSON structure

**Alternative considered**: Inline translations per package. Rejected because it leads to drift between packages and duplicate maintenance.

### 2. `react-i18next` for Dashboard vs. Custom Loader for Browser-UI

**Decision**: Use `react-i18next` (8KB gzip) for the dashboard; use a lightweight custom loader (~50 lines) for browser-ui.

**Rationale**:

| Factor | Dashboard | Browser UI |
|--------|-----------|------------|
| Framework | React with hooks, context, components | Vanilla JS, no framework |
| String count | ~300 strings across 15 pages | ~60 strings |
| Features needed | Namespace lazy loading, Suspense, plurals | Simple key-value lookup |
| Bundle budget | Already ~200KB (React + router + icons) | Must stay under 50KB total |

`react-i18next` provides hooks (`useTranslation`), namespace loading, and Suspense integration that match the dashboard's React architecture. The browser-ui has no framework, so adding `i18next` (~30KB) would be disproportionate.

### 3. Language Detection Strategy

**Decision**: Auto-detect from browser for the initial experience, persist explicit user choice in both `localStorage` and the database, and let the server override the dashboard locale after authentication.

Detection priority:

```
1. Database → preferred_locale (applies after login/refresh and drives email locale)
2. localStorage → blindpass_locale (persists explicit client-side override before login)
3. navigator.language → browser auto-detect
4. Fallback → "en"
```

**Implementation detail**:

- Registration seeds `preferred_locale` from the current browser-selected locale so the first transactional email follows the operator's likely language.
- After that, only an explicit language switch updates the stored user preference.
- Login does not overwrite `preferred_locale`; it only re-applies the server-backed value to the SPA after authentication succeeds.

**Why not URL-based** (`/vi/login`, `/en/login`): The dashboard is a private SPA behind authentication. URL-based locales are better suited for public marketing sites where SEO matters. For the dashboard, `localStorage` + database is simpler and doesn't complicate routing.

**Why not query param** (`?lang=vi`): Query params don't persist across navigation without explicit forwarding on every link and API call.

### 4. API Error Messages Stay English

**Decision**: API error strings remain in English. Only UI-facing text is localized.

**Rationale**: API errors are consumed by:

- Frontend code that maps error codes to translated messages
- CLI tools and SDK consumers
- Log aggregation and monitoring systems

Localizing API errors would require every consumer to handle locale negotiation. Instead, the API keeps English messages for operator/debug value and returns structured error codes (e.g., `invalid_credentials`, `workspace_suspended`) that the frontend maps to translated strings.

### 5. Gateway Messages Excluded

**Decision**: Skip gateway chat message localization.

**Rationale**: The gateway's `defaultMessageFormatter` is already injectable — integrators pass their own formatter via constructor options. The 4 strings it produces go into chat platforms (Slack, Discord) where the user's locale is already handled by that platform. Localizing the default formatter adds complexity for minimal user impact.

### 6. Database-Backed Locale Preference

**Decision**: Add `preferred_locale TEXT DEFAULT 'en'` to the `users` table.

**Rationale**: The server needs to know the user's locale for email template rendering (verification emails, password reset emails). Without a database field, the server would need to rely on `Accept-Language` headers, which are unreliable (they reflect browser defaults, not user preference). The database field also enables the dashboard to initialize with the correct locale on login.

### 7. Incremental Rollout Order

**Decision**: Land locale persistence and dashboard synchronization first, then page migration, then browser-ui and email rendering.

**Why**: The highest-risk failure mode is divergence between browser state and server state. Fixing the user-preference contract first gives every later translation pass a stable source of truth.

Completed rollout order:

1. Add `preferred_locale` to auth responses and a dedicated locale update endpoint
2. Sync dashboard locale from the authenticated user record and persist manual switches server-side
3. Migrate dashboard pages away from hardcoded copy and remove internal placeholder text
4. Wire browser-ui to the shared locale package
5. Localize email template rendering

## Architecture

### Translation File Organization

Namespaces are organized by feature area to enable lazy loading in the dashboard:

```
locales/en/
├── common.json       ← Shared: "Save", "Cancel", "Loading..."
├── auth.json         ← Login, register, password flows
├── dashboard.json    ← Dashboard overview page
├── agents.json       ← Agent enrollment/management
├── members.json      ← Member management
├── billing.json      ← Billing, quotas, x402
├── audit.json        ← Audit log viewer
├── policy.json       ← Workspace policy editor
├── offers.json       ← Public offers marketplace
├── approvals.json    ← Approval inbox
├── analytics.json    ← Analytics page
├── settings.json     ← Workspace settings
├── browser-ui.json   ← Secure secret input page
└── email.json        ← Email template strings
```

### Key Naming Convention

Locale files use nested JSON objects, while components reference them with dotted paths inside a namespace:

```json
{
  "hero": {
    "sectionLabel": "Agent management",
    "title": "Agent enrollment and rotation",
    "body": "Manage agent credentials, rotate bootstrap keys..."
  },
  "table": {
    "sectionLabel": "Fleet overview",
    "title": "Workspace fleet"
  },
  "emptyState": {
    "title": "No agents enrolled",
    "body": "No agents have been enrolled yet."
  }
}
```

### Interpolation

Use ICU-style interpolation for dynamic values:

```json
{
  "confirmRotate.body": "Rotate the API key for {{agentId}}. The previous key will stop working immediately.",
  "stats.activeAdmin": "{{count}} active admin",
  "stats.activeAdmins": "{{count}} active admins"
}
```

### Validation Strategy

Two different checks are needed:

- **Key parity**: every locale file must expose the same key structure
- **Translation completeness**: non-English locales should not silently ship large English-copy placeholders

The shipped validator now enforces both:

- key parity between English and each supported locale
- suspicious untranslated-copy detection for non-English locales

The drift check intentionally ignores a small allowlist of technical or product identifiers such as brand names, transaction-hash labels, and schema-example placeholders where identical copy is expected.

## Future Expansion

### Adding a New Language

1. Create `locales/{code}/` directory with copies of all English JSON files
2. Translate all values (keys stay identical)
3. Add the locale code to `packages/i18n/src/supported.ts`
4. Register the locale in `packages/dashboard/src/i18n/config.ts` and `packages/browser-ui/src/i18n.js`
5. Run `npm run validate --workspace=packages/i18n` to ensure key parity and clean drift output
6. Review the validator allowlist only if the new locale intentionally keeps technical identifiers identical
7. No server-side route changes should be needed unless a new locale code must be accepted by request schemas

### Plural Rules

`react-i18next` supports ICU plural rules out of the box. The Vietnamese language has no grammatical plurals (same form for singular and plural), so plural handling is straightforward for the initial EN/VI pair. Future languages with complex plural rules (Arabic, Polish) will work with i18next's built-in ICU support.

### RTL Support

Not needed for EN/VI. If RTL languages (Arabic, Hebrew) are added later:

- Add `dir="rtl"` attribute to `<html>` based on locale
- Use CSS logical properties (`margin-inline-start` instead of `margin-left`)
- Test layout with RTL text rendering

The current implementation does not use CSS logical properties, so RTL support would require a CSS refactor. This is acceptable since no RTL languages are planned in the near term.

### Server-Side Rendering (SSR)

Not applicable. Both the dashboard and browser-ui are client-rendered SPAs. If SSR is introduced later, the i18n architecture supports server-side resolution via the `resolveLocale()` utility.
