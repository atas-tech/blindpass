# Dashboard redesign mockup

Saved on 2026-09-22 for later review. This is a standalone, interactive design preview of the proposed landing-aligned dashboard, not the dashboard application.

## Open the preview

Open [index.html](index.html) in a browser, or serve this folder from the repository root:

```bash
python3 -m http.server 4176 --bind 127.0.0.1 --directory docs/design/dashboard-redesign
```

Visit `http://127.0.0.1:4176`. No npm installation, build, backend, or account is required. Fonts and icons use external CDN resources; allow network access for the intended appearance. If those resources are unavailable, the labeled controls and sample interactions still work with fallback typography.

## Review scope

- Overview, approval queue and detail, agents, exchange policy, and audit log.
- Lightweight members, usage/billing, and settings views.
- Sample approve/reject decisions update the queue and audit preview locally.
- Agent status filters and mobile navigation are interactive.

All data is fictional. Approval countdowns are fixed examples. Reloading resets preview state. Enrollment and credential management show explanatory notices; there are no real mutations, credentials, or application API calls. The standalone export does not include the conversation's optional design-tweak controls.

## Files and related plans

- [index.html](index.html): complete browser-ready export, including the preview wrapper and rendering helpers.
- [source.html](source.html): editable HTML fragment preserved from the conversation. It relies on rendering helpers and is not the standalone entry point. Keep the export synchronized when revising this source.
- [Redesign plan](../../product/dashboard-redesign.md): visual direction, complete route coverage, behavior constraints and rollout stages.
- [Acceptance plan](../../testing/Dashboard%20Redesign.md): proposed product integration/E2E scenarios and recorded design-only checks.

## Before reusing this as implementation input

This is a preview, and some of its choices are preview-only. The external fonts and icon/positioning scripts loaded from `unpkg.com` and Google Fonts do not belong in the application: the dashboard already has Lucide and a local Inter asset. Copying CSS out of this file will carry the CDN `<link>` and `<script>` tags with it.

The standalone export and `source.html` are kept in step by hand. Update both in the same change, or replace them with a generated export, before revising the mockup again.

The open items carried out of the design review, with their owner stages, are tracked in the [redesign plan](../../product/dashboard-redesign.md#open-items-carried-from-design-review).

Application implementation remains unchanged. Prototype checks are not evidence that product acceptance scenarios pass.
