# BlindPass landing page

A standalone HTML, CSS and JavaScript landing page for BlindPass. It leads with human-to-agent secret provisioning and policy-controlled agent-to-agent exchange: people provide secrets, and agents can request or fulfill exchanges with separate permissions in each direction. API keys, access tokens and passwords are concrete examples.

The workflow picker illustrates human provisioning, agent exchange, and the separately labeled proposed browser-session pilot. Every workflow uses sample metadata only, submits no data, and connects to no application backend. One-use retrieval limits delivery; it does not expire a provider credential or prevent the recipient runtime from accessing plaintext.

Serve the authored static files from the repository root:

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory landing/dist
```

Open `http://127.0.0.1:4173`. No dependency installation or build is required. The page can also be opened directly from [dist/index.html](dist/index.html).

Product copy follows the [roadmap](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md) and [specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md). Edit the HTML, stylesheet and script directly in `dist/`; this directory contains authored source, not disposable build output. `index.html` references `styles.css`, `script.js` and `reel.js` with `?v=` set to the first 8 hex digits of each file's SHA-256 (`sha256sum landing/dist/styles.css | cut -c1-8`). Pages caches every file for 10 minutes, so an unchanged URL can pair new HTML with a stale stylesheet. That happened with the reel's first deploy: the video rendered at 1600px and the page overflowed. After editing one of these files, update its version; `landing/tests/assets.test.mjs` fails and blocks the deploy until you do. The font is the existing Inter asset reused from the browser UI.

Current-flow copy is grounded in the [exchange policy guide](../docs/guides/policy.md), [OpenClaw integration contracts](../docs/plugins/openclaw-capability-extension.md), and their linked source. The Linux host broker, browser handoff and fleet-controller parity remain proposed; these illustrations do not establish deployment or stock-client compatibility.

Run the dependency-free demo transition checks from the repository root:

```bash
node --check landing/dist/script.js
node --test landing/tests/workflow.test.mjs
```

These checks use DOM doubles to cover success, rejection, flow switching and the retained pilot simulation. They do not establish browser layout, backend behavior, or real secret delivery.

## Machine-readable summary

[dist/llms.txt](dist/llms.txt) publishes with the page and is the summary automated readers will quote. Keep it to claims the repository supports, and keep its implemented/proposed split identical to the page's. It separately records the boundaries that marketing copy tends to drop: the plaintext endpoints, that delivery limits are not revocation, and that approval does not constrain later use. It also states the site's own analytics disposition (none; hosted by GitHub Pages), which must stay identical to the Analytics section below. Do not reintroduce archive-era terminology such as "zero-knowledge", named defensive-layer counts, TEE or egress filtering; [Specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md#repository-findings) and the [threat model](../docs/security/blindpass-threat-model.md) correct those.

## Reel

The "In motion" section embeds [dist/assets/blindpass-reel.mp4](dist/assets/blindpass-reel.mp4) (15 s, 1920×1080, 60 fps, H.264 High with AAC 128 kbps, 8.0 MB) with [dist/assets/reel-poster.jpg](dist/assets/reel-poster.jpg) as its poster. [dist/reel.js](dist/reel.js) keeps it `preload="none"` until it scrolls into view, then autoplays muted and loops; it pauses off-screen. A viewer's pause holds across scrolling. "Sound" unmutes and restarts from the top so the score lands on its cues. With `prefers-reduced-motion: reduce` it never autoplays or preloads.

The reel shows only the implemented agent-to-agent exchange and this page's own content. Keep it that way: it must not depict the proposed host broker, browser handoff or fleet work as available. The video and score are rendered from [reel/](reel/README.md): an HTML/JS timeline and a numpy synthesis script, with no samples or licensed audio. `landing/reel/render.sh` regenerates both assets. Changing the reel's content means re-rendering it.

## Analytics

GA4 was removed on 2026-10-06 (P07-D1). The property `G-QDP5XZPTDV` and every `googletagmanager.com`, `gtag` and `dataLayer` reference are gone from `dist/`. The page runs no analytics or tag manager, has no consent banner because nothing needs consent, sets no cookies and uses no browser storage. Its HTML, CSS and scripts request nothing from another origin: the font, video and poster are local. [release-gate.test.mjs](tests/release-gate.test.mjs) enforces all of this before every deploy, and the fresh-browser network record is in [p07-landing-2026-10-06.md](../docs/testing/evidence/p07-landing-2026-10-06.md).

Removal does not mean nothing is processed. What remains, with what could not be verified:

- **GitHub Pages is the host.** The site deploys from `.github/workflows/deploy-landing-pages.yml` and serves from the custom domain `blindpass.atas.tech` (response header `server: GitHub.com` behind a Fastly edge, checked 2026-10-06). GitHub receives every request, including the visitor's IP address, and handles it under its own [privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement), which lists IP address under service-usage information and gives no Pages-specific retention period. This repository cannot read or configure those logs, and what GitHub or its CDN retains, for how long and who can see it is not verified.
- **DNS for `atas.tech` is operated outside this repository.** Its provider and query logging are not verified.
- **Outbound clicks** go to `github.com` under GitHub's terms. The page sets no `Referrer-Policy`, so the browser default applies.
- **Data already collected stays collected.** The deployed page served the GA4 tag until this removal reaches `main`. Whatever Google Analytics holds for that property is unaffected by this change; deleting the property or its data, or recording that it is retained, is an owner action that has not been taken.
- **No headers are set by this repository.** GitHub Pages does not let a project set response headers, so the live page has no Content-Security-Policy, frame or referrer headers of its own (F-11's landing half). A `<meta>` policy is possible and is a separate decision.

## Open items

Accepted on 2026-09-22 with the decision deferred, not resolved. Close each one deliberately rather than by inheriting the current state.

| Item | Decision needed | Owner stage |
|---|---|---|
| Tag-dependent CTAs | “Read the docs” and “Explore BlindPass” still point at the repository README and root. P07-D7 sends them to `docs/deploy/native-quickstart.md` and the GitHub Release page at the release tag. No tag exists, and the plan forbids a placeholder, so both stay as they are until P07.6 and are recorded as unresolved in the evidence record. | P07.6 |
| Hosted platform link | `https://app.atas.tech/` was removed from [dist/llms.txt](dist/llms.txt) because the repository only evidences it in archive/Phase documents. Restore it once the deployment is confirmed live, or leave it out. | Before the next content revision |
| Rendered verification | Metadata and the diagram label were checked in a browser on 2026-10-06 (see the evidence record). No crawler, Lighthouse or Safari/Firefox result exists. | Before treating the page as released |

## Verification

Run `npm run test:landing` from the repository root. [deploy-landing-pages.yml](../.github/workflows/deploy-landing-pages.yml) runs it before publishing, so a failing demo blocks the deploy.

Verification on 2026-09-22: all seven demo scenarios passed, along with JavaScript syntax, local asset/link/HTML-reference checks and `git diff --check`. Workspace build/tests were attempted but did not pass: build/test tooling is not installed, and the unchanged browser-UI auth-storage suite also reported a session-storage assertion failure. Browser visual checks and backend integration/E2E were not run for this landing-content update.

Updated on 2026-09-22 for the analytics, metadata and content revision: seven demo scenarios and `node --check` passed after adding a terminal-step assertion. Social/canonical metadata, the `role="img"` diagram label and the GA4 snippet are unverified in a browser; no rendering, tag-firing, crawler or Lighthouse check was run.

Updated on 2026-09-26 for the reel: `npm run test:landing` passed 13 tests, including six reel-player DOM-double tests. The section was also checked in a real browser (Arch `chromium` via Playwright, 1440×900 and 390×844, default autoplay policy). Nothing downloaded before scroll. Muted autoplay started in view. Sound unmuted and restarted from 0. A pause held after scrolling away and back. Reduced motion neither played nor loaded. There was no horizontal overflow. The only failed request was the deliberately blocked GA4 script. Safari/iOS and Firefox playback were not tested.

Updated on 2026-10-06 for P07.5: GA4 removed, the footer “Security” link retargeted to the new root [SECURITY.md](../SECURITY.md), and `tests/release-gate.test.mjs` added to `npm run test:landing`. Fresh-browser network, storage and click-through evidence (desktop 1440×900, mobile 390×844) is in [p07-landing-2026-10-06.md](../docs/testing/evidence/p07-landing-2026-10-06.md). Two of the six CTA rows remain unresolved until a release tag exists.

The P07.5/P07.6 landing-promotion gate is maintained in the Obsidian vault. It owns the GA4 disposition and the six GitHub-bound CTA destinations. P07.6 blocks promotion while any CTA row is unresolved; removal of hosted dashboard analytics did not resolve the landing tag, and removing the tag does not resolve the CTA rows.
