# BlindPass landing page

A standalone HTML, CSS and JavaScript landing page for BlindPass. It leads with human-to-agent secret provisioning and policy-controlled agent-to-agent exchange: people provide secrets, and agents can request or fulfill exchanges with separate permissions in each direction. API keys, access tokens and passwords are concrete examples.

The workflow picker illustrates human provisioning, agent exchange, and the separately labeled proposed browser-session pilot. Every workflow uses sample metadata only, submits no data, and connects to no application backend. One-use retrieval limits delivery; it does not expire a provider credential or prevent the recipient runtime from accessing plaintext.

Serve the authored static files from the repository root:

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory landing/dist
```

Open `http://127.0.0.1:4173`. No dependency installation or build is required. The page can also be opened directly from [dist/index.html](dist/index.html).

Product copy follows the [roadmap](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md) and [specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md). Edit the HTML, stylesheet and script directly in `dist/`; this directory contains authored source, not disposable build output. The font is the existing Inter asset reused from the browser UI.

Current-flow copy is grounded in the [exchange policy guide](../docs/guides/policy.md), [OpenClaw integration contracts](../docs/plugins/openclaw-capability-extension.md), and their linked source. The Linux host broker, browser handoff and fleet-controller parity remain proposed; these illustrations do not establish deployment or stock-client compatibility.

Run the dependency-free demo transition checks from the repository root:

```bash
node --check landing/dist/script.js
node --test landing/tests/workflow.test.mjs
```

These checks use DOM doubles to cover success, rejection, flow switching and the retained pilot simulation. They do not establish browser layout, backend behavior, or real secret delivery.

## Machine-readable summary

[dist/llms.txt](dist/llms.txt) publishes with the page and is the summary automated readers will quote. Keep it to claims the repository supports, and keep its implemented/proposed split identical to the page's. It separately records the boundaries that marketing copy tends to drop: the plaintext endpoints, that delivery limits are not revocation, and that approval does not constrain later use. Do not reintroduce archive-era terminology such as "zero-knowledge", named defensive-layer counts, TEE or egress filtering; [Specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md#repository-findings) and the [threat model](../docs/security/blindpass-threat-model.md) correct those.

## Analytics

The page loads Google Analytics 4 (`G-QDP5XZPTDV`) from `googletagmanager.com`. This is the only third-party request the page makes; everything else is local. It sets cookies and sends visitor IP addresses to Google on load, with no consent gate and no `anonymize_ip`, so it needs a privacy-notice and consent decision before serving EU/UK visitors.

## Open items

Accepted on 2026-09-22 with the decision deferred, not resolved. Close each one deliberately rather than by inheriting the current state.

| Item | Decision needed | Owner stage |
|---|---|---|
| GA4 consent | Serving EU/UK visitors without a consent gate or `anonymize_ip` is a privacy-notice decision, not a default. Either add a consent gate and IP anonymization, restrict the audience, or record an explicit accepted-risk. A tracker with no notice also undercuts the page's own claim discipline. | Before broad promotion |
| Hosted platform link | `https://app.atas.tech/` was removed from [dist/llms.txt](dist/llms.txt) because the repository only evidences it in archive/Phase documents. Restore it once the deployment is confirmed live, or leave it out. | Before the next content revision |
| Rendered verification | Social/canonical metadata, the `role="img"` diagram label and the GA4 snippet have never been checked in a browser. No rendering, tag-firing, crawler or Lighthouse result exists. | Before treating the page as released |

## Verification

Run `npm run test:landing` from the repository root. [deploy-landing-pages.yml](../.github/workflows/deploy-landing-pages.yml) runs it before publishing, so a failing demo blocks the deploy.

Verification on 2026-09-22: all seven demo scenarios passed, along with JavaScript syntax, local asset/link/HTML-reference checks and `git diff --check`. Workspace build/tests were attempted but did not pass: build/test tooling is not installed, and the unchanged browser-UI auth-storage suite also reported a session-storage assertion failure. Browser visual checks and backend integration/E2E were not run for this landing-content update.

Updated on 2026-09-22 for the analytics, metadata and content revision: seven demo scenarios and `node --check` passed after adding a terminal-step assertion. Social/canonical metadata, the `role="img"` diagram label and the GA4 snippet are unverified in a browser; no rendering, tag-firing, crawler or Lighthouse check was run.

The P07.5/P07.6 landing-promotion gate is maintained in the Obsidian vault. It owns the GA4 removal or consent-gated disposition and the six GitHub-bound CTA destinations. Browser network and click evidence are required before broad promotion; removal of hosted dashboard analytics does not resolve this landing tag.
