# Licensing Strategy Proposal: BlindPass

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../README.md) and [roadmap](../product/Roadmap.md).

This document proposes a default licensing strategy for the BlindPass monorepo. It is intended as a product and engineering recommendation, not legal advice. Final adoption should be reviewed by counsel before public release.

---

## Proposed Decision

Adopt a split-licensing model:

| Package | Proposed License | Role |
| :--- | :--- | :--- |
| `packages/sps-server` | **AGPL-3.0** | Secret Provisioning Service / trust anchor |
| `packages/dashboard` | **AGPL-3.0** | Hosted control plane UI |
| `packages/agent-skill` | **MIT** | Agent-side SDK / skill logic |
| `packages/browser-ui` | **MIT** | Client-side encryption sandbox |
| `packages/gateway` | **MIT** | Interception / delivery middleware |
| `packages/openclaw-plugin` | **MIT** | Runtime integration plugin |

Keep the code in one monorepo for now. Revisit repo separation only if customer procurement, distribution, or packaging friction becomes material.

---

## Why This Split Fits the Product

### AGPL for the Infrastructure Core
**Target packages:** `packages/sps-server`, `packages/dashboard`

AGPL is a strong fit for the hosted control plane and trust anchor because those components are the heart of the service.

Why this is attractive:
1. **Protects hosted modifications:** If a third party modifies the AGPL-covered server or dashboard and lets users interact with that modified version over a network, AGPL is designed to require an offer of the corresponding source code for that modified program.
2. **Supports transparency:** The security-sensitive parts of the platform remain auditable, which is valuable for a system centered on secret handling and trust.
3. **Preserves commercial options:** If the project later offers commercial licensing for customers who cannot adopt AGPL terms, this split keeps that path open.

Important clarification:
- AGPL obligations are strongest around the AGPL-covered program itself. This document should not imply that every adjacent or unrelated service in a deployment is automatically subject to AGPL.
- Internal use is often operationally simpler than external SaaS distribution, but enterprise review can still be driven by policy, procurement, or compliance concerns.

### MIT for the Integration Surface
**Target packages:** `packages/agent-skill`, `packages/gateway`, `packages/browser-ui`, `packages/openclaw-plugin`

MIT is a strong fit for libraries, adapters, and embeddable components that should be easy to adopt in many environments.

Why this is attractive:
1. **Low-friction adoption:** Developers can integrate the SDKs and plugins into proprietary or open systems with minimal licensing overhead.
2. **Portable client components:** `browser-ui` can be embedded in other products without forcing the surrounding application into a copyleft posture.
3. **Flexible middleware use:** `gateway` and `openclaw-plugin` are more likely to be adopted if they can fit cleanly into existing internal stacks.

Important clarification:
- The MIT packages should remain clearly separable works. This proposal assumes they are integration layers around the protocol and service, not repackaged copies of AGPL-covered application code.

---

## Boundary Policy for Mixed Licensing

The licensing split only remains clean if package boundaries remain clean.

Recommended policy:
1. **MIT packages may talk to AGPL services over APIs and protocols.**
2. **MIT packages should not copy or vendor AGPL source files.**
3. **MIT packages should not import AGPL-only modules as embedded runtime dependencies.**
4. **Shared protocol definitions, schemas, and generated clients should be authored under permissive terms if they are intended to be reused by MIT packages.**
5. **If a package starts embedding AGPL application logic rather than integrating with it, its license should be re-evaluated.**

This policy is more important than the repo layout. A mixed-license monorepo is workable, but only when package boundaries are intentional and documented.

---

## Monorepo vs. Split Repo

### Recommendation
Stay in the monorepo for now.

Why:
1. **Atomic changes:** API, SDK, and dashboard changes can ship in one commit.
2. **Simpler CI/CD:** One workspace, one dependency graph, one release process to manage during the early phases.
3. **Lower maintenance overhead:** Separate repos add versioning, sync, and release complexity before the ecosystem is mature.

### Reasons to Split Later
Consider splitting some MIT packages into their own repositories if:
1. **Enterprise procurement blocks mixed-license repos:** Some customers may refuse to clone a repository that contains AGPL code, even if the package they want is MIT.
2. **Language-specific SDKs mature:** Python, Go, or other SDKs may eventually deserve standalone repos and release pipelines.
3. **Public distribution becomes packaging-heavy:** Separate repos can simplify community onboarding and package-specific issue tracking.

Starting in one repo does not prevent a later split. If needed, packages can be extracted later with preserved history.

---

## Implementation Notes

If this proposal is approved, implementation should include:
1. **Choose exact SPDX identifiers:** For example, decide whether the AGPL packages are `AGPL-3.0-only` or `AGPL-3.0-or-later`.
2. **Add package-level `LICENSE` files:** Each publishable package should clearly declare its governing license.
3. **Update `package.json` metadata:** Add `license` fields and any needed `SEE LICENSE IN` references.
4. **Add a root licensing matrix:** Document which packages are AGPL and which are MIT in one easy-to-find place.
5. **Use SPDX headers selectively:** Add file-level SPDX headers where they improve provenance or reduce ambiguity, without creating unnecessary maintenance burden.
6. **Document contribution terms:** Decide whether a CLA is necessary for dual-licensing goals, or whether a lighter-weight DCO-style process is enough.

---

## Risks and Open Questions

Before final adoption, confirm:
1. **Package boundaries are real:** Especially for `gateway` and `browser-ui`.
2. **Distribution goals are clear:** Are these packages intended to remain private for now, or eventually be published?
3. **Commercial licensing intent is real:** If dual-licensing is a likely business path, contribution terms should be chosen with that in mind.
4. **Customer profile supports the tradeoff:** AGPL can be strategically useful, but it may reduce adoption in some enterprise environments.

---

## Recommended Next Steps

1. **Counsel review:** Validate the proposed split and exact license identifiers.
2. **Boundary review:** Confirm that MIT packages do not embed AGPL implementation code.
3. **Metadata rollout:** Add per-package `LICENSE` files, `package.json` license fields, and a root licensing matrix.
4. **Contribution policy:** Decide between CLA, DCO, or another contribution framework.
5. **Publishing plan:** If MIT packages are meant for external reuse, decide whether they should eventually be published separately from the AGPL applications.

---

## References

- GNU AGPL overview: https://www.gnu.org/licenses/agpl
- GNU AGPL v3 text: https://www.gnu.org/licenses/agpl-3.0.en.html
- GNU GPL/AGPL FAQ: https://www.gnu.org/licenses/gpl-faq.en.html
