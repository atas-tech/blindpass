# Security documentation

The [current threat model](blindpass-threat-model.md) owns the present interpretation of security boundaries and selected source-verified status. It separates existing SPS behavior from the proposed Linux/browser pilot. Its 2026-09-22 update is a documentation/source review, not a fresh penetration test, production-header probe or release audit.

| Reference | Use |
|---|---|
| [Current threat model](blindpass-threat-model.md) | Actual auth/storage behavior, plaintext boundaries, residual risks and proposed fleet threats |
| [Product finding register](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md#repository-findings) | F-1–F-13 with historical provenance and selected current corrections |
| [Pilot security tests](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md) | Required future OS, browser, deployment and release evidence |
| [Dependency baseline](../product/decisions/0003-dependency-baseline-2026-09.md) | 2026-09-22 `npm audit` snapshot, upgrade tiers and Socket review status; existing npm manifests remain unchanged. The Cargo controller and CLI dependency set is reviewed in [decision 0004](../product/decisions/0004-controller-dependency-review-2026-09.md); `blindpass-core` has no crate dependencies |
| Historical audits and threat model | Maintained in the Obsidian vault; they are evidence, not a current open/closed ledger |

Key corrections from source inspection: hosted cookies exist, but both frontends still support `localStorage` body-token paths; verification/reset tokens are hashed with expiry/one-use checks; the implemented HPKE AEAD is ChaCha20-Poly1305; production nginx configuration exists for both frontends but still has permissive connection policies. Historical audit claims to the contrary must not be copied as current state.

The SPS Fastify request serializer now records the HTTP method and route template, omitting raw URLs so signed browser-link query values and token-bearing path segments do not appear in ordinary request logs. The browser E2E recorder also omits generated API keys and signed URLs. This is a source/test change; reverse proxies and external log collectors require separate configuration review.

Keep a finding's original identifier/date when recording new evidence. Describe whether a result comes from code, tests or a deployed instance. Closing a documentation conflict does not close the underlying security risk or establish a pilot guarantee.
