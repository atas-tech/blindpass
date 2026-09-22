# Security documentation

The [current threat model](blindpass-threat-model.md) owns the present interpretation of security boundaries and selected source-verified status. It separates existing SPS behavior from the proposed Linux/browser pilot. Its 2026-09-22 update is a documentation/source review, not a fresh penetration test, production-header probe or release audit.

| Reference | Use |
|---|---|
| [Current threat model](blindpass-threat-model.md) | Actual auth/storage behavior, plaintext boundaries, residual risks and proposed fleet threats |
| [Product finding register](../product/Specification.md#repository-findings) | F-1–F-13 with historical provenance and selected current corrections |
| [Pilot security tests](../testing/Linux%20Fleet%20Pilot.md) | Required future OS, browser, deployment and release evidence |
| [Dependency baseline](../product/decisions/0003-dependency-baseline-2026-09.md) | 2026-09-22 `npm audit` snapshot, upgrade tiers and Socket review status; no manifest changed yet |
| Historical audits and threat model | Maintained in the Obsidian vault; they are evidence, not a current open/closed ledger |

Key corrections from source inspection: hosted cookies exist, but both frontends still support `localStorage` body-token paths; verification/reset tokens are hashed with expiry/one-use checks; the implemented HPKE AEAD is ChaCha20-Poly1305; production nginx configuration exists for both frontends but still has permissive connection policies. Historical audit claims to the contrary must not be copied as current state.

Keep a finding's original identifier/date when recording new evidence. Describe whether a result comes from code, tests or a deployed instance. Closing a documentation conflict does not close the underlying security risk or establish a pilot guarantee.
