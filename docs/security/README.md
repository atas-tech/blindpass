# Security documentation

The [current threat model](blindpass-threat-model.md) owns the present interpretation of security boundaries and selected source-verified status. It separates existing SPS behavior from the proposed Linux/browser pilot. Its 2026-09-22 update is a documentation/source review, not a fresh penetration test, production-header probe or release audit.

| Reference | Use |
|---|---|
| [Current threat model](blindpass-threat-model.md) | Actual auth/storage behavior, plaintext boundaries, residual risks and proposed fleet threats |
| [Product finding register](../product/Specification.md#repository-findings) | F-1–F-13 with historical provenance and selected current corrections |
| [Pilot security tests](../testing/Linux%20Fleet%20Pilot.md) | Required future OS, browser, deployment and release evidence |
| [Audit v2, March 24](../archive/security/Security%20Audit%20v2.md) | Original 24 findings and remediation snapshot; not a current open/closed ledger |
| [Audit v1, March 4](../archive/security/Security%20Audit%20v1%20%282026-03-04%29.md) | Earlier baseline |
| [March supplement](../archive/security/security_best_practices_report.md) | Origin-injection and logging history |
| [Earlier threat model](../archive/security/Threat%20Model%202026-03.md) | Original assumptions/ranking for hosted and paid/guest surfaces |

Key corrections from source inspection: hosted cookies exist, but both frontends still support `localStorage` body-token paths; verification/reset tokens are hashed with expiry/one-use checks; the implemented HPKE AEAD is ChaCha20-Poly1305; production nginx configuration exists for both frontends but still has permissive connection policies. Historical audit claims to the contrary must not be copied as current state.

Keep a finding's original identifier/date when recording new evidence. Describe whether a result comes from code, tests or a deployed instance. Closing a documentation conflict does not close the underlying security risk or establish a pilot guarantee.
