# Security documentation

The [current threat model](blindpass-threat-model.md) owns the present interpretation of security boundaries and selected source-verified status. It separates behavior implemented in the tree from the proposed Linux/browser pilot; findings that pointed at the SPS or dashboard, removed on 2026-10-07, keep their record and are marked as removed. Its 2026-09-22 update is a documentation/source review, not a fresh penetration test, production-header probe or release audit.

| Reference | Use |
|---|---|
| [Current threat model](blindpass-threat-model.md) | Actual auth/storage behavior, plaintext boundaries, residual risks and proposed fleet threats |
| [Finding disposition](finding-disposition.md) | P07.1: F-1–F-13 and TM-001–TM-014 mapped to current code paths, regression tests and status, with new boundary findings (N-01–N-06) and missing-test gaps |
| [Dependency evidence 2026-10-06](dependency-evidence-2026-10-06.md) | P07-D5: Socket scans of the actual Cargo/npm manifests and lockfiles (the tree before the 2026-10-07 removal of the legacy stack) with coverage limits, blocked tooling and packages, escalations, uncovered components. License reconciliation is in [license inventory](../release/license-inventory.md); SBOMs in [docs/release/sbom](../release/sbom/README.md) |
| [Product finding register](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md#repository-findings) | F-1–F-13 with historical provenance and selected current corrections |
| [Pilot security tests](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md) | Required future OS, browser, deployment and release evidence |
| [Dependency baseline](../product/decisions/0003-dependency-baseline-2026-09.md) | 2026-09-22 `npm audit` snapshot, upgrade tiers and Socket review status; existing npm manifests remain unchanged. The Cargo controller and CLI dependency set is reviewed in [decision 0004](../product/decisions/0004-controller-dependency-review-2026-09.md); `blindpass-core` has no crate dependencies |
| Historical audits and threat model | Maintained in the Obsidian vault; they are evidence, not a current open/closed ledger |

Key correction from source inspection that still applies: the implemented HPKE AEAD is ChaCha20-Poly1305. The 2026-09-22 corrections about hosted refresh cookies, `localStorage` body tokens, email verification/reset tokens, the SPS request-log serializer and the dashboard nginx configuration described the SPS and dashboard; those packages were removed on 2026-10-07 (git history before the removal commit), and the rows that pointed at them are marked in the [threat model](blindpass-threat-model.md) and the [finding disposition](finding-disposition.md). Historical audit claims to the contrary must not be copied as current state. Log and artifact exposure on the current path is TM-004 there; reverse proxies and external log collectors require separate configuration review.

Keep a finding's original identifier/date when recording new evidence. Describe whether a result comes from code, tests or a deployed instance. Closing a documentation conflict does not close the underlying security risk or establish a pilot guarantee.
