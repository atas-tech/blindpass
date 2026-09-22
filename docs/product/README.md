# Product roadmap and specification

The September 2026 product reviews and Linux/browser research are consolidated into two canonical documents:

| Document | Purpose |
|---|---|
| [Roadmap](Roadmap.md) | Product outcome, W0–W6 sequence and gates, freeze register, pricing hypotheses, validation and stopping criteria |
| [Specification](Specification.md) | Trust boundaries, host identity, browser session handoff, native service delivery, controller packaging/recovery, repository findings and open decisions |

The [Linux Fleet Pilot and Roadmap Test Plan](../testing/Linux%20Fleet%20Pilot.md) is the single E2E/integration acceptance catalog for both pilot workflows. It retains the original fleet IDs and namespaces browser IDs with `B-`, including explicitly deferred scenarios.

**Status:** Consolidated on 2026-09-22. Linux fleet direction and native/container controller deployment are recorded requirements. Detailed implementation remains proposed; browser session handoff is the proposed W1 operation pending application/integration selection. These documents do not establish implementation, test execution, or release readiness.

The [roadmap consolidation record](Roadmap.md#consolidation-record) identifies the source reviews and evidence dates. The [specification finding register](Specification.md#repository-findings) retains F-1–F-13 and carried audit items. Earlier overlapping product research and the two separate pilot plans have been removed after incorporation.

[Architecture phase plans](../archive/architecture/Implementation%20Plan.md) remain historical implementation records, [security documents](../security) own audit status, and [guides](../guides) describe existing usage. Forward product scope is governed by the roadmap above.
