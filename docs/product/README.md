# Product roadmap and specification

The September 2026 product reviews and Linux/browser research are consolidated into two canonical documents:

| Document | Purpose |
|---|---|
| [Roadmap](Roadmap.md) | Product outcome, W0–W6 sequence and gates, freeze register, pricing hypotheses, validation and stopping criteria |
| [Specification](Specification.md) | Trust boundaries, host identity, browser session handoff, native service delivery, controller packaging/recovery, repository findings and open decisions |
| Implementation phases | P00–P10 review drafts are maintained in the Obsidian vault: work packages, API/product transition, component targets, dependencies, rollback and paired acceptance plans |

Start implementation review with the phase index in the Obsidian vault. P00–P08 take the existing product through baseline, broker proof, Rust API migration, fleet control, UI/UX, completed workflows, deployment, release and pilot/retirement. P09/P10 remain deferred W4/W6 expansions. Each phase has a corresponding integration/E2E scenario document there.

The dashboard and secret-input redesign proposals and their UI acceptance plans are maintained in the Obsidian vault. They preserve the roadmap's product scope and do not establish implementation.

[Decision records](decisions/README.md) fix choices the roadmap and specification left open: the rebuilt dashboard stack (0001), Rust for the host broker and new controller behind the existing machine-client contract (0002), and the September 2026 dependency baseline (0003). They record direction and dated evidence, not implementation.

The [Linux Fleet Pilot and Roadmap Test Plan](../testing/Linux%20Fleet%20Pilot.md) is the single E2E/integration acceptance catalog for both pilot workflows. It retains the original fleet IDs and namespaces browser IDs with `B-`, including explicitly deferred scenarios.

**Status:** Consolidated and expanded into implementation review drafts on 2026-09-22. Linux fleet direction and native/container controller deployment are recorded requirements. Phase plans remain proposed; browser session handoff is the proposed W1 operation pending application/integration selection. These documents do not establish implementation, test execution, or release readiness.

The [roadmap consolidation record](Roadmap.md#consolidation-record) identifies the source reviews and evidence dates. The [specification finding register](Specification.md#repository-findings) retains F-1–F-13 and carried audit items. Earlier overlapping product research and the two separate pilot plans have been removed after incorporation.

Historical architecture phase plans remain in the Obsidian vault, security documents own audit status, and guides describe existing usage. Forward product scope is governed by the roadmap above.
