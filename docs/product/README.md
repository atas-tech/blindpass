# Product Review Documents

Product, market, and strategy documents. Architecture and phase plans live in [../architecture](../architecture), security analysis in [../security](../security).

## September 2026 Review

A review conducted 2026-09-10 against commit `5b233c3`, revised on 2026-09-12 to include the Linux fleet direction, review corrections, and native/container control-plane deployment requirements.

| Document | Contents |
|---|---|
| [Product Review 2026-09](Product%20Review%202026-09.md) | Linux fleet direction, native/container deployment requirements, competitive landscape, validation gate, pricing hypotheses, and risks |
| [Repo State Findings 2026-09](Repo%20State%20Findings%202026-09.md) | Observed defects in code and live deployment, with file and line references |
| [Roadmap Reset 2026-09](Roadmap%20Reset%202026-09.md) | Proposed scope cut, milestone order, freeze register, success metrics |

**Verdict in one line:** continue with a bounded Omarchy-first Linux fleet pilot that completes an authenticated AI operation and a native service job, using a control plane deployable as either a native service or a container.

**Read first:** [Product Review 2026-09](Product%20Review%202026-09.md), particularly [Linux fleet direction](Product%20Review%202026-09.md#24-linux-fleet-direction) and [native/container deployment](Product%20Review%202026-09.md#25-native-and-container-control-plane-deployment). The [roadmap reset](Roadmap%20Reset%202026-09.md) describes the proposed sequence.

## Native Linux and Fleet Research

- [Native Linux Fleet Research 2026-09](Native%20Linux%20Fleet%20Research%202026-09.md) — operator experience, host brokers, native service credentials, controller packaging, and a two-host pilot.
- [Linux Fleet Research Round 2 2026-09](Linux%20Fleet%20Research%20Round%202%202026-09.md) — **verified** systemd credential socket authentication (including a working forgery), competitive landscape for the fleet direction, Omarchy beachhead assessment, SPIRE reassessment, and corrections to round one.
- [Native Linux Fleet Pilot test plan](../testing/Native%20Linux%20Fleet%20Pilot.md) — proposed E2E, integration, native/container parity, backup/restore, and migration scenarios; not yet implemented or executed.

## Proposal Status

The Linux fleet direction and support for native/container controller deployment are recorded at the user's request. Detailed architecture, milestone sequencing, and commercial packaging remain proposals. These edits establish no new implementation or release readiness. The phase plans in [../architecture](../architecture) remain the record of what was built.

## Verification note

Original market and deployment observations remain dated 2026-09-10. The September 12 revision checked selected protocol, competitor, and Linux integration sources and recorded additional code findings; it did not re-verify every original claim. Deployment-mode support is a product requirement pending implementation and testing.
