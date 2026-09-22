# Architecture Review: Phase Split & Guest x402 Flows

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../README.md) and [roadmap](../product/Roadmap.md).

**Commit**: `5c7f5da` — `docs(architecture): split hosted phases and refine guest x402 flows`

## Summary of Changes

The commit splits what was a monolithic **Phase 3B** (9 milestones) into four focused phases:

| Phase | Scope | Status |
|-------|-------|--------|
| **3B** | Operator Dashboard & Admin UX (5 milestones) | ✅ Complete |
| **3C** | Paid Guest Secret Exchange | 📝 Planned |
| **3D** | Autonomous Payments & Crypto Billing | 🚧 In Progress (M1 landed) |
| **3E** | Hosted Hardening, Ecosystem & Launch | 📝 Planned |

Also adds [policy.md](../guides/policy.md) (workspace-admin policy guide), and new test plans for 3C/3D/3E.

Follow-on planning updates now also add [Hosted Workspace Policy Foundation](architecture/Hosted%20Workspace%20Policy%20Foundation.md) plus its dedicated test plan so the workspace-scoped PostgreSQL policy engine is no longer buried inside Phase 3E.

This review was validated against the current repository state, not just the docs diff. A few of the original concerns are real implementation questions; a few others needed tightening so they point at the actual risk.

---

## Discussion Points

### 1. Phase 3C ↔ 3D Dependency Direction

Phase 3C lists Phase 3D payment rail abstractions as a **prerequisite**, while Phase 3D says guest flows will reuse the same x402 rail. That looks less like a true circular dependency and more like a sequencing / interface-contract question:

- 3D M1 already establishes the verify / settle / idempotency foundation for enrolled agents
- 3C still needs its own guest-scoped quota, ledger, abuse controls, and intent lifecycle
- the unresolved part is whether the shared payment provider contract is stable enough for 3C to build on now

> [!IMPORTANT]
> **Question**: Is 3C Milestone 3 allowed to proceed once the shared x402 provider interface is frozen, or should it wait until 3D M1 is explicitly hardened for reuse outside the enrolled-agent path?

### 2. Guest Identity: New Actor Type vs. Extension

Phase 3C introduces `guest_agent` and `guest_human` as first-class actor types, explicitly avoiding reuse of `enrolled_agents`. This is a clean design choice, but has ripple effects:

- **Audit log schema and APIs**: the current implementation still hard-codes `actor_type` to `user | agent | system` in migrations, service types, route schemas, and dashboard page types
- **Policy engine**: the current `ExchangePolicyEngine` is built around enrolled agent IDs and ring parsing; guest actors do not naturally fit that model
- **Dashboard and analytics**: audit filters, approval surfaces, badges, and aggregate reporting all need guest-actor awareness

> [!IMPORTANT]
> This is not just a documentation note. It is a real migration and code sweep across audit persistence, route validation, UI typing, and any reporting logic that currently assumes the actor enum is closed.

Current recommendation:

- keep **Enrolled Agents** as a dedicated admin surface for managed workspace agents only
- add separate guest-focused control-plane pages such as **Public Offers** and **Guest Intents**
- keep shared operational views such as audit, approvals, and analytics guest-aware via a `Type` badge / filter rather than pretending guest traffic is the same thing as enrolled-agent traffic

### 3. Settled Policy Snapshot (3C §3A) — Scope Creep Risk

The "settled policy snapshot" concept is elegant, but it is probably the single most expensive design choice in 3C.

Today the enrolled-agent exchange flow re-evaluates **live policy** during later lifecycle steps and rejects if the policy hash changed. Phase 3C proposes the opposite behavior for paid guest intents:

- persist a settled allow / approval / secret-binding snapshot per paid intent
- authorize later submit / retrieve steps against that settled snapshot
- still allow platform-global overrides or explicit revocation to break the flow

> [!WARNING]
> This is not a small extension of the existing policy model. It creates a second authorization model beside the current live-policy re-evaluation path.

Related: if the product keeps settled snapshots, operator revocation of a specific paid guest intent stops being optional. That route is now worth treating as part of the core 3C control plane, not a follow-up support feature.

Current recommendation:

- define `POST /api/v2/public/intents/:id/revoke` now
- treat **offer revoke** and **intent revoke** as separate controls
- make intent revoke a prominent action in guest-intent drill-downs and the relevant Approvals / Audit workflow, not just a hidden support tool

### 4. Workspace Policy Management And Env→DB Migration

Phase 3C guest offers rely on `secret_name` or `secret_alias` binding, but the hosted runtime still resolves the secret registry and exchange policy from process-global env vars today unless the workspace-scoped PostgreSQL policy foundation lands first.

This raises two linked questions that should be resolved together:

- Is 3E M1 actually a prerequisite for 3C in hosted mode?
- If not, what is the migration / fallback story once hosted workspaces move from env-backed policy to DB-backed policy?

Current recommendation:

- make the **workspace-scoped PostgreSQL policy engine** a hard prerequisite for Phase 3C in hosted mode
- pull that policy slice forward as shared foundation work rather than forcing all of Phase 3E to move first
- avoid building guest-intent logic on top of the temporary env-backed hosted policy path unless the team is willing to carry that intermediate state for a while

This direction is now reflected in the roadmap via the standalone **Hosted Workspace Policy Foundation** milestone and test plan.

The follow-on planning update also chooses a concrete hosted rollout strategy: **auto-seed existing workspaces from the current env-backed hosted policy, then switch hosted policy reads to PostgreSQL without a permanent runtime fallback chain**.

### 5. `fulfill_url` Authentication Model

The capability split (`guest_access_token` vs `fulfill_url`) is strong, but the document still needs an explicit product decision about the human fulfiller:

- **Unauthenticated `fulfill_url`**: anyone with the URL can submit. Simpler, works for external humans outside the workspace.
- **Authenticated `fulfill_url`**: requires the human to be logged into the workspace before the submit page renders. Prevents URL-forwarding attacks but limits who can fulfill.

The current browser submit flow is capability-based, so requiring workspace login is a meaningful product and implementation fork, not just a small auth toggle.

Current recommendation:

- if the intended fulfiller is a **workspace human** responding on behalf of the workspace, require workspace authentication before rendering or submitting the fulfill flow
- treat the signed `fulfill_url` as the request locator / capability for the specific intent, not the only proof that the caller is allowed to act
- if the product later needs an **external human fulfiller** variant, model that explicitly as a separate flow rather than overloading the same hosted workspace-human path

This direction is now reflected in the Phase 3C architecture and test plan: the hosted human fulfill flow requires an active same-workspace login.

### 6. Offer Token Security Model

Phase 3C stores only a **hash** of the offer token (`offer_token_hash`). This is good practice, but:

- the document does not specify the hashing algorithm or whether a server-side pepper is used
- the document implies high-entropy capability URLs, but it should state that clearly
- there is no mention of **offer token rotation** or regeneration for an existing offer

Even if plain SHA-256 lookup is acceptable for long random tokens, the doc should state that the tokens are server-generated high-entropy secrets rather than shorter operator-chosen values.

### 7. Free Quota Race Condition (3D M1)

This point needed tightening after checking the implementation.

The current code already locks the existing `workspace_exchange_usage` row before incrementing it, so the main race is not "9/10 free usage with no lock". The more precise concurrency edge is the **start of a new month**, where the row does not yet exist and parallel inserts could race before the lockable row exists.

> [!NOTE]
> The review should point at the month-boundary insert path, not the already-locked steady-state increment path.

### 8. `quota_then_x402` — Two Quota Systems

The `payment_policy=quota_then_x402` model creates a second quota tracking system alongside the enrolled-agent `workspace_exchange_usage`:

| Quota System | Scope | Tracked In |
|---|---|---|
| Enrolled-agent free cap | Per workspace per month | `workspace_exchange_usage` |
| Guest offer free uses | Per offer (lifetime) | `public_exchange_offers.uses_consumed` vs `included_free_uses` |

These are semantically different, which is fine, but operators will likely need clearer wording in docs and dashboard UI:

- workspace monthly free cap for enrolled agents
- included free uses on a specific guest offer

Otherwise "free tier" will mean two different things depending on the surface.

### 9. x402 Signer Boundary (3D M2)

Phase 3D M2 defines a clear signer-isolation boundary — the runtime calls `signPayment(quote)` without seeing the private key. The recommended implementation order is:

1. Remote signer / KMS / HSM
2. Local encrypted keystore
3. Dev-only in-process key (with zeroing)

> [!NOTE]
> This is well-designed. The main question is release sequencing: if the provider contract is stable, guest x402 work probably should not wait on a perfect production signer service choice. That feels more like a production-hardening gate than a design blocker.

### 10. Hosted Crypto Billing (3D M3) — First Provider

This is now resolved in the roadmap docs: **Coinbase Payment Links** is the committed first shipped hosted crypto billing provider for Phase 3D Milestone 3, while the broader billing model stays extensible for future providers.

### 11. Phase 3E Launch Ordering

Phase 3E places **hosted deployment + domain cutover** as the **last milestone** (M3). This means:

- All SDKs, docs, and community guides (M2) are written against local dev
- Production URLs aren't live until everything else is done

This is safe but means there's no early production smoke-testing. The existing Unraid deployment doc changes suggest some infra is already running — could a "soft launch" milestone exist earlier?

### 12. `httpOnly` Cookie Migration

Both Phase 3B and 3E carried a note to revisit `httpOnly` cookies before wider go-live. The follow-on planning update now does the right thing: it promotes hosted cookie/session hardening into an explicit **Phase 3E Milestone 1** deliverable instead of leaving it as a late checklist item.

That is the correct posture. The current dashboard auth model still stores the refresh token in `localStorage`, so migrating to `Secure` + `httpOnly` cookies should be treated as a **blocker** for 3E M3 / pre-GA sign-off.

---

## Corrections / Clarifications

- The earlier draft of this review overstated the free-cap race. The existing implementation already locks the steady-state monthly usage row; the remaining concern is the month-boundary row-creation path.
- The follow-on planning update now adds `POST /api/v2/public/intents/:id/revoke` to the Phase 3C endpoint sketch, which matches the settled-snapshot recommendation.
- The follow-on planning update also pulls workspace policy out into the standalone **Hosted Workspace Policy Foundation** milestone rather than leaving it buried inside Phase 3E.
- **Phase 3A status** in the Implementation Plan table still shows "🚧 In Progress", while the Phase 3A doc says the six core milestones are complete and follow-on work moved into later phases. That looks like a wording mismatch rather than an architectural contradiction.
- The Unraid deployment doc diff renames `Phase 3B` references to `Phase 3D/3E` — changes look correct
- The new [policy.md](../guides/policy.md) guide is clear and well-structured; the hosted vs. self-hosted distinction is cleanly presented
- Test plans for 3C/3D/3E are thorough and follow the established pattern
