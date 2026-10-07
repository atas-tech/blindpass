# Pilot recruitment protocol

**Owner values accepted 2026-10-07 (P08 slice 1); reviewer acceptance, the evidence-store check (G4) and the release gates G1 and G2 are still open. Recruitment has not started and may not start.** The plan
([P08](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/08-pilot-and-retirement.md),
[P08 tests](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/08-pilot-and-retirement.md))
and the [pilot catalog](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/Linux%20Fleet%20Pilot.md)
(R04, O08, C16) own the criteria. This page restates them, proposes the missing values and holds the forms.
Nothing here is a traction figure. On 2026-10-07 the product owner accepted the recommended values below
("follow the recommendation"); a value still marked **OPEN** is not decided. The reviewer's acceptance goes in the
P08 review row.

## Gate: what must be true before the first operator is contacted

| # | Condition | State on 2026-10-07 |
|---|---|---|
| G1 | P07.6 recorded a dated go decision for the exact release candidate, with its evidence matrix and [known limitations](known-limitations.md) | **Not met.** P07 is not accepted, nothing is published, the draft matrix is blocked |
| G2 | An operator can install the controller **and enrol a node and complete a first workload** from published documents alone | **Not met.** [Node package status](../deploy/node-candidate.md): 0.1.0 has no installer and documents no operator path to a first workload. P08-E01 cannot be run without it |
| G3 | The approval-frequency ceiling is accepted (below) | **Accepted by the owner 2026-10-07:** 12 per operator per active day |
| G4 | The evidence store is chosen and verified (below, P08-D1) | **Chosen, not verified.** The store must exist and pass the exposure check before the first contact |
| G5 | Success measures are accepted (below, P08-D4) | **Accepted by the owner 2026-10-07:** the roadmap baseline |
| G6 | Consent text is accepted and its blanks are filled | **Filled with the recommended values below; the reviewer has not accepted it** |
| G7 | A failed required guarantee has not frozen recruitment ([rollback](rollback.md)) | Applies from the go decision on |

The 90-day window starts at pilot publication, not at the first contact. Record recruitment delays instead of
silently moving the start.

## Decisions to accept before recruitment

| ID | Decision | Proposed value | Why it matters |
|---|---|---|---|
| P08-D1 | Where raw observations live | **Accepted:** one encrypted directory (gocryptfs, or an age-encrypted archive) on the product owner's own workstation, outside `~/Projects`, outside the docs vault and outside every synced or backed-up path. Owner: the product owner. Readers: the owner only; anyone added is recorded in the evidence record first. Retention: until 180 days after the go, narrow or stop decision, then deleted. Withdrawal: that operator's raw notes are deleted within 14 days of the request. **Verification before the first contact:** write a generated canary into the store and confirm that `git status` in both repositories, the vault's obsidian-git, every sync client and every backup job never see it | The docs vault is a Git repository that obsidian-git pushes automatically. It is not private, and a pseudonym does not anonymise a transcript |
| P08-D4 | What counts as success | **Accepted:** the roadmap baseline in the table below. The stricter "two repeat operators in week two" and "12 prompts per day" are recorded as targets, not gates; the reviewer still chooses go, narrow or stop from the evidence | Narrow is never assigned mechanically |
| O08 | Approval-frequency ceiling | **Accepted: 12 prompts per operator per active day**, dismissals and overrides counted separately | Exceeding the accepted ceiling fails the usability gate. It is fixed before anyone is observed |
| C16 | Alternative baseline | Each operator also runs one equivalent backup/restore job through a native `LoadCredentialEncrypted=` credstore | The pilot compares against the alternative; delivery alone does not justify the broker |
| — | Incentives | **Accepted: none.** Any incentive added later is disclosed in the summary | Paid or favoured participants bias repeat-use evidence |

## Success measures (P08-D4)

Measured over the first 90 days after publication. These are experiment targets, not traction.

| Measure | Required evidence (roadmap baseline) |
|---|---|
| External setup | At least three deliberately recruited operators attempt installation; record failures and preferred deployment mode |
| Repeat use | At least two repeat real workflows without maintainer intervention |
| Completed work | An authenticated AI task and a native backup/restore job across two hosts |
| Deployment | Passing common and package suites, and migration evidence in both directions |
| Approval fatigue | Prompts per operator per active day, dismissals and overrides, against the accepted ceiling |
| Added value | The credstore baseline (C16) and existing managers compared; which workflow each operator would keep, and why |
| Buyer evidence | Willingness to pay for support or hosting, and whether an existing tool would suffice |

Record the denominator for every figure: operators attempted, completed, repeated. Record assistance separately
(below). A figure without its denominator is not reported.

## Recruiting

Recruit three operators on purpose; downloads and stars are not recruitment. Each operator:

- runs Linux with systemd and has a real, recurring workload that needs a credential (not a demo);
- chooses the native or the Compose profile, and the choice is recorded rather than steered;
- is told what is unfinished before starting (the [known limitations](known-limitations.md) and the status of the
  node package).

Record how each operator was reached and their starting familiarity (never used a credential manager / uses
systemd credentials or an existing manager / runs a secrets service) without names, employers or hostnames in any
file of this repository or the vault. Recruitment through the maintainer's own network biases the result; say so in
the summary.

## Consent

Show this text before any observation. Keep the signed or recorded consent only in the
evidence store (P08-D1).

> We are testing whether BlindPass helps you run real work with fewer exposed credentials. With your agreement we
> will record: your installation attempts, where you got stuck and what help you needed; how many approval prompts
> you received and what you did with them; whether and when you used it again; and your view on alternatives and
> on paying. We will **not** record credentials, secret values, hostnames, addresses or screen contents.
> Raw notes are kept by the BlindPass product owner alone, in an encrypted directory on their own workstation that
> is not synced or backed up, until 180 days after we decide what to do with the pilot, and then deleted. Only a
> summary combining the three operators is published, and you may read and veto the lines about you before it is.
> You can withdraw at any time; we delete your raw notes within 14 days of your request and remove you from any
> unpublished summary. With three operators even a combined summary can be recognised by people who know you; tell
> us which details you want left out.
> Using BlindPass is free during the pilot and there is no payment or other incentive.

## Setup tasks (the same for every operator)

Each task records: outcome (done / done with help / abandoned), elapsed time, every step that needed more than the
published documents, and the version and profile used. A step that needs the maintainer counts as a maintainer
intervention.

| Task | Procedure | Blocked today by |
|---|---|---|
| T1 Install and verify | [Start here](../deploy/README.md), the native or Compose quickstart, then verify the download | G1: nothing is published |
| T2 Enrol a node | Operator procedure for the node package | G2: no documented path in 0.1.0 |
| T3 Register a workload and approve it | Console, exact scope approval | G2 |
| T4 First real browser task through a stock AI client | The P05 workflow | G2, and a stock client with credentials |
| T5 Backup and restore across two hosts | [Compose reference](../deploy/compose-quickstart.md), [native reference](../deploy/native-quickstart.md), [recovery](../deploy/recovery-activation.md) | G2 |
| T6 Upgrade | [Upgrade](../deploy/upgrade.md) | G1 |
| T7 Credstore baseline (C16) | The same backup/restore job with `LoadCredentialEncrypted=` and no broker | None |

## Observation record

One record per operator per week, in the evidence store. Define an **active day** as a calendar day on which the
operator's workload requested at least one approval.

| Field | Value |
|---|---|
| Operator alias, week | |
| Release, profile and client versions | |
| Tasks attempted / completed (T1–T7) | |
| Assistance: none / documentation gap fixed / maintainer intervention (count, what) | |
| Failures and their cause (setup, availability, upgrade, recovery) | |
| Approval prompts, dismissals, overrides, active days | |
| Repeat real workflows (distinct, dated) | |
| Controller availability issues | |
| C16: which workflow they would keep and why | |
| Willingness to pay, and would an existing tool have sufficed | |

**Maintainer intervention** means any help beyond the published documents that changes an outcome, including a
chat answer, a config edit or a restart. A documentation fix made after a question is recorded as the gap it was.
Repeat use counts only when it occurred without intervention.

## What may enter the repository or the vault

Only a reviewed summary that combines operators, written to `docs/release/pilot/summary.md`, and the go, narrow or
stop decision (a new decision record in the vault product decisions directory, linked from repository evidence).
Never: a quote, a transcript, a name, an employer, a hostname, a timestamp precise enough to identify a session,
or a credential, link or token (use generated dummy canaries for any exposure check). Before publishing a summary
line, the operator it concerns has read and approved it. Raw material stays in the evidence store.

## Freeze and stop

A failed required guarantee freezes recruitment until corrective evidence is recorded ([rollback](rollback.md)).
Reassess at 90 days if repeat use is absent despite deliberate recruitment, if approvals exceed the accepted
ceiling, or if operators mainly want existing credential templates. Narrow the supported profile if acceptable
isolation cannot be shown. Pricing is a separate decision; no paid plan, enterprise expansion, OpenClaw migration
(P09) or cross-workload work (P10) follows automatically.
