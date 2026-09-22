# Phase 3C: Paid Guest Secret Exchange Test Plan

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This phase validates the public, one-time paid secret exchange path for unregistered external requesters. It covers both:

- **Guest agent -> Human** delivery using the existing browser submit path
- **Guest -> Agent** delivery using the existing exchange contract once production A2A transport is ready

The test plan is intentionally separated from Phase 3D because the enrolled-agent x402 overage flow is a different trust and billing model.

## Preconditions

- Phase 3A hosted platform is working locally with PostgreSQL and Redis
- The hosted workspace policy foundation is available locally so guest offers resolve against workspace-scoped PostgreSQL policy
- Phase 3D enrolled-agent x402 flow is available as the provider/client baseline when x402 is the chosen payment rail
- Browser UI is available for human-submit scenarios
- Production-style guest offer tokens are generated from the server, not fixtures hand-built in the test body

## Milestone 1: Offer Lifecycle And Guest Intent Core

- [x] **Integration 901: Admin creates a human-delivery public offer**
  - [ ] Log in as `workspace_admin`
  - [ ] Call `POST /api/v2/public/offers` with `delivery_mode=human`, `payment_policy=quota_then_x402`, `included_free_uses=1`, and `price_usd_cents=5`
  - [ ] Assert the response returns the offer record plus a one-time plaintext offer token
  - [ ] Assert only the token hash is stored durably

- [x] **Integration 902: Operator can create and revoke an offer**
  - [ ] Log in as `workspace_operator`
  - [ ] Create an offer successfully
  - [ ] Revoke it via `POST /api/v2/public/offers/:id/revoke`
  - [ ] Assert later guest intent creation fails with `410` or the chosen revoked-offer response

- [x] **Integration 903: Viewer is denied offer management**
  - [ ] Log in as `workspace_viewer`
  - [ ] Attempt create/list/revoke calls
  - [ ] Assert `403 Forbidden`

- [x] **Integration 904: Offer expiry is enforced before payment**
  - [ ] Create an offer with a short TTL
  - [ ] Wait until expiry
  - [ ] Attempt guest intent creation
  - [ ] Assert SPS rejects before returning a payment challenge

- [x] **Integration 905: Guest intent status is minimally revealing**
  - [ ] Create a valid offer
  - [ ] Start an intent and capture its public status handle
  - [ ] Query status as an unauthenticated caller
  - [ ] Assert the response reveals only coarse lifecycle state and no workspace/member/internal secret identifiers

- [x] **Integration 906: One active unpaid intent per guest subject is enforced**
  - [ ] Start an unpaid guest intent from one IP / external subject
  - [ ] Attempt to create a second unpaid intent against the same offer before the first expires
  - [ ] Assert the server rejects or resumes the existing intent instead of creating a second parallel record

- [x] **Integration 906B: `quota_then_x402` switches from free activation to paid activation**
  - [ ] Create a human-delivery offer with `payment_policy=quota_then_x402` and `included_free_uses=1`
  - [ ] Complete the first allowed guest intent and assert no `402` challenge is returned
  - [ ] Start a second guest intent against the same offer
  - [ ] Assert SPS now returns `402 Payment Required` so the guest agent can continue per request via x402

## Milestone 2: Approval Before Payment

- [x] **Integration 907: Approval-gated intent does not return a payable x402 challenge until approved**
  - [ ] Create an offer with `require_approval=true`
  - [ ] Start a guest intent
  - [ ] Assert the response is `pending_approval`
  - [ ] Assert no payment record is created and no `PAYMENT-REQUIRED` header is returned

- [x] **Integration 908: Approved intent becomes payable**
  - [ ] Approve the pending intent as `workspace_operator`
  - [ ] Retry or resume the same intent
  - [ ] Assert SPS now returns `402 Payment Required`
  - [ ] Use the dedicated guest-intent approve route rather than the enrolled-agent exchange approval route

- [x] **Integration 909: Rejected intent never becomes payable**
  - [ ] Reject a pending intent
  - [ ] Retry or resume from the guest side
  - [ ] Assert SPS returns the rejected state and never returns a payment challenge

- [x] **E2E 910: Approvals inbox surfaces guest intents correctly**
  - [ ] Create a guest intent requiring approval
  - [ ] Open the dashboard approvals page
  - [ ] Assert the card or dedicated guest-intent view distinguishes guest actors from enrolled agents
  - [ ] Approve and reject from the UI in separate runs

## Milestone 3: Guest x402 Payment

- [x] **Integration 911: Allowed guest intent returns `402 Payment Required`**
  - [ ] Create a direct-allow offer
  - [ ] Start a guest intent as a machine requester
  - [ ] Assert the response is `402`
  - [ ] Assert the quote includes the configured USD cents, `exact` scheme, and the expected network metadata

- [x] **Integration 912: Valid payment settles exactly once**
  - [ ] Retry the same intent with a valid `PAYMENT-SIGNATURE` and `payment-identifier`
  - [ ] Assert SPS verifies and settles payment
  - [ ] Assert exactly one guest payment ledger row is marked `settled`
  - [ ] Assert the request/exchange resource is created only after settlement

- [x] **Integration 913: Idempotent retry returns cached success**
  - [ ] Repeat the same successful paid request with the same `payment-identifier`
  - [ ] Assert SPS returns the cached success result without charging twice

- [x] **Integration 914: Payment identifier reuse with different body is rejected**
  - [ ] Submit a successful paid request
  - [ ] Retry with the same `payment-identifier` and a different public key or purpose
  - [ ] Assert `409`

- [x] **Integration 915: Failed payment does not create a secret request or exchange**
  - [ ] Force facilitator verify or settle failure
  - [ ] Assert SPS records the payment as failed
  - [ ] Assert no downstream request/exchange record is created

- [x] **Integration 916: Expired quote is rejected**
  - [ ] Start an intent and let the quote expire
  - [ ] Retry with a stale payment
  - [ ] Assert SPS fails closed without creating the paid resource

## Milestone 4: Guest Agent -> Human Delivery

- [x] **E2E 917: Paid guest human-delivery intent produces a browser secret URL**
  - [ ] Start a direct-allow guest-agent intent in `delivery_mode=human`
  - [ ] Complete payment
  - [ ] Assert SPS returns `guest_access_token`, `intent_id`, `request_id`, and `fulfill_url`
  - [ ] Assert the guest response does not expose a general-purpose submit token beyond the scoped `fulfill_url`

- [x] **E2E 918: Human fulfills and guest retrieves exactly once**
  - [ ] Have the guest agent forward only the returned `fulfill_url` to the human
  - [ ] Open the returned `fulfill_url` while logged out
  - [ ] Assert the hosted flow requires workspace authentication before rendering submit controls
  - [ ] Sign in as a member of the target workspace and return to the same fulfill flow
  - [ ] Verify the page shows immutable SPS-controlled request details such as requester label, purpose, and expiry
  - [ ] Submit ciphertext through the browser UI
  - [ ] Poll with the guest token until `submitted`
  - [ ] Retrieve successfully once
  - [ ] Attempt a second retrieval and assert not available

- [x] **Integration 918B: Wrong-workspace or non-member user cannot consume the fulfill flow**
  - [ ] Create a paid human-delivery guest request
  - [ ] Open the `fulfill_url` as a user outside the target workspace or without a valid hosted session
  - [ ] Assert metadata display and submit are denied

- [x] **Integration 919: Wrong guest token cannot retrieve**
  - [ ] Create and fulfill a paid guest request
  - [ ] Attempt retrieval with a token minted for a different guest intent
  - [ ] Assert denial without leaking whether the request exists

- [x] **Integration 920: Revoked guest intent cannot be fulfilled or retrieved**
  - [ ] Create a paid guest request
  - [ ] Revoke it via `POST /api/v2/public/intents/:id/revoke` before human submit
  - [ ] Assert browser submit and guest retrieve both fail closed

- [x] **Integration 921: Guest request audit records use guest actor metadata without secret leakage**
  - [ ] Complete a human-delivery guest request
  - [ ] Query audit
  - [ ] Assert the actor is marked as a guest actor and no plaintext secret values, ciphertext, raw tokens, or payment signatures are present

## Milestone 5: Guest -> Agent Delivery

- [x] **Integration 922: Paid guest agent-delivery intent creates an exchange**
  - [ ] Create an offer with `delivery_mode=agent` and a pinned `secret_name`
  - [ ] Complete approval and payment
  - [ ] Assert SPS returns `guest_access_token`, `exchange_id`, and the expected fulfillment delivery reference

- [x] **Integration 923: Wrong fulfiller agent is denied**
  - [ ] Create an offer that pins `allowed_fulfiller_id`
  - [ ] Let a different workspace agent attempt fulfillment
  - [ ] Assert the fulfill call fails without changing exchange state

- [x] **Integration 924: Guest requester can poll and retrieve through the exchange lifecycle**
  - [ ] Complete a guest-paid exchange end-to-end through the runtime path
  - [ ] Assert status progresses `pending -> reserved -> submitted -> retrieved`
  - [ ] Assert retrieval is one-time

- [x] **Integration 925: Approval-gated guest exchange becomes payable only after approval**
  - [ ] Create a guest exchange offer requiring approval
  - [ ] Assert the intent stays non-payable until approved
  - [ ] Approve, pay, and complete the exchange successfully

- [x] **Integration 926: Agent-transport outage does not burn a retrievable secret**
  - [ ] Force the runtime delivery path to fail after payment but before fulfillment
  - [ ] Assert SPS does not mark the exchange fulfilled
  - [ ] Assert the guest can see a recoverable failure state and the workspace can retry or revoke safely

## Milestone 6: Abuse Controls And Operations

- [x] **Integration 927: Public intent creation is rate-limited by IP**
  - [ ] Repeatedly create intents from one IP until the threshold is exceeded
  - [ ] Assert SPS throttles only the offending IP and records the abuse signal

- [x] **Integration 928: Offer-level throttling isolates one abused offer from others**
  - [ ] Hammer one offer token
  - [ ] Assert a second healthy offer in the same workspace still works

- [x] **Integration 929: Expired unpaid intents are cleaned up**
  - [ ] Create unpaid intents and allow them to expire
  - [ ] Run the cleanup path
  - [ ] Assert they cannot be resumed and do not count as active intents anymore

- [x] **Integration 930: Expired paid-but-unfulfilled intents fail closed**
  - [ ] Complete payment
  - [ ] Let the guest requester token expire before fulfillment/retrieval
  - [ ] Assert retrieve fails and the workspace sees the expired state for support handling

- [x] **E2E 931: Dashboard shows guest offer and intent operations without exposing secret payloads**
  - [ ] Open the Public Offers page
  - [ ] Open a guest intent drill-down
  - [ ] Assert operators can inspect lifecycle, payment state, and failure reasons
  - [ ] Assert no secret plaintext, ciphertext, raw request URLs, or guest token values are displayed

## Exit Criteria

- A guest agent can complete a paid one-time secret flow with a human fulfiller without an enrolled-agent record
- Approval-gated requests do not charge until approved
- Guest payment retries are idempotent
- `quota_then_x402` allows request continuation after free quota exhaustion
- Human and agent delivery modes both preserve one-time retrieval ownership
- Hosted human fulfill requires an active same-workspace login; leaked `fulfill_url` alone is insufficient
- Public abuse controls are enforced independently from enrolled-agent quotas
- Audit and dashboard operations make guest traffic supportable without exposing secrets
