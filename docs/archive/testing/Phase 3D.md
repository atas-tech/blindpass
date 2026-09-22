# Phase 3D Test Plan: Autonomous Payments & Crypto Billing

> Historical record, archived during the 2026-09-22 documentation alignment. Dates, checkboxes, commands, and proposed decisions below describe their original review period; they do not establish current support or authorize new work. See the [current documentation](../../README.md) and [roadmap](../../product/Roadmap.md).

This document defines the End-to-End (E2E), integration, and operational verification scenarios for the payments roadmap split out of Phase 3B.

## Scope

Phase 3D covers:

- enrolled-agent x402 overage payments
- real Node-runtime x402 payer support
- hosted crypto billing checkout for fixed-term workspace plans

For Milestone 3, the test plan intentionally assumes **Coinbase Payment Links** as the first shipped hosted crypto billing provider. The broader billing model may remain extensible, but these rollout scenarios are intentionally Coinbase-specific.

> [!NOTE]
> Public paid guest requester flows are tracked separately in `docs/testing/Phase 3C.md`.

## Milestone 1: Enrolled-Agent x402 Payments

- [ ] **E2E: x402 Payment Flow (Playwright)**
  - [ ] **Scenario 601: Free-tier workspace hits 402 after monthly free cap**
    - [ ] Seed a free-tier workspace that has already consumed its 10 free exchange requests for the current UTC month.
    - [ ] Have an agent call `POST /api/v2/secret/exchange/request`.
    - [ ] Assert the response is `402 Payment Required` and contains the `PAYMENT-REQUIRED` header.
    - [ ] Assert the header payload uses network `eip155:84532`, quotes `$0.05` / `0.05 USDC`, and includes the internal USDC quote metadata.
  - [ ] **Scenario 602: Paid-tier agent bypasses payment gate**
    - [ ] Seed a standard-tier workspace (subscription-backed via Stripe).
    - [ ] Have an agent call `POST /api/v2/secret/exchange/request`.
    - [ ] Assert the response is `200 OK` (or the expected success response) and the exchange request is created without an x402 payment prompt.
  - [ ] **Scenario 603: Agent rejects payment due to budget limits**
    - [ ] Configure an enrolled agent with a $0.04 USD monthly budget.
    - [ ] Send a `402 Payment Required` requesting `$0.05` / `0.05 USDC`.
    - [ ] Assert the agent SDK rejects the payment locally before attempting to sign or broadcast.
  - [ ] **Scenario 604: Paid request is denied by default without an allowance**
    - [ ] Seed a free-tier workspace beyond the monthly free cap.
    - [ ] Do not create an `agent_allowances` row for the requester agent.
    - [ ] Have the agent retry with a valid x402 payment.
    - [ ] Assert SPS denies the request and records an `x402_budget_denied` audit event.
  - [ ] **Scenario 605: Successful payment verification and settlement**
    - [ ] Intercept the `verify` and `settle` calls to the mock Facilitator client.
    - [ ] Have the agent submit a valid `PAYMENT-SIGNATURE` header with a `payment-identifier`.
    - [ ] Assert the server locks the agent allowance row, lazily resets it if the month rolled over, and atomically reserves the quoted USD amount.
    - [ ] Assert the server calls `verifyPayment` and then `settlePayment` on the `X402Provider`.
    - [ ] Assert the exchange resource is only successfully created after successful settlement.
    - [ ] Assert the `x402_transactions` table records the transaction (including `payment_id`, `quoted_amount_cents`, `quoted_currency`, `quoted_asset_symbol`, and `network_id`).
  - [ ] **Scenario 606: Concurrent execution is strictly serialized**
    - [ ] Seed a free-tier workspace that has exhausted its monthly free cap.
    - [ ] Have an agent start a valid x402 payment flow.
    - [ ] Before the first settlement completes, simulate a second simultaneous `POST /api/v2/secret/exchange/request` with a valid `PAYMENT-SIGNATURE` for the same agent.
    - [ ] Assert the second request is rejected with `409 payment_in_progress`.
    - [ ] Let the first settlement complete and verify the state is clean for subsequent requests.
  - [ ] **Scenario 607: Idempotent retry reuses the prior successful result**
    - [ ] Seed a free-tier workspace beyond the monthly free cap and configure a valid allowance.
    - [ ] Submit a paid request with a unique `payment-identifier` and let it settle successfully.
    - [ ] Retry the same logical request with the same `payment-identifier`.
    - [ ] Assert SPS returns the cached success response without charging twice.
    - [ ] Retry with the same `payment-identifier` but a different request body.
    - [ ] Assert SPS rejects the request with `409`.

## Milestone 2: Real Agent-Paid x402 (Node Runtime)

- [ ] **Implementation: official x402 contract and Node payer**
  - [x] Replace the mock-only facilitator payload/response contract with the official x402 buyer/seller contract in SPS.
  - [x] Keep the existing allowance reservation, ledger write, idempotency, and exchange creation sequencing around the real x402 verification and settlement calls.
  - [x] Add a Node-based x402 payment provider in `packages/agent-skill` so agents can pay directly without any browser wallet flow.
  - [x] Restrict the first real-money implementation to `exact` scheme on Base Sepolia (`eip155:84532`) and fail closed on unsupported schemes or networks.
  - [ ] Add runtime configuration for the agent payer wallet, facilitator base URL, local spend limit, and network selection.
  - [x] Wire `x402PaymentProvider` and `x402BudgetProvider` through the real OpenClaw / runtime bridge path instead of only the demo script.
  - [x] Validate quote expiry before settlement and assert facilitator verification output still matches the quoted network / scheme before creating the exchange resource.
  - [ ] Expand x402 ledger and logs as needed to capture payer address, facilitator error metadata, and the final transaction hash for support and reconciliation.

> [!NOTE]
> Implementation snapshot as of `2026-03-24`: the Node runtime now emits the official x402 v2 `PAYMENT-SIGNATURE` contract from `packages/agent-skill`, SPS verifies/settles against the official v2 payload shape, and the OpenClaw bridge can source payer config from runtime env vars for Base Sepolia exact payments. Remaining Milestone 2 work is real-chain smoke verification, broader runtime config hardening, and support-grade ledger expansion.

- [ ] **Integration: real Base Sepolia payment smoke path**
  - [ ] Provision a dedicated test agent wallet with Base Sepolia ETH for gas and testnet USDC for payment.
  - [ ] Configure SPS to use a real facilitator endpoint and a test treasury `payTo` address for Base Sepolia.
  - [ ] Exhaust the workspace free exchange cap and configure an explicit x402 allowance for the requester agent.
  - [ ] Have the agent request `POST /api/v2/secret/exchange/request` through the actual runtime path with no mocked `payment-signature`.
  - [ ] Assert the agent creates a real x402 payment, SPS verifies it, SPS settles it, and the exchange request is created only after successful settlement.
  - [ ] Assert the response includes a real transaction hash and the `x402_transactions` row is `settled` with Base Sepolia network metadata.
  - [ ] Assert the allowance balance is decremented exactly once and the same `payment-identifier` still behaves idempotently on retry.

- [ ] **Integration: real payment failure modes**
  - [ ] Configure the agent local x402 budget below the quoted amount and assert the SDK rejects the payment before signing or broadcast.
  - [ ] Configure an unsupported scheme or network in the `PAYMENT-REQUIRED` payload and assert the agent fails closed locally.
  - [ ] Let a quote expire before retrying payment and assert SPS rejects the payment attempt before settlement.
  - [ ] Use a wallet without sufficient ETH gas or USDC balance and assert the paid exchange fails closed without creating an exchange resource.
  - [ ] Force facilitator `verify` or `settle` failure against a real-like response shape and assert SPS rolls back reserved allowance and records a failed transaction.
  - [ ] Assert the OpenClaw / runtime bridge surfaces actionable operator errors when x402 is required but the payer wallet is missing or disabled.

- [ ] **Operational readiness: mainnet**
  - [ ] Switch the supported production network from Base Sepolia (`eip155:84532`) to Base mainnet (`eip155:8453`) only after the full testnet flow is stable.
  - [ ] Configure the production facilitator endpoint and any required CDP credentials separately from testnet configuration.
  - [ ] Replace the test `payTo` address with the production treasury or multisig destination.
  - [ ] Store agent payer keys in a secret manager or equivalent secure runtime store rather than long-lived plaintext environment variables.
  - [ ] Add per-agent, per-workspace, and daily spend ceilings plus a global kill switch for x402 overage payments.
  - [ ] Add transaction reconciliation, stuck-payment monitoring, and alerting for failed verify / settle / ledger transitions.
  - [ ] Run a low-value canary rollout on mainnet before enabling broader budgets or wider workspace access.

## Milestone 3: Hosted Crypto Billing Checkout

- [ ] **Implementation: one-time hosted crypto checkout**
  - [ ] Add a dedicated web crypto checkout path using Coinbase Payment Links instead of forcing Coinbase into the existing recurring Stripe subscription abstraction.
  - [ ] Treat the first crypto plan purchase as a fixed-term plan purchase with manual renewal, not an auto-renewing subscription.
  - [ ] Ship the first crypto SKU as a single fixed-term Standard plan offer (for example, `Standard Annual`) to minimize product and accounting complexity.
  - [ ] Add billing state for the Coinbase provider, provider payment reference, and `plan_expires_at` so one-time crypto purchases can activate and later expire cleanly.
  - [ ] Add an authenticated route to create a Coinbase Payment Link for the current workspace and selected crypto plan SKU.
  - [ ] Add a Coinbase webhook route that validates the provider signature and upgrades the workspace only after a successful hosted payment event.
  - [ ] Add expiry handling so a crypto-paid Standard workspace downgrades back to Free when the purchased term ends and no renewal has been paid.
  - [ ] Update the billing dashboard to show a `Pay with crypto` path for free-tier workspaces and a `Renew with crypto` path for Coinbase-managed workspaces.
  - [ ] Hide or disable the recurring subscription portal UX when a workspace billing record is managed by Coinbase rather than Stripe.

- [ ] **E2E: hosted crypto checkout activation**
  - [ ] Have a verified workspace admin start a Coinbase crypto checkout from the Billing page and assert SPS returns a hosted payment link URL.
  - [ ] Redirect the admin to the hosted Coinbase checkout and assert the payment link includes workspace and plan metadata needed for webhook reconciliation.
  - [ ] Simulate or receive a successful Coinbase payment webhook and assert the workspace upgrades to `standard`.
  - [ ] Assert the billing record stores the Coinbase provider name, provider payment reference, and `plan_expires_at`.
  - [ ] Assert the dashboard now shows the workspace as Standard without requiring any Stripe customer or subscription reference.

- [ ] **E2E: hosted crypto checkout failure and idempotency**
  - [ ] Simulate an abandoned or failed Coinbase checkout and assert the workspace remains on the Free tier.
  - [ ] Replay the same successful Coinbase webhook twice and assert the workspace term is activated exactly once with no duplicate billing side effects.
  - [ ] Simulate a successful renewal purchase for an already active Coinbase-paid workspace and assert the term is extended rather than reset incorrectly.
  - [ ] Assert a Stripe billing portal session cannot be opened for a Coinbase-managed workspace and the UI points the user to the crypto renewal path instead.

- [ ] **Operational readiness: Coinbase web checkout**
  - [ ] Record provider payment reference, transaction hash, amount, asset, and network metadata for support and reconciliation.
  - [ ] Add alerting for webhook verification failures, pending unpaid crypto checkouts, and expired Coinbase-paid workspaces that were not downgraded on time.
  - [ ] Document provider environment variables, webhook setup, supported networks/assets, and manual refund / support runbooks for operators.

## Exit Criteria

- Enrolled-agent x402 overage payments are idempotent, serialized safely, and settled before releasing the paid resource
- Real Node-runtime payer support works against the supported test network before any mainnet rollout
- Hosted crypto checkout activates and renews fixed-term workspace plans without reusing the recurring Stripe lifecycle
