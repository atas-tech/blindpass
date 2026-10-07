# Cross-workload fulfillment — need, boundary and contract (P10.1)

**Status:** implementing; activated by owner instruction on 2026-10-07. The operator need the phase requires was **not
named**; it is recorded as open in the
[P10 plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/phases/10-cross-workload-fulfillment.md).
The feature is off by default on the controller (`BLINDPASS_FULFILLMENTS_ENABLED`) and on every broker (no
`--fulfillment-source` / `--fulfillment-destination` flags). **Mode:** `reencrypt` only. `provider_issue` and
`brokered_action` are rejected and never advertised.
**Code:** `crates/blindpass-core/src/fulfillment.rs`, controller `store/fulfillments.rs` and `routes/fulfillments.rs`,
broker `ops/fulfill.rs`, node relay routing in `crates/blindpass-node`.
**Tests:** `P10-I01`–`P10-I04`, `P10-E01`–`P10-E02` in the vault
[P10 acceptance plan](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/testing/phases/10-cross-workload-fulfillment.md);
pilot cases X01–X03. The slice table at the end is the only statement of what exists today.

## Need and reference task

No operator has named a cross-workload need. Until one does, the reference task below is the only thing the code is
held to; it uses dummy data and says nothing about demand.

> **Reference task.** Service A (issuer) on node 1 holds an API credential in broker custody. Service B (recipient) on
> node 2 needs the same credential. An operator selects both registered workloads and the credential name; a named
> approver approves; B's systemd unit starts, loads the credential through `LoadCredential=` and authenticates to a
> provider with it.

| Question the plan asks | Answer |
|---|---|
| Operator | An authenticated controller operator (role `operator` or `admin`); never a workload or agent |
| Issuer | One registered, active workload whose broker holds the credential and has opted the unit in with `--fulfillment-source UNIT` |
| Recipient | One registered, active workload on a **different** node whose broker maps a credential for its unit and has opted in with `--fulfillment-destination UNIT` |
| Resource and action | The issuer unit's mapped credential, released once; action is the fixed `fulfill.reencrypt` / `fulfill.receive` pair |
| Consumption mode | Native service delivery to the recipient unit: the credential is stored in the recipient broker's memory and read by the unit through the root-only credential loader |
| Why secret transfer | The recipient must present the same credential to the provider. A scoped provider credential or a brokered operation would need a provider adapter that does not exist |
| Provider lifetime/revocation | None known to BlindPass. A re-encrypted static credential stays valid at its provider after every BlindPass revocation; the controller records `provider_revocation = unsupported` and never implies otherwise |
| Completed task | The recipient unit read the credential through the loader (`completed`), and in the VM scenario authenticated to a dummy provider |

**Rejected: an unbounded general scheduler.** One fulfillment is one issuer workload, one recipient workload, one
credential and one transfer. There is no recurrence, queue, account pool, federation or billing.

## Why the existing operation/grant model is insufficient

Verified against the tree at `6caa684` (2026-10-07).

| Existing mechanism | Why it does not carry a transfer |
|---|---|
| `operations` + `grants` | One grant per operation (`grants.operation_id UNIQUE`) and a single node, workload and invocation; a transfer needs two parties that must agree on one contract. Operations originate from broker evidence of a running invocation; a service-to-service transfer has none. The `Grant` wire format has an exact field set |
| v2 exchanges | An exchange record authorizes one payload flow to one requester key. It carries no node, workload, invocation or approval binding for a second party, and ciphertext sealed to one key is not re-encryption for another |
| Browser Source provisioning (P05) | The right pattern (a one-use key minted and signed by the receiving broker, ciphertext relayed, controller signs the delivery), but its encryptor is an operator's browser and it is bound to a `browser.session` grant |
| Credential loader | Authenticates the consuming unit by pidfd, but is not grant-bound and delivers only what broker memory already holds |

Reused unchanged: node enrollment and keys, the signed-envelope format and issuer epoch, the node inbox and outbox,
`application_ack`, controller audit, expiry sweeps, the recovery invalidation and backup machinery.

## Verification corrections to the plan (2026-10-07)

The plan was written against commit `0350339`. These facts were checked in the working tree and change the design.

| # | Plan statement | Finding |
|---|---|---|
| 1 | Legacy `StoredExchange` / "legacy v2" handlers | The legacy SPS was removed on 2026-10-07. "Legacy v2" now means the controller's own `/api/v2/secret/exchange/*` routes. They share the single `Store`, pool and database role with fleet code; isolation is authentication and convention only, so the payload needs its own store module and table and tests that prove the v2 surface cannot reach it |
| 2 | `source_custody_id`, "existing custody record" | No custody record or id exists. Broker custody is an in-memory map keyed `unit:credential`, root-provisioned, expiring, lost on restart, one credential per unit by `--map` |
| 3 | "Enrolled recipient key" as the seal target | The node's enrolled recipient private key is never used to decrypt anything, and rotation discards it. Every existing receive path uses a one-use ephemeral key signed by the receiving broker |
| 4 | Two grants, one `fulfillment_id` | `Grant` has an exact field set, one grant per operation, an invocation binding and no tenant or key-version field. New actions would also have to be added to `supported_operation_binding`, which would let ordinary operations request them |
| 5 | Pre-start native delivery "uses P03's loader binding" | Not implemented: `grants.service_delivery_binding` is never written. Loader delivery is unit-bound by pidfd, not grant-bound |
| 6 | `cross_workload` policy scope | Fleet policy rules are keyed by (action, mode); there is no scope. `FleetRuleInput` rejects unknown fields. The fleet decision hash is not the legacy v2 hash, so CV05 outputs are not affected |
| 7 | "Issuer recovery generation" | The issuer epoch is tenant-wide in `controller_meta`, stamped into every signed envelope |
| 8 | Upload "to the controller" | The broker is `AF_UNIX`-only; everything goes through the unprivileged node relay. Node events are capped at 64 KiB and the event kinds are a closed list in four places |
| 9 | State table and "ed25519 / canonical JSON are P03 targets" | Stale: Ed25519, canonical JSON, enrolled keys, grants and the browser/noop operations exist |
| 10 | HPKE re-seal primitives | Confirmed: `open_with_info` and `seal_with_info` take caller `info` and AAD. No production caller uses `info`. HPKE base mode does not authenticate the sender, so an issuer signature is required |

## Decisions closed (P10-D1 to P10-D6)

| # | Decision |
|---|---|
| D1 | Mode `reencrypt` only. The recipient broker mints a **one-use** X25519 key per fulfillment (30–180 s) and signs an offer; the issuer broker opens its own custody, seals to that key and signs the result; the recipient broker opens once into its own custody. The enrolled node key is not used to receive. The operator verifies the **node fingerprints** of both parties, which the enrollment approval already pinned |
| D2 | Not a grant pair. One `fulfillment_id` is carried by purpose-built controller-signed documents (`fulfillment_authorization` for each side, `fulfillment_delivery`, `fulfillment_revocation`) and node-signed documents (`fulfillment_offer`, `fulfillment_submit`) plus `fulfillment_result` events. Every document carries the issuer epoch and the SHA-256 digest of the immutable terms |
| D3 | Tables `cross_fulfillments` (metadata, immutable lineage) and `cross_fulfillment_payloads` (ciphertext, deleted on receipt, expiry or revocation). Only `store/fulfillments.rs` touches them; no v2 or other fleet route reads them |
| D4 | The fleet policy document gains an optional `cross_workload` array. A fulfillment is denied unless one rule names both the issuer and the recipient workload ids explicitly (no wildcard). A rule decides `allow`, `pending_approval` (named approvers, no self-approval) or `deny`. `rules` and every existing policy hash are untouched |
| D5 | Approval detail shows both workloads, both nodes, both fingerprints, credential names, mode and expiry as verified fields and the purpose as untrusted text. Grouped approvals are not offered. **Built:** the approver returns the two displayed node fingerprints with the decision; the controller compares them with the live enrolled keys and refuses a changed pair with `409 authorization_changed` |
| D6 | Statuses `awaiting_approval`, `approved`, `offered`, `available`, `recipient_consumed`, `completed`, `denied`, `revoked`, `expired`, `failed`, `uncertain` (there is no stored `requested` state: a request is either denied, waiting for approval or approved when it is created). Revocation deletes payload bytes only, keeps metadata and records `delivery_revoked_at` separately from `provider_revocation`, which is always `unsupported` |

## Contract

### Trust and plaintext lifetime

| Holder | Plaintext | Lifetime |
|---|---|---|
| Issuer broker (root, memory) | Source credential and the sealed copy while sealing | Wiped after sealing; the source stays in custody for its normal lifetime |
| Controller and node relays | **None.** Ciphertext sealed to a one-use key, ciphertext digest, public metadata | Controller payload: until the recipient reports `stored`, expiry or revocation (bounded by 10 min) |
| Recipient broker (root, memory) | The credential after opening | Normal broker credential lifetime, **not** the fulfillment TTL; removed early only if unread at revocation or expiry |
| Recipient unit | Whatever it reads | Outside BlindPass: the unit can copy or disclose it |

The controller's authorization power and its ability to substitute the recipient's node keys are not neutralised by its
lack of plaintext. The issuer broker cannot independently verify the recipient's keys: it trusts the controller-signed
terms, which carry node fingerprints the operator approved. This is the same trust the pilot already places in the
controller for grants.

### Immutable terms and digest

`terms` (canonical JSON, `version` 1): `fulfillment_id`, `tenant_id`, `mode` (`reencrypt`), `issuer` and `recipient`
parties (`node_id`, `workload_id`, `unit`, `credential`, `registration_version`, `key_version`, `signing_public`,
`recipient_public`, `fingerprint`), `policy_version`, `rule_id`, `approval_reference` (optional), `prior_fulfillment_id`
(optional), `max_plaintext_bytes`, `issued_at_ms`, `expires_at_ms`, `issuer_epoch`. `terms_digest` is the lowercase hex
SHA-256 of `blindpass:fleet-fulfillment-terms:v1\0` and the canonical bytes. The purpose text is **not** in the terms.

### HPKE binding

Suite and library are the existing ones (DHKEM X25519, HKDF-SHA256, ChaCha20-Poly1305, base mode). `info` is
`blindpass:fleet-fulfillment-info:v1\0` plus the 32 digest bytes. AAD is `blindpass:fleet-fulfillment-aad:v1\0` plus the
canonical `{offer_id, recipient_public, terms_digest}`. The issuer signs a `fulfillment_submit` envelope covering `enc`,
the ciphertext digest, the `offer_id` and the `terms_digest` with its node signing key; HPKE alone does not authenticate
the issuer, so the recipient verifies that signature against the key in the controller-signed terms. A successful
decryption is not evidence of issuer authenticity.

### Sequence

```text
operator ─POST /api/v3/fulfillments {issuer_workload_id, recipient_workload_id, issuer_credential, recipient_credential, purpose[, prior_fulfillment_id]}─▶ controller
controller: cross_workload rule → deny | pending_approval → operator approves (≠ requester) | allow
controller ─fulfillment_authorization(side=recipient)─▶ recipient node → broker: verify, mint one-use key, sign offer
recipient broker ─fulfillment_offer─▶ controller (validates against the terms)
controller ─fulfillment_authorization(side=issuer, offer)─▶ issuer node → broker: verify both, open own custody, seal, sign
issuer broker ─fulfillment_submit─▶ controller: verify signature, store payload (idempotent), queue delivery   [status available]
controller ─fulfillment_delivery─▶ recipient node → broker: verify controller + issuer signatures, open once, store  
recipient broker ─fulfillment_result(stored)─▶ controller: delete payload                                   [recipient_consumed]
recipient unit reads the credential through the loader ─fulfillment_result(consumed)─▶ controller            [completed]
```

### Bounds

| Bound | Value | Where enforced | Test |
|---|---|---|---|
| Approval TTL | 10 min | controller | P10-I01 |
| Fulfillment expiry (approval to loader read) | 10 min, capped by the rule's `max_ttl_seconds` | controller, both brokers | P10-E01 |
| One-use offer key lifetime | 180 s, capped by the fulfillment | recipient broker | P10-I02 |
| Maximum plaintext | 8 KiB (documents stay under the 64 KiB node cap) | all three parties | P10-I02 |
| Active fulfillments per recipient workload | 1 | controller (unique index) and broker | P10-I02 |
| Tombstone/lineage retention | revocation tombstones 7 days; terminal metadata follows audit retention | controller | P10-I04 |
| Offline revocation | bounded by node connectivity and the 10-minute expiry, not instant | brokers | P10-I04 |

### Local ceilings (broker, root-owned)

A broker releases a source only for a unit named by `--fulfillment-source UNIT` and accepts a credential only for a unit
named by `--fulfillment-destination UNIT`; both must also be mapped by `--map`. With neither flag the broker refuses every
fulfillment. A controller-signed document cannot widen these. The destination must be empty or owned by the
`prior_fulfillment_id` named in the terms; a live credential from any other source is never overwritten.

### Failure and recovery

| Event | Result |
|---|---|
| Duplicate request, same idempotency key and body | Original fulfillment returned; no second authorization |
| Same key, different body, or a second `fulfillment_submit` with different bytes | `409`; first bytes win |
| Lost submit/result reply | The node outbox retries identical bytes; controller deduplicates |
| Recipient never reports after delivery | `uncertain` at expiry; the payload is deleted and is never re-served; the operator starts a new fulfillment |
| Broker restart | Offer keys, pending state and stored credentials are lost (custody is memory-only); the fulfillment ends `expired` or `uncertain`, never resumed |
| Revocation | Payload deleted; both brokers drop pending state; an unread stored credential is removed; a read credential cannot be recalled |
| Stale controller restore | The issuer epoch rises on recovery; older documents fail verification and recovery invalidation revokes non-terminal fulfillments |
| Feature disabled | New creation refused; startup revokes every non-terminal fulfillment (`feature_disabled`) |
| Node key rotated mid-flow | The offer and terms bind the key version; the fulfillment fails closed and needs fresh authorization |

## Exclusions

No provider adapter, scoped-credential issuance, brokered action, scheduler, account pool, federation, billing, grouped
approval, desktop-app approval or multi-recipient fan-out. The desktop approval app and the metadata widget do not show
fulfillments; the console does.

## Implementation slices

| Slice | State |
|---|---|
| 1 contract, verification | this document |
