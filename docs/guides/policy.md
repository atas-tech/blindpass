# Exchange policy configuration

This documents the implemented **payload-exchange policy** of the Rust controller, not the proposed Linux operation-grant model. Policy examples contain secret names and classifications, never credential values. Source: [policy routes](../../crates/blindpass-controller/src/routes/admin_policy.rs), [exchange routes](../../crates/blindpass-controller/src/routes/exchanges.rs) and the [policy engine](../../crates/blindpass-core/src/policy.rs). The legacy SPS had per-workspace policy and its own policy API; it was removed on 2026-10-07 and is in git history before the removal commit.

## Storage and roles

The controller keeps one versioned policy document for its tenant in its database (SQLite or PostgreSQL). Until an administrator saves one, exchanges are evaluated against the optional startup values `BLINDPASS_SECRET_REGISTRY_JSON` and `BLINDPASS_EXCHANGE_POLICY_JSON`, which the controller validates like an administrator write and refuses to start on if invalid ([controller configuration](../architecture/README.md#controller-configuration)). That startup policy reads as version 1. Once a document is stored it is the one in force, and changing the environment values does not modify it.

| API | Authorization | Behavior |
|---|---|---|
| `GET /api/v3/admin/policy` | Any signed-in operator | Read the current document and version |
| `POST /api/v3/admin/policy/validate` | Administrator, CSRF and Origin | Validate a draft without persisting it |
| `PUT /api/v3/admin/policy` | Administrator, CSRF and Origin | Replace both documents; `If-Match` must carry the current version |

The [console](../../packages/console) Policy page uses these routes. Tenant identity, trust-provider settings, cryptography, rate limits and exchange lifecycle state are controlled by the controller's configuration and runtime, not by these policy documents.

## Document fields

Registry entries require `secretName` and `classification`, with optional `description`. Every rule must reference a registered name and a unique `ruleId`.

Exchange rules support `requesterIds`, `fulfillerIds`, `requesterRings`, `fulfillerRings`, `purposes`, `sameRing`, `allowedRings`, `mode` and `reason`. Modes are `allow`, `pending_approval` and `deny`. A `pending_approval` rule must name one or more `approverIds`. `approverRings` is not supported by the Rust controller and is rejected, as is a pending rule without an approver ID; the controller does not infer approvers from ring membership.

**Empty and absent lists.** A requester, fulfiller, purpose or ring list that is absent or empty matches everything. In particular, `"requesterIds": []` or `"fulfillerIds": []` matches every agent, so an allow rule whose identity list was emptied is open to all of them. (The legacy SPS matched no agent; the owner chose the controller's behaviour on 2026-10-07.) A list entry that is blank or only whitespace is rejected rather than trimmed, because trimming it would leave an empty list. To restrict a rule, list the agents. To refuse everyone, use `mode: "deny"`. Rule ids, rule secret names and reasons are trimmed, and a blank `reason` is replaced by the generated text. An unrecognised `mode` is rejected, and one that still reaches evaluation denies. The shared cases that pin all of this are `packages/contract-tests/fixtures/cv05-policy-decided.json`, which both the controller and the TypeScript oracle replay.

The controller bounds a document to 2,000 registry entries and 5,000 exchange rules, with further field validation. PUT requires the complete replacement documents; omission is not a partial-rule update. Read the current version first and handle a `409 policy_version_conflict` by refreshing and reviewing the policy rather than blindly retrying an overwrite.

Example PUT body, sent with `If-Match: 1` (the version returned by GET):

```json
{
  "secret_registry": [
    {"secretName": "staging.read_token", "classification": "internal"}
  ],
  "exchange_policy": [
    {
      "ruleId": "approve-staging-read",
      "secretName": "staging.read_token",
      "requesterIds": ["staging-reader"],
      "fulfillerIds": ["credential-owner"],
      "approverIds": ["p02-admin"],
      "purposes": ["staging-check"],
      "mode": "pending_approval",
      "reason": "Require operator approval for this exchange"
    }
  ]
}
```

Validation uses the same two arrays. A validation response may be HTTP 200 with `valid: false` and an `errors` array; inspect the result, not only the HTTP status. A PUT that fails validation answers `400 invalid_policy` with an `issues` array.

## Bootstrap configuration

For a new disposable controller before an administrator has saved a policy:

```bash
export BLINDPASS_SECRET_REGISTRY_JSON='[{"secretName":"staging.read_token","classification":"internal"}]'
export BLINDPASS_EXCHANGE_POLICY_JSON='[{"ruleId":"approve-staging-read","secretName":"staging.read_token","requesterIds":["staging-reader"],"fulfillerIds":["credential-owner"],"mode":"pending_approval"}]'
```

Do not copy a broad development allow rule into an unrelated controller. Use the console Policy page or the API to inspect and save the stored policy; the [controller contract](../api/controller.openapi.yaml) describes the request envelopes.

The fleet pilot needs workload/invocation identity, local authority ceilings and operation/session lifetime enforcement beyond this exchange engine. Its proposed contract is in the [specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md#identity-and-authorization).
