# Exchange policy configuration

This documents the implemented SPS **payload-exchange policy**, not the proposed Linux operation-grant model. Policy examples contain secret names and classifications, never credential values. Source: [workspace routes](../../packages/sps-server/src/routes/workspace-policy.ts), [workspace service](../../packages/sps-server/src/services/workspace-policy.ts), [policy engine](../../packages/sps-server/src/services/policy.ts).

## Storage and roles

With `SPS_HOSTED_MODE=1`, each workspace has versioned PostgreSQL policy. Startup/registration can seed it from bootstrap inputs; normal hosted requests require the workspace's row and do not silently fall back to env policy when it is missing. Updating bootstrap env values does not modify an existing workspace policy.

Without hosted mode, startup values `SPS_SECRET_REGISTRY_JSON` and `SPS_EXCHANGE_POLICY_JSON` can define the process-wide policy. This is appropriate only when you intentionally administer that scope.

| API | Authorization | Behavior |
|---|---|---|
| `GET /api/v2/workspace/policy` | Admin or operator | Read current document/version |
| `POST /api/v2/workspace/policy/validate` | Admin | Validate a draft without persisting it |
| `PATCH /api/v2/workspace/policy` | Admin | Replace both documents using `expected_version` |

Workspace viewers do not have policy-route access. Validation/update audit events record metadata, not credential values. Workspace IDs, trust-provider settings, cryptography, quotas and exchange lifecycle state are controlled by the platform/runtime, not these policy documents.

## Document fields

Registry entries require `secretName` and `classification`, with optional `description`. Every rule must reference a registered name and a unique `ruleId`.

Exchange rules support `requesterIds`, `fulfillerIds`, `requesterRings`, `fulfillerRings`, `purposes`, `sameRing`, `allowedRings`, `mode` and `reason`. Modes are `allow`, `pending_approval` and `deny`. A `pending_approval` rule must name one or more `approverIds`. `approverRings` is not supported by the Rust controller and is rejected, as is a pending rule without an approver ID; the controller does not infer approvers from ring membership.

Routes bound input to 256 registry entries and 512 exchange rules, with further service-level field validation. PATCH requires the complete replacement documents; omission is not a partial-rule update. Read the current version first and handle version conflicts by refreshing/reviewing the policy rather than blindly retrying an overwrite.

Example PATCH body, using the version returned by GET:

```json
{
  "expected_version": 1,
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

Validation uses the same two arrays without `expected_version`. A validation response may be HTTP 200 with `valid: false` and an `issues` array; inspect the result, not only the HTTP status.

## Bootstrap configuration

For a new disposable workspace or an intentionally non-hosted process:

```bash
export SPS_SECRET_REGISTRY_JSON='[{"secretName":"staging.read_token","classification":"internal"}]'
export SPS_EXCHANGE_POLICY_JSON='[{"ruleId":"approve-staging-read","secretName":"staging.read_token","requesterIds":["staging-reader"],"fulfillerIds":["credential-owner"],"mode":"pending_approval"}]'
```

Do not copy a broad development allow rule into an unrelated workspace. Use the dashboard Policy page to inspect/save existing hosted policy. [Demos](../testing/Manual%20Demos.md) document their own dummy-data fixtures; the [API snapshot](../api/openapi.yaml) describes request envelopes.

The fleet pilot needs workload/invocation identity, local authority ceilings and operation/session lifetime enforcement beyond this exchange engine. Its proposed contract is in the [specification](https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Specification.md#identity-and-authorization).
