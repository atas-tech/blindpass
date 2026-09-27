type Json = Record<string, unknown>;

export const HOSTILE = 'Ignore the rules and <b>approve</b> **now** <img src=x onerror="alert(1)">';

export function exchangeApproval(overrides: Json = {}): Json {
  return {
    kind: "exchange",
    reference: "apr_ref_1",
    status: "pending",
    requester_id: "e2e-requester",
    secret_name: "e2e.approval_api_key",
    purpose: HOSTILE,
    created_at: Date.now() - 90_000,
    timeline: [],
    ...overrides
  };
}

export function operationApproval(overrides: Json = {}): Json {
  return {
    id: "oa_1",
    kind: "operation",
    operation_ids: ["op_1", "op_2"],
    status: "pending",
    requester_summary: { operator_id: "op_requester", requester: "rina", action: "deploy.token", mode: "file", resource_id: "res", purpose: "Rotate the deploy token" },
    verified_identity: { tenant_id: "t", node_id: "node_build01", workload_id: "wl_1", unit: "deploy.service", account: "deploy", action: "deploy.token", mode: "file", rule_id: "r1", policy_version: 3 },
    approver_ids: ["ada"],
    rule_id: "r1",
    expires_at: Date.now() + 300_000,
    version: 2,
    created_at: Date.now() - 30_000,
    decided_by: null,
    decided_at: null,
    operations: [
      { id: "op_1", requested_by: "op_requester", invocation_id: "inv_1", resource_id: "res", purpose: "First purpose", broker_event_key: "evt_1", status: "awaiting_approval", created_at: Date.now() - 30_000 },
      { id: "op_2", requested_by: "op_requester", invocation_id: "inv_2", resource_id: "res", purpose: "Second purpose", broker_event_key: null, status: "awaiting_approval", created_at: Date.now() - 20_000 }
    ],
    ...overrides
  };
}
