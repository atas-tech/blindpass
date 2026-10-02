// Shared arrangement for the Source provisioning journeys: named operators, an
// enrolled API-node fixture with generated keys, a browser-mode policy that needs
// the owner's approval, and an administrator-configured Source destination.
// Everything is created through the controller's real HTTP contract; the only
// non-product actor is the JavaScript node fixture (see fleet-node.ts).
import { FleetNode, type GrantBody, type OfferFixture } from "./fleet-node.js";
import { AdminClient, type Stack } from "./stack.js";

export const DESTINATION = { unit: "blindpass-login@report-primary.service", credential: "report-source" };

export interface Actor {
  id: string;
  username: string;
  password: string;
  client: AdminClient;
}

export interface World {
  stack: Stack;
  admin: AdminClient;
  node: FleetNode;
  owner: Actor;
  other: Actor;
  viewer: Actor;
  sequence: number;
}

export interface SeededOperation {
  operationId: string;
  approvalId: string;
  grant: GrantBody;
  serverTimeMs: number;
  purpose: string;
  workloadName: string;
}

async function actor(stack: Stack, admin: AdminClient, username: string, role: "operator" | "viewer" | "admin", displayName: string): Promise<Actor> {
  const created = await admin.createOperator(username, role, displayName);
  const client = new AdminClient(stack);
  if ((await client.login(username, created.password)) !== 200) throw new Error(`${username} could not sign in`);
  return { id: created.id, username, password: created.password, client };
}

/** `existingAdmin` is an already bootstrapped and signed-in client, for stacks another spec prepared. */
export async function startWorld(stack: Stack, existingAdmin?: AdminClient): Promise<World> {
  const admin = existingAdmin ?? new AdminClient(stack);
  if (!existingAdmin) await admin.bootstrap();
  const owner = await actor(stack, admin, "e2e-source-owner", "operator", "Source Owner");
  const other = await actor(stack, admin, "e2e-other-operator", "operator", "Other Operator");
  const viewer = await actor(stack, admin, "e2e-source-viewer", "viewer", "Source Viewer");
  const node = await FleetNode.enroll(stack, admin, "e2e-source-node");

  const policy = await admin.call<{ version: number }>("GET", "/api/v3/policies");
  const saved = await admin.call("PUT", "/api/v3/policies", {
    expected_version: policy.body.version,
    rules: [{ id: "e2e-source-rule", action: "browser.session", mode: "browser_session", decision: "pending_approval", approval_required: true, max_ttl_seconds: 120, approver_ids: [owner.id] }]
  }, { "if-match": `"${policy.body.version}"` });
  if (saved.status !== 200) throw new Error(`policy save failed: ${saved.status}`);
  const bound = await admin.call("PUT", `/api/v3/nodes/${node.id}/source-bindings/report-primary`, { source_unit: DESTINATION.unit, credential: DESTINATION.credential, expected_version: 0 });
  if (bound.status !== 200) throw new Error(`source binding failed: ${bound.status}`);
  return { stack, admin, node, owner, other, viewer, sequence: 0 };
}

/**
 * Register a browser workload, have the node request an operation for it, let the
 * named owner approve it, and read the signed grant from the node inbox. No offer
 * is published yet, so the operation is "awaiting the node's offer".
 */
export async function seedOperation(world: World, label: string): Promise<SeededOperation> {
  world.sequence += 1;
  const n = world.sequence;
  const name = `source-worker-${n}`;
  const workload = await world.admin.call<{ id: string; unit: string; account: string }>("POST", "/api/v3/workloads", {
    node_id: world.node.id,
    name,
    unit: `e2e-source-${n}.service`,
    account: `uid:${1001 + n}`,
    consumption_mode: "browser_session",
    local_ceiling_seconds: 300
  });
  if (workload.status !== 201) throw new Error(`workload create failed: ${workload.status}`);
  const purpose = `${label} - read the approved report ${n}`;
  await world.node.requestOperation(workload.body, purpose);

  let approvalId = "";
  let operationId = "";
  for (let attempt = 0; attempt < 40 && !approvalId; attempt += 1) {
    const listed = await world.admin.call<{ items: Array<{ id: string; purpose: string; approval_id: string | null }> }>("GET", "/api/v3/operations?limit=100");
    const found = listed.body.items.find((item) => item.purpose === purpose && item.approval_id);
    if (found) {
      approvalId = found.approval_id!;
      operationId = found.id;
    } else await new Promise((resolve) => setTimeout(resolve, 150));
  }
  if (!approvalId) throw new Error("the operation request did not create an approval");
  const detail = await world.owner.client.call<{ version: number; operation_ids: string[] }>("GET", `/api/v3/approvals/${approvalId}`);
  const decided = await world.owner.client.call("POST", `/api/v3/approvals/${approvalId}/approve`, { expected_status: "pending", expected_version: detail.body.version, operation_ids: detail.body.operation_ids }, {
    "idempotency-key": `e2e-approve-${n}-${"0".repeat(12)}`,
    "if-match": `"${detail.body.version}"`
  });
  if (decided.status !== 200) throw new Error(`approval failed: ${decided.status}`);
  const { grant, serverTimeMs } = await world.node.grantFor(operationId);
  return { operationId, approvalId, grant, serverTimeMs, purpose, workloadName: name };
}

/** Sign and post the node's offer; the controller must accept the JavaScript-signed offer. */
export async function publishOffer(world: World, seeded: SeededOperation, ttlMs = 100_000): Promise<OfferFixture> {
  const { serverTimeMs } = await world.node.inbox();
  const fixture = await world.node.signOffer(seeded.grant, DESTINATION, serverTimeMs, ttlMs);
  const posted = await world.node.publishOffer(fixture);
  const accepted = (posted.body as { accepted?: number } | null)?.accepted;
  if (posted.status !== 200 || accepted !== 1) throw new Error(`the controller did not accept the JavaScript-signed offer: ${posted.status} ${JSON.stringify(posted.body)}`);
  return fixture;
}
