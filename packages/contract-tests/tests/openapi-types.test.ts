import { expect, it } from "vitest";
import type { components, paths } from "../src/generated/controller.js";

type SubmitOperation = NonNullable<paths["/api/v2/secret/submit/{id}"]["post"]>;
type SubmitPayload = SubmitOperation["requestBody"]["content"]["application/json"];
type CapabilitiesOperation = NonNullable<paths["/api/v3/capabilities"]["get"]>;
type CapabilitiesResponse = CapabilitiesOperation["responses"]["200"]["content"]["application/json"];
type BrowserCapabilityOperation = NonNullable<paths["/api/v2/secret/browser-status/{id}/capability"]["post"]>;
type BrowserCapabilityResponse = BrowserCapabilityOperation["responses"]["200"]["content"]["application/json"];
type BrowserStatusOperation = NonNullable<paths["/api/v2/secret/browser-status/{id}"]["get"]>;
type BrowserStatusResponse = BrowserStatusOperation["responses"]["200"]["content"]["application/json"];
type TestSeedOperation = NonNullable<paths["/api/v3/admin/test/seed"]["post"]>;
type TestSeedResponse = TestSeedOperation["responses"]["200"]["content"]["application/json"];
type NodeChallenge = components["schemas"]["NodeSessionChallenge"];
type NodePollOperation = NonNullable<paths["/api/v3/node/poll"]["post"]>;
type NodePollInput = NodePollOperation["requestBody"]["content"]["application/json"];
type NodePollResponse = components["schemas"]["NodePollResponse"];

const encryptedPayload: SubmitPayload = {
  enc: "dummy-enc",
  ciphertext: "dummy-ciphertext"
};

const capabilities: CapabilitiesResponse = {
  api: ["compat.v2", "admin.v3"],
  version: "0.1.0",
  schema_version: 9,
  setup_required: true,
  features: { browser_status: true, fleet_authorization: true }
};

const browserCapability: BrowserCapabilityResponse = { status_sig: "exp.status-signature" };
const browserStatus: BrowserStatusResponse = { status: "submitted" };
const testSeed: TestSeedResponse = {
  workspace_id: "dummy-workspace",
  user_id: "dummy-user",
  agents: { "dummy-agent": "dummy-key" },
  local_admin: {
    operator_id: "dummy-operator",
    username: "admin",
    temporary_password: "dummy-password",
    session_id: "dummy-session",
    csrf_token: "dummy-csrf"
  }
};

it("generated operation and component types describe the controller wire shapes", () => {
  const payload: components["schemas"]["EncryptedPayload"] = encryptedPayload;
  expect(payload).toEqual({ enc: "dummy-enc", ciphertext: "dummy-ciphertext" });
  expect(capabilities.features.browser_status).toBe(true);
  expect(browserCapability.status_sig).toMatch(/^exp\./);
  expect(browserStatus.status).toBe("submitted");
  expect(testSeed.agents["dummy-agent"]).toBe("dummy-key");
  expect(testSeed.local_admin?.username).toBe("admin");

  const challenge: NodeChallenge = {
    nonce: "A".repeat(43),
    controller_time_ms: 1_800_000_000_000,
    expires_at_ms: 1_800_000_060_000,
    issuer_pub: "A".repeat(43),
    issuer_kid: `ed25519-${"A".repeat(43)}`,
    issuer_epoch: 1,
    min_protocol_version: "blindpass-node/1",
    audience: "blindpass-node",
    tenant_id: "tenant-a",
    node_id: "nd_node-a",
    key_version: 1,
    capabilities_hash: "a".repeat(64)
  };
  const poll: NodePollResponse = {
    documents: [],
    highest_seq: null,
    server_time_ms: 1_800_000_000_000,
    time_reply: {
      kind: "time_reply",
      v: 1,
      body: { node_id: "nd_node-a", challenge: "A".repeat(43), controller_time_ms: 1_800_000_000_000, issuer_epoch: 1 },
      sig: "A".repeat(86),
      kid: "issuer",
      epoch: 1
    }
  };
  const pollInput: NodePollInput = { time_challenge: "A".repeat(43) };
  expect(challenge.audience).toBe("blindpass-node");
  expect(pollInput.time_challenge).toHaveLength(43);
  expect(poll.time_reply?.kind).toBe("time_reply");

  if (false) {
    // @ts-expect-error ciphertext is required by the generated schema type.
    const invalid: SubmitPayload = { enc: "dummy-enc" };
    expect(invalid).toBeDefined();
  }
});
