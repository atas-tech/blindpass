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

const encryptedPayload: SubmitPayload = {
  enc: "dummy-enc",
  ciphertext: "dummy-ciphertext"
};

const capabilities: CapabilitiesResponse = {
  api: ["compat.v2", "admin.v3"],
  version: "0.1.0",
  schema_version: 5,
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

  if (false) {
    // @ts-expect-error ciphertext is required by the generated schema type.
    const invalid: SubmitPayload = { enc: "dummy-enc" };
    expect(invalid).toBeDefined();
  }
});
