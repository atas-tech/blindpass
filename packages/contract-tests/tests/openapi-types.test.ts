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

const encryptedPayload: SubmitPayload = {
  enc: "dummy-enc",
  ciphertext: "dummy-ciphertext"
};

const capabilities: CapabilitiesResponse = {
  api: ["compat.v2", "admin.v3"],
  version: "0.1.0",
  schema_version: 1,
  setup_required: true,
  features: { browser_status: true }
};

const browserCapability: BrowserCapabilityResponse = { status_sig: "exp.status-signature" };
const browserStatus: BrowserStatusResponse = { status: "submitted" };

it("generated operation and component types describe the controller wire shapes", () => {
  const payload: components["schemas"]["EncryptedPayload"] = encryptedPayload;
  expect(payload).toEqual({ enc: "dummy-enc", ciphertext: "dummy-ciphertext" });
  expect(capabilities.features.browser_status).toBe(true);
  expect(browserCapability.status_sig).toMatch(/^exp\./);
  expect(browserStatus.status).toBe("submitted");

  if (false) {
    // @ts-expect-error ciphertext is required by the generated schema type.
    const invalid: SubmitPayload = { enc: "dummy-enc" };
    expect(invalid).toBeDefined();
  }
});
