import { expect, test } from "./fixtures.js";
import { setupWorkspace } from "./setup.js";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

test.describe("Guest Secret Exchange (Phase 3C)", () => {
  const browserUiUrl = "http://127.0.0.1:5175";

  test("Scenario 917: Guest Agent -> Human Fulfill -> Guest Agent Retrieval", async ({ page, db }) => {
    // 1. Setup workspace with a specific agent for the fulfiller
    const { agents } = await setupWorkspace(
      page, 
      "guest-917", 
      "workspace_admin", 
      ["guest-fulfillment-bot"]
    );
    const fulfillerApiKey = agents["guest-fulfillment-bot"];
    expect(fulfillerApiKey, "Agent API key for guest-fulfillment-bot is missing").toBeTruthy();
    
    // 1.5 Exchange Agent API Key for a JWT Access Token
    const authRes = await page.request.post("http://127.0.0.1:3100/api/v2/agents/token", {
      headers: { "Authorization": `Bearer ${fulfillerApiKey}` }
    });
    expect(authRes.status(), `Agent token exchange failed: ${await authRes.text()}`).toBe(200);
    const { access_token: agentJwt } = await authRes.json();

    // 2. Generate a recipient key and secure link on behalf of the agent.
    const suite = new CipherSuite({
      kem: KemId.DhkemX25519HkdfSha256,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Chacha20Poly1305
    });
    const keyPair = await suite.kem.generateKeyPair();
    const publicKey = await suite.kem.serializePublicKey(keyPair.publicKey);
    const tokenRes = await page.request.post("http://127.0.0.1:3100/api/v2/secret/request", {
      headers: { "Authorization": `Bearer ${agentJwt}` },
      data: {
        public_key: Buffer.from(publicKey).toString("base64"),
        description: "E2E Guest Exchange Test"
      }
    });
    expect(tokenRes.status(), "Failed to create secret request").toBe(201);
    const { request_id, secret_url } = await tokenRes.json();
    expect(request_id).toBeDefined();
    expect(secret_url).toBeDefined();

    // 3. Visit the fulfillment link in Browser-UI
    // Use replaceAll to ensure api_url in query string is also updated
    const secretUrlFix = secret_url.replace(/localhost/g, "127.0.0.1");
    await page.goto(secretUrlFix);
    
    // 4. Wait for the page to be ready (ensure no 401)
    await expect(page.getByTestId("status")).toContainText(/session code/i, { timeout: 15000 });

    // 5. Submit the secret - ensure input is enabled
    const testSecret = "P00-DUMMY-BROWSER-INPUT";
    const secretInput = page.getByTestId("secret-input");
    await expect(secretInput).toBeEnabled({ timeout: 15000 });
    await secretInput.fill(testSecret);
    await page.getByTestId("submit-btn").click();
    
    // 6. Wait for success
    await expect(page.getByTestId("success-message")).toBeVisible({ timeout: 15000 });

    // 7. Open the ciphertext with the generated private key and prove one-use retrieval.
    const retrieveRes = await page.request.get(`http://127.0.0.1:3100/api/v2/secret/retrieve/${request_id}`, {
      headers: { "Authorization": `Bearer ${agentJwt}` }
    });
    expect(retrieveRes.status(), "Failed to retrieve secret via API").toBe(200);
    const secretData = await retrieveRes.json();
    const bytes = (value: string) => Uint8Array.from(Buffer.from(value, "base64")).buffer;
    const plaintext = await suite.open(
      { recipientKey: keyPair.privateKey, enc: bytes(secretData.enc) },
      bytes(secretData.ciphertext)
    );
    expect(new TextDecoder().decode(plaintext)).toBe(testSecret);
    const replay = await page.request.get(`http://127.0.0.1:3100/api/v2/secret/retrieve/${request_id}`, {
      headers: { "Authorization": `Bearer ${agentJwt}` }
    });
    expect(replay.status()).toBe(410);
  });
});
