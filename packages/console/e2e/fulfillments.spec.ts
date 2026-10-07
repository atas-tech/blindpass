// P10 console journeys for cross-workload fulfillment (P10-E01 GUI portion), driven in
// Chromium against the REAL Rust controller (preview and embedded profiles).
//
// Honest scope: both nodes are the JavaScript FleetNode fixture (generated keys, the
// controller's node HTTP contract), not brokers and not blindpass-node, so nothing is
// sealed, delivered or read here. What is real: the controller (cross-workload rule,
// requester/approver separation, fingerprint-bound approval, authorization documents,
// revocation), the console page and the operators' cookie/CSRF sessions. The sealed
// transfer itself is covered by tests/fleet/p10-vm.py.
import { expect, test, type Page } from "@playwright/test";
import { FleetNode } from "./support/fleet-node.js";
import { ADMIN, AdminClient, Stack } from "./support/stack.js";

interface Actor {
  id: string;
  username: string;
  password: string;
}

interface Workload {
  id: string;
  name: string;
}

async function signIn(page: Page, stack: Stack, actor: Pick<Actor, "username" | "password">) {
  await page.goto(`${stack.consoleUrl}/login`);
  await page.getByLabel("Username").fill(actor.username);
  await page.getByLabel("Password", { exact: true }).fill(actor.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/);
}

async function operator(stack: Stack, admin: AdminClient, username: string, role: "operator" | "viewer"): Promise<Actor> {
  const created = await admin.createOperator(username, role, username);
  return { id: created.id, username, password: created.password };
}

async function workload(admin: AdminClient, node: FleetNode, name: string, unit: string): Promise<Workload> {
  const created = await admin.call<{ id: string }>("POST", "/api/v3/workloads", {
    node_id: node.id,
    name,
    unit,
    account: "uid:1001",
    consumption_mode: "file",
    local_ceiling_seconds: 120
  });
  if (created.status !== 201) throw new Error(`workload create failed: ${created.status}`);
  return { id: created.body.id, name };
}

const PURPOSE = "<img src=x onerror=alert(1)> rotate the report key";

test.describe("cross-workload fulfillment in the console (API-node fixtures)", () => {
  test.describe.configure({ mode: "serial" });
  let stack: Stack;
  let admin: AdminClient;
  let approver: Actor;
  let viewer: Actor;
  let nodeA: FleetNode;
  let nodeB: FleetNode;
  let issuer: Workload;
  let recipient: Workload;

  test.beforeAll(async () => {
    stack = await Stack.start({ fulfillments: true });
    admin = new AdminClient(stack);
    await admin.bootstrap();
    approver = await operator(stack, admin, "e2e-fulfillment-approver", "operator");
    viewer = await operator(stack, admin, "e2e-fulfillment-viewer", "viewer");
    nodeA = await FleetNode.enroll(stack, admin, "e2e-issuer-node");
    nodeB = await FleetNode.enroll(stack, admin, "e2e-recipient-node");
    issuer = await workload(admin, nodeA, "e2e-issuer-app", "e2e-issuer-app.service");
    recipient = await workload(admin, nodeB, "e2e-recipient-app", "e2e-recipient-app.service");
    const policy = await admin.call<{ version: number; rules: unknown[] }>("GET", "/api/v3/policies");
    const saved = await admin.call("PUT", "/api/v3/policies", {
      expected_version: policy.body.version,
      rules: policy.body.rules,
      cross_workload: [{ id: "e2e-cross-rule", issuer_workload_ids: [issuer.id], recipient_workload_ids: [recipient.id], decision: "pending_approval", approver_ids: [approver.id], max_ttl_seconds: 300 }]
    }, { "if-match": `"${policy.body.version}"` });
    if (saved.status !== 200) throw new Error(`cross-workload policy save failed: ${saved.status}`);
  });
  test.afterAll(async () => stack?.stop());

  test("P10-E01 GUI: the requester asks, a different named approver verifies both fingerprints and approves, and both nodes receive their authorization", async ({ browser }) => {
    const requesterContext = await browser.newContext();
    const requester = await requesterContext.newPage();
    await signIn(requester, stack, ADMIN);
    await requester.goto(`${stack.consoleUrl}/fulfillments`);
    await expect(requester.getByRole("heading", { name: "Credential fulfillments." })).toBeVisible();
    await requester.getByRole("button", { name: "Request fulfillment" }).click();
    const request = requester.getByRole("dialog");
    await request.getByLabel("Issuer workload").selectOption(issuer.id);
    await request.getByLabel("Recipient workload").selectOption(recipient.id);
    await request.getByLabel("Issuer credential name").fill("api-key");
    await request.getByLabel("Recipient credential name").fill("api-key");
    await request.getByLabel("Purpose").fill(PURPOSE);
    await request.getByRole("button", { name: "Send request" }).click();
    await expect(requester.getByText("Fulfillment requested")).toBeVisible();

    const row = requester.locator("tr[data-fulfillment]").first();
    await expect(row).toContainText("Awaiting approval");
    await expect(row).toContainText("api-key");
    const id = (await row.getAttribute("data-fulfillment")) ?? "";
    expect(id).not.toBe("");

    // The requester cannot decide their own request: the review shows why and offers no approval.
    await row.getByRole("button", { name: /Review fulfillment for/ }).click();
    const own = requester.getByRole("dialog");
    await expect(own).toContainText("You requested this fulfillment, so you can't approve or reject it.");
    await expect(own.getByRole("button", { name: "Approve fulfillment" })).toBeDisabled();
    await expect(own.getByRole("button", { name: "Reject" })).toBeDisabled();
    await requester.keyboard.press("Escape");
    await requesterContext.close();

    // The named approver sees the facts the controller verified and the requester's purpose as text.
    const approverContext = await browser.newContext();
    const reviewer = await approverContext.newPage();
    await signIn(reviewer, stack, approver);
    await reviewer.goto(`${stack.consoleUrl}/fulfillments`);
    await reviewer.locator(`tr[data-fulfillment="${id}"]`).getByRole("button", { name: /Review fulfillment for/ }).click();
    const review = reviewer.getByRole("dialog");
    // The console groups a fingerprint for reading; compare the digits without the grouping.
    await expect(review).toContainText("e2e-cross-rule");
    const shown = (await review.innerText()).replace(/[\s:-]/g, "").toLowerCase();
    expect(shown).toContain(nodeA.keys.fingerprint.toLowerCase());
    expect(shown).toContain(nodeB.keys.fingerprint.toLowerCase());
    await expect(review).toContainText("e2e-cross-rule");
    await expect(review).toContainText("<img src=x onerror=alert(1)>");
    await expect(review.locator("img")).toHaveCount(0);
    const approve = review.getByRole("button", { name: "Approve fulfillment" });
    await expect(approve).toBeDisabled();
    await review.getByLabel("I checked that both fingerprints match the nodes I enrolled.").check();
    await expect(approve).toBeEnabled();
    await approve.click();
    await expect(reviewer.getByText("Fulfillment approved")).toBeVisible();
    await expect(reviewer.locator(`tr[data-fulfillment="${id}"]`)).toContainText(/Approved|Key offered/);
    await approverContext.close();

    // The controller queued its signed authorization for the recipient node, and for the
    // issuer only after the recipient's offer, which this fixture node never publishes.
    const { document } = await nodeB.waitForDocument((entry) => entry.envelope.kind === "fulfillment_authorization");
    expect(document.envelope.kind).toBe("fulfillment_authorization");
    const issuerInbox = await nodeA.inbox();
    expect(issuerInbox.documents.some((entry) => entry.envelope.kind === "fulfillment_authorization")).toBe(false);
    const stored = await admin.call<{ status: string; approval?: { status?: string } }>("GET", `/api/v3/fulfillments/${id}`);
    expect(stored.status).toBe(200);
    expect(["approved", "offered"]).toContain(stored.body.status);
  });

  test("P10-E01 GUI: revoking from the console ends the fulfillment and says what cannot be recalled", async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    await signIn(page, stack, ADMIN);
    await page.goto(`${stack.consoleUrl}/fulfillments`);
    const row = page.locator("tr[data-fulfillment]").first();
    await row.getByRole("button", { name: /Revoke fulfillment for/ }).click();
    const confirm = page.getByRole("dialog");
    await expect(confirm).toContainText("Anything the recipient workload has already read can't be recalled.");
    await confirm.getByRole("button", { name: "Revoke fulfillment" }).click();
    await expect(page.getByText("Fulfillment revoked").first()).toBeVisible();
    await expect(page.getByText("can't be recalled").first()).toBeVisible();
    await expect(row).toContainText("Revoked");
    await expect(row).toContainText("Revocation reason:");
    // Nothing was stored on the recipient yet, so the row makes no provider claim at all.
    await expect(row).not.toContainText("provider");
    const id = (await row.getAttribute("data-fulfillment")) ?? "";
    const stored = await admin.call<{ status: string; provider_revocation: string }>("GET", `/api/v3/fulfillments/${id}`);
    expect(stored.body.status).toBe("revoked");
    expect(["not_attempted", "unsupported"]).toContain(stored.body.provider_revocation);
    await context.close();
  });

  test("P10-I01 GUI: a pair no rule names is refused with the policy explanation, and a viewer has no Fulfillments page", async ({ browser }) => {
    const reversed = await browser.newContext();
    const page = await reversed.newPage();
    await signIn(page, stack, ADMIN);
    await page.goto(`${stack.consoleUrl}/fulfillments`);
    await page.getByRole("button", { name: "Request fulfillment" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Issuer workload").selectOption(recipient.id);
    await dialog.getByLabel("Recipient workload").selectOption(issuer.id);
    await dialog.getByLabel("Issuer credential name").fill("api-key");
    await dialog.getByLabel("Recipient credential name").fill("api-key");
    await dialog.getByLabel("Purpose").fill("reverse of the ruled pair");
    await dialog.getByRole("button", { name: "Send request" }).click();
    await expect(dialog).toContainText("No cross-workload policy rule allows this issuer and recipient.");
    await reversed.close();

    const viewerContext = await browser.newContext();
    const viewerPage = await viewerContext.newPage();
    await signIn(viewerPage, stack, viewer);
    await expect(viewerPage.getByRole("link", { name: "Fulfillments" })).toHaveCount(0);
    await viewerPage.goto(`${stack.consoleUrl}/fulfillments`);
    await expect(viewerPage.getByRole("button", { name: "Request fulfillment" })).toHaveCount(0);
    await expect(viewerPage.locator("tr[data-fulfillment]")).toHaveCount(0);
    await viewerContext.close();
  });
});

test.describe("cross-workload fulfillment switched off", () => {
  let stack: Stack;

  test.beforeAll(async () => {
    stack = await Stack.start({});
    await new AdminClient(stack).bootstrap();
  });
  test.afterAll(async () => stack?.stop());

  test("P10-E02 GUI: with the controller flag off the console shows no Fulfillments page", async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    await signIn(page, stack, ADMIN);
    await expect(page.getByRole("link", { name: "Fulfillments" })).toHaveCount(0);
    await page.goto(`${stack.consoleUrl}/fulfillments`);
    await expect(page.getByRole("button", { name: "Request fulfillment" })).toHaveCount(0);
    await context.close();
  });
});
