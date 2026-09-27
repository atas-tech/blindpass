import { expect, test, type Browser, type Page } from "@playwright/test";
import { axeViolations, horizontalOverflow } from "./support/a11y.js";
import { nodeKeys, submitEnrollment } from "./support/node.js";
import { ADMIN, AdminClient, Stack } from "./support/stack.js";

async function signIn(browser: Browser, stack: Stack, username: string, password: string, options: { bypassCSP?: boolean; width?: number } = {}) {
  const context = await browser.newContext({ bypassCSP: options.bypassCSP ?? false, ...(options.width ? { viewport: { width: options.width, height: 844 } } : {}) });
  const page = await context.newPage();
  const consoleText: string[] = [];
  page.on("console", (message) => consoleText.push(message.text()));
  await page.goto(`${stack.consoleUrl}/login`);
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).not.toHaveURL(/\/login/);
  return { context, page, consoleText };
}

/** Create an enrollment in the UI and return the one-use token from the reveal. */
async function createEnrollment(page: Page, stack: Stack, name: string): Promise<string> {
  await page.goto(`${stack.consoleUrl}/enrollments`);
  await page.getByRole("button", { name: "New enrollment" }).click();
  const dialog = page.getByRole("dialog", { name: "Create an enrollment" });
  await dialog.getByLabel("Node name").fill(name);
  await dialog.getByRole("button", { name: "Create and show token" }).click();
  const reveal = page.getByRole("dialog", { name: `Enrollment token for ${name}` });
  const token = ((await reveal.locator("[data-secret-reveal]").textContent()) ?? "").trim();
  expect(token.length).toBeGreaterThanOrEqual(48);
  const command = await reveal.locator(".command-block").textContent();
  expect(command).toMatch(/blindpass-node enroll --controller .+ --issuer-fingerprint [a-f0-9]{64} --token-stdin/);
  expect(command).not.toContain(token);
  await reveal.getByLabel("I stored this value somewhere safe").check();
  await reveal.getByRole("button", { name: "Done" }).click();
  await expect(reveal).toBeHidden();
  return token;
}

test.describe("fleet against the controller", () => {
  let stack: Stack;
  let admin: AdminClient;
  let operatorPassword: string;
  let viewerPassword: string;

  test.beforeAll(async () => {
    stack = await Stack.start({});
    admin = new AdminClient(stack);
    await admin.bootstrap();
    operatorPassword = (await admin.createOperator("e2e-operator", "operator", "E2E Operator")).password;
    viewerPassword = (await admin.createOperator("e2e-viewer", "viewer", "E2E Viewer")).password;
  });
  test.afterAll(async () => stack?.stop());

  test("P04-E01 / I10: enroll a node with the exact fingerprint, register a workload, edit and revoke it", async ({ browser }) => {
    const { context, page, consoleText } = await signIn(browser, stack, ADMIN.username, ADMIN.password, { bypassCSP: true });
    const token = await createEnrollment(page, stack, "e2e-build-01");
    const issuer = await admin.call<{ issuer_pub: string }>("GET", "/api/v3/capabilities");
    expect(issuer.body.issuer_pub).toBeTruthy();

    const keys = nodeKeys();
    const submitted = await submitEnrollment(stack.controllerUrl, token, keys);
    expect(submitted.status).toBe(201);
    // The token is spent: a second machine can't reuse it.
    expect((await submitEnrollment(stack.controllerUrl, token)).status).not.toBe(201);

    const row = page.locator('[data-enrollment="e2e-build-01"]');
    await expect(row).toContainText("Needs review");
    await page.getByRole("button", { name: "Review enrollment e2e-build-01" }).click();
    const review = page.getByRole("dialog", { name: "Review e2e-build-01" });
    await expect(review).not.toContainText(keys.fingerprint.slice(0, 12));
    const approve = review.getByRole("button", { name: "Approve node" });
    await expect(approve).toBeDisabled();
    await review.getByLabel("Fingerprint printed by the node").fill(keys.fingerprint.replace(/.$/, keys.fingerprint.endsWith("0") ? "1" : "0"));
    await expect(review.getByText(/doesn't match the keys/)).toBeVisible();
    await expect(approve).toBeDisabled();
    await review.getByLabel("Fingerprint printed by the node").fill(keys.fingerprint.match(/.{4}/g)!.join(" "));
    await expect(review.getByText("Fingerprint matches", { exact: true })).toBeVisible();
    expect(await axeViolations(page, "dialog[open]")).toEqual([]);
    await approve.click();
    await expect(page.getByText("e2e-build-01 approved as a node")).toBeVisible();
    await expect(row).toContainText("Approved");

    await page.getByRole("link", { name: "Nodes" }).first().click();
    const nodeRow = page.locator('[data-node="e2e-build-01"]');
    await expect(nodeRow).toContainText("Offline");
    await expect(nodeRow).toContainText("Not yet");
    await nodeRow.getByRole("link", { name: "e2e-build-01", exact: true }).click();
    await expect(page.getByRole("heading", { name: "e2e-build-01", level: 1 })).toBeVisible();
    const nodeId = decodeURIComponent(page.url().split("/nodes/")[1]!);
    await expect(page.locator(".fingerprint").first()).toBeVisible();
    expect(await axeViolations(page, ".main")).toEqual([]);

    await page.getByRole("link", { name: "Register workload" }).click();
    const create = page.getByRole("dialog", { name: "Register a workload" });
    await expect(create.getByLabel("Node")).toHaveValue(nodeId);
    await create.getByLabel("Workload name").fill("deploy");
    await create.getByLabel("systemd unit").fill("deploy.service");
    await create.getByLabel("Runs as").fill("Deploy User");
    await create.getByRole("button", { name: "Register" }).click();
    await expect(create.getByText(/Use a lowercase account name/)).toBeVisible();
    await create.getByLabel("Runs as").fill("deploy");
    await create.getByRole("button", { name: "Register" }).click();
    await expect(page.getByRole("heading", { name: "deploy", level: 1 })).toBeVisible();
    await expect(page.getByText("Registration v1")).toBeVisible();

    // A second active workload on the same unit is refused with a useful message.
    await page.goto(`${stack.consoleUrl}/workloads?node=${encodeURIComponent(nodeId)}&new=1`);
    const again = page.getByRole("dialog", { name: "Register a workload" });
    await again.getByLabel("Workload name").fill("deploy-2");
    await again.getByLabel("systemd unit").fill("deploy.service");
    await again.getByLabel("Runs as").fill("deploy");
    await again.getByRole("button", { name: "Register" }).click();
    await expect(again.getByText("An active workload on this node already uses this unit.")).toBeVisible();
    await again.getByRole("button", { name: "Cancel" }).click();

    await page.locator('[data-workload="deploy"]').getByRole("link", { name: "deploy", exact: true }).click();
    await page.getByRole("button", { name: "Edit registration" }).click();
    await page.getByLabel("Runs as").fill("uid:1500");
    await expect(page.getByText("This changes who can receive grants")).toBeVisible();
    await page.getByRole("button", { name: "Save registration" }).click();
    await expect(page.getByText("Registration saved as v2")).toBeVisible();
    await expect(page.locator(".kv")).toContainText("uid:1500");

    await page.getByRole("button", { name: "Revoke", exact: true }).click();
    const revoke = page.getByRole("dialog", { name: "Revoke deploy?" });
    await expect(revoke).toContainText("deploy.service · uid:1500");
    await revoke.getByRole("button", { name: "Revoke workload" }).click();
    await expect(page.getByRole("heading", { name: "deploy", level: 1 })).toBeVisible();
    await expect(page.locator(".page-meta")).toContainText("Revoked");
    const workloads = await admin.call<{ items: Array<{ name: string; status: string; account: string }> }>("GET", `/api/v3/workloads?node_id=${encodeURIComponent(nodeId)}`);
    expect(workloads.body.items.find((item) => item.name === "deploy")).toMatchObject({ status: "revoked", account: "uid:1500" });

    expect(await page.content()).not.toContain(token);
    expect(consoleText.join("\n")).not.toContain(token);
    await context.close();
  });

  test("I10: a mismatched fingerprint can't be approved and the enrollment is rejected", async ({ browser }) => {
    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password);
    const token = await createEnrollment(page, stack, "e2e-intruder");
    const attacker = await submitEnrollment(stack.controllerUrl, token);
    expect(attacker.status).toBe(201);
    const expected = nodeKeys().fingerprint; // what the real machine would have printed
    await page.getByRole("button", { name: "Review enrollment e2e-intruder" }).click();
    const review = page.getByRole("dialog", { name: "Review e2e-intruder" });
    await review.getByLabel("Fingerprint printed by the node").fill(expected);
    await expect(review.getByText(/doesn't match the keys/)).toBeVisible();
    await expect(review.getByRole("button", { name: "Approve node" })).toBeDisabled();
    await review.getByRole("button", { name: "Reject" }).click();
    await review.getByRole("button", { name: "Confirm reject" }).click();
    await expect(page.locator('[data-enrollment="e2e-intruder"]')).toContainText("Rejected");
    const nodes = await admin.call<{ items: Array<{ name: string }> }>("GET", "/api/v3/nodes");
    expect(nodes.body.items.some((item) => item.name === "e2e-intruder")).toBe(false);
    await context.close();
  });

  test("E10: revoking an offline node queues the revocation and says who may still hold grants", async ({ browser }) => {
    const created = await admin.call<{ id: string; token: string }>("POST", "/api/v3/enrollments", { name: "e2e-retire" });
    const keys = nodeKeys();
    await submitEnrollment(stack.controllerUrl, created.body.token, keys);
    const current = await admin.call<{ version: number }>("GET", `/api/v3/enrollments/${created.body.id}`);
    const approved = await admin.call<{ id: string }>("POST", `/api/v3/enrollments/${created.body.id}/approve`, { expected_fingerprint: keys.fingerprint, expected_version: current.body.version });
    expect(approved.status).toBe(200);

    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password);
    await page.goto(`${stack.consoleUrl}/nodes/${encodeURIComponent(approved.body.id)}`);
    await page.getByRole("button", { name: "Revoke node" }).click();
    const dialog = page.getByRole("dialog", { name: "Revoke e2e-retire?" });
    const submit = dialog.getByRole("button", { name: "Revoke node" });
    await expect(submit).toBeDisabled();
    await dialog.getByLabel("Type e2e-retire to confirm").fill("e2e-retir");
    await expect(submit).toBeDisabled();
    await dialog.getByLabel("Type e2e-retire to confirm").fill("e2e-retire");
    await submit.click();
    await expect(page.locator(".notice", { hasText: "Revocation queued" })).toBeVisible();
    await expect(page.getByText(/may still hold grants/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Revoke node" })).toHaveCount(0);
    const node = await admin.call<{ status: string; revocation_pending: boolean }>("GET", `/api/v3/nodes/${encodeURIComponent(approved.body.id)}`);
    expect(node.body).toMatchObject({ status: "revoked", revocation_pending: true });
    await context.close();
  });

  test("fleet policy: an admin sets socket delivery to need named approvers; the stored rules match exactly", async ({ browser }) => {
    const before = await admin.call<{ version: number; rules: Array<Record<string, unknown>> }>("GET", "/api/v3/policies");
    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password, { bypassCSP: true });
    await page.goto(`${stack.consoleUrl}/policy/fleet`);
    const socket = page.getByRole("radiogroup", { name: "Decision for Socket" });
    await socket.getByRole("radio", { name: "Needs approval" }).click();
    await page.locator('[data-mode="socket"]').getByLabel("Approvers").fill("e2e-operator");
    await page.locator('[data-mode="socket"]').getByLabel("Longest grant").fill("300");
    await page.getByRole("button", { name: "Save fleet policy" }).click();
    await expect(page.getByText(`Fleet policy saved as version ${before.body.version + 1}`)).toBeVisible();
    expect(await axeViolations(page, ".main")).toEqual([]);
    const after = await admin.call<{ version: number; rules: Array<Record<string, unknown>> }>("GET", "/api/v3/policies");
    expect(after.body.rules.find((rule) => rule.mode === "socket")).toEqual({ id: "noop-marker-socket", action: "noop.marker", mode: "socket", decision: "pending_approval", approval_required: true, max_ttl_seconds: 300, approver_ids: ["e2e-operator"] });
    await context.close();
  });

  test("DR-E02 / P04-I05: operators see empty grant and operation lists as empty; viewers are refused by UI and API alike", async ({ browser }) => {
    const operator = await signIn(browser, stack, "e2e-operator", operatorPassword);
    // The same names DR-E25 expects to be absent when fleet.v3 is off.
    for (const name of ["Nodes", "Enrollments", "Workloads", "Grants", "Operations", "Fleet policy"]) {
      await expect(operator.page.getByRole("navigation").getByRole("link", { name })).toHaveCount(1);
    }
    await operator.page.goto(`${stack.consoleUrl}/grants`);
    await expect(operator.page.getByText("No grants")).toBeVisible();
    await operator.page.goto(`${stack.consoleUrl}/operations`);
    await expect(operator.page.getByText("No operations", { exact: true })).toBeVisible();
    await operator.page.goto(`${stack.consoleUrl}/enrollments`);
    await expect(operator.page.getByRole("button", { name: "New enrollment" })).toHaveCount(0);
    await operator.context.close();

    const viewer = await signIn(browser, stack, "e2e-viewer", viewerPassword);
    await expect(viewer.page.getByRole("link", { name: "Grants" })).toHaveCount(0);
    await expect(viewer.page.getByRole("link", { name: "Nodes" }).first()).toBeVisible();
    await viewer.page.goto(`${stack.consoleUrl}/grants`);
    await expect(viewer.page.getByRole("heading", { name: "Your role can't open this page" })).toBeVisible();
    const statuses = await viewer.page.evaluate(async () => Promise.all(["/api/v3/grants", "/api/v3/operations", "/api/v3/approvals"].map(async (path) => (await fetch(path)).status)));
    expect(statuses).toEqual([403, 403, 403]);
    await viewer.page.goto(`${stack.consoleUrl}/nodes`);
    await expect(viewer.page.getByRole("heading", { name: "Nodes you trust." })).toBeVisible();
    await viewer.context.close();
  });

  test("DR-E07: fleet screens fit a phone without horizontal overflow", async ({ browser }) => {
    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password, { width: 390 });
    for (const path of ["/enrollments", "/nodes", "/workloads", "/policy/fleet", "/grants", "/operations"]) {
      await page.goto(`${stack.consoleUrl}${path}`);
      await expect(page.locator("[data-page-title]")).toBeVisible();
      expect(await horizontalOverflow(page), path).toBeLessThanOrEqual(0);
    }
    await context.close();
  });
});

test.describe("controller without fleet.v3", () => {
  let stack: Stack;
  test.beforeAll(async () => {
    stack = await Stack.start({ fleet: false });
    await new AdminClient(stack).bootstrap();
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E25: fleet navigation and routes are absent and no fleet API is called", async ({ browser }) => {
    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password);
    const fleetCalls: string[] = [];
    page.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (/^\/api\/v3\/(nodes|enrollments|workloads|grants|operations|policies)/.test(path)) fleetCalls.push(path);
    });
    for (const name of ["Nodes", "Enrollments", "Workloads", "Grants", "Operations", "Fleet policy"]) {
      await expect(page.getByRole("navigation").getByRole("link", { name })).toHaveCount(0);
    }
    await expect(page.getByTestId("stat-nodes")).toHaveCount(0);
    for (const path of ["/nodes", "/enrollments", "/workloads", "/grants", "/operations", "/policy/fleet"]) {
      await page.goto(`${stack.consoleUrl}${path}`);
      await expect(page.getByRole("heading", { name: "This page doesn't exist" })).toBeVisible();
    }
    await page.goto(`${stack.consoleUrl}/approvals`);
    await expect(page.locator("[data-page-title]")).toBeVisible();
    expect(fleetCalls).toEqual([]);
    await context.close();
  });
});
