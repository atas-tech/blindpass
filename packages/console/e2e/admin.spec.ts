import { expect, test, type Browser, type Page } from "@playwright/test";
import { axeViolations } from "./support/a11y.js";
import { ADMIN, AGENT_IDS, AdminClient, SECRET_NAMES, Stack } from "./support/stack.js";

async function signIn(browser: Browser, stack: Stack, username: string, password: string, bypassCSP = false) {
  const context = await browser.newContext({ bypassCSP });
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

async function readReveal(page: Page, title: string): Promise<string> {
  const reveal = page.getByRole("dialog", { name: title });
  await expect(reveal).toBeVisible();
  const key = (await reveal.locator("[data-secret-reveal]").textContent())?.trim() ?? "";
  expect(key.length).toBeGreaterThan(20);
  await expect(reveal.getByRole("button", { name: "Done" })).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(reveal).toBeVisible();
  await reveal.getByLabel("I stored this value somewhere safe").check();
  await reveal.getByRole("button", { name: "Done" }).click();
  await expect(reveal).toBeHidden();
  return key;
}

async function tokenStatus(stack: Stack, key: string): Promise<number> {
  const response = await fetch(`${stack.controllerUrl}/api/v2/agents/token`, { method: "POST", headers: { authorization: `Bearer ${key}` } });
  return response.status;
}

test.describe("administration against the controller", () => {
  let stack: Stack;
  let admin: AdminClient;
  let operatorPassword: string;

  test.beforeAll(async () => {
    stack = await Stack.start({});
    admin = new AdminClient(stack);
    await admin.bootstrap();
    operatorPassword = (await admin.createOperator("e2e-operator", "operator", "E2E Operator")).password;
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E12 / DR-E13 / DR-I05: enroll, rotate and revoke an agent; each key is revealed once and works only while current", async ({ browser }) => {
    const { context, page, consoleText } = await signIn(browser, stack, ADMIN.username, ADMIN.password, true);
    await page.goto(`${stack.consoleUrl}/agents`);
    await page.getByRole("button", { name: "Enroll agent" }).click();
    const dialog = page.getByRole("dialog", { name: "Enroll an agent" });
    await dialog.getByLabel(/Agent ID/).fill("e2e-build-agent");
    await dialog.getByLabel("Display name").fill("Build agent");
    await dialog.getByRole("button", { name: "Enroll and show key" }).click();
    const bootstrapKey = await readReveal(page, "Bootstrap key for e2e-build-agent");
    expect(await tokenStatus(stack, bootstrapKey)).toBe(200);
    const row = page.locator('[data-agent="e2e-build-agent"]');
    await expect(row).toContainText("Active");
    expect(await axeViolations(page, ".main")).toEqual([]);

    // Duplicate IDs are refused with a useful message.
    await page.getByRole("button", { name: "Enroll agent" }).click();
    await dialog.getByLabel(/Agent ID/).fill("e2e-build-agent");
    await dialog.getByLabel("Display name").fill("Again");
    await dialog.getByRole("button", { name: "Enroll and show key" }).click();
    await expect(dialog.getByText("An agent with this ID already exists.")).toBeVisible();
    await dialog.getByRole("button", { name: "Cancel" }).click();

    await page.getByRole("button", { name: "Rotate the key for e2e-build-agent" }).click();
    await page.getByRole("dialog", { name: "Rotate the key for e2e-build-agent?" }).getByRole("button", { name: "Rotate and show key" }).click();
    const replacement = await readReveal(page, "Replacement key for e2e-build-agent");
    expect(replacement).not.toBe(bootstrapKey);
    expect(await tokenStatus(stack, bootstrapKey)).toBe(401);
    expect(await tokenStatus(stack, replacement)).toBe(200);

    await page.getByRole("button", { name: "Revoke e2e-build-agent" }).click();
    await page.getByRole("dialog", { name: "Revoke e2e-build-agent?" }).getByRole("button", { name: "Revoke agent" }).click();
    await expect(page.getByText("e2e-build-agent revoked")).toBeVisible();
    expect(await tokenStatus(stack, replacement)).toBe(401);
    await page.getByRole("radio", { name: /Revoked/ }).click();
    await expect(row).toContainText("Revoked");

    // Neither key survives the reveal: not in the page, storage, URL or console.
    await page.reload();
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    for (const key of [bootstrapKey, replacement]) {
      expect(await page.content()).not.toContain(key);
      expect(page.url()).not.toContain(key);
      expect(JSON.stringify(await page.evaluate(() => ({ ...localStorage, ...sessionStorage })))).not.toContain(key);
      expect(consoleText.join("\n")).not.toContain(key);
    }
    await context.close();
  });

  test("DR-E14: operator reads the policy; admin edits it, invalid rules are explained and the saved document round-trips", async ({ browser }) => {
    const before = await admin.call<{ version: number; policy: { exchange_policy: Array<Record<string, unknown>>; secret_registry: unknown[] } }>("GET", "/api/v3/admin/policy");
    const operator = await signIn(browser, stack, "e2e-operator", operatorPassword);
    await operator.page.goto(`${stack.consoleUrl}/policy`);
    await expect(operator.page.locator('[data-rule="e2e-approval"]')).toBeVisible();
    await expect(operator.page.getByText("Only administrators can change the exchange policy.")).toBeVisible();
    await expect(operator.page.getByRole("button", { name: "Edit policy" })).toHaveCount(0);
    await operator.context.close();

    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password, true);
    await page.goto(`${stack.consoleUrl}/policy`);
    await page.getByRole("button", { name: "Edit policy" }).click();
    await page.getByRole("button", { name: "Add rule" }).click();
    const added = page.locator(".rule-card").last();
    await added.getByLabel("Rule ID").fill("e2e-console-rule");
    await added.getByLabel("Secret").selectOption(SECRET_NAMES.allowed);
    await page.getByRole("button", { name: "Save policy" }).click();
    // pending_approval without approvers is refused by the controller.
    await expect(added.getByText("required for pending_approval")).toBeVisible();
    expect((await admin.call<{ version: number }>("GET", "/api/v3/admin/policy")).body.version).toBe(before.body.version);

    await added.getByLabel("Approvers").fill("e2e-admin\ne2e-operator");
    await added.getByLabel("Requesters").fill(AGENT_IDS.requester);
    await added.getByLabel("Rule ID").click();
    await page.getByRole("button", { name: "Save policy" }).click();
    await expect(page.getByText(`Policy saved as version ${before.body.version + 1}`)).toBeVisible();
    expect(await axeViolations(page, ".main")).toEqual([]);

    const after = await admin.call<{ version: number; policy: { exchange_policy: Array<Record<string, unknown>>; secret_registry: unknown[] } }>("GET", "/api/v3/admin/policy");
    expect(after.body.version).toBe(before.body.version + 1);
    expect(after.body.policy.secret_registry).toEqual(before.body.policy.secret_registry);
    expect(after.body.policy.exchange_policy.slice(0, before.body.policy.exchange_policy.length)).toEqual(before.body.policy.exchange_policy);
    expect(after.body.policy.exchange_policy.at(-1)).toEqual({
      ruleId: "e2e-console-rule",
      secretName: SECRET_NAMES.allowed,
      mode: "pending_approval",
      approverIds: ["e2e-admin", "e2e-operator"],
      requesterIds: [AGENT_IDS.requester]
    });
    await context.close();
  });

  test("DR-E14: a concurrent save is detected; the draft survives and saves on the new version only when chosen", async ({ browser }) => {
    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password);
    await page.goto(`${stack.consoleUrl}/policy`);
    await page.getByRole("button", { name: "Edit policy" }).click();
    const first = page.locator(".rule-card").first();
    await first.getByLabel("Reason shown to the requester").fill("Reviewed in the console");

    // Someone else saves meanwhile.
    const current = await admin.call<{ version: number; policy: { secret_registry: unknown[]; exchange_policy: unknown[] } }>("GET", "/api/v3/admin/policy");
    const concurrent = await admin.call<{ version: number }>(
      "PUT",
      "/api/v3/admin/policy",
      { secret_registry: current.body.policy.secret_registry, exchange_policy: [...current.body.policy.exchange_policy, { ruleId: "e2e-concurrent", secretName: SECRET_NAMES.allowed, mode: "deny" }] },
      { "if-match": `"${current.body.version}"` }
    );
    expect(concurrent.status).toBe(200);

    await page.getByRole("button", { name: "Save policy" }).click();
    const conflict = page.locator(".notice", { hasText: `Someone saved version ${concurrent.body.version}` });
    await expect(conflict).toBeVisible();
    await expect(conflict).toContainText("e2e-concurrent");
    expect((await admin.call<{ version: number }>("GET", "/api/v3/admin/policy")).body.version).toBe(concurrent.body.version);
    await conflict.getByRole("button", { name: /Keep my draft/ }).click();
    await page.getByRole("button", { name: "Save policy" }).click();
    await expect(page.getByText(`Policy saved as version ${concurrent.body.version + 1}`)).toBeVisible();
    const saved = await admin.call<{ policy: { exchange_policy: Array<Record<string, unknown>> } }>("GET", "/api/v3/admin/policy");
    // The operator chose their draft, which was based on the earlier rules: the concurrent rule is not silently merged in.
    expect(saved.body.policy.exchange_policy.some((rule) => rule.ruleId === "e2e-concurrent")).toBe(false);
    expect(saved.body.policy.exchange_policy[0]!.reason).toBe("Reviewed in the console");
    await context.close();
  });

  test("DR-E15: audit pages by cursor without gaps or duplicates and deep-links an exchange timeline", async ({ browser }) => {
    const keys = await stack.seedAgents([AGENT_IDS.requester, AGENT_IDS.fulfiller]);
    const token = await stack.agentToken(keys[AGENT_IDS.requester]!);
    let exchangeId = "";
    for (let index = 0; index < 60; index += 1) {
      const result = await stack.requestExchange(token, `Audit fixture ${index}`, SECRET_NAMES.allowed);
      exchangeId ||= result.exchange_id ?? "";
    }
    expect(exchangeId).not.toBe("");
    const expected: string[] = [];
    let cursor: string | null = null;
    do {
      const page: { body: { items: Array<{ id: string }>; next_cursor: string | null } } = await admin.call<{ items: Array<{ id: string }>; next_cursor: string | null }>("GET", `/api/v3/admin/audit?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
      expected.push(...page.body.items.map((item) => item.id));
      cursor = page.body.next_cursor;
    } while (cursor);
    expect(expected.length).toBeGreaterThan(50);

    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password, true);
    await page.goto(`${stack.consoleUrl}/audit`);
    const seen: string[] = [];
    for (;;) {
      await expect(page.locator("[data-audit]").first()).toBeVisible();
      seen.push(...(await page.locator("tr[data-audit]").evaluateAll((rows) => rows.map((row) => row.getAttribute("data-audit") ?? ""))));
      const older = page.getByRole("button", { name: "Older" });
      if (!(await older.isVisible()) || !(await older.isEnabled())) break;
      const firstBefore = await page.locator("tr[data-audit]").first().getAttribute("data-audit");
      await older.click();
      await expect(page.locator("tr[data-audit]").first()).not.toHaveAttribute("data-audit", firstBefore ?? "");
    }
    expect(new Set(seen).size).toBe(seen.length);
    expect(seen).toEqual(expected);
    expect(await axeViolations(page, ".main")).toEqual([]);

    await page.goto(`${stack.consoleUrl}/audit`);
    await page.getByLabel("Exchange ID").fill(exchangeId);
    await page.getByRole("button", { name: "Open timeline" }).click();
    await expect(page).toHaveURL(new RegExp(`/audit/exchange/${exchangeId}$`));
    await expect(page.locator(".timeline-item").first()).toContainText("Exchange requested");
    await page.reload();
    await expect(page.locator(".timeline-item").first()).toBeVisible();

    await page.goto(`${stack.consoleUrl}/audit/exchange/ex_does_not_exist`);
    await expect(page.getByText("No audit for this exchange")).toBeVisible();
    await context.close();
  });
});
