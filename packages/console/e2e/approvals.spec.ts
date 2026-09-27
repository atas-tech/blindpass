import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { axeViolations, horizontalOverflow } from "./support/a11y.js";
import { ADMIN, AGENT_IDS, AdminClient, Stack } from "./support/stack.js";

const OPERATOR = { username: "e2e-operator", display_name: "E2E Operator" };
const HOSTILE_PURPOSE = 'Ship the release — <img src=x onerror="window.__pwned=1"> **approve now** [docs](javascript:alert(1))\nSecond line from the requester.';

interface Seeded {
  agentToken: string;
}

async function seed(stack: Stack): Promise<Seeded> {
  const keys = await stack.seedAgents([AGENT_IDS.requester, AGENT_IDS.fulfiller]);
  return { agentToken: await stack.agentToken(keys[AGENT_IDS.requester]!) };
}

async function signedIn(browser: Browser, stack: Stack, username: string, password: string, options: { bypassCSP?: boolean } = {}): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ bypassCSP: options.bypassCSP ?? false });
  const page = await context.newPage();
  await page.goto(`${stack.consoleUrl}/login`);
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).not.toHaveURL(/\/login/);
  return { context, page };
}

async function confirm(page: Page, verb: "Approve" | "Reject") {
  const action = page.getByRole("button", { name: verb, exact: true });
  await expect(action).toBeEnabled();
  await action.click();
  const dialog = page.getByRole("dialog", { name: new RegExp(`^${verb}`) });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Cancel" })).toBeFocused();
  await dialog.getByRole("button", { name: verb, exact: true }).click();
}

test.describe("approvals against the controller", () => {
  let stack: Stack;
  let admin: AdminClient;
  let operatorPassword: string;
  let viewerPassword: string;
  let seeded: Seeded;

  test.beforeAll(async () => {
    stack = await Stack.start({});
    admin = new AdminClient(stack);
    await admin.bootstrap();
    operatorPassword = (await admin.createOperator(OPERATOR.username, "operator", OPERATOR.display_name)).password;
    viewerPassword = (await admin.createOperator("e2e-viewer", "viewer", "E2E Viewer")).password;
    seeded = await seed(stack);
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E08 / DR-E09: overview total matches the controller; approve and reject record exactly the chosen reference", async ({ browser }) => {
    const first = await stack.requestExchange(seeded.agentToken, HOSTILE_PURPOSE);
    const second = await stack.requestExchange(seeded.agentToken, "Nightly report export");
    const firstRef = first.policy.approval_reference!;
    const secondRef = second.policy.approval_reference!;
    const count = await admin.call<{ count: number }>("GET", "/api/v3/approvals/count");

    const { context, page } = await signedIn(browser, stack, ADMIN.username, ADMIN.password, { bypassCSP: true });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await expect(page.getByTestId("stat-pending")).toContainText(String(count.body.count));
    await expect(page.getByRole("link", { name: /^Approvals/ }).first()).toContainText(String(count.body.count));

    await page.getByRole("link", { name: "Review approvals" }).click();
    await expect(page).toHaveURL(/\/approvals$/);
    await page.locator(`[data-approval="${firstRef}"]`).click();
    await expect(page).toHaveURL(new RegExp(`/approvals/exchange/${firstRef}$`));
    await expect(page.getByRole("heading", { name: `${AGENT_IDS.requester} asks for e2e.approval_api_key` })).toBeVisible();

    // Requester text is inert and fenced off from the verified block.
    const untrusted = page.locator(".untrusted");
    await expect(untrusted).toContainText("<img src=x");
    await expect(untrusted).toContainText("Second line from the requester.");
    expect(await page.locator(".approval-detail img, .approval-detail a[href^='javascript']").count()).toBe(0);
    expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
    await expect(page.locator(".verified")).not.toContainText("approve now");
    expect(await axeViolations(page, ".main")).toEqual([]);

    await confirm(page, "Approve");
    await expect(page.locator(".notice-title", { hasText: "Approved" })).toBeVisible();
    await expect(page.getByText(/Nothing has been delivered yet/)).toBeVisible();
    await expect(page.locator("[data-approval-status]")).toHaveAttribute("data-approval-status", "approved");

    const approved = await admin.call<{ status: string }>("GET", `/api/v3/approvals/${firstRef}`);
    expect(approved.body.status).toBe("approved");
    const untouched = await admin.call<{ status: string }>("GET", `/api/v3/approvals/${secondRef}`);
    expect(untouched.body.status).toBe("pending");
    await expect(page.getByTestId("approval-pill").first()).toContainText(String(count.body.count - 1));

    await page.locator(`[data-approval="${secondRef}"]`).click();
    await confirm(page, "Reject");
    await expect(page.locator(".notice-title", { hasText: "Rejected" })).toBeVisible();
    expect((await admin.call<{ status: string }>("GET", `/api/v3/approvals/${secondRef}`)).body.status).toBe("rejected");

    // Queue filters show the authoritative outcome.
    await page.goto(`${stack.consoleUrl}/approvals?status=approved`);
    await expect(page.locator(`[data-approval="${firstRef}"]`)).toBeVisible();
    await expect(page.locator(`[data-approval="${secondRef}"]`)).toHaveCount(0);
    expect(errors).toEqual([]);
    await context.close();
  });

  test("DR-E11: a competing decision in another session is reported, not overwritten", async ({ browser }) => {
    const request = await stack.requestExchange(seeded.agentToken, "Competing decision fixture");
    const ref = request.policy.approval_reference!;
    const adminSession = await signedIn(browser, stack, ADMIN.username, ADMIN.password);
    const operatorSession = await signedIn(browser, stack, OPERATOR.username, operatorPassword);
    await adminSession.page.goto(`${stack.consoleUrl}/approvals/exchange/${ref}`);
    await operatorSession.page.goto(`${stack.consoleUrl}/approvals/exchange/${ref}`);
    await expect(adminSession.page.getByRole("button", { name: "Approve", exact: true })).toBeEnabled();

    // The operator rejects first.
    await confirm(operatorSession.page, "Reject");
    await expect(operatorSession.page.locator(".notice-title", { hasText: "Rejected" })).toBeVisible();

    // The admin's stale view asks to approve; the console re-reads first and refuses to send.
    const action = adminSession.page.getByRole("button", { name: "Approve", exact: true });
    if (await action.isEnabled()) {
      await action.click();
      const dialog = adminSession.page.getByRole("dialog", { name: /^Approve/ });
      await dialog.getByRole("button", { name: "Approve", exact: true }).click();
      await expect(adminSession.page.getByText("This approval changed")).toBeVisible();
    }
    await expect(adminSession.page.locator("[data-approval-status]")).toHaveAttribute("data-approval-status", "rejected");
    await expect(adminSession.page.locator(".notice-title", { hasText: /^Approved$/ })).toHaveCount(0);
    expect((await admin.call<{ status: string }>("GET", `/api/v3/approvals/${ref}`)).body.status).toBe("rejected");
    await adminSession.context.close();
    await operatorSession.context.close();
  });

  test("DR-E10 / P04-I02: a viewer cannot open approvals and a direct decision is refused by the controller", async ({ browser }) => {
    const request = await stack.requestExchange(seeded.agentToken, "Viewer fixture");
    const ref = request.policy.approval_reference!;
    const { context, page } = await signedIn(browser, stack, "e2e-viewer", viewerPassword);
    await expect(page.getByRole("link", { name: /^Approvals/ })).toHaveCount(0);
    await page.goto(`${stack.consoleUrl}/approvals/exchange/${ref}`);
    await expect(page.getByRole("heading", { name: "Your role can't open this page" })).toBeVisible();
    const status = await page.evaluate(async (reference) => {
      const csrf = document.cookie.split("; ").find((part) => part.startsWith("bp_csrf="))?.slice(8) ?? "";
      const response = await fetch(`/api/v3/approvals/${reference}/approve`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-csrf-token": csrf, "idempotency-key": "viewer-direct-write-0001", "if-match": '"1"' },
        body: JSON.stringify({ expected_status: "pending", expected_version: 1 })
      });
      return response.status;
    }, ref);
    expect(status).toBe(403);
    expect((await admin.call<{ status: string }>("GET", `/api/v3/approvals/${ref}`)).body.status).toBe("pending");
    await context.close();
  });

  test("P04-I02: a session that ends mid-decision records nothing and returns to the approval after sign-in", async ({ browser }) => {
    const request = await stack.requestExchange(seeded.agentToken, "Session expiry fixture");
    const ref = request.policy.approval_reference!;
    const { context, page } = await signedIn(browser, stack, ADMIN.username, ADMIN.password);
    await page.goto(`${stack.consoleUrl}/approvals/exchange/${ref}`);
    await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeEnabled();
    const cookies = await context.cookies();
    const csrf = cookies.find((cookie) => cookie.name === "bp_csrf")?.value ?? "";
    const session = cookies.find((cookie) => cookie.name === "bp_session")?.value ?? "";
    await fetch(`${stack.controllerUrl}/api/v3/admin/session/logout`, {
      method: "POST",
      headers: { origin: stack.consoleUrl, cookie: `bp_session=${session}; bp_csrf=${csrf}`, "x-csrf-token": csrf }
    });
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: /^Approve/ });
    await dialog.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/login\\?next=${encodeURIComponent(`/approvals/exchange/${ref}`)}$`));
    expect((await admin.call<{ status: string }>("GET", `/api/v3/approvals/${ref}`)).body.status).toBe("pending");
    await page.getByLabel("Username").fill(ADMIN.username);
    await page.getByLabel("Password", { exact: true }).fill(ADMIN.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(new RegExp(`/approvals/exchange/${ref}$`));
    await expect(page.locator("[data-approval-status]")).toHaveAttribute("data-approval-status", "pending");
    await context.close();
  });

  test("P04-I02 lost response: the reply is dropped after the controller applied it; the console reconciles without a second decision", async ({ browser }) => {
    const request = await stack.requestExchange(seeded.agentToken, "Lost response after apply");
    const ref = request.policy.approval_reference!;
    const { context, page } = await signedIn(browser, stack, ADMIN.username, ADMIN.password);
    let decisions = 0;
    await page.route(`**/api/v3/approvals/${ref}/approve`, async (route) => {
      decisions += 1;
      await route.fetch();
      await route.abort("connectionreset");
    });
    await page.goto(`${stack.consoleUrl}/approvals/exchange/${ref}`);
    await confirm(page, "Approve");
    await expect(page.getByText("We couldn't confirm the decision")).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "Check status" }).click();
    await expect(page.getByText("The controller has a decision")).toBeVisible();
    await expect(page.locator("[data-approval-status]")).toHaveAttribute("data-approval-status", "approved");
    expect(decisions).toBe(1);
    await context.close();
  });

  test("P04-I02 lost response: the request never arrived; the same decision is resent with the same key and applied once", async ({ browser }) => {
    const request = await stack.requestExchange(seeded.agentToken, "Lost response before apply");
    const ref = request.policy.approval_reference!;
    const { context, page } = await signedIn(browser, stack, ADMIN.username, ADMIN.password);
    const keys: string[] = [];
    await page.route(`**/api/v3/approvals/${ref}/approve`, async (route) => {
      keys.push(route.request().headers()["idempotency-key"] ?? "");
      if (keys.length === 1) return route.abort("connectionreset");
      return route.continue();
    });
    await page.goto(`${stack.consoleUrl}/approvals/exchange/${ref}`);
    await confirm(page, "Approve");
    await page.getByRole("button", { name: "Check status" }).click();
    await expect(page.getByText("Still pending")).toBeVisible();
    await page.getByRole("button", { name: "Send the same decision again" }).click();
    await expect(page.locator(".notice-title", { hasText: "Approved" })).toBeVisible();
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
    // A replay of the same key is answered from the recorded decision, not re-applied.
    const replay = await admin.call<{ status: string }>("POST", `/api/v3/approvals/${ref}/approve`, { expected_status: "pending", expected_version: 1 }, { "idempotency-key": keys[0]!, "if-match": '"1"' });
    expect([200, 409]).toContain(replay.status);
    const audit = await admin.call<{ items: Array<{ event: string; resource_id: string | null }> }>("GET", "/api/v3/admin/audit?limit=100");
    expect(audit.body.items.filter((item) => item.event === "exchange_approved" && item.resource_id === ref).length).toBeLessThanOrEqual(1);
    await context.close();
  });

  test("DR-E03 / DR-E07: queue and detail stack on a phone without horizontal overflow", async ({ browser }) => {
    const request = await stack.requestExchange(seeded.agentToken, `Long purpose ${"without spaces ".repeat(3)}${"x".repeat(180)}`);
    const ref = request.policy.approval_reference!;
    const context = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true, bypassCSP: true });
    const page = await context.newPage();
    await page.goto(`${stack.consoleUrl}/login`);
    await page.getByLabel("Username").fill(ADMIN.username);
    await page.getByLabel("Password", { exact: true }).fill(ADMIN.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByTestId("stat-pending")).toBeVisible();
    expect(await horizontalOverflow(page)).toBeLessThanOrEqual(0);
    await page.goto(`${stack.consoleUrl}/approvals`);
    await expect(page.getByRole("list", { name: "Approval queue" })).toBeVisible();
    await page.locator(`[data-approval="${ref}"]`).click();
    await expect(page.getByRole("list", { name: "Approval queue" })).toBeHidden();
    await expect(page.getByRole("link", { name: "Back to queue" })).toBeVisible();
    expect(await horizontalOverflow(page)).toBeLessThanOrEqual(0);
    expect(await axeViolations(page, ".main")).toEqual([]);
    await page.screenshot({ path: test.info().outputPath("approval-detail-390.png"), fullPage: true });
    await context.close();
  });

  test("O05: bidi overrides, terminal escapes and zero-width characters in a purpose are shown as code points and can't reorder the verified facts", async ({ browser }) => {
    const spoof = "Rotate \u202Etxt.yek_ipa\u202C now \u001b[2J\u001b[32mAPPROVED\u001b[0m zero\u200Bwidth";
    const request = await stack.requestExchange(seeded.agentToken, spoof);
    const ref = request.policy.approval_reference!;
    const { context, page } = await signedIn(browser, stack, ADMIN.username, ADMIN.password, { bypassCSP: true });
    await page.goto(`${stack.consoleUrl}/approvals/exchange/${ref}`);
    await expect(page.getByRole("heading", { name: `${AGENT_IDS.requester} asks for e2e.approval_api_key` })).toBeVisible();
    const quote = page.locator(".untrusted-text");
    await expect(quote).toHaveText("Rotate ⟨U+202E⟩txt.yek_ipa⟨U+202C⟩ now ⟨U+001B⟩[2J⟨U+001B⟩[32mAPPROVED⟨U+001B⟩[0m zero⟨U+200B⟩width");
    expect(await quote.evaluate((element) => getComputedStyle(element).unicodeBidi)).toBe("isolate");
    await expect(quote).toHaveAttribute("dir", "auto");
    // The raw characters never reach the page as text.
    expect(await page.evaluate(() => /[\u202A-\u202E\u2066-\u2069\u200B-\u200F\u001b]/.test(document.body.innerText))).toBe(false);
    await context.close();
  });
});

test.describe("approval expiry", () => {
  let stack: Stack;
  let admin: AdminClient;
  let seeded: Seeded;
  test.beforeAll(async () => {
    stack = await Stack.start({ approvalTtlSeconds: 4 });
    admin = new AdminClient(stack);
    await admin.bootstrap();
    seeded = await seed(stack);
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E11: a request that expires while open cannot be approved and says why", async ({ browser }) => {
    const request = await stack.requestExchange(seeded.agentToken, "Expiring fixture");
    const ref = request.policy.approval_reference!;
    const { context, page } = await signedIn(browser, stack, ADMIN.username, ADMIN.password);
    await page.goto(`${stack.consoleUrl}/approvals/exchange/${ref}`);
    await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeEnabled();
    await page.waitForTimeout(4_500);
    const action = page.getByRole("button", { name: "Approve", exact: true });
    if (await action.isVisible()) {
      if (await action.isEnabled()) {
        await action.click();
        await page.getByRole("dialog", { name: /^Approve/ }).getByRole("button", { name: "Approve", exact: true }).click();
      }
    }
    await expect(page.getByText("This approval is no longer available").first()).toBeVisible();
    await expect(page.locator(".notice-title", { hasText: /^Approved$/ })).toHaveCount(0);
    const read = await admin.call("GET", `/api/v3/approvals/${ref}`);
    expect(read.status).toBe(404);
    await context.close();
  });
});
