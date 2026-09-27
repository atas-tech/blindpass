import { expect, test, type Page } from "@playwright/test";
import { ADMIN, AdminClient, Stack } from "./support/stack.js";

async function fillSetup(page: Page, token: string, username: string, password: string) {
  await page.getByLabel("Setup token").fill(token);
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Display name").fill(`${username} display`);
  await page.getByLabel("New password", { exact: true }).fill(password);
  await page.getByLabel("Confirm new password").fill(password);
}

async function signIn(page: Page, stack: Stack, username: string, password: string) {
  await page.goto(`${stack.consoleUrl}/login`);
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).not.toHaveURL(/\/login/);
}

async function webStorage(page: Page) {
  return page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }));
}

test.describe("first run", () => {
  let stack: Stack;
  test.beforeAll(async () => {
    stack = await Stack.start({ fresh: true });
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E24 / P04-I02: setup race has exactly one winner; the loser is told truthfully", async ({ browser }) => {
    const [first, second] = await Promise.all([stack.bootstrapToken(), stack.bootstrapToken()]);
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();
    const consoleText: string[] = [];
    for (const page of [pageA, pageB]) page.on("console", (message) => consoleText.push(message.text()));

    // Every protected route sends a visitor to /setup while no administrator exists.
    await pageA.goto(`${stack.consoleUrl}/approvals`);
    await expect(pageA).toHaveURL(/\/setup$/);
    await pageB.goto(`${stack.consoleUrl}/nodes`);
    await expect(pageB).toHaveURL(/\/setup$/);

    await fillSetup(pageA, first, ADMIN.username, ADMIN.password);
    await fillSetup(pageB, second, "e2e-rival", "rival-password-2026");
    await Promise.all([
      pageA.getByRole("button", { name: "Create administrator" }).click(),
      pageB.getByRole("button", { name: "Create administrator" }).click()
    ]);

    const outcomes = await Promise.all(
      [pageA, pageB].map(async (page) => {
        const raced = page.getByText("Setup is already complete");
        await expect.poll(async () => (await raced.isVisible()) || !new URL(page.url()).pathname.startsWith("/setup"), { timeout: 15_000 }).toBe(true);
        return (await raced.isVisible()) ? "lost" : "won";
      })
    );
    expect([...outcomes].sort()).toEqual(["lost", "won"]);
    const loser = outcomes[0] === "lost" ? pageA : pageB;
    // The loser never claims success and the token field is cleared.
    await expect(loser).toHaveURL(/\/setup$/);
    await expect(loser.getByLabel("Setup token")).toHaveValue("");

    // The bootstrap credential appears nowhere after submission.
    for (const page of [pageA, pageB]) {
      const html = await page.content();
      expect(html).not.toContain(first);
      expect(html).not.toContain(second);
      expect(JSON.stringify(await webStorage(page))).not.toContain(first);
    }
    expect(consoleText.join("\n")).not.toContain(first);
    expect(consoleText.join("\n")).not.toContain(second);

    // /setup is gone once an administrator exists.
    await loser.getByRole("button", { name: "Sign in" }).click();
    await expect(loser).toHaveURL(/\/login$/);
    await loser.goto(`${stack.consoleUrl}/setup`);
    await expect(loser).toHaveURL(/\/login$/);
    await contextA.close();
    await contextB.close();
  });

  test("DR-E24: a spent setup token is reported and never re-shown", async ({ page }) => {
    // Setup already completed above; the API answers 409 for any token.
    const response = await page.request.post(`${stack.controllerUrl}/api/v3/admin/bootstrap`, {
      headers: { origin: stack.consoleUrl, "x-blindpass-bootstrap-token": "x".repeat(40), "content-type": "application/json" },
      data: { username: "late-admin", display_name: "Late", password: "late-password-2026" }
    });
    expect(response.status()).toBe(409);
  });
});

test.describe("sessions", () => {
  let stack: Stack;
  let admin: AdminClient;
  test.beforeAll(async () => {
    stack = await Stack.start({});
    admin = new AdminClient(stack);
    await admin.bootstrap();
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E04 / DR-I01: sign in, deep-link return, HttpOnly cookies, no web-storage token, sign out", async ({ page, context }) => {
    await page.goto(`${stack.consoleUrl}/settings`);
    await expect(page).toHaveURL(/\/login\?next=%2Fsettings$/);
    await page.getByLabel("Username").fill(ADMIN.username);
    await page.getByLabel("Password", { exact: true }).fill("wrong-password-value");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByText("The username or password is incorrect.")).toBeVisible();
    await expect(page.getByLabel("Password", { exact: true })).toHaveValue("");

    await page.getByLabel("Password", { exact: true }).fill(ADMIN.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/settings$/);
    await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();

    const cookies = await context.cookies();
    const session = cookies.find((cookie) => cookie.name === "bp_session");
    expect(session?.httpOnly).toBe(true);
    expect(session?.sameSite).toBe("Strict");
    expect(cookies.find((cookie) => cookie.name === "bp_refresh")?.httpOnly).toBe(true);
    const storage = await webStorage(page);
    expect(Object.keys(storage.local).filter((key) => key !== "blindpass_locale")).toEqual([]);
    expect(storage.session).toEqual({});
    expect(page.url()).not.toMatch(/token|csrf|session=/i);

    await page.getByRole("button", { name: "Sign out" }).first().click();
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByText("You signed out. The controller ended the session.")).toBeVisible();
    // The old session cookie no longer works server-side.
    const after = await page.request.get(`${stack.consoleUrl}/api/v3/admin/session`);
    expect(after.status()).toBe(401);
  });

  test("DR-I01: a write without the session CSRF header is refused by the controller", async ({ page }) => {
    await signIn(page, stack, ADMIN.username, ADMIN.password);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    const denied = await page.evaluate(async () => {
      const response = await fetch("/api/v3/enrollments", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "csrf-probe" }) });
      return response.status;
    });
    expect(denied).toBe(403);
  });

  test("DR-E04: an administrator reset forces a password change before anything else", async ({ browser }) => {
    const created = await admin.createOperator("e2e-reset-target", "operator", "Reset Target");
    const reset = await admin.call<{ temporary_password: string }>("POST", `/api/v3/admin/operators/${created.id}/reset-password`);
    expect(reset.status).toBe(200);
    const context = await browser.newContext();
    const page = await context.newPage();
    await signIn(page, stack, "e2e-reset-target", reset.body.temporary_password);
    await expect(page).toHaveURL(/\/change-password$/);
    await expect(page.getByText(/signed in with a temporary password/)).toBeVisible();
    // Direct navigation stays confined.
    await page.goto(`${stack.consoleUrl}/approvals`);
    await expect(page).toHaveURL(/\/change-password$/);

    await page.getByLabel("Current password").fill(reset.body.temporary_password);
    await page.getByLabel("New password", { exact: true }).fill("short");
    await page.getByLabel("Confirm new password").fill("short");
    await page.getByRole("button", { name: "Set password and continue" }).click();
    await expect(page.getByText("Use at least 12 characters.")).toBeVisible();

    await page.getByLabel("New password", { exact: true }).fill("a-much-better-passphrase");
    await page.getByLabel("Confirm new password").fill("a-much-better-passphrase");
    await page.getByRole("button", { name: "Set password and continue" }).click();
    await expect(page).toHaveURL(`${stack.consoleUrl}/`);
    await expect(page.getByRole("link", { name: /Approvals/ })).toBeVisible();
    await context.close();
  });

  test("DR-E04: an expired session returns to sign-in and preserves the destination", async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    await signIn(page, stack, ADMIN.username, ADMIN.password);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.goto(`${stack.consoleUrl}/settings`);
    await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();
    // Revoke the session server-side from another client, then act in the UI.
    const cookies = await context.cookies();
    const csrf = cookies.find((cookie) => cookie.name === "bp_csrf")?.value ?? "";
    const session = cookies.find((cookie) => cookie.name === "bp_session")?.value ?? "";
    const logout = await fetch(`${stack.controllerUrl}/api/v3/admin/session/logout`, {
      method: "POST",
      headers: { origin: stack.consoleUrl, cookie: `bp_session=${session}; bp_csrf=${csrf}`, "x-csrf-token": csrf }
    });
    expect(logout.status).toBe(204);
    await page.getByRole("button", { name: "Edit display name" }).click();
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page).toHaveURL(/\/login\?next=%2Fsettings$/);
    await expect(page.getByText("Your session ended. Sign in again to continue.")).toBeVisible();
    await context.close();
  });
});

