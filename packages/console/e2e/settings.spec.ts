import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { axeViolations, horizontalOverflow } from "./support/a11y.js";
import { ADMIN, AdminClient, Stack } from "./support/stack.js";

async function signIn(browser: Browser, stack: Stack, username: string, password: string, options: { bypassCSP?: boolean; width?: number } = {}): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ bypassCSP: options.bypassCSP ?? false, ...(options.width ? { viewport: { width: options.width, height: 844 } } : {}) });
  const page = await context.newPage();
  await page.goto(`${stack.consoleUrl}/login`);
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).not.toHaveURL(/\/login(\?|$)/);
  return { context, page };
}

/** Call the controller from the page with its own cookies and CSRF token. Writes send a schema-valid body. */
async function apiStatus(page: Page, path: string, method = "GET", body: unknown = {}): Promise<number> {
  return page.evaluate(
    async ({ path, method, body }) => {
      const csrf = document.cookie.split("; ").find((part) => part.startsWith("bp_csrf="))?.slice(8) ?? "";
      const response = await fetch(path, { method, headers: method === "GET" ? {} : { "x-csrf-token": decodeURIComponent(csrf), "content-type": "application/json" }, body: method === "GET" ? undefined : JSON.stringify(body) });
      return response.status;
    },
    { path, method, body }
  );
}

async function closeReveal(page: Page, title: string): Promise<string> {
  const reveal = page.getByRole("dialog", { name: title });
  const value = ((await reveal.locator("[data-secret-reveal]").textContent()) ?? "").trim();
  await reveal.getByLabel("I stored this value somewhere safe").check();
  await reveal.getByRole("button", { name: "Done" }).click();
  await expect(reveal).toBeHidden();
  return value;
}

test.describe("settings and operators against the controller", () => {
  let stack: Stack;
  let admin: AdminClient;

  test.beforeAll(async () => {
    stack = await Stack.start({});
    admin = new AdminClient(stack);
    await admin.bootstrap();
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E17: the only administrator can't demote or remove themselves; the controls explain why and the API agrees", async ({ browser }) => {
    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password, { bypassCSP: true });
    await page.getByRole("link", { name: "Operators" }).click();
    await expect(page).toHaveURL(/\/settings\/operators$/);
    const row = page.locator(`[data-operator="${ADMIN.username}"]`);
    await expect(row.getByText("You", { exact: true })).toBeVisible();
    for (const name of [`Change role for ${ADMIN.username}`, `Remove ${ADMIN.username}`]) {
      const button = row.getByRole("button", { name });
      await expect(button).toBeDisabled();
      await expect(button).toHaveAccessibleDescription("The controller must keep one active administrator. Make another operator an administrator first.");
    }
    await expect(row.getByRole("button", { name: `Reset password for ${ADMIN.username}` })).toHaveAccessibleDescription("Change your own password in Settings.");
    expect(await axeViolations(page, ".main")).toEqual([]);
    const me = await admin.call<{ operator: { id: string } }>("GET", "/api/v3/admin/session");
    expect((await admin.call("PATCH", `/api/v3/admin/operators/${me.body.operator.id}`, { role: "viewer" })).status).toBe(409);
    expect((await admin.call("DELETE", `/api/v3/admin/operators/${me.body.operator.id}`)).status).toBe(409);
    await context.close();
  });

  test("DR-E17: add an operator, refuse a duplicate, and the temporary password forces a change at first sign-in", async ({ browser }) => {
    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password, { bypassCSP: true });
    const pageText: string[] = [];
    page.on("console", (message) => pageText.push(message.text()));
    await page.goto(`${stack.consoleUrl}/settings/operators`);
    await page.getByRole("button", { name: "Add operator" }).click();
    let dialog = page.getByRole("dialog", { name: "Add an operator" });
    // Cancel leaves nothing behind.
    await dialog.getByLabel("Username").fill("e2e-cancelled");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();

    await page.getByRole("button", { name: "Add operator" }).click();
    dialog = page.getByRole("dialog", { name: "Add an operator" });
    await expect(dialog.getByLabel("Username")).toHaveValue("");
    await dialog.getByLabel("Username").fill("no");
    await dialog.getByLabel("Display name").fill("Sam Operator");
    await dialog.getByRole("button", { name: "Create and show password" }).click();
    await expect(dialog.getByText(/Use 3–128 letters/)).toBeVisible();
    await dialog.getByLabel("Username").fill("e2e-sam");
    await dialog.getByRole("radio", { name: /^Operator/ }).check();
    expect(await axeViolations(page, "dialog[open]")).toEqual([]);
    await dialog.getByRole("button", { name: "Create and show password" }).click();
    const temporary = await closeReveal(page, "Temporary password for e2e-sam");
    expect(temporary.length).toBeGreaterThanOrEqual(24);
    await expect(page.locator('[data-operator="e2e-sam"]')).toContainText("Operator");
    expect(await page.content()).not.toContain(temporary);
    expect(pageText.join("\n")).not.toContain(temporary);

    // The same username again is refused in place.
    await page.getByRole("button", { name: "Add operator" }).click();
    dialog = page.getByRole("dialog", { name: "Add an operator" });
    await dialog.getByLabel("Username").fill("e2e-sam");
    await dialog.getByLabel("Display name").fill("Another Sam");
    await dialog.getByRole("button", { name: "Create and show password" }).click();
    await expect(dialog.getByText("An operator with this username already exists.")).toBeVisible();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    const listed = await admin.call<{ items: Array<{ username: string }> }>("GET", "/api/v3/admin/operators");
    expect(listed.body.items.map((item) => item.username).sort()).toEqual([ADMIN.username, "e2e-sam"].sort());

    const sam = await browser.newContext();
    const samPage = await sam.newPage();
    await samPage.goto(`${stack.consoleUrl}/login`);
    await samPage.getByLabel("Username").fill("e2e-sam");
    await samPage.getByLabel("Password", { exact: true }).fill(temporary);
    await samPage.getByRole("button", { name: "Sign in" }).click();
    await expect(samPage).toHaveURL(/\/change-password$/);
    await samPage.getByLabel("Current password").fill(temporary);
    await samPage.getByLabel("New password", { exact: true }).fill("sam-chose-this-passphrase");
    await samPage.getByLabel("Confirm new password").fill("sam-chose-this-passphrase");
    await samPage.getByRole("button", { name: "Set password and continue" }).click();
    await expect(samPage).toHaveURL(`${stack.consoleUrl}/`);
    await expect(samPage.getByRole("link", { name: /Approvals/ })).toBeVisible();
    await expect(samPage.getByRole("link", { name: "Operators" })).toHaveCount(0);
    await sam.close();
    await context.close();
  });

  test("DR-E17 / DR-E02: role changes reach open sessions at once; reset and remove end them", async ({ browser }) => {
    const target = await admin.createOperator("e2e-rina", "operator", "Rina Operator");
    const rina = await signIn(browser, stack, "e2e-rina", target.password);
    expect(await apiStatus(rina.page, "/api/v3/approvals")).toBe(200);

    const { context, page } = await signIn(browser, stack, ADMIN.username, ADMIN.password);
    await page.goto(`${stack.consoleUrl}/settings/operators`);
    await page.getByRole("button", { name: "Change role for e2e-rina" }).click();
    const roleDialog = page.getByRole("dialog", { name: "Change e2e-rina's role" });
    await expect(roleDialog.getByRole("button", { name: "Change role" })).toBeDisabled();
    await roleDialog.getByRole("radio", { name: /^Viewer/ }).check();
    await expect(roleDialog.getByText("Operator → Viewer")).toBeVisible();
    await roleDialog.getByRole("button", { name: "Change role" }).click();
    await expect(page.getByText("e2e-rina is now Viewer")).toBeVisible();
    await expect(page.locator('[data-operator="e2e-rina"]')).toContainText("Viewer");
    // Rina's open session is now a viewer's: the API refuses and the UI follows on navigation.
    expect(await apiStatus(rina.page, "/api/v3/approvals")).toBe(403);
    await rina.page.goto(`${stack.consoleUrl}/approvals`);
    await expect(rina.page.getByRole("heading", { name: "Your role can't open this page" })).toBeVisible();

    await page.getByRole("button", { name: "Reset password for e2e-rina" }).click();
    await page.getByRole("dialog", { name: "Reset e2e-rina's password?" }).getByRole("button", { name: "Reset and show password" }).click();
    const temporary = await closeReveal(page, "Temporary password for e2e-rina");
    expect(await apiStatus(rina.page, "/api/v3/admin/session")).toBe(401);
    await rina.page.goto(`${stack.consoleUrl}/`);
    await expect(rina.page).toHaveURL(/\/login/);
    await rina.context.close();

    const again = await browser.newContext();
    const againPage = await again.newPage();
    await againPage.goto(`${stack.consoleUrl}/login`);
    await againPage.getByLabel("Username").fill("e2e-rina");
    await againPage.getByLabel("Password", { exact: true }).fill(temporary);
    await againPage.getByRole("button", { name: "Sign in" }).click();
    await expect(againPage).toHaveURL(/\/change-password$/);

    await page.getByRole("button", { name: "Remove e2e-rina" }).click();
    const remove = page.getByRole("dialog", { name: "Remove e2e-rina?" });
    await expect(remove).toContainText(target.id);
    await expect(remove.getByRole("button", { name: "Cancel" })).toBeFocused();
    await remove.getByRole("button", { name: "Remove operator" }).click();
    await expect(page.getByText("e2e-rina removed")).toBeVisible();
    await expect(page.locator('[data-operator="e2e-rina"]')).toHaveCount(0);
    expect(await apiStatus(againPage, "/api/v3/admin/session")).toBe(401);
    await again.close();
    await context.close();
  });

  test("DR-E17: with a second administrator the first can step down, loses the page and keeps a working session", async ({ browser }) => {
    const second = await admin.createOperator("e2e-second-admin", "admin", "Second Admin");
    const self = await admin.createOperator("e2e-stepping-down", "admin", "Stepping Down");
    const { context, page } = await signIn(browser, stack, "e2e-stepping-down", self.password);
    await page.goto(`${stack.consoleUrl}/settings/operators`);
    await expect(page.locator('[data-operator="e2e-stepping-down"]').getByRole("button", { name: "Remove e2e-stepping-down" })).toHaveAccessibleDescription("Ask another administrator to remove your account.");
    await page.getByRole("button", { name: "Change role for e2e-stepping-down" }).click();
    const dialog = page.getByRole("dialog", { name: "Change your role" });
    await dialog.getByRole("radio", { name: /^Operator/ }).check();
    await expect(dialog.getByText(/You'll lose access to operator management/)).toBeVisible();
    await dialog.getByRole("button", { name: "Change role" }).click();
    await expect(page).toHaveURL(`${stack.consoleUrl}/`);
    await expect(page.getByRole("link", { name: "Operators" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: /Approvals/ })).toBeVisible();
    expect(await apiStatus(page, "/api/v3/admin/operators")).toBe(403);
    await context.close();
    expect((await admin.call("DELETE", `/api/v3/admin/operators/${second.id}`)).status).toBe(204);
    expect((await admin.call("DELETE", `/api/v3/admin/operators/${self.id}`)).status).toBe(204);
  });

  test("DR-E02: operators and viewers can't reach operator management by URL or API", async ({ browser }) => {
    for (const role of ["operator", "viewer"] as const) {
      const account = await admin.createOperator(`e2e-${role}-probe`, role);
      const { context, page } = await signIn(browser, stack, `e2e-${role}-probe`, account.password);
      await expect(page.getByRole("link", { name: "Operators" })).toHaveCount(0);
      await page.goto(`${stack.consoleUrl}/settings/operators`);
      await expect(page.getByRole("heading", { name: "Your role can't open this page" })).toBeVisible();
      expect(await apiStatus(page, "/api/v3/admin/operators")).toBe(403);
      expect(await apiStatus(page, "/api/v3/admin/operators", "POST", { username: `e2e-${role}-made`, display_name: "Escalation probe", role: "admin", password: "probe-password-long-enough" })).toBe(403);
      await page.goto(`${stack.consoleUrl}/settings`);
      await expect(page.getByRole("link", { name: "Manage operators" })).toHaveCount(0);
      await expect(page.getByText("Only an administrator can change names and roles.")).toBeVisible();
      await context.close();
    }
  });

  test("DR-E20: profile, locale and password settings save, cancel, validate and persist across reload", async ({ browser }) => {
    const account = await admin.createOperator("e2e-settings-admin", "admin", "Settings Admin");
    const { context, page } = await signIn(browser, stack, "e2e-settings-admin", account.password, { bypassCSP: true });
    await page.goto(`${stack.consoleUrl}/settings`);
    await expect(page.getByText(/billing|plan|upgrade/i)).toHaveCount(0);
    const profile = page.locator("section", { has: page.getByRole("heading", { name: "Profile" }) });

    await profile.getByRole("button", { name: "Edit display name" }).click();
    await profile.getByLabel("Display name").fill("Discarded Name");
    await profile.getByRole("button", { name: "Cancel" }).click();
    await expect(profile).toContainText("Settings Admin");
    await profile.getByRole("button", { name: "Edit display name" }).click();
    await profile.getByLabel("Display name").fill("   ");
    await profile.getByRole("button", { name: "Save" }).click();
    await expect(profile.locator(".field-error")).toBeVisible();
    await profile.getByLabel("Display name").fill("Settings Admin Renamed");
    await profile.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Display name saved")).toBeVisible();
    await page.reload();
    await expect(profile).toContainText("Settings Admin Renamed");

    await page.getByRole("radiogroup", { name: "Language" }).getByRole("radio", { name: "Tiếng Việt" }).click();
    await expect(page.getByRole("heading", { name: "Cài đặt", level: 1 })).toBeVisible();
    await page.reload();
    await expect(page.getByRole("heading", { name: "Cài đặt", level: 1 })).toBeVisible();
    await page.getByRole("radiogroup", { name: "Ngôn ngữ" }).getByRole("radio", { name: "English" }).click();
    await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();

    const password = page.locator("section", { has: page.getByRole("heading", { name: "Password" }) });
    await password.getByLabel("Current password").fill("not-the-current-password");
    await password.getByLabel("New password", { exact: true }).fill("settings-admin-next-passphrase");
    await password.getByLabel("Confirm new password").fill("settings-admin-next-passphrase");
    await password.getByRole("button", { name: /password/i }).last().click();
    await expect(password.getByRole("alert")).toBeVisible();
    await expect(password.getByLabel("Current password")).toHaveAttribute("type", "password");
    await password.getByLabel("Current password").fill(account.password);
    await password.getByRole("button", { name: /password/i }).last().click();
    await expect(page.getByText("Password changed")).toBeVisible();
    expect(await page.content()).not.toContain("settings-admin-next-passphrase");
    await context.close();

    const relogin = await signIn(browser, stack, "e2e-settings-admin", "settings-admin-next-passphrase");
    await expect(relogin.page.getByRole("heading", { level: 1 })).toBeVisible();
    await relogin.context.close();
  });

  test("DR-E01 (P04 route matrix): hosted-product paths show the unavailable page with a docs link, signed in or not, and never redirect", async ({ browser }) => {
    const anonymous = await browser.newContext();
    const page = await anonymous.newPage();
    const external: string[] = [];
    page.on("request", (request) => {
      if (!request.url().startsWith(stack.consoleUrl)) external.push(request.url());
    });
    for (const path of ["/billing", "/analytics", "/signup", "/verify", "/public/offers/1", "/forgot-password", "/members"]) {
      await page.goto(`${stack.consoleUrl}${path}`);
      await expect(page.getByTestId("unavailable-feature")).toBeVisible();
      await expect(page).toHaveURL(`${stack.consoleUrl}${path}`);
      await expect(page.getByRole("heading", { name: "Not available in this product" })).toBeVisible();
      const docs = page.getByRole("link", { name: "What changed in BlindPass" });
      await expect(docs).toHaveAttribute("href", /docs-vault\/blob\/main\/blindpass\/docs\/product\/Roadmap\.md#freeze-register$/);
      await expect(docs).toHaveAttribute("rel", "noreferrer noopener");
      await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
    }
    expect(external).toEqual([]);
    await anonymous.close();

    const { context, page: signedIn } = await signIn(browser, stack, ADMIN.username, ADMIN.password, { width: 390 });
    await signedIn.goto(`${stack.consoleUrl}/billing`);
    await expect(signedIn.getByTestId("unavailable-feature")).toBeVisible();
    await expect(signedIn.getByRole("link", { name: "Back to overview" })).toBeVisible();
    expect(await horizontalOverflow(signedIn)).toBeLessThanOrEqual(0);
    await signedIn.goto(`${stack.consoleUrl}/settings/operators`);
    expect(await horizontalOverflow(signedIn)).toBeLessThanOrEqual(0);
    await context.close();
  });
});
