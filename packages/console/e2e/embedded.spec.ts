// P04-E04: the controller serves the console and the secret-input page from
// the assets it was built with (P04-D9). Build the workspace first, then the
// controller, so it embeds packages/console/dist and
// packages/browser-ui/dist-embedded.
//
// The rollback test swaps in the previous controller artifact when
// BLINDPASS_E2E_PREVIOUS_CONTROLLER_BIN points at it (a build without
// embedded assets, e.g. of the commit before slice 13).
import { expect, test, type BrowserContext, type Page, type Request } from "@playwright/test";
import { access } from "node:fs/promises";
import { ADMIN, AdminClient } from "./support/stack.js";
import { InputStack } from "./support/input.js";

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const IMMUTABLE = "public, max-age=31536000, immutable";

interface Watched {
  context: BrowserContext;
  page: Page;
  requests: Request[];
  violations: () => Promise<string[]>;
  errors: string[];
}

/** A page that records every request, CSP violation and script error. */
async function watch(context: BrowserContext): Promise<Watched> {
  await context.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = seen;
    document.addEventListener("securitypolicyviolation", (event) => seen.push(`${event.violatedDirective} ${event.blockedURI}`));
  });
  const page = await context.newPage();
  const requests: Request[] = [];
  const errors: string[] = [];
  page.on("request", (request) => requests.push(request));
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error" && /Content Security Policy|Refused to/i.test(message.text())) errors.push(message.text());
  });
  return { context, page, requests, errors, violations: () => page.evaluate(() => (window as unknown as { __csp: string[] }).__csp) };
}

async function signIn(page: Page, url: string) {
  await page.goto(`${url}/login`);
  await page.getByLabel("Username").fill(ADMIN.username);
  await page.getByLabel("Password", { exact: true }).fill(ADMIN.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).not.toHaveURL(/\/login/);
}

test.describe("embedded console and input page", () => {
  let input: InputStack;
  let admin: AdminClient;

  test.beforeAll(async () => {
    input = await InputStack.start({ embedded: true });
    const shell = await fetch(`${input.stack.controllerUrl}/approvals`, { headers: { accept: "text/html" } });
    if (shell.status !== 200 || !(await shell.text()).includes('<div id="root"></div>')) {
      throw new Error("the controller binary does not embed the console: run `npm run build`, then rebuild blindpass-controller");
    }
    admin = new AdminClient(input.stack);
    await admin.bootstrap();
  });
  test.afterAll(async () => input?.stop());

  test("P04-E04 / DR-E26: deep links load and survive a reload on the controller origin under the P04 CSP header, with no violations and self-hosted Inter", async ({ browser }) => {
    const { context, page, requests, errors, violations } = await watch(await browser.newContext());
    const origin = input.stack.controllerUrl;

    // A deep link before sign-in goes to login and comes back afterwards.
    await page.goto(`${origin}/settings/operators`);
    await expect(page).toHaveURL(/\/login\?next=/);
    await page.getByLabel("Username").fill(ADMIN.username);
    await page.getByLabel("Password", { exact: true }).fill(ADMIN.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(`${origin}/settings/operators`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

    for (const route of ["/approvals", "/nodes", "/audit", "/settings/operators", "/settings"]) {
      const response = await page.goto(`${origin}${route}`);
      expect(response?.status(), route).toBe(200);
      const headers = response!.headers();
      expect(headers["content-security-policy"], route).toBe(CSP);
      expect(headers["cache-control"], route).toBe("no-store");
      expect(headers["x-frame-options"], route).toBe("DENY");
      expect(headers["cross-origin-opener-policy"], route).toBe("same-origin");
      expect(headers["referrer-policy"], route).toBe("no-referrer");
      await expect(page.getByRole("heading", { level: 1 }), route).toBeVisible();
      await page.reload();
      await expect(page, route).toHaveURL(`${origin}${route}`);
      await expect(page.getByRole("heading", { level: 1 }), route).toBeVisible();
    }

    // An unknown path inside a console section is the console's not-found
    // view; any other unknown path keeps the controller's JSON 404 (CT18).
    const unknown = await page.goto(`${origin}/settings/no-such-tab`);
    expect(unknown?.status()).toBe(200);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    const outside = await page.request.get(`${origin}/no-such-screen`);
    expect(outside.status()).toBe(404);
    expect(outside.headers()["content-type"]).toBe("application/json");

    // Inter comes from the controller origin, and the page actually uses it.
    expect(await page.evaluate(async () => {
      await document.fonts.ready;
      return [...document.fonts].some((face) => face.family.replace(/"/g, "").startsWith("Inter") && face.status === "loaded");
    })).toBe(true);
    expect(requests.some((request) => new URL(request.url()).origin === origin && /\/assets\/Inter[^/]*\.woff2$/.test(new URL(request.url()).pathname))).toBe(true);

    expect(await violations()).toEqual([]);
    expect(errors).toEqual([]);
    const foreign = requests.map((request) => new URL(request.url())).filter((url) => url.origin !== origin && url.protocol !== "data:");
    expect(foreign.map(String)).toEqual([]);
    await context.close();
  });

  test("P04-E04: hashed assets are immutable, misses are 404 and API paths never return the shell", async ({ request }) => {
    const origin = input.stack.controllerUrl;
    const html = await (await request.get(`${origin}/`)).text();
    const assets = [...html.matchAll(/(?:src|href)="(\/assets\/[^"]+)"/g)].map((match) => match[1]!);
    expect(assets.length).toBeGreaterThan(0);
    for (const asset of assets) {
      const response = await request.get(`${origin}${asset}`);
      expect(response.status(), asset).toBe(200);
      expect(response.headers()["cache-control"], asset).toBe(IMMUTABLE);
      expect(response.headers()["x-content-type-options"], asset).toBe("nosniff");
    }
    for (const missing of ["/assets/index-missing.js", "/input/assets/missing.js", "/robots.txt"]) {
      expect((await request.get(`${origin}${missing}`)).status(), missing).toBe(404);
    }
    const api = await request.get(`${origin}/api/v3/no-such-route`, { headers: { accept: "text/html" } });
    expect(api.status()).toBe(404);
    expect(await api.text()).not.toContain("<!doctype html>");
    expect((await request.post(`${origin}/approvals`)).status()).toBe(405);
  });

  test("P04-E04 / SI-E03: a signed link opens the embedded input page on the controller origin; it seals, submits and the requester opens the value once", async ({ browser }) => {
    const origin = input.stack.controllerUrl;
    const request = await input.createRequest("Embedded input canary");
    expect(new URL(request.secretUrl).origin).toBe(origin);
    expect(new URL(request.secretUrl).pathname).toBe("/");
    const { context, page, requests, errors, violations } = await watch(await browser.newContext());
    const response = await page.goto(request.secretUrl);
    expect(response?.headers()["content-security-policy"]).toBe(CSP);
    expect(response?.headers()["cache-control"]).toBe("no-store");
    await expect(page.getByTestId("status")).toHaveText("Awaiting input");
    await expect(page.getByTestId("confirmation-code")).toHaveText(request.confirmationCode);
    await expect(page.getByTestId("request-description")).toHaveText("Embedded input canary");
    const value = "dummy-embedded-input-canary";
    await page.getByTestId("secret-input").fill(value);
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("outcome-title")).toHaveText("Your part is done.");

    expect(await violations()).toEqual([]);
    expect(errors).toEqual([]);
    expect(requests.every((entry) => new URL(entry.url()).origin === origin)).toBe(true);
    expect(requests.some((entry) => new URL(entry.url()).pathname.startsWith("/input/assets/"))).toBe(true);
    const retrieved = await input.retrieve(request.requestId);
    expect(retrieved.status).toBe(200);
    expect(Buffer.from(await request.open(retrieved.body!)).toString("utf8")).toBe(value);
    expect((await input.retrieve(request.requestId)).status).toBe(410);
    await context.close();
  });

  test("P04-E04 / DR-E23 rollback: the previous controller artifact runs on the same database and the embedded build comes back with sessions intact", async ({ browser }) => {
    const previous = process.env.BLINDPASS_E2E_PREVIOUS_CONTROLLER_BIN;
    test.skip(!previous, "set BLINDPASS_E2E_PREVIOUS_CONTROLLER_BIN to the previous controller build to test rollback");
    await access(previous!);
    const origin = input.stack.controllerUrl;
    const operator = await admin.createOperator("e2e-rollback", "operator");
    const context = await browser.newContext();
    const page = await context.newPage();
    await signIn(page, origin);

    // Roll back: the previous artifact has no embedded UI, but reads the same
    // database, keeps the browser session and the operator created above.
    await input.stack.stopController();
    await input.stack.startController(previous);
    expect((await page.request.get(`${origin}/api/v3/admin/session`)).status()).toBe(200);
    expect((await fetch(`${origin}/approvals`)).status).toBe(404);
    const rolledBack = new AdminClient(input.stack);
    expect(await rolledBack.login("e2e-rollback", operator.password)).toBe(200);

    // Roll forward again: the console is back, still signed in.
    await input.stack.stopController();
    await input.stack.startController();
    await page.goto(`${origin}/approvals`);
    await expect(page).toHaveURL(`${origin}/approvals`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await context.close();
  });
});
