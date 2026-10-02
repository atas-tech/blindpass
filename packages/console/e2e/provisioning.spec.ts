// P05-PV06-S / P04-E03 / P05-E01 (GUI portion): operator-facing fleet Source
// provisioning, driven in Chromium against the REAL Rust controller (preview and
// embedded profiles; SQLite by default, PostgreSQL with BLINDPASS_E2E_POSTGRES_URL).
//
// Honest scope: this is the API-node-fixture variant. The node is a JavaScript
// fixture with generated keys that plays the controller's node HTTP contract
// (e2e/support/fleet-node.ts). There is no real broker, no blindpass-node
// process, no systemd identity, no Unix control socket and no Omarchy session.
// What is real: the controller (authority, offer ingestion, scoped link,
// metadata, ciphertext submit, signed delivery), the console React panel, the
// input page, the browser's HPKE and the operator's cookie/CSRF session.
import { expect, test, type Browser, type BrowserContext, type Page, type Request } from "@playwright/test";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { axeViolations, horizontalOverflow } from "./support/a11y.js";
import { openDelivery, type OfferFixture } from "./support/fleet-node.js";
import { DESTINATION, publishOffer, seedOperation, startWorld, type Actor, type SeededOperation, type World } from "./support/provisioning-world.js";
import { mentions, scanForCanary, scannerDetects } from "./support/scan.js";
import { ADMIN, Stack } from "./support/stack.js";

interface Watched {
  context: BrowserContext;
  requests: Request[];
  consoleText: string[];
  pageErrors: string[];
  violations: () => Promise<string[]>;
}

/** A context that records every request, console message, page error and CSP violation. */
async function watchedContext(browser: Browser, options: { bypassCSP?: boolean; width?: number; locale?: string } = {}): Promise<Watched> {
  const context = await browser.newContext({ bypassCSP: options.bypassCSP ?? false, ...(options.width ? { viewport: { width: options.width, height: 900 } } : {}) });
  await context.addInitScript((locale) => {
    const seen: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = seen;
    document.addEventListener("securitypolicyviolation", (event) => seen.push(`${event.violatedDirective} ${event.blockedURI}`));
    if (locale) {
      try {
        localStorage.setItem("blindpass_locale", locale);
      } catch {
        // storage unavailable: the page stays in English
      }
    }
  }, options.locale ?? null);
  const requests: Request[] = [];
  const consoleText: string[] = [];
  const pageErrors: string[] = [];
  context.on("request", (request) => requests.push(request));
  context.on("console", (message) => consoleText.push(`${message.type()}: ${message.text()}`));
  const watchPage = (page: Page) => page.on("pageerror", (error) => pageErrors.push(error.message));
  context.on("page", watchPage);
  return {
    context,
    requests,
    consoleText,
    pageErrors,
    violations: async () => {
      const found: string[] = [];
      for (const page of context.pages()) found.push(...(await page.evaluate(() => (window as unknown as { __csp?: string[] }).__csp ?? []).catch(() => [])));
      return found;
    }
  };
}

const SIGN_IN_LABELS = { en: { user: "Username", password: "Password", button: "Sign in" }, vi: { user: "Tên đăng nhập", password: "Mật khẩu", button: "Đăng nhập" } };

async function signIn(page: Page, stack: Stack, actor: Pick<Actor, "username" | "password">, locale: "en" | "vi" = "en") {
  const labels = SIGN_IN_LABELS[locale];
  await page.goto(`${stack.consoleUrl}/login`);
  await page.getByLabel(labels.user).fill(actor.username);
  await page.getByLabel(labels.password, { exact: true }).fill(actor.password);
  await page.getByRole("button", { name: labels.button, exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/);
}

async function openOperation(page: Page, stack: Stack, seeded: SeededOperation) {
  await page.goto(`${stack.consoleUrl}/operations/${encodeURIComponent(seeded.operationId)}`);
  await expect(page.getByRole("heading", { name: "Provide Source" })).toBeVisible();
}

const panel = (page: Page) => page.locator("section.provision-panel");

/** Click the console button and return the input page it opens in a new tab. */
async function openInputPage(context: BrowserContext, console: Page, name = "Provide Source"): Promise<Page> {
  const [input] = await Promise.all([context.waitForEvent("page"), panel(console).getByRole("button", { name, exact: true }).click()]);
  await input.waitForLoadState("domcontentloaded");
  return input;
}

const field = (page: Page) => page.getByTestId("secret-input");
const state = (page: Page) => page.getByTestId("status");
const title = (page: Page) => page.getByTestId("outcome-title");

async function expectInputReady(page: Page, seeded: SeededOperation) {
  await expect(state(page)).toHaveText("Awaiting input");
  await expect(page.getByTestId("fleet-purpose")).toHaveText(seeded.purpose);
  await expect(page.getByTestId("fleet-workload")).toHaveText(seeded.workloadName);
  await expect(page.getByTestId("fleet-unit")).toHaveText(DESTINATION.unit);
  await expect(page.getByTestId("fleet-credential")).toHaveText(DESTINATION.credential);
  await expect(page.getByTestId("fleet-expiry")).toContainText(/\d\d:\d\d remaining/);
}

/** The node's provisioning deliveries for one operation (the node inbox is shared by every test). */
async function deliveriesFor(world: World, seeded: SeededOperation) {
  const all = await world.node.deliveries();
  return all.filter((entry) => ((entry.envelope.body as { binding?: { grant?: { operation_id?: string } } }).binding?.grant?.operation_id ?? "") === seeded.operationId);
}

const linkRoute = (seeded: SeededOperation) => `/api/v3/admin/operations/${encodeURIComponent(seeded.operationId)}/provisioning-link`;
const SUBMIT_URL = /\/api\/v3\/fleet\/provisioning\/[a-f0-9]{64}\/submit\?sig=/;
const METADATA_URL = /\/api\/v3\/fleet\/provisioning\/[a-f0-9]{64}\/metadata\?sig=/;
const key = () => `e2e-link-${randomBytes(8).toString("hex")}`;

/** The input page's field contents, whichever of the two fields is showing. */
const typedValues = (page: Page) => page.evaluate(() => [...document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("[data-testid='secret-input'], [data-testid='secret-input-multi']")].map((element) => element.value).join(""));

const bytesOf = (text: string) => Buffer.from(new TextEncoder().encode(text)).toString("hex");

// Playwright's recorder stores the text the driver types (fill parameters) in the
// live trace, so tracing is off here: a trace would put the canary into an
// artifact through the harness, and the scan below could no longer prove that the
// product left none. Failures keep screenshots; the positive control in scan.ts
// shows the scanner does find a canary inside a trace archive.
test.use({ trace: "off" });

test.describe("fleet Source provisioning against the controller (API-node fixture)", () => {
  let stack: Stack;
  let world: World;

  test.beforeAll(async () => {
    stack = await Stack.start({});
    world = await startWorld(stack);
  });
  test.afterAll(async () => stack?.stop());

  test("P05-PV06-S / P04-E03 / P05-E01 GUI: the named owner provides a Source from the console and the node receives exactly the typed bytes, with the canary nowhere else", async ({ browser }, testInfo) => {
    test.setTimeout(180_000);
    const canary = `P05-GUI-${randomBytes(8).toString("hex")}`;
    // A leading space, a combining-free accented letter, CJK and an astral character, all kept exactly.
    const typed = ` ${canary} é漢字\u{1F511}`;
    expect(await scannerDetects(canary)).toHaveLength(10);

    const seeded = await seedOperation(world, "main journey");
    const watched = await watchedContext(browser);
    try {
      const console = await watched.context.newPage();
      await signIn(console, stack, world.owner);
      await openOperation(console, stack, seeded);

      // The grant is live but the node has not published its offer: nothing to do yet.
      await expect(panel(console).getByRole("status")).toContainText("Waiting for the node");
      await expect(panel(console).getByRole("button")).toHaveCount(0);

      // The node posts a JavaScript-signed offer; the controller accepts it (interop proof).
      const fixture = await publishOffer(world, seeded, 100_000);
      await expect(panel(console).getByRole("button", { name: "Provide Source", exact: true })).toBeVisible({ timeout: 15_000 });
      await expect(panel(console).locator(".countdown")).toBeVisible();

      const input = await openInputPage(watched.context, console);
      expect(await input.evaluate(() => window.opener)).toBeNull();
      expect(new URL(input.url()).pathname).toBe("/");
      expect(new URL(input.url()).searchParams.get("kind")).toBe("fleet");
      await expectInputReady(input, seeded);
      await expect(input.getByTestId("submit-btn")).toBeEnabled();

      // The console now reads the owner's link as issued and offers an idempotent reopen.
      await expect(panel(console).getByRole("button", { name: "Open the Source page again" })).toBeVisible({ timeout: 15_000 });

      await field(input).fill(typed);
      await expect(field(input)).toHaveValue(typed);
      await input.getByTestId("submit-btn").click();
      await expect(title(input)).toHaveText("Your part is done.", { timeout: 20_000 });
      await expect(state(input)).toHaveText("Submitted");
      await expect(field(input)).toHaveValue("");
      await expect(input.getByTestId("secret-input-multi")).toHaveValue("");

      // The node's inbox holds one controller-signed delivery that opens to the exact typed bytes.
      const deliveries = await deliveriesFor(world, seeded);
      expect(deliveries).toHaveLength(1);
      const opened = await openDelivery(fixture, deliveries[0]!);
      expect(Buffer.from(opened).toString("hex")).toBe(bytesOf(typed));
      expect(new TextDecoder().decode(opened).startsWith(" ")).toBe(true);

      // The console confirms receipt with no secret and no action.
      await expect(panel(console).getByText(/encrypted Source was received/)).toBeVisible({ timeout: 15_000 });
      await expect(panel(console).getByRole("button")).toHaveCount(0);

      // Exact retry is idempotent: replaying the very same ciphertext from the page answers 200 and enqueues nothing new.
      const submit = watched.requests.filter((request) => request.method() === "POST" && /\/api\/v3\/fleet\/provisioning\/[a-f0-9]{64}\/submit\?sig=/.test(request.url()));
      expect(submit).toHaveLength(1);
      const replayed = await input.evaluate(
        async ({ url, body }) => {
          const csrf = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("bp_csrf="))?.slice("bp_csrf=".length) ?? "";
          const response = await fetch(url, { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json", "x-csrf-token": csrf }, body });
          return response.status;
        },
        { url: submit[0]!.url(), body: submit[0]!.postData() ?? "" }
      );
      expect(replayed).toBe(200);
      expect(await deliveriesFor(world, seeded)).toHaveLength(1);

      // Reload recovery: the link, the cookie and the receipt bring back "Already submitted", never an open field.
      await input.reload();
      await expect(title(input)).toHaveText("Already submitted.");
      await expect(field(input)).toBeHidden();

      // ---- The canary is nowhere it shouldn't be.
      const sent = [...watched.requests];
      for (const request of sent) {
        expect(mentions(request.url(), canary), `URL ${request.method()} ${new URL(request.url()).pathname}`).toBe(false);
        expect(mentions(request.postData() ?? "", canary), `body of ${request.method()} ${new URL(request.url()).pathname}`).toBe(false);
        expect(request.url()).not.toContain("/api/v2/");
      }
      const post = submit[0]!;
      expect(Object.keys(JSON.parse(post.postData() ?? "{}")).sort()).toEqual(["ciphertext", "enc"]);
      const headers = await post.allHeaders();
      expect(headers["x-csrf-token"]).toBeTruthy();
      expect(headers["cookie"]).toContain("bp_session=");
      expect(post.url()).toMatch(/\/api\/v3\/fleet\/provisioning\/[a-f0-9]{64}\/submit\?sig=\d+\.[A-Za-z0-9_-]{43}$/);
      expect(post.url()).not.toContain(headers["x-csrf-token"]!);
      expect(watched.consoleText.filter((text) => mentions(text, canary))).toEqual([]);
      expect(watched.pageErrors.filter((text) => mentions(text, canary))).toEqual([]);
      expect(await watched.violations()).toEqual([]);
      for (const page of watched.context.pages()) {
        const storage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
        expect(mentions(storage, canary)).toBe(false);
        expect(mentions(await page.content(), canary)).toBe(false);
        expect(mentions(page.url(), canary)).toBe(false);
      }
      const screenshot = testInfo.outputPath("after-submit.png");
      await input.screenshot({ path: screenshot });

      // Fail-closed scan of every Playwright artifact and of the controller's own state.
      const artifacts = await scanForCanary([path.resolve(path.dirname(testInfo.outputDir), "..")], canary);
      expect(artifacts.files).toBeGreaterThan(0);
      expect(artifacts.findings).toEqual([]);
      if (!stack.usesPostgres) {
        const controller = await scanForCanary([stack.dataDirectory], canary);
        expect(controller.files).toBeGreaterThan(0);
        expect(controller.findings).toEqual([]);
      }
      expect(mentions(stack.controllerLog(), canary)).toBe(false);
      await testInfo.attach("canary-scan", { contentType: "application/json", body: JSON.stringify({ artifactFiles: artifacts.files, artifactArchives: artifacts.archives, sqliteScanned: !stack.usesPostgres, controllerLogBytes: stack.controllerLog().length }) });
    } finally {
      await watched.context.close();
    }
  });

  test("P05-PV06-S roles: only the approving operator can provide; a second operator sees the state with no action, and viewers, administrators and anonymous callers are refused", async ({ browser }) => {
    test.setTimeout(180_000);
    const seeded = await seedOperation(world, "roles");
    await publishOffer(world, seeded, 100_000);

    // API: the link route belongs to the approver alone.
    for (const [name, client] of [["other operator", world.other.client], ["administrator", world.admin], ["viewer", world.viewer.client]] as const) {
      const refused = await client.call("POST", linkRoute(seeded), undefined, { "idempotency-key": key() });
      expect(refused.status, `${name} link`).toBe(403);
      expect(JSON.stringify(refused.body)).not.toMatch(/input_path|metadata_sig|submit_sig|kind=fleet/);
    }
    expect((await world.viewer.client.call("GET", `/api/v3/operations/${seeded.operationId}`)).status).toBe(403);
    const asOther = await world.other.client.call<{ provisioning: { state: string; can_provide: boolean } }>("GET", `/api/v3/operations/${seeded.operationId}`);
    expect(asOther.body.provisioning).toMatchObject({ state: "offer_ready", can_provide: false });
    expect((await world.node.deliveries()).filter((entry) => JSON.stringify(entry).includes(seeded.operationId))).toHaveLength(0);

    // Console, second operator: the state and the offer clock, but no action.
    const otherWatch = await watchedContext(browser);
    try {
      const page = await otherWatch.context.newPage();
      await signIn(page, stack, world.other);
      await openOperation(page, stack, seeded);
      await expect(panel(page).locator(".countdown")).toBeVisible();
      await expect(panel(page).getByText(/Only the operator who approved this request can provide its Source/)).toBeVisible();
      await expect(panel(page).getByRole("button")).toHaveCount(0);
      expect(otherWatch.requests.filter((request) => request.url().includes("/provisioning-link"))).toHaveLength(0);
    } finally {
      await otherWatch.context.close();
    }

    // Console, viewer: the route is role-gated and no panel is rendered.
    const viewerWatch = await watchedContext(browser);
    try {
      const page = await viewerWatch.context.newPage();
      await signIn(page, stack, world.viewer);
      await page.goto(`${stack.consoleUrl}/operations/${encodeURIComponent(seeded.operationId)}`);
      await expect(page.getByRole("heading", { name: "Your role can't open this page" })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Provide Source" })).toHaveCount(0);
    } finally {
      await viewerWatch.context.close();
    }

    // The approver opens the link; every other session that holds it is turned away.
    const issued = await world.owner.client.call<{ input_path: string }>("POST", linkRoute(seeded), undefined, { "idempotency-key": key() });
    expect(issued.status).toBe(201);
    const inputUrl = `${stack.consoleUrl}${issued.body.input_path}`;
    const sessions: Array<[string, { username: string; password: string } | null]> = [["other operator", world.other], ["administrator", ADMIN], ["anonymous", null]];
    for (const [name, actor] of sessions) {
      const watched = await watchedContext(browser);
      try {
        const page = await watched.context.newPage();
        if (actor) await signIn(page, stack, actor);
        await page.goto(inputUrl);
        await expect(title(page), name).toHaveText("Sign in as the named operator.");
        await expect(state(page)).toHaveText("Sign-in required");
        await expect(page.getByTestId("outcome-link")).toHaveAttribute("href", "/login");
        await expect(page.getByTestId("outcome-action")).toHaveText("Check again");
        await expect(field(page)).toBeHidden();
        await expect(page.getByTestId("fleet-purpose")).toBeHidden();
        expect(watched.requests.filter((request) => request.method() === "POST" && SUBMIT_URL.test(request.url())), name).toHaveLength(0);
        expect(await page.content()).not.toContain(seeded.purpose);
      } finally {
        await watched.context.close();
      }
    }
    expect(await deliveriesFor(world, seeded)).toHaveLength(0);
  });

  test("P05-PV06-S input page: malformed, altered and foreign links are refused before any request, or by the controller, and never open a field", async ({ browser }) => {
    test.setTimeout(120_000);
    const id = "a".repeat(64);
    const sig = `1.${"A".repeat(43)}`;
    const refusedLocally = [
      `kind=fleet&id=${id.slice(1)}&metadata_sig=${sig}&submit_sig=${sig}`,
      `kind=fleet&id=${id.toUpperCase()}&metadata_sig=${sig}&submit_sig=${sig}`,
      `kind=fleet&id=${id}&metadata_sig=abc&submit_sig=${sig}`,
      `kind=fleet&id=${id}&metadata_sig=${sig}&submit_sig=${sig}&extra=1`,
      `kind=fleet&id=${id}&id=${id}&metadata_sig=${sig}&submit_sig=${sig}`,
      `kind=fleet&kind=fleet&id=${id}&metadata_sig=${sig}&submit_sig=${sig}`,
      `kind=other&id=${id}&metadata_sig=${sig}&submit_sig=${sig}`,
      `kind=&id=${id}&metadata_sig=${sig}&submit_sig=${sig}`
    ];
    const watched = await watchedContext(browser);
    try {
      const page = await watched.context.newPage();
      for (const query of refusedLocally) {
        const before = watched.requests.length;
        await page.goto(`${stack.consoleUrl}/?${query}`);
        await expect(title(page), query).toHaveText("This link is unavailable.");
        await expect(field(page)).toBeHidden();
        const api = watched.requests.slice(before).filter((request) => new URL(request.url()).pathname.startsWith("/api/"));
        expect(api.map((request) => request.url()), `no API request for ${query}`).toEqual([]);
      }
      expect(await watched.violations()).toEqual([]);
    } finally {
      await watched.context.close();
    }

    // Well-formed but unknown to the controller: the controller answers, the page opens nothing.
    const unknown = await watchedContext(browser);
    try {
      const page = await unknown.context.newPage();
      await signIn(page, stack, world.owner);
      await page.goto(`${stack.consoleUrl}/?kind=fleet&id=${id}&metadata_sig=${sig}&submit_sig=${sig}`);
      await expect(title(page)).toHaveText("This link is unavailable.");
      await expect(field(page)).toBeHidden();
      expect(unknown.requests.filter((request) => request.method() === "POST" && SUBMIT_URL.test(request.url()))).toHaveLength(0);
    } finally {
      await unknown.context.close();
    }

    // A real link with an altered capability is refused by the controller, never accepted.
    const seeded = await seedOperation(world, "altered link");
    await publishOffer(world, seeded, 100_000);
    const issued = await world.owner.client.call<{ input_path: string }>("POST", linkRoute(seeded), undefined, { "idempotency-key": key() });
    const url = new URL(`${stack.consoleUrl}${issued.body.input_path}`);
    const original = url.searchParams.get("metadata_sig")!;
    url.searchParams.set("metadata_sig", `${original.slice(0, original.lastIndexOf(".") + 1)}${"B".repeat(43)}`);
    const altered = await watchedContext(browser);
    try {
      const page = await altered.context.newPage();
      await signIn(page, stack, world.owner);
      await page.goto(url.toString());
      await expect(title(page)).toHaveText("This link is unavailable.");
      await expect(field(page)).toBeHidden();
    } finally {
      await altered.context.close();
    }
    expect(await deliveriesFor(world, seeded)).toHaveLength(0);
  });

  test("P05-PV06-S expiry: the console flips to ended and an open input page clears its field when the server-timed offer ends, with nothing sent", async ({ browser }) => {
    test.setTimeout(180_000);
    const canary = `P05-GUI-${randomBytes(8).toString("hex")}`;
    const seeded = await seedOperation(world, "expiry");
    const watched = await watchedContext(browser);
    try {
      const consolePage = await watched.context.newPage();
      await signIn(consolePage, stack, world.owner);
      await openOperation(consolePage, stack, seeded);
      await expect(panel(consolePage).getByRole("status")).toContainText("Waiting for the node");

      // Start the clock only now, so the page has time to open before it runs out.
      const fixture = await publishOffer(world, seeded, 14_000);
      await expect(panel(consolePage).getByRole("button", { name: "Provide Source", exact: true })).toBeVisible({ timeout: 10_000 });
      const input = await openInputPage(watched.context, consolePage);
      await expectInputReady(input, seeded);
      await field(input).fill(canary);

      // The page's countdown runs on the controller's clock and ends with the offer.
      await expect(title(input)).toHaveText("This Source request is no longer available.", { timeout: 25_000 });
      await expect(input.getByTestId("outcome-body")).toHaveText("The offer ended while this page was open. Nothing was sent, and the field was cleared.");
      expect(await typedValues(input)).toBe("");
      expect(watched.requests.filter((request) => request.method() === "POST" && SUBMIT_URL.test(request.url()))).toHaveLength(0);

      // The console reaches the same conclusion on its next read, and the controller refuses a new link.
      await expect(panel(consolePage).getByText("The Source offer ended")).toBeVisible({ timeout: 15_000 });
      await expect(panel(consolePage).getByRole("button")).toHaveCount(0);
      const late = await world.owner.client.call("POST", linkRoute(seeded), undefined, { "idempotency-key": key() });
      expect(late.status).toBe(410);
      expect(await deliveriesFor(world, seeded)).toHaveLength(0);
      expect(watched.requests.some((request) => mentions(request.postData() ?? "", canary) || mentions(request.url(), canary))).toBe(false);
      expect(fixture.expiresAtMs).toBeGreaterThan(0);
    } finally {
      await watched.context.close();
    }
  });

  test("P05-PV06-S / P04-E03: a second tab with a different value is refused as a conflict, and the node holds exactly the first tab's bytes", async ({ browser }) => {
    test.setTimeout(180_000);
    const seeded = await seedOperation(world, "two tabs");
    const fixture = await publishOffer(world, seeded, 100_000);
    const first = `first-${randomBytes(6).toString("hex")}`;
    const second = `second-${randomBytes(6).toString("hex")}`;
    const watched = await watchedContext(browser);
    try {
      const consolePage = await watched.context.newPage();
      await signIn(consolePage, stack, world.owner);
      await openOperation(consolePage, stack, seeded);
      await expect(panel(consolePage).getByRole("button", { name: "Provide Source", exact: true })).toBeVisible({ timeout: 15_000 });
      const tabA = await openInputPage(watched.context, consolePage);
      await expectInputReady(tabA, seeded);
      // The idempotent reopen yields the very same link, so both tabs talk about one offer.
      await expect(panel(consolePage).getByRole("button", { name: "Open the Source page again" })).toBeVisible({ timeout: 15_000 });
      const tabB = await openInputPage(watched.context, consolePage, "Open the Source page again");
      await expectInputReady(tabB, seeded);
      expect(tabB.url()).toBe(tabA.url());
      const links = watched.requests.filter((request) => request.method() === "POST" && request.url().endsWith("/provisioning-link"));
      expect(links).toHaveLength(2);
      expect(new Set(links.map((request) => request.headers()["idempotency-key"])).size).toBe(1);

      await field(tabA).fill(first);
      await field(tabB).fill(second);
      await tabA.getByTestId("submit-btn").click();
      await expect(title(tabA)).toHaveText("Your part is done.", { timeout: 20_000 });
      await tabB.getByTestId("submit-btn").click();
      await expect(title(tabB)).toHaveText("Already submitted.", { timeout: 20_000 });
      await expect(tabB.getByTestId("outcome-body")).toHaveText("A different encrypted value was already received for this operation, so this one wasn't stored.");
      expect(await typedValues(tabB)).toBe("");

      const delivered = await deliveriesFor(world, seeded);
      expect(delivered).toHaveLength(1);
      expect(Buffer.from(await openDelivery(fixture, delivered[0]!)).toString("utf8")).toBe(first);
      const posts = watched.requests.filter((request) => request.method() === "POST" && SUBMIT_URL.test(request.url()));
      expect(posts).toHaveLength(2);
      expect(posts.some((request) => mentions(request.postData() ?? "", first) || mentions(request.postData() ?? "", second))).toBe(false);
      expect(watched.consoleText.some((text) => mentions(text, first) || mentions(text, second))).toBe(false);
    } finally {
      await watched.context.close();
    }
  });

  test("P04-E03 / P05-E01 GUI: a lost reply is reconciled from the controller's receipt without a second submission", async ({ browser }) => {
    test.setTimeout(180_000);
    const seeded = await seedOperation(world, "lost reply");
    const fixture = await publishOffer(world, seeded, 100_000);
    const typed = `lost-${randomBytes(6).toString("hex")}`;
    const watched = await watchedContext(browser);
    try {
      const consolePage = await watched.context.newPage();
      await signIn(consolePage, stack, world.owner);
      await openOperation(consolePage, stack, seeded);
      await expect(panel(consolePage).getByRole("button", { name: "Provide Source", exact: true })).toBeVisible({ timeout: 15_000 });
      const input = await openInputPage(watched.context, consolePage);
      await expectInputReady(input, seeded);
      // The controller stores the ciphertext; the browser never hears the answer.
      await input.route(SUBMIT_URL, async (route) => {
        await route.fetch();
        await route.abort("connectionreset");
      });
      await field(input).fill(typed);
      await input.getByTestId("submit-btn").click();
      await expect(title(input)).toHaveText("Your part is done.", { timeout: 20_000 });
      await expect(input.getByTestId("outcome-body")).toHaveText("The connection dropped, but a re-check shows the controller holds the receipt. You can close this tab.");
      expect(await typedValues(input)).toBe("");
      expect(watched.requests.filter((request) => request.method() === "POST" && SUBMIT_URL.test(request.url()))).toHaveLength(1);
      const delivered = await deliveriesFor(world, seeded);
      expect(delivered).toHaveLength(1);
      expect(Buffer.from(await openDelivery(fixture, delivered[0]!)).toString("utf8")).toBe(typed);
    } finally {
      await watched.context.close();
    }
  });

  test("P04-E03 GUI: an unconfirmed submission is never repeated on its own; a refusal that stored nothing keeps the value so the operator can retry", async ({ browser }) => {
    test.setTimeout(180_000);
    const seeded = await seedOperation(world, "refusals");
    const fixture = await publishOffer(world, seeded, 100_000);
    const typed = `retry-${randomBytes(6).toString("hex")}`;
    const watched = await watchedContext(browser);
    try {
      const consolePage = await watched.context.newPage();
      await signIn(consolePage, stack, world.owner);
      await openOperation(consolePage, stack, seeded);
      await expect(panel(consolePage).getByRole("button", { name: "Provide Source", exact: true })).toBeVisible({ timeout: 15_000 });
      const input = await openInputPage(watched.context, consolePage);
      await expectInputReady(input, seeded);
      const submits = () => watched.requests.filter((request) => request.method() === "POST" && SUBMIT_URL.test(request.url()));

      // 429: nothing stored, the value stays, the operator may press again.
      let mode: "rate" | "down" | "through" = "rate";
      await input.route(SUBMIT_URL, async (route) => {
        if (mode === "through") return route.continue();
        if (mode === "rate") return route.fulfill({ status: 429, contentType: "application/json", headers: { "retry-after": "1" }, body: JSON.stringify({ error: { code: "rate_limited" } }) });
        return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: { code: "unavailable" } }) });
      });
      await field(input).fill(typed);
      await input.getByTestId("submit-btn").click();
      await expect(input.getByTestId("input-error")).toBeVisible({ timeout: 15_000 });
      await expect(state(input)).toHaveText("Awaiting input");
      expect(await typedValues(input)).toBe(typed);
      expect(submits()).toHaveLength(1);

      // 503 with no receipt behind it: not confirmed, not repeated, no value kept for a blind resend.
      mode = "down";
      await input.getByTestId("submit-btn").click();
      await expect(title(input)).toHaveText("Submission not confirmed.", { timeout: 20_000 });
      await expect(input.getByTestId("outcome-body")).toHaveText("No receipt was found when we checked, so it may not have arrived, or it may still arrive.");
      await expect(input.getByTestId("outcome-action")).toHaveText("Check again");
      expect(submits()).toHaveLength(2);
      await input.waitForTimeout(1_500);
      expect(submits()).toHaveLength(2);
      expect(await deliveriesFor(world, seeded)).toHaveLength(0);

      // A re-check asks only the status route; it finds no receipt and still sends nothing.
      const metadataBefore = watched.requests.filter((request) => METADATA_URL.test(request.url())).length;
      await input.getByTestId("outcome-action").click();
      await expect(title(input)).toHaveText("Submission not confirmed.");
      expect(watched.requests.filter((request) => METADATA_URL.test(request.url())).length).toBeGreaterThan(metadataBefore);
      expect(submits()).toHaveLength(2);
      expect(await deliveriesFor(world, seeded)).toHaveLength(0);

      // A fresh page for the same live link can still deliver, and the receipt is unique.
      mode = "through";
      const again = await openInputPage(watched.context, consolePage, "Open the Source page again");
      await expectInputReady(again, seeded);
      await field(again).fill(typed);
      await again.getByTestId("submit-btn").click();
      await expect(title(again)).toHaveText("Your part is done.", { timeout: 20_000 });
      const delivered = await deliveriesFor(world, seeded);
      expect(delivered).toHaveLength(1);
      expect(Buffer.from(await openDelivery(fixture, delivered[0]!)).toString("utf8")).toBe(typed);
    } finally {
      await watched.context.close();
    }
  });

  test("P05-PV06-S clearing: a hidden page and a leaving page clear the typed value, and a reload starts empty and ready again", async ({ browser }) => {
    test.setTimeout(180_000);
    const seeded = await seedOperation(world, "clearing");
    await publishOffer(world, seeded, 100_000);
    const typed = `clear-${randomBytes(6).toString("hex")}`;
    const watched = await watchedContext(browser);
    try {
      const consolePage = await watched.context.newPage();
      await signIn(consolePage, stack, world.owner);
      await openOperation(consolePage, stack, seeded);
      await expect(panel(consolePage).getByRole("button", { name: "Provide Source", exact: true })).toBeVisible({ timeout: 15_000 });
      const input = await openInputPage(watched.context, consolePage);
      await expectInputReady(input, seeded);

      // Simulated, not a real tab switch: headless Chromium does not hide background tabs.
      await field(input).fill(typed);
      expect(await typedValues(input)).toBe(typed);
      await input.evaluate(() => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
        document.dispatchEvent(new Event("visibilitychange"));
      });
      expect(await typedValues(input)).toBe("");
      await input.evaluate(() => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
      });

      await field(input).fill(typed);
      expect(await typedValues(input)).toBe(typed);
      await input.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })));
      expect(await typedValues(input)).toBe("");

      // A reload keeps the link (the capabilities stay in the address bar), but never the value.
      await field(input).fill(typed);
      await input.reload();
      await expectInputReady(input, seeded);
      expect(await typedValues(input)).toBe("");
      expect(mentions(input.url(), typed)).toBe(false);
      expect(await deliveriesFor(world, seeded)).toHaveLength(0);
      expect(watched.requests.filter((request) => request.method() === "POST" && SUBMIT_URL.test(request.url()))).toHaveLength(0);
    } finally {
      await watched.context.close();
    }
  });

  test("P05-PV06-S Vietnamese and keyboard: the console panel and the input page follow the locale, and the form is reachable and usable by keyboard alone", async ({ browser }) => {
    test.setTimeout(180_000);
    const seeded = await seedOperation(world, "locale and keyboard");
    const fixture = await publishOffer(world, seeded, 100_000);
    const typed = `phim-${randomBytes(6).toString("hex")} Tiếng Việt`;
    const watched = await watchedContext(browser, { locale: "vi" });
    try {
      const consolePage = await watched.context.newPage();
      await signIn(consolePage, stack, world.owner, "vi");
      await consolePage.goto(`${stack.consoleUrl}/operations/${encodeURIComponent(seeded.operationId)}`);
      await expect(consolePage.locator("html")).toHaveAttribute("lang", "vi");
      await expect(panel(consolePage).getByRole("heading", { name: "Cung cấp Source" })).toBeVisible();
      const [input] = await Promise.all([watched.context.waitForEvent("page"), panel(consolePage).getByRole("button", { name: "Cung cấp Source", exact: true }).click()]);
      await input.waitForLoadState("domcontentloaded");
      await expect(input.locator("html")).toHaveAttribute("lang", "vi");
      await expect(state(input)).toHaveText("Chờ nhập");
      await expect(input.getByTestId("fleet-credential")).toHaveText(DESTINATION.credential);

      // Keyboard only: Tab reaches the field, typing fills it, Tab reaches the button, Enter sends.
      await input.locator("body").focus();
      for (let step = 0; step < 12 && !(await field(input).evaluate((element) => element === document.activeElement)); step += 1) await input.keyboard.press("Tab");
      await expect(field(input)).toBeFocused();
      await input.keyboard.type(typed);
      await expect(field(input)).toHaveValue(typed);
      for (let step = 0; step < 12 && !(await input.getByTestId("submit-btn").evaluate((element) => element === document.activeElement)); step += 1) await input.keyboard.press("Tab");
      await expect(input.getByTestId("submit-btn")).toBeFocused();
      await input.keyboard.press("Enter");
      await expect(title(input)).toHaveText("Bạn đã hoàn tất.", { timeout: 20_000 });
      const delivered = await deliveriesFor(world, seeded);
      expect(delivered).toHaveLength(1);
      expect(Buffer.from(await openDelivery(fixture, delivered[0]!)).toString("utf8")).toBe(typed);
      expect(watched.requests.some((request) => mentions(request.postData() ?? "", typed) || mentions(request.url(), typed))).toBe(false);
    } finally {
      await watched.context.close();
    }
  });
});
