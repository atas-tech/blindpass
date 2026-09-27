import { expect, test, type Browser, type BrowserContextOptions, type Page, type Request } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { axeViolations, horizontalOverflow, smallTargets } from "./support/a11y.js";
import { InputStack, withParam, type SecretRequest } from "./support/input.js";

const HOSTILE = 'Deploy key <img src=x onerror="window.__owned=1"> **now** <script>window.__owned=2</script>';
const LONG_EN = `Production database credential for the nightly export job on the reporting cluster, requested by the release pipeline so it can rotate the replica password before the maintenance window closes ${"x".repeat(80)}`;
const LONG_VI = "Thông tin xác thực cơ sở dữ liệu sản xuất cho tác vụ xuất dữ liệu hằng đêm trên cụm báo cáo, được yêu cầu bởi quy trình phát hành để xoay vòng mật khẩu bản sao trước khi hết thời gian bảo trì";
const WIDTHS = [320, 390, 768, 1024, 1440];

async function open(browser: Browser, url: string, options: BrowserContextOptions = {}) {
  const context = await browser.newContext(options);
  const page = await context.newPage();
  const requests: Request[] = [];
  const logs: string[] = [];
  page.on("request", (request) => requests.push(request));
  page.on("console", (message) => logs.push(message.text()));
  page.on("pageerror", (error) => logs.push(error.message));
  await page.goto(url);
  return { context, page, requests, logs };
}

const badge = (page: Page) => page.getByTestId("status");
const submits = (requests: Request[]) => requests.filter((request) => request.method() === "POST" && request.url().includes("/api/v2/secret/submit/"));

async function ready(page: Page) {
  await expect(badge(page)).toHaveText("Awaiting input");
  await expect(page.getByTestId("submit-btn")).toBeEnabled();
}

async function fieldValues(page: Page): Promise<string[]> {
  return page.evaluate(() => [...document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input:not([type=checkbox]), textarea")].map((element) => element.value).filter(Boolean));
}

test.describe("secret input against the controller", () => {
  let input: InputStack;

  test.beforeAll(async () => {
    input = await InputStack.start({});
  });
  test.afterAll(async () => input?.stop());

  test("SI-E01 / CC03: requester text renders as text, with the code and a server-clock countdown; the link can't choose the API origin", async ({ browser }) => {
    const request = await input.createRequest(HOSTILE);
    const { context, page, requests } = await open(browser, withParam(request.secretUrl, "api_url", "https://attacker.example"));
    await ready(page);
    await expect(page.getByTestId("request-description")).toHaveText(HOSTILE);
    expect(await page.evaluate(() => (window as unknown as { __owned?: number }).__owned)).toBeUndefined();
    expect(await page.locator("#secret-card img, #secret-card script").count()).toBe(0);
    await expect(page.getByTestId("confirmation-code")).toHaveText(request.confirmationCode);
    await expect(page.getByTestId("expiry")).toHaveText(/^0[23]:\d\d remaining$/);
    await expect(page.getByText("Written by the requester. BlindPass doesn't verify it.")).toBeVisible();

    const url = new URL(request.secretUrl);
    const metadata = requests.filter((entry) => entry.url().includes("/api/v2/secret/metadata/"));
    expect(metadata).toHaveLength(1);
    expect(new URL(metadata[0]!.url()).searchParams.get("sig")).toBe(url.searchParams.get("metadata_sig"));
    expect(requests.some((entry) => new URL(entry.url()).hostname === "attacker.example")).toBe(false);

    const document = await page.request.get(input.inputUrl);
    const headers = document.headers();
    expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(headers["content-security-policy"]).not.toContain("unsafe-inline");
    expect(headers["content-security-policy"]).toContain(`connect-src 'self' ${input.stack.controllerUrl}`);
    expect(headers["x-frame-options"]).toBe("DENY");
    expect(headers["referrer-policy"]).toBe("no-referrer");
    await context.close();
  });

  test("SI-I03: a refresh token left by the earlier input page is removed; only the language preference is stored", async ({ browser }) => {
    const request = await input.createRequest("Legacy storage canary");
    const context = await browser.newContext();
    await context.addInitScript(() => {
      if (location.pathname === "/" && !sessionStorage.getItem("seeded")) {
        sessionStorage.setItem("seeded", "1");
        localStorage.setItem("blindpass_refresh_token", "legacy-dummy-refresh-canary");
      }
    });
    const page = await context.newPage();
    await page.goto(request.secretUrl);
    await ready(page);
    await page.getByTestId("language").selectOption("vi");
    expect(await page.evaluate(() => Object.keys(localStorage))).toEqual(["blindpass_locale"]);
    await context.close();
  });

  test("SI-E03 / SI-I01: a multiline PEM keeps its exact bytes through browser HPKE; only the requester opens it, once", async ({ browser }) => {
    const request = await input.createRequest("Multiline canary");
    const value = `-----BEGIN PRIVATE KEY-----\n  indented line  \n\ttabbed\n\nnon-ascii é ơ 漢 🔑\ntrailing spaces   \n-----END PRIVATE KEY-----\n`;
    const { context, page, requests } = await open(browser, request.secretUrl);
    await ready(page);
    await page.getByTestId("multiline").check();
    await expect(page.getByText(/Multiline values are visible on screen/)).toBeVisible();
    await page.getByTestId("secret-input-multi").fill(value);
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("outcome-title")).toHaveText("Your part is done.");
    await expect(page.getByTestId("outcome-title")).toBeFocused();
    await expect(badge(page)).toHaveText("Submitted");
    await expect(page.getByTestId("outcome-body")).not.toContainText(/retriev|decrypted by/i);
    expect(await fieldValues(page)).toEqual([]);
    expect(submits(requests)).toHaveLength(1);
    expect(new URL(submits(requests)[0]!.url()).searchParams.get("sig")).toBe(new URL(request.secretUrl).searchParams.get("submit_sig"));

    expect((await input.retrieve(request.requestId, "other")).status).not.toBe(200);
    const retrieved = await input.retrieve(request.requestId);
    expect(retrieved.status).toBe(200);
    expect(Buffer.from(await request.open(retrieved.body!)).toString("utf8")).toBe(value);
    expect((await input.retrieve(request.requestId)).status).toBe(410);
    await context.close();
  });

  test("SI-E03: pasted line breaks move to multiline instead of being dropped; reveal remasks; clear empties; empty and duplicate submits are refused", async ({ browser }) => {
    const request = await input.createRequest("Entry controls canary");
    const { context, page, requests } = await open(browser, request.secretUrl);
    await ready(page);
    const single = page.getByTestId("secret-input");
    await single.fill("prefix-");
    await single.evaluate((element: HTMLInputElement) => {
      element.setSelectionRange(element.value.length, element.value.length);
      const data = new DataTransfer();
      data.setData("text/plain", "line one\r\nline two");
      element.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
    });
    await expect(page.getByTestId("multiline")).toBeChecked();
    await expect(page.getByTestId("input-error")).toHaveText("Switched to multiline so the pasted line breaks are kept.");
    expect(await page.getByTestId("secret-input-multi").inputValue()).toBe("prefix-line one\nline two");
    await expect(page.getByTestId("secret-input-multi")).toBeFocused();

    // The page refuses to leave multiline while line breaks remain.
    await page.getByTestId("multiline").click();
    await expect(page.getByTestId("multiline")).toBeChecked();
    await expect(page.getByTestId("input-error")).toHaveText("Keep multiline on while the value has line breaks, or clear it first.");
    await page.getByTestId("clear").click();
    expect(await page.getByTestId("secret-input-multi").inputValue()).toBe("");
    await page.getByTestId("multiline").uncheck();
    await expect(single).toBeVisible();

    await single.fill("reveal-me");
    await page.getByTestId("visibility").click();
    await expect(single).toHaveAttribute("type", "text");
    await expect(page.getByTestId("visibility")).toHaveAttribute("aria-pressed", "true");
    await page.evaluate(() => window.dispatchEvent(new Event("blur")));
    await expect(single).toHaveAttribute("type", "password");
    await page.getByTestId("clear").click();
    await expect(single).toHaveValue("");
    await expect(single).toBeFocused();

    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("input-error")).toHaveText("Enter the secret to continue.");
    await expect(single).toHaveAttribute("aria-invalid", "true");
    expect(submits(requests)).toHaveLength(0);

    const exact = "  spaced\tvalue  ";
    await single.fill(exact);
    await page.evaluate(() => {
      const form = document.getElementById("secret-form") as HTMLFormElement;
      form.requestSubmit();
      form.requestSubmit();
      form.requestSubmit();
    });
    await expect(badge(page)).toHaveText("Submitted");
    expect(submits(requests)).toHaveLength(1);
    const retrieved = await input.retrieve(request.requestId);
    expect(Buffer.from(await request.open(retrieved.body!)).toString("utf8")).toBe(exact);
    await context.close();
  });

  test("SI-E04: after success the page stays usable when the browser refuses to close the tab", async ({ browser }) => {
    const request = await input.createRequest("Close canary");
    const context = await browser.newContext();
    const page = await context.newPage();
    // A tab with history that no script opened can't be closed by script.
    await page.goto(`${input.inputUrl}/robots.txt`).catch(() => undefined);
    await page.goto(request.secretUrl);
    await ready(page);
    await page.getByTestId("secret-input").fill("close-canary");
    await page.getByTestId("submit-btn").press("Enter");
    await expect(badge(page)).toHaveText("Submitted");
    await page.getByTestId("outcome-action").click();
    await expect(page.locator("#outcome-followup")).toHaveText("Your browser kept this tab open. You can close it yourself.");
    await expect(page.getByTestId("outcome-title")).toHaveText("Your part is done.");
    await context.close();
  });

  test("SI-E02: incomplete, tampered, wrong-scope and foreign links keep entry disabled with truthful copy", async ({ browser }) => {
    const request = await input.createRequest("Link validation canary");
    const other = await input.createRequest("Other request");
    const url = new URL(request.secretUrl);
    const metadataSig = url.searchParams.get("metadata_sig")!;
    const submitSig = url.searchParams.get("submit_sig")!;
    const cases: Array<[string, string, boolean]> = [
      ["missing submit scope", withParam(request.secretUrl, "submit_sig", null), false],
      ["missing id", withParam(request.secretUrl, "id", null), false],
      ["tampered metadata signature", withParam(request.secretUrl, "metadata_sig", `${metadataSig.slice(0, -2)}${metadataSig.endsWith("AA") ? "BB" : "AA"}`), true],
      ["submit scope used for metadata", withParam(request.secretUrl, "metadata_sig", submitSig), true],
      ["signature for another request", withParam(request.secretUrl, "id", other.requestId), true],
      ["unknown request", withParam(request.secretUrl, "id", "0".repeat(64)), true]
    ];
    for (const [name, link, contactsController] of cases) {
      const { context, page, requests } = await open(browser, link);
      await expect(badge(page), name).toHaveText("Unavailable");
      await expect(page.getByTestId("outcome-title"), name).toHaveText("This link is unavailable.");
      await expect(page.getByTestId("secret-input"), name).toBeHidden();
      await expect(page.getByTestId("submit-btn"), name).toBeDisabled();
      const calls = requests.filter((entry) => entry.url().startsWith(input.stack.controllerUrl));
      expect(calls.length, name).toBe(contactsController ? 1 : 0);
      await context.close();
    }
  });

  test("SI-E05: an already-submitted link says so; refusals keep the value; nothing is sent twice", async ({ browser }) => {
    const request = await input.createRequest("Refusal canary");
    const { context, page, requests } = await open(browser, request.secretUrl);
    await ready(page);

    // Oversized input is refused before anything is encrypted or sent.
    await page.getByTestId("multiline").check();
    await page.getByTestId("secret-input-multi").fill("x".repeat(393_201));
    await expect(page.getByTestId("input-size")).toHaveText("384 KB of 384 KB");
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("input-error")).toHaveText("This value is 384 KB; the limit is 384 KB. Nothing was sent.");
    expect(submits(requests)).toHaveLength(0);
    await page.getByTestId("clear").click();
    await page.getByTestId("multiline").uncheck();

    // A rate-limit answer is a definite refusal: the value stays for a later retry.
    await page.route("**/api/v2/secret/submit/**", (route) => route.fulfill({ status: 429, contentType: "application/json", body: '{"error":"rate_limited"}' }), { times: 1 });
    await page.getByTestId("secret-input").fill("kept-after-429");
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("input-error")).toHaveText("Too many attempts. Wait a minute, then submit again.");
    await expect(page.getByTestId("secret-input")).toHaveValue("kept-after-429");
    await expect(page.getByTestId("secret-input")).toBeFocused();
    expect(await input.agentStatus(request.requestId)).toBe(200);
    await page.getByTestId("submit-btn").click();
    await expect(badge(page)).toHaveText("Submitted");

    // The same link opened again: the CT19 status read says submitted before any entry.
    await page.goto(request.secretUrl);
    await expect(page.getByTestId("outcome-title")).toHaveText("Already submitted.");
    await expect(page.getByTestId("outcome-note")).toContainText("This doesn't confirm retrieval.");
    await expect(page.getByTestId("secret-input")).toBeHidden();
    expect(await fieldValues(page)).toEqual([]);
    const retrieved = await input.retrieve(request.requestId);
    expect(Buffer.from(await request.open(retrieved.body!)).toString("utf8")).toBe("kept-after-429");
    await context.close();
  });

  test("SI-E05: a second tab that submits after another tab already did gets 'already submitted', not success", async ({ browser }) => {
    const request = await input.createRequest("Two tabs canary");
    const first = await open(browser, request.secretUrl);
    const second = await open(browser, request.secretUrl);
    await ready(first.page);
    await ready(second.page);
    await first.page.getByTestId("secret-input").fill("from-the-first-tab");
    await first.page.getByTestId("submit-btn").click();
    await expect(badge(first.page)).toHaveText("Submitted");
    await second.page.getByTestId("secret-input").fill("from-the-second-tab");
    await second.page.getByTestId("submit-btn").click();
    await expect(second.page.getByTestId("outcome-title")).toHaveText("Already submitted.");
    expect(await fieldValues(second.page)).toEqual([]);
    const retrieved = await input.retrieve(request.requestId);
    expect(Buffer.from(await request.open(retrieved.body!)).toString("utf8")).toBe("from-the-first-tab");
    await first.context.close();
    await second.context.close();
  });

  test("SI-E05: an encryption failure sends nothing and keeps the value", async ({ browser }) => {
    const request = await input.createRequest("Encryption canary");
    const context = await browser.newContext();
    const page = await context.newPage();
    const requests: Request[] = [];
    page.on("request", (entry) => requests.push(entry));
    // Recovery-path test: the real metadata answer with an unusable key.
    await page.route("**/api/v2/secret/metadata/**", async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as Record<string, unknown>;
      await route.fulfill({ response, json: { ...body, public_key: "AAAA" } });
    });
    await page.goto(request.secretUrl);
    await ready(page);
    await page.getByTestId("secret-input").fill("never-sent");
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("input-error")).toHaveText("Your browser couldn't encrypt this value. Nothing was sent.");
    await expect(page.getByTestId("secret-input")).toHaveValue("never-sent");
    expect(submits(requests)).toHaveLength(0);
    await context.close();
  });

  test("SI-I02: a reply lost after the controller accepted is confirmed through the browser status contract and never resent", async ({ browser }) => {
    const request = await input.createRequest("Lost reply canary");
    const { context, page, requests } = await open(browser, request.secretUrl);
    await ready(page);
    await page.route("**/api/v2/secret/submit/**", async (route) => {
      await route.fetch();
      await route.abort("connectionreset");
    });
    await page.getByTestId("secret-input").fill("accepted-but-unconfirmed");
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("outcome-title")).toHaveText("Your part is done.");
    await expect(page.getByTestId("outcome-body")).toHaveText("The connection dropped, but a status check confirms the controller received the encrypted secret. You can close this tab.");
    await expect(page.getByTestId("outcome-title")).toBeFocused();
    expect(await fieldValues(page)).toEqual([]);
    expect(submits(requests)).toHaveLength(1);

    // Only the CT19 browser routes are used: the metadata signature buys a separate status-only signature.
    const url = new URL(request.secretUrl);
    const capability = requests.filter((entry) => entry.url().includes("/browser-status/") && entry.url().includes("/capability"));
    const status = requests.filter((entry) => entry.url().includes("/browser-status/") && !entry.url().includes("/capability"));
    expect(capability.length).toBeGreaterThanOrEqual(1);
    for (const entry of capability) expect(new URL(entry.url()).searchParams.get("sig")).toBe(url.searchParams.get("metadata_sig"));
    expect(status.length).toBeGreaterThanOrEqual(2);
    for (const entry of status) expect([url.searchParams.get("metadata_sig"), url.searchParams.get("submit_sig")]).not.toContain(new URL(entry.url()).searchParams.get("sig"));
    expect(requests.some((entry) => /\/api\/v2\/secret\/(status|retrieve)\//.test(entry.url()) || entry.headers()["authorization"])).toBe(false);

    const retrieved = await input.retrieve(request.requestId);
    expect(Buffer.from(await request.open(retrieved.body!)).toString("utf8")).toBe("accepted-but-unconfirmed");
    await context.close();
  });

  test("SI-I02: a submission that never arrived reads as pending; entry returns empty and the human sends it once", async ({ browser }) => {
    for (const [name, failure] of [
      ["dropped before the controller", (route: import("@playwright/test").Route) => route.abort("connectionreset")],
      ["5xx from a proxy", (route: import("@playwright/test").Route) => route.fulfill({ status: 503, body: "" })]
    ] as const) {
      const request = await input.createRequest(`Never arrived: ${name}`);
      const { context, page, requests } = await open(browser, request.secretUrl);
      await ready(page);
      await page.route("**/api/v2/secret/submit/**", failure, { times: 1 });
      await page.getByTestId("secret-input").fill("first-attempt");
      await page.getByTestId("submit-btn").click();
      await expect(page.getByTestId("input-error"), name).toHaveText("A status check shows the controller didn't receive it, so nothing was stored. Enter the secret again to send it.");
      await expect(page.getByTestId("secret-input"), name).toHaveValue("");
      await expect(page.getByTestId("secret-input"), name).toBeFocused();
      await page.waitForTimeout(500);
      expect(submits(requests), name).toHaveLength(1);
      await page.getByTestId("secret-input").fill("second-attempt");
      await page.getByTestId("submit-btn").click();
      await expect(badge(page), name).toHaveText("Submitted");
      const retrieved = await input.retrieve(request.requestId);
      expect(Buffer.from(await request.open(retrieved.body!)).toString("utf8"), name).toBe("second-attempt");
      await context.close();
    }
  });

  test("SI-I02: when the status check can't answer either, the outcome stays unknown until a manual check", async ({ browser }) => {
    const request = await input.createRequest("Status outage canary");
    const { context, page, requests } = await open(browser, request.secretUrl);
    await ready(page);
    await page.route("**/api/v2/secret/submit/**", async (route) => {
      await route.fetch();
      await route.abort("connectionreset");
    });
    await page.route("**/api/v2/secret/browser-status/**", (route) => route.abort("internetdisconnected"));
    await page.getByTestId("secret-input").fill("maybe-arrived");
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("outcome-body")).toHaveText("The status check didn't get an answer either. Your secret may already have been submitted.");
    await expect(page.getByTestId("outcome-title")).toHaveText("Submission not confirmed.");
    await expect(page.getByTestId("outcome-note")).toHaveText("Don't send it again until the outcome is known. Ask the requester whether it arrived.");
    await expect(badge(page)).toHaveText("Status unknown");
    await page.unroute("**/api/v2/secret/browser-status/**");
    await page.getByTestId("outcome-action").click();
    await expect(page.getByTestId("outcome-title")).toHaveText("Your part is done.");
    expect(submits(requests)).toHaveLength(1);
    await context.close();
  });

  test("P04-I03: the status capability is minimal and bound to its request and scope", async () => {
    const one = await input.createRequest("Scope canary one");
    const two = await input.createRequest("Scope canary two");
    const base = input.stack.controllerUrl;
    const sigs = (request: SecretRequest) => {
      const url = new URL(request.secretUrl);
      return { metadata: url.searchParams.get("metadata_sig")!, submit: url.searchParams.get("submit_sig")! };
    };
    const capability = (request: SecretRequest, sig: string) => fetch(`${base}/api/v2/secret/browser-status/${request.requestId}/capability?sig=${encodeURIComponent(sig)}`, { method: "POST" });
    const status = (request: SecretRequest, sig: string) => fetch(`${base}/api/v2/secret/browser-status/${request.requestId}?sig=${encodeURIComponent(sig)}`);

    const issued = await capability(one, sigs(one).metadata);
    expect(issued.status).toBe(200);
    const body = (await issued.json()) as Record<string, string>;
    expect(Object.keys(body)).toEqual(["status_sig"]);
    const read = await status(one, body.status_sig!);
    expect(read.status).toBe(200);
    expect(await read.json()).toEqual({ status: "pending" });

    // Wrong scope, foreign request and missing credentials all read as gone, never as a status.
    expect((await capability(one, sigs(one).submit)).status).toBe(410);
    expect((await capability(two, sigs(one).metadata)).status).toBe(410);
    expect((await status(one, sigs(one).metadata)).status).toBe(410);
    expect((await status(one, sigs(one).submit)).status).toBe(410);
    expect((await status(two, body.status_sig!)).status).toBe(410);
    expect((await fetch(`${base}/api/v2/secret/browser-status/${one.requestId}`)).status).toBe(410);
    // The agent-authenticated status route stays closed to browser credentials.
    expect((await fetch(`${base}/api/v2/secret/status/${one.requestId}?sig=${encodeURIComponent(body.status_sig!)}`)).status).toBe(401);
  });

  test("SI-I03: a canary never reaches URLs, storage, logs, request bodies or the DOM; no referrer or third-party request; framing is refused", async ({ browser }) => {
    const canary = `si-i03-${randomBytes(9).toString("hex")}`;
    const encoded = [canary, Buffer.from(canary).toString("base64"), encodeURIComponent(canary)];
    const request = await input.createRequest("Exposure canary");
    const { context, page, requests, logs } = await open(browser, request.secretUrl);
    await ready(page);
    const leaks = async (stage: string) => {
      const storage = await page.evaluate(() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]));
      const content = await page.evaluate(() => document.documentElement.outerHTML);
      for (const needle of encoded) {
        expect(storage, `${stage}: storage`).not.toContain(needle);
        expect(content, `${stage}: DOM`).not.toContain(needle);
        expect(page.url(), `${stage}: URL`).not.toContain(needle);
        expect(logs.join("\n"), `${stage}: console`).not.toContain(needle);
        for (const entry of requests) {
          expect(entry.url(), `${stage}: request URL`).not.toContain(needle);
          expect(entry.postData() ?? "", `${stage}: request body`).not.toContain(needle);
        }
      }
    };

    await page.getByTestId("secret-input").fill(canary);
    await page.getByTestId("clear").click();
    expect(await fieldValues(page)).toEqual([]);
    await leaks("clear");

    await page.getByTestId("secret-input").fill(canary);
    await page.goto(`${input.inputUrl}/robots.txt`).catch(() => undefined);
    await page.goBack();
    await ready(page);
    expect(await fieldValues(page)).toEqual([]);
    await leaks("navigation");

    await page.route("**/api/v2/secret/submit/**", (route) => route.fulfill({ status: 400, contentType: "application/json", body: '{"error":"invalid"}' }), { times: 1 });
    await page.getByTestId("secret-input").fill(canary);
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("input-error")).toHaveText(/rejected the encrypted payload/);
    await page.getByTestId("submit-btn").click();
    await expect(badge(page)).toHaveText("Submitted");
    expect(await fieldValues(page)).toEqual([]);
    await leaks("success");

    for (const entry of requests) {
      const origin = new URL(entry.url()).origin;
      expect([input.inputUrl, input.stack.controllerUrl], entry.url()).toContain(origin);
      if (origin === input.stack.controllerUrl) expect((await entry.allHeaders())["referer"] ?? "", entry.url()).toBe("");
    }
    await context.close();

    const framer = await browser.newContext();
    const host = await framer.newPage();
    const framed: string[] = [];
    host.on("request", (entry) => framed.push(entry.url()));
    await host.goto(`${input.stack.consoleUrl}/login`);
    await host.evaluate((src) => {
      const frame = document.createElement("iframe");
      frame.src = src;
      document.body.append(frame);
    }, (await input.createRequest("Framed canary")).secretUrl);
    await host.waitForTimeout(1500);
    expect(framed.some((url) => url.includes("/api/v2/secret/metadata/"))).toBe(false);
    await framer.close();
  });

  test("SI-E06 / P04-E03: every state fits 320–1440 px in both languages with long text, passes axe and keeps 44 px touch targets", async ({ browser }) => {
    const context = await browser.newContext({ bypassCSP: true, hasTouch: true, reducedMotion: "reduce" });
    const page = await context.newPage();
    const check = async (state: string) => {
      for (const locale of ["en", "vi"] as const) {
        await page.getByTestId("language").selectOption(locale);
        await expect(page.locator("html")).toHaveAttribute("lang", locale);
        for (const width of WIDTHS) {
          await page.setViewportSize({ width, height: 900 });
          expect(await horizontalOverflow(page), `${state} ${locale} ${width}`).toBeLessThanOrEqual(0);
        }
        await page.setViewportSize({ width: 390, height: 844 });
        expect(await smallTargets(page, 44), `${state} ${locale} targets`).toEqual([]);
        await page.setViewportSize({ width: 1024, height: 900 });
        expect(await axeViolations(page), `${state} ${locale} axe`).toEqual([]);
      }
      await page.getByTestId("language").selectOption("en");
    };
    const fresh = async (description: string): Promise<SecretRequest> => {
      const request = await input.createRequest(description);
      await page.goto(request.secretUrl);
      return request;
    };

    await fresh(LONG_EN);
    await ready(page);
    await page.getByTestId("multiline").check();
    await page.getByTestId("secret-input-multi").fill(`{"key":"${"k".repeat(300)}"}\nsecond line`);
    await page.getByTestId("submit-btn").click({ trial: true });
    await check("ready");
    // Keyboard focus from the text area: multiline checkbox, then the submit button.
    await page.getByTestId("secret-input-multi").focus();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await expect(page.getByTestId("submit-btn")).toBeFocused();
    expect(await page.getByTestId("submit-btn").evaluate((element) => getComputedStyle(element).outlineStyle)).not.toBe("none");

    await page.route("**/api/v2/secret/submit/**", () => undefined);
    await page.getByTestId("submit-btn").click();
    await expect(badge(page)).toHaveText("Sending");
    expect(await page.locator("#outcome-symbol svg").evaluate((element) => getComputedStyle(element).animationName)).toBe("none");
    await check("submitting");
    await page.unroute("**/api/v2/secret/submit/**");

    await fresh(LONG_VI);
    await ready(page);
    await page.getByTestId("secret-input").fill("layout-canary");
    await page.getByTestId("submit-btn").click();
    await expect(badge(page)).toHaveText("Submitted");
    await check("submitted");

    const used = await fresh("Used canary");
    await ready(page);
    await page.getByTestId("secret-input").fill("first");
    await page.getByTestId("submit-btn").click();
    await expect(badge(page)).toHaveText("Submitted");
    await page.goto(used.secretUrl);
    await expect(badge(page)).toHaveText("Already submitted");
    await check("used");

    const invalid = await input.createRequest("Invalid canary");
    await page.goto(withParam(invalid.secretUrl, "metadata_sig", "1.tampered"));
    await expect(badge(page)).toHaveText("Unavailable");
    await check("invalid");

    await page.route("**/api/v2/secret/metadata/**", () => undefined);
    await page.goto((await input.createRequest("Loading canary")).secretUrl);
    await expect(badge(page)).toHaveText("Checking request");
    await check("loading");
    await page.unroute("**/api/v2/secret/metadata/**");

    await page.route("**/api/v2/secret/metadata/**", (route) => route.abort("internetdisconnected"));
    await page.goto((await input.createRequest("Error canary")).secretUrl);
    await expect(badge(page)).toHaveText("Not loaded");
    await check("error");
    await page.unroute("**/api/v2/secret/metadata/**");
    await page.getByTestId("outcome-action").click();
    await ready(page);

    // The Rust controller never answers 401 here; this compatibility state is rendered from a mocked reply.
    await page.route("**/api/v2/secret/metadata/**", (route) => route.fulfill({ status: 401, contentType: "application/json", body: '{"error":"login_required"}' }));
    await page.goto((await input.createRequest("Auth canary")).secretUrl);
    await expect(badge(page)).toHaveText("Sign-in required");
    await check("auth");
    await page.unroute("**/api/v2/secret/metadata/**");

    await fresh("Unknown canary");
    await ready(page);
    await page.route("**/api/v2/secret/submit/**", (route) => route.abort("connectionreset"));
    await page.route("**/api/v2/secret/browser-status/**", (route) => route.abort("internetdisconnected"));
    await page.getByTestId("secret-input").fill("unknown-canary");
    await page.getByTestId("submit-btn").click();
    await expect(badge(page)).toHaveText("Status unknown");
    await check("unknown");
    await context.close();
  });
});

test.describe("secret input deadlines", () => {
  let input: InputStack;

  test.beforeAll(async () => {
    input = await InputStack.start({ requestTtlSeconds: 6 });
  });
  test.afterAll(async () => input?.stop());

  test("SI-E05 / CC03: a link that expired before opening disables entry", async ({ browser }) => {
    const request = await input.createRequest("Expired at load");
    await new Promise((resolve) => setTimeout(resolve, 6_500));
    const { context, page } = await open(browser, request.secretUrl, { bypassCSP: true });
    await expect(badge(page)).toHaveText("No longer available");
    await expect(page.getByTestId("outcome-title")).toHaveText("This link is no longer available.");
    await expect(page.getByTestId("outcome-body")).toHaveText("It has expired or its request is finished. Nothing can be submitted through it.");
    await expect(page.getByTestId("submit-btn")).toBeDisabled();
    for (const locale of ["en", "vi"] as const) {
      await page.getByTestId("language").selectOption(locale);
      for (const width of WIDTHS) {
        await page.setViewportSize({ width, height: 900 });
        expect(await horizontalOverflow(page), `expired ${locale} ${width}`).toBeLessThanOrEqual(0);
      }
      expect(await axeViolations(page), `expired ${locale}`).toEqual([]);
    }
    await context.close();
  });

  test("SI-E05: the countdown follows the controller deadline and clears the field when it runs out", async ({ browser }) => {
    const request = await input.createRequest("Expires while typing");
    const { context, page, requests } = await open(browser, request.secretUrl);
    await ready(page);
    await expect(page.getByTestId("expiry")).toHaveText(/^00:0[0-5] remaining$/);
    await page.getByTestId("secret-input").fill("typed-too-late");
    await expect(page.getByTestId("outcome-body")).toHaveText("The link expired while this page was open. Nothing was sent, and the field was cleared.", { timeout: 8_000 });
    await expect(page.getByTestId("outcome-title")).toBeFocused();
    expect(await fieldValues(page)).toEqual([]);
    expect(submits(requests)).toHaveLength(0);
    await context.close();
  });

  test("SI-E05: expiry during submit reports that the controller no longer accepts it", async ({ browser }) => {
    const request = await input.createRequest("Expires during submit");
    const created = Date.now();
    const { context, page } = await open(browser, request.secretUrl);
    await ready(page);
    await page.route("**/api/v2/secret/submit/**", async (route) => {
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, created + 7_000 - Date.now())));
      await route.continue();
    });
    await page.getByTestId("secret-input").fill("sent-too-late");
    await page.getByTestId("submit-btn").click();
    await expect(page.getByTestId("outcome-body")).toHaveText("The controller no longer accepts submissions for this link. Confirm with the requester whether they still need it.", { timeout: 10_000 });
    expect(await fieldValues(page)).toEqual([]);
    await context.close();
  });

  test("P04-I03: a 410 from the status contract after a lost reply never reads as failure and never resubmits", async ({ browser }) => {
    const request = await input.createRequest("Gone after lost reply");
    const created = Date.now();
    const { context, page, requests } = await open(browser, request.secretUrl);
    await ready(page);
    await page.route("**/api/v2/secret/submit/**", (route) => route.abort("connectionreset"));
    // Hold the status read until the link has expired, so the controller answers 410.
    await page.route("**/api/v2/secret/browser-status/**", async (route) => {
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, created + 7_000 - Date.now())));
      await route.continue();
    });
    await page.getByTestId("secret-input").fill("fate-unknown");
    await page.getByTestId("submit-btn").click();
    await expect(badge(page)).toHaveText("Checking status");
    await expect(page.getByTestId("outcome-body")).toHaveText("This link is no longer available, so its status can't be checked. Your secret may or may not have been submitted.", { timeout: 10_000 });
    await expect(page.getByTestId("outcome-note")).toContainText("Don't assume it failed");
    await expect(page.getByTestId("outcome-action")).toBeHidden();
    await page.waitForTimeout(500);
    expect(submits(requests)).toHaveLength(1);
    await context.close();
  });

  test("P04-I03: expired credentials get 410 from both CT19 routes", async () => {
    const request = await input.createRequest("Expired capability");
    const url = new URL(request.secretUrl);
    const base = input.stack.controllerUrl;
    const issued = await fetch(`${base}/api/v2/secret/browser-status/${request.requestId}/capability?sig=${encodeURIComponent(url.searchParams.get("metadata_sig")!)}`, { method: "POST" });
    const { status_sig } = (await issued.json()) as { status_sig: string };
    await new Promise((resolve) => setTimeout(resolve, 6_500));
    expect((await fetch(`${base}/api/v2/secret/browser-status/${request.requestId}/capability?sig=${encodeURIComponent(url.searchParams.get("metadata_sig")!)}`, { method: "POST" })).status).toBe(410);
    const read = await fetch(`${base}/api/v2/secret/browser-status/${request.requestId}?sig=${encodeURIComponent(status_sig)}`);
    expect(read.status).toBe(410);
    expect(await read.json()).toEqual({ status: "expired" });
  });

  test("SI-E05: a suspended tab rechecks the deadline on return instead of trusting stalled timers", async ({ browser }) => {
    const request = await input.createRequest("Suspended tab");
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.clock.install();
    await page.goto(request.secretUrl);
    await ready(page);
    await page.getByTestId("secret-input").fill("left-in-a-background-tab");
    // Freeze timers, hide the tab, move the wall clock past the deadline, then return.
    const pageNow = await page.evaluate(() => Date.now());
    await page.clock.pauseAt(new Date(pageNow + 100));
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await page.clock.setSystemTime(new Date(pageNow + 60_000));
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect(page.getByTestId("outcome-body")).toHaveText("The link expired while this page was open. Nothing was sent, and the field was cleared.");
    expect(await fieldValues(page)).toEqual([]);
    await context.close();
  });
});
