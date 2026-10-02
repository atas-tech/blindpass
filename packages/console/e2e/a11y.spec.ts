// DR-E07 / DR-E22: every carried route at the declared widths, 200% zoom,
// keyboard-only and reduced motion, with realistic long data. axe covers the
// automatable WCAG rules; the focus walk checks what axe can't: every stop
// is visible, on screen and shows a focus indicator. Manual screen-reader
// review is still separate.
import { expect, test, type Page } from "@playwright/test";
import { axeViolations, horizontalOverflow, smallTargets } from "./support/a11y.js";
import { publishOffer, seedOperation, startWorld } from "./support/provisioning-world.js";
import { ADMIN, AGENT_IDS, AdminClient, Stack } from "./support/stack.js";

const ROUTES = [
  "/",
  "/approvals",
  "/agents",
  "/policy",
  "/audit",
  "/enrollments",
  "/nodes",
  "/workloads",
  "/policy/fleet",
  "/grants",
  "/operations",
  "/settings",
  "/settings/operators"
];
const WIDTHS = [320, 390, 768, 1024, 1440];
const LONG = `Rotate the reporting replica credential before the maintenance window closes — ${"requested-by-the-release-pipeline ".repeat(3)}`.slice(0, 240);

async function signIn(page: Page, stack: Stack) {
  await page.goto(`${stack.consoleUrl}/login`);
  await page.getByLabel("Username").fill(ADMIN.username);
  await page.getByLabel("Password", { exact: true }).fill(ADMIN.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).not.toHaveURL(/\/login/);
}

async function settle(page: Page) {
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.locator(".skeleton, [aria-busy='true']")).toHaveCount(0);
}

/**
 * Tab through the page. Every stop must be a real, visible, on-screen
 * element with a focus indicator (outline or ring), and focus must not
 * fall back to the body before the walk wraps.
 */
async function focusWalk(page: Page, limit = 80): Promise<string[]> {
  const problems: string[] = [];
  const seen = new Set<string>();
  await page.locator("body").focus();
  for (let step = 0; step < limit; step++) {
    await page.keyboard.press("Tab");
    const stop = await page.evaluate(() => {
      const element = document.activeElement as HTMLElement | null;
      if (!element || element === document.body) return { kind: "body" as const };
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      const ring = style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0;
      const shadow = style.boxShadow !== "none";
      // A native control wrapped by a styled label shows the ring on the label.
      const wrapper = element.closest("label, .role-option, .segmented-option, .secret-field");
      const wrapperStyle = wrapper ? getComputedStyle(wrapper) : null;
      const wrapperRing = wrapperStyle ? (wrapperStyle.outlineStyle !== "none" && parseFloat(wrapperStyle.outlineWidth) > 0) || wrapperStyle.boxShadow !== "none" : false;
      const name = `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""}${element.className && typeof element.className === "string" ? `.${element.className.split(" ")[0]}` : ""} "${(element.getAttribute("aria-label") ?? element.textContent ?? "").trim().slice(0, 30)}"`;
      return {
        kind: "element" as const,
        name,
        visible: rect.width > 0 && rect.height > 0 && style.visibility !== "hidden",
        onScreen: rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth,
        indicator: ring || shadow || wrapperRing
      };
    });
    if (stop.kind === "body") {
      if (step === 0) problems.push("first Tab leaves focus on the body");
      break;
    }
    if (seen.has(stop.name) && seen.size > 3) break;
    seen.add(stop.name);
    if (!stop.visible) problems.push(`${stop.name} is focusable but not visible`);
    else if (!stop.onScreen) problems.push(`${stop.name} is focused off screen`);
    else if (!stop.indicator) problems.push(`${stop.name} has no focus indicator`);
  }
  return problems;
}

test.describe("accessibility across the console", () => {
  let stack: Stack;
  let admin: AdminClient;

  test.beforeAll(async () => {
    stack = await Stack.start({});
    admin = new AdminClient(stack);
    await admin.bootstrap();
    await admin.createOperator("e2e-long-operator-name-for-wrapping-checks", "operator", "Nguyễn Thị Phương Thảo — Night Shift Operations Lead");
    const keys = await stack.seedAgents([AGENT_IDS.requester, AGENT_IDS.fulfiller]);
    const token = await stack.agentToken(keys[AGENT_IDS.requester]!);
    await stack.requestExchange(token, LONG);
    await stack.requestExchange(token, "Nightly export");
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E07: every route fits 320–1440 px without horizontal overflow, passes axe, and keeps 44 px targets on touch", async ({ browser }) => {
    test.setTimeout(300_000);
    const context = await browser.newContext({ bypassCSP: true });
    const page = await context.newPage();
    await signIn(page, stack);
    const failures: string[] = [];
    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: 900 });
      for (const route of ROUTES) {
        await page.goto(`${stack.consoleUrl}${route}`);
        await settle(page);
        const overflow = await horizontalOverflow(page);
        if (overflow > 0) failures.push(`${route} at ${width}px overflows by ${overflow}px`);
        if (width === 390 || width === 1440) {
          for (const violation of await axeViolations(page)) failures.push(`${route} at ${width}px axe ${violation}`);
        }
      }
    }
    expect(failures).toEqual([]);
    await context.close();

    const touch = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
    const phone = await touch.newPage();
    await signIn(phone, stack);
    const small: string[] = [];
    for (const route of ROUTES) {
      await phone.goto(`${stack.consoleUrl}${route}`);
      await settle(phone);
      for (const target of await smallTargets(phone, 44)) small.push(`${route}: ${target}`);
    }
    expect(small).toEqual([]);
    await touch.close();
  });

  test("DR-E07 / DR-E22 / P05-PV06-S: the operation detail with the Provide Source panel in every state, and the fleet input page, fit 320-1440 px, pass axe and have a clean focus walk", async ({ browser }) => {
    test.setTimeout(300_000);
    const world = await startWorld(stack, admin);
    const seeded = await seedOperation(world, "accessibility");
    const context = await browser.newContext({ bypassCSP: true, viewport: { width: 1440, height: 900 } });
    const failures: string[] = [];
    const panelHeading = (page: Page) => page.getByRole("heading", { name: "Provide Source" });
    const audit = async (page: Page, label: string, widths = WIDTHS) => {
      for (const width of widths) {
        await page.setViewportSize({ width, height: 900 });
        const overflow = await horizontalOverflow(page);
        if (overflow > 0) failures.push(`${label} at ${width}px overflows by ${overflow}px`);
        if (width === 390 || width === 1440) for (const violation of await axeViolations(page)) failures.push(`${label} at ${width}px axe ${violation}`);
      }
      await page.setViewportSize({ width: 1440, height: 900 });
      for (const problem of await focusWalk(page)) failures.push(`${label}: ${problem}`);
    };
    try {
      const page = await context.newPage();
      await page.goto(`${stack.consoleUrl}/login`);
      await page.getByLabel("Username").fill(world.owner.username);
      await page.getByLabel("Password", { exact: true }).fill(world.owner.password);
      await page.getByRole("button", { name: "Sign in" }).click();
      await expect(page).not.toHaveURL(/\/login/);
      await page.goto(`${stack.consoleUrl}/operations/${encodeURIComponent(seeded.operationId)}`);
      await expect(panelHeading(page)).toBeVisible();
      await expect(page.locator("section.provision-panel").getByRole("status")).toContainText("Waiting for the node");
      await audit(page, "operation detail, waiting for the offer");

      await publishOffer(world, seeded, 200_000);
      const provide = page.locator("section.provision-panel").getByRole("button", { name: "Provide Source", exact: true });
      await expect(provide).toBeVisible({ timeout: 15_000 });
      await audit(page, "operation detail, offer ready");

      const [input] = await Promise.all([context.waitForEvent("page"), provide.click()]);
      await input.waitForLoadState("domcontentloaded");
      await expect(input.getByTestId("status")).toHaveText("Awaiting input");
      await audit(input, "fleet input page, ready");

      await expect(page.locator("section.provision-panel").getByRole("button", { name: "Open the Source page again" })).toBeVisible({ timeout: 15_000 });
      await audit(page, "operation detail, link issued");

      await input.setViewportSize({ width: 1440, height: 900 });
      await input.getByTestId("secret-input").fill("accessibility check value");
      await input.getByTestId("submit-btn").click();
      await expect(input.getByTestId("outcome-title")).toHaveText("Your part is done.", { timeout: 20_000 });
      await audit(input, "fleet input page, submitted");

      await expect(page.locator("section.provision-panel").getByText("Source received")).toBeVisible({ timeout: 15_000 });
      await audit(page, "operation detail, submitted");

      // The refusal states a stranger sees (no session): sign-in required, and an unavailable link.
      const stranger = await browser.newContext({ bypassCSP: true, viewport: { width: 1440, height: 900 } });
      try {
        const anonymous = await stranger.newPage();
        const issued = await world.owner.client.call<{ input_path: string }>("POST", `/api/v3/admin/operations/${encodeURIComponent(seeded.operationId)}/provisioning-link`, undefined, { "idempotency-key": `e2e-a11y-${Date.now()}-${"0".repeat(8)}` });
        // The operation is submitted, so the link route answers 410; fall back to a well-formed dummy link.
        const target = issued.status === 201 || issued.status === 200 ? issued.body.input_path : `/?kind=fleet&id=${"a".repeat(64)}&metadata_sig=1.${"A".repeat(43)}&submit_sig=1.${"A".repeat(43)}`;
        await anonymous.goto(`${stack.consoleUrl}${target}`);
        await expect(anonymous.getByTestId("outcome-title")).toBeVisible();
        await audit(anonymous, "fleet input page, refused");
      } finally {
        await stranger.close();
      }
    } finally {
      await context.close();
    }
    expect(failures).toEqual([]);
  });

  test("DR-E07: at 200% zoom (720 CSS px on a 1440 px window) every route stays usable and navigation is reachable", async ({ browser }) => {
    test.setTimeout(180_000);
    const context = await browser.newContext({ viewport: { width: 720, height: 450 }, deviceScaleFactor: 2 });
    const page = await context.newPage();
    await signIn(page, stack);
    const failures: string[] = [];
    for (const route of ROUTES) {
      await page.goto(`${stack.consoleUrl}${route}`);
      await settle(page);
      const overflow = await horizontalOverflow(page);
      if (overflow > 0) failures.push(`${route} overflows by ${overflow}px`);
    }
    expect(failures).toEqual([]);
    // The navigation stays reachable: either the sidebar or its toggle is on screen.
    const toggle = page.getByRole("button", { name: "Open navigation" });
    const nav = page.getByRole("navigation", { name: "Main navigation" });
    expect((await toggle.isVisible()) || (await nav.isVisible())).toBe(true);
    await context.close();
  });

  test("DR-E22: keyboard-only, every focus stop on every route is visible, on screen and shows a focus indicator; the skip link moves to the content", async ({ browser }) => {
    test.setTimeout(240_000);
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await signIn(page, stack);
    const failures: string[] = [];
    for (const route of ROUTES) {
      await page.goto(`${stack.consoleUrl}${route}`);
      await settle(page);
      for (const problem of await focusWalk(page)) failures.push(`${route}: ${problem}`);
    }
    expect(failures).toEqual([]);

    await page.goto(`${stack.consoleUrl}/approvals`);
    await settle(page);
    await page.locator("body").focus();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
    await page.keyboard.press("Enter");
    expect(await page.evaluate(() => document.activeElement?.closest("main") !== null || document.activeElement?.id === "main")).toBe(true);
    await context.close();
  });

  test("DR-E07: with reduced motion requested, nothing on the console animates or transitions for longer than a frame", async ({ browser }) => {
    const context = await browser.newContext({ reducedMotion: "reduce" });
    const page = await context.newPage();
    await signIn(page, stack);
    const slow: string[] = [];
    for (const route of ["/", "/approvals", "/settings"]) {
      await page.goto(`${stack.consoleUrl}${route}`);
      await settle(page);
      slow.push(...(await page.evaluate(() => {
        const found: string[] = [];
        for (const element of document.querySelectorAll<HTMLElement>("body *")) {
          const style = getComputedStyle(element);
          const longest = Math.max(...`${style.transitionDuration},${style.animationDuration}`.split(",").map((value) => parseFloat(value) * (value.trim().endsWith("ms") ? 1 : 1000)));
          if (longest > 16) found.push(`${element.tagName.toLowerCase()}.${String(element.className).split(" ")[0]} ${longest}ms`);
        }
        return found.slice(0, 10);
      })).map((entry) => `${route}: ${entry}`));
    }
    expect(slow).toEqual([]);
    await context.close();
  });
});
