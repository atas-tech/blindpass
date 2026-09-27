// DR-E06: English and Vietnamese across sign-in and every protected screen,
// through reload and sign-out/in. Besides the headings, each Vietnamese page
// is scanned for any English catalog string that has a different Vietnamese
// translation, which catches hardcoded or untranslated copy on real data.
import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { horizontalOverflow } from "./support/a11y.js";
import { ADMIN, AGENT_IDS, AdminClient, REPO_ROOT, Stack } from "./support/stack.js";

type Catalog = { [key: string]: string | Catalog };

async function catalog(locale: "en" | "vi"): Promise<Catalog> {
  return JSON.parse(await readFile(path.join(REPO_ROOT, `packages/i18n/locales/${locale}/console.json`), "utf8")) as Catalog;
}

function lookup(source: Catalog, key: string): string {
  const value = key.split(".").reduce<string | Catalog>((node, part) => (node as Catalog)[part]!, source);
  if (typeof value !== "string") throw new Error(`no string at ${key}`);
  return value;
}

/** English strings whose Vietnamese translation differs, split at placeholders. */
function englishOnly(en: Catalog, vi: Catalog, prefix = ""): string[] {
  const found: string[] = [];
  for (const [key, value] of Object.entries(en)) {
    const other = vi[key];
    if (typeof value === "string") {
      if (typeof other !== "string" || other === value) continue;
      for (const piece of value.split(/\{\{[^}]+\}\}|<\d+>|<\/\d+>/)) {
        const text = piece.trim();
        // Short fragments ("of", "ID") are too ambiguous to scan for.
        if (text.length >= 12 && !other.includes(text)) found.push(text);
      }
    } else if (other && typeof other !== "string") {
      found.push(...englishOnly(value, other, `${prefix}${key}.`));
    }
  }
  return found;
}

const ROUTES: Array<{ path: string; heading: string }> = [
  { path: "/", heading: "overview.greeting" },
  { path: "/approvals", heading: "approvals.title" },
  { path: "/agents", heading: "agents.title" },
  { path: "/policy", heading: "policy.title" },
  { path: "/audit", heading: "audit.title" },
  { path: "/enrollments", heading: "fleet.enrollment.title" },
  { path: "/nodes", heading: "fleet.node.title" },
  { path: "/workloads", heading: "fleet.workload.title" },
  { path: "/policy/fleet", heading: "fleet.policy.title" },
  { path: "/grants", heading: "fleet.grant.title" },
  { path: "/operations", heading: "fleet.operation.title" },
  { path: "/settings", heading: "settings.title" },
  { path: "/settings/operators", heading: "operators.title" }
];

/** A heading matcher; placeholders ({{name}}) match anything. */
function heading(source: Catalog, key: string): RegExp {
  const pattern = lookup(source, key).split(/\{\{[^}]+\}\}/).map((piece) => piece.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp(`^${pattern}$`);
}

async function leaks(page: Page, strings: string[]): Promise<string[]> {
  const text = await page.evaluate(() => document.body.innerText);
  return strings.filter((value) => text.includes(value));
}

test.describe("locale across the console", () => {
  let stack: Stack;
  let en: Catalog;
  let vi: Catalog;
  let english: string[];

  test.beforeAll(async () => {
    [en, vi] = await Promise.all([catalog("en"), catalog("vi")]);
    // Seeded names are data, not copy.
    english = englishOnly(en, vi).filter((value) => !ADMIN.display_name.includes(value));
    stack = await Stack.start({});
    const admin = new AdminClient(stack);
    await admin.bootstrap();
    // Real rows on the list screens, so row and status copy is scanned too.
    const keys = await stack.seedAgents([AGENT_IDS.requester, AGENT_IDS.fulfiller]);
    await stack.requestExchange(await stack.agentToken(keys[AGENT_IDS.requester]!), "Locale scan purpose");
  });
  test.afterAll(async () => stack?.stop());

  test("DR-E06: Vietnamese chosen at sign-in holds on every screen, through reload and sign-out/in, with no English catalog strings and no overflow", async ({ browser }) => {
    // 26 screen loads in one context; this also guards the preview harness
    // against the repeated-reload failure the cache profile fixes.
    test.setTimeout(240_000);
    expect(english.length).toBeGreaterThan(100);
    for (const route of ROUTES) lookup(en, route.heading);
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const page = await context.newPage();
    await page.goto(`${stack.consoleUrl}/login`);
    await page.getByRole("combobox", { name: lookup(en, "locale.label") }).selectOption("vi");
    await expect(page.locator("html")).toHaveAttribute("lang", "vi");
    await expect(page.getByRole("button", { name: lookup(vi, "auth.signIn") })).toBeVisible();
    expect(await leaks(page, english)).toEqual([]);
    await page.getByLabel(lookup(vi, "auth.fields.username")).fill(ADMIN.username);
    await page.getByLabel(lookup(vi, "auth.fields.password"), { exact: true }).fill(ADMIN.password);
    await page.getByRole("button", { name: lookup(vi, "auth.signIn") }).click();
    await expect(page).not.toHaveURL(/\/login/);

    for (const width of [390, 1440]) {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
      for (const route of ROUTES) {
        await page.goto(`${stack.consoleUrl}${route.path}`);
        await expect(page.getByRole("heading", { level: 1, name: heading(vi, route.heading) }), route.path).toBeVisible();
        // Let lists and panels settle before scanning.
        await expect(page.locator(".skeleton, [aria-busy='true']")).toHaveCount(0);
        await expect(page.locator("html")).toHaveAttribute("lang", "vi");
        expect(await leaks(page, english), `${route.path} at ${width}px`).toEqual([]);
        expect(await horizontalOverflow(page), `${route.path} at ${width}px`).toBeLessThanOrEqual(0);
      }
    }

    await page.goto(`${stack.consoleUrl}/approvals`);
    await page.reload();
    await expect(page.getByRole("heading", { level: 1, name: heading(vi, "approvals.title") })).toBeVisible();
    await page.getByRole("button", { name: lookup(vi, "auth.signOut") }).click();
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole("button", { name: lookup(vi, "auth.signIn") })).toBeVisible();
    await page.getByLabel(lookup(vi, "auth.fields.username")).fill(ADMIN.username);
    await page.getByLabel(lookup(vi, "auth.fields.password"), { exact: true }).fill(ADMIN.password);
    await page.getByRole("button", { name: lookup(vi, "auth.signIn") }).click();
    await expect(page.getByRole("heading", { level: 1, name: heading(vi, "overview.greeting") })).toBeVisible();

    // Back to English: every heading follows at once.
    await page.getByRole("combobox", { name: lookup(vi, "locale.label") }).selectOption("en");
    await expect(page.locator("html")).toHaveAttribute("lang", "en");
    await expect(page.getByRole("heading", { level: 1, name: heading(en, "overview.greeting") })).toBeVisible();
    // Control: the same scan does find English copy on an English page.
    expect((await leaks(page, english)).length).toBeGreaterThan(0);
    await context.close();
  });
});
