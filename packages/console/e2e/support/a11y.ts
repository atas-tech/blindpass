import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";

const require = createRequire(import.meta.url);
let axeSource: string | null = null;

/**
 * Run axe-core in the page (WCAG 2.x A/AA rules, including contrast). The
 * page must come from a context created with bypassCSP, because axe is
 * injected as a script the console's CSP would otherwise refuse.
 */
export async function axeViolations(page: Page, include?: string): Promise<string[]> {
  axeSource ??= await readFile(require.resolve("axe-core/axe.min.js"), "utf8");
  if (!(await page.evaluate(() => "axe" in window))) await page.addScriptTag({ content: axeSource });
  return page.evaluate(async (selector) => {
    const axe = (window as unknown as { axe: { run: (context: unknown, options: unknown) => Promise<{ violations: Array<{ id: string; impact: string; nodes: Array<{ target: string[] }> }> }> } }).axe;
    const result = await axe.run(selector ? { include: [selector] } : document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] },
      rules: { region: { enabled: false } }
    });
    return result.violations.map((violation) => `${violation.id} (${violation.impact}): ${violation.nodes.map((node) => node.target.join(" ")).slice(0, 4).join(", ")}`);
  }, include ?? null);
}

/** Every element that could be touched must reach the target size. */
export async function smallTargets(page: Page, minimum: number): Promise<string[]> {
  return page.evaluate((min) => {
    const found: string[] = [];
    for (const element of document.querySelectorAll<HTMLElement>("button, a[href], input, select, textarea, summary, [role=radio]")) {
      const style = getComputedStyle(element);
      if (style.visibility === "hidden" || style.display === "none" || element.closest("[hidden], [inert]")) continue;
      const rect = element.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) continue;
      if (element instanceof HTMLInputElement && element.type === "checkbox") continue;
      if (rect.height + 0.5 < min) found.push(`${element.tagName.toLowerCase()}${element.className ? "." + String(element.className).split(" ")[0] : ""} "${(element.textContent ?? element.getAttribute("aria-label") ?? "").trim().slice(0, 30)}" ${Math.round(rect.width)}×${Math.round(rect.height)}`);
    }
    return found;
  }, minimum);
}

/** Horizontal overflow of the whole document (DR-E03/E07). */
export async function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}
