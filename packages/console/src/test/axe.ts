import axe from "axe-core";

/**
 * Run axe against rendered markup. jsdom has no layout or computed colour,
 * so contrast and target-size are checked in the browser suite and by the
 * token contrast test instead.
 */
export async function axeViolations(root: Element): Promise<string[]> {
  const result = await axe.run(root, {
    rules: {
      "color-contrast": { enabled: false },
      "target-size": { enabled: false },
      region: { enabled: false }
    }
  });
  return result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.html).join(" | ")}`);
}
