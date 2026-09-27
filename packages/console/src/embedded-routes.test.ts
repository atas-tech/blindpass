// The controller serves the console shell only for the route sections the
// console defines (P04-D9), so other unknown paths keep the machine
// contract's JSON 404 (CT18). This keeps the controller's list in step with
// the router.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (file: string) => readFileSync(path.resolve(here, file), "utf8");

function routerSections(): string[] {
  const source = read("app.tsx");
  const paths = [
    ...[...source.matchAll(/path: "(\/[^"]*)"/g)].map((match) => match[1]!),
    ...[...source.matchAll(/fleetRoute\("(\/[^"]*)"/g)].map((match) => match[1]!),
    ...JSON.parse(source.match(/export const REMOVED_ROUTES = (\[[^\]]*\])/)![1]!) as string[]
  ];
  return [...new Set(paths.map((route) => route.split("/")[1]!.replace("*", "")))].sort();
}

function controllerSections(): string[] {
  const source = read("../../../crates/blindpass-controller/src/embedded_ui.rs");
  const list = source.match(/const CONSOLE_SECTIONS: &\[&str\] = &\[([^\]]*)\]/);
  if (!list) throw new Error("CONSOLE_SECTIONS not found in embedded_ui.rs");
  return [...list[1]!.matchAll(/"([^"]*)"/g)].map((match) => match[1]!).sort();
}

describe("embedded console routes", () => {
  it("the controller's shell sections are exactly the router's top-level sections", () => {
    const sections = routerSections();
    expect(sections).toContain("");
    expect(sections).toContain("approvals");
    expect(sections).toContain("billing");
    expect(controllerSections()).toEqual(sections);
  });
});
