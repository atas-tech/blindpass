import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

const script = readFileSync(new URL("../dist/script.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");

// Minimal DOM doubles exercise the shipped script; these are not browser/layout tests.
function element(children = {}, dataset = {}) {
  const attributes = new Map();
  const listeners = new Map();
  return {
    textContent: "", hidden: false, dataset,
    classList: { toggle() {} },
    querySelector(selector) {
      assert.ok(children[selector], `Missing child ${selector}`);
      return children[selector];
    },
    setAttribute(name, value) { attributes.set(name, value); },
    getAttribute(name) { return attributes.get(name); },
    removeAttribute(name) { attributes.delete(name); },
    addEventListener(name, callback) { listeners.set(name, callback); },
    click() { assert.equal(this.hidden, false); listeners.get("click")(); },
    focus() {}
  };
}

function setup() {
  const nodes = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map((match) => [`#${match[1]}`, element()]));
  nodes[".menu-toggle"] = element();
  nodes["#demo-primary"] = element({ span: element() });
  const buttons = Object.fromEntries(["human", "exchange", "browser"].map((flow) => [flow, element({}, { flow })]));
  const steps = Array.from({ length: 4 }, () => element({ strong: element(), small: element() }));
  const details = Array.from({ length: 4 }, () => element({ dt: element(), dd: element() }));
  const lists = { "[data-flow]": Object.values(buttons), ".workflow-steps li": steps, ".request-details > div": details };
  runInNewContext(script, {
    document: {
      querySelector(selector) { assert.ok(nodes[selector], `Missing HTML selector ${selector}`); return nodes[selector]; },
      querySelectorAll(selector) { assert.ok(lists[selector]); return lists[selector]; },
      addEventListener() {}
    },
    window: { matchMedia: () => ({ addEventListener() {} }) }
  });
  return {
    nodes, buttons, steps, details,
    primary: () => nodes["#demo-primary"].click(),
    secondary: () => nodes["#demo-secondary"].click(),
    status: () => nodes["#request-status"].textContent,
    feedback: () => nodes["#demo-feedback"].textContent
  };
}

test("human provisioning completes without claiming provider-key revocation", () => {
  const demo = setup();
  assert.equal(demo.buttons.human.getAttribute("aria-pressed"), "true");
  demo.primary();
  assert.equal(demo.status(), "Waiting for a person");
  demo.primary();
  assert.equal(demo.status(), "Example ciphertext ready");
  assert.equal(demo.nodes["#demo-secondary"].hidden, true);
  demo.primary();
  assert.equal(demo.status(), "Example secret delivered");
  assert.match(demo.feedback(), /API key remains valid/);
  assert.ok(demo.steps.every((step) => step.getAttribute("aria-current") === undefined), "a finished flow leaves no step current");
  demo.primary();
  assert.equal(demo.status(), "Ready to request");
});

test("agent approval is followed by fulfillment and retrieval, not immediate delivery", () => {
  const demo = setup();
  demo.buttons.exchange.click();
  demo.primary();
  assert.equal(demo.status(), "Example approval required");
  demo.primary();
  assert.equal(demo.status(), "Example exchange authorized");
  demo.primary();
  assert.equal(demo.status(), "Example ciphertext ready");
  assert.equal(demo.steps[3].getAttribute("aria-current"), "step");
  demo.primary();
  assert.equal(demo.status(), "Example exchange complete");
  assert.ok(demo.steps.every((step) => step.getAttribute("aria-current") === undefined), "retrieval advances past the last step");
  assert.match(demo.nodes["#request-description"].textContent, /permission is not automatically reciprocal/);
  assert.match(demo.feedback(), /does not revoke/);
});

for (const flow of ["human", "exchange", "browser"]) {
  test(`${flow} rejection stops before delivery and allows restarting`, () => {
    const demo = setup();
    demo.buttons[flow].click();
    demo.primary();
    demo.secondary();
    assert.match(demo.status(), /declined|rejected/);
    assert.equal(demo.nodes["#demo-secondary"].hidden, true);
    demo.primary();
    assert.equal(demo.status(), "Ready to request");
  });
}

test("switching flows resets progress, selection, labels and secret metadata", () => {
  const demo = setup();
  demo.primary();
  demo.primary();
  demo.buttons.browser.click();
  assert.equal(demo.status(), "Ready to request");
  assert.match(demo.nodes["#flow-caption"].textContent, /Proposed pilot/);
  assert.equal(demo.details[0].querySelector("dt").textContent, "Workload");
  demo.buttons.exchange.click();
  assert.equal(demo.buttons.browser.getAttribute("aria-pressed"), "false");
  assert.equal(demo.buttons.exchange.getAttribute("aria-pressed"), "true");
  assert.equal(demo.details[0].querySelector("dd").textContent, "report-agent");
  assert.equal(demo.steps[0].getAttribute("aria-current"), "step");
  assert.equal(demo.steps[2].getAttribute("aria-current"), undefined);
});

test("browser pilot retains completion and simulated early revocation", () => {
  const demo = setup();
  demo.buttons.browser.click();
  demo.primary();
  demo.primary();
  assert.equal(demo.status(), "Example session active");
  demo.secondary();
  assert.equal(demo.status(), "Example access revoked");
  assert.match(demo.feedback(), /No real session/);
  demo.primary();
  demo.primary();
  demo.primary();
  demo.primary();
  assert.equal(demo.status(), "Example session ended");
});
