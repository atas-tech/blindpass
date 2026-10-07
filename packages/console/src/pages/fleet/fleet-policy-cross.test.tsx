import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../../test/axe.js";
import { fakeController, json, renderRoute, type Call } from "../../test/controller.js";

function workload(id: string, node: string, name: string, status = "active") {
  return { id, node_id: node, name, unit: `${name}.service`, account: "svc", consumption_mode: "file", local_ceiling_seconds: 120, registration_version: 1, status, created_at: Date.now() - 100_000, version: 1 };
}

const WORKLOADS = [workload("wl_i", "nd_i", "issuer-app"), workload("wl_r", "nd_r", "recipient-app"), workload("wl_s", "nd_s", "spare-app"), workload("wl_dead", "nd_r", "retired-app", "revoked")];

const MULTI_RULE = { id: "cross-multi", issuer_workload_ids: ["wl_i", "wl_gone"], recipient_workload_ids: ["wl_r", "wl_s"], decision: "pending_approval", max_ttl_seconds: 300, approver_ids: ["ada", "rina"] };

function policy(cross: unknown[], rules: unknown[] = [{ id: "noop-file", action: "noop.marker", mode: "file", decision: "allow", approval_required: false, max_ttl_seconds: 60 }]) {
  return { version: 5, rules, cross_workload: cross, updated_at: Date.now(), updated_by: "op_ada" };
}

function setup(options: { cross?: unknown[]; role?: "admin" | "operator"; fulfillments?: boolean; put?: (call: Call) => Response } = {}) {
  const cross = options.cross ?? [];
  return fakeController({
    role: options.role ?? "admin",
    fulfillments: options.fulfillments ?? true,
    handler: (call) => {
      if (call.path === "/api/v3/workloads") return json(200, { items: WORKLOADS, next_cursor: null });
      if (call.path === "/api/v3/policies" && call.method === "PUT") {
        if (options.put) return options.put(call);
        const body = call.body as { rules: unknown[]; cross_workload?: unknown[] };
        return json(200, { version: 6, rules: body.rules, cross_workload: body.cross_workload ?? cross, updated_at: Date.now(), updated_by: "op_ada" });
      }
      if (call.path === "/api/v3/policies") return json(200, policy(cross));
      return undefined;
    }
  });
}

const put = (calls: Call[]) => calls.find((call) => call.method === "PUT")!;

describe("P10-D4 cross-workload policy rules", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("the panel exists only when the controller reports the fulfillment flag", async () => {
    setup({ fulfillments: false, cross: [MULTI_RULE] });
    renderRoute("/policy/fleet");
    await screen.findByRole("radiogroup", { name: "Decision for Socket" });
    expect(screen.queryByRole("heading", { name: "Cross-workload rules" })).toBeNull();
  });

  it("states first match wins and that an unmatched pair is denied", async () => {
    setup({ cross: [] });
    renderRoute("/policy/fleet");
    const panel = (await screen.findByRole("heading", { name: "Cross-workload rules" })).closest("section")!;
    expect(panel.textContent).toMatch(/first rule that names both workloads decides/i);
    expect(panel.textContent).toMatch(/no matching rule/i);
    expect(panel.textContent).toMatch(/denied/);
  });

  it("changing only the exchange-rule matrix sends no cross_workload field, so the server keeps the stored rules", async () => {
    const { calls } = setup({ cross: [MULTI_RULE] });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    const socket = await screen.findByRole("radiogroup", { name: "Decision for Socket" });
    await user.click(within(socket).getByRole("radio", { name: "Deny" }));
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText("Fleet policy saved as version 6")).toBeTruthy();
    const body = put(calls).body as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["expected_version", "rules"]);
  });

  it("a rule with several ids, including a workload that is gone, round-trips unchanged when only its lifetime changes", async () => {
    const { calls } = setup({ cross: [MULTI_RULE] });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    const rule = await ruleSection("cross-multi");
    expect(within(rule).getByRole("checkbox", { name: /wl_gone/ })).toBeTruthy();
    expect(within(rule).getByText(/no longer registered/i)).toBeTruthy();
    const ttl = within(rule).getByLabelText("Longest fulfillment (seconds)");
    await user.clear(ttl);
    await user.type(ttl, "120");
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText("Fleet policy saved as version 6")).toBeTruthy();
    expect(put(calls).body).toEqual({
      expected_version: 5,
      rules: [{ id: "noop-file", action: "noop.marker", mode: "file", decision: "allow", approval_required: false, max_ttl_seconds: 60 }],
      cross_workload: [{ ...MULTI_RULE, max_ttl_seconds: 120 }]
    });
    expect(put(calls).headers.get("if-match")).toBe('"5"');
  });

  it("adds an allow rule from the workload list and sends the exact selectors", async () => {
    const { calls } = setup({ cross: [] });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    await user.click(await screen.findByRole("button", { name: "Add cross-workload rule" }));
    const rule = await ruleSection("cross-rule-1");
    // Revoked workloads are not offered as selectors.
    expect(within(rule).queryByRole("checkbox", { name: /retired-app/ })).toBeNull();
    const id = within(rule).getByLabelText("Rule ID");
    await user.clear(id);
    await user.type(id, "rotate-api");
    await user.click(within(within(rule).getByRole("group", { name: "Issuer workloads" })).getByRole("checkbox", { name: /issuer-app/ }));
    await user.click(within(within(rule).getByRole("group", { name: "Recipient workloads" })).getByRole("checkbox", { name: /recipient-app/ }));
    await user.click(within(rule).getByRole("radio", { name: "Allow" }));
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText("Fleet policy saved as version 6")).toBeTruthy();
    expect((put(calls).body as { cross_workload: unknown[] }).cross_workload).toEqual([{ id: "rotate-api", issuer_workload_ids: ["wl_i"], recipient_workload_ids: ["wl_r"], decision: "allow", max_ttl_seconds: 300 }]);
  });

  it("pending approval requires named approvers and sends them once each", async () => {
    const { calls } = setup({ cross: [] });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    await user.click(await screen.findByRole("button", { name: "Add cross-workload rule" }));
    const rule = await ruleSection("cross-rule-1");
    await user.click(within(within(rule).getByRole("group", { name: "Issuer workloads" })).getByRole("checkbox", { name: /issuer-app/ }));
    await user.click(within(within(rule).getByRole("group", { name: "Recipient workloads" })).getByRole("checkbox", { name: /recipient-app/ }));
    await user.click(within(rule).getByRole("radio", { name: "Needs approval" }));
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await within(rule).findByText(/Name 1–32 approvers/)).toBeTruthy();
    expect(calls.some((call) => call.method === "PUT")).toBe(false);
    await user.type(within(rule).getByLabelText("Cross-workload approvers"), "ada{enter}rina, ada");
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText("Fleet policy saved as version 6")).toBeTruthy();
    expect((put(calls).body as { cross_workload: Array<Record<string, unknown>> }).cross_workload[0]).toMatchObject({ decision: "pending_approval", approver_ids: ["ada", "rina"] });
  });

  it.each([
    ["no issuer selected", async (user: ReturnType<typeof userEvent.setup>, rule: HTMLElement) => user.click(within(within(rule).getByRole("group", { name: "Issuer workloads" })).getByRole("checkbox", { name: /issuer-app/ })), /Choose 1–16 issuer workloads/],
    ["a rule id with spaces", async (user: ReturnType<typeof userEvent.setup>, rule: HTMLElement) => { const id = within(rule).getByLabelText("Rule ID"); await user.clear(id); await user.type(id, "bad id"); }, /Use letters, digits, _ and -/],
    ["a lifetime above 600 seconds", async (user: ReturnType<typeof userEvent.setup>, rule: HTMLElement) => { const ttl = within(rule).getByLabelText("Longest fulfillment (seconds)"); await user.clear(ttl); await user.type(ttl, "601"); }, /whole number from 1 to 600/]
  ])("%s blocks the save and sends nothing", async (_name, breakIt, message) => {
    const { calls } = setup({ cross: [] });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    await user.click(await screen.findByRole("button", { name: "Add cross-workload rule" }));
    const rule = await ruleSection("cross-rule-1");
    // A valid baseline, then break exactly one thing.
    await user.click(within(within(rule).getByRole("group", { name: "Issuer workloads" })).getByRole("checkbox", { name: /issuer-app/ }));
    await user.click(within(within(rule).getByRole("group", { name: "Recipient workloads" })).getByRole("checkbox", { name: /recipient-app/ }));
    await breakIt(user, rule);
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText(message)).toBeTruthy();
    expect(calls.some((call) => call.method === "PUT")).toBe(false);
  });

  it("removing the last rule sends an explicit empty array, which denies every fulfillment", async () => {
    const { calls } = setup({ cross: [MULTI_RULE] });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    const rule = await ruleSection("cross-multi");
    await user.click(within(rule).getByRole("button", { name: "Remove rule cross-multi" }));
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText("Fleet policy saved as version 6")).toBeTruthy();
    expect((put(calls).body as Record<string, unknown>).cross_workload).toEqual([]);
  });

  it("order matters: moving a rule up changes the array order that is sent", async () => {
    const second = { id: "cross-allow", issuer_workload_ids: ["wl_i"], recipient_workload_ids: ["wl_r"], decision: "allow", max_ttl_seconds: 60 };
    const { calls } = setup({ cross: [MULTI_RULE, second] });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    const rule = await ruleSection("cross-allow");
    expect((within(rule).getByRole("button", { name: "Move rule cross-allow down" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(within(rule).getByRole("button", { name: "Move rule cross-allow up" }));
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText("Fleet policy saved as version 6")).toBeTruthy();
    expect((put(calls).body as { cross_workload: Array<{ id: string }> }).cross_workload.map((item) => item.id)).toEqual(["cross-allow", "cross-multi"]);
  });

  it("operators can read the cross-workload rules but not edit them", async () => {
    setup({ cross: [MULTI_RULE], role: "operator" });
    renderRoute("/policy/fleet");
    const panel = (await screen.findByRole("heading", { name: "Cross-workload rules" })).closest("section")!;
    expect(panel.textContent).toContain("cross-multi");
    expect(panel.textContent).toContain("issuer-app");
    expect(panel.textContent).toContain("wl_gone");
    expect(within(panel).queryByRole("button", { name: "Add cross-workload rule" })).toBeNull();
    expect(within(panel).queryByRole("textbox")).toBeNull();
  });

  it("maps a refused rule to a specific message and keeps the draft", async () => {
    setup({ cross: [MULTI_RULE], put: () => json(400, { error: "invalid_policy_rule", message: "server text must not be shown" }) });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    const rule = await ruleSection("cross-multi");
    const ttl = within(rule).getByLabelText("Longest fulfillment (seconds)");
    await user.clear(ttl);
    await user.type(ttl, "90");
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    const alert = await screen.findByText(/The controller refused a cross-workload rule/);
    expect(alert.textContent).not.toContain("server text must not be shown");
    expect((within(await ruleSection("cross-multi")).getByLabelText("Longest fulfillment (seconds)") as HTMLInputElement).value).toBe("90");
  });

  it("the cross-workload panel passes the accessibility checks", async () => {
    setup({ cross: [MULTI_RULE] });
    const { container } = renderRoute("/policy/fleet");
    await ruleSection("cross-multi");
    await waitFor(() => expect(screen.getByRole("heading", { name: "Cross-workload rules" })).toBeTruthy());
    expect(await axeViolations(container)).toEqual([]);
  });
});

async function ruleSection(id: string): Promise<HTMLElement> {
  return waitFor(() => {
    const section = document.querySelector<HTMLElement>(`section[data-cross-rule="${id}"]`);
    if (!section) throw new Error(`no cross-workload rule ${id}`);
    return section;
  });
}
