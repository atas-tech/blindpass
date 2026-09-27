import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../test/axe.js";
import { fakeController, json, renderRoute } from "../test/controller.js";

const CANARY_KEY = "bpk_canary_4f1d0c2e9a7b-DUMMY-NOT-A-SECRET";

function agent(overrides: Record<string, unknown> = {}) {
  return { id: "row_1", agent_id: "release-agent", workspace_id: "w", display_name: "Release agent", status: "active", created_at: "2026-09-20T10:00:00.000Z", revoked_at: null, ...overrides };
}

describe("agents", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("DR-E12 / DR-E13: enroll reveals the key once, requires confirmation, and the key is gone afterwards", async () => {
    let agents = [agent()];
    fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/admin/agents" && call.method === "POST") {
          const created = agent({ id: "row_2", agent_id: (call.body as { agent_id: string }).agent_id, display_name: "Build agent" });
          agents = [...agents, created];
          return json(201, { agent: created, bootstrap_api_key: CANARY_KEY });
        }
        if (call.path === "/api/v3/admin/agents") return json(200, { items: agents, next_cursor: null });
        return undefined;
      }
    });
    const user = userEvent.setup();
    const { container } = renderRoute("/agents");
    await screen.findByText("Release agent");
    await user.click(screen.getByRole("button", { name: "Enroll agent" }));
    const dialog = await screen.findByRole("dialog", { name: "Enroll an agent" });
    await user.click(within(dialog).getByRole("button", { name: "Enroll and show key" }));
    expect(within(dialog).getByText("Use 1–128 letters, digits and . _ : @ / - only.")).toBeTruthy();
    await user.type(within(dialog).getByLabelText(/Agent ID/), "build agent");
    await user.type(within(dialog).getByLabelText("Display name"), "Build agent");
    await user.click(within(dialog).getByRole("button", { name: "Enroll and show key" }));
    expect(within(dialog).getByText(/Use 1–128/)).toBeTruthy();
    await user.clear(within(dialog).getByLabelText(/Agent ID/));
    await user.type(within(dialog).getByLabelText(/Agent ID/), "build-agent");
    await user.click(within(dialog).getByRole("button", { name: "Enroll and show key" }));

    const reveal = await screen.findByRole("dialog", { name: "Bootstrap key for build-agent" });
    expect(reveal.textContent).toContain(CANARY_KEY);
    const close = within(reveal).getByRole("button", { name: "Done" });
    expect((close as HTMLButtonElement).disabled).toBe(true);
    reveal.dispatchEvent(new Event("cancel", { cancelable: true }));
    expect(reveal.hasAttribute("open")).toBe(true);
    await user.click(within(reveal).getByLabelText("I stored this value somewhere safe"));
    await user.click(close);
    await waitFor(() => expect(container.ownerDocument.body.textContent).not.toContain(CANARY_KEY));
    expect(await screen.findByText("Build agent")).toBeTruthy();
    expect(JSON.stringify({ ...window.localStorage, ...window.sessionStorage })).not.toContain(CANARY_KEY);
  });

  it("DR-E12: rotate names the exact agent, reveals a replacement, and revoke confirms the scope", async () => {
    const { calls } = fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/admin/agents/row_1/rotate-key") return json(200, { agent: agent(), bootstrap_api_key: CANARY_KEY });
        if (call.path === "/api/v3/admin/agents/row_1" && call.method === "DELETE") return json(200, agent({ status: "revoked" }));
        if (call.path === "/api/v3/admin/agents") return json(200, { items: [agent(), agent({ id: "row_9", agent_id: "other-agent", display_name: "Other" })], next_cursor: null });
        return undefined;
      }
    });
    const user = userEvent.setup();
    renderRoute("/agents");
    await user.click(await screen.findByRole("button", { name: "Rotate the key for release-agent" }));
    const confirm = await screen.findByRole("dialog", { name: "Rotate the key for release-agent?" });
    expect(document.activeElement?.textContent).toBe("Cancel");
    await user.click(within(confirm).getByRole("button", { name: "Rotate and show key" }));
    const reveal = await screen.findByRole("dialog", { name: "Replacement key for release-agent" });
    expect(reveal.textContent).toContain("previous key no longer works");
    await user.click(within(reveal).getByRole("checkbox"));
    await user.click(within(reveal).getByRole("button", { name: "Done" }));
    await user.click(screen.getByRole("button", { name: "Revoke release-agent" }));
    const revoke = await screen.findByRole("dialog", { name: "Revoke release-agent?" });
    expect(revoke.textContent).toContain("can't be undone");
    await user.click(within(revoke).getByRole("button", { name: "Revoke agent" }));
    await waitFor(() => expect(calls.some((call) => call.method === "DELETE" && call.path === "/api/v3/admin/agents/row_1")).toBe(true));
    expect(calls.some((call) => call.path.includes("row_9") && call.method !== "GET")).toBe(false);
  });

  it("an operator cannot open agents", async () => {
    fakeController({ role: "operator", handler: () => undefined });
    renderRoute("/agents");
    expect(await screen.findByRole("heading", { name: "Your role can't open this page" })).toBeTruthy();
  });
});

const POLICY = {
  version: 4,
  policy: {
    secret_registry: [
      { secretName: "stripe.api_key", classification: "sensitive", description: "Payments" },
      { secretName: "docs.token", classification: "internal", owner: "docs-team" }
    ],
    exchange_policy: [
      { ruleId: "stripe-review", secretName: "stripe.api_key", mode: "pending_approval", requesterIds: ["release-agent"], approverIds: ["ada"], sameRing: false, purposes: ["release"] },
      { rule_id: "docs-open", secret_name: "docs.token", mode: "allow" }
    ]
  }
};

describe("exchange policy", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("DR-E14: open lists read as 'Any agent'; operators are read-only", async () => {
    fakeController({ role: "operator", handler: (call) => (call.path === "/api/v3/admin/policy" ? json(200, POLICY) : undefined) });
    const { container } = renderRoute("/policy");
    expect(await screen.findByText("stripe-review")).toBeTruthy();
    expect(screen.getByText("Only administrators can change the exchange policy.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Edit policy" })).toBeNull();
    const docs = container.querySelector('[data-rule="docs-open"]')!;
    expect(within(docs as HTMLElement).getAllByText("Any agent")).toHaveLength(2);
    expect(container.querySelector('[data-rule="stripe-review"]')?.textContent).toContain("Also set: sameRing, purposes");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("DR-E14: an edit round-trips every field, sends If-Match and reports the new version", async () => {
    const { calls } = fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/admin/policy/validate") return json(200, { valid: true, errors: [] });
        if (call.path === "/api/v3/admin/policy" && call.method === "PUT") return json(200, { version: 5, policy: call.body });
        if (call.path === "/api/v3/admin/policy") return json(200, POLICY);
        return undefined;
      }
    });
    const user = userEvent.setup();
    renderRoute("/policy");
    await user.click(await screen.findByRole("button", { name: "Edit policy" }));
    const reason = screen.getAllByLabelText(/Reason shown to the requester/)[0]!;
    await user.type(reason, "Release review");
    await user.click(screen.getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText("Policy saved as version 5")).toBeTruthy();
    const put = calls.find((call) => call.method === "PUT")!;
    expect(put.headers.get("if-match")).toBe('"4"');
    const body = put.body as typeof POLICY.policy;
    expect(body.exchange_policy[0]).toEqual({ ...POLICY.policy.exchange_policy[0], reason: "Release review" });
    expect(body.exchange_policy[1]).toEqual(POLICY.policy.exchange_policy[1]);
    expect(body.secret_registry).toEqual(POLICY.policy.secret_registry);
  });

  it("DR-E14: server validation issues land on the right field and nothing is saved", async () => {
    const { calls } = fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/admin/policy/validate") return json(200, { valid: false, errors: ["exchange_policy[0].approverIds: required for pending_approval", "exchange_policy[1].ruleId: duplicate"] });
        if (call.path === "/api/v3/admin/policy") return json(200, POLICY);
        return undefined;
      }
    });
    const user = userEvent.setup();
    const { container } = renderRoute("/policy");
    await user.click(await screen.findByRole("button", { name: "Edit policy" }));
    await user.clear(screen.getAllByLabelText("Rule ID")[0]!);
    await user.type(screen.getAllByLabelText("Rule ID")[0]!, "renamed");
    await user.click(screen.getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText("required for pending_approval")).toBeTruthy();
    expect(screen.getByText("duplicate")).toBeTruthy();
    expect(container.querySelectorAll(".rule-card.has-issues")).toHaveLength(2);
    expect(calls.some((call) => call.method === "PUT")).toBe(false);
  });

  it("DR-E14: a version conflict shows both sides and keeps the draft until the operator chooses", async () => {
    const latest = { version: 6, policy: { ...POLICY.policy, exchange_policy: [...POLICY.policy.exchange_policy, { ruleId: "new-rule", secretName: "docs.token", mode: "deny" }] } };
    let reads = 0;
    const { calls } = fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/admin/policy/validate") return json(200, { valid: true, errors: [] });
        if (call.path === "/api/v3/admin/policy" && call.method === "PUT") {
          return call.headers.get("if-match") === '"6"' ? json(200, { version: 7, policy: call.body }) : json(409, { error: "policy_version_conflict" });
        }
        if (call.path === "/api/v3/admin/policy") return json(200, reads++ === 0 ? POLICY : latest);
        return undefined;
      }
    });
    const user = userEvent.setup();
    renderRoute("/policy");
    await user.click(await screen.findByRole("button", { name: "Edit policy" }));
    await user.click(screen.getAllByRole("button", { name: /Remove rule 2/ })[0]!);
    await user.click(screen.getByRole("button", { name: "Save policy" }));
    const conflict = await screen.findByText("Someone saved version 6 while you were editing");
    const panel = conflict.closest(".notice")!;
    expect(panel.textContent).toContain("new-rule");
    expect(panel.textContent).toContain("docs-open");
    await user.click(within(panel as HTMLElement).getByRole("button", { name: "Keep my draft on version 6" }));
    expect(screen.getByText("Editing from version 6")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText("Policy saved as version 7")).toBeTruthy();
    expect(calls.filter((call) => call.method === "PUT").map((call) => call.headers.get("if-match"))).toEqual(['"4"', '"6"']);
  });

  it("DR-E14: discarding restores the stored policy", async () => {
    const { calls } = fakeController({ handler: (call) => (call.path === "/api/v3/admin/policy" ? json(200, POLICY) : undefined) });
    const user = userEvent.setup();
    renderRoute("/policy");
    await user.click(await screen.findByRole("button", { name: "Edit policy" }));
    await user.click(screen.getAllByRole("button", { name: /Remove rule 1/ })[0]!);
    expect(screen.queryByDisplayValue("stripe-review")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(await screen.findByText("stripe-review")).toBeTruthy();
    expect(calls.some((call) => call.method === "PUT")).toBe(false);
  });
});

describe("audit", () => {
  afterEach(() => vi.unstubAllGlobals());

  const page = (prefix: string, next: string | null) => ({
    items: Array.from({ length: 3 }, (_, index) => ({ id: `${prefix}${index}`, event: index === 0 ? "exchange_requested" : "policy_changed", actor_id: "release-agent", resource_id: index === 0 ? `ex_${prefix}${index}` : null, created_at: Date.now() - index * 1000, metadata: index === 0 ? { purpose: '<script>alert("x")</script> ship it', approval_reference: "apr_1" } : {} })),
    next_cursor: next
  });

  it("DR-E15: pages by cursor without losing or duplicating rows, and filters only the loaded page", async () => {
    const { calls } = fakeController({
      handler: (call) => (call.path === "/api/v3/admin/audit" ? json(200, call.query.get("cursor") === "c2" ? page("b", null) : page("a", "c2")) : undefined)
    });
    const user = userEvent.setup();
    const { container } = renderRoute("/audit");
    await screen.findByText("3 events");
    await user.click(screen.getByRole("button", { name: "Older" }));
    await waitFor(() => expect(container.querySelector('[data-audit="b0"]')).toBeTruthy());
    expect(container.querySelector('[data-audit="a0"]')).toBeNull();
    expect(calls.filter((call) => call.path === "/api/v3/admin/audit").map((call) => call.query.get("cursor"))).toEqual([null, "c2"]);
    await user.click(screen.getByRole("button", { name: "Newer" }));
    await waitFor(() => expect(container.querySelector('[data-audit="a0"]')).toBeTruthy());
    await user.selectOptions(screen.getByLabelText("Kind"), "exchange");
    expect(screen.getByText("1 of 3 on this page")).toBeTruthy();
  });

  it("DR-E15: metadata renders as inert text and exchange rows deep-link to the timeline", async () => {
    fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/admin/audit") return json(200, page("a", null));
        if (call.path === "/api/v3/admin/audit/exchange/ex_a0") return json(200, { items: page("a", null).items.slice(0, 1), next_cursor: null });
        return undefined;
      }
    });
    const user = userEvent.setup();
    const { container, router } = renderRoute("/audit");
    await user.click(await screen.findByRole("button", { name: "Details" }));
    expect(screen.getByText('<script>alert("x")</script> ship it')).toBeTruthy();
    expect(container.querySelector(".metadata script")).toBeNull();
    await user.click(screen.getByRole("link", { name: /ex_a0/ }));
    expect(router.state.location.pathname).toBe("/audit/exchange/ex_a0");
    expect(await screen.findByRole("heading", { name: "Exchange timeline" })).toBeTruthy();
    expect((await screen.findByRole("link", { name: /Open approval/ })).getAttribute("href")).toBe("/approvals/exchange/apr_1");
  });

  it("DR-E15: an unknown exchange ID says so instead of showing an empty timeline", async () => {
    fakeController({ role: "viewer", handler: (call) => (call.path.startsWith("/api/v3/admin/audit/exchange/") ? json(404, { error: "exchange_not_found" }) : undefined) });
    renderRoute("/audit/exchange/ex_unknown");
    expect(await screen.findByText("No audit for this exchange")).toBeTruthy();
  });

  it("DR-E16: a failed audit read is an error, not an empty log", async () => {
    fakeController({ handler: (call) => (call.path === "/api/v3/admin/audit" ? json(429, { error: "rate_limited" }, { "retry-after": "7" }) : undefined) });
    renderRoute("/audit");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("7");
    expect(screen.queryByText("No audit events yet")).toBeNull();
  });
});
