import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { routes } from "../../app.js";
import { SessionProvider } from "../../session/session.js";
import { axeViolations } from "../../test/axe.js";
import { ToastProvider } from "../../ui/toast.js";
import { exchangeApproval, HOSTILE, operationApproval } from "../../test/fixtures.js";

type Json = Record<string, unknown>;

interface Scenario {
  role?: "admin" | "operator" | "viewer";
  fleet?: boolean;
  approvals?: Json[];
  /** Override a decision response; receives the request and the call number. */
  decide?: (request: { path: string; body: Json; headers: Headers }, call: number) => Response | Promise<Response>;
  /** Override detail reads (after the decision, for reconciliation). */
  detail?: (id: string, call: number) => Response | null;
  count?: () => Response;
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function install(scenario: Scenario) {
  const role = scenario.role ?? "operator";
  const fleet = scenario.fleet ?? true;
  let approvals = scenario.approvals ?? [exchangeApproval()];
  let decideCalls = 0;
  const detailCalls = new Map<string, number>();
  const decisions: Array<{ path: string; body: Json; headers: Headers }> = [];
  const fetchMock = vi.fn(async (input: URL | string, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://console.test");
    const method = init.method ?? "GET";
    if (url.pathname === "/api/v3/capabilities") {
      return json(200, { api: fleet ? ["admin.v3", "fleet.v3"] : ["admin.v3"], version: "0.1.0", schema_version: 13, setup_required: false, features: {} });
    }
    if (url.pathname === "/api/v3/admin/session") {
      return json(200, { operator: { id: "op_ada", username: "ada", display_name: "Ada", role, disabled_at: null }, csrf_token: "csrf", expires_at: Date.now() + 3_600_000, must_change_password: false });
    }
    if (url.pathname.endsWith("/count")) {
      if (scenario.count) return scenario.count();
      return json(200, { count: approvals.filter((item) => item.status === "pending").length });
    }
    const listPath = fleet ? "/api/v3/approvals" : "/api/v3/admin/approvals";
    if (url.pathname === listPath && method === "GET") {
      const status = url.searchParams.get("status") ?? "pending";
      const items = approvals.filter((item) => item.status === status);
      return json(200, fleet ? { items, next_cursor: null, count: approvals.filter((item) => item.status === "pending").length } : { items, next_cursor: null });
    }
    const decideMatch = url.pathname.match(/\/approvals\/([^/]+)\/(approve|reject)$/);
    if (decideMatch && method === "POST") {
      const request = { path: url.pathname, body: JSON.parse(String(init.body)) as Json, headers: new Headers(init.headers) };
      decisions.push(request);
      decideCalls += 1;
      if (scenario.decide) return scenario.decide(request, decideCalls);
      const id = decodeURIComponent(decideMatch[1]!);
      approvals = approvals.map((item) => ((item.reference ?? item.id) === id ? { ...item, status: decideMatch[2] === "approve" ? "approved" : "rejected" } : item));
      return json(200, { status: "approved" });
    }
    const detailMatch = url.pathname.match(/\/approvals\/([^/]+)$/);
    if (detailMatch && method === "GET") {
      const id = decodeURIComponent(detailMatch[1]!);
      const call = (detailCalls.get(id) ?? 0) + 1;
      detailCalls.set(id, call);
      const override = scenario.detail?.(id, call);
      if (override) return override;
      const found = approvals.find((item) => (item.reference ?? item.id) === id);
      return found ? json(200, found) : json(404, { error: "approval_not_found" });
    }
    if (url.pathname === "/api/v3/admin/audit") return json(200, { items: [], next_cursor: null });
    return json(200, { items: [], next_cursor: null });
  });
  vi.stubGlobal("fetch", fetchMock);
  return {
    fetchMock,
    decisions,
    setApprovals: (next: Json[]) => {
      approvals = next;
    }
  };
}

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  const view = render(
    <ToastProvider>
      <SessionProvider>
        <RouterProvider router={router} />
      </SessionProvider>
    </ToastProvider>
  );
  return { router, ...view };
}

async function openConfirmAndDecide(verb: "Approve" | "Reject") {
  const user = userEvent.setup();
  const action = await screen.findByRole("button", { name: verb });
  await waitFor(() => expect((action as HTMLButtonElement).disabled).toBe(false));
  await user.click(action);
  const dialog = await screen.findByRole("dialog", { name: new RegExp(`^${verb}`) });
  // Focus starts on Cancel: no keystroke approves by default.
  expect(document.activeElement?.textContent).toBe("Cancel");
  const text = dialog.textContent ?? "";
  await user.click(within(dialog).getByRole("button", { name: verb }));
  return { user, text };
}

describe("approvals", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("DR-E08: the queue lists the controller's pending approvals and opens the matching detail", async () => {
    install({ approvals: [exchangeApproval(), operationApproval()] });
    const { router } = renderAt("/approvals");
    const queue = await screen.findByRole("list", { name: "Approval queue" });
    const links = within(queue).getAllByRole("link");
    expect(links).toHaveLength(2);
    expect(links[1]!.textContent).toContain("2 operations");
    await userEvent.click(links[0]!);
    expect(router.state.location.pathname).toBe("/approvals/exchange/apr_ref_1");
    expect(await screen.findByRole("heading", { name: "e2e-requester asks for e2e.approval_api_key" })).toBeTruthy();
  });

  it("DR-I05 / safe text: requester purpose is inert text in an unverified block, apart from verified facts", async () => {
    install({});
    const { container } = renderAt("/approvals/exchange/apr_ref_1");
    await screen.findByRole("heading", { name: /asks for/ });
    const untrusted = container.querySelector(".untrusted")!;
    expect(untrusted.textContent).toContain(HOSTILE);
    expect(untrusted.textContent).toContain("Not verified");
    expect(container.querySelector(".untrusted img, .untrusted b, .untrusted strong")).toBeNull();
    const verified = container.querySelector(".verified")!;
    expect(verified.textContent).toContain("e2e-requester");
    expect(verified.textContent).not.toContain("Ignore the rules");
    // The queue shows verified fields only.
    expect(container.querySelector(".queue")?.textContent).not.toContain("Ignore the rules");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("DR-E09: approve re-reads, sends expected state with an Idempotency-Key, and does not claim delivery", async () => {
    const { decisions } = install({});
    renderAt("/approvals/exchange/apr_ref_1");
    await openConfirmAndDecide("Approve");
    expect(await screen.findByText("Approved", { selector: ".notice-title" })).toBeTruthy();
    expect(screen.getByText(/Nothing has been delivered yet/)).toBeTruthy();
    expect(decisions).toHaveLength(1);
    const [decision] = decisions;
    expect(decision!.path).toBe("/api/v3/approvals/apr_ref_1/approve");
    expect(decision!.body).toEqual({ expected_status: "pending", expected_version: 1 });
    expect(decision!.headers.get("if-match")).toBe('"1"');
    expect(decision!.headers.get("idempotency-key")!.length).toBeGreaterThanOrEqual(16);
    expect(decision!.headers.get("x-csrf-token")).toBe("csrf");
  });

  it("exchange-only controllers use the exchange decision route", async () => {
    const { decisions } = install({ fleet: false });
    renderAt("/approvals/exchange/apr_ref_1");
    await openConfirmAndDecide("Reject");
    await screen.findByText("Rejected", { selector: ".notice-title" });
    expect(decisions[0]!.path).toBe("/api/v3/admin/approvals/apr_ref_1/reject");
    expect(decisions[0]!.body).toEqual({ expected_status: "pending" });
  });

  it("DR-E09: operation decisions send the exact group, version and If-Match", async () => {
    const { decisions } = install({ approvals: [operationApproval()] });
    renderAt("/approvals/operation/oa_1");
    expect(await screen.findByRole("heading", { name: "deploy.token for deploy.service" })).toBeTruthy();
    const { text } = await openConfirmAndDecide("Approve");
    expect(text).toContain("Broker on node_build01");
    expect(text).toContain("deploy.token for deploy.service as deploy (File)");
    await screen.findByText("Approved", { selector: ".notice-title" });
    expect(decisions[0]!.body).toEqual({ expected_status: "pending", expected_version: 2, operation_ids: ["op_1", "op_2"] });
    expect(decisions[0]!.headers.get("if-match")).toBe('"2"');
  });

  it("DR-E11: an approval that changed while confirming is not sent", async () => {
    const { decisions } = install({
      approvals: [operationApproval()],
      detail: (_id, call) => (call >= 2 ? json(200, operationApproval({ version: 3 })) : null)
    });
    renderAt("/approvals/operation/oa_1");
    await openConfirmAndDecide("Approve");
    expect(await screen.findByText("This approval changed")).toBeTruthy();
    expect(screen.getByText(/nothing was sent/)).toBeTruthy();
    expect(decisions).toHaveLength(0);
  });

  it("DR-E11: a competing decision (409) shows the authoritative state, not success", async () => {
    install({
      decide: () => json(409, { error: "approval_not_pending" }),
      detail: (_id, call) => (call >= 3 ? json(200, exchangeApproval({ status: "rejected" })) : null)
    });
    const { container } = renderAt("/approvals/exchange/apr_ref_1");
    await openConfirmAndDecide("Approve");
    expect(await screen.findByText("This approval changed")).toBeTruthy();
    expect(screen.queryByText("Approved", { selector: ".notice-title" })).toBeNull();
    await waitFor(() => expect(container.querySelector("[data-approval-status]")?.getAttribute("data-approval-status")).toBe("rejected"));
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("P04-I02 lost response: unknown outcome requires a status check and a resend reuses the same key", async () => {
    const { decisions } = install({
      decide: (_request, call) => (call === 1 ? json(504, { error: "gateway_timeout" }) : json(200, { status: "approved" }))
    });
    renderAt("/approvals/exchange/apr_ref_1");
    const { user } = await openConfirmAndDecide("Approve");
    expect(await screen.findByText("We couldn't confirm the decision")).toBeTruthy();
    // No decide button is offered until the operator reconciles.
    expect((screen.getByRole("button", { name: "Approve" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "Check status" }));
    expect(await screen.findByText("Still pending")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Send the same decision again" }));
    await screen.findByText("Approved", { selector: ".notice-title" });
    expect(decisions).toHaveLength(2);
    expect(decisions[1]!.headers.get("idempotency-key")).toBe(decisions[0]!.headers.get("idempotency-key"));
  });

  it("P04-I02 lost response: when the controller already recorded it, the console says so and sends nothing", async () => {
    const { decisions } = install({
      decide: () => json(502, { error: "bad_gateway" }),
      detail: (_id, call) => (call >= 3 ? json(200, exchangeApproval({ status: "approved" })) : null)
    });
    renderAt("/approvals/exchange/apr_ref_1");
    const { user } = await openConfirmAndDecide("Approve");
    await user.click(await screen.findByRole("button", { name: "Check status" }));
    expect(await screen.findByText("The controller has a decision")).toBeTruthy();
    expect(decisions).toHaveLength(1);
  });

  it("DR-E09: a scope denial explains who may decide", async () => {
    install({ decide: () => json(403, { error: "approval_scope_denied" }) });
    renderAt("/approvals/exchange/apr_ref_1");
    await openConfirmAndDecide("Approve");
    expect(await screen.findByText("You aren't an approver for this request")).toBeTruthy();
  });

  it("operation approvals that do not name this operator, or that it requested, offer no decision", async () => {
    install({ approvals: [operationApproval({ approver_ids: ["someone-else"] }), operationApproval({ id: "oa_2", approver_ids: ["ada"], requester_summary: { operator_id: "op_ada", requester: "ada", purpose: "mine" } })] });
    renderAt("/approvals/operation/oa_1");
    expect(await screen.findByText(/aren't a named approver/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Approve" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("an approved operation reports the grant boundary and links to the operation", async () => {
    install({ approvals: [operationApproval({ status: "approved", decided_by: "op_ada", decided_at: Date.now() })] });
    renderAt("/approvals/operation/oa_1");
    expect(await screen.findByRole("link", { name: "View operation" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("DR-E10: a viewer cannot open approvals", async () => {
    install({ role: "viewer" });
    renderAt("/approvals/exchange/apr_ref_1");
    expect(await screen.findByRole("heading", { name: "Your role can't open this page" })).toBeTruthy();
  });

  it("DR-E16: a failed queue read is an error with retry, never an empty queue", async () => {
    const scenario = install({});
    const original = scenario.fetchMock.getMockImplementation()!;
    let failed = false;
    scenario.fetchMock.mockImplementation(async (input: URL | string, init?: RequestInit) => {
      const url = new URL(String(input), "http://console.test");
      if (url.pathname === "/api/v3/approvals" && !failed) {
        failed = true;
        return json(500, { error: "internal" });
      }
      return original(input, init);
    });
    renderAt("/approvals");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toContain("No pending approvals");
    await userEvent.click(within(alert).getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("list", { name: "Approval queue" })).toBeTruthy();
  });
});
