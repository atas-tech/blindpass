import { render, screen, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { routes } from "../app.js";
import { SessionProvider } from "../session/session.js";
import { axeViolations } from "../test/axe.js";
import { ToastProvider } from "../ui/toast.js";
import { exchangeApproval } from "../test/fixtures.js";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function install({ role = "admin", fleet = true, fail = [] as string[] }: { role?: "admin" | "operator" | "viewer"; fleet?: boolean; fail?: string[] }) {
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: URL | string) => {
      const url = new URL(String(input), "http://console.test");
      calls.push(url.pathname);
      if (fail.includes(url.pathname)) return json(500, { error: "internal" });
      switch (url.pathname) {
        case "/api/v3/capabilities":
          return json(200, { api: fleet ? ["admin.v3", "fleet.v3"] : ["admin.v3"], version: "0.1.0", schema_version: 13, setup_required: false, features: {} });
        case "/api/v3/admin/session":
          return json(200, { operator: { id: "op_ada", username: "ada", display_name: "Ada", role, disabled_at: null }, csrf_token: "csrf", expires_at: Date.now() + 3_600_000, must_change_password: false });
        case "/api/v3/approvals/count":
          return json(200, { count: 7 });
        case "/api/v3/admin/approvals/count":
          return json(200, { count: 2 });
        case "/api/v3/approvals":
          return json(200, { items: [exchangeApproval(), exchangeApproval({ reference: "apr_ref_2" })], next_cursor: null, count: 7 });
        case "/api/v3/nodes":
          return json(200, {
            items: ["online", "online", "stale", "revoked"].map((status, index) => ({ id: `node_${index}`, name: `node-${index}`, status })),
            next_cursor: null
          });
        case "/api/v3/admin/agents":
          return json(200, {
            items: [
              { id: "a1", agent_id: "one", workspace_id: "w", display_name: "One", status: "active", created_at: "2026-09-01T00:00:00Z", revoked_at: null },
              { id: "a2", agent_id: "two", workspace_id: "w", display_name: "Two", status: "revoked", created_at: "2026-09-01T00:00:00Z", revoked_at: "2026-09-02T00:00:00Z" }
            ],
            next_cursor: null
          });
        case "/api/v3/admin/audit":
          return json(200, {
            items: [
              { id: "e1", event: "exchange_approved", actor_id: "op_ada", resource_id: "apr_ref_9", created_at: Date.now() - 60_000, metadata: {} },
              { id: "e2", event: "fleet.node_revoked", actor_id: "op_rina", resource_id: "node_3", created_at: Date.now() - 120_000, metadata: {} },
              { id: "e3", event: "future_event_kind", actor_id: null, resource_id: null, created_at: Date.now() - 180_000, metadata: {} }
            ],
            next_cursor: null
          });
        default:
          return json(404, { error: "not_found" });
      }
    })
  );
  return calls;
}

function renderOverview() {
  const router = createMemoryRouter(routes, { initialEntries: ["/"] });
  return render(
    <ToastProvider>
      <SessionProvider>
        <RouterProvider router={router} />
      </SessionProvider>
    </ToastProvider>
  );
}

describe("overview", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("DR-E08: the pending total is the unified count, never a sum of the two sources", async () => {
    const calls = install({});
    renderOverview();
    const stat = await screen.findByTestId("stat-pending");
    expect(await within(stat).findByText("7")).toBeTruthy();
    expect(calls).not.toContain("/api/v3/admin/approvals/count");
    expect(await screen.findByText("5 more waiting")).toBeTruthy();
  });

  it("nodes show only controller-computed statuses; agents are 'active', not online", async () => {
    install({});
    const { container } = renderOverview();
    const nodes = await screen.findByTestId("stat-nodes");
    expect(await within(nodes).findByText("4")).toBeTruthy();
    expect(nodes.textContent).toMatch(/2\s*online/);
    expect(nodes.textContent).toMatch(/1\s*stale/);
    expect(nodes.textContent).toMatch(/0\s*offline/);
    const agents = await screen.findByTestId("stat-agents");
    expect(await within(agents).findByText("of 2 enrolled")).toBeTruthy();
    expect(agents.textContent).toContain("not that the agent is online");
    // Unknown audit codes stay visible verbatim.
    expect(await screen.findByText("future_event_kind")).toBeTruthy();
    expect(screen.getByText("Exchange approved")).toBeTruthy();
    expect(screen.getByText("Node revoked")).toBeTruthy();
    expect(screen.getByText("by you").getAttribute("title")).toBe("op_ada");
    expect(screen.getByText("by op_rina")).toBeTruthy();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("DR-E16: each source fails on its own and a failure never reads as zero", async () => {
    install({ fail: ["/api/v3/approvals/count", "/api/v3/nodes", "/api/v3/admin/audit"] });
    renderOverview();
    const pending = await screen.findByTestId("stat-pending");
    expect(await within(pending).findByText("Unavailable")).toBeTruthy();
    expect(within(pending).queryByText("0")).toBeNull();
    const nodes = screen.getByTestId("stat-nodes");
    expect(await within(nodes).findByText("Unavailable")).toBeTruthy();
    // The agents card still loads.
    expect(await within(screen.getByTestId("stat-agents")).findByText("of 2 enrolled")).toBeTruthy();
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((alert) => alert.textContent?.includes("No audit events"))).toBe(false);
  });

  it("viewers see fleet and audit state, with no approval or agent figures", async () => {
    const calls = install({ role: "viewer" });
    renderOverview();
    await screen.findByTestId("stat-nodes");
    expect(screen.queryByTestId("stat-pending")).toBeNull();
    expect(screen.queryByTestId("stat-agents")).toBeNull();
    expect(screen.queryByRole("link", { name: "Review approvals" })).toBeNull();
    expect(calls.some((path) => path.includes("approvals"))).toBe(false);
    expect(calls).not.toContain("/api/v3/admin/agents");
  });

  it("exchange-only controllers read the exchange count and show no fleet card", async () => {
    install({ fleet: false });
    renderOverview();
    const stat = await screen.findByTestId("stat-pending");
    expect(await within(stat).findByText("2")).toBeTruthy();
    expect(screen.queryByTestId("stat-nodes")).toBeNull();
  });
});
