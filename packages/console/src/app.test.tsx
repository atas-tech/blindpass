import { render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { routes } from "./app.js";
import { SessionProvider } from "./session/session.js";
import { ToastProvider } from "./ui/toast.js";

interface FakeController {
  setupRequired?: boolean;
  session?: { role: "admin" | "operator" | "viewer"; mustChange?: boolean } | null;
  fleet?: boolean;
}

function installController({ setupRequired = false, session = null, fleet = true }: FakeController) {
  const fetchMock = vi.fn(async (input: URL | string) => {
    const url = new URL(String(input), "http://console.test");
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.pathname === "/api/v3/capabilities") {
      return json(200, { api: fleet ? ["compat.v2", "admin.v3", "fleet.v3"] : ["compat.v2", "admin.v3"], version: "0.1.0", schema_version: 13, setup_required: setupRequired, features: { browser_status: true, fleet_authorization: fleet } });
    }
    if (url.pathname === "/api/v3/admin/session") {
      if (!session) return json(401, { error: "session_required" });
      return json(200, {
        operator: { id: "op_1", username: "ada", display_name: "Ada", role: session.role, disabled_at: null },
        csrf_token: "csrf",
        expires_at: Date.now() + 3_600_000,
        must_change_password: Boolean(session.mustChange)
      });
    }
    if (url.pathname.endsWith("/count")) return json(200, { count: 0 });
    return json(200, { items: [], next_cursor: null, count: 0 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(
    <ToastProvider>
      <SessionProvider>
        <RouterProvider router={router} />
      </SessionProvider>
    </ToastProvider>
  );
  return router;
}

describe("route gates", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("DR-E24: with no administrator every protected route goes to /setup", async () => {
    installController({ setupRequired: true });
    const router = renderAt("/approvals");
    expect(await screen.findByRole("heading", { name: /set up/i })).toBeTruthy();
    expect(router.state.location.pathname).toBe("/setup");
  });

  it("DR-E24: once an administrator exists /setup goes to /login", async () => {
    installController({ setupRequired: false });
    const router = renderAt("/setup");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
    expect(router.state.location.pathname).toBe("/login");
  });

  it("DR-E04: a signed-out deep link returns to its target after sign-in", async () => {
    installController({});
    const router = renderAt("/audit?cursor=abc");
    await screen.findByRole("heading", { name: "Sign in" });
    expect(router.state.location.pathname).toBe("/login");
    expect(new URLSearchParams(router.state.location.search).get("next")).toBe("/audit?cursor=abc");
  });

  it("DR-E04: a temporary password confines the session to /change-password", async () => {
    installController({ session: { role: "admin", mustChange: true } });
    const router = renderAt("/settings");
    expect(await screen.findByRole("heading", { name: "Change password" })).toBeTruthy();
    expect(router.state.location.pathname).toBe("/change-password");
    expect(screen.getAllByText(/temporary password/i).length).toBeGreaterThan(0);
  });

  it("DR-E01: removed hosted routes show the unavailable page with no controls", async () => {
    installController({ session: { role: "admin" } });
    renderAt("/billing");
    const page = await screen.findByTestId("unavailable-feature");
    expect(page.textContent).toContain("Not available in this product");
    expect(page.querySelectorAll("input, form")).toHaveLength(0);
  });

  it("an unknown route inside the shell is a 404, not a blank page", async () => {
    installController({ session: { role: "viewer" } });
    renderAt("/no-such-page");
    expect(await screen.findByRole("heading", { name: "This page doesn't exist" })).toBeTruthy();
  });

  it("DR-E02: navigation reflects the role; viewers get no approvals or administration entries", async () => {
    installController({ session: { role: "viewer" } });
    renderAt("/settings");
    await screen.findByRole("heading", { name: "Settings" });
    const nav = screen.getAllByRole("navigation", { name: "Main navigation" })[0]!;
    const labels = [...nav.querySelectorAll("a")].map((link) => link.textContent);
    expect(labels).toContain("Nodes");
    expect(labels).not.toContain("Approvals");
    expect(labels).not.toContain("Agents");
    expect(labels).not.toContain("Grants");
    expect(labels).not.toContain("Operators");
  });

  it("fleet navigation is absent when the controller has no fleet group", async () => {
    installController({ session: { role: "admin" }, fleet: false });
    renderAt("/settings");
    await screen.findByRole("heading", { name: "Settings" });
    const nav = screen.getAllByRole("navigation", { name: "Main navigation" })[0]!;
    const labels = [...nav.querySelectorAll("a")].map((link) => link.textContent);
    expect(labels).not.toContain("Nodes");
    expect(labels).toContain("Agents");
  });

  it("stores no credential in web storage", async () => {
    installController({ session: { role: "admin" } });
    renderAt("/settings");
    await screen.findByRole("heading", { name: "Settings" });
    const storage = window.localStorage;
    const keys = [...Array(storage.length).keys()].map((index) => storage.key(index));
    expect(keys.every((key) => key === "blindpass_locale")).toBe(true);
    expect(window.sessionStorage.length).toBe(0);
  });
});
