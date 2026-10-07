import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { routes } from "../../app.js";
import { SessionProvider } from "../../session/session.js";
import { ToastProvider } from "../../ui/toast.js";

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

function installController(login: () => Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: URL | string) => {
      const url = new URL(String(input), "http://console.test");
      if (url.pathname === "/api/v3/capabilities") {
        return json(200, { api: ["admin.v3"], version: "0.1.0", schema_version: 19, setup_required: false, features: { browser_status: true, fleet_authorization: false } });
      }
      if (url.pathname === "/api/v3/admin/session/login") return login();
      if (url.pathname === "/api/v3/admin/session") return json(401, { error: "session_required" });
      return json(200, { items: [], next_cursor: null, count: 0 });
    })
  );
}

async function submitLogin() {
  const router = createMemoryRouter(routes, { initialEntries: ["/login"] });
  render(
    <ToastProvider>
      <SessionProvider>
        <RouterProvider router={router} />
      </SessionProvider>
    </ToastProvider>
  );
  const user = userEvent.setup();
  await screen.findByRole("heading", { name: "Sign in" });
  await user.type(screen.getByLabelText(/username/i), "ada");
  await user.type(screen.getByLabelText(/password/i), "a-long-dummy-password");
  await user.click(screen.getByRole("button", { name: /sign in/i }));
}

describe("sign-in refusals (P07-D4)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("a locked account says so, with how long, and points at the administrator reset", async () => {
    installController(() => json(423, { error: "locked", message: "locked", retry_after: 840 }, { "retry-after": "840" }));
    await submitLogin();
    const notice = await screen.findByText(/locked/i, { selector: "[role=alert], [role=status], .notice *, p, div" });
    expect(notice.textContent).toMatch(/14 min/);
    expect(notice.textContent).not.toMatch(/incorrect/i);
    expect(notice.textContent).not.toMatch(/didn.t complete/i);
  });

  it("an exhausted address still gets the wait-and-retry message", async () => {
    installController(() => json(429, { error: "login_rate_limited" }, { "retry-after": "60" }));
    await submitLogin();
    await waitFor(() => expect(screen.getByText(/too many attempts/i)).toBeTruthy());
  });
});
