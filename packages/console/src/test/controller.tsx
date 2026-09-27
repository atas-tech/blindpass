import { render } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { vi } from "vitest";
import { routes } from "../app.js";
import { SessionProvider } from "../session/session.js";
import { ToastProvider } from "../ui/toast.js";

export type Role = "admin" | "operator" | "viewer";

export const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

export interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
  headers: Headers;
}

type Handler = (call: Call) => Response | Promise<Response> | undefined;

/**
 * A fake controller for page tests: capabilities and session are answered
 * for the given role, and each route handler may answer or pass (undefined).
 */
export function fakeController({ role = "admin", fleet = true, handler }: { role?: Role; fleet?: boolean; handler: Handler }) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: URL | string, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://console.test");
    const call: Call = { method: init.method ?? "GET", path: url.pathname, query: url.searchParams, body: init.body ? JSON.parse(String(init.body)) : undefined, headers: new Headers(init.headers) };
    calls.push(call);
    if (call.path === "/api/v3/capabilities") {
      return json(200, { api: fleet ? ["admin.v3", "fleet.v3"] : ["admin.v3"], version: "0.1.0", schema_version: 13, setup_required: false, features: {} });
    }
    if (call.path === "/api/v3/admin/session") {
      return json(200, { operator: { id: "op_ada", username: "ada", display_name: "Ada", role, disabled_at: null }, csrf_token: "csrf", expires_at: Date.now() + 3_600_000, must_change_password: false });
    }
    const answer = await handler(call);
    if (answer) return answer;
    if (call.path.endsWith("/count")) return json(200, { count: 0 });
    return json(200, { items: [], next_cursor: null, count: 0 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

export function renderRoute(path: string) {
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
