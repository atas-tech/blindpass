import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { App } from "../App.js";
import { AuthProvider } from "../auth/AuthContext.js";
import { apiRequest, configureApiClient } from "../api/client.js";

function renderApp(initialEntries = ["/"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe("dashboard milestone 2", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("redirects unauthenticated users to login", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401 }))
    );
    renderApp(["/"]);

    expect(await screen.findByLabelText("Email address")).toBeInTheDocument();
  });

  it("uses cookie-backed refresh without persisting tokens in browser storage", async () => {
    const fetchMock = vi.fn<
      (input: string | URL | Request, init?: RequestInit) => Promise<Response>
    >().mockImplementation(async (input) => {
      const url = String(input);

      if (url.endsWith("/api/v2/auth/refresh")) {
        return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401 });
      }

      if (url.endsWith("/api/v2/auth/login")) {
        return new Response(
          JSON.stringify({
            access_token: "header.eyJmcGMiOmZhbHNlfQ.signature",
            user: {
              id: "user-1",
              email: "owner@example.com",
              role: "workspace_admin",
              status: "active",
              email_verified: true,
              force_password_change: false,
              workspace_id: "workspace-1",
              created_at: "2026-03-13T00:00:00.000Z",
              updated_at: "2026-03-13T00:00:00.000Z"
            },
            workspace: {
              id: "workspace-1",
              slug: "acme",
              display_name: "Acme",
              tier: "free",
              status: "active",
              owner_user_id: "user-1",
              created_at: "2026-03-13T00:00:00.000Z",
              updated_at: "2026-03-13T00:00:00.000Z"
            }
          }),
          { status: 200 }
        );
      }

      if (url.endsWith("/api/v2/auth/logout")) {
        return new Response(null, { status: 204 });
      }

      return new Response(null, { status: 404 });
    });

    vi.stubGlobal("fetch", fetchMock);
    renderApp(["/login"]);

    await screen.findByLabelText("Email address");
    await userEvent.type(screen.getByLabelText("Email address"), "owner@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "Password123!");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await screen.findByText("Workspace command overview");
    expect(window.sessionStorage.getItem("sps_refresh_token")).toBeNull();
    expect(window.localStorage.getItem("sps_refresh_token")).toBeNull();

    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    await screen.findByLabelText("Email address");
    expect(window.sessionStorage.getItem("sps_refresh_token")).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringMatching(/\/api\/v2\/auth\/login$/),
      expect.objectContaining({ credentials: "include" })
    );
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringMatching(/\/api\/v2\/auth\/logout$/),
      expect.objectContaining({ credentials: "include" })
    );
  });

  it("redirects force-password-change users to change-password", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            access_token: "header.eyJmcGMiOnRydWV9.signature",
            user: {
              id: "user-2",
              email: "operator@example.com",
              role: "workspace_operator",
              status: "active",
              email_verified: true,
              force_password_change: true,
              workspace_id: "workspace-1",
              created_at: "2026-03-13T00:00:00.000Z",
              updated_at: "2026-03-13T00:00:00.000Z"
            },
            workspace: {
              id: "workspace-1",
              slug: "acme",
              display_name: "Acme",
              tier: "free",
              status: "active",
              owner_user_id: "user-1",
              created_at: "2026-03-13T00:00:00.000Z",
              updated_at: "2026-03-13T00:00:00.000Z"
            }
          }),
          { status: 200 }
        )
      )
    );

    renderApp(["/agents"]);
    expect(await screen.findByText("Change password")).toBeInTheDocument();
  });

  it("redirects non-admins away from the home route", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            access_token: "header.eyJmcGMiOmZhbHNlfQ.signature",
            user: {
              id: "user-2",
              email: "operator@example.com",
              role: "workspace_operator",
              status: "active",
              email_verified: true,
              force_password_change: false,
              workspace_id: "workspace-1",
              created_at: "2026-03-13T00:00:00.000Z",
              updated_at: "2026-03-13T00:00:00.000Z"
            },
            workspace: {
              id: "workspace-1",
              slug: "acme",
              display_name: "Acme",
              tier: "free",
              status: "active",
              owner_user_id: "user-1",
              created_at: "2026-03-13T00:00:00.000Z",
              updated_at: "2026-03-13T00:00:00.000Z"
            }
          }),
          { status: 200 }
        )
      )
    );

    renderApp(["/"]);
    expect(await screen.findByText("Agent enrollment and rotation")).toBeInTheDocument();
    expect(screen.queryByText("Members")).not.toBeInTheDocument();
  });

  it("registers a workspace and redirects into the shell", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = String(input);

      if (url.endsWith("/api/v2/auth/refresh")) {
        return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401 });
      }

      return new Response(
        JSON.stringify({
          access_token: "header.eyJmcGMiOmZhbHNlfQ.signature",
          user: {
            id: "user-3",
            email: "owner@example.com",
            role: "workspace_admin",
            status: "active",
            email_verified: false,
            force_password_change: false,
            workspace_id: "workspace-3",
            created_at: "2026-03-13T00:00:00.000Z",
            updated_at: "2026-03-13T00:00:00.000Z"
          },
          workspace: {
            id: "workspace-3",
            slug: "agent-lab",
            display_name: "Agent Lab",
            tier: "free",
            status: "active",
            owner_user_id: "user-3",
            created_at: "2026-03-13T00:00:00.000Z",
            updated_at: "2026-03-13T00:00:00.000Z"
          }
        }),
        { status: 201 }
      );
    }));

    renderApp(["/register"]);

    await screen.findByLabelText("Display name");
    await userEvent.type(screen.getByLabelText("Display name"), "Agent Lab");
    await userEvent.type(screen.getByLabelText("Email address"), "owner@example.com");
    await userEvent.type(screen.getByLabelText("Workspace slug"), "agent-lab");
    await userEvent.type(screen.getByLabelText("Password"), "Password123!");
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: /create workspace/i }));

    expect(await screen.findByText("Workspace command overview")).toBeInTheDocument();
  });

  it("api client retries once on 401 after refreshing the session", async () => {
    const refreshAuth = vi.fn().mockResolvedValue("next-token");
    const handleAuthFailure = vi.fn();
    configureApiClient({
      getAccessToken: () => "old-token",
      refreshAuth,
      handleAuthFailure
    });

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: "expired" }), { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await apiRequest<{ ok: boolean }>("/api/v2/workspace");

    expect(result.ok).toBe(true);
    expect(refreshAuth).toHaveBeenCalledTimes(1);
    expect(handleAuthFailure).not.toHaveBeenCalled();
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "http://127.0.0.1:3100/api/v2/workspace",
      expect.objectContaining({ credentials: "include" })
    );
  });
});
