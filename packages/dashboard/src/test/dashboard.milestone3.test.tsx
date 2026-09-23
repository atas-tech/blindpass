import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App.js";
import { AuthProvider } from "../auth/AuthContext.js";
import { ApiKeyReveal } from "../components/ApiKeyReveal.js";

function renderApp(initialEntries = ["/"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

function createAdminSession() {
  return {
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
      owner_email_verified: true,
      created_at: "2026-03-13T00:00:00.000Z",
      updated_at: "2026-03-13T00:00:00.000Z"
    }
  };
}

describe("dashboard milestone 3", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("copies and dismisses bootstrap keys only after acknowledgement", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText }
    });

    render(
      <ApiKeyReveal
        apiKey="ak_test_secret"
        description="Store it now."
        onClose={vi.fn()}
        open
        title="Bootstrap key"
      />
    );

    await userEvent.click(screen.getByRole("button", { name: /copy key/i }));
    expect(writeText).toHaveBeenCalledWith("ak_test_secret");
    expect(screen.getByRole("button", { name: /i saved this key/i })).toBeDisabled();

    await userEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByRole("button", { name: /i saved this key/i })).toBeEnabled();
  });

  it("appends paginated agent rows without duplication", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);

      if (url.endsWith("/api/v2/auth/refresh")) {
        return new Response(JSON.stringify(createAdminSession()), { status: 200 });
      }

      if (url.includes("/api/v2/agents?limit=10&status=active")) {
        return new Response(JSON.stringify({ agents: [], next_cursor: null }), { status: 200 });
      }

      if (url.includes("/api/v2/agents?limit=10")) {
        if (url.includes("cursor=cursor-2")) {
          return new Response(
            JSON.stringify({
              agents: [
                {
                  id: "agent-1",
                  agent_id: "agent-a",
                  display_name: "Agent A",
                  status: "active",
                  created_at: "2026-03-11T00:00:00.000Z",
                  revoked_at: null
                }
              ],
              next_cursor: null
            }),
            { status: 200 }
          );
        }

        return new Response(
          JSON.stringify({
            agents: [
              {
                id: "agent-3",
                agent_id: "agent-c",
                display_name: "Agent C",
                status: "active",
                created_at: "2026-03-13T00:00:00.000Z",
                revoked_at: null
              },
              {
                id: "agent-2",
                agent_id: "agent-b",
                display_name: "Agent B",
                status: "revoked",
                created_at: "2026-03-12T00:00:00.000Z",
                revoked_at: "2026-03-12T02:00:00.000Z"
              }
            ],
            next_cursor: "cursor-2"
          }),
          { status: 200 }
        );
      }

      return new Response(null, { status: 404 });
    });

    vi.stubGlobal("fetch", fetchMock);
    renderApp(["/agents"]);

    expect(await screen.findByText("agent-c")).toBeInTheDocument();
    expect(screen.getByText("agent-b")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /load more/i }));

    expect(await screen.findByText("agent-a")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getAllByText(/agent-[abc]/i)).toHaveLength(3);
    });
  });

  it("blocks weak temporary passwords and disables last-admin suspension", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);

      if (url.endsWith("/api/v2/auth/refresh")) {
        return new Response(JSON.stringify(createAdminSession()), { status: 200 });
      }

      if (url.includes("/api/v2/members?limit=100&status=active")) {
        return new Response(
          JSON.stringify({
            members: [
              {
                id: "user-1",
                email: "owner@example.com",
                role: "workspace_admin",
                status: "active",
                email_verified: true,
                force_password_change: false,
                created_at: "2026-03-13T00:00:00.000Z",
                updated_at: "2026-03-13T00:00:00.000Z"
              }
            ],
            next_cursor: null
          }),
          { status: 200 }
        );
      }

      if (url.includes("/api/v2/members?limit=10")) {
        return new Response(
          JSON.stringify({
            members: [
              {
                id: "user-1",
                email: "owner@example.com",
                role: "workspace_admin",
                status: "active",
                email_verified: true,
                force_password_change: false,
                created_at: "2026-03-13T00:00:00.000Z",
                updated_at: "2026-03-13T00:00:00.000Z"
              }
            ],
            next_cursor: null
          }),
          { status: 200 }
        );
      }

      return new Response(null, { status: 404 });
    });

    vi.stubGlobal("fetch", fetchMock);
    renderApp(["/members"]);

    expect(await screen.findByLabelText("Role for owner@example.com")).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: /add member/i }));
    await userEvent.type(screen.getByLabelText("Email address"), "viewer@example.com");
    await userEvent.type(screen.getByLabelText("Temporary password"), "short");
    await userEvent.click(screen.getByRole("button", { name: /^create member$/i }));

    expect(await screen.findByText(/temporary password must be at least 12 characters/i)).toBeInTheDocument();
  });

  it("updates workspace display name and syncs the shell", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);

      if (url.endsWith("/api/v2/auth/refresh")) {
        return new Response(JSON.stringify(createAdminSession()), { status: 200 });
      }

      if (url.endsWith("/api/v2/workspace")) {
        return new Response(
          JSON.stringify({
            workspace: {
              id: "workspace-1",
              slug: "acme",
              display_name: "Acme",
              tier: "free",
              status: "active",
              owner_user_id: "user-1",
              owner_email_verified: true,
              created_at: "2026-03-13T00:00:00.000Z",
              updated_at: "2026-03-13T00:00:00.000Z"
            }
          }),
          { status: 200 }
        );
      }

      if (url.endsWith("/api/v2/workspace") && false) {
        return new Response(null, { status: 404 });
      }

      return new Response(
        JSON.stringify({
          workspace: {
            id: "workspace-1",
            slug: "acme",
            display_name: "Acme Prime",
            tier: "free",
            status: "active",
            owner_user_id: "user-1",
            owner_email_verified: true,
            created_at: "2026-03-13T00:00:00.000Z",
            updated_at: "2026-03-13T00:00:00.000Z"
          }
        }),
        { status: 200 }
      );
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);

        if (url.endsWith("/api/v2/workspace") && init?.method === "PATCH") {
          return new Response(
            JSON.stringify({
              workspace: {
                id: "workspace-1",
                slug: "acme",
                display_name: "Acme Prime",
                tier: "free",
                status: "active",
                owner_user_id: "user-1",
                owner_email_verified: true,
                created_at: "2026-03-13T00:00:00.000Z",
                updated_at: "2026-03-13T00:00:00.000Z"
              }
            }),
            { status: 200 }
          );
        }

        return fetchMock(input);
      })
    );

    renderApp(["/settings"]);

    const displayNameInput = await screen.findByLabelText(/^display name$/i);
    expect(displayNameInput).toHaveValue("Acme");
    await waitFor(() => {
      expect(displayNameInput).toBeEnabled();
    });

    await userEvent.clear(displayNameInput);
    await userEvent.type(displayNameInput, "Acme Prime");
    await userEvent.click(screen.getByRole("button", { name: /save workspace/i }));

    expect(await screen.findByText("Workspace display name updated.")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getAllByText("Acme Prime").length).toBeGreaterThan(0);
    });
  });
});
