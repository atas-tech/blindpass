import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createBillingCheckoutSession,
  createBillingPortalSession,
  listBillingAllowances,
  listX402Transactions
} from "../../api/dashboard.js";
import { apiRequest } from "../../api/client.js";
import { useAuth } from "../../auth/useAuth.js";
import { useDashboardSummary } from "../../hooks/useDashboardSummary.js";
import { BillingPage } from "../Billing.js";

vi.mock("../../api/dashboard.js", () => ({
  createBillingCheckoutSession: vi.fn(),
  createBillingPortalSession: vi.fn(),
  listBillingAllowances: vi.fn(async () => ({ allowances: [] })),
  listX402Transactions: vi.fn(async () => ({ transactions: [], next_cursor: null }))
}));

vi.mock("../../api/client.js", () => ({
  apiRequest: vi.fn(async () => ({
    agents: [{
      id: "agent-row-1",
      agent_id: "agent:crm-bot",
      display_name: "CRM Bot",
      status: "active"
    }],
    next_cursor: null
  }))
}));

vi.mock("../../auth/useAuth.js", () => ({
  useAuth: vi.fn()
}));

vi.mock("../../hooks/useDashboardSummary.js", () => ({
  useDashboardSummary: vi.fn()
}));

function mockSummary(tier: "free" | "standard") {
  return {
    summary: {
      workspace: {
        id: "workspace-1",
        slug: "acme",
        display_name: "Acme",
        tier,
        status: "active"
      },
      billing: {
        workspace_id: "workspace-1",
        workspace_slug: "acme",
        tier,
        status: "active",
        billing_provider: tier === "standard" ? "stripe" : null,
        provider_customer_id: tier === "standard" ? "cus_123" : null,
        provider_subscription_id: tier === "standard" ? "sub_123" : null,
        subscription_status: tier === "standard" ? "active" : "none"
      },
      counts: {
        active_agents: 1,
        active_members: 1
      },
      quota: {
        exchange_requests: {
          used: 2,
          limit: 10,
          reset_at: 1_773_619_200
        },
        secret_requests: {
          used: 4,
          limit: 10,
          reset_at: 1_773_619_200
        },
        agents: {
          used: 1,
          limit: 5
        },
        members: {
          used: 1,
          limit: 3
        },
        a2a_exchange_available: false
      }
    },
    loading: false,
    error: null,
    refresh: vi.fn()
  };
}

describe("BillingPage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    (useAuth as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      workspace: {
        id: "workspace-1",
        slug: "acme",
        display_name: "Acme",
        tier: "free",
        status: "active",
        owner_user_id: "user-1",
        created_at: "2026-03-14T00:00:00.000Z",
        updated_at: "2026-03-14T00:00:00.000Z"
      },
      setWorkspaceSummary: vi.fn()
    });
    vi.stubGlobal("location", {
      ...window.location,
      assign: vi.fn()
    });
  });

  it("starts checkout for free-tier workspaces", async () => {
    (useDashboardSummary as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockSummary("free"));
    (createBillingCheckoutSession as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      checkout_url: "https://checkout.example.test/session"
    });
    (listBillingAllowances as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({ allowances: [] });
    (listX402Transactions as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({ transactions: [], next_cursor: null });
    (apiRequest as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      agents: [{
        id: "agent-row-1",
        agent_id: "agent:crm-bot",
        display_name: "CRM Bot",
        status: "active"
      }],
      next_cursor: null
    });

    render(<BillingPage />);

    await userEvent.click(screen.getByRole("button", { name: /upgrade to standard/i }));

    expect(createBillingCheckoutSession).toHaveBeenCalledTimes(1);
    expect(window.location.assign).toHaveBeenCalledWith("https://checkout.example.test/session");
    expect(screen.getByText("Agent payments active")).toBeInTheDocument();
  });

  it("opens the billing portal for standard-tier workspaces", async () => {
    (useDashboardSummary as unknown as ReturnType<typeof vi.fn>).mockReturnValue(mockSummary("standard"));
    (createBillingPortalSession as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      portal_url: "https://billing.example.test/portal"
    });
    (listBillingAllowances as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({ allowances: [] });
    (listX402Transactions as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({ transactions: [], next_cursor: null });
    (apiRequest as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      agents: [{
        id: "agent-row-1",
        agent_id: "agent:crm-bot",
        display_name: "CRM Bot",
        status: "active"
      }],
      next_cursor: null
    });

    render(<BillingPage />);

    await userEvent.click(screen.getByRole("button", { name: /manage subscription/i }));

    expect(createBillingPortalSession).toHaveBeenCalledTimes(1);
    expect(window.location.assign).toHaveBeenCalledWith("https://billing.example.test/portal");
    expect(screen.getByText("Workspace plan")).toBeInTheDocument();
  });
});
