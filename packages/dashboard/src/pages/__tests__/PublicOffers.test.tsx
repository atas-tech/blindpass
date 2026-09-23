import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "../../api/client.js";
import { useAuth } from "../../auth/useAuth.js";
import { PublicOffersPage } from "../PublicOffers.js";

vi.mock("../../api/client.js", () => ({
  apiRequest: vi.fn()
}));

vi.mock("../../auth/useAuth.js", () => ({
  useAuth: vi.fn()
}));

function buildOffer() {
  return {
    id: "offer-1",
    workspace_id: "ws_1",
    created_by_user_id: "user-1",
    offer_label: "Stripe handoff",
    delivery_mode: "human",
    payment_policy: "always_x402",
    price_usd_cents: 5,
    included_free_uses: 0,
    secret_name: "stripe.api_key.prod",
    allowed_fulfiller_id: null,
    require_approval: true,
    status: "active",
    max_uses: null,
    used_count: 1,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    revoked_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
}

function buildIntent(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "intent-1",
    workspace_id: "ws_1",
    offer_id: "offer-1",
    offer_label: "Stripe handoff",
    offer_status: "active",
    offer_used_count: 1,
    offer_max_uses: null,
    offer_expires_at: new Date(Date.now() + 60_000).toISOString(),
    actor_type: "guest_agent",
    status: "pending_approval",
    effective_status: "pending_approval",
    approval_status: "pending",
    approval_reference: "apr_guest_1",
    requester_label: "External requester",
    purpose: "Charge order 784",
    delivery_mode: "human",
    payment_policy: "always_x402",
    price_usd_cents: 5,
    included_free_uses: 0,
    resolved_secret_name: "stripe.api_key.prod",
    allowed_fulfiller_id: null,
    request_id: null,
    request_state: null,
    exchange_id: null,
    exchange_state: null,
    agent_delivery: null,
    activated_at: null,
    revoked_at: null,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    latest_payment: null,
    ...overrides
  };
}

describe("PublicOffersPage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("renders read-only support detail for viewers", async () => {
    const offer = buildOffer();
    const intent = buildIntent({
      effective_status: "activated",
      status: "activated",
      approval_status: "approved",
      request_id: "req_1",
      request_state: {
        status: "pending",
        expires_at: new Date(Date.now() + 60_000).toISOString()
      },
      latest_payment: {
        payment_id: "pay_1",
        status: "settled",
        tx_hash: "0xabc",
        settled_at: new Date().toISOString(),
        created_at: new Date().toISOString()
      }
    });

    (useAuth as any).mockReturnValue({
      user: { role: "workspace_viewer" }
    });
    (apiRequest as any).mockImplementation((path: string) => {
      if (path === "/api/v2/public/offers") {
        return Promise.resolve({ offers: [offer] });
      }
      if (path.startsWith("/api/v2/public/intents/admin?")) {
        return Promise.resolve({ intents: [intent] });
      }
      if (path === "/api/v2/public/intents/admin/intent-1") {
        return Promise.resolve({ intent });
      }
      return Promise.reject(new Error(`Unexpected path ${path}`));
    });

    render(<PublicOffersPage />);

    expect(await screen.findByText("Public offers and guest requests")).toBeInTheDocument();
    expect((await screen.findAllByText("Stripe handoff")).length).toBeGreaterThan(0);
    expect(await screen.findByText("Human handoff")).toBeInTheDocument();
    expect((await screen.findAllByText("Payment required")).length).toBeGreaterThan(0);
    expect(await screen.findByText("Viewer access is read-only")).toBeInTheDocument();
    expect((await screen.findAllByText("Charge order 784")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /approve/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /revoke intent/i })).not.toBeInTheDocument();
  });

  it("shows guest-agent delivery failure detail and lets operators retry safely", async () => {
    const offer = buildOffer();
    const failedIntent = buildIntent({
      delivery_mode: "agent",
      status: "activated",
      effective_status: "activated",
      approval_status: "approved",
      exchange_id: "ex_1",
      exchange_state: {
        status: "pending",
        fulfilled_by: null,
        expires_at: new Date(Date.now() + 60_000).toISOString()
      },
      agent_delivery: {
        state: "delivery_failed",
        recoverable: true,
        failure_reason: "runtime transport unavailable",
        failed_at: new Date().toISOString(),
        last_dispatched_at: new Date().toISOString(),
        attempt_count: 1
      }
    });
    const retriedIntent = buildIntent({
      ...failedIntent,
      agent_delivery: {
        state: "pending",
        recoverable: false,
        failure_reason: null,
        failed_at: null,
        last_dispatched_at: new Date().toISOString(),
        attempt_count: 2
      }
    });

    (useAuth as any).mockReturnValue({
      user: { role: "workspace_operator" }
    });
    let currentIntent = failedIntent;
    (apiRequest as any).mockImplementation((path: string, init?: RequestInit) => {
      if (path === "/api/v2/public/offers") {
        return Promise.resolve({ offers: [offer] });
      }
      if (path.startsWith("/api/v2/public/intents/admin?")) {
        return Promise.resolve({ intents: [currentIntent] });
      }
      if (path === "/api/v2/public/intents/admin/intent-1") {
        return Promise.resolve({ intent: currentIntent });
      }
      if (path === "/api/v2/public/intents/intent-1/retry-agent-delivery" && init?.method === "POST") {
        currentIntent = retriedIntent;
        return Promise.resolve({ intent: currentIntent, exchange_id: "ex_1", fulfillment_token: "redacted" });
      }
      return Promise.reject(new Error(`Unexpected path ${path}`));
    });

    render(<PublicOffersPage />);

    expect(await screen.findByText("Delivery failed")).toBeInTheDocument();
    expect(await screen.findByText(/Failure: runtime transport unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText("redacted")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /retry delivery/i }));
    await userEvent.click(await screen.findByTestId("confirm-dialog-btn"));

    await waitFor(() => {
      expect(apiRequest).toHaveBeenCalledWith("/api/v2/public/intents/intent-1/retry-agent-delivery", { method: "POST" });
    });
    expect(await screen.findByText(/attempt 2/i)).toBeInTheDocument();
    expect(await screen.findByText(/No guest-agent delivery failure recorded/i)).toBeInTheDocument();
  });

  it("lets operators approve a pending guest intent from the support detail", async () => {
    const offer = buildOffer();
    const pendingIntent = buildIntent();
    const approvedIntent = buildIntent({
      status: "payment_required",
      effective_status: "payment_required",
      approval_status: "approved"
    });

    (useAuth as any).mockReturnValue({
      user: { role: "workspace_operator" }
    });
    let currentIntent = pendingIntent;
    (apiRequest as any).mockImplementation((path: string, init?: RequestInit) => {
      if (path === "/api/v2/public/offers") {
        return Promise.resolve({ offers: [offer] });
      }
      if (path.startsWith("/api/v2/public/intents/admin?")) {
        return Promise.resolve({ intents: [currentIntent] });
      }
      if (path === "/api/v2/public/intents/admin/intent-1") {
        return Promise.resolve({ intent: currentIntent });
      }
      if (path === "/api/v2/public/intents/intent-1/approve" && init?.method === "POST") {
        currentIntent = approvedIntent;
        return Promise.resolve({ intent: currentIntent });
      }
      return Promise.reject(new Error(`Unexpected path ${path}`));
    });

    render(<PublicOffersPage />);

    expect((await screen.findAllByText("Charge order 784")).length).toBeGreaterThan(0);
    await userEvent.click(await screen.findByRole("button", { name: /approve/i }));
    await userEvent.click(await screen.findByTestId("confirm-dialog-btn"));

    await waitFor(() => {
      expect(apiRequest).toHaveBeenCalledWith("/api/v2/public/intents/intent-1/approve", { method: "POST" });
    });
    expect((await screen.findAllByText("Payment required")).length).toBeGreaterThan(0);
  });
});
