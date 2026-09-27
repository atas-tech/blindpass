import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../../test/axe.js";
import { fakeController, json, renderRoute } from "../../test/controller.js";
import { HOSTILE } from "../../test/fixtures.js";
import { formatCapabilities } from "./common.js";

const FINGERPRINT = "ab".repeat(32);

function enrollment(overrides: Record<string, unknown> = {}) {
  return { id: "en_1", name: "build-01", status: "submitted", fingerprint: FINGERPRINT, protocol_version: "blindpass-node/1", capabilities: { modes: ["file"] }, created_at: Date.now() - 5_000, expires_at: Date.now() + 600_000, version: 2, ...overrides };
}

function node(overrides: Record<string, unknown> = {}) {
  return { id: "nd_1", name: "build-01", status: "offline", revocation_pending: false, rotation_pending: false, pending_key_version: null, pending_rotation_id: null, protocol_version: "blindpass-node/1", capabilities: {}, key_version: 1, signing_fingerprint: FINGERPRINT, recipient_fingerprint: "cd".repeat(32), last_seen_at: null, last_poll_at: null, created_at: Date.now() - 60_000, version: 1, ...overrides };
}

function grant(overrides: Record<string, unknown> = {}) {
  return { id: "gr_1", operation_id: "op_1", node_id: "nd_1", workload_id: "wl_1", invocation_id: "inv", account: "deploy", resource_id: "res", recipient_key_id: "rk", policy_version: 1, approval_reference: null, action: "noop.marker", mode: "file", audience: "blindpass-node", issuer_epoch: 1, issued_at: Date.now() - 10_000, expires_at: Date.now() + 100_000, status: "delivered", unit: "deploy.service", consumed_at: null, revoked_at: null, revoked_by: null, broker_revocation_outcome: null, ...overrides };
}

describe("fleet", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("DR-E25: without fleet.v3 every fleet route is absent, not a placeholder", async () => {
    const { calls } = fakeController({ fleet: false, handler: () => undefined });
    for (const path of ["/nodes", "/enrollments", "/workloads", "/grants", "/operations", "/policy/fleet"]) {
      const { unmount } = renderRoute(path);
      expect(await screen.findByRole("heading", { name: "This page doesn't exist" })).toBeTruthy();
      unmount();
    }
    expect(calls.some((call) => /\/api\/v3\/(nodes|enrollments|workloads|grants|operations|policies)/.test(call.path))).toBe(false);
  });

  it.each([
    [0, "timeout"],
    [403, "role_denied"],
    [500, "internal"]
  ])("P04-I05: a %s nodes read is an error, never an empty fleet", async (status, code) => {
    fakeController({ handler: (call) => (call.path === "/api/v3/nodes" ? (status === 0 ? Promise.reject(new TypeError("network")) : json(status, { error: code })) : undefined) });
    const { container } = renderRoute("/nodes");
    const alert = await screen.findByRole("alert");
    expect(alert).toBeTruthy();
    expect(screen.queryByText("No nodes")).toBeNull();
    expect(container.querySelector("main .badge, main tbody")).toBeNull();
  });

  it("P04-E01 enroll: approve stays disabled until the typed fingerprint matches exactly; the submitted value is never shown first", async () => {
    const { calls } = fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/enrollments/en_1/approve") return json(200, node());
        if (call.path === "/api/v3/enrollments") return json(200, { items: [enrollment()], next_cursor: null });
        return undefined;
      }
    });
    const user = userEvent.setup();
    renderRoute("/enrollments");
    await user.click(await screen.findByRole("button", { name: "Review enrollment build-01" }));
    const dialog = await screen.findByRole("dialog", { name: "Review build-01" });
    expect(dialog.textContent).not.toContain(FINGERPRINT.slice(0, 16));
    const approve = within(dialog).getByRole("button", { name: "Approve node" }) as HTMLButtonElement;
    expect(approve.disabled).toBe(true);
    const input = within(dialog).getByLabelText("Fingerprint printed by the node");
    await user.type(input, "ab".repeat(31) + "ac");
    expect(within(dialog).getByText(/doesn't match the keys/)).toBeTruthy();
    expect(approve.disabled).toBe(true);
    await user.clear(input);
    await user.type(input, FINGERPRINT.toUpperCase().match(/.{4}/g)!.join(" "));
    expect(approve.disabled).toBe(false);
    await user.click(approve);
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v3/enrollments/en_1/approve")).toBe(true));
    expect(calls.find((call) => call.path === "/api/v3/enrollments/en_1/approve")!.body).toEqual({ expected_fingerprint: FINGERPRINT, expected_version: 2 });
  });

  it("an offline node never reads as online and a queued revocation is explained", async () => {
    fakeController({ handler: (call) => (call.path === "/api/v3/nodes/nd_1" ? json(200, node({ status: "revoked", revocation_pending: true })) : undefined) });
    const { container } = renderRoute("/nodes/nd_1");
    expect(await screen.findByRole("heading", { name: "build-01" })).toBeTruthy();
    expect(screen.getAllByText("Revocation queued").length).toBeGreaterThan(0);
    expect(screen.getByText(/may still hold grants/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Revoke node" })).toBeNull();
    expect(await axeViolations(container)).toEqual([]);
  });

  it.each([
    ["grant_revoked", "Grant revoked", /wasn't used/],
    ["not_revocable_offline", "Revoked, but the node is offline", /may use it before it expires/],
    ["grant_revoked_after_consumption", "Revoked after it was used", /up to 90 seconds/]
  ])("I10/E10: a %s revocation tells the operator who may still hold the value", async (status, title, body) => {
    fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/grants/gr_1" && call.method === "DELETE") return json(200, { status, grant_id: "gr_1", consumer_lifetime_seconds: status === "grant_revoked_after_consumption" ? 90 : null });
        if (call.path === "/api/v3/grants") return json(200, { items: [grant()], next_cursor: null });
        return undefined;
      }
    });
    const user = userEvent.setup();
    renderRoute("/grants");
    await user.click(await screen.findByRole("button", { name: "Revoke grant for deploy.service" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke this grant?" });
    expect(dialog.textContent).toContain("Broker on nd_1");
    await user.click(within(dialog).getByRole("button", { name: "Revoke grant" }));
    expect(await screen.findByText(title)).toBeTruthy();
    expect(screen.getByText(body)).toBeTruthy();
  });

  it("viewers can read nodes but not grants or operations", async () => {
    fakeController({ role: "viewer", handler: () => undefined });
    const { unmount } = renderRoute("/grants");
    expect(await screen.findByRole("heading", { name: "Your role can't open this page" })).toBeTruthy();
    unmount();
    renderRoute("/nodes");
    expect(await screen.findByRole("heading", { name: "Nodes you trust." })).toBeTruthy();
  });

  it("fleet policy derives approval_required and names approvers only for pending approval", async () => {
    const { calls } = fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/policies" && call.method === "PUT") return json(200, { version: 3, rules: (call.body as { rules: unknown[] }).rules, updated_at: Date.now(), updated_by: "op_ada" });
        if (call.path === "/api/v3/policies") return json(200, { version: 2, rules: [{ id: "noop-file", action: "noop.marker", mode: "file", decision: "allow", approval_required: false, max_ttl_seconds: 60 }], updated_at: Date.now(), updated_by: "op_ada" });
        return undefined;
      }
    });
    const user = userEvent.setup();
    renderRoute("/policy/fleet");
    const socket = await screen.findByRole("radiogroup", { name: "Decision for Socket" });
    await user.click(within(socket).getByRole("radio", { name: "Needs approval" }));
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText(/Name 1–32 approvers/)).toBeTruthy();
    const approvers = screen.getByLabelText("Approvers");
    await user.type(approvers, "ada{enter}rina");
    await user.click(screen.getByRole("button", { name: "Save fleet policy" }));
    expect(await screen.findByText("Fleet policy saved as version 3")).toBeTruthy();
    const put = calls.find((call) => call.method === "PUT")!;
    expect(put.headers.get("if-match")).toBe('"2"');
    expect(put.body).toEqual({
      expected_version: 2,
      rules: [
        { id: "noop-file", action: "noop.marker", mode: "file", decision: "allow", approval_required: false, max_ttl_seconds: 60 },
        { id: "noop-marker-socket", action: "noop.marker", mode: "socket", decision: "pending_approval", approval_required: true, max_ttl_seconds: 120, approver_ids: ["ada", "rina"] }
      ]
    });
  });

  it("node-reported capabilities render one line per key and stay inert text", async () => {
    expect(formatCapabilities({ modes: ["file", "socket"], actions: ["noop.marker"], limits: { ttl: 60 } })).toBe('modes: file, socket\nactions: noop.marker\nlimits: {"ttl":60}');
    fakeController({ handler: (call) => (call.path === "/api/v3/nodes/nd_1" ? json(200, node({ capabilities: { note: HOSTILE } })) : undefined) });
    const { container } = renderRoute("/nodes/nd_1");
    expect(await screen.findByText(`note: ${HOSTILE}`)).toBeTruthy();
    expect(container.querySelector("main img, main script, main a[href^='javascript']")).toBeNull();
  });
});
