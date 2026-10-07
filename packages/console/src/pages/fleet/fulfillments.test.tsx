import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../../test/axe.js";
import { fakeController, json, renderRoute, type Call } from "../../test/controller.js";
import { HOSTILE } from "../../test/fixtures.js";

const ISSUER_FP = "ab".repeat(32);
const RECIPIENT_FP = "cd".repeat(32);
const GROUPED_ISSUER = "abab abab abab abab abab abab abab abab abab abab abab abab abab abab abab abab";

function fulfillment(overrides: Record<string, unknown> = {}) {
  return {
    id: "fu_1",
    status: "awaiting_approval",
    version: 1,
    mode: "reencrypt",
    issuer: { workload_id: "wl_i", node_id: "nd_i", unit: "issuer-app.service", credential: "api-token", key_version: 1, registration_version: 1, fingerprint: ISSUER_FP },
    recipient: { workload_id: "wl_r", node_id: "nd_r", unit: "recipient-app.service", credential: "api-token", key_version: 1, registration_version: 1, fingerprint: RECIPIENT_FP },
    parties_bound: false,
    requested_by: "op_rina",
    purpose: "Rotate the dummy token",
    untrusted_fields: ["purpose"],
    policy_version: 3,
    rule_id: "cross-approve",
    decision: "pending_approval",
    approval: { status: "pending", approver_ids: ["ada"], decided_by: null, decided_at: null },
    prior_fulfillment_id: null,
    ttl_seconds: 300,
    terms_digest: null,
    failure_code: null,
    revocation_reason: null,
    delivery_revoked_at: null,
    provider_revocation: "unsupported",
    created_at: Date.now() - 30_000,
    expires_at: Date.now() + 270_000,
    approved_at: null,
    offered_at: null,
    available_at: null,
    stored_at: null,
    completed_at: null,
    closed_at: null,
    ...overrides
  };
}

function workload(id: string, node: string, name: string, overrides: Record<string, unknown> = {}) {
  return { id, node_id: node, name, unit: `${name}.service`, account: "svc", consumption_mode: "file", local_ceiling_seconds: 120, registration_version: 1, status: "active", created_at: Date.now() - 100_000, version: 1, ...overrides };
}

const WORKLOADS = [workload("wl_i", "nd_i", "issuer-app"), workload("wl_r", "nd_r", "recipient-app"), workload("wl_x", "nd_i", "issuer-sibling"), workload("wl_dead", "nd_r", "retired-app", { status: "revoked" })];

function node(id: string, name: string) {
  return { id, name, status: "online", revocation_pending: false, rotation_pending: false, pending_key_version: null, pending_rotation_id: null, protocol_version: "blindpass-node/1", capabilities: {}, key_version: 1, signing_fingerprint: ISSUER_FP, recipient_fingerprint: RECIPIENT_FP, last_seen_at: Date.now(), last_poll_at: null, created_at: Date.now() - 60_000, version: 1 };
}

type Answer = Response | Promise<Response> | undefined;

/** Workload and node lists plus a fulfillment list; `extra` answers first. */
function controller(options: { items?: unknown[]; extra?: (call: Call) => Answer; role?: "admin" | "operator" | "viewer"; fulfillments?: boolean } = {}) {
  return fakeController({
    role: options.role ?? "admin",
    fulfillments: options.fulfillments ?? true,
    handler: (call) => {
      const answered = options.extra?.(call);
      if (answered) return answered;
      if (call.path === "/api/v3/workloads") return json(200, { items: WORKLOADS, next_cursor: null });
      if (call.path === "/api/v3/nodes") return json(200, { items: [node("nd_i", "issuer-node"), node("nd_r", "recipient-node")], next_cursor: null });
      if (call.path === "/api/v3/fulfillments" && call.method === "GET") return json(200, { items: options.items ?? [], next_cursor: null });
      const detail = /^\/api\/v3\/fulfillments\/([^/]+)$/.exec(call.path);
      if (detail && call.method === "GET") {
        const found = (options.items ?? []).find((item) => (item as { id: string }).id === detail[1]);
        return found ? json(200, found) : json(404, { error: "fulfillment_not_found" });
      }
      return undefined;
    }
  });
}

describe("P10 fulfillments console", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("P10-I01: the route and nav item exist only when the controller reports the fulfillment flag", async () => {
    const off = fakeController({ fulfillments: false, handler: () => undefined });
    const first = renderRoute("/fulfillments");
    expect(await screen.findByRole("heading", { name: "This page doesn't exist" })).toBeTruthy();
    expect(off.calls.some((call) => call.path.startsWith("/api/v3/fulfillments"))).toBe(false);
    first.unmount();

    controller({ items: [] });
    renderRoute("/");
    expect(await screen.findByRole("link", { name: "Fulfillments" })).toBeTruthy();
  });

  it("without the flag the nav has no fulfillment entry", async () => {
    fakeController({ fulfillments: false, handler: () => undefined });
    renderRoute("/");
    await screen.findByRole("link", { name: "Grants" });
    expect(screen.queryByRole("link", { name: "Fulfillments" })).toBeNull();
  });

  it("viewers are refused every fulfillment route", async () => {
    const { calls } = controller({ role: "viewer" });
    renderRoute("/fulfillments");
    expect(await screen.findByRole("heading", { name: "Your role can't open this page" })).toBeTruthy();
    expect(calls.some((call) => call.path === "/api/v3/fulfillments")).toBe(false);
  });

  it.each([
    ["awaiting_approval", "Awaiting approval"],
    ["approved", "Approved"],
    ["offered", "Key offered"],
    ["available", "Ciphertext ready"],
    ["recipient_consumed", "Stored on recipient"],
    ["completed", "Completed"],
    ["denied", "Denied"],
    ["revoked", "Revoked"],
    ["expired", "Expired"],
    ["failed", "Failed"],
    ["uncertain", "Uncertain"]
  ])("a %s fulfillment is labelled %s in words, with its workloads named", async (status, label) => {
    controller({ items: [fulfillment({ status })] });
    renderRoute("/fulfillments");
    const row = await waitForRow("fu_1");
    expect(within(row).getByText(label)).toBeTruthy();
    expect(row.textContent).toContain("issuer-app");
    expect(row.textContent).toContain("recipient-app");
    // The operator's purpose text is never part of the list.
    expect(row.textContent).not.toContain("Rotate the dummy token");
  });

  it("an uncertain fulfillment says what happened, that it holds the slot, and offers revoke", async () => {
    controller({ items: [fulfillment({ status: "uncertain", failure_code: "no_recipient_result" })] });
    renderRoute("/fulfillments");
    const row = await waitForRow("fu_1");
    expect(within(row).getByText(/recipient never confirmed/i)).toBeTruthy();
    expect(within(row).getByText(/holds the recipient's slot/i)).toBeTruthy();
    expect(within(row).getByRole("button", { name: "Revoke fulfillment for recipient-app" })).toBeTruthy();
  });

  it("failure codes and reasons are plain text, and a closed fulfillment can't be revoked", async () => {
    controller({
      items: [
        fulfillment({ id: "fu_f", status: "failed", failure_code: HOSTILE, revocation_reason: "failed" }),
        fulfillment({ id: "fu_c", status: "completed", approval: { status: "approved", approver_ids: ["ada"], decided_by: "op_ada", decided_at: Date.now() } })
      ]
    });
    const { container } = renderRoute("/fulfillments");
    const failed = await waitForRow("fu_f");
    expect(failed.textContent).toContain(HOSTILE);
    expect(container.querySelector("main img, main script, main b")).toBeNull();
    const done = await waitForRow("fu_c");
    expect(within(done).queryByRole("button", { name: /Revoke/ })).toBeNull();
    // A completed transfer never reads as revoked at the provider.
    expect(done.textContent).toMatch(/cannot revoke this at the provider/i);
    expect(done.textContent).not.toMatch(/erased|wiped/i);
  });

  it("filters by status through the query string", async () => {
    const { calls } = controller({ items: [] });
    const user = userEvent.setup();
    renderRoute("/fulfillments");
    await screen.findByText("No fulfillments");
    await user.selectOptions(screen.getByLabelText("Status"), "uncertain");
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v3/fulfillments" && call.query.get("status") === "uncertain")).toBe(true));
  });

  it("P10-I01: the list and the review dialog pass the accessibility checks", async () => {
    controller({ items: [fulfillment()] });
    const user = userEvent.setup();
    const { container } = renderRoute("/fulfillments");
    await waitForRow("fu_1");
    expect(await axeViolations(container)).toEqual([]);
    await user.click(screen.getByRole("button", { name: "Review fulfillment for recipient-app" }));
    const dialog = await screen.findByRole("dialog", { name: "Review fulfillment" });
    expect(await axeViolations(dialog)).toEqual([]);
  });

  describe("request", () => {
    async function openCreate() {
      const user = userEvent.setup();
      renderRoute("/fulfillments");
      await screen.findByText("No fulfillments");
      await user.click(screen.getByRole("button", { name: "Request fulfillment" }));
      const dialog = await screen.findByRole("dialog", { name: "Request a credential fulfillment" });
      return { user, dialog };
    }

    async function fill(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement, overrides: { issuer?: string; recipient?: string; issuerCredential?: string; recipientCredential?: string; purpose?: string } = {}) {
      await waitFor(() => expect((within(dialog).getByLabelText("Issuer workload") as HTMLSelectElement).options.length).toBeGreaterThan(1));
      await user.selectOptions(within(dialog).getByLabelText("Issuer workload"), overrides.issuer ?? "wl_i");
      await user.selectOptions(within(dialog).getByLabelText("Recipient workload"), overrides.recipient ?? "wl_r");
      await user.type(within(dialog).getByLabelText("Issuer credential name"), overrides.issuerCredential ?? "api-token");
      await user.type(within(dialog).getByLabelText("Recipient credential name"), overrides.recipientCredential ?? "api-token");
      const purpose = within(dialog).getByLabelText("Purpose");
      if (overrides.purpose && /[\u0000-\u001f]/.test(overrides.purpose)) fireEvent.change(purpose, { target: { value: overrides.purpose } });
      else await user.type(purpose, overrides.purpose ?? "Rotate the dummy token");
    }

    it("lists only active workloads, validates names like the server, and sends nothing when invalid", async () => {
      const { calls } = controller({ items: [] });
      const { user, dialog } = await openCreate();
      await waitFor(() => expect((within(dialog).getByLabelText("Issuer workload") as HTMLSelectElement).options.length).toBeGreaterThan(1));
      const options = Array.from((within(dialog).getByLabelText("Recipient workload") as HTMLSelectElement).options).map((option) => option.value);
      expect(options).toEqual(["", "wl_i", "wl_r", "wl_x"]);
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      expect(await within(dialog).findAllByText(/Choose a workload/)).toHaveLength(2);
      await fill(user, dialog, { issuerCredential: "../etc/passwd", recipientCredential: ".hidden" });
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      expect(await within(dialog).findAllByText(/Use letters, digits, _ - and \./)).toHaveLength(2);
      expect(calls.some((call) => call.method === "POST" && call.path === "/api/v3/fulfillments")).toBe(false);
    });

    it("refuses the same workload, or two workloads on one node, before sending", async () => {
      const { calls } = controller({ items: [] });
      const { user, dialog } = await openCreate();
      await fill(user, dialog, { issuer: "wl_i", recipient: "wl_x" });
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      expect(await within(dialog).findByText(/different nodes/)).toBeTruthy();
      await user.selectOptions(within(dialog).getByLabelText("Recipient workload"), "wl_i");
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      expect(await within(dialog).findByText(/different workloads/)).toBeTruthy();
      expect(calls.some((call) => call.method === "POST")).toBe(false);
    });

    it("refuses control characters and an overlong purpose", async () => {
      const { calls } = controller({ items: [] });
      const { user, dialog } = await openCreate();
      await fill(user, dialog, { purpose: "rotate\u001b[31m token" });
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      expect(await within(dialog).findByText(/1–512 characters/)).toBeTruthy();
      fireEvent.change(within(dialog).getByLabelText("Purpose"), { target: { value: "p".repeat(513) } });
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      expect(await within(dialog).findByText(/1–512 characters/)).toBeTruthy();
      expect(calls.some((call) => call.method === "POST")).toBe(false);
    });

    it("sends the exact binding with an idempotency key, reuses the key on retry and takes a new one for the next request", async () => {
      let attempt = 0;
      const { calls } = controller({
        items: [],
        extra: (call) => {
          if (call.method === "POST" && call.path === "/api/v3/fulfillments") {
            attempt += 1;
            return attempt === 1 ? json(503, { error: "not_ready" }) : json(201, fulfillment());
          }
          return undefined;
        }
      });
      const { user, dialog } = await openCreate();
      await fill(user, dialog);
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      expect(await within(dialog).findByText(/The action didn't complete/)).toBeTruthy();
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      await waitFor(() => expect(screen.queryByRole("dialog", { name: "Request a credential fulfillment" })).toBeNull());
      const posts = calls.filter((call) => call.method === "POST" && call.path === "/api/v3/fulfillments");
      expect(posts).toHaveLength(2);
      expect(posts[0]!.body).toEqual({ issuer_workload_id: "wl_i", recipient_workload_id: "wl_r", issuer_credential: "api-token", recipient_credential: "api-token", purpose: "Rotate the dummy token" });
      expect(posts[1]!.body).toEqual(posts[0]!.body);
      const key = posts[0]!.headers.get("idempotency-key");
      expect(key).toMatch(/^console-/);
      expect(posts[1]!.headers.get("idempotency-key")).toBe(key);
      // A later request is a different request.
      await user.click(screen.getByRole("button", { name: "Request fulfillment" }));
      const next = await screen.findByRole("dialog", { name: "Request a credential fulfillment" });
      await fill(user, next);
      await user.click(within(next).getByRole("button", { name: "Send request" }));
      await waitFor(() => expect(calls.filter((call) => call.method === "POST" && call.path === "/api/v3/fulfillments")).toHaveLength(3));
      expect(calls.filter((call) => call.method === "POST" && call.path === "/api/v3/fulfillments")[2]!.headers.get("idempotency-key")).not.toBe(key);
    });

    it.each([
      [403, "cross_workload_denied", /No cross-workload policy rule allows/],
      [409, "recipient_busy", /already has a live fulfillment/],
      [409, "party_unavailable", /unavailable, or both are on one node/],
      [404, "fulfillments_disabled", /isn't enabled on this controller/],
      [400, "same_party", /different workloads/],
      [409, "idempotency_conflict", /different request/],
      [404, "workload_not_found", /no longer exists/],
      [409, "prior_invalid", /prior fulfillment/]
    ])("maps %s %s to a specific message", async (status, code, message) => {
      controller({ items: [], extra: (call) => (call.method === "POST" && call.path === "/api/v3/fulfillments" ? json(status, { error: code, message: "server text must not be shown" }) : undefined) });
      const { user, dialog } = await openCreate();
      await fill(user, dialog);
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      const alert = await within(dialog).findByRole("alert");
      expect(alert.textContent).toMatch(message);
      expect(alert.textContent).not.toContain("server text must not be shown");
    });

    it("a lost reply says the request may exist and points at the list", async () => {
      controller({ items: [], extra: (call) => (call.method === "POST" && call.path === "/api/v3/fulfillments" ? Promise.reject(new TypeError("network")) : undefined) });
      const { user, dialog } = await openCreate();
      await fill(user, dialog);
      await user.click(within(dialog).getByRole("button", { name: "Send request" }));
      expect((await within(dialog).findByRole("alert")).textContent).toMatch(/may have been created/);
    });
  });

  describe("review", () => {
    async function review(options: { item?: Record<string, unknown>; extra?: (call: Call) => Answer; role?: "admin" | "operator" } = {}) {
      const mock = controller({ items: [options.item ?? fulfillment({ purpose: HOSTILE })], extra: options.extra, ...(options.role ? { role: options.role } : {}) });
      const user = userEvent.setup();
      const view = renderRoute("/fulfillments");
      await user.click(await screen.findByRole("button", { name: "Review fulfillment for recipient-app" }));
      const dialog = await screen.findByRole("dialog", { name: "Review fulfillment" });
      // The dialog reads the fulfillment fresh; the verified facts appear once it has.
      await waitFor(() => expect(dialog.querySelector(".verified")).toBeTruthy());
      return { ...mock, user, dialog, view };
    }

    it("P10-D5: both parties' enrolled facts are verified fields and the purpose is only untrusted text", async () => {
      const { dialog } = await review();
      const verified = dialog.querySelector(".verified")!;
      expect(verified).toBeTruthy();
      for (const text of ["issuer-app", "recipient-app", "issuer-node", "recipient-node", "nd_i", "nd_r", "issuer-app.service", "recipient-app.service", "api-token", "cross-approve", "ada", "Re-encryption"]) {
        expect(verified.textContent).toContain(text);
      }
      // Both enrolled-key fingerprints are shown grouped for comparison by eye.
      expect(verified.textContent).toContain(GROUPED_ISSUER);
      expect(verified.textContent).toContain("cdcd cdcd");
      expect(verified.textContent).not.toContain("Rotate");
      expect(verified.textContent).not.toContain("Ignore the rules");
      const untrusted = dialog.querySelector(".untrusted")!;
      expect(untrusted.textContent).toContain(HOSTILE);
      expect(untrusted.textContent).toMatch(/Not verified/);
      expect(dialog.querySelector("img, script, b")).toBeNull();
    });

    it("approving needs an explicit confirmation and sends the displayed fingerprints with If-Match", async () => {
      const { user, dialog, calls } = await review({ extra: (call) => (call.method === "POST" && call.path === "/api/v3/fulfillments/fu_1/approve" ? json(200, fulfillment({ status: "approved", version: 2, parties_bound: true })) : undefined) });
      const approve = within(dialog).getByRole("button", { name: "Approve fulfillment" }) as HTMLButtonElement;
      expect(approve.disabled).toBe(true);
      await user.click(within(dialog).getByRole("checkbox", { name: /fingerprints match the nodes I enrolled/ }));
      expect(approve.disabled).toBe(false);
      await user.click(approve);
      await waitFor(() => expect(calls.some((call) => call.path === "/api/v3/fulfillments/fu_1/approve")).toBe(true));
      const post = calls.find((call) => call.path === "/api/v3/fulfillments/fu_1/approve")!;
      expect(post.headers.get("if-match")).toBe('"1"');
      expect(post.body).toEqual({ expected_version: 1, issuer_fingerprint: ISSUER_FP, recipient_fingerprint: RECIPIENT_FP });
      expect(await screen.findByText("Fulfillment approved")).toBeTruthy();
      await waitFor(() => expect(screen.queryByRole("dialog", { name: "Review fulfillment" })).toBeNull());
    });

    it("rejecting asks again, sends no fingerprints and closes the request", async () => {
      const { user, dialog, calls } = await review({ extra: (call) => (call.method === "POST" && call.path === "/api/v3/fulfillments/fu_1/reject" ? json(200, fulfillment({ status: "denied", version: 2 })) : undefined) });
      await user.click(within(dialog).getByRole("button", { name: "Reject" }));
      expect(calls.some((call) => call.path.endsWith("/reject"))).toBe(false);
      await user.click(within(dialog).getByRole("button", { name: "Confirm rejection" }));
      await waitFor(() => expect(calls.some((call) => call.path === "/api/v3/fulfillments/fu_1/reject")).toBe(true));
      const post = calls.find((call) => call.path === "/api/v3/fulfillments/fu_1/reject")!;
      expect(post.headers.get("if-match")).toBe('"1"');
      expect(post.body).toEqual({ expected_version: 1 });
      expect(await screen.findByText("Fulfillment rejected")).toBeTruthy();
    });

    it.each([
      [409, "authorization_changed", /changed since this request/],
      [403, "self_approval_denied", /can't approve your own/],
      [403, "approval_scope_denied", /isn't named as an approver/],
      [409, "approval_conflict", /no longer pending/],
      [428, "if_match_required", /out of date/]
    ])("maps %s %s to a specific message", async (status, code, message) => {
      const { user, dialog, calls } = await review({ extra: (call) => (call.method === "POST" && call.path.endsWith("/approve") ? json(status, { error: code, message: "server text must not be shown" }) : undefined) });
      await user.click(within(dialog).getByRole("checkbox", { name: /fingerprints match/ }));
      await user.click(within(dialog).getByRole("button", { name: "Approve fulfillment" }));
      const alert = await within(dialog).findByRole("alert");
      expect(alert.textContent).toMatch(message);
      expect(alert.textContent).not.toContain("server text must not be shown");
      if (code === "authorization_changed") {
        // The list is re-read so the next review shows the current keys.
        await waitFor(() => expect(calls.filter((call) => call.path === "/api/v3/fulfillments" && call.method === "GET").length).toBeGreaterThan(1));
      }
    });

    it("the requester can't approve their own request from the console", async () => {
      const { dialog } = await review({ item: fulfillment({ requested_by: "op_ada" }) });
      expect(within(dialog).getByText(/You requested this/)).toBeTruthy();
      // The controller refuses a self-approval and a self-rejection alike; withdrawing is a revoke.
      expect((within(dialog).getByRole("button", { name: "Approve fulfillment" }) as HTMLButtonElement).disabled).toBe(true);
      expect((within(dialog).getByRole("button", { name: "Reject" }) as HTMLButtonElement).disabled).toBe(true);
      expect(within(dialog).getByText(/Use Revoke to withdraw it/)).toBeTruthy();
    });

    it("without enrolled-key fingerprints there is nothing to verify and approval stays off", async () => {
      const bare = fulfillment({ issuer: { workload_id: "wl_i", node_id: "nd_i", credential: "api-token" }, recipient: { workload_id: "wl_r", node_id: "nd_r", credential: "api-token" } });
      const { user, dialog } = await review({ item: bare });
      expect(within(dialog).getByText(/enrolled keys aren't available/)).toBeTruthy();
      const checkbox = within(dialog).getByRole("checkbox", { name: /fingerprints match/ }) as HTMLInputElement;
      expect(checkbox.disabled).toBe(true);
      await user.click(checkbox);
      expect((within(dialog).getByRole("button", { name: "Approve fulfillment" }) as HTMLButtonElement).disabled).toBe(true);
    });

    it("a fulfillment that no longer awaits approval has no review action", async () => {
      controller({ items: [fulfillment({ status: "approved", approval: { status: "approved", approver_ids: ["ada"], decided_by: "op_x", decided_at: Date.now() } })] });
      renderRoute("/fulfillments");
      const row = await waitForRow("fu_1");
      expect(within(row).queryByRole("button", { name: /Review/ })).toBeNull();
    });
  });

  describe("revoke", () => {
    it("states exactly what revoking does and does not undo, and never claims the provider was revoked", async () => {
      const revoked = fulfillment({ status: "revoked", version: 3, revocation_reason: "operator", delivery_revoked_at: Date.now(), provider_revocation: "unsupported" });
      const { calls } = controller({ items: [fulfillment({ status: "available", parties_bound: true })], extra: (call) => (call.method === "DELETE" && call.path === "/api/v3/fulfillments/fu_1" ? json(200, revoked) : undefined) });
      const user = userEvent.setup();
      renderRoute("/fulfillments");
      await user.click(await screen.findByRole("button", { name: "Revoke fulfillment for recipient-app" }));
      const dialog = await screen.findByRole("dialog", { name: "Revoke this fulfillment?" });
      for (const part of [/stored ciphertext is deleted/i, /both nodes are told/i, /already read can't be recalled/i, /BlindPass cannot revoke this at the provider/i]) {
        expect(dialog.textContent).toMatch(part);
      }
      expect(dialog.textContent).not.toMatch(/erased|wiped/i);
      await user.click(within(dialog).getByRole("button", { name: "Revoke fulfillment" }));
      await waitFor(() => expect(calls.some((call) => call.method === "DELETE")).toBe(true));
      const outcome = await screen.findByText("Fulfillment revoked");
      expect(outcome).toBeTruthy();
      expect(screen.getAllByText(/BlindPass cannot revoke this at the provider/i).length).toBeGreaterThan(0);
    });

    it("an unknown outcome is reported as unknown, not as revoked", async () => {
      controller({ items: [fulfillment({ status: "uncertain" })], extra: (call) => (call.method === "DELETE" ? Promise.reject(new TypeError("network")) : undefined) });
      const user = userEvent.setup();
      renderRoute("/fulfillments");
      await user.click(await screen.findByRole("button", { name: "Revoke fulfillment for recipient-app" }));
      const dialog = await screen.findByRole("dialog", { name: "Revoke this fulfillment?" });
      await user.click(within(dialog).getByRole("button", { name: "Revoke fulfillment" }));
      expect((await within(dialog).findByRole("alert")).textContent).toMatch(/didn't answer/);
      expect(screen.queryByText("Fulfillment revoked")).toBeNull();
    });
  });
});

async function waitForRow(id: string): Promise<HTMLElement> {
  return waitFor(() => {
    const row = document.querySelector<HTMLElement>(`tr[data-fulfillment="${id}"]`);
    if (!row) throw new Error(`no row for ${id}`);
    return row;
  });
}
