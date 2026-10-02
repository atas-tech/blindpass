import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axeViolations } from "../../test/axe.js";
import { fakeController, json, renderRoute, type Call } from "../../test/controller.js";
import { inputPageUrl, provisioningKey } from "./provide-source.js";

// The operator-facing Source provisioning panel (P05-PV06-S GUI portion). The
// link below is a generated dummy: the tests prove it never reaches the DOM, a
// log or storage, and is used exactly once, by window.open.
const LINK_ID = "d".repeat(64);
const META_SIG = `1900000100.${"M".repeat(43)}`;
const SUBMIT_SIG = `1900000100.${"S".repeat(43)}`;
const INPUT_PATH = `/?kind=fleet&id=${LINK_ID}&metadata_sig=${META_SIG}&submit_sig=${SUBMIT_SIG}`;

type State = "not_applicable" | "awaiting_offer" | "offer_ready" | "link_issued" | "submitted" | "expired";

function provisioning(state: State, canProvide = false, offerEndsInMs: number | null = null) {
  return { state, offer_expires_at_ms: offerEndsInMs === null ? null : Date.now() + offerEndsInMs, can_provide: canProvide };
}

function operation(provision: unknown, overrides: Record<string, unknown> = {}) {
  return {
    id: "op_1",
    workload_id: "wl_1",
    node_id: "nd_1",
    action: "browser.session",
    mode: "browser_session",
    purpose: "read approved report",
    resource_id: "report-primary",
    policy_version: 1,
    decision: "pending_approval",
    status: "granted",
    approval_id: "oa_1",
    grant_id: "gr_1",
    result: null,
    created_at: Date.now() - 60_000,
    expires_at: Date.now() + 60_000,
    completed_at: null,
    version: 2,
    ...(provision === undefined ? {} : { provisioning: provision }),
    ...overrides
  };
}

function link(overrides: Record<string, unknown> = {}) {
  return { id: LINK_ID, metadata_sig: META_SIG, submit_sig: SUBMIT_SIG, operator_id: "op_ada", operation_id: "op_1", expires_at_ms: Date.now() + 25_000, input_path: INPUT_PATH, ...overrides };
}

function serve(body: unknown, linkReply?: (call: Call) => Response | undefined, role: "admin" | "operator" | "viewer" = "operator") {
  return fakeController({
    role,
    handler: (call) => {
      if (call.path === "/api/v3/operations/op_1" && call.method === "GET") return json(200, body);
      if (call.path === "/api/v3/admin/operations/op_1/provisioning-link") return linkReply?.(call) ?? json(201, link());
      return undefined;
    }
  });
}

const linkCalls = (calls: Call[]) => calls.filter((call) => call.path === "/api/v3/admin/operations/op_1/provisioning-link");
const detailReads = (calls: Call[]) => calls.filter((call) => call.path === "/api/v3/operations/op_1" && call.method === "GET");

async function panel() {
  const heading = await screen.findByRole("heading", { name: "Provide Source" });
  return heading.closest("section") as HTMLElement;
}

describe("provide source panel", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("P05-PV06-S GUI: an operation with no provisioning state, or one that is not applicable, has no panel", async () => {
    for (const body of [operation(undefined, { action: "noop.marker", mode: "file" }), operation(provisioning("not_applicable"))]) {
      serve(body);
      const { unmount } = renderRoute("/operations/op_1");
      expect(await screen.findByRole("heading", { level: 1 })).toBeTruthy();
      expect(screen.queryByRole("heading", { name: "Provide Source" })).toBeNull();
      expect(screen.queryByRole("button", { name: /Source/ })).toBeNull();
      unmount();
    }
  });

  it("P05-PV06-S GUI: awaiting the node's offer shows a waiting status, no button, and re-reads the operation on its own", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"], shouldAdvanceTime: true });
    try {
      const { calls } = serve(operation(provisioning("awaiting_offer")));
      renderRoute("/operations/op_1");
      const section = await panel();
      expect(within(section).getByRole("status").textContent).toMatch(/Waiting for the node/);
      expect(within(section).queryByRole("button")).toBeNull();
      const before = detailReads(calls).length;
      // Step the clock until the next read. While a Source offer is awaited the
      // page re-reads every 3 s, well inside the 10 s ordinary fleet cadence.
      let elapsed = 0;
      while (detailReads(calls).length === before && elapsed < 9_500) {
        await act(async () => {
          await vi.advanceTimersByTimeAsync(500);
        });
        elapsed += 500;
        await waitFor(() => undefined);
      }
      expect(detailReads(calls).length).toBeGreaterThan(before);
      expect(elapsed).toBeLessThanOrEqual(4_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it("P05-PV06-S GUI: for the named owner a live offer shows the remaining time and one labelled button, and the click opens the link once without exposing it", async () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    const logged = [vi.spyOn(console, "log"), vi.spyOn(console, "info"), vi.spyOn(console, "warn"), vi.spyOn(console, "error"), vi.spyOn(console, "debug")];
    const { calls } = serve(operation(provisioning("offer_ready", true, 25_000)));
    const user = userEvent.setup();
    const { container } = renderRoute("/operations/op_1");
    const section = await panel();
    expect(section.querySelector(".countdown")).toBeTruthy();
    expect(within(section).getByText(/The offer ends in/)).toBeTruthy();
    const button = within(section).getByRole("button", { name: "Provide Source" });
    expect(await axeViolations(container)).toEqual([]);
    await user.click(button);
    await waitFor(() => expect(open).toHaveBeenCalledTimes(1));
    expect(open).toHaveBeenCalledWith(new URL(INPUT_PATH, window.location.origin).toString(), "_blank", "noopener,noreferrer");
    const post = linkCalls(calls);
    expect(post).toHaveLength(1);
    expect(post[0]!.method).toBe("POST");
    expect(post[0]!.headers.get("idempotency-key")).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
    expect(post[0]!.headers.get("x-csrf-token")).toBeTruthy();
    expect(post[0]!.body).toBeUndefined();
    // The link was only ever the argument of window.open.
    for (const text of [document.body.innerHTML, document.body.textContent ?? "", JSON.stringify({ ...window.localStorage }), JSON.stringify({ ...window.sessionStorage }), window.location.href]) {
      for (const secret of [LINK_ID, META_SIG, SUBMIT_SIG, "kind=fleet", "metadata_sig"]) expect(text).not.toContain(secret);
    }
    for (const spy of logged) {
      for (const call of spy.mock.calls) expect(JSON.stringify(call)).not.toMatch(/metadata_sig|submit_sig|kind=fleet/);
    }
    expect(section.querySelector("a[href]")).toBeNull();
  });

  it("P05-PV06-S GUI: reopening after a link was issued retries idempotently with the same per-operation key", async () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    const { calls } = serve(operation(provisioning("link_issued", true, 20_000)), (call) => (linkCalls([call]).length ? json(200, link()) : undefined));
    const user = userEvent.setup();
    renderRoute("/operations/op_1");
    const section = await panel();
    expect(within(section).queryByRole("button", { name: "Provide Source" })).toBeNull();
    const again = within(section).getByRole("button", { name: "Open the Source page again" });
    await user.click(again);
    await waitFor(() => expect(open).toHaveBeenCalledTimes(1));
    await user.click(again);
    await waitFor(() => expect(open).toHaveBeenCalledTimes(2));
    const keys = linkCalls(calls).map((call) => call.headers.get("idempotency-key"));
    expect(keys).toHaveLength(2);
    expect(new Set(keys).size).toBe(1);
    // A different operation gets a different key, so keys can never collide across operations.
    expect(keys[0]).toContain("op_1");
  });

  it("P05-PV06-S GUI: a viewer-level or non-owner operator sees the state and why there is no button", async () => {
    serve(operation(provisioning("offer_ready", false, 25_000)));
    renderRoute("/operations/op_1");
    const section = await panel();
    expect(within(section).queryByRole("button")).toBeNull();
    expect(within(section).getByText(/Only the operator who approved this request/)).toBeTruthy();
    expect(within(section).getByText(/The offer ends in/)).toBeTruthy();
  });

  it("P05-PV06-S GUI: viewers can't open operations at all, so no state or button is requested for them", async () => {
    const { calls } = serve(operation(provisioning("offer_ready", true, 25_000)), undefined, "viewer");
    renderRoute("/operations/op_1");
    expect(await screen.findByRole("heading", { name: "Your role can't open this page" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Source/ })).toBeNull();
    expect(calls.some((call) => call.path.startsWith("/api/v3/operations") || call.path.includes("provisioning"))).toBe(false);
  });

  it("P05-PV06-S GUI: after submission the panel confirms receipt with no secret and no button; expiry says to request a new operation", async () => {
    serve(operation(provisioning("submitted")));
    const { unmount } = renderRoute("/operations/op_1");
    let section = await panel();
    expect(within(section).getByText(/encrypted Source was received/)).toBeTruthy();
    expect(within(section).queryByRole("button")).toBeNull();
    unmount();

    serve(operation(provisioning("expired", false)));
    renderRoute("/operations/op_1");
    section = await panel();
    expect(within(section).getByText(/Request a new operation/)).toBeTruthy();
    expect(within(section).queryByRole("button")).toBeNull();
  });

  it.each([
    [409, "provisioning_offer_pending", /hasn't published its offer yet/],
    [403, "provisioning_owner_required", /Only the operator who approved/],
    [410, "provisioning_unavailable", /no longer available/],
    [409, "provisioning_link_conflict", /already exists/],
    [500, "internal", /couldn't open the Source page/]
  ])("P05-PV06-S GUI: a %s %s answer is a fixed message, re-reads the state and opens nothing", async (status, code, message) => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    const { calls } = serve(operation(provisioning("offer_ready", true, 25_000)), () => json(status, { error: code, message: `server text ${META_SIG}` }));
    const user = userEvent.setup();
    renderRoute("/operations/op_1");
    const section = await panel();
    const reads = detailReads(calls).length;
    await user.click(within(section).getByRole("button", { name: "Provide Source" }));
    const notice = await within(section).findByText(message);
    expect(notice).toBeTruthy();
    expect(open).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain(META_SIG);
    await waitFor(() => expect(detailReads(calls).length).toBeGreaterThan(reads));
  });

  it("P05-PV06-S GUI: a lost reply says the retry is safe and the same key makes it so", async () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    let attempts = 0;
    const { calls } = fakeController({
      handler: (call) => {
        if (call.path === "/api/v3/operations/op_1") return json(200, operation(provisioning("offer_ready", true, 25_000)));
        if (call.path === "/api/v3/admin/operations/op_1/provisioning-link") {
          attempts += 1;
          return attempts === 1 ? Promise.reject(new TypeError("network")) : json(200, link());
        }
        return undefined;
      }
    });
    const user = userEvent.setup();
    renderRoute("/operations/op_1");
    const section = await panel();
    await user.click(within(section).getByRole("button", { name: "Provide Source" }));
    expect(await within(section).findByText(/Press the button again/)).toBeTruthy();
    expect(open).not.toHaveBeenCalled();
    await user.click(within(section).getByRole("button", { name: "Provide Source" }));
    await waitFor(() => expect(open).toHaveBeenCalledTimes(1));
    const keys = linkCalls(calls).map((call) => call.headers.get("idempotency-key"));
    expect(keys[0]).toBe(keys[1]);
  });

  it("P05-PV06-S GUI: a link that isn't the fixed same-origin fleet path is never opened", async () => {
    for (const path of ["https://attacker.example/?kind=fleet&id=x", "//attacker.example/", "/login", "javascript:alert(1)", `/?kind=other&id=${LINK_ID}`]) {
      const open = vi.spyOn(window, "open").mockReturnValue(null);
      serve(operation(provisioning("offer_ready", true, 25_000)), () => json(201, link({ input_path: path })));
      const user = userEvent.setup();
      const { unmount } = renderRoute("/operations/op_1");
      const section = await panel();
      await user.click(within(section).getByRole("button", { name: "Provide Source" }));
      expect(await within(section).findByText(/couldn't open the Source page/)).toBeTruthy();
      expect(open).not.toHaveBeenCalled();
      unmount();
      vi.restoreAllMocks();
    }
  });

  it("P05-PV06-S GUI: every state of the panel passes axe", async () => {
    for (const body of [provisioning("awaiting_offer"), provisioning("offer_ready", false, 20_000), provisioning("link_issued", true, 20_000), provisioning("submitted"), provisioning("expired")]) {
      serve(operation(body));
      const { container, unmount } = renderRoute("/operations/op_1");
      await panel();
      expect(await axeViolations(container)).toEqual([]);
      unmount();
    }
  });

  it("P05-PV06-S GUI: the idempotency key is stable per operation, fits the controller's limit and never collides across operations", async () => {
    const key = await provisioningKey("op_1");
    expect(key).toBe("console-source-op_1");
    expect(await provisioningKey("op_1")).toBe(key);
    expect(await provisioningKey("op_2")).not.toBe(key);
    const long = `op_${"x".repeat(125)}`;
    const hashed = await provisioningKey(long);
    expect(hashed).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
    expect(await provisioningKey(long)).toBe(hashed);
    expect(await provisioningKey(`${long}y`)).not.toBe(hashed);
  });

  it("P05-PV06-S GUI: only the exact same-origin fleet input path is accepted", () => {
    expect(inputPageUrl(INPUT_PATH, "http://console.test")).toBe(`http://console.test${INPUT_PATH}`);
    for (const bad of [null, 7, "", "/", "/?kind=fleet", `${INPUT_PATH}&extra=1`, `${INPUT_PATH}#frag`, `/?kind=fleet&id=${LINK_ID}&id=${LINK_ID}&metadata_sig=a&submit_sig=b`, `/x?kind=fleet&id=${LINK_ID}&metadata_sig=a&submit_sig=b`, `//evil.example${INPUT_PATH}`, `https://evil.example${INPUT_PATH}`]) {
      expect(inputPageUrl(bad, "http://console.test"), String(bad)).toBeNull();
    }
  });
});
