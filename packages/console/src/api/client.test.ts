import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, ensurePreSessionCsrf, hasServerClock, newIdempotencyKey, onSessionError, serverNow, setCsrfToken } from "./client.js";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers }
  });
}

describe("controller client", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken(null);
    document.cookie = "bp_csrf=; Max-Age=0; Path=/";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends same-origin credentials, no-store and never puts a credential in the URL", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { items: [], next_cursor: null }));
    setCsrfToken("csrf-secret-value");
    await api.get("/api/v3/admin/agents", { query: { cursor: "c1", limit: 10, empty: "" } });
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.pathname).toBe("/api/v3/admin/agents");
    expect(url.search).toBe("?cursor=c1&limit=10");
    expect(url.href).not.toContain("csrf-secret-value");
    expect(init.credentials).toBe("same-origin");
    expect(init.cache).toBe("no-store");
    // Reads carry no CSRF header.
    expect(new Headers(init.headers).has("x-csrf-token")).toBe(false);
  });

  it("adds the session CSRF secret, Idempotency-Key and quoted If-Match to writes", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { ok: true }));
    setCsrfToken("session-csrf");
    await api.put("/api/v3/policies", { rules: [] }, { idempotencyKey: "console-key-0000000001", ifMatch: 7 });
    const headers = new Headers((fetchMock.mock.calls[0] as [URL, RequestInit])[1].headers);
    expect(headers.get("x-csrf-token")).toBe("session-csrf");
    expect(headers.get("idempotency-key")).toBe("console-key-0000000001");
    expect(headers.get("if-match")).toBe('"7"');
    expect(headers.get("content-type")).toBe("application/json");
  });

  it("double-submits a random pre-session CSRF cookie for login", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, {}));
    await api.post("/api/v3/admin/session/login", { username: "a", password: "b" }, { csrf: "pre-session", authenticated: false });
    const headers = new Headers((fetchMock.mock.calls[0] as [URL, RequestInit])[1].headers);
    const token = headers.get("x-csrf-token");
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    expect(document.cookie).toContain(`bp_csrf=${token}`);
    expect(ensurePreSessionCsrf()).toBe(token);
  });

  it("classifies controller errors without inventing outcomes", async () => {
    const cases: Array<[number, string | undefined, ApiError["kind"]]> = [
      [401, "session_expired", "unauthorized"],
      [403, "password_change_required", "password_change_required"],
      [403, "csrf_or_origin_denied", "csrf"],
      [403, "role_denied", "forbidden"],
      [404, "not_found", "not_found"],
      [409, "stale", "conflict"],
      [410, "gone", "gone"],
      [400, "invalid_request", "invalid"],
      [429, "rate_limited", "rate_limited"],
      [503, "not_ready", "unavailable"],
      [500, undefined, "server"]
    ];
    for (const [status, code, kind] of cases) {
      fetchMock.mockResolvedValueOnce(jsonResponse(status, code ? { error: code, message: "m" } : { oops: true }));
      const error = await api.get("/api/v3/x", { authenticated: false }).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).kind).toBe(kind);
      expect((error as ApiError).code).toBe(code ?? null);
    }
  });

  it("reports a network failure and a timeout as unknown outcomes, not empty data", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    const network = (await api.post("/api/v3/admin/approvals/r/approve", {}).catch((caught: unknown) => caught)) as ApiError;
    expect(network.kind).toBe("network");
    expect(network.outcomeUnknown).toBe(true);

    fetchMock.mockImplementationOnce((_url: URL, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    }));
    const timeout = (await api.get("/api/v3/nodes", { timeoutMs: 20 }).catch((caught: unknown) => caught)) as ApiError;
    expect(timeout.kind).toBe("timeout");
    expect(timeout.outcomeUnknown).toBe(true);
  });

  it("notifies session listeners on 401 from authenticated calls only", async () => {
    const listener = vi.fn();
    const unsubscribe = onSessionError(listener);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { error: "session_required" }));
    await api.get("/api/v3/nodes").catch(() => undefined);
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { error: "invalid_credentials" }));
    await api.post("/api/v3/admin/session/login", {}, { authenticated: false }).catch(() => undefined);
    unsubscribe();
    expect(listener).toHaveBeenCalledTimes(1);
    expect(listener.mock.calls[0]?.[0]).toMatchObject({ kind: "unauthorized", code: "session_required" });
  });

  it("carries Retry-After on rate limits", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(429, { error: "rate_limited" }, { "retry-after": "12" }));
    const error = (await api.get("/api/v3/nodes").catch((caught: unknown) => caught)) as ApiError;
    expect(error.retryAfterSeconds).toBe(12);
  });

  it("corrects its clock from the controller Date header", async () => {
    const ahead = new Date(Date.now() + 120_000).toUTCString();
    fetchMock.mockResolvedValueOnce(jsonResponse(200, {}, { date: ahead }));
    await api.get("/api/v3/capabilities", { authenticated: false });
    expect(hasServerClock()).toBe(true);
    expect(serverNow() - Date.now()).toBeGreaterThan(110_000);
  });

  it("rejects an unreadable success body instead of treating it as data", async () => {
    fetchMock.mockResolvedValueOnce(new Response("<html>proxy error</html>", { status: 200 }));
    const error = (await api.get("/api/v3/nodes").catch((caught: unknown) => caught)) as ApiError;
    expect(error.code).toBe("invalid_response");
  });

  it("mints idempotency keys inside the controller's 16–128 character bound", () => {
    const key = newIdempotencyKey();
    expect(key.length).toBeGreaterThanOrEqual(16);
    expect(key.length).toBeLessThanOrEqual(128);
    expect(newIdempotencyKey()).not.toBe(key);
  });
});

describe("controller client bounds (P07 client timeouts)", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  function hangUntilAborted() {
    const fetchMock = vi.fn((_url: URL, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    }));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("gives up on a silent controller after the default budget, inside the 30 s total bound", async () => {
    vi.useFakeTimers();
    hangUntilAborted();
    const result = api.get("/api/v3/nodes").catch((caught: unknown) => caught);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(((await result) as ApiError).kind).toBe("timeout");
  });

  it("clamps a longer per-call timeout to 30 s", async () => {
    vi.useFakeTimers();
    hangUntilAborted();
    const result = api.get("/api/v3/nodes", { timeoutMs: 600_000 }).catch((caught: unknown) => caught);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(((await result) as ApiError).kind).toBe("timeout");
  });

  it("classifies a 423 lock as its own kind and carries the wait", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(423, { error: "locked", retry_after: 840 }, { "retry-after": "840" })));
    const locked = (await api.post("/api/v3/admin/session/login", {}, { authenticated: false }).catch((caught: unknown) => caught)) as ApiError;
    expect(locked.kind).toBe("locked");
    expect(locked.status).toBe(423);
    expect(locked.retryAfterSeconds).toBe(840);
    expect(locked.outcomeUnknown).toBe(false);
  });
});
