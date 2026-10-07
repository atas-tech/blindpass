// Same-origin fetch wrapper for the controller API.
//
// Session authority lives only in the controller's HttpOnly bp_session
// cookie. The CSRF secret is held in memory (from the session response)
// and mirrored by the readable bp_csrf cookie; nothing is written to
// localStorage or sessionStorage, and no credential enters a URL.

export type ApiErrorKind =
  | "unauthorized"
  | "password_change_required"
  | "forbidden"
  | "csrf"
  | "not_found"
  | "conflict"
  | "gone"
  | "invalid"
  | "too_large"
  | "rate_limited"
  | "locked"
  | "unavailable"
  | "timeout"
  | "network"
  | "server";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly kind: ApiErrorKind;
  readonly retryAfterSeconds: number | null;
  /** Validation issues the controller listed, as plain strings. */
  readonly issues: string[];

  constructor(status: number, code: string | null, message: string, retryAfterSeconds: number | null = null, issues: string[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
    this.issues = issues;
    this.kind = classify(status, code);
  }

  /** True when the request may have reached the controller and changed state. */
  get outcomeUnknown(): boolean {
    return this.kind === "network" || this.kind === "timeout" || this.status === 502 || this.status === 504;
  }
}

function classify(status: number, code: string | null): ApiErrorKind {
  if (status === 0) return code === "timeout" ? "timeout" : "network";
  if (status === 401) return "unauthorized";
  if (status === 403) {
    if (code === "password_change_required") return "password_change_required";
    if (code && /csrf|origin/.test(code)) return "csrf";
    return "forbidden";
  }
  if (status === 404) return "not_found";
  if (status === 408) return "timeout";
  if (status === 409 || status === 412) return "conflict";
  if (status === 410) return "gone";
  if (status === 400 || status === 422) return "invalid";
  if (status === 413) return "too_large";
  if (status === 423) return "locked";
  if (status === 429) return "rate_limited";
  if (status === 503) return "unavailable";
  return "server";
}

type Listener = (error: ApiError) => void;
const sessionListeners = new Set<Listener>();

/** Subscribe to authentication failures on authenticated requests. */
export function onSessionError(listener: Listener): () => void {
  sessionListeners.add(listener);
  return () => sessionListeners.delete(listener);
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  for (const part of document.cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=") || null;
  }
  return null;
}

function randomToken(bytes = 32): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return Array.from(buffer, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Login is double-submit protected before a session exists: the page sets a
 * random bp_csrf cookie and sends the same value in X-CSRF-Token. The
 * controller replaces the cookie with the session-bound secret on success.
 */
export function ensurePreSessionCsrf(): string {
  const existing = readCookie("bp_csrf");
  if (existing) return existing;
  const token = randomToken();
  const secure = location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `bp_csrf=${token}; Path=/; SameSite=Strict${secure}`;
  return token;
}

export function newIdempotencyKey(): string {
  return `console-${crypto.randomUUID()}`;
}

/** Offset between the controller's Date header and the local clock, in ms. */
let serverOffsetMs: number | null = null;

export function serverNow(): number {
  return Date.now() + (serverOffsetMs ?? 0);
}

export function hasServerClock(): boolean {
  return serverOffsetMs !== null;
}

function observeServerDate(response: Response, sentAt: number): void {
  const header = response.headers.get("date");
  if (!header) return;
  const serverMs = Date.parse(header);
  if (Number.isNaN(serverMs)) return;
  // The Date header has one-second resolution; assume the midpoint of the
  // round trip and keep the most conservative (latest) estimate.
  const midpoint = sentAt + (Date.now() - sentAt) / 2;
  const offset = serverMs + 500 - midpoint;
  serverOffsetMs = serverOffsetMs === null ? offset : Math.max(serverOffsetMs - 250, Math.min(serverOffsetMs + 250, offset));
}

export interface RequestOptions {
  query?: Record<string, string | number | undefined | null>;
  body?: unknown;
  idempotencyKey?: string;
  ifMatch?: number;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeoutMs?: number;
  /** False for bootstrap/login, whose 401 is a form error, not a lost session. */
  authenticated?: boolean;
  csrf?: "session" | "pre-session" | "none";
}

const DEFAULT_TIMEOUT_MS = 15_000;
/** P07 client bound: no request waits longer than 30 s in total, whatever a caller asks. */
const MAX_TIMEOUT_MS = 30_000;

export async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  const url = new URL(path, location.origin);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
  }

  const headers = new Headers(options.headers);
  headers.set("accept", "application/json");
  if (options.body !== undefined) headers.set("content-type", "application/json");
  const unsafe = method !== "GET" && method !== "HEAD";
  const csrfMode = options.csrf ?? (unsafe ? "session" : "none");
  if (csrfMode === "pre-session") headers.set("x-csrf-token", ensurePreSessionCsrf());
  if (csrfMode === "session") {
    const token = csrfToken ?? readCookie("bp_csrf");
    if (token) headers.set("x-csrf-token", token);
  }
  if (options.idempotencyKey) headers.set("idempotency-key", options.idempotencyKey);
  if (options.ifMatch !== undefined) headers.set("if-match", `"${options.ifMatch}"`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new DOMException("timeout", "TimeoutError")), Math.min(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS));
  const abortFromCaller = () => controller.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", abortFromCaller, { once: true });

  const sentAt = Date.now();
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    const timedOut = controller.signal.aborted;
    throw new ApiError(0, timedOut ? "timeout" : "network", timedOut ? "The controller did not answer in time." : "The controller could not be reached.");
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener("abort", abortFromCaller);
  }
  observeServerDate(response, sentAt);

  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let payload: unknown = undefined;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = undefined;
    }
  }

  if (!response.ok) {
    const body = (payload && typeof payload === "object" ? payload : {}) as Record<string, unknown>;
    const code = typeof body.error === "string" ? body.error : typeof body.code === "string" ? body.code : null;
    const message = typeof body.message === "string" ? body.message : response.statusText || "Request failed";
    const retryAfter = Number(response.headers.get("retry-after") ?? body.retry_after_seconds ?? body.retry_after);
    const issues = Array.isArray(body.issues) ? body.issues.filter((issue): issue is string => typeof issue === "string") : [];
    const error = new ApiError(response.status, code, message, Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null, issues);
    if (options.authenticated !== false && (error.kind === "unauthorized" || error.kind === "password_change_required")) {
      for (const listener of sessionListeners) listener(error);
    }
    throw error;
  }

  if (payload === undefined) {
    throw new ApiError(response.status, "invalid_response", "The controller returned an unreadable response.");
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string, options?: RequestOptions) => request<T>("GET", path, options),
  post: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("POST", path, { ...options, body }),
  put: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("PUT", path, { ...options, body }),
  patch: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("PATCH", path, { ...options, body }),
  delete: <T>(path: string, options?: RequestOptions) => request<T>("DELETE", path, options)
};
