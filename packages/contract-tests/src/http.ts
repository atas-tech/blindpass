export interface HttpResult<T = unknown> {
  status: number;
  contentType: string | null;
  headers: Headers;
  body: T | null;
  text: string;
}

export async function httpRequest<T = unknown>(
  baseUrl: string,
  path: string,
  init: RequestInit = {}
): Promise<HttpResult<T>> {
  const response = await fetch(`${baseUrl.replace(/\/$/, "")}${path}`, init);
  const text = await response.text();
  const contentType = response.headers.get("content-type");
  let body: T | null = null;

  if (text && contentType?.toLowerCase().includes("json")) {
    try {
      body = JSON.parse(text) as T;
    } catch {
      body = null;
    }
  }

  return {
    status: response.status,
    contentType,
    headers: response.headers,
    body,
    text
  };
}

export function jsonRequestBody(value: unknown): RequestInit {
  return {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(value)
  };
}

export function withBearer(token: string, init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${token}`);
  return {
    ...init,
    headers
  };
}

export function withOrigin(origin: string, init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  headers.set("origin", origin);
  return {
    ...init,
    headers
  };
}

export async function waitForHttp(baseUrl: string, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl.replace(/\/$/, "")}/healthz`);
      if (response.ok) {
        return;
      }
      lastError = new Error(`healthz returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }

    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw new Error(`Timed out waiting for ${baseUrl}/healthz: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
}
