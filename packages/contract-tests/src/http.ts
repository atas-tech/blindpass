import { request as nodeRequest } from "node:http";

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

/**
 * Declares a request body of `declaredBytes` without sending it and reads the early rejection. A server may answer an
 * over-limit Content-Length before the body arrives and close the connection, so a client that streams the whole body
 * races that close and sees EPIPE/ECONNRESET under load. Declaring the length keeps the check deterministic.
 */
export async function httpRejectedBeforeBody<T = unknown>(
  baseUrl: string,
  path: string,
  init: RequestInit,
  declaredBytes: number
): Promise<HttpResult<T>> {
  const headers = Object.fromEntries(new Headers(init.headers));
  headers["content-length"] = String(declaredBytes);
  const url = new URL(`${baseUrl.replace(/\/$/, "")}${path}`);
  return new Promise<HttpResult<T>>((resolve, reject) => {
    const req = nodeRequest(url, { method: init.method ?? "POST", headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("error", reject);
      response.on("end", () => {
        req.destroy();
        const responseHeaders = new Headers();
        for (const [name, value] of Object.entries(response.headers)) {
          if (Array.isArray(value)) value.forEach((entry) => responseHeaders.append(name, entry));
          else if (value !== undefined) responseHeaders.set(name, value);
        }
        const text = Buffer.concat(chunks).toString("utf8");
        const contentType = responseHeaders.get("content-type");
        let body: T | null = null;
        if (text && contentType?.toLowerCase().includes("json")) {
          try {
            body = JSON.parse(text) as T;
          } catch {
            body = null;
          }
        }
        resolve({ status: response.statusCode ?? 0, contentType, headers: responseHeaders, body, text });
      });
    });
    req.on("error", reject);
    req.flushHeaders();
  });
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
