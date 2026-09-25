import { describe, expect, it, vi } from "vitest";
import { GatewaySpsClient } from "../src/sps-client.js";
import { RequestSecretInterceptor, createRequestSecretInterceptor } from "../src/interceptor.js";

describe("interceptor", () => {
  it("surfaces request rate limits without retrying", async () => {
    const fetchImpl = vi.fn(async () => new Response("rate limited", {
      status: 429,
      headers: { "retry-after": "60" }
    }));
    const client = new GatewaySpsClient({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "gateway-token",
      fetchImpl
    });

    await expect(client.createSecretRequest({ description: "API key", publicKey: "cHVi" }))
      .rejects.toThrow("SPS request failed with status 429");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("creates SPS request, notifies chat, and returns non-sensitive response", async () => {
    const fetchImpl: typeof fetch = vi.fn(async (input, init) => {
      expect(String(input)).toBe("http://localhost:3100/api/v2/secret/request");
      expect(init?.method).toBe("POST");
      expect((init?.headers as Record<string, string>).authorization).toBe("Bearer gateway-token");
      const body = JSON.parse(String(init?.body));
      expect(body.public_key).toBe("cHVi");
      expect(body.description).toBe("API key for Stripe");

      return new Response(
        JSON.stringify({
          request_id: "req-123",
          confirmation_code: "BLUE-FOX-42",
          secret_url: "https://secrets.local/r/req-123?metadata_sig=x&submit_sig=y"
        }),
        { status: 201, headers: { "content-type": "application/json" } }
      );
    });

    const chatAdapter = {
      sendMessage: vi.fn(async () => undefined)
    };

    const spsClient = new GatewaySpsClient({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "gateway-token",
      fetchImpl
    });

    const interceptor = new RequestSecretInterceptor({
      spsClient,
      chatAdapter
    });

    const response = await interceptor.interceptToolCall("request_secret", {
      description: "API key for Stripe",
      public_key: "cHVi",
      channel_id: "telegram:chat-1"
    });

    expect(response).toEqual({
      status: "secret_request_pending",
      request_id: "req-123"
    });

    const sentMessage = (chatAdapter.sendMessage as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
    expect(sentMessage).toContain("BLUE-FOX-42");
    expect(sentMessage).toContain("https://secrets.local/r/req-123");
    expect(JSON.stringify(response)).not.toContain("BLUE-FOX-42");
    expect(JSON.stringify(response)).not.toContain("https://");
  });

  it("returns null for unrelated tool calls", async () => {
    const interceptor = createRequestSecretInterceptor({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "token",
      fetchImpl: vi.fn(async () => new Response("{}", { status: 200 })),
      chatAdapter: {
        sendMessage: vi.fn(async () => undefined)
      }
    });

    await expect(interceptor.interceptToolCall("other_tool", {})).resolves.toBeNull();
  });

  it("throws for malformed request_secret input", async () => {
    const interceptor = createRequestSecretInterceptor({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "token",
      fetchImpl: vi.fn(async () => new Response("{}", { status: 200 })),
      chatAdapter: {
        sendMessage: vi.fn(async () => undefined)
      }
    });

    await expect(interceptor.interceptToolCall("request_secret", { description: "x" })).rejects.toThrow(
      "request_secret requires description, public_key, and channel_id"
    );
  });

  it("throws for invalid field sizes and formats", async () => {
    const interceptor = createRequestSecretInterceptor({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "token",
      fetchImpl: vi.fn(async () => new Response("{}", { status: 200 })),
      chatAdapter: {
        sendMessage: vi.fn(async () => undefined)
      }
    });

    await expect(
      interceptor.interceptToolCall("request_secret", {
        description: "x".repeat(513),
        public_key: "cHVi",
        channel_id: "demo"
      })
    ).rejects.toThrow("request_secret.description must be 1-512 characters");

    await expect(
      interceptor.interceptToolCall("request_secret", {
        description: "ok",
        public_key: "not-base64***",
        channel_id: "demo"
      })
    ).rejects.toThrow("request_secret.public_key must be base64 and 4-2048 characters");
  });
});
