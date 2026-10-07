import { describe, expect, it } from "vitest";
import { SpsClient } from "../src/sps-client.js";

describe("SpsClient", () => {
  it("surfaces request and exchange rate limits without retrying", async () => {
    const requestedUrls: string[] = [];
    const fetchImpl: typeof fetch = async (input) => {
      requestedUrls.push(String(input));
      return new Response("rate limited", { status: 429, headers: { "retry-after": "60" } });
    };
    const client = new SpsClient({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "token",
      fetchImpl
    });

    await expect(client.requestSecret({ description: "API key", publicKey: "pub" }))
      .rejects.toThrow("SPS request failed with status 429");
    await expect(client.createExchangeRequest({
      publicKey: "pub",
      secretName: "stripe.api_key",
      purpose: "production deployment",
      fulfillerHint: "deployer"
    })).rejects.toThrow("SPS exchange request failed with status 429");

    expect(requestedUrls).toEqual([
      "http://localhost:3100/api/v2/secret/request",
      "http://localhost:3100/api/v2/secret/exchange/request"
    ]);
  });

  it("requests and polls until submitted", async () => {
    let statusCalls = 0;
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith("/api/v2/secret/request")) {
        return new Response(
          JSON.stringify({
            request_id: "req-1",
            confirmation_code: "BLUE-FOX-42",
            secret_url: "http://localhost/r/req-1"
          }),
          { status: 201, headers: { "content-type": "application/json" } }
        );
      }

      if (url.endsWith("/api/v2/secret/status/req-1")) {
        statusCalls += 1;
        const status = statusCalls < 2 ? "pending" : "submitted";
        return new Response(JSON.stringify({ status }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }

      if (url.endsWith("/api/v2/secret/retrieve/req-1")) {
        return new Response(
          JSON.stringify({
            enc: "enc",
            ciphertext: "ct"
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }

      return new Response("not found", { status: 404 });
    };

    const client = new SpsClient({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "token",
      fetchImpl
    });

    const request = await client.requestSecret({
      description: "API key",
      publicKey: "pub"
    });

    expect(request.requestId).toBe("req-1");

    const poll = await client.pollStatus("req-1", 1, 1000, 500);
    expect(poll.status).toBe("submitted");

    const retrieved = await client.retrieveSecret("req-1");
    expect(retrieved).toEqual({ enc: "enc", ciphertext: "ct" });
  });

  it("times out when never submitted", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("/status/")) {
        return new Response(JSON.stringify({ status: "pending" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
      return new Response("not found", { status: 404 });
    };

    const client = new SpsClient({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "token",
      fetchImpl
    });

    await expect(client.pollStatus("req-timeout", 1, 5, 5)).rejects.toThrow(
      "User did not provide the secret in time"
    );
  });

  it("supports exchange request / status / retrieve", async () => {
    let statusCalls = 0;
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith("/api/v2/secret/exchange/request")) {
        return new Response(
          JSON.stringify({
            exchange_id: "ex-1",
            status: "pending",
            expires_at: 123456,
            fulfillment_token: "token-1"
          }),
          { status: 201, headers: { "content-type": "application/json" } }
        );
      }

      if (url.endsWith("/api/v2/secret/exchange/status/ex-1")) {
        statusCalls += 1;
        const status = statusCalls < 2 ? "pending" : "submitted";
        return new Response(JSON.stringify({ status }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }

      if (url.endsWith("/api/v2/secret/exchange/retrieve/ex-1")) {
        return new Response(
          JSON.stringify({
            enc: "enc",
            ciphertext: "ct",
            secret_name: "stripe.api_key.prod",
            fulfilled_by: "agent:payment-bot"
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }

      return new Response("not found", { status: 404 });
    };

    const client = new SpsClient({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "token",
      fetchImpl
    });

    const created = await client.createExchangeRequest({
      publicKey: "pub",
      secretName: "stripe.api_key.prod",
      purpose: "charge-order",
      fulfillerHint: "agent:payment-bot"
    });
    expect(created.exchangeId).toBe("ex-1");

    const poll = await client.pollExchangeStatus("ex-1", 1, 1000, 100);
    expect(poll.status).toBe("submitted");

    const retrieved = await client.retrieveExchange("ex-1");
    expect(retrieved).toEqual({
      enc: "enc",
      ciphertext: "ct",
      secretName: "stripe.api_key.prod",
      fulfilledBy: "agent:payment-bot"
    });
  });

  it("fails fast when exchange stays reserved too long", async () => {
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url.includes("/api/v2/secret/exchange/status/")) {
        return new Response(JSON.stringify({ status: "reserved" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }

      if (url.includes("/api/v2/secret/exchange/revoke/")) {
        return new Response(JSON.stringify({ status: "revoked" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }

      return new Response("not found", { status: 404 });
    };

    const client = new SpsClient({
      baseUrl: "http://localhost:3100",
      gatewayBearerToken: "token",
      fetchImpl
    });

    await expect(client.pollExchangeStatus("ex-stalled", 1, 1000, 5)).rejects.toThrow(
      "did not complete the exchange in time"
    );
  });

  it("treats a 402 as an ordinary failed exchange request and never retries it", async () => {
    const seen: Array<{ path: string; paymentHeaders: boolean }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      seen.push({
        path: new URL(String(input)).pathname,
        paymentHeaders: headers.has("payment-identifier") || headers.has("payment-signature")
      });
      return new Response(JSON.stringify({ error: "payment required" }), {
        status: 402,
        headers: { "content-type": "application/json", "payment-required": "ignored" }
      });
    };
    const client = new SpsClient({ baseUrl: "https://sps.example", gatewayBearerToken: "token", fetchImpl });

    await expect(client.createExchangeRequest({
      publicKey: "pub",
      secretName: "stripe.api_key.prod",
      purpose: "charge-order",
      fulfillerHint: "agent:payment-bot"
    })).rejects.toThrow("SPS exchange request failed with status 402");

    expect(seen).toEqual([{ path: "/api/v2/secret/exchange/request", paymentHeaders: false }]);
  });

  describe("Automatic Authentication & Refresh", () => {
    it("performs lazy authentication on the first request", async () => {
      let tokenMinted = false;
      const fetchImpl: typeof fetch = async (input) => {
        const url = String(input);
        if (url.endsWith("/api/v2/agents/token")) {
          tokenMinted = true;
          return new Response(JSON.stringify({
            access_token: "jwt-1",
            access_token_expires_at: new Date(Date.now() + 3600000).toISOString(),
            agent: { id: "a1", workspace_id: "w1", agent_id: "agent-1", status: "active", created_at: new Date().toISOString() }
          }), { status: 200, headers: { "content-type": "application/json" } });
        }
        if (url.endsWith("/api/v2/secret/request")) {
          return new Response(JSON.stringify({ request_id: "r1" }), { status: 201, headers: { "content-type": "application/json" } });
        }
        return new Response("not found", { status: 404 });
      };

      const client = new SpsClient({
        baseUrl: "http://localhost:3100",
        bootstrapApiKey: "bootstrap-1",
        fetchImpl
      });

      expect(tokenMinted).toBe(false);
      await client.requestSecret({ description: "x", publicKey: "p" });
      expect(tokenMinted).toBe(true);
    });

    it("proactively refreshes token before expiry", async () => {
      let mintCount = 0;
      const fetchImpl: typeof fetch = async (input) => {
        const url = String(input);
        if (url.endsWith("/api/v2/agents/token")) {
          mintCount++;
          const expiresAt = mintCount === 1 
            ? new Date(Date.now() + 30000).toISOString() // Expires in 30s (within 60s threshold)
            : new Date(Date.now() + 3600000).toISOString();
          return new Response(JSON.stringify({
            access_token: `jwt-${mintCount}`,
            access_token_expires_at: expiresAt,
            agent: { id: "a1" }
          }), { status: 200, headers: { "content-type": "application/json" } });
        }
        if (url.endsWith("/api/v2/secret/request")) {
          return new Response(JSON.stringify({ request_id: "r1" }), { status: 201, headers: { "content-type": "application/json" } });
        }
        return new Response("not found", { status: 404 });
      };

      const client = new SpsClient({
        baseUrl: "http://localhost:3100",
        bootstrapApiKey: "bootstrap-1",
        fetchImpl
      });

      await client.requestSecret({ description: "x", publicKey: "p" });
      expect(mintCount).toBe(1);

      // Second call should trigger another mint because the first one is within threshold
      await client.requestSecret({ description: "x", publicKey: "p" });
      expect(mintCount).toBe(2);
    });

    it("retries on 401 by refreshing token", async () => {
      let mintCount = 0;
      let requestCount = 0;
      const fetchImpl: typeof fetch = async (input, init) => {
        const url = String(input);
        if (url.endsWith("/api/v2/agents/token")) {
          mintCount++;
          return new Response(JSON.stringify({
            access_token: `jwt-${mintCount}`,
            access_token_expires_at: new Date(Date.now() + 3600000).toISOString()
          }), { status: 200 });
        }
        if (url.endsWith("/api/v2/secret/request")) {
          requestCount++;
          const auth = (init?.headers as any)?.authorization || (init?.headers as Headers).get("authorization");
          if (auth === "Bearer jwt-1") {
            return new Response("unauthorized", { status: 401 });
          }
          return new Response(JSON.stringify({ request_id: "r1" }), { status: 201 });
        }
        return new Response("not found", { status: 404 });
      };

      const client = new SpsClient({
        baseUrl: "http://localhost:3100",
        bootstrapApiKey: "bootstrap-1",
        fetchImpl
      });

      await client.requestSecret({ description: "x", publicKey: "p" });
      expect(mintCount).toBe(2); // Initial mint + refresh after 401
      expect(requestCount).toBe(2); // Failed attempt + retry
    });

    it("prevents concurrent token minting", async () => {
      let mintCount = 0;
      const fetchImpl: typeof fetch = async (input) => {
        if (String(input).endsWith("/api/v2/agents/token")) {
          mintCount++;
          await new Promise(r => setTimeout(r, 10)); // Artificial delay
          return new Response(JSON.stringify({
            access_token: "jwt-1",
            access_token_expires_at: new Date(Date.now() + 3600000).toISOString()
          }), { status: 200 });
        }
        return new Response(JSON.stringify({}), { status: 200 });
      };

      const client = new SpsClient({
        baseUrl: "http://localhost:3100",
        bootstrapApiKey: "bootstrap-1",
        fetchImpl
      });

      // Fire multiple requests simultaneously
      await Promise.all([
        client.requestSecret({ description: "1", publicKey: "p" }),
        client.requestSecret({ description: "2", publicKey: "p" }),
        client.requestSecret({ description: "3", publicKey: "p" })
      ]);

      expect(mintCount).toBe(1);
    });
  });
});
