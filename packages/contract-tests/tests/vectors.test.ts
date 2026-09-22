import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildVectorResults, evaluatePolicyVectors, runHpkeRoundTrip } from "../src/vectors.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

describe("P00 golden vectors", () => {
  it("CV01 signs browser links with scope separation", async () => {
    const vectors = await buildVectorResults();
    expect(vectors.cv01.metadata).toMatch(/^\d+\.[A-Za-z0-9_-]{43}$/);
    expect(vectors.cv01.submit).toMatch(/^\d+\.[A-Za-z0-9_-]{43}$/);
    expect(vectors.cv01.metadata).not.toBe(vectors.cv01.submit);
  });

  it("CV02 derives domain-separated signing secrets", async () => {
    const vectors = await buildVectorResults();
    expect(Object.keys(vectors.cv02)).toEqual(["browser-sig", "agent-fulfillment"]);
    expect(vectors.cv02["browser-sig"]).toHaveLength(43);
    expect(vectors.cv02["agent-fulfillment"]).toHaveLength(43);
    expect(vectors.cv02["browser-sig"]).not.toBe(vectors.cv02["agent-fulfillment"]);
  });

  it("CV03 emits a stable HS256 fulfillment-token shape", async () => {
    const vectors = await buildVectorResults();
    expect(vectors.cv03.token.split(".")).toHaveLength(3);
    expect(vectors.cv03).toMatchObject({ issuer: "sps", audience: "agent-fulfill" });
  });

  it("CV04 preserves the confirmation-code dictionary and shape", async () => {
    const fixture = JSON.parse(await readFile(path.join(HERE, "../fixtures/cv04-confirmation-code.json"), "utf8")) as {
      adjectives: string[];
      nouns: string[];
      number_min: number;
      number_max: number;
      format: string;
    };
    expect(fixture.adjectives).toHaveLength(8);
    expect(fixture.nouns).toHaveLength(8);
    expect(fixture.number_min).toBe(0);
    expect(fixture.number_max).toBe(99);
    expect(fixture.format).toBe("ADJECTIVE-NOUN-00");
  });

  it("CV05 evaluates policy decisions and hashes identically", async () => {
    const results = await evaluatePolicyVectors();
    for (const result of results) {
      expect(result.source_hash).toBe(result.policy_hash);
    }
    expect(results.map((result) => result.mode)).toEqual(["allow", "pending_approval", "none", "none"]);
  });

  it("CV06 runs the TypeScript HPKE round trip with the accepted suite", async () => {
    const result = await runHpkeRoundTrip();
    expect(result.enc).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(result.ciphertext).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(result.plaintext).toBe("CV06-P00-round-trip");
  });
});
