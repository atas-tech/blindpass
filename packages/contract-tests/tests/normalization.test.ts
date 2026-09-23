import { describe, expect, it } from "vitest";
import { normalizeHttpResult, normalizeSnapshotValue } from "../src/normalization.js";

describe("contract snapshot normalization", () => {
  it("preserves secret names, policy hashes and opaque signed values", () => {
    const policyHash = "a".repeat(64);
    const signedValue = "stripe.api_key.prod";
    const jwtHeader = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const jwtPayload = Buffer.from(JSON.stringify({ sub: "agent-1" })).toString("base64url");
    const jwt = `${jwtHeader}.${jwtPayload}.c2ln`;
    expect(normalizeSnapshotValue({
      secret_name: signedValue,
      policy_hash: policyHash,
      signed_fixture: signedValue,
      auth_opaque: jwt,
      not_a_jwt: "header.payload.signature"
    })).toEqual({
      secret_name: signedValue,
      policy_hash: policyHash,
      signed_fixture: signedValue,
      auth_opaque: "<jwt>",
      not_a_jwt: "header.payload.signature"
    });
  });

  it("normalizes UUIDs only in known identifier fields and approval reason text", () => {
    const adminId = "ac69222b-c82a-4e72-ac4f-ea90522f1414";
    expect(normalizeSnapshotValue({
      decided_by: adminId,
      reason: `exchange approved by ${adminId}`,
      secret_name: "finance.secret"
    })).toEqual({
      decided_by: "<uuid>",
      reason: "exchange approved by <uuid>",
      secret_name: "finance.secret"
    });
  });

  it("records selected response headers while stabilizing retry timing", () => {
    const headers = new Headers({
      "access-control-allow-origin": "https://allowed.example",
      "retry-after": "2"
    });
    expect(normalizeHttpResult({
      status: 429,
      contentType: "application/json; charset=utf-8",
      headers,
      body: { error: "rate limited", retry_after_seconds: 2 }
    })).toEqual({
      status: 429,
      content_type: "application/json",
      headers: {
        "access-control-allow-origin": "https://allowed.example",
        "retry-after": "<seconds>"
      },
      body: { error: "rate limited", retry_after_seconds: "<seconds>" }
    });
  });
});
