import assert from "node:assert/strict";
import test from "node:test";
import { isValidRequestContext, parseContext } from "../src/request-context.js";

test("parseContext reads the signed request parameters and nothing else", () => {
  const ctx = parseContext("?id=abc123&metadata_sig=100.meta&submit_sig=100.submit&api_url=https%3A%2F%2Fattacker.example");
  assert.deepEqual(ctx, { requestId: "abc123", metadataSig: "100.meta", submitSig: "100.submit" });
  // The API origin is fixed at build time; a link can never choose it.
  assert.equal("apiUrl" in ctx, false);
});

test("a context needs the id and both scoped signatures", () => {
  assert.equal(isValidRequestContext(parseContext("?id=a&metadata_sig=m&submit_sig=s")), true);
  for (const search of ["", "?id=a", "?id=a&metadata_sig=m", "?id=a&submit_sig=s", "?metadata_sig=m&submit_sig=s", "?id=&metadata_sig=m&submit_sig=s"]) {
    assert.equal(isValidRequestContext(parseContext(search)), false, search);
  }
});

test("preview flags no longer unlock entry", () => {
  assert.equal(isValidRequestContext(parseContext("?preview=1")), false);
  assert.equal(isValidRequestContext(parseContext("?test=1")), false);
});
