import assert from "node:assert/strict";
import test from "node:test";
import { isValidRequestContext, parseContext, parseLink } from "../src/request-context.js";

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

const FLEET_ID = "a".repeat(64);
const SIG = `1790000000.${"A".repeat(43)}`;
const fleetQuery = (extra = "") => `?kind=fleet&id=${FLEET_ID}&metadata_sig=${SIG}&submit_sig=${SIG.replace("A", "B")}${extra}`;

test("P05-PV06-S GUI: a link without kind is the legacy page, unchanged", () => {
  const link = parseLink("?id=abc123&metadata_sig=100.meta&submit_sig=100.submit&api_url=https%3A%2F%2Fattacker.example");
  assert.equal(link.kind, "legacy");
  assert.equal(link.valid, true);
  assert.deepEqual(link.ctx, { requestId: "abc123", metadataSig: "100.meta", submitSig: "100.submit" });
  assert.equal(parseLink("").valid, false);
  assert.equal(parseLink("?id=a&metadata_sig=m").valid, false);
});

test("P05-PV06-S GUI: kind=fleet with the exact id and both fleet capability shapes is a valid fleet link", () => {
  const link = parseLink(fleetQuery());
  assert.equal(link.kind, "fleet");
  assert.equal(link.valid, true);
  assert.deepEqual(link.ctx, { requestId: FLEET_ID, metadataSig: SIG, submitSig: SIG.replace("A", "B") });
});

test("P05-PV06-S GUI: any missing, unknown, duplicated or malformed fleet parameter is the invalid-link state", () => {
  const bad = [
    "?kind=fleet",
    `?kind=fleet&id=${FLEET_ID}&metadata_sig=${SIG}`,
    `?kind=fleet&id=${FLEET_ID}&submit_sig=${SIG}`,
    `?kind=fleet&metadata_sig=${SIG}&submit_sig=${SIG}`,
    fleetQuery("&api_url=https%3A%2F%2Fattacker.example"),
    fleetQuery("&preview=1"),
    fleetQuery(`&id=${"b".repeat(64)}`),
    fleetQuery(`&kind=fleet`),
    `?kind=fleet&id=${"A".repeat(64)}&metadata_sig=${SIG}&submit_sig=${SIG}`,
    `?kind=fleet&id=${"a".repeat(63)}&metadata_sig=${SIG}&submit_sig=${SIG}`,
    `?kind=fleet&id=${FLEET_ID}&metadata_sig=nodot&submit_sig=${SIG}`,
    `?kind=fleet&id=${FLEET_ID}&metadata_sig=${SIG}&submit_sig=1.short`,
    `?kind=fleet&id=${FLEET_ID}&metadata_sig=${SIG}x&submit_sig=${SIG}`,
    `?kind=fleet&id=${FLEET_ID}&metadata_sig=&submit_sig=${SIG}`,
    `?kind=Fleet&id=${FLEET_ID}&metadata_sig=${SIG}&submit_sig=${SIG}`
  ];
  for (const search of bad) {
    const link = parseLink(search);
    assert.equal(link.valid, false, search);
    assert.notEqual(link.kind, "legacy", search);
  }
  // Another kind never falls back to the legacy page.
  for (const search of ["?kind=other&id=a&metadata_sig=m&submit_sig=s", "?kind=&id=a&metadata_sig=m&submit_sig=s"]) {
    const link = parseLink(search);
    assert.equal(link.valid, false, search);
    assert.notEqual(link.kind, "legacy", search);
  }
});
