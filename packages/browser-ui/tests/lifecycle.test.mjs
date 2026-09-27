import assert from "node:assert/strict";
import test from "node:test";
import { ENTRY_STATES, TERMINAL_STATES, metadataOutcome, submitOutcome } from "../src/lifecycle.js";

test("metadata answers map to the P04 state machine", () => {
  assert.deepEqual(metadataOutcome(200), { state: "ready" });
  assert.deepEqual(metadataOutcome(410), { state: "expired", reason: "load" });
  for (const status of [400, 403, 404]) assert.deepEqual(metadataOutcome(status), { state: "invalid", reason: "load" }, String(status));
  assert.deepEqual(metadataOutcome(401), { state: "auth" });
  // Anything else is a load failure the human can retry; it never becomes a dummy ready state.
  for (const status of [0, 429, 500, 502, 503]) assert.deepEqual(metadataOutcome(status), { state: "error" }, String(status));
});

test("submit answers never report success without a 201", () => {
  assert.deepEqual(submitOutcome(201), { state: "submitted" });
  assert.deepEqual(submitOutcome(409), { state: "used" });
  assert.deepEqual(submitOutcome(410), { state: "expired", reason: "submit" });
  assert.deepEqual(submitOutcome(403), { state: "invalid", reason: "submit" });
  assert.deepEqual(submitOutcome(401), { state: "auth" });
  // Definite refusals return to entry with the value kept, so the human can fix it.
  assert.deepEqual(submitOutcome(400), { state: "ready", error: "rejected" });
  assert.deepEqual(submitOutcome(413), { state: "ready", error: "tooLarge" });
  assert.deepEqual(submitOutcome(429), { state: "ready", error: "rateLimited" });
  // A lost or failed response may hide an accepted submission: never retry blindly.
  for (const status of [0, 500, 502, 503, 504]) assert.deepEqual(submitOutcome(status), { state: "unknown" }, String(status));
  assert.equal(submitOutcome(200).state, "unknown");
});

test("only ready accepts entry and every terminal state clears it", () => {
  assert.deepEqual([...ENTRY_STATES], ["ready"]);
  for (const state of ["submitted", "used", "expired", "invalid", "auth", "unknown"]) assert.equal(TERMINAL_STATES.has(state), true, state);
  for (const state of ["loading", "ready", "submitting", "error"]) assert.equal(TERMINAL_STATES.has(state), false, state);
});

import { capabilityOutcome, statusOutcome } from "../src/lifecycle.js";

test("CT19 capability answers: a status-only signature, gone, or unavailable", () => {
  assert.deepEqual(capabilityOutcome(200, { status_sig: "1790000000.abcdefghijklmnop" }), { sig: "1790000000.abcdefghijklmnop" });
  assert.deepEqual(capabilityOutcome(200, { status_sig: "" }), { unavailable: true });
  assert.deepEqual(capabilityOutcome(200, {}), { unavailable: true });
  assert.deepEqual(capabilityOutcome(410, { status: "expired" }), { gone: true });
  for (const status of [0, 403, 429, 500]) assert.deepEqual(capabilityOutcome(status, null), { unavailable: true }, String(status));
});

test("CT19 status answers: only pending or submitted are trusted; 410 never means failure", () => {
  assert.equal(statusOutcome(200, { status: "submitted" }), "submitted");
  assert.equal(statusOutcome(200, { status: "pending" }), "pending");
  assert.equal(statusOutcome(200, { status: "retrieved" }), "unavailable");
  assert.equal(statusOutcome(200, null), "unavailable");
  assert.equal(statusOutcome(410, { status: "expired" }), "gone");
  for (const status of [0, 401, 403, 500, 503]) assert.equal(statusOutcome(status, null), "unavailable", String(status));
});
