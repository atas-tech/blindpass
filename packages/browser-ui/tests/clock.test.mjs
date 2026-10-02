import assert from "node:assert/strict";
import test from "node:test";
import { createDeadline, createServerDeadline, formatRemaining } from "../src/clock.js";

const EXPIRY = 1_900_000_300; // unix seconds

test("with the controller's Date, remaining time follows the server clock, not the device clock", () => {
  // The device clock is 10 minutes fast; the controller says it's 300 s before expiry.
  const serverNow = (EXPIRY - 300) * 1000;
  const deadline = createDeadline({ expirySeconds: EXPIRY, dateHeader: new Date(serverNow).toUTCString(), sentAt: serverNow + 600_000 - 200, receivedAt: serverNow + 600_000, perfAt: 5_000 });
  assert.equal(deadline.serverClock, true);
  // Conservative: the Date header has one-second resolution and the round trip took 200 ms.
  assert.equal(deadline.remaining({ perf: 5_000, wall: serverNow + 600_000 }), 300_000 - 1_000 - 200);
  assert.equal(deadline.remaining({ perf: 65_000, wall: serverNow + 660_000 }), 240_000 - 1_200);
});

test("elapsed time is the larger of monotonic and wall time, so a suspended tab can't stretch the deadline", () => {
  const serverNow = (EXPIRY - 120) * 1000;
  const deadline = createDeadline({ expirySeconds: EXPIRY, dateHeader: new Date(serverNow).toUTCString(), sentAt: serverNow, receivedAt: serverNow, perfAt: 0 });
  // performance.now() paused for 5 minutes while the wall clock kept going.
  assert.equal(deadline.remaining({ perf: 1_000, wall: serverNow + 300_000 }), 0);
  assert.equal(deadline.expired({ perf: 1_000, wall: serverNow + 300_000 }), true);
  // A wall clock moved backwards doesn't add time either.
  assert.equal(deadline.remaining({ perf: 60_000, wall: serverNow - 3_600_000 }), 120_000 - 1_000 - 60_000);
});

test("without usable clock evidence there is no countdown, only the controller's deadline", () => {
  for (const dateHeader of [null, "", "not a date"]) {
    const deadline = createDeadline({ expirySeconds: EXPIRY, dateHeader, sentAt: 0, receivedAt: 0, perfAt: 0 });
    assert.equal(deadline.serverClock, false, String(dateHeader));
    assert.equal(deadline.remaining({ perf: 0, wall: 0 }), null);
    assert.equal(deadline.expired({ perf: 0, wall: 0 }), false);
    assert.equal(deadline.expiresAt.getTime(), EXPIRY * 1000);
  }
});

test("a missing or nonsensical expiry gives no deadline", () => {
  for (const expirySeconds of [undefined, null, 0, -1, "soon", Number.NaN]) {
    assert.equal(createDeadline({ expirySeconds, dateHeader: new Date().toUTCString(), sentAt: 0, receivedAt: 0, perfAt: 0 }), null, String(expirySeconds));
  }
});

test("formatRemaining rounds down and never shows negative time", () => {
  assert.equal(formatRemaining(168_900), "02:48");
  assert.equal(formatRemaining(59_999), "00:59");
  assert.equal(formatRemaining(3_725_000), "1:02:05");
  assert.equal(formatRemaining(-5), "00:00");
});

const SERVER_NOW = 1_900_000_000_000;
const OFFER_END = SERVER_NOW + 30_000;

test("P05-PV06-S GUI: the server's own milliseconds drive the fleet deadline, not the device clock", () => {
  // The device clock is ten minutes fast; the controller said it was 30 s before the offer ends.
  const deadline = createServerDeadline({ serverTimeMs: SERVER_NOW, expiresAtMs: OFFER_END, sentAt: SERVER_NOW + 600_000 - 200, receivedAt: SERVER_NOW + 600_000, perfAt: 5_000 });
  assert.equal(deadline.serverClock, true);
  assert.equal(deadline.expiresAt.getTime(), OFFER_END);
  // The whole round trip counts as already elapsed on the server.
  assert.equal(deadline.remaining({ perf: 5_000, wall: SERVER_NOW + 600_000 }), 30_000 - 200);
  assert.equal(deadline.serverNow({ perf: 5_000, wall: SERVER_NOW + 600_000 }), SERVER_NOW + 200);
  assert.equal(deadline.remaining({ perf: 15_000, wall: SERVER_NOW + 610_000 }), 20_000 - 200);
  assert.equal(deadline.serverNow({ perf: 15_000, wall: SERVER_NOW + 610_000 }), SERVER_NOW + 10_200);
  assert.equal(deadline.expired({ perf: 35_000, wall: SERVER_NOW + 630_000 }), true);
});

test("P05-PV06-S GUI: a suspended tab or a moved wall clock cannot stretch the fleet deadline or the sealing time", () => {
  const deadline = createServerDeadline({ serverTimeMs: SERVER_NOW, expiresAtMs: OFFER_END, sentAt: 1_000, receivedAt: 1_000, perfAt: 0 });
  // performance.now() paused while the wall clock moved 40 s.
  assert.equal(deadline.remaining({ perf: 1_000, wall: 41_000 }), 0);
  assert.equal(deadline.expired({ perf: 1_000, wall: 41_000 }), true);
  assert.equal(deadline.serverNow({ perf: 1_000, wall: 41_000 }), SERVER_NOW + 40_000);
  // A wall clock moved backwards adds nothing; monotonic time still counts.
  assert.equal(deadline.remaining({ perf: 10_000, wall: -3_600_000 }), 20_000);
  assert.equal(deadline.serverNow({ perf: 10_000, wall: -3_600_000 }), SERVER_NOW + 10_000);
});

test("P05-PV06-S GUI: unusable fleet clock evidence gives no deadline at all", () => {
  const good = { serverTimeMs: SERVER_NOW, expiresAtMs: OFFER_END, sentAt: 0, receivedAt: 0, perfAt: 0 };
  for (const change of [{ serverTimeMs: undefined }, { serverTimeMs: -1 }, { serverTimeMs: 1.5 }, { serverTimeMs: "now" }, { expiresAtMs: 0 }, { expiresAtMs: null }, { expiresAtMs: Number.NaN }, { expiresAtMs: SERVER_NOW }, { expiresAtMs: SERVER_NOW - 1 }, { expiresAtMs: Number.MAX_SAFE_INTEGER + 2 }]) {
    assert.equal(createServerDeadline({ ...good, ...change }), null, JSON.stringify(change));
  }
});
