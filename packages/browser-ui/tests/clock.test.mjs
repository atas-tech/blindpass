import assert from "node:assert/strict";
import test from "node:test";
import { createDeadline, formatRemaining } from "../src/clock.js";

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
