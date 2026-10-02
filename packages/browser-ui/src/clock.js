/**
 * The link deadline, derived from the metadata `expiry` (Unix seconds) and
 * the controller's Date header. Without a usable Date there is no countdown:
 * the page shows the controller's deadline and lets the controller decide.
 *
 * The estimate is deliberately short: Date has one-second resolution and the
 * whole round trip is counted as already elapsed on the server.
 */
export function createDeadline({ expirySeconds, dateHeader, sentAt, receivedAt, perfAt }) {
  if (typeof expirySeconds !== "number" || !Number.isFinite(expirySeconds) || expirySeconds <= 0) return null;
  const expiresAt = new Date(expirySeconds * 1000);
  const serverDate = dateHeader ? Date.parse(dateHeader) : Number.NaN;
  if (!Number.isFinite(serverDate)) {
    return { serverClock: false, expiresAt, remaining: () => null, expired: () => false };
  }
  const roundTrip = Math.max(0, receivedAt - sentAt);
  const remainingAtReceipt = expirySeconds * 1000 - (serverDate + 1000 + roundTrip);
  const remaining = ({ perf, wall }) => {
    const elapsed = Math.max(0, perf - perfAt, wall - receivedAt);
    return Math.max(0, remainingAtReceipt - elapsed);
  };
  return { serverClock: true, expiresAt, remaining, expired: (now) => remaining(now) === 0 };
}

/**
 * The fleet deadline from the controller's own milliseconds (`server_time_ms`
 * sampled while it answered, and the offer's `expires_at_ms`). The whole round
 * trip counts as already elapsed on the server, so the estimate never runs long,
 * and elapsed time is the larger of monotonic and wall-clock time, so a
 * suspended tab can't stretch it. `serverNow` is the same conservative reading
 * of the controller's clock and is the only time the sealing step sees; the
 * browser's wall clock alone is never used.
 */
export function createServerDeadline({ serverTimeMs, expiresAtMs, sentAt, receivedAt, perfAt }) {
  const instant = (value) => Number.isSafeInteger(value) && value > 0;
  if (!instant(serverTimeMs) || !instant(expiresAtMs) || expiresAtMs <= serverTimeMs) return null;
  const roundTrip = Math.max(0, receivedAt - sentAt);
  const atReceipt = serverTimeMs + roundTrip;
  const elapsed = ({ perf, wall }) => Math.max(0, perf - perfAt, wall - receivedAt);
  const remaining = (now) => Math.max(0, expiresAtMs - atReceipt - elapsed(now));
  return {
    serverClock: true,
    expiresAt: new Date(expiresAtMs),
    remaining,
    serverNow: (now) => atReceipt + elapsed(now),
    expired: (now) => remaining(now) === 0
  };
}

export function formatRemaining(ms) {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const pad = (value) => String(value).padStart(2, "0");
  return hours > 0 ? `${hours}:${pad(minutes)}:${pad(seconds)}` : `${pad(minutes)}:${pad(seconds)}`;
}
