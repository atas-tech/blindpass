/**
 * The input page state machine (P04 "Input page state machine"). Only
 * "ready" accepts entry; every terminal state clears the field.
 */
export const ENTRY_STATES = new Set(["ready"]);
export const TERMINAL_STATES = new Set(["submitted", "used", "expired", "invalid", "auth", "unknown"]);

/** Outcome of the metadata read. 0 means the request itself failed. */
export function metadataOutcome(status) {
  if (status === 200) return { state: "ready" };
  if (status === 410) return { state: "expired", reason: "load" };
  if (status === 400 || status === 403 || status === 404) return { state: "invalid", reason: "load" };
  if (status === 401) return { state: "auth" };
  return { state: "error" };
}

/**
 * Outcome of the submit call. Success needs the documented 201; a network
 * failure, a 5xx or any unexpected answer may hide an accepted submission,
 * so it is "unknown" and never retried automatically.
 */
export function submitOutcome(status) {
  switch (status) {
    case 201:
      return { state: "submitted" };
    case 409:
      return { state: "used" };
    case 410:
      return { state: "expired", reason: "submit" };
    case 403:
      return { state: "invalid", reason: "submit" };
    case 401:
      return { state: "auth" };
    case 400:
      return { state: "ready", error: "rejected" };
    case 413:
      return { state: "ready", error: "tooLarge" };
    case 429:
      return { state: "ready", error: "rateLimited" };
    default:
      return { state: "unknown" };
  }
}

/**
 * CT19: the metadata signature buys a status-only signature. It can't
 * submit or retrieve; 410 means the source link is gone.
 */
export function capabilityOutcome(status, body) {
  if (status === 200 && typeof body?.status_sig === "string" && body.status_sig) return { sig: body.status_sig };
  if (status === 410) return { gone: true };
  return { unavailable: true };
}

/**
 * CT19 browser status. 410 conflates consumed, expired and invalid, so it
 * is "gone", never "failed"; anything but pending/submitted is unavailable.
 */
export function statusOutcome(status, body) {
  if (status === 200 && (body?.status === "pending" || body?.status === "submitted")) return body.status;
  if (status === 410) return "gone";
  return "unavailable";
}
