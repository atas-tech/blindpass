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

/**
 * Fleet link (kind=fleet): the operator-bound metadata read. A ready body opens
 * entry, a receipt means it was already submitted, and 401/403 both mean the
 * named operator's console session is missing (unless the 403 says the link's
 * own capability is bad). Nothing else is a ready state.
 */
export function fleetMetadataOutcome(status, body) {
  if (status === 200) {
    if (body?.status === "ready") return { state: "ready" };
    if (body?.status === "submitted") return { state: "used", reason: "load" };
    return { state: "error" };
  }
  // The controller names a bad capability in the 403 body; that is an altered or
  // incomplete link, so asking the operator to sign in would mislead them.
  if (status === 403 && (body?.error === "provisioning_capability_invalid" || body?.error === "provisioning_capability_required")) return { state: "invalid", reason: "load" };
  if (status === 401 || status === 403) return { state: "auth" };
  if (status === 410) return { state: "expired", reason: "load" };
  if (status === 400 || status === 404) return { state: "invalid", reason: "load" };
  return { state: "error" };
}

/**
 * Fleet submit: 201 (first receipt) or 200 (exact retry) is success. 409 means
 * a different ciphertext already holds the receipt. 400/413/429 are definite
 * refusals that keep the value; a lost reply or any other answer may hide a
 * committed receipt, so it is "unknown" and never retried automatically.
 */
export function fleetSubmitOutcome(status) {
  switch (status) {
    case 201:
    case 200:
      return { state: "submitted" };
    case 409:
      return { state: "used", reason: "conflict" };
    case 410:
      return { state: "expired", reason: "submit" };
    case 404:
      return { state: "invalid", reason: "submit" };
    case 401:
    case 403:
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
 * The single metadata re-read after a lost submit reply (the fleet form of
 * CT19, with no separate status capability). Only a receipt confirms success;
 * a live link without one is "pending", which is not proof that nothing will
 * arrive; a link that is gone can't be checked.
 */
export function fleetStatusOutcome(status, body) {
  if (status === 200 && body?.status === "submitted") return "submitted";
  if (status === 200 && body?.status === "ready") return "pending";
  if (status === 404 || status === 410) return "gone";
  if (status === 401 || status === 403) return "auth";
  return "unavailable";
}
