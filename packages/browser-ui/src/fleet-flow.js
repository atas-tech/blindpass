// The operator-bound fleet input flow (kind=fleet). It owns the protocol only:
// transport, clock and CSRF are injected, so app.js stays the single place that
// touches the DOM and tests drive the flow with fakes. The Source value is passed
// in by the caller for one call, sealed and discarded; it is never stored on the
// flow, put in a URL, header, error or result.
import { createServerDeadline } from "./clock.js";
import { sealVerifiedBrowserSource, verifyBrowserRecipientOffer } from "./fleet-provisioning.js";
import { fleetMetadataOutcome, fleetStatusOutcome, fleetSubmitOutcome } from "./lifecycle.js";
import { FLEET_MAX_SOURCE_BYTES, secretBytes } from "./secret-value.js";

export { FLEET_MAX_SOURCE_BYTES };

const MAX_SUMMARY_CHARACTERS = 2_048;
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
// Fleet requests carry the named operator's cookie, same origin only, and never
// follow a redirect away from the controller.
const sameOrigin = { credentials: "same-origin", redirect: "error" };

/** Fixed fleet routes; ids and signatures are encoded, nothing else enters a path. */
export function fleetPaths(ctx) {
  const id = encodeURIComponent(ctx.requestId);
  return {
    metadata: `/api/v3/fleet/provisioning/${id}/metadata?sig=${encodeURIComponent(ctx.metadataSig)}`,
    submit: `/api/v3/fleet/provisioning/${id}/submit?sig=${encodeURIComponent(ctx.submitSig)}`
  };
}

function validReadyBody(body) {
  return (
    plain(body) &&
    plain(body.offer) &&
    plain(body.expected) &&
    plain(body.summary) &&
    typeof body.summary.purpose === "string" &&
    typeof body.summary.workload_name === "string" &&
    body.summary.purpose.length <= MAX_SUMMARY_CHARACTERS &&
    body.summary.workload_name.length <= MAX_SUMMARY_CHARACTERS
  );
}

/**
 * `call(path, init)` resolves `{ status, body, sentAt, receivedAt, perfAt }` and
 * never rejects; `now()` is `{ perf, wall }`; `csrfToken()` reads the readable
 * bp_csrf cookie (null when absent). `verify` and `seal` default to the
 * independently verified path of fleet-provisioning.js: an offer is never sealed
 * to without first being verified against the controller's separately supplied
 * `expected` grant, key version, destination and enrolled signing key.
 */
export function createFleetFlow({ ctx, call, now, csrfToken, verify = verifyBrowserRecipientOffer, seal = sealVerifiedBrowserSource }) {
  const paths = fleetPaths(ctx);
  let offered = null;

  /** Read and verify the offer. Anything but a verified, live offer withdraws the previous one. */
  async function load() {
    const outcome = await read();
    if (outcome.state !== "ready") offered = null;
    return outcome;
  }

  async function read() {
    const result = await call(paths.metadata, sameOrigin);
    const outcome = fleetMetadataOutcome(result.status, result.body);
    if (outcome.state !== "ready") return outcome;
    const body = result.body;
    if (!validReadyBody(body)) return { state: "error" };
    const deadline = createServerDeadline({ serverTimeMs: body.server_time_ms, expiresAtMs: body.expires_at_ms, sentAt: result.sentAt, receivedAt: result.receivedAt, perfAt: result.perfAt });
    if (!deadline) return { state: "error" };
    // Snapshot the public data so later mutation can't change what is sealed to.
    const offer = structuredClone(body.offer);
    const expected = structuredClone(body.expected);
    let binding;
    try {
      binding = await verify(offer, expected, Math.floor(deadline.serverNow(now())));
    } catch {
      return { state: "invalid", reason: "offer" };
    }
    // The link deadline the controller reports must be the offer's own deadline.
    if (binding.expires_at_ms !== body.expires_at_ms) return { state: "invalid", reason: "offer" };
    if (deadline.expired(now())) return { state: "expired", reason: "whileOpen" };
    offered = { offer, expected, deadline };
    return {
      state: "ready",
      view: { purpose: body.summary.purpose, workloadName: body.summary.workload_name, sourceUnit: binding.source_unit, credential: binding.credential, deadline }
    };
  }

  /** Seal and send once. The caller clears the value for every outcome but `ready`. */
  async function submit(value) {
    if (!offered) return { state: "invalid", reason: "load" };
    const bytes = secretBytes(value).length;
    if (bytes === 0) return { state: "ready", error: "empty" };
    if (bytes > FLEET_MAX_SOURCE_BYTES) return { state: "ready", error: "tooLarge" };
    if (offered.deadline.expired(now())) return { state: "expired", reason: "whileOpen" };
    const token = csrfToken();
    if (!token) return { state: "auth" };
    let payload;
    try {
      payload = await seal(offered.offer, offered.expected, value, Math.floor(offered.deadline.serverNow(now())));
    } catch (error) {
      // Only the two fixed offer-expiry messages mean time ran out; any other
      // text, which could contain anything, is reported as a fixed encryption failure.
      const expired = error instanceof Error && (error.message === "invalid_provisioning_offer" || error.message === "invalid_provisioning_binding");
      return expired ? { state: "expired", reason: "whileOpen" } : { state: "ready", error: "encryption" };
    }
    const result = await call(paths.submit, {
      ...sameOrigin,
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": token },
      body: JSON.stringify({ enc: payload.enc, ciphertext: payload.ciphertext })
    });
    payload = null;
    return fleetSubmitOutcome(result.status);
  }

  /** One metadata re-read after a lost reply: submitted, pending, gone, auth or unavailable. */
  async function reconcile() {
    const result = await call(paths.metadata, sameOrigin);
    return fleetStatusOutcome(result.status, result.body);
  }

  return { load, submit, reconcile, paths };
}
