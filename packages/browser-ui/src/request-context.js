/**
 * Read the signed-link parameters. The link's api_url is deliberately
 * ignored: the controller origin is fixed when the page is built, so a
 * crafted link can't point the page at another server's public key.
 */
export function parseContext(search = "") {
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  return {
    requestId: params.get("id"),
    metadataSig: params.get("metadata_sig"),
    submitSig: params.get("submit_sig")
  };
}

export function isValidRequestContext(ctx) {
  return Boolean(ctx?.requestId && ctx?.metadataSig && ctx?.submitSig);
}

const FLEET_PARAMETERS = ["kind", "id", "metadata_sig", "submit_sig"];
const FLEET_ID = /^[a-f0-9]{64}$/;
// `<expiry seconds>.<43 base64url characters>`, the fleet capability shape.
const FLEET_CAPABILITY = /^[0-9]{1,16}\.[A-Za-z0-9_-]{43}$/;

/**
 * Classify a link. Without `kind` it is the legacy exchange link exactly as
 * before. `kind=fleet` is the operator-bound fleet link and is strict: exactly
 * these four parameters, each once, with the controller's id and capability
 * shapes. Any other kind, or any unknown, repeated or malformed fleet
 * parameter, is an invalid link and never falls back to the legacy page.
 */
export function parseLink(search = "") {
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  if (!params.has("kind")) {
    const ctx = parseContext(search);
    return { kind: "legacy", ctx, valid: isValidRequestContext(ctx) };
  }
  if (params.get("kind") !== "fleet") return { kind: "unknown", ctx: null, valid: false };
  const keys = [...params.keys()];
  const exact = keys.length === FLEET_PARAMETERS.length && FLEET_PARAMETERS.every((name) => keys.filter((key) => key === name).length === 1);
  const ctx = { requestId: params.get("id"), metadataSig: params.get("metadata_sig"), submitSig: params.get("submit_sig") };
  const valid = exact && FLEET_ID.test(ctx.requestId ?? "") && FLEET_CAPABILITY.test(ctx.metadataSig ?? "") && FLEET_CAPABILITY.test(ctx.submitSig ?? "");
  return { kind: "fleet", ctx: valid ? ctx : null, valid };
}
