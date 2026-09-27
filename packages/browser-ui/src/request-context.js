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
