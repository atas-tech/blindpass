import { useEffect, useState } from "react";
import { useSession } from "../../session/session.js";

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

/**
 * SHA-256 of the controller's issuer public key, as blindpass-node expects
 * for --issuer-fingerprint. Needs WebCrypto, which browsers only expose in
 * a secure context (HTTPS or localhost).
 */
export async function issuerFingerprint(issuerPub: string): Promise<string | null> {
  const bytes = fromBase64Url(issuerPub);
  if (bytes.length !== 32 || !globalThis.crypto?.subtle) return null;
  const digest = await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function useIssuerFingerprint(): { value: string | null; state: "loading" | "ready" | "unavailable" } {
  const { capabilities } = useSession();
  const issuerPub = capabilities?.issuer_pub;
  const [result, setResult] = useState<{ value: string | null; state: "loading" | "ready" | "unavailable" }>({ value: null, state: "loading" });
  useEffect(() => {
    let active = true;
    if (!issuerPub) {
      setResult({ value: null, state: "unavailable" });
      return;
    }
    issuerFingerprint(issuerPub)
      .then((value) => active && setResult(value ? { value, state: "ready" } : { value: null, state: "unavailable" }))
      .catch(() => active && setResult({ value: null, state: "unavailable" }));
    return () => {
      active = false;
    };
  }, [issuerPub]);
  return result;
}
