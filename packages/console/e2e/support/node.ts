// Minimal node-side enrollment for console E2E: real Ed25519/X25519 keys and
// the same domain-separated proof and fingerprint as blindpass-core/fleet.rs.
// It does not open a node channel, so enrolled nodes stay offline.
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";

const ENROLLMENT_DOMAIN = Buffer.from("blindpass:fleet-enrollment-proof:v1\0", "utf8");
const FINGERPRINT_DOMAIN = Buffer.from("blindpass:fleet-node-fingerprint:v1\0", "utf8");

function rawPublic(key: KeyObject): Buffer {
  const jwk = key.export({ format: "jwk" }) as { x: string };
  return Buffer.from(jwk.x, "base64url");
}

function field(value: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length);
  return Buffer.concat([length, value]);
}

export interface SimulatedNode {
  signingPub: Buffer;
  recipientPub: Buffer;
  fingerprint: string;
}

export function nodeKeys(): SimulatedNode & { signingKey: KeyObject } {
  const signing = generateKeyPairSync("ed25519");
  const recipient = generateKeyPairSync("x25519");
  const signingPub = rawPublic(signing.publicKey);
  const recipientPub = rawPublic(recipient.publicKey);
  const fingerprint = createHash("sha256").update(Buffer.concat([FINGERPRINT_DOMAIN, signingPub, recipientPub])).digest("hex");
  return { signingKey: signing.privateKey, signingPub, recipientPub, fingerprint };
}

/** Submit an enrollment the way blindpass-node does; returns the node's printed fingerprint. */
export async function submitEnrollment(
  controllerUrl: string,
  token: string,
  keys = nodeKeys(),
  capabilities: Record<string, unknown> = { modes: ["file", "socket"], actions: ["noop.marker"] }
): Promise<SimulatedNode & { status: number }> {
  const message = Buffer.concat([ENROLLMENT_DOMAIN, field(Buffer.from(token, "utf8")), field(keys.signingPub), field(keys.recipientPub)]);
  const proof = sign(null, message, keys.signingKey);
  const response = await fetch(`${controllerUrl}/api/v3/node/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      token,
      signing_pub: keys.signingPub.toString("base64url"),
      recipient_pub: keys.recipientPub.toString("base64url"),
      proof: proof.toString("base64url"),
      protocol_version: "blindpass-node/1",
      capabilities,
      host_facts: { os: "linux", simulated: true }
    })
  });
  return { status: response.status, signingPub: keys.signingPub, recipientPub: keys.recipientPub, fingerprint: keys.fingerprint };
}
