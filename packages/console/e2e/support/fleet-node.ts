// TEST-ONLY API-node fixture for the Source provisioning journeys (P05-PV06-S GUI
// portion). It is NOT a broker and not blindpass-node: it plays the node side of
// the controller's HTTP contract with generated keys, in JavaScript, so a real
// controller can be driven end to end from the browser:
//
//   enroll -> open a signed session -> post a signed operation request ->
//   read the grant from the node inbox -> sign and post a recipient offer ->
//   read the provisioning_delivery from the inbox and open it with the offer's
//   private key.
//
// Every signed message below is built independently of the page code from the
// canonical rules in crates/blindpass-core (domain prefix + sorted-key compact
// JSON), so the controller accepting the signatures is interoperability
// evidence for the JavaScript signer, not a tautology. None of this runs in a
// product: no broker custody, systemd identity, kernel peer check or Unix socket.
import { randomBytes, sign } from "node:crypto";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { nodeKeys, submitEnrollment } from "./node.js";
import type { AdminClient, Stack } from "./stack.js";

const NODE_CHALLENGE_DOMAIN = "blindpass:fleet-node-challenge:v1\0";
const NODE_EVENT_DOMAIN = "blindpass:fleet-node-event:v1\0";
const DOCUMENT_DOMAIN = "blindpass:fleet-document:v1\0";
const SOURCE_DOMAIN = "blindpass:fleet-browser-source:v1\0";
const PROTOCOL = "blindpass-node/1";
const suite = new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Chacha20Poly1305 });

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Sorted-key compact JSON, the controller's canonical form for the ASCII/integer data signed here. */
function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted((value as Record<string, unknown>)[key])]));
  return value;
}

export const canonical = (value: unknown): string => JSON.stringify(sorted(value));

const b64u = (bytes: Uint8Array | Buffer): string => Buffer.from(bytes).toString("base64url");

function buffer(base64url: string): ArrayBuffer {
  const bytes = Uint8Array.from(Buffer.from(base64url, "base64url"));
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export interface Reply<T = Json> {
  status: number;
  body: T;
}

export interface InboxDocument {
  seq: number;
  envelope: { kind: string; v: number; kid: string; epoch: number; sig: string; body: Record<string, Json> };
}

/** A grant exactly as the controller signed it into the node inbox. */
export type GrantBody = Record<string, Json> & {
  id: string;
  operation_id: string;
  node_id: string;
  workload_id: string;
  issued_at_ms: number;
  expires_at_ms: number;
};

export interface OfferFixture {
  /** The signed envelope the node posts as a recipient_offer event. */
  offer: Record<string, Json>;
  /** The signed binding; also the AAD of the HPKE seal. */
  binding: Record<string, Json>;
  expiresAtMs: number;
  /** The offer's one-use private key, held only by the test to open the delivery. */
  privateKey: CryptoKey;
}

export class FleetNode {
  readonly keys = nodeKeys();
  id = "";
  private bearer = "";

  constructor(private readonly stack: Stack) {}

  /** Create, submit and approve an enrollment, then open an authenticated channel. */
  static async enroll(stack: Stack, admin: AdminClient, name: string): Promise<FleetNode> {
    const node = new FleetNode(stack);
    const created = await admin.call<{ id: string; token: string; node_id: string }>("POST", "/api/v3/enrollments", { name });
    if (created.status !== 201) throw new Error(`enrollment create failed: ${created.status}`);
    const submitted = await submitEnrollment(stack.controllerUrl, created.body.token, node.keys, { protocol_version: PROTOCOL });
    if (submitted.status !== 201) throw new Error(`enrollment submit failed: ${submitted.status}`);
    const detail = await admin.call<{ version: number }>("GET", `/api/v3/enrollments/${created.body.id}`);
    const approved = await admin.call("POST", `/api/v3/enrollments/${created.body.id}/approve`, { expected_fingerprint: node.keys.fingerprint, expected_version: detail.body.version });
    if (approved.status !== 200) throw new Error(`enrollment approve failed: ${approved.status}`);
    node.id = created.body.node_id;
    await node.openSession();
    return node;
  }

  private async raw(route: string, init: { method: string; headers?: Record<string, string>; body?: unknown; timeoutMs?: number }): Promise<Reply<never>> {
    const response = await fetch(`${this.stack.controllerUrl}${route}`, {
      method: init.method,
      headers: { ...(init.body === undefined ? {} : { "content-type": "application/json" }), ...init.headers },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: init.timeoutMs ? AbortSignal.timeout(init.timeoutMs) : undefined
    });
    const text = await response.text();
    return { status: response.status, body: (text ? JSON.parse(text) : null) as never };
  }

  /** The two-phase signed channel login: challenge, then a signature over the canonical challenge. */
  async openSession(): Promise<void> {
    const hello = { node_id: this.id, key_version: 1, protocol_version: PROTOCOL, capabilities: { protocol_version: PROTOCOL } };
    const challenge = await this.raw("/api/v3/node/session", { method: "POST", body: hello });
    if (challenge.status !== 200) throw new Error(`node challenge failed: ${challenge.status}`);
    const c = challenge.body as Record<string, Json>;
    const message = Buffer.from(
      NODE_CHALLENGE_DOMAIN +
        canonical({
          audience: "blindpass-node",
          capabilities_hash: c.capabilities_hash,
          controller_time_ms: c.controller_time_ms,
          expires_at_ms: c.expires_at_ms,
          issuer_epoch: c.issuer_epoch,
          key_version: 1,
          node_id: this.id,
          nonce: c.nonce,
          protocol_version: PROTOCOL,
          tenant_id: c.tenant_id
        })
    );
    const session = await this.raw("/api/v3/node/session", { method: "POST", body: { ...hello, nonce: c.nonce, signature: b64u(sign(null, message, this.keys.signingKey)) } });
    if (session.status !== 200) throw new Error(`node session failed: ${session.status}`);
    this.bearer = `Bearer ${(session.body as { token: string }).token}`;
  }

  /** Sign and post one node event; its signature covers the canonical node id, key, kind and body. */
  async post(kind: string, key: string, body: Record<string, Json>): Promise<Reply> {
    const message = Buffer.from(NODE_EVENT_DOMAIN + canonical({ body, idempotency_key: key, kind, node_id: this.id }));
    return this.raw("/api/v3/node/events", {
      method: "POST",
      headers: { authorization: this.bearer },
      body: { events: [{ idempotency_key: key, kind, body, broker_signature: b64u(sign(null, message, this.keys.signingKey)) }] }
    }) as Promise<Reply>;
  }

  /** A browser_session operation request as the broker would sign it; returns the event key. */
  async requestOperation(workload: { id: string; unit: string; account: string }, purpose: string, ttlSeconds = 120): Promise<string> {
    const key = `event_e2e_${randomBytes(8).toString("hex")}`;
    const posted = await this.post("operation_request", key, {
      request_version: 2,
      node_id: this.id,
      workload_id: workload.id,
      unit: workload.unit,
      account: workload.account,
      action: "browser.session",
      mode: "browser_session",
      purpose,
      resource_id: "report-primary",
      invocation_id: randomBytes(16).toString("hex"),
      ttl_seconds: ttlSeconds,
      observed_at_ms: Date.now()
    });
    if (posted.status !== 200) throw new Error(`operation request failed: ${posted.status}`);
    return key;
  }

  /**
   * The node's inbox as a poll would return it. An empty inbox is held by the
   * controller for 30 s, so a short timeout turns "nothing yet" into an empty list.
   */
  async inbox(): Promise<{ documents: InboxDocument[]; serverTimeMs: number }> {
    try {
      const polled = await this.raw("/api/v3/node/poll", { method: "POST", headers: { authorization: this.bearer }, body: {}, timeoutMs: 4_000 });
      if (polled.status !== 200) throw new Error(`node poll failed: ${polled.status}`);
      const body = polled.body as { documents: InboxDocument[]; server_time_ms: number };
      return { documents: body.documents, serverTimeMs: body.server_time_ms };
    } catch (error) {
      if (error instanceof DOMException || (error as Error).name === "TimeoutError" || (error as Error).name === "AbortError") return { documents: [], serverTimeMs: Date.now() };
      throw error;
    }
  }

  async waitForDocument(match: (document: InboxDocument) => boolean, timeoutMs = 30_000): Promise<{ document: InboxDocument; serverTimeMs: number }> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const { documents, serverTimeMs } = await this.inbox();
      const document = documents.find(match);
      if (document) return { document, serverTimeMs };
      if (Date.now() > deadline) throw new Error("timed out waiting for a node inbox document");
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  async grantFor(operationId: string): Promise<{ grant: GrantBody; serverTimeMs: number }> {
    const { document, serverTimeMs } = await this.waitForDocument((entry) => entry.envelope.kind === "grant" && entry.envelope.body.operation_id === operationId);
    return { grant: document.envelope.body as GrantBody, serverTimeMs };
  }

  async deliveries(): Promise<InboxDocument[]> {
    return (await this.inbox()).documents.filter((entry) => entry.envelope.kind === "provisioning_delivery");
  }

  /**
   * Sign a recipient offer for `grant` with a fresh one-use recipient key. The
   * offer ends `ttlMs` after the controller's clock (never after the grant).
   */
  async signOffer(grant: GrantBody, destination: { unit: string; credential: string }, serverTimeMs: number, ttlMs: number): Promise<OfferFixture> {
    const pair = await suite.kem.generateKeyPair();
    const expiresAtMs = Math.min(serverTimeMs + ttlMs, grant.expires_at_ms);
    const binding: Record<string, Json> = {
      version: 1,
      purpose: "browser_source",
      offer_id: `pv_${randomBytes(12).toString("hex")}`,
      node_key_version: 1,
      source_unit: destination.unit,
      credential: destination.credential,
      recipient_public: b64u(new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey))),
      issued_at_ms: Math.max(serverTimeMs, grant.issued_at_ms),
      expires_at_ms: expiresAtMs,
      grant
    };
    const envelope = { v: 1, kind: "recipient_offer", kid: `${this.id}-1`, epoch: 1, body: binding };
    const signature = sign(null, Buffer.from(DOCUMENT_DOMAIN + canonical(envelope)), this.keys.signingKey);
    return { offer: { ...envelope, sig: b64u(signature) } as Record<string, Json>, binding, expiresAtMs, privateKey: pair.privateKey };
  }

  /** Post the signed offer as the node's recipient_offer event. */
  async publishOffer(fixture: OfferFixture): Promise<Reply> {
    return this.post("recipient_offer", `event_offer_${randomBytes(8).toString("hex")}`, fixture.offer);
  }
}

/**
 * Open a controller-signed provisioning_delivery with the offer's private key.
 * The delivery must carry the very binding that was signed, and the AAD is
 * rebuilt here from that binding independently of the page's helper.
 */
export async function openDelivery(fixture: OfferFixture, delivery: InboxDocument): Promise<Uint8Array> {
  const body = delivery.envelope.body as { binding: Json; enc: string; ciphertext: string };
  if (canonical(body.binding) !== canonical(fixture.binding)) throw new Error("the delivery does not carry the signed offer binding");
  const aad = new TextEncoder().encode(SOURCE_DOMAIN + canonical(fixture.binding));
  const plain = await suite.open({ recipientKey: fixture.privateKey, enc: buffer(body.enc) }, buffer(body.ciphertext), aad.buffer.slice(aad.byteOffset, aad.byteOffset + aad.byteLength) as ArrayBuffer);
  return new Uint8Array(plain);
}
