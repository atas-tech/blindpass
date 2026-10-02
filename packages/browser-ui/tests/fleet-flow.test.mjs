// SPDX-License-Identifier: MIT
// The fleet-mode input flow (P05-PV06-S GUI portion, P04-E03 input outcomes)
// against injected transport, a real signed offer and a real HPKE recipient. The
// Source below is a generated dummy canary; nothing here is a credential.
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { generateKeyPairSync, sign } from "node:crypto";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { FLEET_MAX_SOURCE_BYTES, createFleetFlow } from "../src/fleet-flow.js";
import { browserProvisioningAad } from "../src/fleet-provisioning.js";

const suite = new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Chacha20Poly1305 });
const template = JSON.parse(await readFile(new URL("./fixtures/fleet-provisioning-v1.json", import.meta.url)));
const sort = (value) => (value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sort(value[key])])) : value);

const SERVER_NOW = 1_900_000_000_000;
const ID = "c".repeat(64);
const META_SIG = `1900000100.${"M".repeat(43)}`;
const SUBMIT_SIG = `1900000100.${"S".repeat(43)}`;
const CTX = { requestId: ID, metadataSig: META_SIG, submitSig: SUBMIT_SIG };
const CANARY = "P05-GUI-CANARY";
const TYPED = ` ${CANARY}é 漢字 \u{1F511}\nsecond line `;
const CSRF = "csrf-test-token-0123456789abcdef";

/** A signed offer for a generated recipient, valid for 30 s after SERVER_NOW. */
async function fixture() {
  const signing = generateKeyPairSync("ed25519");
  const recipient = await suite.kem.generateKeyPair();
  const recipientPublic = Buffer.from(new Uint8Array(await suite.kem.serializePublicKey(recipient.publicKey))).toString("base64url");
  const binding = structuredClone(template);
  binding.recipient_public = recipientPublic;
  binding.issued_at_ms = SERVER_NOW - 1_000;
  binding.expires_at_ms = SERVER_NOW + 30_000;
  binding.grant.issued_at_ms = SERVER_NOW - 2_000;
  binding.grant.expires_at_ms = SERVER_NOW + 60_000;
  const envelope = { v: 1, kind: "recipient_offer", kid: "nd_node-a-1", epoch: 1, body: binding };
  const bytes = Buffer.from(`blindpass:fleet-document:v1\0${JSON.stringify(sort(envelope))}`);
  const offer = { ...envelope, sig: sign(null, bytes, signing.privateKey).toString("base64url") };
  const expected = {
    grant: structuredClone(binding.grant),
    node_key_version: 1,
    source_unit: binding.source_unit,
    credential: binding.credential,
    signing_public: signing.publicKey.export({ format: "jwk" }).x
  };
  return { binding, offer, expected, recipient };
}

function ready(f, change = {}) {
  return {
    status: "ready",
    server_time_ms: SERVER_NOW,
    expires_at_ms: f.binding.expires_at_ms,
    offer: f.offer,
    expected: f.expected,
    summary: { purpose: "read approved report", workload_name: "report-worker" },
    ...change
  };
}

/** Scripted transport: each call takes the next reply; every request is recorded. */
function harness(replies, { csrf = CSRF, round = 200 } = {}) {
  const calls = [];
  const clock = { perf: 0, wall: 1_000 };
  const queue = [...replies];
  const call = async (path, init = {}) => {
    calls.push({ path, init });
    const reply = queue.shift() ?? { status: 0, body: null };
    return { body: null, date: null, sentAt: clock.wall - round, receivedAt: clock.wall, perfAt: clock.perf, ...reply };
  };
  return { calls, clock, call, now: () => ({ ...clock }), csrfToken: () => csrf };
}

function flowFor(h, extra = {}) {
  return createFleetFlow({ ctx: CTX, call: h.call, now: h.now, csrfToken: h.csrfToken, ...extra });
}

async function openPayload(f, payload) {
  const decode = (value) => Uint8Array.from(Buffer.from(value, "base64url")).buffer;
  const aad = browserProvisioningAad(f.binding);
  return new TextDecoder().decode(await suite.open({ recipientKey: f.recipient.privateKey, enc: decode(payload.enc) }, decode(payload.ciphertext), aad.buffer));
}

test("P05-PV06-S GUI: the metadata read is a same-origin credentialed GET on the fleet route with only the metadata signature", async () => {
  const f = await fixture();
  const h = harness([{ status: 200, body: ready(f) }]);
  const outcome = await flowFor(h).load();
  assert.equal(outcome.state, "ready");
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].path, `/api/v3/fleet/provisioning/${ID}/metadata?sig=${encodeURIComponent(META_SIG)}`);
  assert.equal(h.calls[0].init.credentials, "same-origin");
  assert.ok(!(h.calls[0].init.method && h.calls[0].init.method !== "GET"));
  assert.ok(!h.calls[0].path.includes("S".repeat(43)), "the submit capability never rides on the metadata read");
});

test("P05-PV06-S GUI: a verified offer shows purpose, workload and destination from independent data with a server-time countdown", async () => {
  const f = await fixture();
  const h = harness([{ status: 200, body: ready(f) }], { round: 200 });
  const outcome = await flowFor(h).load();
  assert.equal(outcome.state, "ready");
  assert.deepEqual(
    { ...outcome.view, deadline: undefined },
    { purpose: "read approved report", workloadName: "report-worker", sourceUnit: f.expected.source_unit, credential: f.expected.credential, deadline: undefined }
  );
  // The device clock is irrelevant: only the controller's milliseconds and the elapsed time count.
  assert.equal(outcome.view.deadline.remaining(h.now()), 30_000 - 200);
  h.clock.perf += 10_000;
  h.clock.wall += 10_000;
  assert.equal(outcome.view.deadline.remaining(h.now()), 20_000 - 200);
});

test("P05-PV06-S GUI: an offer that fails verification against the independent expectations never opens entry", async () => {
  const mutations = [
    (body) => { body.offer.body.credential = "changed-source"; },
    (body) => { body.expected.source_unit = "blindpass-login@other.service"; },
    (body) => { body.expected.grant.operation_id = "op_other-operation"; },
    (body) => { body.expected.signing_public = "A".repeat(43); },
    (body) => { body.offer.sig = "A".repeat(86); },
    (body) => { body.expected.node_key_version = 2; },
    (body) => { body.offer.extra = "unexpected"; },
    // The metadata deadline must be the offer's own deadline.
    (body) => { body.expires_at_ms += 1_000; },
    // A deadline already behind the controller's own clock is not an offer.
    (body) => { body.server_time_ms = body.expires_at_ms + 1; }
  ];
  for (const [index, mutate] of mutations.entries()) {
    const f = await fixture();
    const body = ready(f);
    body.offer = structuredClone(body.offer);
    body.expected = structuredClone(body.expected);
    mutate(body);
    const h = harness([{ status: 200, body }]);
    const flow = flowFor(h);
    const outcome = await flow.load();
    assert.ok(["invalid", "error", "expired"].includes(outcome.state), `${index}: ${JSON.stringify(outcome)}`);
    assert.notEqual(outcome.state, "ready", String(index));
    assert.equal(outcome.view, undefined);
    // Without a verified offer there is nothing to seal to.
    assert.deepEqual((await flow.submit(TYPED)).state, "invalid");
    assert.equal(h.calls.length, 1, `${index}: only the metadata read was sent`);
  }
});

test("P05-PV06-S GUI: malformed metadata bodies are a load failure, never a ready state", async () => {
  const f = await fixture();
  for (const change of [{ summary: null }, { summary: { purpose: 1, workload_name: "w" } }, { summary: { purpose: "p" } }, { offer: null }, { expected: null }, { server_time_ms: "now" }, { expires_at_ms: null }]) {
    const h = harness([{ status: 200, body: ready(f, change) }]);
    const outcome = await flowFor(h).load();
    assert.notEqual(outcome.state, "ready", JSON.stringify(change));
  }
});

test("P05-PV06-S GUI: sign-in, unavailable and expired answers map to fixed states without a ready view", async () => {
  const cases = [
    [401, { state: "auth" }],
    [403, { state: "auth" }],
    [404, { state: "invalid", reason: "load" }],
    [410, { state: "expired", reason: "load" }],
    [500, { state: "error" }],
    [0, { state: "error" }]
  ];
  for (const [status, expected] of cases) {
    const h = harness([{ status, body: null }]);
    assert.deepEqual(await flowFor(h).load(), expected, String(status));
  }
  const f = await fixture();
  const h = harness([{ status: 200, body: { status: "submitted", offer_id: "pv", ciphertext_digest: "a".repeat(64), delivery_digest: "b".repeat(64), submitted_at_ms: 1, expires_at_ms: 2 } }]);
  assert.deepEqual(await flowFor(h).load(), { state: "used", reason: "load" });
  void f;
});

test("P05-PV06-S GUI: submit seals the exact typed bytes to the verified offer and posts only enc and ciphertext with the CSRF header", async () => {
  const f = await fixture();
  const h = harness([{ status: 200, body: ready(f) }, { status: 201, body: { status: "submitted" } }]);
  const flow = flowFor(h);
  assert.equal((await flow.load()).state, "ready");
  h.clock.perf += 5_000;
  h.clock.wall += 5_000;
  const outcome = await flow.submit(TYPED);
  assert.deepEqual(outcome, { state: "submitted" });
  assert.equal(h.calls.length, 2);
  const post = h.calls[1];
  assert.equal(post.path, `/api/v3/fleet/provisioning/${ID}/submit?sig=${encodeURIComponent(SUBMIT_SIG)}`);
  assert.equal(post.init.method, "POST");
  assert.equal(post.init.credentials, "same-origin");
  const headers = Object.fromEntries(Object.entries(post.init.headers).map(([name, value]) => [name.toLowerCase(), value]));
  assert.equal(headers["x-csrf-token"], CSRF);
  assert.equal(headers["content-type"], "application/json");
  assert.deepEqual(Object.keys(headers).sort(), ["content-type", "x-csrf-token"]);
  assert.ok(!post.path.includes(CSRF) && !post.path.includes(META_SIG), "no cookie or CSRF value in the URL");
  const payload = JSON.parse(post.init.body);
  assert.deepEqual(Object.keys(payload).sort(), ["ciphertext", "enc"]);
  // The plaintext is only inside the ciphertext, byte for byte, leading space included.
  for (const text of [post.path, post.init.body, JSON.stringify(headers)]) {
    assert.ok(!text.includes(CANARY));
    assert.ok(!text.includes(encodeURIComponent(CANARY)));
  }
  assert.equal(await openPayload(f, payload), TYPED);
  assert.ok((await openPayload(f, payload)).startsWith(" "));
});

test("P05-PV06-S GUI: the server's clock, not Date.now, is the time the offer is sealed against", async () => {
  const f = await fixture();
  const seen = [];
  const h = harness([{ status: 200, body: ready(f) }, { status: 201, body: { status: "submitted" } }], { round: 200 });
  const flow = flowFor(h, {
    seal: async (offer, expected, value, nowMs) => {
      seen.push(nowMs);
      return { enc: "A".repeat(43), ciphertext: "B".repeat(48) };
    }
  });
  await flow.load();
  // The wall clock jumped a year ahead while only 7 s of monotonic time passed.
  h.clock.perf += 7_000;
  h.clock.wall += 365 * 24 * 3600 * 1000;
  const outcome = await flow.submit(TYPED);
  assert.equal(outcome.state, "expired", "the larger elapsed time (the jump) expires the offer before anything is sealed");
  assert.deepEqual(seen, []);
  const g = harness([{ status: 200, body: ready(f) }, { status: 201, body: {} }], { round: 200 });
  const other = flowFor(g, { seal: async (offer, expected, value, nowMs) => { seen.push(nowMs); return { enc: "A".repeat(43), ciphertext: "B".repeat(48) }; } });
  await other.load();
  g.clock.perf += 7_000;
  g.clock.wall += 7_000;
  await other.submit(TYPED);
  assert.deepEqual(seen, [SERVER_NOW + 200 + 7_000]);
  assert.ok(Number.isSafeInteger(seen[0]));
});

test("P05-PV06-S GUI: no CSRF cookie, an elapsed deadline, an empty value or one over 64 KiB send nothing", async () => {
  const f = await fixture();
  // No CSRF cookie: the operator session is not usable from this page.
  let h = harness([{ status: 200, body: ready(f) }], { csrf: null });
  let flow = flowFor(h);
  await flow.load();
  assert.deepEqual(await flow.submit(TYPED), { state: "auth" });
  assert.equal(h.calls.length, 1);

  // The offer ended while the page was open.
  h = harness([{ status: 200, body: ready(f) }]);
  flow = flowFor(h);
  await flow.load();
  h.clock.perf += 31_000;
  h.clock.wall += 31_000;
  assert.deepEqual(await flow.submit(TYPED), { state: "expired", reason: "whileOpen" });
  assert.equal(h.calls.length, 1);

  // Empty and oversize values are refused locally and keep the field.
  h = harness([{ status: 200, body: ready(f) }]);
  flow = flowFor(h);
  await flow.load();
  assert.deepEqual(await flow.submit(""), { state: "ready", error: "empty" });
  assert.deepEqual(await flow.submit("x".repeat(FLEET_MAX_SOURCE_BYTES + 1)), { state: "ready", error: "tooLarge" });
  // 21,846 three-byte characters are 65,538 bytes: bytes, not characters, count.
  assert.deepEqual(await flow.submit("漢".repeat(21_846)), { state: "ready", error: "tooLarge" });
  assert.equal(FLEET_MAX_SOURCE_BYTES, 65_536);
  assert.equal(h.calls.length, 1);
});

test("P05-PV06-S GUI: exactly 64 KiB seals and posts; the limit is the sealer's own", async () => {
  const f = await fixture();
  const h = harness([{ status: 200, body: ready(f) }, { status: 201, body: {} }]);
  const flow = flowFor(h);
  await flow.load();
  const value = "k".repeat(FLEET_MAX_SOURCE_BYTES);
  assert.deepEqual(await flow.submit(value), { state: "submitted" });
  assert.equal((await openPayload(f, JSON.parse(h.calls[1].init.body))).length, FLEET_MAX_SOURCE_BYTES);
});

test("P04-E03 / P05-PV06-S GUI: refusals, conflicts and lost replies map to the documented states and never echo the value", async () => {
  const cases = [
    [201, { state: "submitted" }],
    [200, { state: "submitted" }],
    [409, { state: "used", reason: "conflict" }],
    [410, { state: "expired", reason: "submit" }],
    [401, { state: "auth" }],
    [403, { state: "auth" }],
    [400, { state: "ready", error: "rejected" }],
    [413, { state: "ready", error: "tooLarge" }],
    [429, { state: "ready", error: "rateLimited" }],
    [0, { state: "unknown" }],
    [502, { state: "unknown" }]
  ];
  for (const [status, expected] of cases) {
    const f = await fixture();
    const h = harness([{ status: 200, body: ready(f) }, { status, body: { error: "provisioning_ciphertext_conflict", message: CANARY } }]);
    const flow = flowFor(h);
    await flow.load();
    const outcome = await flow.submit(TYPED);
    assert.deepEqual(outcome, expected, String(status));
    assert.ok(!JSON.stringify(outcome).includes(CANARY), String(status));
  }
});

test("P04-I03 / P05-PV06-S GUI: after a lost reply one metadata re-read decides: a receipt confirms, none stays not confirmed", async () => {
  const receipt = { status: "submitted", offer_id: "pv", ciphertext_digest: "a".repeat(64), delivery_digest: "b".repeat(64), submitted_at_ms: 1, expires_at_ms: 2 };
  const cases = [
    [{ status: 200, body: receipt }, "submitted"],
    [{ status: 200, body: { status: "ready" } }, "pending"],
    [{ status: 410, body: null }, "gone"],
    [{ status: 404, body: null }, "gone"],
    [{ status: 403, body: null }, "auth"],
    [{ status: 0, body: null }, "unavailable"],
    [{ status: 503, body: null }, "unavailable"]
  ];
  for (const [reply, expected] of cases) {
    const f = await fixture();
    const h = harness([{ status: 200, body: ready(f) }, { status: 0, body: null }, reply]);
    const flow = flowFor(h);
    await flow.load();
    assert.deepEqual(await flow.submit(TYPED), { state: "unknown" });
    assert.equal(await flow.reconcile(), expected, JSON.stringify(reply));
    // Exactly one POST and one re-read: nothing is resubmitted automatically.
    assert.deepEqual(h.calls.map((call) => call.init.method ?? "GET"), ["GET", "POST", "GET"]);
    assert.equal(h.calls[2].init.credentials, "same-origin");
    assert.equal(h.calls[2].path, h.calls[0].path);
  }
});

test("P05-PV06-S GUI: a sealing failure keeps the value and exposes only a fixed state, never the upstream message", async () => {
  const f = await fixture();
  for (const [message, expected] of [
    ["invalid_provisioning_offer", { state: "expired", reason: "whileOpen" }],
    ["invalid_provisioning_binding", { state: "expired", reason: "whileOpen" }],
    ["provisioning_encryption_failed", { state: "ready", error: "encryption" }],
    [`unexpected ${CANARY}`, { state: "ready", error: "encryption" }]
  ]) {
    const h = harness([{ status: 200, body: ready(f) }]);
    const flow = flowFor(h, { seal: async () => { throw new Error(message); } });
    await flow.load();
    const outcome = await flow.submit(TYPED);
    assert.deepEqual(outcome, expected, message);
    assert.ok(!JSON.stringify(outcome).includes(CANARY));
    assert.equal(h.calls.length, 1, "nothing was sent");
  }
});
