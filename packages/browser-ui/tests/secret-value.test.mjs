import assert from "node:assert/strict";
import test from "node:test";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { sealBase64 } from "../src/crypto.js";
import { MAX_SECRET_BYTES, formatBytes, hasLineBreak, secretBytes } from "../src/secret-value.js";

const suite = new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Chacha20Poly1305 });

async function recipient() {
  const pair = await suite.kem.generateKeyPair();
  const raw = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { pair, publicKey: Buffer.from(raw).toString("base64") };
}

async function open(pair, payload) {
  const plain = await suite.open({ recipientKey: pair.privateKey, enc: Buffer.from(payload.enc, "base64") }, Buffer.from(payload.ciphertext, "base64"));
  return new Uint8Array(plain);
}

test("SI-E03: values are encoded exactly as typed, whitespace and all", () => {
  for (const value of ["  padded  ", "\ttab", "trailing newline\n", "é ö ơ đ 漢字 🔑", "a\u0000b"]) {
    assert.deepEqual(secretBytes(value), new TextEncoder().encode(value), JSON.stringify(value));
  }
  assert.equal(secretBytes("é").length, 2);
});

test("line breaks are detected for the multiline guard", () => {
  assert.equal(hasLineBreak("one line"), false);
  assert.equal(hasLineBreak("a\nb"), true);
  assert.equal(hasLineBreak("a\r\nb"), true);
  assert.equal(hasLineBreak("a\rb"), true);
});

test("SI-I01 (unit): HPKE seal opens to the exact bytes for the intended key only", async () => {
  const intended = await recipient();
  const other = await recipient();
  const value = "-----BEGIN KEY-----\nline two  \n\n  indented\n-----END KEY-----\n";
  const payload = await sealBase64(intended.publicKey, value);
  assert.deepEqual(await open(intended.pair, payload), new TextEncoder().encode(value));
  await assert.rejects(open(other.pair, payload));
});

test("the size limit matches the controller's 524,288-character ciphertext cap exactly", async () => {
  const { publicKey } = await recipient();
  const atLimit = await sealBase64(publicKey, "x".repeat(MAX_SECRET_BYTES));
  assert.ok(atLimit.ciphertext.length <= 524_288, String(atLimit.ciphertext.length));
  const over = await sealBase64(publicKey, "x".repeat(MAX_SECRET_BYTES + 1));
  assert.ok(over.ciphertext.length > 524_288, String(over.ciphertext.length));
});

test("formatBytes is readable in both locales", () => {
  assert.equal(formatBytes(512, "en"), "512 B");
  assert.equal(formatBytes(MAX_SECRET_BYTES, "en"), "384 KB");
  assert.equal(formatBytes(1536, "vi"), "1,5 KB");
});
