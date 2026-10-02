// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { AeadId, CipherSuite, KdfId, KemId } from 'hpke-js';
import { browserProvisioningAad, sealBrowserSource } from '../src/fleet-provisioning.js';

const fixture = JSON.parse(await readFile(new URL('./fixtures/fleet-provisioning-v1.json', import.meta.url)));
const clone = () => structuredClone(fixture);
const suite = new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Chacha20Poly1305 });
const sort = value => value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])) : value;

test('P05-PV01 browser exact domain/canonical full grant binding', () => {
  const value = browserProvisioningAad(fixture);
  assert.equal(new TextDecoder().decode(value), `blindpass:fleet-browser-source:v1\0${JSON.stringify(sort(fixture))}`);
  assert.ok(value.length < 16_384);
  const reordered = Object.fromEntries(Object.entries(fixture).reverse());
  assert.deepEqual(browserProvisioningAad(reordered), value);
});

test('P05-PV02 schema/key/mode/destination and malformed metadata are rejected with fixed diagnostics', () => {
  for (const change of [{ version: 2 }, { purpose: 'native_password' }, { node_key_version: 2 },
    { source_unit: '../source.service' }, { credential: '../credential' }, { recipient_public: 'A'.repeat(43) },
    { password: 'PV-PRIVATE-CANARY' }, { offer_id: 'x' }, { issued_at_ms: NaN }, { expires_at_ms: Infinity }]) {
    assert.throws(() => browserProvisioningAad({ ...clone(), ...change }), { message: 'invalid_provisioning_binding' });
  }
  for (const value of [null, [], {}, { ...fixture, grant: { ...fixture.grant, mode: 'native_file' } },
    { ...fixture, grant: { ...fixture.grant, private: 'PV-PRIVATE-CANARY' } }]) {
    assert.throws(() => browserProvisioningAad(value), { message: 'invalid_provisioning_binding' });
  }
});

test('P05-PV03 stale/future offer and extended original deadline deny before encryption', async () => {
  for (const now of [fixture.issued_at_ms - 1, fixture.expires_at_ms, NaN, Infinity]) {
    await assert.rejects(sealBrowserSource(fixture, 'DUMMY', now), { message: 'invalid_provisioning_binding' });
  }
  assert.throws(() => browserProvisioningAad({ ...fixture, expires_at_ms: fixture.grant.expires_at_ms + 1 }), /invalid_provisioning_binding/);
});

test('P05-PV04 real browser HPKE preserves exact UTF-8 with bound AAD and rejects changed context', async () => {
  const pair = await suite.kem.generateKeyPair();
  const pub = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  const binding = { ...clone(), recipient_public: Buffer.from(pub).toString('base64url') };
  const plaintext = '  DUMMY-PV-SOURCE é 漢字 🔑\n';
  const payload = await sealBrowserSource(binding, plaintext, binding.issued_at_ms);
  assert.deepEqual(Object.keys(payload).sort(), ['ciphertext', 'enc']);
  assert.ok(!JSON.stringify(payload).includes('DUMMY-PV-SOURCE'));
  const decode = value => Uint8Array.from(Buffer.from(value, 'base64url')).buffer;
  const open = aad => suite.open({ recipientKey: pair.privateKey, enc: decode(payload.enc) }, decode(payload.ciphertext), aad.buffer);
  assert.equal(new TextDecoder().decode(await open(browserProvisioningAad(binding))), plaintext);
  await assert.rejects(open(new Uint8Array()));
  await assert.rejects(open(browserProvisioningAad({ ...binding, credential: 'other-credential' })));
  await assert.rejects(sealBrowserSource(binding, '', binding.issued_at_ms), { message: 'invalid_provisioning_source' });
  await assert.rejects(sealBrowserSource(binding, 'x'.repeat(65537), binding.issued_at_ms), { message: 'invalid_provisioning_source' });
});

test('P05-PV02 nested/accessor metadata cannot reflect upstream private errors', async () => {
  const accessor = clone();
  Object.defineProperty(accessor, 'credential', { enumerable: true, get() { throw new Error('PV-PRIVATE-ERROR-CANARY'); } });
  assert.throws(() => browserProvisioningAad(accessor), { message: 'invalid_provisioning_binding' });
  await assert.rejects(sealBrowserSource(accessor, 'DUMMY', fixture.issued_at_ms), { message: 'invalid_provisioning_binding' });
});
