// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyBrowserRecipientOffer, sealVerifiedBrowserSource } from '../src/fleet-provisioning.js';

const binding = JSON.parse(await readFile(new URL('./fixtures/fleet-provisioning-v1.json', import.meta.url)));
const sort = value => value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])) : value;
function fixture() {
  const keys = generateKeyPairSync('ed25519');
  const envelope = { v: 1, kind: 'recipient_offer', kid: 'nd_node-a-1', epoch: 1, body: structuredClone(binding) };
  const bytes = Buffer.from(`blindpass:fleet-document:v1\0${JSON.stringify(sort(envelope))}`);
  const offer = { ...envelope, sig: sign(null, bytes, keys.privateKey).toString('base64url') };
  const expected = { grant: structuredClone(binding.grant), node_key_version: 1,
    source_unit: binding.source_unit, credential: binding.credential,
    signing_public: keys.publicKey.export({ format: 'jwk' }).x };
  return { offer, expected };
}
test('PV05-S03 correct pinned key/context returns immutable binding and snapshots original data', async () => {
  const { offer, expected } = fixture();
  const value = await verifyBrowserRecipientOffer(offer, expected, binding.issued_at_ms);
  assert.deepEqual(value, binding); assert.equal(Object.isFrozen(value), true); assert.equal(Object.isFrozen(value.grant), true);
  offer.body.credential = 'changed'; expected.grant.operation_id = 'op_other';
  assert.equal(value.credential, binding.credential); assert.equal(value.grant.operation_id, binding.grant.operation_id);
});
test('PV05-S02 signature/body/kind/kid/epoch/field mutation is rejected before sealing', async () => {
  for (const mutate of [o => { o.body.credential = 'other'; }, o => { o.body.grant.operation_id = 'op_other'; },
    o => { o.kind = 'audit_event'; }, o => { o.kid = 'nd_other-1'; }, o => { o.epoch = 2; },
    o => { o.sig = 'A'.repeat(86); }, o => { o.rawLink = 'PV-OFFER-PRIVATE-CANARY'; }]) {
    const { offer, expected } = fixture(); mutate(offer);
    await assert.rejects(sealVerifiedBrowserSource(offer, expected, 'DUMMY', binding.issued_at_ms), { message: 'invalid_provisioning_offer' });
  }
});
test('PV05-S03 independently trusted identity/context cannot be replaced with offer supplied trust', async () => {
  for (const mutate of [e => { e.signing_public = fixture().expected.signing_public; },
    e => { e.grant.operation_id = 'op_other'; }, e => { e.source_unit = 'other.service'; },
    e => { e.credential = 'other'; }, e => { e.node_key_version = 2; },
    e => { e.grant.node_id = 'nd_other'; }]) {
    const { offer, expected } = fixture(); mutate(expected);
    await assert.rejects(verifyBrowserRecipientOffer(offer, expected, binding.issued_at_ms), { message: 'invalid_provisioning_offer' });
  }
  const { offer, expected } = fixture();
  for (const now of [binding.issued_at_ms - 1, binding.expires_at_ms, NaN, Infinity]) {
    await assert.rejects(verifyBrowserRecipientOffer(offer, expected, now), { message: 'invalid_provisioning_offer' });
  }
});
