// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { test } from 'node:test';
import { certificateSpkiPin, verifyPinnedLeaf } from '../../helpers/login/src/certificate-pins.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';

const der = (pem) => new X509Certificate(pem).raw.toString('base64');
async function material(options) {
  const tls = await createTestTls(options);
  const leaf = new X509Certificate(tls.cert);
  const ca = new X509Certificate(tls.ca);
  await tls.close();
  return { chain: [der(tls.cert), der(tls.ca)], pin: certificateSpkiPin(leaf), caPin: certificateSpkiPin(ca), leaf };
}
const rejects = (input) => assert.throws(() => verifyPinnedLeaf(input), (error) => error.message === 'certificate_rejected');

test('P05-H pinned leaf: matching pin, hostname/IP and validity pass; the chain is not consulted', async () => {
  const { chain, pin, leaf } = await material();
  const now = Date.parse(leaf.validFrom) + 60_000;
  for (const origin of ['https://localhost', 'https://localhost:8443', 'https://127.0.0.1:8443']) verifyPinnedLeaf({ chain, origin, pins: [pin], now });
  verifyPinnedLeaf({ chain: [chain[0]], origin: 'https://localhost', pins: ['A'.repeat(43) + '=', pin], now });
});

test('P05-H a pin that is not the served leaf SPKI fails, including the CA pin and other keys', async () => {
  const { chain, pin, caPin, leaf } = await material(); const other = await material();
  const now = Date.parse(leaf.validFrom) + 60_000;
  for (const pins of [[other.pin], [caPin], ['A'.repeat(43) + '='], []]) rejects({ chain, origin: 'https://localhost', pins, now });
  verifyPinnedLeaf({ chain, origin: 'https://localhost', pins: [other.pin, pin], now });
});

test('P05-H a matching pin never excuses a wrong host, an expired or a not-yet-valid certificate', async () => {
  const fresh = await material(); const wrongHost = await material({ dnsNames: ['other.example.test'], ipAddresses: [] });
  const expired = await material({ expired: true });
  const now = Date.parse(fresh.leaf.validFrom) + 60_000;
  rejects({ chain: wrongHost.chain, origin: 'https://localhost', pins: [wrongHost.pin], now });
  rejects({ chain: wrongHost.chain, origin: 'https://127.0.0.1', pins: [wrongHost.pin], now });
  verifyPinnedLeaf({ chain: wrongHost.chain, origin: 'https://other.example.test', pins: [wrongHost.pin], now });
  rejects({ chain: expired.chain, origin: 'https://localhost', pins: [expired.pin], now });
  verifyPinnedLeaf({ chain: expired.chain, origin: 'https://localhost', pins: [expired.pin], now: Date.parse('2020-01-01T12:00:00Z') });
  rejects({ chain: fresh.chain, origin: 'https://localhost', pins: [fresh.pin], now: Date.parse(fresh.leaf.validFrom) - 1_000 });
  rejects({ chain: fresh.chain, origin: 'https://localhost', pins: [fresh.pin], now: Date.parse(fresh.leaf.validTo) });
});

test('P05-H empty, malformed or oversized certificate input fails closed without detail', async () => {
  const { chain, pin, leaf } = await material(); const now = Date.parse(leaf.validFrom) + 60_000;
  for (const bad of [[], undefined, null, [''], ['not base64!'], [chain[0].slice(0, 100)], [42], [chain[0]].concat(Array(10).fill(chain[1])), { 0: chain[0] }]) {
    rejects({ chain: bad, origin: 'https://localhost', pins: [pin], now });
  }
  for (const origin of ['http://localhost', 'localhost', undefined, 'https://']) rejects({ chain, origin, pins: [pin], now });
  rejects({ chain, origin: 'https://localhost', pins: [pin], now: NaN });
  rejects({ chain, origin: 'https://localhost', pins: undefined, now });
});
