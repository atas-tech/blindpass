// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { recipientProbe } from './provisioning-offer-probe.mjs';
import { verifyBrowserRecipientOffer, sealVerifiedBrowserSource } from '../../packages/browser-ui/src/fleet-provisioning.js';

for (const variant of ['original', 'body', 'signature', 'trusted-key', 'trusted-operation', 'trusted-destination', 'epoch', 'expired']) {
  test(`PV05-S04 actual Rust-signed offer/WebCrypto/encryption ${variant}`, { timeout: 10_000 }, async () => {
    const probe = recipientProbe();
    try {
      const ready = await probe.metadata; let now = ready.binding.issued_at_ms;
      if (variant === 'body') ready.offer.body.credential = 'other-credential';
      if (variant === 'signature') ready.offer.sig = 'A'.repeat(86);
      if (variant === 'trusted-key') ready.expected.signing_public = ready.binding.recipient_public;
      if (variant === 'trusted-operation') ready.expected.grant.operation_id = 'op_other';
      if (variant === 'trusted-destination') ready.expected.source_unit = 'other.service';
      if (variant === 'epoch') ready.offer.epoch = 2;
      if (variant === 'expired') now = ready.binding.expires_at_ms;
      if (variant === 'original') {
        const verified = await verifyBrowserRecipientOffer(ready.offer, ready.expected, now);
        assert.deepEqual(verified, ready.binding);
        await probe.submit(await sealVerifiedBrowserSource(ready.offer, ready.expected, '  DUMMY-PV-SOURCE é 漢字 🔑\n', now));
      } else {
        await assert.rejects(sealVerifiedBrowserSource(ready.offer, ready.expected, 'DUMMY', now), { message: 'invalid_provisioning_offer' });
        await probe.rejectBeforeDelivery();
      }
    } finally { probe.dispose(); }
  });
}
