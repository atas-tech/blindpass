// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { build } from 'esbuild';
import { chromium } from 'playwright';
import { recipientProbe } from './provisioning-offer-probe.mjs';

test('PV05-S04 actual sandboxed Chromium verifies native signature and seals before Rust opens', { timeout: 30_000 }, async () => {
  const bundle = await build({ entryPoints: [new URL('../../packages/browser-ui/src/fleet-provisioning.js', import.meta.url).pathname],
    bundle: true, write: false, platform: 'browser', format: 'esm', target: 'es2022' });
  const server = createServer((req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.url === '/') { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Operator crypto probe</title>'); }
    else if (req.url === '/fleet-provisioning.js') { res.setHeader('Content-Type', 'text/javascript'); res.end(bundle.outputFiles[0].contents); }
    else { res.statusCode = 404; res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const probe = recipientProbe(); let browser;
  try {
    const ready = await probe.metadata;
    browser = await chromium.launch({ headless: true, chromiumSandbox: true });
    const context = await browser.newContext({ serviceWorkers: 'block' });
    const page = await context.newPage(); const consoleMessages = []; const errors = [];
    page.on('console', message => consoleMessages.push(message.text())); page.on('pageerror', error => errors.push(error.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const value = await page.evaluate(async ready => {
      const lib = await import('/fleet-provisioning.js'); const now = ready.binding.issued_at_ms;
      const verified = await lib.verifyBrowserRecipientOffer(ready.offer, ready.expected, now);
      const changed = structuredClone(ready.offer); changed.body.credential = 'foreign-credential';
      let rejected = false;
      try { await lib.sealVerifiedBrowserSource(changed, ready.expected, 'DUMMY', now); }
      catch (error) { rejected = error.message === 'invalid_provisioning_offer'; }
      return { secure: window.isSecureContext, frozen: Object.isFrozen(verified) && Object.isFrozen(verified.grant), rejected,
        payload: await lib.sealVerifiedBrowserSource(ready.offer, ready.expected, '  DUMMY-PV-SOURCE é 漢字 🔑\n', now) };
    }, ready);
    assert.equal(value.secure, true); assert.equal(value.frozen, true); assert.equal(value.rejected, true);
    await probe.submit(value.payload);
    assert.deepEqual(errors, []); assert.deepEqual(consoleMessages, []);
  } finally { await browser?.close(); probe.dispose(); await new Promise(resolve => server.close(resolve)); }
});
