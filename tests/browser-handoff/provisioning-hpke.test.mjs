// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { browserProvisioningAad, sealBrowserSource } from '../../packages/browser-ui/src/fleet-provisioning.js';
import { sealBase64 } from '../../packages/browser-ui/src/crypto.js';

const plaintext = '  DUMMY-PV-SOURCE é 漢字 🔑\n';
const fixture = JSON.parse(await readFile(new URL('../../packages/browser-ui/tests/fixtures/fleet-provisioning-v1.json', import.meta.url)));
for (const variant of ['original', 'destination', 'operation', 'offer', 'wrong-recipient', 'legacy-empty-aad', 'partial']) {
  test(`P05-PV01/PV04 actual browser-to-Rust HPKE ${variant}`, { timeout: 10_000 }, async () => {
    const child = spawn(new URL('../../target/debug/examples/provisioning-hpke-probe', import.meta.url).pathname, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    let first; let rejectFirst; const metadata = new Promise((resolve, reject) => { first = resolve; rejectFirst = reject; });
    const lines = []; let stderr = ''; let bytes = 0;
    const closed = new Promise((resolve, reject) => { child.once('close', resolve); child.once('error', error => { rejectFirst(error); reject(error); }); });
    closed.catch(() => {});
    createInterface({ input: child.stdout }).on('line', line => {
      bytes += line.length;
      if (bytes > 32_768) { child.kill('SIGKILL'); rejectFirst(new Error('probe output bounded')); return; }
      if (!lines.length) { try { first(JSON.parse(line)); } catch { rejectFirst(new Error('probe metadata invalid')); } }
      lines.push(line);
    });
    child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 1024) child.kill('SIGKILL'); });
    const timer = setTimeout(() => { child.kill('SIGKILL'); rejectFirst(new Error('probe deadline')); }, 5000);
    try {
      const ready = await metadata;
      assert.deepEqual(Buffer.from(ready.aad, 'base64url'), Buffer.from(browserProvisioningAad(ready.binding)));
      let payload;
      if (variant === 'legacy-empty-aad') {
        const legacy = await sealBase64(Buffer.from(ready.binding.recipient_public, 'base64url').toString('base64'), plaintext);
        payload = Object.fromEntries(Object.entries(legacy).map(([key, value]) => [key, Buffer.from(value, 'base64').toString('base64url')]));
      } else {
        const binding = structuredClone(ready.binding);
        if (variant === 'destination') binding.credential = 'other-credential';
        if (variant === 'operation') binding.grant.operation_id = 'op_other';
        if (variant === 'offer') binding.offer_id = 'offer_different_0001';
        if (variant === 'wrong-recipient') binding.recipient_public = fixture.recipient_public;
        payload = await sealBrowserSource(binding, plaintext, binding.issued_at_ms);
        if (variant === 'partial') payload.ciphertext = Buffer.from(payload.ciphertext, 'base64url').subarray(0, -1).toString('base64url');
      }
      child.stdin.end(`${JSON.stringify(payload)}\n`);
      const code = await closed;
      assert.equal(code, variant === 'original' ? 0 : 1);
      assert.equal(lines.slice(1).join('\n'), variant === 'original' ? 'PROVISIONING-HPKE-PROBE accepted' : '');
      assert.equal(stderr, variant === 'original' ? '' : 'PROVISIONING-HPKE-PROBE denied stage=open\n');
      assert.ok(!lines.join('\n').includes('DUMMY-PV-SOURCE')); assert.ok(!stderr.includes('DUMMY-PV-SOURCE'));
    } finally { clearTimeout(timer); child.kill(); }
  });
}
