// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

export function recipientProbe() {
  const child = spawn(new URL('../../target/debug/examples/provisioning-hpke-probe', import.meta.url).pathname,
    [], { stdio: ['pipe', 'pipe', 'pipe'] });
  let resolveMetadata; let rejectMetadata; let stderr = ''; let bytes = 0; const lines = [];
  const metadata = new Promise((resolve, reject) => { resolveMetadata = resolve; rejectMetadata = reject; });
  const closed = new Promise((resolve, reject) => { child.once('close', resolve); child.once('error', error => { rejectMetadata(error); reject(error); }); });
  closed.catch(() => {});
  createInterface({ input: child.stdout }).on('line', line => {
    bytes += line.length;
    if (bytes > 32_768) { child.kill('SIGKILL'); rejectMetadata(new Error('probe output bounded')); return; }
    if (!lines.length) { try { resolveMetadata(JSON.parse(line)); } catch { rejectMetadata(new Error('probe metadata invalid')); } }
    lines.push(line);
  });
  child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 1024) child.kill('SIGKILL'); });
  const timer = setTimeout(() => { child.kill('SIGKILL'); rejectMetadata(new Error('probe deadline')); }, 5000);
  return { metadata,
    async submit(payload) {
      child.stdin.end(`${JSON.stringify(payload)}\n`); const code = await closed;
      assert.equal(code, 0); assert.equal(lines.slice(1).join('\n'), 'PROVISIONING-HPKE-PROBE accepted'); assert.equal(stderr, '');
      assert.ok(!lines.join('\n').includes('DUMMY-PV-SOURCE'));
    },
    async rejectBeforeDelivery() {
      child.stdin.end(); assert.equal(await closed, 1);
      assert.equal(lines.length, 1); assert.ok(!stderr.includes('DUMMY-PV-SOURCE'));
    },
    dispose() { clearTimeout(timer); child.kill(); }
  };
}
