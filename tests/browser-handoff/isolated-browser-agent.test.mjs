// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { test } from 'node:test';

async function run(command) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['tests/browser-handoff/isolated-browser-agent.mjs'], {
      stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH, HOME: process.env.HOME },
    });
    let stdout = ''; let stderrBytes = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('agent control deadline')); }, 3000);
    child.stdout.on('data', (bytes) => { stdout += bytes.toString(); });
    child.stderr.on('data', (bytes) => { stderrBytes += bytes.length; bytes.fill(0); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout, stderrBytes }); });
    // The real driver's stop command must close its private pipe as well as
    // sending the control line; leaving stdin open keeps Node's handle alive.
    child.stdin.end(`${JSON.stringify(command)}\n`);
  });
}

test('P05-I02 persistent workload test agent stops on private stop plus EOF', async () => {
  const result = await run({ type: 'stop' });
  assert.deepEqual(result, { code: 0, stdout: '{"type":"agent-ready"}\n', stderrBytes: 0 });
});

test('P05-I06 workload test control rejects unknown private commands without reflecting input', async () => {
  const result = await run({ type: 'PRIVATE-CANARY', password: 'PRIVATE-SOURCE-CANARY' });
  assert.deepEqual(result, { code: 64, stdout: '{"type":"agent-ready"}\n', stderrBytes: 0 });
});
