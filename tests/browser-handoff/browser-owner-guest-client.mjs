// SPDX-License-Identifier: AGPL-3.0-only
// Disposable workload parent stays alive while its actual requesting child dies.
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { createConnection, createServer } from 'node:net';
import { chmod } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const base = '/run/p05-browser-owner/agent';
const unit = 'p05-browser-owner-agent.service';
const invocation = process.env.INVOCATION_ID;
assert.match(invocation, /^[a-f0-9]{32}$/);

async function work(operation) {
  return new Promise((resolve, reject) => {
    const socket = createConnection('/run/blindpass/workload.sock');
    const chunks = [];
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('work_deadline')); }, 3000);
    socket.on('connect', () => socket.end(`WORK node-a workload-a ${unit} ${invocation} ${operation}\n`));
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('error', () => { clearTimeout(timer); reject(new Error('work_failed')); });
    socket.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString()); });
  });
}

if (process.argv[2] === 'child') {
  process.on('message', async message => {
    try { process.send({ reply: await work(message.operation) }); }
    catch { process.send({ failed: true }); }
  });
} else {
  const children = new Map();
  async function dispatch(command) {
    assert.match(command.id, /^[a-z0-9]{1,16}$/);
    if (command.action === 'spawn') {
      assert.ok(!children.has(command.id) && children.size < 8);
      const child = fork(fileURLToPath(import.meta.url), ['child'], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
      children.set(command.id, child);
      return { spawned: true };
    }
    const child = children.get(command.id);
    assert.ok(child);
    if (command.action === 'kill') {
      const closed = new Promise(resolve => child.once('close', resolve));
      child.kill('SIGKILL');
      await closed;
      children.delete(command.id);
      return { stopped: true };
    }
    assert.equal(command.action, 'work');
    assert.equal(typeof command.operation, 'string');
    assert.ok(command.operation.length <= 1800 && !/[\r\n]/.test(command.operation));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { child.removeListener('message', receive); reject(new Error('child_deadline')); }, 4000);
      function receive(reply) { clearTimeout(timer); resolve(reply); }
      child.once('message', receive);
      child.send({ operation: command.operation });
    });
  }
  const server = createServer({ allowHalfOpen: true }, socket => {
    let data = '';
    const timer = setTimeout(() => socket.destroy(), 5000);
    socket.on('data', chunk => { data += chunk; if (data.length > 4096) socket.destroy(); });
    socket.on('end', async () => {
      try { socket.end(JSON.stringify(await dispatch(JSON.parse(data)))); }
      catch { socket.end(JSON.stringify({ failed: true })); }
      finally { clearTimeout(timer); }
    });
  });
  server.listen(`${base}/driver.sock`, async () => { await chmod(`${base}/driver.sock`, 0o600); });
}
