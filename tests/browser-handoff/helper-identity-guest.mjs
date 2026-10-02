// SPDX-License-Identifier: AGPL-3.0-only
// Actual systemd helper proof. No credential or website job is supplied.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { connect } from 'node:net';
import { createInterface } from 'node:readline';
import { frame, decode } from './worker-harness.mjs';

const uid = Number(execFileSync('/usr/bin/id', ['-u', 'blindpass-login'], { encoding: 'utf8' }).trim());
const group = Number(execFileSync('/usr/bin/id', ['-g', 'blindpass-login'], { encoding: 'utf8' }).trim());
const child = spawn('/usr/lib/blindpass/login/blindpass-runtime-identity-probe', [], { stdio: ['pipe', 'pipe', 'pipe', 'pipe'] });
const closed = new Promise((resolve) => child.once('close', resolve));
let errors = 0; let socket; let challenge = ''; let stage = 'ready';
const messages = []; const waiters = new Map();
child.stdin.on('error', () => {});
child.stderr.on('data', (bytes) => { errors += bytes.length; bytes.fill(0); });
createInterface({ input: child.stdout }).on('line', (line) => {
  try {
    const value = JSON.parse(line); const waiter = waiters.get(value.type);
    if (waiter) { waiters.delete(value.type); waiter(value); } else messages.push(value);
  } catch { child.kill(); }
});
function next(type) {
  const index = messages.findIndex((value) => value.type === type);
  if (index >= 0) return Promise.resolve(messages.splice(index, 1)[0]);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { waiters.delete(type); reject(new Error('helper proof deadline')); }, 20_000);
    waiters.set(type, (value) => { clearTimeout(timer); resolve(value); });
  });
}
const privateChallenge = new Promise((resolve, reject) => {
  const chunks = []; let used = 0;
  child.stdio[3].on('data', (bytes) => { used += bytes.length; if (used <= 64) chunks.push(bytes); else { bytes.fill(0); child.kill(); } });
  child.stdio[3].once('end', () => {
    const bytes = Buffer.concat(chunks);
    try {
      const value = bytes.toString(); if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('invalid proof');
      resolve(value);
    } catch { reject(new Error('helper proof unavailable')); }
    finally { bytes.fill(0); for (const chunk of chunks) chunk.fill(0); }
  });
});
async function wrongUnit(name) {
  const python = 'import socket,json,sys,struct\ns=socket.socket(socket.AF_UNIX)\ns.settimeout(5)\ns.connect("/run/blindpass-helper-identity/identity.sock")\nb=json.dumps({"version":1,"challenge":sys.stdin.read()}).encode()\ns.sendall(struct.pack("!I",len(b))+b)\ns.shutdown(socket.SHUT_WR)\nassert s.recv(64)==b"ERR runtime_identity_denied\\n"\nprint("helper_other_unit_denied")';
  const other = spawn('/usr/bin/systemd-run', ['--quiet', '--wait', '--pipe', '--collect', `--unit=${name}`,
    '-p', 'User=blindpass-login', '-p', 'Group=blindpass-login', '-p', 'RuntimeMaxSec=8s', '-p', 'LimitCORE=0',
    '/usr/bin/python3', '-c', python], { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = ''; let diagnostics = 0;
  other.stdin.on('error', () => {});
  other.stdout.on('data', (bytes) => { output += bytes; bytes.fill(0); });
  other.stderr.on('data', (bytes) => { diagnostics += bytes.length; bytes.fill(0); });
  const bytes = Buffer.from(challenge); other.stdin.end(bytes, () => bytes.fill(0));
  assert.equal(await new Promise((resolve) => other.once('close', resolve)), 0);
  assert.equal(diagnostics, 0); assert.equal(output.trim(), 'helper_other_unit_denied');
}
const timer = setTimeout(() => { socket?.destroy(); child.kill('SIGKILL'); }, 30_000);
try {
  child.stdin.write(`${JSON.stringify({ version: 2, uid, group, workloadUid: 65534, browserUid: 61001 })}\n`);
  await next('identity-ready'); challenge = await privateChallenge;
  stage = 'same-uid-wrong-unit'; await wrongUnit('p05-helper-proof-other');
  stage = 'actual-helper';
  socket = connect({ path: '/run/blindpass-private/login.sock', allowHalfOpen: true });
  socket.on('error', () => {});
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', () => reject(new Error('private helper unavailable'))); });
  const control = frame({ version: 2, challenge }); socket.write(control, () => control.fill(0));
  await next('identity-verified');
  child.stdin.write('check\n'); assert.equal((await next('identity-status')).status, 'alive');
  stage = 'one-use'; await wrongUnit('p05-helper-proof-replay');
  const reply = new Promise((resolve, reject) => {
    const chunks = []; let used = 0;
    socket.on('data', (bytes) => { used += bytes.length; if (used <= 260) chunks.push(bytes); else { bytes.fill(0); socket.destroy(); reject(new Error('private helper reply oversized')); } });
    socket.once('end', () => {
      const bytes = Buffer.concat(chunks);
      try { assert.deepEqual(decode(bytes), { status: 'invalid_request' }); resolve(); }
      catch { reject(new Error('private helper malformed request outcome')); }
      finally { bytes.fill(0); for (const chunk of chunks) chunk.fill(0); }
    });
  });
  const invalid = frame({ version: 0 }); socket.end(invalid, () => invalid.fill(0)); await reply;
  stage = 'held-pidfd-exit';
  let status;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    child.stdin.write('check\n'); status = (await next('identity-status')).status;
    if (status === 'exited') break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(status, 'exited');
  child.stdin.end('stop\n'); assert.equal(await closed, 0); assert.equal(errors, 0);
  console.log('P05-HELPER-IDENTITY-VM actual_reverse_pidfd=verified same_uid_wrong_unit=denied legitimate_ticket=preserved replay=denied held_proof_after_exit=denied source_bytes=0');
} catch { throw new Error(`Helper identity VM failed during ${stage}`); }
finally { clearTimeout(timer); challenge = ''; socket?.destroy(); if (child.exitCode === null) { child.kill('SIGKILL'); await closed; } }
