// SPDX-License-Identifier: AGPL-3.0-only
// The worker connects itself: kernel SO_PEERPIDFD identifies this process,
// rather than systemd's socket activation listener. No selectable endpoint.
import { connect } from 'node:net';
import { lstat } from 'node:fs/promises';

const SOCKET = '/run/blindpass-runtime/identity.sock';
const unavailable = () => new Error('runtime_identity_unavailable');

export function validateRuntimeIdentityMetadata(parent, socket, uid, groups) {
  if (uid === 0 || !parent.isDirectory() || parent.uid !== 0 || parent.gid === 0
    || (parent.mode & 0o7777) !== 0o750 || !groups.includes(parent.gid)
    || !socket.isSocket() || socket.uid !== 0 || socket.gid !== parent.gid
    || (socket.mode & 0o7777) !== 0o660 || socket.nlink !== 1) throw unavailable();
}

export function encodeRuntimeIdentityProof(challenge) {
  if (typeof challenge !== 'string' || !/^[a-f0-9]{64}$/.test(challenge)) throw unavailable();
  const bytes = Buffer.from(JSON.stringify({ version: 1, challenge }));
  const frame = Buffer.alloc(4 + bytes.length);
  frame.writeUInt32BE(bytes.length); bytes.copy(frame, 4); bytes.fill(0);
  return frame;
}

export async function proveRuntimeIdentity(challenge) {
  return proveIdentity(challenge, '/run/blindpass-runtime', SOCKET);
}

// Separate fixed socket/group boundary from the workload browser. Neither
// entry point accepts an endpoint or claimed manager identity.
export async function proveHelperIdentity(challenge) {
  return proveIdentity(challenge, '/run/blindpass-helper-identity', '/run/blindpass-helper-identity/identity.sock');
}

async function proveIdentity(challenge, parentPath, socketPath) {
  let frame;
  try {
    frame = encodeRuntimeIdentityProof(challenge); challenge = '';
    const parent = await lstat(parentPath);
    const metadata = await lstat(socketPath);
    validateRuntimeIdentityMetadata(parent, metadata, process.getuid(), [...process.getgroups(), process.getgid()]);
    await new Promise((resolve, reject) => {
      const reply = Buffer.alloc(64); let used = 0; let finished = false;
      const socket = connect({ path: socketPath, allowHalfOpen: true });
      const timer = setTimeout(() => finish(false), 3000);
      const finish = (success) => {
        if (finished) return; finished = true; clearTimeout(timer);
        socket.destroy(); reply.fill(0); frame.fill(0);
        if (success) resolve(); else reject(unavailable());
      };
      socket.on('error', () => finish(false));
      socket.once('connect', () => socket.end(frame, () => frame.fill(0)));
      socket.on('data', (bytes) => {
        if (used + bytes.length > reply.length) { bytes.fill(0); finish(false); return; }
        bytes.copy(reply, used); used += bytes.length; bytes.fill(0);
      });
      socket.once('end', () => finish(reply.subarray(0, used).equals(Buffer.from('OK runtime_identity\n'))));
      socket.once('close', () => { if (!finished) finish(false); });
    });
  } catch { throw unavailable(); }
  finally { frame?.fill(0); challenge = ''; }
}
