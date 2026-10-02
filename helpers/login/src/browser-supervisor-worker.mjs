// SPDX-License-Identifier: AGPL-3.0-only
// Root-owned outside supervisor. Fixed inherited fd 3 (embedding) or fd 0
// (installed socket activation) carries private IPC. No normal diagnostics.
import { createHash } from 'node:crypto';
import { Socket, connect, createServer } from 'node:net';
import { fstatSync, readFileSync } from 'node:fs';
import { chmod, lstat, mkdir, rm } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { attachFramedStream, TunnelMux } from './browser-transport.mjs';
import { createApprovedEgressConnector } from './browser-network.mjs';
import { BrowserSupervisor } from './browser-supervisor.mjs';

const WORKER = '/run/blindpass-private/browser.sock';
const BACKENDS = '/run/blindpass-backends';
const unavailable = () => new Error('supervisor_unavailable');

export function selectSupervisorTransport(args, uid, env, stat) {
  if (uid !== 0 || !Array.isArray(args)
    || ['NODE_OPTIONS', 'NODE_PATH', 'DEBUG', 'PWDEBUG', 'LD_PRELOAD', 'LD_LIBRARY_PATH'].some(name => env[name])) throw unavailable();
  const fd = args.length === 0 ? 3 : args.length === 1 && args[0] === '--socket' ? 0 : undefined;
  if (fd === undefined || !stat(fd).isSocket()) throw unavailable();
  return fd;
}

export function parseSupervisorBoottime(value) {
  if (typeof value !== 'string' || value.length > 96 || !/^\d+\.\d{2} \d+\.\d{2}\n$/.test(value)) throw unavailable();
  const [whole, fraction] = value.split(' ')[0].split('.');
  const result = Number(whole) * 1000 + Number(fraction) * 10;
  if (!Number.isSafeInteger(result) || result < 0) throw unavailable();
  return result;
}
export function privateBackendPath(operationId) {
  if (typeof operationId !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(operationId)) throw unavailable();
  return `${BACKENDS}/${createHash('sha256').update(operationId).digest('hex')}/cdp.sock`;
}
export function validateSupervisorBackendDirectory(value) {
  if (!value.isDirectory() || value.uid !== 0 || value.gid !== 0 || (value.mode & 0o7777) !== 0o700) throw unavailable();
}
export function validateSupervisorWorkerSocket(parent, socket) {
  validateSupervisorBackendDirectory(parent);
  if (!socket.isSocket() || socket.uid !== 0 || socket.gid !== 0 || (socket.mode & 0o7777) !== 0o600 || socket.nlink !== 1) throw unavailable();
}
const boottime = () => parseSupervisorBoottime(readFileSync('/proc/uptime', 'utf8'));

async function backend(operationId, accept, failed) {
  if (process.getuid() !== 0) throw unavailable();
  const ancestor = await lstat('/run');
  if (!ancestor.isDirectory() || ancestor.uid !== 0 || (ancestor.mode & 0o022) !== 0) throw unavailable();
  try { await mkdir(BACKENDS, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw unavailable(); }
  validateSupervisorBackendDirectory(await lstat(BACKENDS));
  const path = privateBackendPath(operationId); const directory = path.slice(0, path.lastIndexOf('/'));
  await mkdir(directory, { mode: 0o700 }); // stale/live operation directories are not silently reused
  const sockets = new Set(); let closing;
  const server = createServer(socket => {
    socket.pause(); sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    try { accept(socket); } catch { socket.destroy(); failed(); }
  });
  server.maxConnections = 16;
  const close = () => {
    if (closing) return closing;
    closing = (async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(() => resolve()));
      await rm(directory, { recursive: true, force: true });
    })();
    return closing;
  };
  try {
    validateSupervisorBackendDirectory(await lstat(directory));
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
    await chmod(path, 0o600);
    validateSupervisorWorkerSocket(await lstat(directory), await lstat(path));
    server.on('error', failed);
    return { close };
  } catch { await close(); throw unavailable(); }
}

async function main() {
  let fd;
  try {
    fd = selectSupervisorTransport(process.argv.slice(2), process.getuid(), process.env, fstatSync);
  } catch { process.exit(64); }
  process.umask(0o077);
  const parent = new Socket({ fd, readable: true, writable: true });
  let worker; let workerChannel; let parentChannel; let supervisor;
  const mux = new TunnelMux({ role: 'root', send: message => workerChannel.send(message),
    connect: () => createApprovedEgressConnector(supervisor.configuration)(), onFailure: () => { void supervisor.fail(); } });
  async function sendWorker(message) {
    if (supervisor.closed) throw unavailable();
    if (!workerChannel) {
      if (message.type !== 'start') throw unavailable();
      const directory = await lstat('/run/blindpass-private'); const before = await lstat(WORKER);
      validateSupervisorWorkerSocket(directory, before);
      if (supervisor.closed) throw unavailable();
      worker = connect({ path: WORKER });
      try {
        await new Promise((resolve, reject) => {
          const finish = error => {
            clearTimeout(timer); worker.off('connect', connected); worker.off('close', closed); worker.off('error', failed);
            if (error) reject(unavailable()); else resolve();
          };
          const connected = () => finish(); const closed = () => finish(true); const failed = () => finish(true);
          const timer = setTimeout(() => { finish(true); worker.destroy(); }, 5000);
          worker.once('error', failed); worker.once('close', closed); worker.once('connect', connected);
        });
        worker.on('error', () => { void supervisor.fail(); });
        const after = await lstat(WORKER);
        validateSupervisorWorkerSocket(await lstat('/run/blindpass-private'), after);
        if (supervisor.closed || before.dev !== after.dev || before.ino !== after.ino) throw unavailable();
        workerChannel = attachFramedStream(worker, { receive: value => supervisor.receiveWorker(value),
          onFailure: () => { void supervisor.fail(); } });
      } catch { worker.destroy(); throw unavailable(); }
    }
    await workerChannel.send(message);
  }
  supervisor = new BrowserSupervisor({ sendWorker, sendParent: message => parentChannel.send(message), mux,
    now: boottime, createBackend: (id, accept) => backend(id, accept, () => { void supervisor.fail(); }),
    closeWorker: async () => { workerChannel?.close(); worker?.destroy(); },
    onTerminal: () => { parent.end(); setTimeout(() => parent.destroy(), 250).unref(); } });
  parentChannel = attachFramedStream(parent, { receive: value => supervisor.receiveParent(value),
    onFailure: () => { void supervisor.close(); } });
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { void supervisor.fail(); });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch(() => { process.exit(70); });
}
