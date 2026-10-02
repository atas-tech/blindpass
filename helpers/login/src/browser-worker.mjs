// SPDX-License-Identifier: AGPL-3.0-only
// Persistent private root<->DynamicUser browser channel. Normal output is empty.
import { Socket, connect } from 'node:net';
import { constants, fstatSync } from 'node:fs';
import { lstat, mkdir, open, rm } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import { attachFramedStream, TunnelMux } from './browser-transport.mjs';
import { IsolatedBrowserSession } from './isolated-browser.mjs';
import { startApprovedConnectProxy } from './browser-network.mjs';
import { proveRuntimeIdentity } from './runtime-identity-client.mjs';

const CHROMIUM = '/usr/lib/blindpass/login/browsers/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell';
let stream;
try {
  if (process.argv.length !== 2 || !fstatSync(0).isSocket() || !fstatSync(1).isSocket()
    || ['NODE_OPTIONS', 'NODE_PATH', 'DEBUG', 'PWDEBUG', 'LD_PRELOAD', 'LD_LIBRARY_PATH'].some((name) => process.env[name])) process.exit(64);
  stream = new Socket({ fd: 0, readable: true, writable: true });
} catch { process.exit(64); }

let session; let channel; let cdp;
const mux = new TunnelMux({ role: 'worker', send: (message) => channel.send(message),
  connect: async () => {
    if (!cdp) throw new Error('channel_unavailable');
    return new Promise((resolve, reject) => {
      const socket = connect({ host: '127.0.0.1', port: cdp.port });
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('channel_unavailable')); }, 5000);
      socket.once('error', () => { clearTimeout(timer); reject(new Error('channel_unavailable')); });
      socket.once('connect', () => { clearTimeout(timer); socket.pause(); resolve(socket); });
    });
  }, onFailure: () => { void session.fail(); } });

async function start(recipe) {
  const root = process.env.RUNTIME_DIRECTORY;
  const invocation = process.env.INVOCATION_ID;
  let context; let proxy; let profile;
  try {
    // These checks reject accidental host-network launches. The root broker must
    // additionally verify PrivateNetwork and the actual namespace/unit/invocation
    // through systemd and procfs; this check alone is not isolation evidence.
    const interfaces = networkInterfaces();
    if (!Object.keys(interfaces).length || Object.keys(interfaces).some((name) => name !== 'lo')
      || !/^\/run\/blindpass-browser-[A-Za-z0-9_.:@-]{1,180}$/.test(root ?? '')
      || !/^[a-f0-9]{32}$/.test(invocation ?? '')) throw new Error('unsafe_runtime');
    const directory = await lstat(root);
    if (!directory.isDirectory() || directory.uid !== process.getuid() || (directory.mode & 0o777) !== 0o700) throw new Error('unsafe_runtime');
    profile = `${root}/profile`; await mkdir(profile, { mode: 0o700 }); // no preexisting profile accepted
    proxy = await startApprovedConnectProxy(recipe, mux);
    const { chromium } = await import('playwright');
    context = await chromium.launchPersistentContext(profile, {
      executablePath: CHROMIUM, headless: true, chromiumSandbox: true, timeout: 15_000,
      acceptDownloads: false, serviceWorkers: 'block',
      args: ['--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
        `--proxy-server=${proxy.url}`, '--proxy-bypass-list=<-loopback>',
        ...(recipe.certificateSpkiPins.length ? [`--ignore-certificate-errors-spki-list=${recipe.certificateSpkiPins.join(',')}`] : [])],
    });
    const file = await open(`${profile}/DevToolsActivePort`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let data;
    try {
      const metadata = await file.stat();
      if (!metadata.isFile() || metadata.nlink !== 1 || metadata.uid !== process.getuid() || metadata.size > 1024) throw new Error('unsafe_runtime');
      data = await file.readFile();
      const match = /^(\d{1,5})\n(\/devtools\/browser\/[a-f0-9-]{36})\n?$/.exec(data.toString('ascii'));
      if (!match || Number(match[1]) < 1 || Number(match[1]) > 65535) throw new Error('unsafe_runtime');
      cdp = { port: Number(match[1]), path: match[2] };
    } finally { data?.fill(0); await file.close(); }
    return { context, pid: process.pid, invocation, devtoolsPath: cdp.path,
      cleanup: async () => { cdp = undefined; await proxy.close(); await rm(profile, { recursive: true, force: true }); } };
  } catch {
    try { await context?.close(); } catch { /* manager verifies/kills cgroup */ }
    try { await proxy?.close(); } catch { /* manager removes private runtime directory */ }
    if (profile) { try { await rm(profile, { recursive: true, force: true }); } catch { /* root reconciliation */ } }
    throw new Error('runtime_unavailable');
  }
}

session = new IsolatedBrowserSession({ send: (message) => channel.send(message), mux, start, prove: proveRuntimeIdentity,
  onTerminal: () => { stream.end(); setTimeout(() => stream.destroy(), 250).unref(); } });
channel = attachFramedStream(stream, { receive: (message) => session.receive(message),
  onFailure: () => { void session.close(); } });
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { void session.fail(); });
