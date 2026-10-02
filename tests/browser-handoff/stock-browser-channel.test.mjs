// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, chmod, rm, readdir } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { startFixture } from './fixture-app/server.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { frame, decode, runWorker } from './worker-harness.mjs';

function stockClient(config) {
  const child = spawn(process.execPath, ['node_modules/@playwright/mcp/cli.js', '--config', config], {
    stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH, HOME: process.env.HOME },
  });
  const waiting = new Map(); let sequence = 0; const errors = [];
  child.stderr.on('data', (data) => errors.push(data));
  const closed = new Promise((resolve) => child.on('close', resolve));
  createInterface({ input: child.stdout }).on('line', (line) => {
    try { const message = JSON.parse(line); waiting.get(message.id)?.(message); waiting.delete(message.id); }
    catch { child.kill(); }
  });
  return { async request(method, params) {
    return new Promise((resolve, reject) => {
      const id = ++sequence; const timeout = setTimeout(() => reject(new Error('Stock tool response deadline')), 10_000);
      waiting.set(id, (message) => { clearTimeout(timeout); resolve(message); });
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }, notify(method) { child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method })}\n`); },
  async close() { child.stdin.end(); const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    try { await closed; } finally { clearTimeout(timer); }
    return Buffer.concat(errors).toString();
  } };
}

test('P05-D2 feasibility / B-I02 actual stock Playwright MCP Unix CDP channel, approved cookie import and reconnect',
  { timeout: 60_000 }, async (t) => {
    const directory = await mkdtemp('/tmp/blindpass-p05-stock-channel-');
    t.after(() => rm(directory, { recursive: true, force: true }));
    const tls = await createTestTls(); t.after(() => tls.close());
    const password = `P05-STOCK-SOURCE-CANARY-${randomBytes(24).toString('hex')}`;
    const app = await startFixture({ ...tls, adminToken: randomBytes(32).toString('hex'), accounts: [
      { username: 'primary', password, report: 'Stock channel report: 12 artifacts' },
      { username: 'isolation', password: randomBytes(24).toString('hex'), report: 'Isolation report' },
    ] }); t.after(() => app.close());
    const pin = createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64');
    const raw = await runWorker(frame({ version: 1, configuration: { kind: 'fixture', origin: app.origin, account: 'primary',
      sessionMaxMs: 300_000, certificateSpkiPins: [pin] }, credential: { account: 'primary', password } }));
    assert.equal(raw.code, 0); assert.equal(raw.stdout, ''); assert.equal(raw.stderr, '');
    const session = decode(raw.output); raw.output.fill(0); assert.equal(session.status, 'authenticated');
    const context = await chromium.launchPersistentContext(`${directory}/workload-profile`, { headless: true,
      chromiumSandbox: true, args: ['--remote-debugging-port=0', `--ignore-certificate-errors-spki-list=${pin}`] });
    t.after(() => context.close());
    await context.addCookies(session.cookies);
    const [port, devtoolsPath] = (await readFile(`${directory}/workload-profile/DevToolsActivePort`, 'utf8')).trim().split('\n');
    assert.ok(/^\d+$/.test(port)); assert.ok(/^\/devtools\/browser\/[a-f0-9-]+$/.test(devtoolsPath));
    // This probe exercises the real stock channel. Production additionally
    // requires a network namespace and OS invocation-checked broker proxy.
    const sockets = new Set();
    const proxy = createServer((_req, res) => { res.writeHead(403); res.end(); });
    proxy.on('upgrade', (request, socket, head) => {
      if (request.url !== devtoolsPath) { socket.destroy(); return; }
      const upstream = connect({ host: '127.0.0.1', port: Number(port) });
      sockets.add(socket); sockets.add(upstream);
      socket.on('error', () => upstream.destroy()); upstream.on('error', () => socket.destroy());
      socket.on('close', () => { sockets.delete(socket); upstream.destroy(); });
      upstream.on('close', () => { sockets.delete(upstream); socket.destroy(); });
      upstream.on('connect', () => {
        const headers = request.rawHeaders;
        let opening = `GET ${devtoolsPath} HTTP/1.1\r\n`;
        for (let index = 0; index < headers.length; index += 2) opening += `${headers[index]}: ${headers[index + 1]}\r\n`;
        upstream.write(`${opening}\r\n`); if (head.length) upstream.write(head);
        socket.pipe(upstream); upstream.pipe(socket);
      });
    });
    const socketPath = `${directory}/context.sock`;
    await new Promise((resolve) => proxy.listen(socketPath, resolve)); await chmod(socketPath, 0o600);
    t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => proxy.close(resolve)); });
    const endpoint = `ws+unix:${socketPath}:${devtoolsPath}`;
    const config = `${directory}/stock-config.json`;
    await writeFile(config, JSON.stringify({ browser: { browserName: 'chromium', cdpEndpoint: endpoint, cdpTimeout: 5000 },
      saveSession: false, outputMode: 'stdout', outputDir: `${directory}/output`, snapshot: { mode: 'full' } }), { mode: 0o600 });
    let stage = 'initialize';
    for (let connection = 0; connection < 2; connection++) {
      const client = stockClient(config);
      try {
        stage = `initialize-${connection}`;
        const initialized = await client.request('initialize', { protocolVersion: '2025-11-25', capabilities: {},
          clientInfo: { name: 'blindpass-stock-channel-contract', version: '1' } });
        assert.ok(initialized.result?.serverInfo);
        client.notify('notifications/initialized');
        stage = `tools-${connection}`;
        const list = await client.request('tools/list', {});
        assert.ok(list.result.tools.some((tool) => tool.name === 'browser_navigate'));
        stage = `task-${connection}`;
        const result = await client.request('tools/call', { name: 'browser_navigate', arguments: { url: `${app.origin}/reports` } });
        t.diagnostic(JSON.stringify({ stockResponse: { rpcError: result.error?.code ?? null,
          isError: result.result?.isError ?? false,
          unixUnsupported: /unsupported|invalid.*url|protocol.*not/.test(JSON.stringify(result).toLowerCase()),
          connectionFailure: /connect|websocket|ECONN/.test(JSON.stringify(result)),
          reportPresent: JSON.stringify(result).includes('Stock channel report: 12 artifacts'),
          unauthorized: /unauthorized|sign in/i.test(JSON.stringify(result)),
          snapshotLink: /Snapshot\]|snapshot.*ya?ml/i.test(JSON.stringify(result)),
          textHeadings: result.result?.content?.filter((item) => item.type === 'text').flatMap((item) => item.text.match(/### [A-Za-z ]+/g) ?? []) ?? [],
          pageCount: context.pages().length, } }));
        stage = `task-status-${connection}`;
        assert.ok(!result.error && !result.result.isError);
        const snapshot = await client.request('tools/call', { name: 'browser_snapshot', arguments: {} });
        const visible = JSON.stringify({ navigate: result, snapshot });
        stage = `task-report-${connection}`;
        assert.ok(visible.includes('Stock channel report: 12 artifacts'));
        stage = `task-exposure-${connection}`;
        assert.ok(!visible.includes(password)); assert.ok(!visible.includes(endpoint));
        assert.ok(!visible.includes(session.cookies[0].value));
      } catch { throw new Error(`Stock Unix channel check failed during ${stage}`); }
      finally { const stderr = await client.close(); assert.equal(stderr.length, 0, 'stock tool stderr empty'); }
    }
    let artifactFiles = 0;
    async function scanArtifacts(path) {
      let entries;
      try { entries = await readdir(path, { withFileTypes: true }); }
      catch (error) { if (error.code === 'ENOENT') return; throw new Error('Stock artifact scan failed'); }
      for (const entry of entries) {
        const file = `${path}/${entry.name}`;
        if (entry.isDirectory()) await scanArtifacts(file);
        else if (entry.isFile()) {
          const data = await readFile(file); artifactFiles++;
          assert.ok(!data.includes(Buffer.from(password)), 'source password absent from managed stock artifacts');
          assert.ok(!data.includes(Buffer.from(session.cookies[0].value)), 'session cookie absent from normal artifacts');
          assert.ok(!data.includes(Buffer.from(endpoint)), 'raw control endpoint absent from normal artifacts');
          data.fill(0);
        }
      }
    }
    await scanArtifacts(`${directory}/output`);
    t.diagnostic(JSON.stringify({ stockTool: '@playwright/mcp@0.0.83', runtime: '1.64.0-alpha-1790635538000',
      browser: context.browser().version(), transport: 'Unix CDP', taskReads: 2, reconnects: 1, artifactFiles,
      sourcePasswordInModel: false, namespaceAndOsIdentity: 'not established by this probe' }));
  });
