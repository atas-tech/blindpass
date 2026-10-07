// SPDX-License-Identifier: AGPL-3.0-only
// P07 F-3 (owner decision 2026-10-07): the published bundle has NO default SPS endpoint. Built the way the
// release builds it, the bundle must refuse to talk to any SPS until SPS_BASE_URL is set, must never send an
// enrolled agent key to a built-in host, and must work normally once the endpoint is set.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BUILD_BUNDLE = path.join(ROOT, 'scripts/build_bundle.sh');
const LEGACY_HOST = 'sps.blindpass.dev';
const DUMMY_KEY = `ak_${'0123456789abcdef'.repeat(2)}_dummy_generated_key`;

let scratch; let dist;

before(async () => {
  scratch = await mkdtemp(path.join(tmpdir(), 'blindpass-endpoint-bundle-'));
  dist = path.join(scratch, 'dist');
  // A fresh build into a scratch directory, so the test never trusts a stale shared dist.
  const build = spawnSync('bash', [BUILD_BUNDLE], { cwd: ROOT, encoding: 'utf8', timeout: 600_000, env: { ...process.env, BLINDPASS_BUNDLE_OUT: dist } });
  assert.equal(build.status, 0, `${build.stdout}${build.stderr}`);
});
after(() => rm(scratch, { recursive: true, force: true }));

// ---- static: the artifact itself carries no default ----------------------------------------------------------

test('the built bundle code and its manifest copy name no default SPS host', async () => {
  for (const file of ['blindpass.mjs', 'mcp-server.mjs', 'blindpass-resolver.mjs', 'index.mjs']) {
    assert.ok(existsSync(path.join(dist, file)), `${file} missing from the build`);
    const text = await readFile(path.join(dist, file), 'utf8');
    assert.ok(!text.includes(LEGACY_HOST), `${file} still contains the default host: esbuild did not drop the legacy default`);
  }
  const manifest = JSON.parse(await readFile(path.join(dist, 'openclaw.plugin.json'), 'utf8'));
  const sps = manifest.configSchema.properties.SPS_BASE_URL;
  assert.ok(sps, 'the SPS_BASE_URL setting must stay declared');
  assert.equal(Object.hasOwn(sps, 'default'), false, 'the bundle manifest must not declare a default endpoint');
  assert.ok(!JSON.stringify(manifest).includes(LEGACY_HOST), 'the bundle manifest still names the default host');
  // The source manifest is the legacy plugin's and keeps its default: only the bundle copy changes.
  const source = JSON.parse(await readFile(path.join(ROOT, 'packages/openclaw-plugin/openclaw.plugin.json'), 'utf8'));
  assert.equal(source.configSchema.properties.SPS_BASE_URL.default, `https://${LEGACY_HOST}`);
});

test('the client configuration examples name a placeholder endpoint, not a built-in host', async () => {
  for (const name of ['claude_desktop_config.json', 'codex_mcp_config.json', 'antigravity_settings.json']) {
    const config = JSON.parse(await readFile(path.join(ROOT, 'agents', name), 'utf8'));
    const value = config.mcpServers.blindpass.env.SPS_BASE_URL;
    assert.equal(typeof value, 'string', `${name} must show SPS_BASE_URL`);
    assert.ok(!value.includes(LEGACY_HOST), `${name} still points at the legacy host`);
    assert.match(value, /^https:\/\/[^/]*\.example(\.com)?$/, `${name} must use a reserved example host`);
  }
});

// ---- dynamic: the shipped mcp-server.mjs over stdio --------------------------------------------------------

const PRELOAD = `
import fs from 'node:fs';
import net from 'node:net';
const log = (line) => fs.appendFileSync(process.env.BP_NET_LOG, line + '\\n');
globalThis.fetch = async (url) => { log('fetch ' + String(url)); throw new Error('outbound request blocked by the test'); };
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) { log('connect ' + JSON.stringify(args[0])); throw new Error('outbound connection blocked by the test'); };
void connect;
`;

async function callTools(env, calls, { block }) {
  const dir = await mkdtemp(path.join(scratch, 'run-'));
  const netLog = path.join(dir, 'net.log');
  await writeFile(netLog, '');
  const preload = path.join(dir, 'preload.mjs');
  await writeFile(preload, PRELOAD);
  const childEnv = { PATH: process.env.PATH, HOME: dir, BP_NET_LOG: netLog, BLINDPASS_API_KEY: DUMMY_KEY, ...env };
  if (block) childEnv.NODE_OPTIONS = `--import=${preload}`;
  const child = spawn(process.execPath, [path.join(dist, 'mcp-server.mjs')], { cwd: dir, env: childEnv, stdio: ['pipe', 'pipe', 'pipe'] });
  let buffer = ''; const waiting = new Map();
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, index); buffer = buffer.slice(index + 1);
      if (!line.trim()) continue;
      const message = JSON.parse(line);
      waiting.get(message.id)?.(message); waiting.delete(message.id);
    }
  });
  const request = (id, method, params) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no answer to ${method}`)), 20_000);
    waiting.set(id, (message) => { clearTimeout(timer); resolve(message); });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  try {
    const init = await request(1, 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'endpoint-test', version: '1' } });
    assert.equal(init.result?.serverInfo?.name, 'blindpass');
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    const results = [];
    let id = 2;
    for (const [name, args] of calls) results.push(await request(id++, 'tools/call', { name, arguments: args }));
    return { results, attempts: (await readFile(netLog, 'utf8')).split('\n').filter(Boolean) };
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolve) => { child.once('exit', resolve); setTimeout(resolve, 3000).unref(); });
  }
}

const SPS_TOOLS = [
  ['request_secret', { description: 'AWS deployment token', secret_name: 'aws_token' }],
  ['request_secret_exchange', { secret_name: 'stripe.key', purpose: 'charge', fulfiller_id: 'agent:pay' }],
  ['fulfill_secret_exchange', { fulfillment_token: 'dummy-token' }],
];

test('SPS_BASE_URL unset: every SPS tool refuses with a clear message and makes no outbound attempt', async () => {
  const { results, attempts } = await callTools({}, SPS_TOOLS, { block: true });
  assert.equal(results.length, 3);
  for (const [index, response] of results.entries()) {
    const text = response.result?.content?.[0]?.text ?? JSON.stringify(response);
    assert.match(text, /SPS_BASE_URL/, `${SPS_TOOLS[index][0]} did not name the missing setting: ${text}`);
    assert.ok(!text.includes(LEGACY_HOST) && !text.includes(DUMMY_KEY), 'the refusal must not name a host or echo a key');
  }
  assert.deepEqual(attempts, [], `an outbound attempt was made without an endpoint: ${attempts}`);
});

test('SPS_BASE_URL unset and blank values: still refused, still nothing sent', async () => {
  for (const value of ['', '   ']) {
    const { results, attempts } = await callTools({ SPS_BASE_URL: value }, SPS_TOOLS.slice(0, 1), { block: true });
    assert.match(results[0].result?.content?.[0]?.text ?? '', /SPS_BASE_URL/, `blank value ${JSON.stringify(value)} was accepted`);
    assert.deepEqual(attempts, []);
  }
});

test('SPS_BASE_URL set: the bundle reaches exactly that endpoint (and only it) with the agent key', async () => {
  const seen = [];
  const server = createServer((request, response) => {
    seen.push({ method: request.method, url: request.url, key: request.headers['x-agent-api-key'] });
    response.writeHead(401, { 'content-type': 'application/json' }); response.end('{"error":"test"}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    const { results } = await callTools({ SPS_BASE_URL: url }, SPS_TOOLS.slice(0, 1), { block: false });
    assert.equal(seen.length >= 1, true, `the configured endpoint was never contacted: ${JSON.stringify(results)}`);
    assert.deepEqual(seen[0], { method: 'POST', url: '/api/v2/agents/token', key: DUMMY_KEY });
    const text = results[0].result?.content?.[0]?.text ?? '';
    assert.ok(!/SPS_BASE_URL/.test(text), 'a configured endpoint must not be reported as missing');
  } finally { server.close(); }
});
