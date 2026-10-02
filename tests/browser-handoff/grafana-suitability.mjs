// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:https';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { chromium } from '@playwright/test';
import { createTestTls } from './fixture-app/test-tls.mjs';

// This is a rejection probe for a disposable, unmodified local-password Grafana Viewer.
// It never points at an existing application, account, database or live controller.
const home = process.argv[2] && resolve(process.argv[2]);
if (!home) throw new Error('Supply the extracted, checksum-verified Grafana distribution directory');
const binary = join(home, 'bin', 'grafana');
const directory = await mkdtemp(join(tmpdir(), 'blindpass-p05-grafana-'));
const tls = await createTestTls();
let child;
let childTerminal = false;
let browser;
let stage = 'setup';
try {
  const socket = createServer();
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  const origin = `https://127.0.0.1:${port}`;
  const adminPassword = randomBytes(32).toString('hex');
  const password = `P05-GRAFANA-PASSWORD-CANARY-${randomBytes(24).toString('hex')}`;
  const successor = randomBytes(32).toString('hex');
  const adminAuth = `Basic ${Buffer.from(`admin:${adminPassword}`).toString('base64')}`;
  await mkdir(join(directory, 'state'));
  await writeFile(join(directory, 'cert.pem'), tls.cert, { mode: 0o600 });
  await writeFile(join(directory, 'key.pem'), tls.key, { mode: 0o600 });
  await writeFile(join(directory, 'grafana.ini'), `[paths]
data = ${join(directory, 'state')}
logs = ${join(directory, 'logs')}
plugins = ${join(directory, 'plugins')}
provisioning = ${join(directory, 'provisioning')}
[server]
protocol = https
http_addr = 127.0.0.1
http_port = ${port}
root_url = ${origin}
cert_file = ${join(directory, 'cert.pem')}
cert_key = ${join(directory, 'key.pem')}
[security]
admin_password = ${adminPassword}
cookie_secure = true
secret_key = ${randomBytes(32).toString('hex')}
[users]
allow_sign_up = false
auto_assign_org_role = Viewer
[auth]
login_maximum_lifetime_duration = 30m
login_maximum_inactive_lifetime_duration = 30m
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[plugins]
preinstall_disabled = true
[log]
mode = console
level = error
`, { mode: 0o600 });
  function send(path, { method = 'GET', body, cookie, authorization } = {}) {
    return new Promise((resolve, reject) => {
      const req = request(`${origin}${path}`, { method, ca: tls.ca, timeout: 5000,
        headers: { ...(cookie ? { cookie } : {}), ...(authorization ? { authorization } : {}),
          ...(body ? { 'content-type': 'application/json' } : {}) } }, (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers,
          json: res.headers['content-type']?.includes('application/json') ? JSON.parse(text) : undefined }));
      });
      req.on('timeout', () => req.destroy());
      req.on('error', () => reject(new Error('Candidate HTTPS request failed')));
      req.end(body ? JSON.stringify(body) : undefined);
    });
  }
  child = spawn(binary, ['server', '--homepath', home, '--config', join(directory, 'grafana.ini')],
    { stdio: 'ignore' });
  child.once('exit', () => { childTerminal = true; });
  child.once('error', () => { childTerminal = true; });
  stage = 'readiness';
  let health;
  const startupDeadline = Date.now() + 60_000;
  while (Date.now() < startupDeadline) {
    if (childTerminal) throw new Error('Candidate exited before readiness');
    try { health = await send('/api/health'); if (health.status === 200) break; } catch { /* bounded retry */ }
    await setTimeout(250);
  }
  assert.equal(health?.status, 200, 'candidate must start');
  stage = 'viewer-setup';
  const created = await send('/api/admin/users', { method: 'POST', authorization: adminAuth,
    body: { login: 'p05-viewer', name: 'P05 Viewer', email: 'viewer@example.invalid', password } });
  assert.equal(created.status, 200);
  const userId = created.json.id;
  assert.equal((await send(`/api/org/users/${userId}`, { method: 'PATCH', authorization: adminAuth,
    body: { role: 'Viewer' } })).status, 200);
  const login = await send('/login', { method: 'POST', body: { user: 'p05-viewer', password } });
  assert.equal(login.status, 200);
  const cookie = login.headers['set-cookie']?.map((value) => value.split(';')[0]).join('; ');
  assert.ok(cookie, 'candidate must issue session');
  const identity = await send('/api/user', { cookie });
  assert.equal(identity.status, 200);
  assert.equal(identity.json.isGrafanaAdmin, false);
  const orgs = await send('/api/user/orgs', { cookie });
  assert.equal(orgs.status, 200);
  assert.equal(orgs.json[0].role, 'Viewer');
  stage = 'profile-ui';
  const spki = createHash('sha256').update(createPublicKey(tls.cert)
    .export({ type: 'spki', format: 'der' })).digest('base64');
  browser = await chromium.launch({ chromiumSandbox: true, args: [`--ignore-certificate-errors-spki-list=${spki}`] });
  const context = await browser.newContext();
  await context.addCookies(login.headers['set-cookie'].map((value) => {
    const pair = value.split(';')[0];
    const separator = pair.indexOf('=');
    return { name: pair.slice(0, separator), value: pair.slice(separator + 1), url: origin };
  }));
  const page = await context.newPage();
  await page.goto(`${origin}/profile`, { waitUntil: 'domcontentloaded' });
  const email = page.getByLabel('Email', { exact: true });
  await email.waitFor();
  const emailEditable = await email.isEditable();
  stage = 'direct-account-mutation';
  const update = await send('/api/user', { method: 'PUT', cookie,
    body: { login: 'p05-viewer', name: 'P05 Viewer', email: 'replacement@example.invalid' } });
  const passwordChange = await send('/api/user/password', { method: 'PUT', cookie,
    body: { oldPassword: password, newPassword: successor, confirmNew: successor } });
  assert.equal(update.status, 200, 'probe expects unrestricted own-profile mutation');
  assert.equal(passwordChange.status, 200, 'probe expects unrestricted own-password mutation');
  stage = 'revocation';
  const revoked = await send(`/api/admin/users/${userId}/logout`, { method: 'POST', authorization: adminAuth });
  assert.equal(revoked.status, 200);
  const replay = await send('/api/user', { cookie });
  assert.equal(replay.status, 401, 'copied candidate session must fail after logout');
  const summary = { scenario: 'P05-I01', candidate: 'Grafana OSS', version: health.json.version,
    profile: 'HTTPS, local-password Viewer, configured 30m maximum', suitability: 'rejected',
    observations: { emailEditable, ownProfileUpdateStatus: update.status,
      ownPasswordChangeStatus: passwordChange.status, postLogoutCopiedCookieStatus: replay.status },
    notRun: ['sustained activity past 30m', 'broker handler', 'stock-client workflow'],
    reason: 'Viewer can change account/recovery email and password; reject before browser handler acceptance' };
  console.log(JSON.stringify(summary, null, 2));
  // Every credential and session stays in process memory/private disposable files. No captures.
} catch {
  console.error(`P05 candidate suitability probe failed during ${stage}`);
  process.exitCode = 1;
} finally {
  await browser?.close();
  if (child && !childTerminal) {
    const stopped = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGTERM');
    const force = globalThis.setTimeout(() => child.kill('SIGKILL'), 5000);
    await stopped;
    clearTimeout(force);
  }
  await tls.close();
  await rm(directory, { recursive: true, force: true });
}
