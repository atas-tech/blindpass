// SPDX-License-Identifier: AGPL-3.0-only
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, rm, stat, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { startOAuthFixture } from './oauth-fixture.mjs';

const TRUSTED_USER = 'x-p05-trusted-user';
const loginPage = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Managed report sign in</title>
<main><h1>Managed report sign in</h1><a href="/login/generic_oauth">Continue to managed sign in</a></main></html>`;

// A suitability environment for the real application, not a broker operation/helper.
// Only the separate test OAuth issuer consumes source credentials. Every API goes to Grafana without
// an asserted identity, so Grafana's own session and authorization control those APIs.
export async function startManagedGrafana({ home, key, cert, ca, accounts, sessionMaxSeconds = 300, observeLogin, stateRoot = tmpdir(), administrator = 'admin' }) {
  if (!home || !key || !cert || !ca || !Number.isInteger(sessionMaxSeconds) || sessionMaxSeconds < 60
    || sessionMaxSeconds > 1800 || !Array.isArray(accounts) || accounts.length !== 2
    || typeof administrator !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(administrator) || ['primary', 'isolation'].includes(administrator)) {
    throw new Error('Invalid managed Grafana fixture configuration');
  }
  const users = new Map();
  for (const account of accounts) {
    if (!account || !['primary', 'isolation'].includes(account.username) || users.has(account.username)
      || typeof account.password !== 'string' || account.password.length < 8 || account.password.length > 512
      || typeof account.report !== 'string' || account.report.length > 1024) {
      throw new Error('Invalid managed Grafana fixture configuration');
    }
    users.set(account.username, { report: account.report });
  }
  const directory = await mkdtemp(join(stateRoot, 'blindpass-p05-managed-grafana-'));
  const socketPath = join(directory, 'backend.sock');
  let child;
  let issuer;
  let terminal = false;
  let processExit;
  let health;
  const startup = { outputBytes: 0, database: false, migrations: false, migrationComplete: false, http: false, errors: 0 };
  let pendingLog = '';
  function privateLog(bytes) {
    startup.outputBytes += bytes.length;
    const lines = (pendingLog + bytes.toString('utf8')).split('\n'); bytes.fill(0);
    pendingLog = lines.pop(); if (pendingLog.length > 8192) pendingLog = '';
    for (const line of lines) {
      startup.database ||= line.includes('msg="Connecting to DB"');
      startup.migrations ||= line.includes('msg="Starting DB migrations"');
      startup.migrationComplete ||= line.includes('msg="migrations completed"');
      startup.http ||= line.includes('msg="HTTP Server Listen"');
      if (/\blevel=(error|crit)\b/.test(line)) startup.errors++;
    }
  }
  let closed = false;
  let origin;
  let stage = 'setup';
  const flow = { callbacks: 0, originDenials: 0, stateCookieCallbacks: 0, callbackStatus: 0 };

  function backend(path, { method = 'GET', body, trustedUser, cookie, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
      const req = httpRequest({ socketPath, path, method, timeout: 5000, headers: {
        host: new URL(origin).host, 'x-forwarded-proto': 'https', ...headers,
        ...(trustedUser ? { [TRUSTED_USER]: trustedUser } : {}), ...(cookie ? { cookie } : {}),
        ...(body ? { 'content-type': 'application/json' } : {}),
      } }, (res) => {
        let bytes = 0;
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          bytes += Buffer.byteLength(chunk);
          if (bytes > 1_048_576) { res.destroy(); reject(new Error('Managed backend response too large')); }
          else text += chunk;
        });
        res.on('end', () => {
          try { resolve({ status: res.statusCode, headers: res.headers, text,
            json: text && res.headers['content-type']?.includes('application/json') ? JSON.parse(text) : null });
          } catch { reject(new Error('Managed backend response invalid')); }
        });
        res.on('error', () => reject(new Error('Managed backend response failed')));
      });
      req.on('timeout', () => req.destroy());
      req.on('error', () => reject(new Error('Managed backend request failed')));
      req.end(body ? JSON.stringify(body) : undefined);
    });
  }
  function send(res, code, status, extra = {}) {
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra });
    res.end(JSON.stringify(typeof status === 'string' ? { status } : status));
  }
  const frontend = createServer({ key, cert, minVersion: 'TLSv1.2' }, (req, res) => {
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-content-type-options', 'nosniff');
    void handle(req, res).catch(() => {
      if (!res.headersSent) send(res, 502, 'unavailable');
      else res.end();
    });
  });
  frontend.requestTimeout = 5000;
  frontend.headersTimeout = 5000;
  frontend.keepAliveTimeout = 1000;
  frontend.maxConnections = 64;

  async function handle(req, res) {
    const url = new URL(req.url, origin);
    const isCallback = url.pathname === '/login/generic_oauth' && url.searchParams.has('code');
    if (isCallback) {
      flow.callbacks++;
      if (/(^|;\s*)oauth_state=/.test(req.headers.cookie ?? '')) flow.stateCookieCallbacks++;
    }
    if (req.headers.host !== new URL(origin).host || url.origin !== origin
      || req.headers.origin !== undefined && req.headers.origin !== origin) {
      flow.originDenials++;
      req.resume();
      return send(res, 403, 'forbidden');
    }
    if (url.pathname === '/login' && req.method === 'GET') {
      if (url.search) { req.resume(); return send(res, 400, 'invalid_request'); }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
        'content-security-policy': "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" });
      return res.end(loginPage);
    }
    if (url.pathname === '/login' && req.method === 'POST') {
      req.resume();
      return send(res, 401, 'unsupported_authentication');
    }
    // Strip ALL asserted identities, Authorization and forwarding headers. Cookie-only
    // requests are authorized by Grafana. These API paths are never filtered by role here.
    const headers = { host: new URL(origin).host, 'x-forwarded-proto': 'https' };
    for (const name of ['accept', 'accept-language', 'content-type', 'cookie', 'origin', 'referer', 'user-agent']) {
      if (req.headers[name] !== undefined) headers[name] = req.headers[name];
    }
    const upstream = httpRequest({ socketPath, method: req.method, path: `${url.pathname}${url.search}`,
      headers, timeout: 5000 }, (reply) => {
      if (isCallback) flow.callbackStatus = reply.statusCode;
      res.writeHead(reply.statusCode, reply.headers);
      reply.pipe(res);
      reply.on('error', () => res.destroy());
    });
    upstream.on('timeout', () => upstream.destroy());
    upstream.on('error', () => {
      if (!res.headersSent) send(res, 502, 'unavailable');
      else res.destroy();
    });
    req.pipe(upstream);
  }

  async function close() {
    if (closed) return;
    closed = true;
    await issuer?.close();
    frontend.closeAllConnections();
    if (frontend.listening) await new Promise((resolve) => frontend.close(resolve));
    if (child && !terminal) {
      const stopped = new Promise((resolve) => child.once('exit', resolve));
      child.kill('SIGTERM');
      const force = globalThis.setTimeout(() => child.kill('SIGKILL'), 5000);
      await stopped;
      clearTimeout(force);
    }
    users.clear();
    pendingLog = '';
    await rm(directory, { recursive: true, force: true });
  }

  try {
    await new Promise((resolve, reject) => {
      frontend.once('error', reject);
      frontend.listen(0, '127.0.0.1', resolve);
    });
    origin = `https://127.0.0.1:${frontend.address().port}`;
    const clientId = 'p05-managed-reports';
    const clientSecret = randomBytes(32).toString('hex');
    issuer = await startOAuthFixture({ key, cert, accounts, clientId, clientSecret,
      redirectUri: () => `${origin}/login/generic_oauth`, observeLogin });
    await mkdir(join(directory, 'state'));
    await writeFile(join(directory, 'oauth-ca.pem'), ca, { mode: 0o600 });
    await writeFile(join(directory, 'grafana.ini'), `[paths]
data = ${join(directory, 'state')}
logs = ${join(directory, 'logs')}
plugins = ${join(directory, 'plugins')}
provisioning = ${join(directory, 'provisioning')}
[server]
protocol = socket
socket = ${socketPath}
socket_mode = 0600
root_url = ${origin}
[security]
admin_user = ${administrator}
admin_password = ${randomBytes(32).toString('hex')}
secret_key = ${randomBytes(32).toString('hex')}
cookie_secure = true
cookie_samesite = lax
disable_gravatar = true
[users]
allow_sign_up = false
auto_assign_org_role = Viewer
[auth]
disable_login_form = true
login_maximum_lifetime_duration = ${sessionMaxSeconds}s
login_maximum_inactive_lifetime_duration = ${sessionMaxSeconds}s
token_rotation_interval_minutes = 1
[auth.basic]
enabled = false
[auth.proxy]
enabled = true
header_name = ${TRUSTED_USER}
header_property = username
auto_sign_up = false
sync_ttl = 0
enable_login_token = true
[auth.generic_oauth]
enabled = true
name = P05 managed accounts
allow_sign_up = true
client_id = ${clientId}
client_secret = ${clientSecret}
scopes = profile email
auth_url = ${issuer.origin}/authorize
token_url = ${issuer.origin}/token
api_url = ${issuer.origin}/userinfo
use_pkce = true
use_refresh_token = false
tls_client_ca = ${join(directory, 'oauth-ca.pem')}
login_attribute_path = login
email_attribute_path = email
role_attribute_path = role
role_attribute_strict = true
skip_org_role_sync = false
org_attribute_path = organizations
org_mapping = primary:1:Viewer isolation:2:Viewer
allow_assign_grafana_admin = false
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[plugins]
preinstall_disabled = true
[log]
mode = console
level = info
`, { mode: 0o600 });
    const distribution = resolve(home);
    child = spawn(join(distribution, 'bin', 'grafana'),
      ['server', '--homepath', distribution, '--config', join(directory, 'grafana.ini')], { stdio: ['ignore', 'pipe', 'pipe'] });
    // Trusted setup diagnostics remain transient in this private Root pipe.
    // Only fixed startup flags and counters are exposed; raw bodies never are.
    child.stdout.on('data', privateLog); child.stderr.on('data', privateLog);
    child.once('exit', (code, signal) => { terminal = true; processExit = { code, signal }; });
    child.once('error', () => { terminal = true; });
    stage = 'readiness';
    const deadline = performance.now() + 60_000;
    while (performance.now() < deadline) {
      if (terminal) throw new Error('Exited');
      try { health = await backend('/api/health'); if (health.status === 200) break; } catch { /* startup retry */ }
      await setTimeout(250);
    }
    if (health?.status !== 200 || health.json.version !== '13.2.3') throw new Error('Not ready or wrong version');
    if ((await stat(socketPath)).mode & 0o077) throw new Error('Backend socket accessible outside owner');
    const admin = (path, options = {}) => backend(path, { ...options, trustedUser: administrator });
    stage = 'account-setup';
    const org = await admin('/api/orgs', { method: 'POST', body: { name: 'P05 isolation reports' } });
    if (org.status !== 200 || org.json.orgId !== 2) throw new Error('Organization not created');
    for (const [username, user] of users) {
      const orgId = username === 'primary' ? 1 : org.json.orgId;
      if ((await admin(`/api/user/using/${orgId}`, { method: 'POST' })).status !== 200) throw new Error('Organization not selected');
      const dashboard = await admin('/api/dashboards/db', { method: 'POST', body: {
        dashboard: { uid: `p05-${username}`, title: `P05 ${username} backup report`, schemaVersion: 41,
          editable: false, panels: [{ id: 1, type: 'text', title: 'Backup verification',
            gridPos: { x: 0, y: 0, w: 24, h: 8 }, options: { mode: 'markdown', content: user.report } }] },
        overwrite: true,
      } });
      if (dashboard.status !== 200) throw new Error('Report not created');
    }
    return { origin, issuerOrigin: issuer.origin, oauthMetrics: () => ({ ...issuer.metrics(), ...flow }),
      version: health.json.version, admin, administrator, adminSocket: socketPath, close };
  } catch {
    const exit = processExit;
    await close();
    const error = new Error(`Managed Grafana setup failed during ${stage}`);
    error.grafanaExitCode = exit?.code;
    error.grafanaExitSignal = exit?.signal;
    error.grafanaHealthStatus = health?.status ?? 0;
    error.grafanaHealthVersionMatches = health?.json?.version === '13.2.3';
    error.grafanaStartup = { ...startup };
    throw error;
  }
}
