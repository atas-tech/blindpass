// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { createServer, request } from 'node:https';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { startOAuthFixture } from './oauth-fixture.mjs';
import { createTestTls } from './fixture-app/test-tls.mjs';

test('P05-I01 OAuth issuer rejects unsafe client and callback configuration before binding', async (t) => {
  const tls = await createTestTls();
  t.after(() => tls.close());
  const options = { ...tls, accounts: [{ username: 'primary', password: 'dummy-password' }],
    clientId: 'test-client', clientSecret: 'x'.repeat(32), redirectUri: () => 'https://127.0.0.1:9999/callback' };
  await assert.rejects(startOAuthFixture({ ...options, redirectUri: () => 'http://127.0.0.1:9999/callback' }), /Invalid OAuth fixture configuration/);
  await assert.rejects(startOAuthFixture({ ...options, redirectUri: () => 'https://example.invalid/callback' }), /Invalid OAuth fixture configuration/);
  await assert.rejects(startOAuthFixture({ ...options, clientSecret: '' }), /Invalid OAuth fixture configuration/);
  await assert.rejects(startOAuthFixture({ ...options, accounts: [{ username: 'admin', password: 'dummy-password' }] }), /Invalid OAuth fixture configuration/);
  await assert.rejects(startOAuthFixture({ ...options, observeLogin: 'untrusted' }), /Invalid OAuth fixture configuration/);
});

test('P05-I01 OAuth issuer: fixed redirect, PKCE, client binding, single-use code and immutable Viewer identity', async (t) => {
  const tls = await createTestTls();
  t.after(() => tls.close());
  const password = randomBytes(32).toString('hex');
  const clientSecret = randomBytes(32).toString('hex');
  const redirect = 'https://127.0.0.1:9999/login/generic_oauth';
  let observed = 0;
  const issuer = await startOAuthFixture({ ...tls, accounts: [{ username: 'primary', password }],
    clientId: 'test-client', clientSecret, redirectUri: () => redirect,
    observeLogin: async (...args) => { assert.equal(args.length, 0, 'observer gets no credential or code'); observed++; } });
  t.after(() => issuer.close());
  const send = (path, { body, authorization, origin } = {}) => new Promise((resolve, reject) => {
    const req = request(`${issuer.origin}${path}`, { ca: tls.ca, method: body ? 'POST' : 'GET', headers: {
      ...(body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
      ...(authorization ? { authorization } : {}), ...(origin ? { origin } : {}),
    } }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', () => reject(new Error('Issuer test transport failed')));
    req.end(body?.toString());
  });
  const verifier = randomBytes(32).toString('base64url');
  const query = new URLSearchParams({ client_id: 'test-client', response_type: 'code', redirect_uri: redirect,
    code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    state: 'dummy-state' });
  const badRedirect = new URLSearchParams(query);
  badRedirect.set('redirect_uri', 'https://example.invalid/callback');
  assert.equal((await send(`/authorize?${badRedirect}`)).status, 400);
  const duplicate = new URLSearchParams(query);
  duplicate.append('redirect_uri', redirect);
  assert.equal((await send(`/authorize?${duplicate}`)).status, 400, 'ambiguous authorization fields denied');
  const login = await send(`/authorize?${query}`);
  assert.equal(login.status, 200);
  const ticket = login.text.match(/name="ticket" value="([a-f0-9]{64})"/)?.[1];
  assert.ok(ticket, 'private login ticket issued');
  const form = new URLSearchParams({ ticket, username: 'primary', password, role: 'Admin' });
  assert.equal((await send('/authorize', { body: form, origin: 'https://example.invalid' })).status, 403);
  assert.equal(observed, 0, 'invalid origin cannot trigger operation observation');
  const reply = await send('/authorize', { body: form, origin: issuer.origin });
  assert.equal(reply.status, 303);
  assert.equal(observed, 1, 'verified authentication is independently observed before the code reply');
  const callback = new URL(reply.headers.location);
  assert.equal(callback.origin + callback.pathname, redirect);
  assert.equal(callback.searchParams.get('state'), 'dummy-state');
  assert.equal((await send('/authorize', { body: form })).status, 400, 'login ticket consumed once');
  const grant = new URLSearchParams({ client_id: 'test-client', client_secret: clientSecret,
    grant_type: 'authorization_code', code: callback.searchParams.get('code'), redirect_uri: redirect,
    code_verifier: verifier });
  const wrongClient = new URLSearchParams(grant);
  wrongClient.set('client_secret', 'wrong-dummy-secret');
  assert.equal((await send('/token', { body: wrongClient })).status, 401);
  const wrongVerifier = new URLSearchParams(grant);
  wrongVerifier.set('code_verifier', randomBytes(32).toString('base64url'));
  assert.equal((await send('/token', { body: wrongVerifier })).status, 400);
  const issued = await send('/token', { body: grant });
  assert.equal(issued.status, 200);
  const token = JSON.parse(issued.text);
  assert.equal(token.refresh_token, undefined);
  assert.equal(token.expires_in, 600, 'identity token outlives the selected 5m website session maximum');
  assert.equal((await send('/token', { body: grant })).status, 400, 'authorization code consumed once');
  const identity = await send('/userinfo', { authorization: `Bearer ${token.access_token}` });
  assert.equal(identity.status, 200);
  assert.equal(JSON.parse(identity.text).role, 'Viewer');
  assert.deepEqual(JSON.parse(identity.text).organizations, ['primary']);
  assert.equal((await send('/userinfo', { authorization: 'Bearer dummy' })).status, 401);
});

test('P05-I01 native OAuth browser form reaches only the approved cross-origin callback', { timeout: 30_000 }, async (t) => {
  const tls = await createTestTls();
  t.after(() => tls.close());
  let callbacks = 0;
  const callback = createServer(tls, (req, res) => {
    if (req.url.startsWith('/callback?')) callbacks++;
    res.end('Signed in');
  });
  await new Promise((resolve) => callback.listen(0, '127.0.0.1', resolve));
  t.after(async () => { callback.closeAllConnections(); await new Promise((resolve) => callback.close(resolve)); });
  const redirect = `https://127.0.0.1:${callback.address().port}/callback`;
  const password = randomBytes(32).toString('hex');
  const issuer = await startOAuthFixture({ ...tls, accounts: [{ username: 'primary', password }],
    clientId: 'test-client', clientSecret: randomBytes(32).toString('hex'), redirectUri: () => redirect });
  t.after(() => issuer.close());
  const spki = createHash('sha256').update(createPublicKey(tls.cert).export({ type: 'spki', format: 'der' })).digest('base64');
  const browser = await chromium.launch({ chromiumSandbox: true, args: [`--ignore-certificate-errors-spki-list=${spki}`] });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const query = new URLSearchParams({ client_id: 'test-client', response_type: 'code', redirect_uri: redirect,
    code_challenge_method: 'S256', code_challenge: createHash('sha256').update('a'.repeat(43)).digest('base64url'), state: 'dummy-state' });
  try {
    await page.goto(`${issuer.origin}/authorize?${query}`);
    await page.getByLabel('Username').fill('primary');
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.waitForURL((url) => url.origin + url.pathname === redirect, { timeout: 5000 });
    assert.equal(callbacks, 1);
  } catch { throw new Error('Approved OAuth callback was not reached'); }
});
