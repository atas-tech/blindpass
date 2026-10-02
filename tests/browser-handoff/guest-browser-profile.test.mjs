// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { guestBrowserProfile, copiedSession, decodeBootstrapReply, reportSteps } from './guest-browser-profile.mjs';

test('P05-PC12: guest application profiles select only fixed report/replay paths and cookies', () => {
  assert.deepEqual(guestBrowserProfile(), { kind: 'fixture', reportPath: '/reports', replayPath: '/reports', cookieNames: ['__Host-bp-fixture'] });
  assert.deepEqual(guestBrowserProfile('grafana-managed'), { kind: 'grafana-managed', reportPath: '/d/p05-primary', replayPath: '/api/user', cookieNames: ['grafana_session', 'grafana_session_expiry'] });
  for (const value of ['', 'grafana-local', '../report', 'fixture\n', null]) assert.throws(() => guestBrowserProfile(value), { message: 'guest_browser_profile_invalid' });
});

test('P05-PC12: private session scanner requires all exact bounded cookie pairs without duplicates', () => {
  const profile = guestBrowserProfile('grafana-managed');
  assert.equal(copiedSession('"grafana_session=abc_DEF.123; grafana_session_expiry=1790854321"', profile), 'grafana_session=abc_DEF.123; grafana_session_expiry=1790854321');
  for (const text of ['grafana_session=abc', 'other_session=abc; grafana_session_expiry=123', 'grafana_session=abc; grafana_session=def; grafana_session_expiry=123', 'grafana_session=abc%bad; grafana_session_expiry=123', `grafana_session=${'a'.repeat(2049)}; grafana_session_expiry=123`]) assert.throws(() => copiedSession(text, profile), { message: 'guest_session_invalid' });
});

test('P05-PC12: application bootstrap reply is bounded, framed and never reflects upstream content', () => {
  const body = Buffer.from(JSON.stringify({ status: 'authenticated', revokeHandle: { userId: 3 }, cookies: [] }));
  const bytes = Buffer.alloc(body.length + 4); bytes.writeUInt32BE(body.length); body.copy(bytes, 4);
  assert.equal(decodeBootstrapReply(bytes).revokeHandle.userId, 3);
  for (const value of [Buffer.from('PRIVATE-CANARY'), Buffer.alloc(16389), bytes.subarray(0, bytes.length - 1)]) assert.throws(() => decodeBootstrapReply(value), { message: 'guest_bootstrap_failed' });
});

test('P05-PC12: managed stock reads wait for the real report before snapshotting', () => {
  const steps = reportSteps(guestBrowserProfile('grafana-managed'), 'https://127.0.0.1:1234');
  assert.deepEqual(steps.map(step => step.name), ['browser_navigate', 'browser_wait_for', 'browser_snapshot']);
  assert.deepEqual(steps[1].arguments, { text: 'Coordinator report: 12 artifacts' });
  assert.deepEqual(reportSteps(guestBrowserProfile(), 'https://127.0.0.1:1234').map(step => step.name), ['browser_navigate', 'browser_snapshot']);
  for (const origin of ['http://127.0.0.1', 'https://user:password@127.0.0.1', 'https://127.0.0.1/path', 'https://127.0.0.1#private']) assert.throws(() => reportSteps(guestBrowserProfile(), origin), { message: 'guest_browser_profile_invalid' });
});
