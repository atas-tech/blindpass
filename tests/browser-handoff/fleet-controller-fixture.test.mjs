// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomBytes } from 'node:crypto';
import { runPrivate, decodeControllerResponse, isProvisionalBrowserOperation, isConfirmedBrowserClosure } from './fleet-controller-fixture.mjs';

test('P05-PC08 provisional broker uncertainty is controller executing metadata', () => {
  assert.equal(isProvisionalBrowserOperation({ status: 'executing', result: { result_code: 'result_uncertain' } }), true);
  for (const value of [{ status: 'granted' }, { status: 'completed', result: { result_code: 'browser_session_closed' } }]) assert.equal(isProvisionalBrowserOperation(value), false);
});

test('P05-PC08 confirmed cleanup preserves controller revocation authority', () => {
  for (const status of ['completed', 'revoked']) assert.equal(isConfirmedBrowserClosure({ status, result: { result_code: 'browser_session_closed' } }), true);
  for (const status of ['executing', 'granted', 'cancelled', 'expired']) assert.equal(isConfirmedBrowserClosure({ status, result: { result_code: 'browser_session_closed' } }), false);
  assert.equal(isConfirmedBrowserClosure({ status: 'revoked', result: { result_code: 'result_uncertain' } }), false);
});

test('P05-PC08 private controller client accepts an actual empty successful password response', () => {
  assert.deepEqual(decodeControllerResponse(204, Buffer.alloc(0)), {});
  assert.deepEqual(decodeControllerResponse(200, Buffer.from('{"status":"active"}')), { status: 'active' });
});

test('P05-PC08 private controller client never reflects failed or malformed bodies', () => {
  const bytes = Buffer.from(`P05-PRIVATE-${randomBytes(16).toString('hex')}`);
  for (const status of [401, 403, 500]) assert.throws(() => decodeControllerResponse(status, bytes), { message: `fleet_controller_http_${status}` });
  assert.throws(() => decodeControllerResponse(200, bytes), { message: 'fleet_controller_http_200' }); bytes.fill(0);
});

test('P05-PC08 private fixture command drains stdout and withholds diagnostics', async () => {
  const canary = `P05-PRIVATE-${randomBytes(16).toString('hex')}`;
  const output = await runPrivate(process.execPath, ['-e', 'process.stdin.on("data", data => { process.stderr.write(data); process.stdout.write("safe metadata\\n"); });'], { input: canary });
  assert.equal(output.toString(), 'safe metadata\n');
  assert.ok(!output.includes(Buffer.from(canary))); output.fill(0);
});

test('P05-PC08 private fixture failure never embeds upstream output', async () => {
  const canary = `P05-PRIVATE-${randomBytes(16).toString('hex')}`;
  await assert.rejects(runPrivate(process.execPath, ['-e', 'process.stdin.on("data", data => { process.stdout.write(data); process.stderr.write(data); process.exitCode = 17; });'], { input: canary }), { message: 'private_command_failed' });
  await assert.rejects(runPrivate('/does-not-exist/blindpass-test', []), { message: 'private_command_failed' });
});

test('P05-PC08 private fixture command bounds output and execution', async () => {
  await assert.rejects(runPrivate(process.execPath, ['-e', 'process.stdout.write(Buffer.alloc(65537));']), { message: 'private_command_failed' });
  await assert.rejects(runPrivate(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], { timeout: 100 }), { message: 'private_command_failed' });
});
