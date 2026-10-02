// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { parseSupervisorBoottime, privateBackendPath, validateSupervisorWorkerSocket,
  validateSupervisorBackendDirectory, selectSupervisorTransport } from '../../helpers/login/src/browser-supervisor-worker.mjs';

test('P05-I02 supervisor socket activation selects only its inherited private transport, never a caller path', () => {
  const socket = { isSocket: () => true };
  assert.equal(selectSupervisorTransport([], 0, {}, fd => { assert.equal(fd, 3); return socket; }), 3);
  assert.equal(selectSupervisorTransport(['--socket'], 0, {}, fd => { assert.equal(fd, 0); return socket; }), 0);
  for (const args of [['--socket', '--endpoint'], ['--socket', '/tmp/model.sock'], ['--trace'], ['--fd', '9']]) {
    assert.throws(() => selectSupervisorTransport(args, 0, {}, () => socket), /supervisor_unavailable/);
  }
  for (const uid of [1001, undefined, -1]) assert.throws(() => selectSupervisorTransport([], uid, {}, () => socket), /supervisor_unavailable/);
  for (const env of [{ NODE_OPTIONS: '--trace-warnings' }, { DEBUG: 'P05-PRIVATE-CANARY' }, { LD_PRELOAD: 'model' }]) {
    assert.throws(() => selectSupervisorTransport(['--socket'], 0, env, () => socket), /supervisor_unavailable/);
  }
  assert.throws(() => selectSupervisorTransport(['--socket'], 0, {}, () => ({ isSocket: () => false })), /supervisor_unavailable/);
});

test('P05-I03 outside supervisor uses bounded suspend-aware Linux uptime, never wall clock or caller clock', () => {
  assert.equal(parseSupervisorBoottime('123.45 90.01\n'), 123_450);
  for (const value of ['123.45', 'NaN 0.00\n', '-1.00 0.00\n', '1.00 0.00\ntrailing', '1e20 0.00\n', '1.000 0.00\n', 'x'.repeat(97), '999999999999999999999.00 0.00\n']) {
    assert.throws(() => parseSupervisorBoottime(value), /supervisor_unavailable/);
  }
});
test('P05-I02 backend derives one fixed private Unix path from opaque operation identity and accepts no endpoint', () => {
  const operationId = `op_${'a'.repeat(64)}`;
  const hash = createHash('sha256').update(operationId).digest('hex');
  assert.equal(privateBackendPath(operationId), `/run/blindpass-backends/${hash}/cdp.sock`);
  assert.ok(Buffer.byteLength(privateBackendPath(operationId)) < 108);
  for (const value of ['', '../source', '/tmp/backend.sock', 'https://PRIVATE-ENDPOINT-CANARY', 'a'.repeat(129), { endpoint: 'model' }]) {
    assert.throws(() => privateBackendPath(value), /supervisor_unavailable/);
  }
});
test('P05-I06 supervisor requires the protected Root activation socket and fresh private backend directory', () => {
  const parent = { isDirectory: () => true, uid: 0, gid: 0, mode: 0o40700 };
  const socket = { isSocket: () => true, uid: 0, gid: 0, mode: 0o140600, nlink: 1 };
  assert.doesNotThrow(() => validateSupervisorWorkerSocket(parent, socket));
  assert.doesNotThrow(() => validateSupervisorBackendDirectory(parent));
  for (const changed of [{ uid: 1001 }, { gid: 900 }, { mode: 0o40750 }, { mode: 0o41700 }, { isDirectory: () => false }]) {
    assert.throws(() => validateSupervisorWorkerSocket({ ...parent, ...changed }, socket), /supervisor_unavailable/);
    assert.throws(() => validateSupervisorBackendDirectory({ ...parent, ...changed }), /supervisor_unavailable/);
  }
  for (const changed of [{ uid: 1001 }, { gid: 900 }, { mode: 0o140660 }, { mode: 0o141600 }, { nlink: 2 }, { isSocket: () => false }]) {
    assert.throws(() => validateSupervisorWorkerSocket(parent, { ...socket, ...changed }), /supervisor_unavailable/);
  }
});
