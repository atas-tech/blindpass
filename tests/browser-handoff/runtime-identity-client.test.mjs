// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateRuntimeIdentityMetadata, encodeRuntimeIdentityProof } from '../../helpers/login/src/runtime-identity-client.mjs';

test('P05-I02 reverse worker proof requires the fixed root-owned group socket boundary', () => {
  const parent = { isDirectory: () => true, uid: 0, gid: 902, mode: 0o40750 };
  const socket = { isSocket: () => true, uid: 0, gid: 902, mode: 0o140660, nlink: 1 };
  assert.doesNotThrow(() => validateRuntimeIdentityMetadata(parent, socket, 61001, [902, 61001]));
  for (const changed of [{ uid: 61001 }, { gid: 0 }, { mode: 0o40770 }, { mode: 0o41750 }, { isDirectory: () => false }]) {
    assert.throws(() => validateRuntimeIdentityMetadata({ ...parent, ...changed }, socket, 61001, [902]));
  }
  for (const changed of [{ uid: 61001 }, { gid: 903 }, { mode: 0o140666 }, { mode: 0o141660 }, { nlink: 2 }, { isSocket: () => false }]) {
    assert.throws(() => validateRuntimeIdentityMetadata(parent, { ...socket, ...changed }, 61001, [902]));
  }
  assert.throws(() => validateRuntimeIdentityMetadata(parent, socket, 0, [902]));
  assert.throws(() => validateRuntimeIdentityMetadata(parent, socket, 1001, [1001]));
});

test('P05-I02 worker identity proof is a bounded versioned private frame', () => {
  const challenge = 'a'.repeat(64);
  const frame = encodeRuntimeIdentityProof(challenge);
  assert.equal(frame.readUInt32BE(), frame.length - 4);
  assert.deepEqual(JSON.parse(frame.subarray(4)), { version: 1, challenge });
  assert.ok(frame.length <= 260); frame.fill(0);
  for (const bad of ['', 'a'.repeat(63), 'A'.repeat(64), 'a'.repeat(65), undefined, { endpoint: 'PRIVATE-CANARY' }]) {
    assert.throws(() => encodeRuntimeIdentityProof(bad), /runtime_identity_unavailable/);
  }
});
