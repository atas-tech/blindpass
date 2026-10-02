// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { waitRuntimeRemoval } from './runtime-cleanup.mjs';

const absent = () => { throw Object.assign(new Error('private-path-canary'), { code: 'ENOENT' }); };
function fixture(overrides = {}) {
  let clock = 0;
  return { cgroup: '/fixed/cgroup', profile: '/fixed/profile', now: async () => clock,
    read: async () => '', inspect: async () => absent(), delay: async ms => { clock += ms; },
    ...overrides };
}

test('P05-PC13: cgroup empty precedes profile removal; require both within the original bound', async () => {
  let inspections = 0;
  const elapsed = await waitRuntimeRemoval(fixture({ inspect: async () => ++inspections < 3 ? {} : absent() }));
  assert.equal(inspections, 3); assert.equal(elapsed, 50);
});

test('P05-PC13: absent cgroup and profile pass; an existing profile cannot extend the cleanup bound', async () => {
  assert.equal(await waitRuntimeRemoval(fixture({ read: async () => absent() })), 0);
  await assert.rejects(waitRuntimeRemoval(fixture({ inspect: async () => ({}) })), { message: 'cleanup_deadline' });
  await assert.rejects(waitRuntimeRemoval(fixture({ read: async () => '123\n' })), { message: 'cleanup_deadline' });
  await assert.rejects(waitRuntimeRemoval(fixture({ startedAt: -5000 })), { message: 'cleanup_deadline' });
});

test('P05-PC13: permission and filesystem errors cannot establish removal or reflect private paths', async () => {
  const denied = async () => { throw Object.assign(new Error('private-path-canary'), { code: 'EACCES' }); };
  await assert.rejects(waitRuntimeRemoval(fixture({ read: denied })), { message: 'cleanup_cgroup' });
  await assert.rejects(waitRuntimeRemoval(fixture({ inspect: denied })), { message: 'cleanup_profile' });
});
