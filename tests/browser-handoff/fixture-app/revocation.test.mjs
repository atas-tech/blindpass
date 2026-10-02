// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AccountRevocation } from './session-revocation.mjs';

test('P05-I03 lost reply account revoke removes every session and preserves other account', () => {
  const revocation = new AccountRevocation(['primary', 'isolation']);
  const records = [{ account: 'primary', tokenDigest: 'a', reference: '1' },
    { account: 'primary', tokenDigest: 'b', reference: '2' }, { account: 'isolation', tokenDigest: 'c', reference: '3' }];
  const sessions = new Map(records.map((record) => [record.tokenDigest, record]));
  const references = new Map(records.map((record) => [record.reference, record]));
  revocation.revoke('primary', sessions, references); revocation.revoke('primary', sessions, references);
  assert.deepEqual([...sessions.keys()], ['c']); assert.deepEqual([...references.keys()], ['3']);
  assert.ok(!revocation.canCommit('unknown', undefined));
  assert.throws(() => revocation.revoke('unknown', sessions, references), /invalid_account/);
});

test('P05-I03 revoke invalidates pending authentication that could create a late website session', () => {
  const revocation = new AccountRevocation(['primary', 'isolation']);
  const pending = revocation.begin('primary'); const independent = revocation.begin('isolation');
  assert.ok(revocation.canCommit('primary', pending));
  revocation.revoke('primary', new Map(), new Map());
  assert.ok(!revocation.canCommit('primary', pending)); assert.ok(revocation.canCommit('isolation', independent));
  assert.ok(revocation.canCommit('primary', revocation.begin('primary')));
});
