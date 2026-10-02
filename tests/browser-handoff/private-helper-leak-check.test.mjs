// SPDX-License-Identifier: AGPL-3.0-only
// Host test of the end-of-run unit leak check in private-helper-guest.sh, run against a stub systemctl.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const script = await readFile(new URL('./private-helper-guest.sh', import.meta.url), 'utf8');
const start = script.indexOf('assert_units_stopped() {');
const end = script.indexOf('\n}\n', start);
assert.ok(start > 0 && end > start, 'leak-check function present');
const fn = script.slice(start, end + 3);

async function run(t, listing, { status = 0, pattern = 'blindpass-browser@*.service', show = {}, cgroupRoot } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'blindpass-leak-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  // `systemctl show --property=X --value UNIT` answers from FAKE_SHOW_<X>; every other call prints the listing.
  await writeFile(join(directory, 'systemctl'), '#!/usr/bin/env bash\nif [[ ${1:-} == show ]]; then\n  case "$2" in\n    --property=Result) printf "%s\\n" "${FAKE_SHOW_RESULT:-signal}";;\n    --property=ControlGroup) printf "%s\\n" "${FAKE_SHOW_CGROUP:-}";;\n  esac\n  exit "${FAKE_SHOW_STATUS:-0}"\nfi\nprintf "%s" "$FAKE_LISTING"\nexit "${FAKE_STATUS:-0}"\n');
  await chmod(join(directory, 'systemctl'), 0o755);
  return spawnSync('bash', ['-c', `set -Eeuo pipefail\n${fn}\nassert_units_stopped "$1"`, '_', pattern],
    { encoding: 'utf8', env: { PATH: `${directory}:${process.env.PATH}`, FAKE_LISTING: listing, FAKE_STATUS: String(status),
      ...(show.result === undefined ? {} : { FAKE_SHOW_RESULT: show.result }), ...(show.cgroup === undefined ? {} : { FAKE_SHOW_CGROUP: show.cgroup }),
      ...(show.status === undefined ? {} : { FAKE_SHOW_STATUS: String(show.status) }),
      BLINDPASS_CGROUP_ROOT: cgroupRoot ?? join(directory, 'cgroup') } });
}
const row = (unit, load, active, sub) => `${unit} ${load} ${active} ${sub} BlindPass test unit\n`;

test('P05-F2 leak check: no instances, or only inactive/dead instances, pass', async t => {
  assert.equal((await run(t, '')).status, 0);
  assert.equal((await run(t, row('blindpass-browser@0-1-2.service', 'loaded', 'inactive', 'dead') + row('blindpass-browser@0-3-4.service', 'not-found', 'inactive', 'dead'))).status, 0);
});

test('P05-F2 leak check: active, activating, deactivating and reloading units are failures that name the unit', async t => {
  for (const [active, sub] of [['active', 'running'], ['activating', 'start'], ['deactivating', 'stop-sigterm'], ['reloading', 'reload'], ['inactive', 'failed'], ['active', 'listening']]) {
    const result = await run(t, row('blindpass-browser@0-9-9.service', 'loaded', active, sub));
    assert.notEqual(result.status, 0, `${active}/${sub}`);
    assert.match(result.stderr, /^P05-UNIT-LEAK pattern=blindpass-browser@\*\.service unit=blindpass-browser@0-9-9\.service load=loaded active=/);
    assert.equal(result.stdout, '');
  }
});

test('P05-F2 leak check: a failed unit left by a deliberate kill passes only with no process in its control group, and is reported with its result', async t => {
  const failed = row('blindpass-login-helper@4-3571-0.service', 'loaded', 'failed', 'failed');
  const gone = await run(t, failed, { pattern: 'blindpass-login-helper@*.service', show: { result: 'signal', cgroup: '' } });
  assert.equal(gone.status, 0);
  assert.match(gone.stderr, /^P05-UNIT-FAILED pattern=blindpass-login-helper@\*\.service unit=blindpass-login-helper@4-3571-0\.service result=signal control_group=none$/m);
  // A control group that still lists a process is a leak even though the unit says failed.
  const root = await mkdtemp(join(tmpdir(), 'blindpass-cgroup-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'system.slice', 'leaky.service'), { recursive: true });
  await writeFile(join(root, 'system.slice', 'leaky.service', 'cgroup.procs'), '4242\n');
  const live = await run(t, failed, { pattern: 'blindpass-login-helper@*.service', show: { result: 'signal', cgroup: '/system.slice/leaky.service' }, cgroupRoot: root });
  assert.notEqual(live.status, 0);
  assert.match(live.stderr, /^P05-UNIT-LEAK pattern=blindpass-login-helper@\*\.service unit=blindpass-login-helper@4-3571-0\.service load=loaded active=failed sub=failed processes=1$/m);
  // An empty cgroup file (or one that is already gone) is clean; a failing `systemctl show` is never read as clean.
  await writeFile(join(root, 'system.slice', 'leaky.service', 'cgroup.procs'), '');
  assert.equal((await run(t, failed, { pattern: 'blindpass-login-helper@*.service', show: { cgroup: '/system.slice/leaky.service' }, cgroupRoot: root })).status, 0);
  assert.equal((await run(t, failed, { pattern: 'blindpass-login-helper@*.service', show: { status: 1 } })).status, 2);
});

test('P05-F2 leak check: one bad instance among clean ones fails, and a failing systemctl is never read as "no leak"', async t => {
  const mixed = row('blindpass-browser@0-1-2.service', 'loaded', 'inactive', 'dead') + row('blindpass-browser@0-3-4.service', 'loaded', 'deactivating', 'stop-sigterm');
  assert.notEqual((await run(t, mixed)).status, 0);
  const broken = await run(t, '', { status: 1 });
  assert.equal(broken.status, 2);
});

test('P05-F2 leak check: the end-of-run list covers every unit family the guests start', () => {
  for (const pattern of ['blindpass-login-helper@*.service', 'blindpass-browser@*.service', 'blindpass-runtime-manager@*.service',
    'blindpass-browser-supervisor@*.service', 'blindpass-session-revoker@*.service', 'p05-native-supervisor@*.service', 'blindpass-broker.service']) {
    assert.ok(script.includes(`'${pattern}'`), pattern);
  }
  assert.ok(!/--state=running/.test(script.slice(end)), 'the old running-only check is gone');
});
