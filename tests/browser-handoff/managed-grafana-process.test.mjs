// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTestTls } from './fixture-app/test-tls.mjs';
import { startManagedGrafana } from './managed-grafana.mjs';

test('P05-PC12: failed app process retains exit status and withholds its output before cleanup', async t => {
  const home = await mkdtemp(join(tmpdir(), 'blindpass-grafana-process-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const tls = await createTestTls(); t.after(() => tls.close());
  await mkdir(join(home, 'bin'));
  await writeFile(join(home, 'bin/grafana'), '#!/bin/sh\nprintf PRIVATE-PROCESS-CANARY\nprintf PRIVATE-PROCESS-CANARY >&2\nexit 37\n', { mode: 0o700 });
  await assert.rejects(startManagedGrafana({ home, ...tls, accounts: [
    { username: 'primary', password: 'dummy-password', report: 'Report' },
    { username: 'isolation', password: 'dummy-password', report: 'Isolation' },
  ] }), error => {
    assert.equal(error.message, 'Managed Grafana setup failed during readiness');
    assert.equal(error.grafanaExitCode, 37);
    assert.equal(error.grafanaExitSignal, null);
    assert.equal(error.grafanaHealthStatus, 0);
    assert.equal(error.grafanaHealthVersionMatches, false);
    assert.ok(!JSON.stringify(error.grafanaStartup).includes('PRIVATE-PROCESS-CANARY'));
    assert.ok(!String(error).includes('PRIVATE-PROCESS-CANARY'));
    return true;
  });
});

test('P05-PC14C: unique administrator is written only to private app configuration', async t => {
  const home = await mkdtemp(join(tmpdir(), 'blindpass-grafana-admin-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const tls = await createTestTls(); t.after(() => tls.close());
  await mkdir(join(home, 'bin'));
  await writeFile(join(home, 'bin/grafana'), '#!/bin/sh\nif grep -q "^admin_user = p05_admin_canary$" "$5"; then exit 37; fi\nexit 38\n', { mode: 0o700 });
  await assert.rejects(startManagedGrafana({ home, ...tls, administrator: 'p05_admin_canary', accounts: [
    { username: 'primary', password: 'dummy-password', report: 'Report' },
    { username: 'isolation', password: 'dummy-password', report: 'Isolation' },
  ] }), error => { assert.equal(error.grafanaExitCode, 37); assert.ok(!String(error).includes('p05_admin_canary')); return true; });
});

test('P05-PC14C: invalid administrator names are rejected before private state/process setup', async () => {
  for (const administrator of ['admin\nextra = true', 'Uppercase', 'a'.repeat(33), 'primary', 'isolation']) {
    await assert.rejects(startManagedGrafana({ home: '/unused', key: 'dummy', cert: 'dummy', ca: 'dummy', administrator,
      accounts: [{ username: 'primary', password: 'dummy-password', report: 'Report' },
        { username: 'isolation', password: 'dummy-password', report: 'Isolation' }] }),
    { message: 'Invalid managed Grafana fixture configuration' });
  }
});
