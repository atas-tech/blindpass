// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { GUEST_DROP_IN, GUEST_OVERRIDES, SHIPPED_BROKER_UNIT, SHIPPED_BROWSER_DROP_IN, guestBrokerDropIn, shippedExecStart, startShippedBroker } from './shipped-broker-unit.mjs';

const shipped = await readFile(new URL('../../deploy/examples/browser-runtime.conf', import.meta.url), 'utf8');
const base = await readFile(new URL('../../deploy/native/blindpass-broker.service', import.meta.url), 'utf8');
const workload = `node-a:p05-agent:p05-browser-agent.service:998:${'a'.repeat(32)}`;
const fleetWorkload = `node_1:wl_01234567-89ab-cdef-0123-456789abcdef:p05-browser-agent.service:998:${'b'.repeat(32)}`;

test('P05-F6 the guest broker ExecStart is the shipped browser-runtime ExecStart with only the workload group and one --workload changed', () => {
  const tokens = shippedExecStart(shipped);
  assert.equal(tokens[0], '/usr/libexec/blindpass-broker');
  assert.ok(base.includes(`ExecStart=${tokens[0]} `), 'the shipped base unit and drop-in name the same binary');
  for (const value of [workload, fleetWorkload]) {
    const text = guestBrokerDropIn({ shippedDropIn: shipped, workloadGroup: 'p05-browser-agent', workload: value, runtimeMaxSec: 480 });
    const line = text.split('\n').filter(entry => entry.startsWith('ExecStart=')).at(-1).slice('ExecStart='.length).split(' ');
    const expected = [...tokens]; expected[expected.indexOf('--workload-group') + 1] = 'p05-browser-agent';
    assert.deepEqual(line, [...expected, '--workload', value]);
    // Nothing else of the shipped configuration is restated: no sandbox, capability, filter or path directive.
    const keys = text.split('\n').filter(entry => /^[A-Za-z]+=/.test(entry)).map(entry => entry.split('=')[0]);
    assert.deepEqual(keys, ['ExecStart', 'ExecStart', 'Restart', 'TimeoutStopSec', 'RuntimeMaxSec']);
    assert.ok(GUEST_OVERRIDES.every(override => text.includes(`\n${override}`)));
    assert.match(text, /\nRuntimeMaxSec=480s\n/);
  }
  for (const flag of ['--browser-resources', '--browser-runtime', '--node-group blindpass-node', '--map blindpass-login-helper@.service=primary-password', '--map blindpass-session-revoker@.service=fixture-admin']) {
    assert.ok(tokens.join(' ').includes(flag), flag);
  }
});

test('P05-F6 the generator rejects a drop-in that is not the browser-runtime configuration and unsafe inputs', () => {
  const options = { shippedDropIn: shipped, workloadGroup: 'p05-browser-agent', workload, runtimeMaxSec: 180 };
  guestBrokerDropIn(options);
  for (const bad of [{ shippedDropIn: shipped.replace(/ --browser-runtime/, '') }, { shippedDropIn: shipped.replace(/ --browser-resources/, '') },
    { shippedDropIn: shipped.replace('ExecStart=\n', '') }, { shippedDropIn: `${shipped}ExecStart=/bin/sh -c x\n` },
    { shippedDropIn: shipped.replace('--workload-group blindpass-workload', '--workload-group a --workload-group b') },
    { shippedDropIn: shipped.replace('--browser-runtime', '--browser-runtime --workload x:y:z:1:00000000000000000000000000000000') },
    { shippedDropIn: shipped.replace('/usr/libexec/blindpass-broker', 'relative/broker') }, { shippedDropIn: undefined },
    { workloadGroup: 'Bad Group' }, { workloadGroup: 'g\nExecStartPre=/bin/true' }, { workload: `${workload}\nExecStartPre=/bin/true` },
    { workload: 'node-a:p05-agent:unit:998:short' }, { workload: `${workload} --map x=y` }, { runtimeMaxSec: 5 }, { runtimeMaxSec: 99_999 }, { runtimeMaxSec: 1.5 }]) {
    assert.throws(() => guestBrokerDropIn({ ...options, ...bad }), /invalid_broker_unit_configuration/);
  }
});

test('P05-F6 startShippedBroker installs only the generated drop-in, starts the shipped unit and checks the running fragments', async () => {
  const files = new Map([['/etc/systemd/system/blindpass-broker.service', base], [SHIPPED_BROWSER_DROP_IN, shipped]]);
  const written = []; const calls = [];
  const exec = (file, args) => { calls.push([file, ...args]); return args[0] === 'show' ? `/etc/systemd/system/blindpass-broker.service\n${SHIPPED_BROWSER_DROP_IN} ${GUEST_DROP_IN}\n` : ''; };
  await startShippedBroker({ workloadGroup: 'p05-browser-agent', workload, runtimeMaxSec: 180, exec,
    read: async path => files.get(path), write: async (path, text) => { written.push([path, text]); } });
  assert.deepEqual(written.map(([path]) => path), [GUEST_DROP_IN]);
  assert.deepEqual(calls.map(call => call.slice(0, 3).join(' ')), ['systemctl daemon-reload', `systemctl start ${SHIPPED_BROKER_UNIT}`, `systemctl show --value`]);
  // A bootstrap that did not install the shipped unit/drop-in cannot silently run a different broker.
  await assert.rejects(startShippedBroker({ workloadGroup: 'p05-browser-agent', workload, runtimeMaxSec: 180, exec, write: async () => {},
    read: async path => (path === SHIPPED_BROWSER_DROP_IN ? 'ExecStart=\nExecStart=/bin/true\n' : base) }), /invalid_broker_unit_configuration/);
  await assert.rejects(startShippedBroker({ workloadGroup: 'p05-browser-agent', workload, runtimeMaxSec: 180, exec, write: async () => {},
    read: async path => (path === '/etc/systemd/system/blindpass-broker.service' ? '[Service]\nExecStart=/bin/true\n' : shipped) }), /invalid_broker_unit_configuration/);
  const wrongFragments = (file, args) => (args[0] === 'show' ? '/run/systemd/transient/blindpass-broker.service\n' : '');
  await assert.rejects(startShippedBroker({ workloadGroup: 'p05-browser-agent', workload, runtimeMaxSec: 180, exec: wrongFragments, write: async () => {}, read: async path => files.get(path) }), /invalid_broker_unit_configuration/);
});
