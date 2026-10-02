// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { createAgentPipe } from './ai-client-pipe.mjs';

test('P05-PC14A: Root pipe demultiplexes private replies while a normal observer awaits a probe', async () => {
  const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.stdin.on('data', bytes => { const request = JSON.parse(bytes.toString());
    if (request.method === 'p05/private') child.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { ready: true } }) + '\n');
  });
  const forwarded = []; let pipe;
  pipe = createAgentPipe({ child, sendModel: message => forwarded.push(message), onServer: async () => {
    assert.deepEqual(await pipe.bridge.control('restart-stock'), { ready: true });
  } });
  await pipe.bridge.control('startup');
  child.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [] } }) + '\n');
  await pipe.drain(); assert.equal(forwarded.length, 1); assert.equal(pipe.failed, false); pipe.close();
});

test('P05-PC14C: pipe errors and canary replies close input and retain only fixed failure metadata', async () => {
  const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  let model = 0; let failures = 0;
  const pipe = createAgentPipe({ child, sendModel: () => model++, canaries: ['PRIVATE-SOURCE-CANARY'], onFailure: () => failures++ });
  child.stderr.write('PRIVATE-ERROR\nP05-AI-AGENT failed sta');
  child.stderr.write('ge=stock-registry\n');
  assert.equal(pipe.diagnosticStage, 'stock-registry');
  assert.equal(pipe.stderrBytes, 55);
  child.stderr.write('P05-AI-STOCK failed tool=browser_navigate reason=read-');
  child.stderr.write('only\nP05-AI-STOCK failed tool=browser_snapshot reason=PRIVATE-SOURCE-CANARY\n');
  assert.equal(pipe.stockFailure, 'browser_navigate:read-only');
  child.stderr.write('P05-AI-TRANSPORT failed reason=notification\nP05-AI-TRANSPORT failed reason=PRIVATE-SOURCE-CANARY\n');
  assert.equal(pipe.transportFailure, 'notification');
  child.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { text: 'PRIVATE-SOURCE-CANARY' } }) + '\n');
  await pipe.drain(); assert.equal(pipe.failed, true); assert.equal(failures, 1); assert.equal(model, 0);
  assert.equal(child.stdin.writableEnded, true); pipe.close(); assert.equal(failures, 1);
});
