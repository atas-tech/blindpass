// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { clientProtocolMetadata } from './client-protocol-metadata.mjs';

test('M01 readiness: URL declaration under an older initialize revision cannot permit URL elicitation', () => {
  for (const protocolVersion of ['2024-11-05', '2025-03-26', '2025-06-18']) {
    assert.deepEqual(clientProtocolMetadata({ method: 'initialize', params: { protocolVersion, capabilities: { elicitation: { form: {}, url: {} } } } }),
      { type: 'initialize', protocol: protocolVersion, form: true, url: true, urlElicitationPermitted: false });
  }
});

test('M01 readiness: only explicit URL objects on reviewed revisions pass; empty/form-only/null/array declarations deny', () => {
  const record = elicitation => clientProtocolMetadata({ method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: { elicitation } } });
  for (const elicitation of [undefined, {}, { form: {} }, { url: null }, { url: [] }, { url: true }]) assert.equal(record(elicitation).urlElicitationPermitted, false);
  assert.equal(record({ url: {} }).urlElicitationPermitted, true);
});

test('M01 readiness: modern per-request metadata is observed without requiring initialize', () => {
  const _meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': { elicitation: { url: {} } } };
  assert.deepEqual(clientProtocolMetadata({ method: 'tools/list', params: { _meta } }),
    { type: 'request', protocol: '2026-07-28', form: false, url: true, urlElicitationPermitted: true });
  _meta['io.modelcontextprotocol/protocolVersion'] = '2025-11-25';
  assert.equal(clientProtocolMetadata({ method: 'tools/list', params: { _meta } }).urlElicitationPermitted, false);
});

test('M01 readiness: unsupported versions and private client fields are never reflected', () => {
  const canary = 'PRIVATE-URL-CODE-CLIENT-CANARY';
  const value = clientProtocolMetadata({ method: 'initialize', params: { protocolVersion: canary, clientInfo: { name: canary }, capabilities: { elicitation: { url: {} } }, url: canary } });
  assert.equal(value.protocol, 'other'); assert.equal(value.urlElicitationPermitted, false);
  assert.ok(!JSON.stringify(value).includes(canary));
  for (const message of [null, [], {}, { method: 'tools/list', params: {} }]) assert.equal(clientProtocolMetadata(message), undefined);
});
