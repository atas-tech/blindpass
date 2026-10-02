// SPDX-License-Identifier: AGPL-3.0-only
// Readiness evidence only. This does not authorize a production delivery route.
const REVISIONS = new Set(['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28']);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function clientProtocolMetadata(message) {
  if (!record(message)) return undefined;
  let type; let revision; let capabilities;
  if (message.method === 'initialize' && record(message.params)) {
    type = 'initialize'; revision = message.params.protocolVersion; capabilities = message.params.capabilities;
  } else if (record(message.params?._meta)
    && Object.hasOwn(message.params._meta, 'io.modelcontextprotocol/protocolVersion')) {
    type = 'request'; revision = message.params._meta['io.modelcontextprotocol/protocolVersion'];
    capabilities = message.params._meta['io.modelcontextprotocol/clientCapabilities'];
  } else return undefined;
  const form = record(capabilities?.elicitation?.form);
  const url = record(capabilities?.elicitation?.url);
  const reviewed = type === 'initialize' ? revision === '2025-11-25' : revision === '2026-07-28';
  return { type, protocol: REVISIONS.has(revision) ? revision : 'other', form, url,
    urlElicitationPermitted: reviewed && url };
}
