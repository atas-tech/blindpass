// SPDX-License-Identifier: MIT
const key = { type: 'string', pattern: '^[A-Za-z0-9_-]{16,128}$', maxLength: 128 };
const schema = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const safe = (value, operation, args) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some(name => !['status', 'requestKey', 'eventKey', 'grantId', 'operationId', 'outcome', 'cancellation', 'contextHandle'].includes(name))) throw new Error('invalid_broker_result');
  if (!['requested', 'uncertain', 'unknown', 'pending', 'cancelling', 'granted', 'ready', 'closed', 'cancellation_requested'].includes(value.status)) throw new Error('invalid_broker_result');
  for (const name of ['requestKey', 'eventKey', 'grantId', 'operationId']) if (value[name] !== undefined && (typeof value[name] !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(value[name]))) throw new Error('invalid_broker_result');
  if (value.contextHandle !== undefined && (typeof value.contextHandle !== 'string' || !/^ctx_[a-f0-9]{64}$/.test(value.contextHandle))) throw new Error('invalid_broker_result');
  if (value.outcome !== undefined && !['rejected', 'expired', 'cancelled', 'denied', 'completed'].includes(value.outcome)) throw new Error('invalid_broker_result');
  if (value.cancellation !== undefined && !['requested', 'closed', 'unconfirmed'].includes(value.cancellation)) throw new Error('invalid_broker_result');
  let expected;
  if (operation === 'request' && value.requestKey === args.requestKey) {
    if (value.status === 'requested') expected = ['status', 'requestKey', 'eventKey'];
    if (value.status === 'uncertain') expected = ['status', 'requestKey', 'cancellation'];
  }
  if (operation === 'status' && value.eventKey === args.eventKey) {
    if (['unknown', 'pending', 'cancelling'].includes(value.status)) expected = ['status', 'eventKey'];
    if (value.status === 'ready') expected = ['status', 'eventKey', 'contextHandle'];
    if (value.status === 'granted') expected = ['status', 'eventKey', 'grantId', 'operationId'];
    if (value.status === 'closed') expected = ['status', 'eventKey', 'outcome'];
  }
  if (operation === 'cancel') {
    if (value.status === 'cancellation_requested') expected = ['status'];
    if (value.status === 'closed') expected = ['status', 'outcome'];
    if (value.status === 'uncertain') expected = ['status', 'cancellation'];
  }
  if (!expected || Object.keys(value).length !== expected.length || expected.some(name => value[name] === undefined)) throw new Error('invalid_broker_result');
  return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: { ...value } };
};
export function createBrokerTools(client) {
  if (!client || ['request', 'status', 'cancel'].some(name => typeof client[name] !== 'function')) throw new Error('invalid_broker_configuration');
  return [
    { name: 'blindpass_request_operation', description: 'Request the approved browser resource. Choose one opaque requestKey and reuse it unchanged for retries. Returns request metadata; it does not confirm a browser is ready.',
      inputSchema: schema({ action: { type: 'string', enum: ['browser.session'] }, resourceId: { type: 'string', pattern: '^[A-Za-z0-9_-]{1,128}$', maxLength: 128 },
        requestKey: key, purpose: { type: 'string', maxLength: 512 }, ttlSeconds: { type: 'integer', minimum: 1, maximum: 120 } }, ['action', 'resourceId', 'requestKey']),
      execute: async (args, context) => safe(await client.request(args, context.mcpReq.signal), 'request', args) },
    { name: 'blindpass_operation_status', description: 'Read metadata for the request owned by this invocation. Grant status is not proof of browser readiness or website cleanup.',
      inputSchema: schema({ eventKey: key }, ['eventKey']), execute: async (args, context) => safe(await client.status(args.eventKey, context.mcpReq.signal), 'status', args) },
    { name: 'blindpass_cancel_operation', description: 'Withdraw a browser request by eventKey or requestKey. Choose exactly one. A requested cancellation is not verified website or runtime cleanup.',
      inputSchema: schema({ eventKey: key, requestKey: key }), execute: async (args, context) => safe(await client.cancel(args, context.mcpReq.signal), 'cancel', args) },
  ];
}
