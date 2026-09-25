// SPDX-License-Identifier: AGPL-3.0-only

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmod, readFile, writeFile } from 'node:fs/promises';

const baseUrl = process.env.P03_CONTROLLER_URL ?? 'http://127.0.0.1:3200';
const origin = process.env.P03_UI_ORIGIN ?? 'http://127.0.0.1:5175';
const seedPath = process.env.P03_ADMIN_SEED_FILE;

async function main() {
  const [command, ...args] = process.argv.slice(2);
  switch (command) {
    case 'issuer-fingerprint':
      return print(await issuerFingerprint());
    case 'create-enrollment':
      return createEnrollment(...args);
    case 'approve-enrollment':
      return approveEnrollment(...args);
    case 'policy':
      return setPolicy();
    case 'create-workload':
      return createWorkload(...args);
    case 'operation':
      return createAndApproveOperation(...args);
    case 'operation-status':
      return operationStatus(...args);
    case 'node-status':
      return nodeStatus(...args);
    case 'rotate-node-key':
      return rotateNodeKey(...args);
    case 'revoke-node':
      return revokeNode(...args);
    case 'audit-check':
      return auditCheck(...args);
    default:
      throw new Error('unknown p03-admin command');
  }
}

async function issuerFingerprint() {
  const capabilities = await api('/api/v3/capabilities', { method: 'GET' }, false);
  if (typeof capabilities.issuer_pub !== 'string') {
    throw new Error('controller fleet issuer is unavailable');
  }
  const publicKey = Buffer.from(capabilities.issuer_pub, 'base64url');
  if (publicKey.length !== 32 || publicKey.toString('base64url') !== capabilities.issuer_pub) {
    throw new Error('controller issuer key is malformed');
  }
  return createHash('sha256').update(publicKey).digest('hex');
}

async function createEnrollment(name, tokenPath) {
  if (!name || !tokenPath) throw new Error('create-enrollment requires NAME TOKEN_FILE');
  const enrollment = await api('/api/v3/enrollments', {
    method: 'POST',
    headers: writeHeaders(),
    body: JSON.stringify({ name }),
  });
  await writeFile(tokenPath, enrollment.token, { flag: 'wx', mode: 0o600 });
  await chmod(tokenPath, 0o600);
  print({ id: enrollment.id, node_id: enrollment.node_id, expires_at: enrollment.expires_at });
}

async function approveEnrollment(id) {
  if (!id) throw new Error('approve-enrollment requires ENROLLMENT_ID');
  const enrollment = await api(`/api/v3/enrollments/${encodeURIComponent(id)}`, { method: 'GET' });
  if (enrollment.status !== 'submitted' || typeof enrollment.fingerprint !== 'string') {
    throw new Error(`enrollment is ${enrollment.status}, expected submitted`);
  }
  const approved = await api(`/api/v3/enrollments/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    headers: writeHeaders({ 'if-match': `"${enrollment.version}"` }),
    body: JSON.stringify({
      expected_fingerprint: enrollment.fingerprint,
      expected_version: enrollment.version,
    }),
  });
  print({ id: approved.id, name: approved.name, status: approved.status });
}

async function setPolicy() {
  const policy = await api('/api/v3/policies', { method: 'GET' });
  const updated = await api('/api/v3/policies', {
    method: 'PUT',
    headers: writeHeaders({ 'if-match': `"${policy.version}"` }),
    body: JSON.stringify({
      expected_version: policy.version,
      rules: [{
        id: 'p03-approve-noop-file',
        action: 'noop.marker',
        mode: 'file',
        decision: 'pending_approval',
        approval_required: true,
        max_ttl_seconds: 120,
      }],
    }),
  });
  print({ version: updated.version, decision: 'pending_approval' });
}

async function createWorkload(nodeId, name, account) {
  const uid = /^uid:([1-9][0-9]*)$/.exec(account ?? '');
  if (!nodeId || !name || !uid || Number(uid[1]) > 0xffff_ffff) {
    throw new Error('create-workload requires NODE_ID NAME OS_ACCOUNT');
  }
  const workload = await api('/api/v3/workloads', {
    method: 'POST',
    headers: writeHeaders(),
    body: JSON.stringify({
      node_id: nodeId,
      name: `p03-${name}`,
      unit: 'blindpass-p03-workload.service',
      account,
      consumption_mode: 'file',
      local_ceiling_seconds: 120,
    }),
  });
  print({ id: workload.id, node_id: workload.node_id, registration_version: workload.registration_version });
}

async function createAndApproveOperation(workloadId, eventKey, invocationId, resourceId, purpose) {
  if (!workloadId || !eventKey || !invocationId || !resourceId || !purpose) {
    throw new Error('operation requires WORKLOAD_ID EVENT_KEY INVOCATION_ID RESOURCE_ID PURPOSE');
  }
  const headers = writeHeaders({
    'idempotency-key': `p03-${randomUUID().replaceAll('-', '')}`,
  });
  const createRequest = {
    method: 'POST',
    headers,
    body: JSON.stringify({
      workload_id: workloadId,
      action: 'noop.marker',
      mode: 'file',
      purpose,
      resource_id: resourceId,
      invocation_id: invocationId,
      ttl_seconds: 60,
      broker_event_key: eventKey,
    }),
  };
  let operation;
  for (let attempt = 0; attempt < 180; attempt += 1) {
    try {
      operation = await api('/api/v3/operations', createRequest);
      break;
    } catch (error) {
      if (error.status !== 409 || error.code !== 'broker_evidence_required') throw error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  if (!operation) throw new Error('broker event was not accepted within the evidence window');
  if (operation.status !== 'awaiting_approval' || !operation.approval_id) {
    throw new Error(`operation entered unexpected state ${operation.status}`);
  }
  const approval = await api(`/api/v3/approvals/${encodeURIComponent(operation.approval_id)}`, { method: 'GET' });
  if (!Array.isArray(approval.operation_ids) || !approval.operation_ids.includes(operation.id)) {
    throw new Error('approval did not include the requested operation');
  }
  await api(`/api/v3/approvals/${encodeURIComponent(operation.approval_id)}/approve`, {
    method: 'POST',
    headers: writeHeaders({
      'idempotency-key': `p03-approve-${randomUUID().replaceAll('-', '')}`,
      'if-match': `"${approval.version}"`,
    }),
    body: JSON.stringify({
      expected_status: 'pending',
      expected_version: approval.version,
      operation_ids: [operation.id],
    }),
  });
  const granted = await api(`/api/v3/operations/${encodeURIComponent(operation.id)}`, { method: 'GET' });
  if (granted.status !== 'granted' || typeof granted.grant_id !== 'string') {
    throw new Error(`approved operation entered unexpected state ${granted.status}`);
  }
  print({ operation_id: operation.id, grant_id: granted.grant_id, status: granted.status });
}

async function operationStatus(id) {
  if (!id) throw new Error('operation-status requires OPERATION_ID');
  const operation = await api(`/api/v3/operations/${encodeURIComponent(id)}`, { method: 'GET' });
  print({ id: operation.id, status: operation.status, grant_id: operation.grant_id ?? null });
}

async function nodeStatus(id) {
  if (!id) throw new Error('node-status requires NODE_ID');
  const node = await api(`/api/v3/nodes/${encodeURIComponent(id)}`, { method: 'GET' });
  print({
    id: node.id,
    status: node.status,
    revocation_pending: node.revocation_pending,
    rotation_pending: node.rotation_pending,
    pending_key_version: node.pending_key_version,
    key_version: node.key_version,
    last_seen_at: node.last_seen_at,
  });
}

async function rotateNodeKey(id, metadataJson) {
  if (!id || !metadataJson) throw new Error('rotate-node-key requires NODE_ID ROTATION_METADATA');
  let metadata;
  try {
    metadata = JSON.parse(metadataJson);
  } catch {
    throw new Error('broker rotation metadata is malformed');
  }
  if (!Number.isSafeInteger(metadata.key_version) || metadata.key_version < 2
      || typeof metadata.signing_pub !== 'string' || typeof metadata.recipient_pub !== 'string'
      || typeof metadata.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(metadata.fingerprint)) {
    throw new Error('broker rotation metadata is malformed');
  }
  const signing = Buffer.from(metadata.signing_pub, 'base64url');
  const recipient = Buffer.from(metadata.recipient_pub, 'base64url');
  if (signing.length !== 32 || recipient.length !== 32
      || signing.toString('base64url') !== metadata.signing_pub
      || recipient.toString('base64url') !== metadata.recipient_pub) {
    throw new Error('broker rotation public keys are malformed');
  }
  const fingerprint = createHash('sha256').update(Buffer.concat([
    Buffer.from('blindpass:fleet-node-fingerprint:v1\0'), signing, recipient,
  ])).digest('hex');
  if (fingerprint !== metadata.fingerprint) throw new Error('broker rotation fingerprint does not match its keys');

  const node = await api(`/api/v3/nodes/${encodeURIComponent(id)}`, { method: 'GET' });
  if (node.status === 'revoked' || node.rotation_pending === true
      || metadata.key_version !== node.key_version + 1) {
    throw new Error('node state changed or another key rotation is pending');
  }
  const updated = await api(`/api/v3/nodes/${encodeURIComponent(id)}/rotate-key`, {
    method: 'POST',
    headers: writeHeaders(),
    body: JSON.stringify({
      expected_key_version: node.key_version,
      expected_fingerprint: metadata.fingerprint,
      signing_pub: metadata.signing_pub,
      recipient_pub: metadata.recipient_pub,
    }),
  });
  if (updated.rotation_pending !== true || updated.pending_key_version !== metadata.key_version) {
    throw new Error('controller did not stage the requested node key rotation');
  }
  print({ id: updated.id, key_version: updated.key_version, pending_key_version: updated.pending_key_version, rotation_pending: updated.rotation_pending });
}

async function revokeNode(id) {
  if (!id) throw new Error('revoke-node requires NODE_ID');
  const node = await api(`/api/v3/nodes/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: writeHeaders(),
  });
  print({ id: node.id, status: node.status, revocation_pending: node.revocation_pending });
}

async function auditCheck(nodeId, operationId) {
  const [workloadId, invocationId, grantId] = process.argv.slice(-3);
  if (!nodeId || !operationId || !workloadId || !invocationId || !grantId) {
    throw new Error('audit-check requires NODE_ID OPERATION_ID WORKLOAD_ID INVOCATION_ID GRANT_ID');
  }
  const operation = await api(`/api/v3/operations/${encodeURIComponent(operationId)}`, { method: 'GET' });
  const grant = await api(`/api/v3/grants/${encodeURIComponent(grantId)}`, { method: 'GET' });
  if (operation.id !== operationId || operation.node_id !== nodeId
      || operation.workload_id !== workloadId || operation.grant_id !== grantId
      || operation.status !== 'completed') {
    throw new Error('completed operation is not bound to the expected node and workload');
  }
  if (grant.id !== grantId || grant.operation_id !== operationId || grant.node_id !== nodeId
      || grant.workload_id !== workloadId || grant.invocation_id !== invocationId
      || grant.status !== 'consumed') {
    throw new Error('consumed grant is not bound to the expected operation invocation');
  }
  const audit = await api('/api/v3/admin/audit?limit=100', { method: 'GET' });
  const rows = audit.items ?? audit.events ?? [];
  const matches = rows.filter((row) => row.actor_id === nodeId
      && row.event === 'operation_result' && row.resource_id === operationId
      && row.metadata?.operation_id === operationId && row.metadata?.grant_id === grantId
      && row.metadata?.status === 'completed');
  if (matches.length !== 1) {
    throw new Error('controller audit does not contain the completed broker result');
  }
  print({
    node_id: nodeId,
    workload_id: workloadId,
    invocation_id: invocationId,
    operation_id: operationId,
    grant_id: grantId,
    operation_status: operation.status,
    grant_status: grant.status,
    result_audited: true,
    result_events: matches.length,
  });
}

async function api(path, init, authenticated = true) {
  const headers = new Headers(init.headers ?? {});
  headers.set('accept', 'application/json');
  if (init.body !== undefined) headers.set('content-type', 'application/json');
  if (authenticated) {
    const seed = await adminSeed();
    headers.set('cookie', `bp_session=${seed.session_id}; bp_csrf=${seed.csrf_token}`);
    if (!['GET', 'HEAD'].includes((init.method ?? 'GET').toUpperCase())) {
      headers.set('origin', origin);
      headers.set('x-csrf-token', seed.csrf_token);
    }
  }
  const response = await fetch(new URL(path, baseUrl), { ...init, headers });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`controller returned malformed JSON (${response.status})`);
  }
  if (!response.ok) {
    const code = typeof body.error === 'string' ? body.error : 'request_failed';
    const error = new Error(`controller request failed (${response.status} ${code})`);
    error.status = response.status;
    error.code = code;
    throw error;
  }
  return body;
}

async function adminSeed() {
  if (!seedPath) throw new Error('P03_ADMIN_SEED_FILE is required');
  const seed = JSON.parse(await readFile(seedPath, 'utf8'));
  if (!seed.local_admin?.session_id || !seed.local_admin?.csrf_token) {
    throw new Error('test fixture has no local administrator session');
  }
  const cookie = `bp_session=${seed.local_admin.session_id}; bp_csrf=${seed.local_admin.csrf_token}`;
  const statusResponse = await fetch(new URL('/api/v3/admin/session', baseUrl), {
    headers: { accept: 'application/json', cookie },
  });
  if (!statusResponse.ok) throw new Error('test administrator session is unavailable');
  const session = await statusResponse.json();
  if (session.must_change_password === true) {
    if (typeof seed.local_admin.temporary_password !== 'string') {
      throw new Error('test administrator password change cannot be completed');
    }
    const changed = await fetch(new URL('/api/v3/admin/session/change-password', baseUrl), {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        cookie,
        origin,
        'x-csrf-token': seed.local_admin.csrf_token,
      },
      body: JSON.stringify({
        current_password: seed.local_admin.temporary_password,
        new_password: randomBytes(32).toString('base64url'),
      }),
    });
    if (!changed.ok) throw new Error('test administrator password change was rejected');
  }
  return seed.local_admin;
}

function writeHeaders(extra = {}) {
  return { ...extra };
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

main().catch((error) => {
  process.stderr.write(`p03-admin: ${error.message}\n`);
  process.exitCode = 1;
});
