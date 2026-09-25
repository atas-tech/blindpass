import assert from "node:assert/strict";
import { httpRequest, jsonRequestBody, withBearer } from "../../packages/contract-tests/src/http.ts";
import { SECRET_NAMES } from "../../packages/contract-tests/src/fixtures.ts";
import { startRustCrashTestAdapter } from "../../packages/contract-tests/src/adapter.ts";

const ORIGIN = "http://allowed.contract.test";
const CIPHERTEXT = "Q0FOQVJZX1BfMDJfQ1JBU0hfUEFZTE9BRA==";
const ENC = "ZW5jLXBvbGljeQ==";

function assertStatus(response, expected, label) {
  assert.equal(response.status, expected, `${label} returned an unexpected HTTP status`);
}

async function expectConnectionDrop(operation, label) {
  let dropped = false;
  try {
    await operation();
  } catch {
    dropped = true;
  }
  assert.equal(dropped, true, `${label} returned a response instead of losing the connection during process exit`);
}

function requesterHeaders(adapter) {
  return withBearer(adapter.fixture.agents.requester.accessToken);
}

async function createSubmittedSecret(adapter, label) {
  const created = await httpRequest(adapter.baseUrl, "/api/v2/secret/request", withBearer(
    adapter.fixture.agents.requester.accessToken,
    {
      ...jsonRequestBody({ public_key: "Y29udHJhY3QtcHViLWtleQ==", description: label })
    }
  ));
  assertStatus(created, 201, "one-use secret request creation");
  const secretUrl = new URL(created.body.secret_url);
  const requestId = secretUrl.searchParams.get("id");
  const submitSignature = secretUrl.searchParams.get("submit_sig");
  assert.ok(requestId && submitSignature, "one-use secret request returned its signed submit capability");
  const submitted = await httpRequest(adapter.baseUrl,
    `/api/v2/secret/submit/${requestId}?sig=${encodeURIComponent(submitSignature)}`,
    jsonRequestBody({ enc: ENC, ciphertext: CIPHERTEXT }));
  assertStatus(submitted, 201, "one-use secret submission");
  return requestId;
}

async function createSubmittedExchange(adapter, label) {
  const requested = await httpRequest(adapter.baseUrl, "/api/v2/secret/exchange/request", withBearer(
    adapter.fixture.agents.requester.accessToken,
    {
      ...jsonRequestBody({
        public_key: "Y29udHJhY3QtcHViLWtleQ==",
        secret_name: SECRET_NAMES.allowed,
        purpose: label,
        fulfiller_hint: "contract-fulfiller"
      })
    }
  ));
  assertStatus(requested, 201, "exchange creation for one-use retrieval");
  const exchangeId = requested.body.exchange_id;
  const fulfilled = await httpRequest(adapter.baseUrl, "/api/v2/secret/exchange/fulfill", withBearer(
    adapter.fixture.agents.fulfiller.accessToken,
    jsonRequestBody({ fulfillment_token: requested.body.fulfillment_token })
  ));
  assertStatus(fulfilled, 200, "exchange reservation before one-use retrieval");
  const submitted = await httpRequest(adapter.baseUrl,
    `/api/v2/secret/exchange/submit/${exchangeId}`,
    withBearer(adapter.fixture.agents.fulfiller.accessToken, jsonRequestBody({ enc: ENC, ciphertext: CIPHERTEXT })));
  assertStatus(submitted, 201, "exchange submission before one-use retrieval");
  return exchangeId;
}

function adminHeaders(session, extra = {}) {
  return {
    cookie: session.cookie,
    "x-csrf-token": session.csrfToken,
    origin: ORIGIN,
    ...extra
  };
}

async function getPolicy(adapter, session) {
  const response = await httpRequest(adapter.baseUrl, "/api/v3/admin/policy", {
    headers: adminHeaders(session)
  });
  assertStatus(response, 200, "admin policy read");
  return response.body;
}

async function replacePolicy(adapter, session, version, document) {
  return httpRequest(adapter.baseUrl, "/api/v3/admin/policy", {
    method: "PUT",
    headers: adminHeaders(session, {
      "content-type": "application/json",
      "if-match": String(version)
    }),
    body: JSON.stringify(document)
  });
}

async function createApproval(adapter, label) {
  const response = await httpRequest(adapter.baseUrl, "/api/v2/secret/exchange/request", withBearer(
    adapter.fixture.agents.requester.accessToken,
    {
      ...jsonRequestBody({
        public_key: "Y29udHJhY3QtcHViLWtleQ==",
        secret_name: SECRET_NAMES.approval,
        purpose: label,
        fulfiller_hint: "contract-fulfiller"
      })
    }
  ));
  assertStatus(response, 403, "approval-gated exchange request");
  assert.ok(response.body?.policy?.approval_reference, "approval-gated request returned its approval reference");
  return response.body.policy.approval_reference;
}

async function decideApproval(adapter, session, reference, idempotencyKey) {
  return httpRequest(adapter.baseUrl,
    `/api/v3/admin/approvals/${encodeURIComponent(reference)}/approve`, {
      method: "POST",
      headers: adminHeaders(session, {
        "content-type": "application/json",
        "idempotency-key": idempotencyKey
      }),
      body: JSON.stringify({ expected_status: "pending" })
    });
}

async function getApproval(adapter, session, reference) {
  const response = await httpRequest(adapter.baseUrl,
    `/api/v3/admin/approvals/${encodeURIComponent(reference)}`, {
      headers: adminHeaders(session)
    });
  assertStatus(response, 200, "admin approval read after restart");
  return response.body;
}

async function approvalDecisionAudit(adapter, session, reference) {
  const response = await httpRequest(adapter.baseUrl, "/api/v3/admin/audit?limit=100", {
    headers: adminHeaders(session)
  });
  assertStatus(response, 200, "admin audit read after restart");
  return response.body.items.filter((entry) => entry.event === "exchange_approved" && entry.resource_id === reference);
}

const adapter = await startRustCrashTestAdapter();
try {
  const requestBeforeCommit = await createSubmittedSecret(adapter, "P02 I03 retrieval before commit");
  await adapter.startWithFailpoint("secret-retrieve-before-commit");
  await expectConnectionDrop(
    () => httpRequest(adapter.baseUrl, `/api/v2/secret/retrieve/${requestBeforeCommit}`, requesterHeaders(adapter)),
    "pre-commit one-use retrieval"
  );
  await adapter.assertCrashAndRestart();
  const recoveredPayload = await httpRequest(adapter.baseUrl,
    `/api/v2/secret/retrieve/${requestBeforeCommit}`, requesterHeaders(adapter));
  assertStatus(recoveredPayload, 200, "retrieval rolled back before commit");
  assert.equal(recoveredPayload.body.ciphertext, CIPHERTEXT);
  assert.equal(recoveredPayload.body.enc, ENC);
  assertStatus(await httpRequest(adapter.baseUrl,
    `/api/v2/secret/retrieve/${requestBeforeCommit}`, requesterHeaders(adapter)), 410,
  "retrieved payload remains one-use after restart");

  const requestAfterCommit = await createSubmittedSecret(adapter, "P02 I03 retrieval after commit");
  await adapter.startWithFailpoint("secret-retrieve-after-commit");
  await expectConnectionDrop(
    () => httpRequest(adapter.baseUrl, `/api/v2/secret/retrieve/${requestAfterCommit}`, requesterHeaders(adapter)),
    "post-commit one-use retrieval"
  );
  await adapter.assertCrashAndRestart();
  assertStatus(await httpRequest(adapter.baseUrl,
    `/api/v2/secret/retrieve/${requestAfterCommit}`, requesterHeaders(adapter)), 410,
  "lost retrieval reply does not resurrect ciphertext");

  const exchangeBeforeCommit = await createSubmittedExchange(adapter, "P02 I03 exchange retrieval before commit");
  await adapter.startWithFailpoint("exchange-retrieve-before-commit");
  await expectConnectionDrop(
    () => httpRequest(adapter.baseUrl, `/api/v2/secret/exchange/retrieve/${exchangeBeforeCommit}`, requesterHeaders(adapter)),
    "pre-commit exchange retrieval"
  );
  await adapter.assertCrashAndRestart();
  const recoveredExchange = await httpRequest(adapter.baseUrl,
    `/api/v2/secret/exchange/retrieve/${exchangeBeforeCommit}`, requesterHeaders(adapter));
  assertStatus(recoveredExchange, 200, "exchange retrieval rolled back before commit");
  assert.equal(recoveredExchange.body.ciphertext, CIPHERTEXT);
  assert.equal(recoveredExchange.body.enc, ENC);
  assertStatus(await httpRequest(adapter.baseUrl,
    `/api/v2/secret/exchange/retrieve/${exchangeBeforeCommit}`, requesterHeaders(adapter)), 410,
  "exchange payload remains one-use after restart");

  const exchangeAfterCommit = await createSubmittedExchange(adapter, "P02 I03 exchange retrieval after commit");
  await adapter.startWithFailpoint("exchange-retrieve-after-commit");
  await expectConnectionDrop(
    () => httpRequest(adapter.baseUrl, `/api/v2/secret/exchange/retrieve/${exchangeAfterCommit}`, requesterHeaders(adapter)),
    "post-commit exchange retrieval"
  );
  await adapter.assertCrashAndRestart();
  assertStatus(await httpRequest(adapter.baseUrl,
    `/api/v2/secret/exchange/retrieve/${exchangeAfterCommit}`, requesterHeaders(adapter)), 410,
  "lost exchange retrieval reply does not resurrect ciphertext");

  const session = await adapter.bootstrapAdminSession();
  const initialPolicy = await getPolicy(adapter, session);
  const policyBefore = structuredClone(initialPolicy.policy);
  const changedBefore = structuredClone(policyBefore);
  changedBefore.secret_registry[0].description = `${changedBefore.secret_registry[0].description} P02 pre-commit probe.`;
  await adapter.startWithFailpoint("policy-before-commit");
  await expectConnectionDrop(
    () => replacePolicy(adapter, session, initialPolicy.version, changedBefore),
    "pre-commit policy mutation"
  );
  await adapter.assertCrashAndRestart();
  const rolledBackPolicy = await getPolicy(adapter, session);
  assert.equal(rolledBackPolicy.version, initialPolicy.version, "pre-commit policy update rolled back after process restart");
  assert.deepEqual(rolledBackPolicy.policy, policyBefore);
  const committedRetry = await replacePolicy(adapter, session, initialPolicy.version, changedBefore);
  assertStatus(committedRetry, 200, "policy retry after pre-commit crash");
  assert.equal(committedRetry.body.version, initialPolicy.version + 1);

  const secondPolicyVersion = committedRetry.body.version;
  const changedAfter = structuredClone(changedBefore);
  changedAfter.secret_registry[0].description = `${changedAfter.secret_registry[0].description} P02 post-commit probe.`;
  await adapter.startWithFailpoint("policy-after-commit");
  await expectConnectionDrop(
    () => replacePolicy(adapter, session, secondPolicyVersion, changedAfter),
    "post-commit policy mutation"
  );
  await adapter.assertCrashAndRestart();
  const durablePolicy = await getPolicy(adapter, session);
  assert.equal(durablePolicy.version, secondPolicyVersion + 1, "post-commit policy update survived process restart");
  assert.deepEqual(durablePolicy.policy, changedAfter);
  assertStatus(await replacePolicy(adapter, session, secondPolicyVersion, changedAfter), 409,
    "stale policy retry after committed response loss");

  const approvalDocument = structuredClone(durablePolicy.policy);
  const approvalRule = approvalDocument.exchange_policy.find((rule) => rule.ruleId === "contract-approval");
  assert.ok(approvalRule, "approval policy fixture exists");
  approvalRule.approverIds = ["p02-admin"];
  const configuredPolicy = await replacePolicy(adapter, session, durablePolicy.version, approvalDocument);
  assertStatus(configuredPolicy, 200, "configure local test approver");

  const beforeAuditReference = await createApproval(adapter, "P02 I03 audit transaction before commit");
  const beforeAuditKey = "p02-crash-before-audit-0001";
  await adapter.startWithFailpoint("approval-after-audit-before-commit");
  await expectConnectionDrop(
    () => decideApproval(adapter, session, beforeAuditReference, beforeAuditKey),
    "approval and audit transaction before commit"
  );
  await adapter.assertCrashAndRestart();
  assert.equal((await getApproval(adapter, session, beforeAuditReference)).status, "pending",
    "approval decision rolled back with its uncommitted audit event");
  assert.equal((await approvalDecisionAudit(adapter, session, beforeAuditReference)).length, 0,
    "uncommitted audit event did not survive restart");
  assertStatus(await decideApproval(adapter, session, beforeAuditReference, beforeAuditKey), 200,
    "idempotent decision retry after pre-commit crash");
  assert.equal((await getApproval(adapter, session, beforeAuditReference)).status, "approved");
  assert.equal((await approvalDecisionAudit(adapter, session, beforeAuditReference)).length, 1,
    "approval retry produced exactly one durable audit event");

  const afterAuditReference = await createApproval(adapter, "P02 I03 audit transaction after commit");
  const afterAuditKey = "p02-crash-after-audit-0002";
  await adapter.startWithFailpoint("approval-after-commit");
  await expectConnectionDrop(
    () => decideApproval(adapter, session, afterAuditReference, afterAuditKey),
    "approval and audit transaction after commit"
  );
  await adapter.assertCrashAndRestart();
  assert.equal((await getApproval(adapter, session, afterAuditReference)).status, "approved",
    "committed approval decision survived process restart");
  assertStatus(await decideApproval(adapter, session, afterAuditReference, afterAuditKey), 200,
    "idempotent replay after committed response loss");
  assert.equal((await approvalDecisionAudit(adapter, session, afterAuditReference)).length, 1,
    "committed approval replay did not duplicate its audit event");

  console.log(`P02 I03 crash recovery passed on ${process.env.CONTRACT_RUST_BACKEND}.`);
} finally {
  await adapter.close();
}
