import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { renderControllerTypes } from "../generate-controller-types.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const schemaPath = path.join(repoRoot, "docs/api/controller.openapi.yaml");
const controllerSource = path.join(repoRoot, "crates/blindpass-controller/src");

const legacyMachineRoutes = [
  ["POST", "/api/v2/secret/request"],
  ["GET", "/api/v2/secret/metadata/{id}"],
  ["POST", "/api/v2/secret/submit/{id}"],
  ["GET", "/api/v2/secret/status/{id}"],
  ["GET", "/api/v2/secret/retrieve/{id}"],
  ["POST", "/api/v2/secret/exchange/request"],
  ["GET", "/api/v2/secret/exchange/status/{id}"],
  ["POST", "/api/v2/secret/exchange/fulfill"],
  ["POST", "/api/v2/secret/exchange/submit/{id}"],
  ["GET", "/api/v2/secret/exchange/retrieve/{id}"],
  ["DELETE", "/api/v2/secret/exchange/revoke/{id}"],
  ["POST", "/api/v2/agents/token"]
];

async function rustSources(directory = controllerSource) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await rustSources(entryPath));
    } else if (entry.name.endsWith(".rs")) {
      files.push(await readFile(entryPath, "utf8"));
    }
  }
  return files;
}

function routeKey(method, route) {
  return `${method} ${route.replace(/\{[^}]+\}/g, "{}")}`;
}

async function mountedRoutes() {
  const routes = new Set();
  for (const text of await rustSources()) {
    for (const match of text.matchAll(/\.route\(\s*"([^"]+)",\s*((?:[a-z]+\([A-Za-z_:]+\)\s*\.?\s*)+),?\s*\)/g)) {
      for (const method of match[2].matchAll(/([a-z]+)\(/g)) {
        routes.add(routeKey(method[1].toUpperCase(), match[1]));
      }
    }
  }
  return routes;
}

function resolveReference(schema, reference) {
  return reference.slice(2).split("/").reduce((value, key) => value?.[key], schema);
}

test("generated TypeScript declarations match the OpenAPI source", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const generatedPath = path.join(repoRoot, "packages/contract-tests/src/generated/controller.d.ts");
  const generated = await readFile(generatedPath, "utf8");
  assert.equal(generated, renderControllerTypes(schema));
});

test("controller OpenAPI lists the retained machine contract exactly once", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  assert.equal(schema.openapi, "3.1.0");

  const documented = [];
  const operationIds = new Set();
  for (const [route, pathItem] of Object.entries(schema.paths ?? {})) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      const operation = pathItem[method];
      if (operation?.["x-blindpass-status"] === "planned") continue;
      if (operation) {
        assert.ok(operation.operationId, `missing operationId for ${method.toUpperCase()} ${route}`);
        assert.ok(!operationIds.has(operation.operationId), `duplicate operationId ${operation.operationId}`);
        operationIds.add(operation.operationId);
      }
      if (operation?.["x-blindpass-contract"] === "legacy-machine") {
        documented.push([method.toUpperCase(), route]);
      }
    }
  }

  assert.deepEqual(documented.sort(), legacyMachineRoutes.map(([method, route]) => [method, route]).sort());
});

test("retained operations document every response status observed by CT02-CT13", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const requiredStatuses = [
    ["post", "/api/v2/agents/token", ["200", "401", "429"]],
    ["post", "/api/v2/secret/request", ["201", "400", "401", "429"]],
    ["get", "/api/v2/secret/metadata/{id}", ["200", "403", "410"]],
    ["post", "/api/v2/secret/submit/{id}", ["201", "403", "409", "410", "413"]],
    ["get", "/api/v2/secret/status/{id}", ["200", "410"]],
    ["get", "/api/v2/secret/retrieve/{id}", ["200", "409", "410"]],
    ["post", "/api/v2/secret/exchange/request", ["201", "403", "429"]],
    ["get", "/api/v2/secret/exchange/status/{id}", ["200", "410"]],
    ["post", "/api/v2/secret/exchange/fulfill", ["200", "409", "410"]],
    ["post", "/api/v2/secret/exchange/submit/{id}", ["201", "409"]],
    ["get", "/api/v2/secret/exchange/retrieve/{id}", ["200", "409", "410"]],
    ["delete", "/api/v2/secret/exchange/revoke/{id}", ["200", "410"]]
  ];

  for (const [method, route, statuses] of requiredStatuses) {
    const documented = schema.paths[route]?.[method]?.responses ?? {};
    for (const status of statuses) assert.ok(documented[status], `${method.toUpperCase()} ${route} omits observed ${status}`);
  }
});

test("controller OpenAPI keeps hosted user refresh outside the Rust API", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  assert.equal(schema.paths["/api/v2/auth/refresh"], undefined);
});

test("controller OpenAPI includes the reviewed local admin and capability surfaces", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const operations = new Set();
  for (const [route, pathItem] of Object.entries(schema.paths ?? {})) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      if (pathItem[method]) operations.add(`${method.toUpperCase()} ${route}`);
    }
  }

  for (const operation of [
    "GET /api/v3/capabilities",
    "POST /api/v3/admin/bootstrap",
    "POST /api/v3/admin/session/login",
    "POST /api/v3/admin/session/refresh",
    "POST /api/v3/admin/session/logout",
    "GET /api/v3/admin/session",
    "POST /api/v3/admin/session/change-password",
    "GET /api/v3/admin/operators",
    "POST /api/v3/admin/operators",
    "PATCH /api/v3/admin/operators/{id}",
    "DELETE /api/v3/admin/operators/{id}",
    "POST /api/v3/admin/operators/{id}/reset-password",
    "GET /api/v3/admin/agents",
    "POST /api/v3/admin/agents",
    "POST /api/v3/admin/agents/{id}/rotate-key",
    "DELETE /api/v3/admin/agents/{id}",
    "GET /api/v3/admin/policy",
    "PUT /api/v3/admin/policy",
    "POST /api/v3/admin/policy/validate",
    "GET /api/v3/admin/approvals",
    "GET /api/v3/admin/approvals/count",
    "GET /api/v3/admin/approvals/{reference}",
    "POST /api/v3/admin/approvals/{reference}/approve",
    "POST /api/v3/admin/approvals/{reference}/reject",
    "GET /api/v3/admin/audit",
    "GET /api/v3/admin/audit/exchange/{id}",
    "POST /api/v3/admin/test/seed"
  ]) {
    assert.ok(operations.has(operation), `missing ${operation}`);
  }

  const approvalList = schema.paths["/api/v3/admin/approvals"].get;
  assert.ok(approvalList.parameters?.some((parameter) => parameter.in === "query" && parameter.name === "status"));

  for (const [route, pathItem] of Object.entries(schema.paths)) {
    if (!route.startsWith("/api/v3/admin/")) continue;
    for (const [method, operation] of Object.entries(pathItem)) {
      if (!["post", "put", "patch", "delete"].includes(method)) continue;
      if (["/api/v3/admin/bootstrap", "/api/v3/admin/session/login", "/api/v3/admin/test/seed"].includes(route)) continue;
      assert.ok(operation.security?.some((requirement) => (requirement.adminSession || requirement.adminRefresh) && requirement.csrfCookie), `${method.toUpperCase()} ${route} must require session and CSRF`);
      const parameters = (operation.parameters ?? []).map((parameter) => parameter.$ref ? resolveReference(schema, parameter.$ref) : parameter);
      assert.ok(parameters.some((parameter) => parameter.name === "X-CSRF-Token"), `${method.toUpperCase()} ${route} must declare the CSRF header`);
    }
  }
});

test("controller OpenAPI declares secret-free readiness and the adopted CT19 routes", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  assert.ok(schema.paths["/healthz"]?.get);
  assert.ok(schema.paths["/readyz"]?.get);
  assert.ok(schema.paths["/api/v3/capabilities"]?.get);
  assert.equal(schema.info["x-blindpass-ct19"], "adopted");
  assert.equal(schema.info["x-blindpass-legacy-route-count"], legacyMachineRoutes.length);
  assert.equal(schema.components.schemas.CapabilitiesResponse.properties.schema_version.const, 5);

  const serialized = JSON.stringify(schema.paths["/readyz"]);
  assert.doesNotMatch(serialized, /secret|token|credential|password/i);

  const payload = schema.components.schemas.EncryptedPayload;
  assert.deepEqual(payload.required, ["enc", "ciphertext"]);
  assert.equal(payload.additionalProperties, false);
  assert.deepEqual(schema.components.schemas.SecretStatus.properties.status.enum, ["pending", "submitted"]);
  assert.equal(schema.components.schemas.ExpiredStatus.properties.status.const, "expired");
  const browserStatusCapability = schema.components.schemas.CapabilitiesResponse.properties.features.properties.browser_status;

  const browserStatusPaths = Object.keys(schema.paths).filter((route) => route.startsWith("/api/v2/secret/browser-status/"));
  assert.deepEqual(browserStatusPaths.sort(), [
    "/api/v2/secret/browser-status/{id}",
    "/api/v2/secret/browser-status/{id}/capability"
  ]);
  assert.equal(browserStatusCapability.const, true);

  const capabilityRoute = schema.paths["/api/v2/secret/browser-status/{id}/capability"].post;
  assert.deepEqual(capabilityRoute.responses["200"].content["application/json"].schema, {
    $ref: "#/components/schemas/BrowserStatusCapabilityResponse"
  });
  assert.ok(capabilityRoute.description.includes("never extend authority"));
  assert.ok(capabilityRoute.parameters.some((parameter) => parameter.in === "query" && parameter.name === "sig" && parameter.required));
  assert.ok(capabilityRoute.security.some((requirement) => requirement.browserSignedLink));

  const statusRoute = schema.paths["/api/v2/secret/browser-status/{id}"].get;
  assert.deepEqual(statusRoute.responses["200"].content["application/json"].schema, {
    $ref: "#/components/schemas/SecretStatus"
  });
  assert.deepEqual(statusRoute.responses["410"].content["application/json"].schema, {
    $ref: "#/components/schemas/ExpiredStatus"
  });
  assert.match(statusRoute.description, /no request metadata, key, ciphertext or identity/i);
  assert.match(statusRoute.description, /wrong-scope credentials return 410/i);
});

test("P03 OpenAPI defines the fleet and node channel contracts", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const operations = new Set();
  for (const [route, pathItem] of Object.entries(schema.paths ?? {})) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      if (pathItem[method]) operations.add(`${method.toUpperCase()} ${route}`);
    }
  }

  for (const operation of [
    "POST /api/v3/enrollments",
    "POST /api/v3/enrollments/{id}/approve",
    "GET /api/v3/nodes",
    "DELETE /api/v3/nodes/{id}",
    "POST /api/v3/workloads",
    "PUT /api/v3/policies",
    "GET /api/v3/approvals/count",
    "POST /api/v3/approvals/{id}/approve",
    "GET /api/v3/grants",
    "POST /api/v3/operations",
    "GET /api/v3/audit",
    "POST /api/v3/node/enroll",
    "POST /api/v3/node/session",
    "POST /api/v3/node/poll",
    "POST /api/v3/node/events"
  ]) {
    assert.ok(operations.has(operation), `missing ${operation}`);
    const [method, route] = operation.split(" ");
    assert.equal(schema.paths[route][method.toLowerCase()]["x-blindpass-status"], "planned");
  }

  const security = schema.components.securitySchemes;
  assert.equal(security.nodeBearer.bearerFormat, "JWT");
  assert.equal(schema.components.schemas.OperationApproval.properties.id.pattern, "^oa_");
  assert.deepEqual(schema.components.schemas.GrantRevocationResult.properties.status.enum, [
    "grant_revoked",
    "grant_revoked_after_consumption",
    "not_revocable_offline"
  ]);
  for (const [route, pathItem] of Object.entries(schema.paths)) {
    if (!route.startsWith("/api/v3/") || route.startsWith("/api/v3/node/") || route.startsWith("/api/v3/admin/")) continue;
    for (const [method, operation] of Object.entries(pathItem)) {
      if (!["post", "put", "patch", "delete"].includes(method)) continue;
      assert.ok(operation.security?.some((requirement) => requirement.adminSession && requirement.csrfCookie), `${method.toUpperCase()} ${route} must require operator session and CSRF`);
      const parameters = (operation.parameters ?? []).map((parameter) => parameter.$ref ? resolveReference(schema, parameter.$ref) : parameter);
      assert.ok(parameters.some((parameter) => parameter.name === "X-CSRF-Token"), `${method.toUpperCase()} ${route} must declare the CSRF header`);
    }
  }
});

test("test seed schema matches the exercised compatibility fixture response", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const operation = schema.paths["/api/v3/admin/test/seed"].post;
  assert.ok(operation.responses["200"]);
  assert.ok(!operation.responses["201"]);
  const input = schema.components.schemas.TestSeedInput;
  assert.deepEqual(input.required, ["agents"]);
  assert.deepEqual(Object.keys(input.properties), ["agents", "policy", "rotated_agents", "revoked_agents", "local_admin"]);
  const response = schema.components.schemas.TestSeedResponse;
  assert.deepEqual(response.required, ["workspace_id", "user_id", "agents"]);
  assert.ok(!Object.hasOwn(response.properties, "access_token"));
  assert.ok(!Object.hasOwn(response.properties, "refresh_token"));
  assert.equal(response.properties.local_admin.$ref, "#/components/schemas/TestSeedLocalAdmin");
  assert.ok(!Object.hasOwn(schema.components.schemas.TestSeedLocalAdmin.properties, "refresh_token"));

  const auth = await readFile(path.join(controllerSource, "routes/auth.rs"), "utf8");
  const header = auth.match(/async fn test_seed\([\s\S]*?\.get\("([^"]+)"\)/)?.[1];
  assert.equal(schema.components.securitySchemes.seedToken.name, header);
});

test("controller OpenAPI server matches the default listen address", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const config = await readFile(path.join(controllerSource, "config.rs"), "utf8");
  const listen = config.match(/"BLINDPASS_LISTEN"\)\s*\.unwrap_or\("([^"]+)"\)/)?.[1];
  assert.ok(listen, "default BLINDPASS_LISTEN not found");
  assert.deepEqual(schema.servers.map((server) => new URL(server.url).host), [listen]);
});

test("every mounted controller route is documented exactly", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const documented = new Set();
  for (const [route, pathItem] of Object.entries(schema.paths ?? {})) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      if (pathItem[method] && pathItem[method]["x-blindpass-status"] !== "planned") {
        documented.add(routeKey(method.toUpperCase(), route));
      }
    }
  }
  const mounted = await mountedRoutes();
  assert.ok(mounted.size > documented.size / 2, "route parser found too few routes");
  assert.deepEqual([...documented].filter((route) => !mounted.has(route)).sort(), []);
  assert.deepEqual([...mounted].filter((route) => !documented.has(route)).sort(), []);
});

test("admin session scheme documents the forced password change gate", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const scheme = schema.components.securitySchemes.adminSession;
  assert.equal(scheme.in, "cookie");
  assert.match(scheme.description, /password_change_required/);
  assert.match(scheme.description, /403/);
});
