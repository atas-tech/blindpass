import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const inputPath = path.join(repoRoot, "docs/api/controller.openapi.yaml");
const outputPath = path.join(repoRoot, "packages/contract-tests/src/generated/controller.d.ts");
const methods = ["get", "post", "put", "patch", "delete", "head", "options", "trace"];

function resolveLocalRef(root, ref) {
  if (typeof ref !== "string" || !ref.startsWith("#/")) {
    throw new Error(`Only local OpenAPI references are supported: ${String(ref)}`);
  }

  return ref.slice(2).split("/").map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((value, key) => value?.[key], root);
}

function dereference(root, value) {
  if (!value?.$ref) return value;
  const resolved = resolveLocalRef(root, value.$ref);
  if (!resolved) throw new Error(`Unresolved OpenAPI reference: ${value.$ref}`);
  return resolved;
}

function componentType(ref) {
  const prefix = "#/components/schemas/";
  if (!ref.startsWith(prefix)) {
    throw new Error(`Only schema references can be rendered as TypeScript values: ${ref}`);
  }

  const name = ref.slice(prefix.length);
  return `components["schemas"][${JSON.stringify(name)}]`;
}

function renderSchema(schema = {}, depth = 0) {
  if (schema.$ref) return componentType(schema.$ref);
  if (Object.hasOwn(schema, "const")) return JSON.stringify(schema.const);
  if (Array.isArray(schema.enum)) return schema.enum.map((value) => JSON.stringify(value)).join(" | ") || "never";
  if (Array.isArray(schema.oneOf)) return schema.oneOf.map((item) => renderSchema(item, depth)).join(" | ");
  if (Array.isArray(schema.anyOf)) return schema.anyOf.map((item) => renderSchema(item, depth)).join(" | ");
  if (Array.isArray(schema.allOf)) return schema.allOf.map((item) => renderSchema(item, depth)).join(" & ");

  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  const rendered = types.filter(Boolean).map((type) => {
    if (type === "null") return "null";
    if (type === "string") return "string";
    if (type === "number" || type === "integer") return "number";
    if (type === "boolean") return "boolean";
    if (type === "array") return `Array<${renderSchema(schema.items ?? {}, depth + 1)}>`;
    if (type !== "object") return "unknown";

    const properties = schema.properties ?? {};
    const required = new Set(schema.required ?? []);
    const indent = "  ".repeat(depth);
    const fieldIndent = "  ".repeat(depth + 1);
    const fields = Object.entries(properties).map(([name, property]) =>
      `${fieldIndent}${JSON.stringify(name)}${required.has(name) ? "" : "?"}: ${renderSchema(property, depth + 1)};`
    );
    if (schema.additionalProperties === true) fields.push(`${fieldIndent}[key: string]: unknown;`);
    else if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      fields.push(`${fieldIndent}[key: string]: ${renderSchema(schema.additionalProperties, depth + 1)};`);
    }
    if (fields.length === 0) return schema.additionalProperties === false ? "Record<string, never>" : "Record<string, unknown>";
    return `{\n${fields.join("\n")}\n${indent}}`;
  });

  if (rendered.length > 0) return rendered.join(" | ");
  if (schema.properties || schema.additionalProperties !== undefined) return renderSchema({ ...schema, type: "object" }, depth);
  return "unknown";
}

function renderParameters(root, parameters = []) {
  const groups = new Map(["path", "query", "header", "cookie"].map((name) => [name, []]));
  for (const value of parameters) {
    const parameter = dereference(root, value);
    if (!groups.has(parameter.in)) continue;
    groups.get(parameter.in).push(parameter);
  }

  return `  parameters: {\n${[...groups.entries()].map(([location, entries]) => {
    if (entries.length === 0) return `    ${location}: never;`;
    const properties = entries.map((parameter) =>
      `      ${JSON.stringify(parameter.name)}${parameter.required ? "" : "?"}: ${renderSchema(parameter.schema)};`
    ).join("\n");
    return `    ${location}: {\n${properties}\n    };`;
  }).join("\n")}\n  };`;
}

function renderRequestBody(root, body) {
  if (!body) return "  requestBody: never;";
  const resolved = dereference(root, body);
  const content = Object.entries(resolved.content ?? {}).map(([mediaType, media]) =>
    `    ${JSON.stringify(mediaType)}: ${renderSchema(media.schema)};`
  );
  return `  requestBody: {\n    required: ${Boolean(resolved.required)};\n    content: {\n${content.join("\n")}\n    };\n  };`;
}

function renderResponses(root, responses = {}) {
  const rendered = Object.entries(responses).sort(([left], [right]) => Number(left) - Number(right)).map(([status, value]) => {
    const response = dereference(root, value);
    const content = Object.entries(response.content ?? {}).map(([mediaType, media]) =>
      `        ${JSON.stringify(mediaType)}: ${renderSchema(media.schema)};`
    );
    return content.length === 0
      ? `    ${JSON.stringify(status)}: Record<string, never>;`
      : `    ${JSON.stringify(status)}: {\n      content: {\n${content.join("\n")}\n      };\n    };`;
  });
  return `  responses: {\n${rendered.join("\n")}\n  };`;
}

function renderSecurity(security = []) {
  if (security.length === 0) return "  security: never;";
  const choices = security.map((requirement) =>
    `readonly [${Object.keys(requirement).map((name) => JSON.stringify(name)).join(", ")}]`
  );
  return `  security: ReadonlyArray<${choices.join(" | ")}>;`;
}

function assertReferences(root, value, location = "document") {
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) assertReferences(root, item, `${location}[${index}]`);
    return;
  }
  if (!value || typeof value !== "object") return;
  if (value.$ref) {
    if (!resolveLocalRef(root, value.$ref)) throw new Error(`Unresolved reference ${value.$ref} at ${location}`);
  }
  for (const [key, child] of Object.entries(value)) assertReferences(root, child, `${location}.${key}`);
}

export function renderControllerTypes(document) {
  if (document.openapi !== "3.1.0") throw new Error(`Expected OpenAPI 3.1.0, received ${document.openapi}`);
  assertReferences(document, document);

  const schemas = Object.entries(document.components?.schemas ?? {}).map(([name, schema]) =>
    `    ${JSON.stringify(name)}: ${renderSchema(schema, 2)};`
  );
  const operations = [];
  const paths = [];
  const seenOperationIds = new Set();

  for (const [route, pathItem] of Object.entries(document.paths ?? {})) {
    const pathOperations = [];
    for (const method of methods) {
      const operation = pathItem[method];
      if (!operation) continue;
      if (!operation.operationId || seenOperationIds.has(operation.operationId)) {
        throw new Error(`OpenAPI operationId must be present and unique: ${operation.operationId ?? `${method} ${route}`}`);
      }
      seenOperationIds.add(operation.operationId);
      operations.push(`  ${JSON.stringify(operation.operationId)}: {\n${renderParameters(document, operation.parameters ?? [])}\n${renderRequestBody(document, operation.requestBody)}\n${renderResponses(document, operation.responses)}\n${renderSecurity(operation.security)}\n  };`);
      pathOperations.push(`    ${method}?: operations[${JSON.stringify(operation.operationId)}];`);
    }
    paths.push(`  ${JSON.stringify(route)}: {\n${pathOperations.join("\n")}\n  };`);
  }

  return [
    "/* Generated by scripts/generate-controller-types.mjs from docs/api/controller.openapi.yaml. Do not edit. */",
    "export interface components {",
    "  schemas: {",
    schemas.join("\n"),
    "  };",
    "}",
    "",
    "export interface operations {",
    operations.join("\n"),
    "}",
    "",
    "export interface paths {",
    paths.join("\n"),
    "}",
    ""
  ].join("\n");
}

async function main() {
  const document = JSON.parse(await readFile(inputPath, "utf8"));
  const output = renderControllerTypes(document);
  if (process.argv.includes("--check")) {
    const current = await readFile(outputPath, "utf8").catch(() => "");
    if (current !== output) {
      console.error("Generated controller API types are stale; run npm run generate:api.");
      process.exitCode = 1;
    }
    return;
  }

  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, output);
  console.log(`Generated ${path.relative(repoRoot, outputPath)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
