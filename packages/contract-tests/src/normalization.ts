const VOLATILE_KEY_PATTERN = /(?:^|_)(?:access|refresh|fulfillment|bootstrap|api|private|public)?_?token$|(?:^|_)(?:api_key|public_key|signature|sig|ciphertext|enc|secret_url|password|confirmation_code|approval_reference)$/i;
const VOLATILE_NUMBER_KEY_PATTERN = /(?:^|_)(?:created_at|updated_at|expires_at|access_token_expires_at|refresh_token_expires_at|expiry|retrieve_by|decided_at)$/i;
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_GLOBAL_PATTERN = /[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi;
const REQUEST_ID_PATTERN = /^[0-9a-f]{64}$/i;
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function normalizeString(value: string, key: string | null): string {
  if (key && VOLATILE_KEY_PATTERN.test(key)) {
    return `<${key.toLowerCase().replaceAll("_", "-")}>`;
  }

  if (ISO_TIMESTAMP_PATTERN.test(value)) {
    return "<timestamp>";
  }

  if (UUID_PATTERN.test(value)) {
    return "<uuid>";
  }

  if (REQUEST_ID_PATTERN.test(value)) {
    return "<id>";
  }

  if (JWT_PATTERN.test(value)) {
    return "<jwt>";
  }

  if (/^apr_[0-9a-f]+$/i.test(value)) {
    return "<approval-id>";
  }

  return value
    .replace(UUID_GLOBAL_PATTERN, "<uuid>")
    .replace(/test-refresh-\d+-[0-9a-f]+/gi, "test-refresh-<run>");
}

export function normalizeSnapshotValue(value: unknown, key: string | null = null): unknown {
  if (typeof value === "number" && key && VOLATILE_NUMBER_KEY_PATTERN.test(key)) {
    return "<timestamp>";
  }

  if (typeof value === "string") {
    return normalizeString(value, key);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => normalizeSnapshotValue(entry, key));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([entryKey, entryValue]) => [entryKey, normalizeSnapshotValue(entryValue, entryKey)])
    );
  }

  return value;
}

export function normalizeHttpResult(result: {
  status: number;
  contentType: string | null;
  body: unknown;
}): Record<string, unknown> {
  return {
    status: result.status,
    content_type: result.contentType?.split(";", 1)[0] ?? null,
    body: normalizeSnapshotValue(result.body)
  };
}

export function stableJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function containsCanary(value: unknown, canaries: string[]): string[] {
  const serialized = JSON.stringify(value);
  return canaries.filter((canary) => serialized.includes(canary));
}
