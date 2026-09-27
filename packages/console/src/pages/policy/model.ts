import type { PolicyDocumentInput } from "../../api/types.js";

export type Json = Record<string, unknown>;
export type RuleMode = "allow" | "pending_approval" | "deny";

export interface Draft {
  registry: Json[];
  rules: Json[];
}

/** camelCase is the documented spelling; the controller also accepts snake_case. */
export const ALIASES: Record<string, string[]> = {
  secretName: ["secretName", "secret_name"],
  ruleId: ["ruleId", "rule_id"],
  requesterIds: ["requesterIds", "requester_ids"],
  fulfillerIds: ["fulfillerIds", "fulfiller_ids"],
  approverIds: ["approverIds", "approver_ids"],
  classification: ["classification"],
  description: ["description"],
  mode: ["mode"],
  reason: ["reason"]
};

export const RULE_FIELDS = ["ruleId", "secretName", "mode", "requesterIds", "fulfillerIds", "approverIds", "reason"] as const;
export const REGISTRY_FIELDS = ["secretName", "classification", "description"] as const;

function keyFor(object: Json, field: string): string {
  const aliases = ALIASES[field] ?? [field];
  return aliases.find((alias) => alias in object) ?? aliases[0]!;
}

export function read(object: Json, field: string): unknown {
  return object[keyFor(object, field)];
}

export function readString(object: Json, field: string): string {
  const value = read(object, field);
  return typeof value === "string" ? value : "";
}

export function readList(object: Json, field: string): string[] | null {
  const value = read(object, field);
  return Array.isArray(value) ? value.map(String) : null;
}

/** Set one field, keeping whichever spelling the entry already uses and every other field. */
export function write(object: Json, field: string, value: unknown): Json {
  const key = keyFor(object, field);
  const next = { ...object };
  if (value === undefined) delete next[key];
  else next[key] = value;
  return next;
}

/** Fields the form does not edit; they round-trip untouched. */
export function otherFields(object: Json, fields: readonly string[]): string[] {
  const known = new Set(fields.flatMap((field) => ALIASES[field] ?? [field]));
  return Object.keys(object).filter((key) => !known.has(key));
}

export function ruleMode(rule: Json): RuleMode {
  const mode = readString(rule, "mode").trim();
  return mode === "pending_approval" || mode === "deny" ? mode : "allow";
}

/** Parse a one-per-line or comma-separated list. Empty input means "not set". */
export function parseList(text: string): string[] | undefined {
  const items = text
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
  return items.length ? items : undefined;
}

export function toDraft(policy: PolicyDocumentInput): Draft {
  return {
    registry: policy.secret_registry.map((entry) => ({ ...(entry as Json) })),
    rules: policy.exchange_policy.map((rule) => ({ ...(rule as Json) }))
  };
}

export function toDocument(draft: Draft): PolicyDocumentInput {
  return { secret_registry: draft.registry as PolicyDocumentInput["secret_registry"], exchange_policy: draft.rules as PolicyDocumentInput["exchange_policy"] };
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value as Json)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical((value as Json)[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sameDocument(a: Draft, b: Draft): boolean {
  return canonical(toDocument(a)) === canonical(toDocument(b));
}

export interface DiffSummary {
  added: string[];
  removed: string[];
  changed: string[];
}

function diffBy(before: Json[], after: Json[], field: string): DiffSummary {
  const index = (list: Json[]) => new Map(list.map((item, position) => [readString(item, field) || `#${position + 1}`, canonical(item)]));
  const a = index(before);
  const b = index(after);
  return {
    added: [...b.keys()].filter((key) => !a.has(key)),
    removed: [...a.keys()].filter((key) => !b.has(key)),
    changed: [...b.keys()].filter((key) => a.has(key) && a.get(key) !== b.get(key))
  };
}

export function diffDrafts(before: Draft, after: Draft): { rules: DiffSummary; registry: DiffSummary } {
  return { rules: diffBy(before.rules, after.rules, "ruleId"), registry: diffBy(before.registry, after.registry, "secretName") };
}

export function isEmptyDiff(diff: { rules: DiffSummary; registry: DiffSummary }): boolean {
  return [diff.rules, diff.registry].every((part) => !part.added.length && !part.removed.length && !part.changed.length);
}

export interface Issue {
  section: "secret_registry" | "exchange_policy" | null;
  index: number | null;
  field: string | null;
  message: string;
  raw: string;
}

/** "exchange_policy[2].ruleId: required" → section, index, field, message. */
export function parseIssue(raw: string): Issue {
  const match = raw.match(/^(secret_registry|exchange_policy)(?:\[(\d+)\])?(?:\.([A-Za-z_]+))?:\s*(.+)$/);
  if (!match) return { section: null, index: null, field: null, message: raw, raw };
  const field = match[3] ?? null;
  const canonicalField = field ? Object.entries(ALIASES).find(([, aliases]) => aliases.includes(field))?.[0] ?? field : null;
  return { section: match[1] as Issue["section"], index: match[2] !== undefined ? Number(match[2]) : null, field: canonicalField, message: match[4]!, raw };
}

export function issuesFor(issues: Issue[], section: Issue["section"], index: number): Issue[] {
  return issues.filter((issue) => issue.section === section && issue.index === index);
}

export function move<T>(list: T[], index: number, delta: -1 | 1): T[] {
  const target = index + delta;
  if (target < 0 || target >= list.length) return list;
  const next = [...list];
  [next[index], next[target]] = [next[target]!, next[index]!];
  return next;
}

export function blankRule(draft: Draft): Json {
  let n = draft.rules.length + 1;
  const ids = new Set(draft.rules.map((rule) => readString(rule, "ruleId")));
  while (ids.has(`rule-${n}`)) n += 1;
  // No empty lists: the controller treats a missing or empty list as "any".
  return { ruleId: `rule-${n}`, secretName: readString(draft.registry[0] ?? {}, "secretName"), mode: "pending_approval" };
}
