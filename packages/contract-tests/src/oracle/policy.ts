import { createHash } from "node:crypto";

// Clean-room oracle for the exchange-policy contract (CV05): which rule decides an exchange and the SHA-256 that
// binds that decision into a fulfillment token. Pinned by fixtures/cv05-policy.json, cv05-hash-escaping.json,
// cv05-policy-matrix.json (decisions frozen from the retired SPS engine) and cv05-policy-decided.json (the shapes
// the owner decided on 2026-10-07); the Rust controller replays all of them.
//
// Rules the contract depends on:
//  - the first rule whose secret name equals the request's matches; all other conditions must hold
//  - every list (requester, fulfiller, purpose, ring) treats absent OR empty as "any"; a populated list is an
//    exact-match list. An empty identity list matching every agent is the owner's decision (the retired SPS
//    engine matched no agent); admin validation still rejects a blank entry, which would otherwise empty the list
//  - a ring is the segment after "/ring/" in an agent id
//  - sameRing needs both rings present and equal, and, when allowedRings is set, listed
//  - two different workspaces never exchange; an unknown secret never matches
//  - an unrecognised rule mode denies (see normalizeMode)
//  - rule ids, rule secret names and reasons are trimmed, and a blank reason falls back to the generated text
export type PolicyDecisionMode = "allow" | "pending_approval" | "deny";

export interface SecretRegistryEntry {
  secretName: string;
  classification: string;
  description?: string;
}

export interface ExchangePolicyRule {
  ruleId: string;
  secretName: string;
  requesterIds?: string[];
  fulfillerIds?: string[];
  approverIds?: string[];
  requesterRings?: string[];
  fulfillerRings?: string[];
  approverRings?: string[];
  purposes?: string[];
  sameRing?: boolean;
  allowedRings?: string[];
  mode?: PolicyDecisionMode;
  approvalReference?: string | null;
  reason?: string;
}

export interface EvaluateExchangePolicyInput {
  requesterId: string;
  requesterWorkspaceId?: string;
  secretName: string;
  purpose: string;
  fulfillerHint: string;
  fulfillerWorkspaceId?: string;
}

export interface PolicyDecision {
  mode: PolicyDecisionMode;
  approvalRequired: boolean;
  ruleId: string;
  reason: string;
  approvalReference?: string | null;
  requesterRing?: string | null;
  fulfillerRing?: string | null;
  secretName: string;
}

export interface PolicyEvaluation {
  decision: PolicyDecision;
  allowedFulfillerId: string | null;
  approverIds?: string[];
  approverRings?: string[];
}

const trimmed = (values: string[] | undefined): string[] | undefined => values?.map((value) => value.trim()).filter(Boolean);
// Absent or empty means "any"; a populated list must contain the candidate.
const anyOrIncludes = (values: string[] | undefined, candidate: string): boolean => !values || values.length === 0 || values.includes(candidate);
const ringOf = (agentId: string): string | null => /\/ring\/([^/]+)/.exec(agentId)?.[1] ?? null;

// An absent mode is "allow"; a recognised mode may carry surrounding whitespace; anything else DENIES. The legacy
// SPS engine turned an unrecognised mode into "allow". The Rust controller closed that (policy validation rejects
// unknown modes, and a rule that still reaches the engine denies), so the accepted contract is fail-closed.
function normalizeMode(mode: string | undefined): PolicyDecisionMode {
  if (mode == null) return "allow";
  const value = String(mode).trim();
  return value === "allow" ? "allow" : value === "pending_approval" ? "pending_approval" : "deny";
}

export class ExchangePolicyEngine {
  private readonly secrets = new Map<string, SecretRegistryEntry>();
  private readonly rules: ExchangePolicyRule[];

  constructor(registry: SecretRegistryEntry[], rules: ExchangePolicyRule[]) {
    for (const entry of registry) {
      const secretName = entry.secretName.trim();
      this.secrets.set(secretName, { secretName, classification: entry.classification.trim(), description: entry.description?.trim() || undefined });
    }
    this.rules = rules.map((rule) => ({
      ...rule,
      ruleId: rule.ruleId.trim(),
      secretName: rule.secretName.trim(),
      reason: rule.reason?.trim() || undefined,
      requesterIds: trimmed(rule.requesterIds),
      fulfillerIds: trimmed(rule.fulfillerIds),
      approverIds: trimmed(rule.approverIds),
      requesterRings: trimmed(rule.requesterRings),
      fulfillerRings: trimmed(rule.fulfillerRings),
      approverRings: trimmed(rule.approverRings),
      purposes: trimmed(rule.purposes),
      allowedRings: trimmed(rule.allowedRings),
      mode: normalizeMode(rule.mode),
      approvalReference: typeof rule.approvalReference === "string" ? rule.approvalReference.trim() || null : rule.approvalReference ?? null
    }));
  }

  evaluate(input: EvaluateExchangePolicyInput): PolicyEvaluation | null {
    const secret = this.secrets.get(input.secretName);
    if (!secret) return null;
    if (input.requesterWorkspaceId && input.fulfillerWorkspaceId && input.requesterWorkspaceId !== input.fulfillerWorkspaceId) return null;

    const requesterRing = ringOf(input.requesterId);
    const fulfillerRing = ringOf(input.fulfillerHint);
    const rule = this.rules.find((candidate) => {
      if (candidate.secretName !== input.secretName) return false;
      if (!anyOrIncludes(candidate.requesterIds, input.requesterId)) return false;
      if (!anyOrIncludes(candidate.fulfillerIds, input.fulfillerHint)) return false;
      if (!anyOrIncludes(candidate.purposes, input.purpose)) return false;
      if (!anyOrIncludes(candidate.requesterRings, requesterRing ?? "")) return false;
      if (!anyOrIncludes(candidate.fulfillerRings, fulfillerRing ?? "")) return false;
      if (candidate.sameRing) {
        if (!requesterRing || !fulfillerRing || requesterRing !== fulfillerRing) return false;
        if (candidate.allowedRings && !candidate.allowedRings.includes(requesterRing)) return false;
      }
      return true;
    });
    if (!rule) return null;

    const mode = rule.mode ?? "allow";
    const reasons: Record<PolicyDecisionMode, string> = {
      pending_approval: `exchange for ${secret.classification} requires human approval`,
      deny: `exchange for ${secret.classification} is denied by policy`,
      allow: `exchange allowed by static policy for ${secret.classification}`
    };
    return {
      allowedFulfillerId: mode === "allow" ? input.fulfillerHint : null,
      approverIds: rule.approverIds,
      approverRings: rule.approverRings,
      decision: {
        mode,
        approvalRequired: mode === "pending_approval",
        ruleId: rule.ruleId,
        reason: rule.reason ?? reasons[mode],
        approvalReference: rule.approvalReference ?? null,
        requesterRing,
        fulfillerRing,
        secretName: input.secretName
      }
    };
  }
}

// The hashed text is JSON with this exact key order and nulls for absent values, so every runtime must emit the
// same escaping. cv05-hash-escaping.json carries the cases that expose a difference.
export function hashPolicyDecision(decision: PolicyDecision, allowedFulfillerId: string | null, workspaceId?: string | null): string {
  return createHash("sha256").update(JSON.stringify({
    mode: decision.mode,
    approvalRequired: decision.approvalRequired,
    ruleId: decision.ruleId,
    reason: decision.reason,
    approvalReference: decision.approvalReference ?? null,
    requesterRing: decision.requesterRing ?? null,
    fulfillerRing: decision.fulfillerRing ?? null,
    secretName: decision.secretName,
    allowedFulfillerId: allowedFulfillerId ?? null,
    workspaceId: workspaceId ?? null
  })).digest("hex");
}
