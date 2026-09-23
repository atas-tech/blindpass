import { createHash } from "node:crypto";
import type { PolicyDecision, PolicyDecisionMode } from "../types.js";

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

function normalizeList(values: string[]): string[] {
  return values.map((value) => value.trim()).filter(Boolean);
}

function listIncludes(values: string[] | undefined, candidate: string): boolean {
  if (!values || values.length === 0) {
    return true;
  }
  return values.includes(candidate);
}

function ringFromAgentId(agentId: string): string | null {
  const match = agentId.match(/\/ring\/([^/]+)/);
  return match?.[1] ?? null;
}

function normalizeMode(mode: PolicyDecisionMode | undefined): PolicyDecisionMode {
  if (mode === "deny" || mode === "pending_approval") {
    return mode;
  }
  return "allow";
}

function defaultReason(mode: PolicyDecisionMode, classification: string): string {
  if (mode === "pending_approval") {
    return `exchange for ${classification} requires human approval`;
  }
  if (mode === "deny") {
    return `exchange for ${classification} is denied by policy`;
  }
  return `exchange allowed by static policy for ${classification}`;
}

export class ExchangePolicyEngine {
  private readonly registry = new Map<string, SecretRegistryEntry>();
  private readonly rules: ExchangePolicyRule[];

  constructor(registryEntries: SecretRegistryEntry[], rules: ExchangePolicyRule[]) {
    for (const entry of registryEntries) {
      this.registry.set(entry.secretName.trim(), {
        secretName: entry.secretName.trim(),
        classification: entry.classification.trim(),
        description: entry.description?.trim() || undefined
      });
    }

    this.rules = rules.map((rule) => ({
      ...rule,
      requesterIds: rule.requesterIds ? normalizeList(rule.requesterIds) : undefined,
      fulfillerIds: rule.fulfillerIds ? normalizeList(rule.fulfillerIds) : undefined,
      approverIds: rule.approverIds ? normalizeList(rule.approverIds) : undefined,
      requesterRings: rule.requesterRings ? normalizeList(rule.requesterRings) : undefined,
      fulfillerRings: rule.fulfillerRings ? normalizeList(rule.fulfillerRings) : undefined,
      approverRings: rule.approverRings ? normalizeList(rule.approverRings) : undefined,
      purposes: rule.purposes ? normalizeList(rule.purposes) : undefined,
      allowedRings: rule.allowedRings ? normalizeList(rule.allowedRings) : undefined,
      mode: normalizeMode(rule.mode),
      approvalReference: typeof rule.approvalReference === "string" ? rule.approvalReference.trim() || null : rule.approvalReference ?? null
    }));
  }

  hasSecret(secretName: string): boolean {
    return this.registry.has(secretName);
  }

  getSecret(secretName: string): SecretRegistryEntry | null {
    return this.registry.get(secretName) ?? null;
  }

  evaluate(input: EvaluateExchangePolicyInput): {
    decision: PolicyDecision;
    allowedFulfillerId: string | null;
    approverIds?: string[];
    approverRings?: string[];
  } | null {
    const registryEntry = this.registry.get(input.secretName);
    if (!registryEntry) {
      return null;
    }

    if (
      input.requesterWorkspaceId &&
      input.fulfillerWorkspaceId &&
      input.requesterWorkspaceId !== input.fulfillerWorkspaceId
    ) {
      return null;
    }

    const requesterRing = ringFromAgentId(input.requesterId);
    const fulfillerRing = ringFromAgentId(input.fulfillerHint);
    
    const matchedRule = this.rules.find((rule) => {
      if (rule.secretName !== input.secretName) return false;
      if (rule.requesterIds && !rule.requesterIds.includes(input.requesterId)) return false;
      if (rule.fulfillerIds && !rule.fulfillerIds.includes(input.fulfillerHint)) return false;
      if (!listIncludes(rule.purposes, input.purpose)) return false;
      if (!listIncludes(rule.requesterRings, requesterRing ?? "")) return false;
      if (!listIncludes(rule.fulfillerRings, fulfillerRing ?? "")) return false;
      if (rule.sameRing) {
        if (!requesterRing || !fulfillerRing || requesterRing !== fulfillerRing) return false;
        if (rule.allowedRings && !rule.allowedRings.includes(requesterRing)) return false;
      }
      return true;
    });

    if (!matchedRule) {
      return null;
    }

    return {
      allowedFulfillerId: matchedRule.mode === "allow" ? input.fulfillerHint : null,
      approverIds: matchedRule.approverIds,
      approverRings: matchedRule.approverRings,
      decision: {
        mode: matchedRule.mode ?? "allow",
        approvalRequired: matchedRule.mode === "pending_approval",
        ruleId: matchedRule.ruleId,
        reason: matchedRule.reason ?? defaultReason(matchedRule.mode ?? "allow", registryEntry.classification),
        approvalReference: matchedRule.approvalReference ?? null,
        requesterRing,
        fulfillerRing,
        secretName: input.secretName
      }
    };
  }
}

export function hashPolicyDecision(
  decision: PolicyDecision,
  allowedFulfillerId: string | null,
  workspaceId?: string | null
): string {
  const payload = JSON.stringify({
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
  });
  return createHash("sha256").update(payload).digest("hex");
}
