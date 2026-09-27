import type { AdminSession, AnyApproval, ExchangeApproval, OperationApproval } from "../../api/types.js";
import { isOperationApproval } from "../../api/types.js";

export type ApprovalKind = "exchange" | "operation";
export type ApprovalStatus = AnyApproval["status"];
export const APPROVAL_STATUSES = ["pending", "approved", "rejected", "expired"] as const;

export function approvalKind(approval: AnyApproval): ApprovalKind {
  return isOperationApproval(approval) ? "operation" : "exchange";
}

export function approvalKey(approval: AnyApproval): string {
  return isOperationApproval(approval) ? approval.id : approval.reference;
}

export function approvalPath(approval: AnyApproval): string {
  return `/approvals/${approvalKind(approval)}/${encodeURIComponent(approvalKey(approval))}`;
}

/** The stable facts a stale check compares before a decision is sent. */
export function approvalFingerprint(approval: AnyApproval): string {
  if (isOperationApproval(approval)) return `${approval.status}:${approval.version}:${approval.operation_ids.join(",")}`;
  return `${approval.status}`;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** Requester-written purpose, shown only inside an untrusted block. */
export function approvalPurpose(approval: AnyApproval): string | null {
  if (isOperationApproval(approval)) return text(approval.requester_summary.purpose);
  return text(approval.purpose);
}

/** Who asked, as the controller recorded it (session or agent identity). */
export function approvalRequester(approval: AnyApproval): string {
  if (isOperationApproval(approval)) return text(approval.requester_summary.requester) ?? text(approval.requester_summary.operator_id) ?? "—";
  return approval.requester_id;
}

export type DecisionBlock = { reason: "not_pending" } | { reason: "not_named" } | { reason: "self" } | null;

/**
 * Whether this session may decide, as far as the console can tell from the
 * controller's own data. The controller re-checks everything; this only
 * avoids offering a button the server will refuse. Exchange approvals do not
 * expose their approver list, so they stay decidable and the server answers.
 */
export function decisionBlock(approval: AnyApproval, session: AdminSession | null): DecisionBlock {
  if (approval.status !== "pending") return { reason: "not_pending" };
  if (!session || !isOperationApproval(approval)) return null;
  const me = [session.operator.id, session.operator.username];
  if (!approval.approver_ids.some((id) => me.includes(id))) return { reason: "not_named" };
  const requesters = [approval.requester_summary.operator_id, approval.requester_summary.requester, ...(approval.operations ?? []).map((operation) => operation.requested_by)];
  if (requesters.some((id) => typeof id === "string" && me.includes(id))) return { reason: "self" };
  return null;
}

export function isExchangeApproval(approval: AnyApproval): approval is ExchangeApproval {
  return !isOperationApproval(approval);
}

export type { OperationApproval };
