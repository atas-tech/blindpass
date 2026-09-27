import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { AnyApproval } from "../../api/types.js";
import type { ApprovalKind, ApprovalStatus } from "./model.js";

export interface ApprovalPage {
  items: AnyApproval[];
  next_cursor: string | null;
  /** Authoritative pending total, when the list route reports it. */
  count: number | null;
}

export interface ApprovalSource {
  statuses: readonly ApprovalStatus[];
  list: (status: ApprovalStatus, cursor: string | null) => Promise<ApprovalPage>;
  get: (kind: ApprovalKind, id: string) => Promise<AnyApproval>;
  decide: (approval: AnyApproval, verb: "approve" | "reject", idempotencyKey: string) => Promise<unknown>;
}

const PAGE_SIZE = 25;

/**
 * With fleet.v3 the unified routes already merge exchange and operation
 * approvals; without it only the exchange routes exist. The console never
 * combines the two.
 */
export function approvalSource(hasFleet: boolean): ApprovalSource {
  if (hasFleet) {
    return {
      statuses: ["pending", "approved", "rejected", "expired"],
      list: async (status, cursor) => {
        const page = await endpoints.unifiedApprovals.list({ status, limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) });
        return { items: page.items, next_cursor: page.next_cursor, count: page.count };
      },
      get: (_kind, id) => endpoints.unifiedApprovals.get(id),
      decide: (approval, verb, key) => endpoints.unifiedApprovals.decide(approval, verb, key)
    };
  }
  return {
    statuses: ["pending", "approved", "rejected"],
    list: async (status, cursor) => {
      const page = await endpoints.exchangeApprovals.list({ status: status === "expired" ? undefined : status, limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) });
      return { items: page.items, next_cursor: page.next_cursor, count: null };
    },
    get: async (kind, id) => {
      if (kind !== "exchange") throw new ApiError(404, "approval_not_found", "operation approvals need the fleet API");
      return endpoints.exchangeApprovals.get(id);
    },
    decide: (approval, verb, key) => {
      if (approval.kind !== "exchange") throw new Error("operation approvals need the fleet API");
      return endpoints.exchangeApprovals.decide(approval.reference, verb, key);
    }
  };
}
