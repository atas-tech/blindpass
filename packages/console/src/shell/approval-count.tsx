import { createContext, useContext, type ReactNode } from "react";
import * as endpoints from "../api/endpoints.js";
import type { ApiError } from "../api/client.js";
import { useSession } from "../session/session.js";
import { useResource } from "../lib/use-resource.js";

export const APPROVAL_POLL = { visibleMs: 5_000, hiddenMs: 30_000 };

interface ApprovalCountValue {
  /** null while loading or after a failed read: never shown as zero. */
  count: number | null;
  error: ApiError | null;
  reload: () => void;
}

const ApprovalCountContext = createContext<ApprovalCountValue>({ count: null, error: null, reload: () => undefined });

/**
 * One poller for the pending count (P04-D8). With fleet.v3 the unified count
 * already includes exchange approvals, so the two counts are never summed.
 */
export function ApprovalCountProvider({ children }: { children: ReactNode }) {
  const { can, hasFleet, session } = useSession();
  const enabled = Boolean(session) && can("approvals.read") && !session?.must_change_password;
  const { state, reload } = useResource(
    enabled ? `approval-count:${hasFleet ? "unified" : "exchange"}` : null,
    () => (hasFleet ? endpoints.unifiedApprovals.count() : endpoints.exchangeApprovals.count()),
    { poll: APPROVAL_POLL, enabled }
  );
  const value: ApprovalCountValue = {
    count: state.status === "ready" ? state.data.count : null,
    error: state.status === "error" ? state.error : null,
    reload: () => void reload()
  };
  return <ApprovalCountContext.Provider value={value}>{children}</ApprovalCountContext.Provider>;
}

export function useApprovalCount(): ApprovalCountValue {
  return useContext(ApprovalCountContext);
}
