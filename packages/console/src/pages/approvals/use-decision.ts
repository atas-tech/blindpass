import { useCallback, useRef, useState } from "react";
import { ApiError, newIdempotencyKey } from "../../api/client.js";
import type { AnyApproval } from "../../api/types.js";
import { approvalFingerprint } from "./model.js";
import type { ApprovalSource } from "./source.js";

export type Verb = "approve" | "reject";

export type DecisionState =
  | { phase: "idle" }
  | { phase: "checking"; verb: Verb }
  | { phase: "sending"; verb: Verb }
  | { phase: "done"; verb: Verb }
  /** The approval changed before or during the decision; nothing was sent or it was refused. */
  | { phase: "stale"; verb: Verb; beforeSend: boolean }
  | { phase: "denied"; verb: Verb; error: ApiError }
  /** Approved, but the controller could not issue the grant (authorization_changed). */
  | { phase: "grant_blocked"; verb: Verb }
  /** The reply was lost; the controller may or may not have recorded it. */
  | { phase: "unknown"; verb: Verb }
  | { phase: "reconciling"; verb: Verb }
  | { phase: "still_pending"; verb: Verb }
  | { phase: "resolved"; verb: Verb }
  /** The controller no longer returns the approval (expired window or removed); nothing was applied. */
  | { phase: "gone"; verb: Verb };

/**
 * One decision attempt against an approval. The same Idempotency-Key is
 * reused for a retry after a lost reply, so a resend can be replayed but
 * never applied twice; a new decision (or a different verb) gets a new key.
 */
export function useDecision(source: ApprovalSource, onApproval: (approval: AnyApproval) => void) {
  const [state, setState] = useState<DecisionState>({ phase: "idle" });
  const attempt = useRef<{ verb: Verb; key: string; approval: AnyApproval } | null>(null);

  const refetch = useCallback(async (approval: AnyApproval) => {
    const fresh = await source.get(approval.kind, approval.kind === "operation" ? approval.id : approval.reference);
    onApproval(fresh);
    return fresh;
  }, [source, onApproval]);

  const send = useCallback(async (verb: Verb, approval: AnyApproval, key: string) => {
    setState({ phase: "sending", verb });
    try {
      await source.decide(approval, verb, key);
      attempt.current = null;
      setState({ phase: "done", verb });
      await refetch(approval).catch(() => undefined);
    } catch (error) {
      const failure = error instanceof ApiError ? error : new ApiError(0, "network", String(error));
      if (failure.outcomeUnknown) {
        setState({ phase: "unknown", verb });
        return;
      }
      attempt.current = null;
      if (failure.status === 401) {
        // The session listener sends the operator to sign-in; nothing to show here.
        setState({ phase: "idle" });
        return;
      }
      if (failure.status === 409 && failure.code === "authorization_changed") {
        setState({ phase: "grant_blocked", verb });
        await refetch(approval).catch(() => undefined);
        return;
      }
      if (failure.status === 404) {
        setState({ phase: "gone", verb });
        return;
      }
      if (failure.status === 409 && (failure.code === "approval_not_pending" || failure.code === "approval_conflict")) {
        setState({ phase: "stale", verb, beforeSend: false });
        await refetch(approval).catch(() => undefined);
        return;
      }
      setState({ phase: "denied", verb, error: failure });
    }
  }, [source, refetch]);

  /** Re-read the approval, and send only if it still matches what the operator reviewed. */
  const decide = useCallback(async (verb: Verb, reviewed: AnyApproval) => {
    setState({ phase: "checking", verb });
    let fresh: AnyApproval;
    try {
      fresh = await refetch(reviewed);
    } catch (error) {
      const failure = error instanceof ApiError ? error : new ApiError(0, "network", String(error));
      if (failure.status === 401) return setState({ phase: "idle" });
      if (failure.status === 404) return setState({ phase: "gone", verb });
      return setState({ phase: "denied", verb, error: failure });
    }
    if (approvalFingerprint(fresh) !== approvalFingerprint(reviewed)) {
      return setState({ phase: "stale", verb, beforeSend: true });
    }
    const key = attempt.current?.verb === verb ? attempt.current.key : newIdempotencyKey();
    attempt.current = { verb, key, approval: fresh };
    await send(verb, fresh, key);
  }, [refetch, send]);

  /** After a lost reply: read the authoritative state before offering anything else. */
  const reconcile = useCallback(async () => {
    const current = attempt.current;
    if (!current) return;
    setState({ phase: "reconciling", verb: current.verb });
    try {
      const fresh = await refetch(current.approval);
      if (fresh.status === "pending" && approvalFingerprint(fresh) === approvalFingerprint(current.approval)) {
        setState({ phase: "still_pending", verb: current.verb });
      } else {
        attempt.current = null;
        setState({ phase: "resolved", verb: current.verb });
      }
    } catch (error) {
      const failure = error instanceof ApiError ? error : new ApiError(0, "network", String(error));
      if (failure.status === 404) {
        attempt.current = null;
        setState({ phase: "resolved", verb: current.verb });
        return;
      }
      setState(failure.outcomeUnknown ? { phase: "unknown", verb: current.verb } : { phase: "denied", verb: current.verb, error: failure });
    }
  }, [refetch]);

  /** Resend exactly the same decision with the same key. */
  const resend = useCallback(async () => {
    const current = attempt.current;
    if (!current) return;
    await send(current.verb, current.approval, current.key);
  }, [send]);

  const reset = useCallback(() => {
    attempt.current = null;
    setState({ phase: "idle" });
  }, []);

  return { state, decide, reconcile, resend, reset };
}
