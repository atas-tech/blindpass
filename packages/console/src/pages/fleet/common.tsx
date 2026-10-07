import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router";
import * as endpoints from "../../api/endpoints.js";
import { useTranslation } from "react-i18next";
import type { Enrollment, FleetNode, Fulfillment, Grant, Operation } from "../../api/types.js";
import { groupFingerprint } from "../../lib/format.js";
import { collectAll, useResource, type ResourceOptions, type ResourceState } from "../../lib/use-resource.js";
import { EmptyState, ErrorState, Skeleton, StatusBadge, type Tone } from "../../ui/feedback.js";
import type { IconName } from "../../ui/icon.js";
import { Pager } from "../../ui/layout.js";

export const FLEET_POLL = { visibleMs: 10_000, hiddenMs: 60_000 };

const NODE_TONE: Record<FleetNode["status"], Tone> = { online: "ok", stale: "warn", offline: "danger", revoked: "neutral" };
const ENROLLMENT_TONE: Record<Enrollment["status"], Tone> = { issued: "info", submitted: "warn", approved: "ok", rejected: "danger", expired: "neutral" };
const GRANT_TONE: Record<Grant["status"], Tone> = { issued: "info", delivered: "lime", consumed: "ok", revoked: "neutral", expired: "neutral" };
const FULFILLMENT_TONE: Record<Fulfillment["status"], Tone> = {
  awaiting_approval: "warn",
  approved: "info",
  offered: "info",
  available: "lime",
  recipient_consumed: "lime",
  completed: "ok",
  denied: "danger",
  revoked: "neutral",
  expired: "neutral",
  failed: "danger",
  uncertain: "warn"
};
const OPERATION_TONE: Record<Operation["status"], Tone> = {
  requested: "info",
  awaiting_approval: "warn",
  granted: "lime",
  executing: "info",
  completed: "ok",
  failed: "danger",
  uncertain: "warn",
  denied: "danger",
  revoked: "neutral",
  cancelled: "neutral"
};

export function NodeStatusBadge({ node }: { node: FleetNode }) {
  const { t } = useTranslation();
  return (
    <span className="badge-stack">
      <StatusBadge tone={NODE_TONE[node.status]} icon={node.status === "revoked" ? "ban" : node.status === "online" ? "signal" : undefined}>
        {t(`fleet.node.status.${node.status}`)}
      </StatusBadge>
      {node.revocation_pending ? <StatusBadge tone="warn" icon="clock">{t("fleet.node.revocationPending")}</StatusBadge> : null}
      {node.rotation_pending ? <StatusBadge tone="info" icon="rotate">{t("fleet.node.rotationPending")}</StatusBadge> : null}
    </span>
  );
}

export function EnrollmentBadge({ status }: { status: Enrollment["status"] }) {
  const { t } = useTranslation();
  return <StatusBadge tone={ENROLLMENT_TONE[status]}>{t(`fleet.enrollment.status.${status}`)}</StatusBadge>;
}

export function GrantBadge({ status }: { status: Grant["status"] }) {
  const { t } = useTranslation();
  return <StatusBadge tone={GRANT_TONE[status]}>{t(`fleet.grant.status.${status}`)}</StatusBadge>;
}

export function FulfillmentBadge({ status }: { status: Fulfillment["status"] }) {
  const { t } = useTranslation();
  return <StatusBadge tone={FULFILLMENT_TONE[status]}>{t(`fleet.fulfillment.status.${status}`)}</StatusBadge>;
}

export function OperationBadge({ status }: { status: Operation["status"] }) {
  const { t } = useTranslation();
  return <StatusBadge tone={OPERATION_TONE[status]}>{t(`fleet.operation.status.${status}`)}</StatusBadge>;
}

export function Fingerprint({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="muted">—</span>;
  return (
    <code className="fingerprint" title={value}>
      {groupFingerprint(value)}
    </code>
  );
}

/** A cursor-paged list: newer/older, with loading, error and empty kept distinct. */
export function usePagedList<T>(key: string, load: (cursor: string | null) => Promise<{ items: T[]; next_cursor: string | null }>, options: ResourceOptions = {}) {
  const [cursors, setCursors] = useState<Array<string | null>>([null]);
  const cursor = cursors[cursors.length - 1] ?? null;
  const resource = useResource(`${key}:${cursor ?? ""}`, () => load(cursor), options);
  const { state } = resource;
  return {
    ...resource,
    items: state.status === "ready" ? state.data.items : state.status === "error" ? state.previous?.items ?? null : null,
    page: cursors.length,
    reset: () => setCursors([null]),
    pager: (
      <Pager
        hasPrevious={cursors.length > 1}
        hasNext={state.status === "ready" && Boolean(state.data.next_cursor)}
        onPrevious={() => setCursors((list) => list.slice(0, -1))}
        onNext={() => state.status === "ready" && state.data.next_cursor && setCursors((list) => [...list, state.data.next_cursor])}
        busy={state.status === "loading"}
      />
    )
  };
}

/** Loading, error and empty states for a list body; children render the rows. */
export function ListBody<T>({ state, items, onRetry, emptyTitle, emptyBody, emptyIcon = "info", children }: { state: ResourceState<unknown>; items: T[] | null; onRetry: () => void; emptyTitle: ReactNode; emptyBody?: ReactNode; emptyIcon?: IconName; children: (items: T[]) => ReactNode }) {
  if (state.status === "loading") return <Skeleton lines={4} className="panel-pad" />;
  return (
    <>
      {state.status === "error" ? (
        <div className="panel-pad">
          <ErrorState error={state.error} onRetry={onRetry} />
        </div>
      ) : null}
      {state.status === "ready" && items && items.length === 0 ? (
        <EmptyState icon={emptyIcon} title={emptyTitle}>
          {emptyBody}
        </EmptyState>
      ) : null}
      {items && items.length > 0 ? children(items) : null}
    </>
  );
}

/**
 * One line per reported capability ("modes: file, socket"), so a node's
 * self-description reads at a glance. Nested values fall back to compact
 * JSON. The result is plain text for UntrustedText; nothing is interpreted.
 */
export function formatCapabilities(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return JSON.stringify(value);
  const lines = Object.entries(value as Record<string, unknown>).map(([key, item]) => {
    const flat = Array.isArray(item) && item.every((entry) => typeof entry !== "object" || entry === null);
    return `${key}: ${flat ? (item as unknown[]).map(String).join(", ") : typeof item === "string" ? item : JSON.stringify(item)}`;
  });
  return lines.join("\n");
}

/**
 * Node names by ID, for showing a readable label next to a node reference.
 * Best effort: while loading or on failure the raw ID is shown instead, and
 * the ID stays the link target and the value any decision is bound to.
 */
export function useNodeNames(): (id: string) => string | null {
  const nodes = useResource("fleet-node-names", () => collectAll((cursor) => endpoints.nodes.list({ limit: 100, ...(cursor ? { cursor } : {}) })));
  const names = useMemo(() => new Map(nodes.state.status === "ready" ? nodes.state.data.map((node) => [node.id, node.name] as const) : []), [nodes.state]);
  return (id) => names.get(id) ?? null;
}

export function NodeRef({ id, name, className }: { id: string; name: string | null; className?: string }) {
  return (
    <Link className={className ?? "row-link"} to={`/nodes/${encodeURIComponent(id)}`} title={id}>
      {name ?? <span className="mono">{id}</span>}
    </Link>
  );
}
