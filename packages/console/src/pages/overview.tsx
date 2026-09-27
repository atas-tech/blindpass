import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import * as endpoints from "../api/endpoints.js";
import type { AnyApproval, AuditEvent, FleetNode } from "../api/types.js";
import { isOperationApproval } from "../api/types.js";
import { eventLabel } from "../lib/events.js";
import { formatNumber } from "../lib/format.js";
import { collectAll, useResource, type ResourceState } from "../lib/use-resource.js";
import { useSession } from "../session/session.js";
import { APPROVAL_POLL, useApprovalCount } from "../shell/approval-count.js";
import { ButtonLink } from "../ui/button.js";
import { EmptyState, ErrorState, Skeleton } from "../ui/feedback.js";
import { Icon, type IconName } from "../ui/icon.js";
import { PageHeader, Panel } from "../ui/layout.js";
import { Countdown, Timestamp } from "../ui/time.js";
import { approvalKey, approvalPath, approvalRequester } from "./approvals/model.js";
import { approvalSource } from "./approvals/source.js";

const QUEUE_PREVIEW = 5;
const ACTIVITY_PREVIEW = 8;
const NODE_STATUSES = ["online", "stale", "offline", "revoked"] as const;

function StatCard({ label, icon, value, hint, footer, testId }: { label: string; icon: IconName; value: ReactNode; hint?: ReactNode; footer?: ReactNode; testId: string }) {
  return (
    <section className="stat" data-testid={testId} aria-label={label}>
      <header className="stat-header">
        <span className="stat-label">{label}</span>
        <Icon name={icon} size={17} className="stat-icon" />
      </header>
      <div className="stat-value">{value}</div>
      {hint ? <p className="stat-hint">{hint}</p> : null}
      {footer}
    </section>
  );
}

/** A number, a skeleton or an explicit "unavailable": a failed read is never a zero. */
function StatValue<T>({ state, render, onRetry }: { state: ResourceState<T>; render: (data: T) => ReactNode; onRetry: () => void }) {
  const { t } = useTranslation();
  if (state.status === "loading") return <Skeleton lines={1} className="stat-skeleton" />;
  if (state.status === "error") {
    return (
      <span className="stat-unavailable" data-error-kind={state.error.kind}>
        <span className="stat-unavailable-label">{t("overview.unavailable")}</span>
        <button type="button" className="text-button" onClick={onRetry}>
          {t("common.retry")}
        </button>
      </span>
    );
  }
  return <>{render(state.data)}</>;
}

function NodeBreakdown({ nodes }: { nodes: FleetNode[] }) {
  const { t, i18n } = useTranslation();
  if (nodes.length === 0) return <p className="stat-hint">{t("overview.stats.nodesEmpty")}</p>;
  return (
    <ul className="node-breakdown">
      {NODE_STATUSES.map((status) => {
        const count = nodes.filter((node) => node.status === status).length;
        return (
          <li key={status} className={`node-breakdown-item is-${status}${count === 0 ? " is-zero" : ""}`}>
            <span className="node-dot" aria-hidden="true" />
            <span className="mono">{formatNumber(count, i18n.language)}</span> {t(`overview.node.${status}`)}
          </li>
        );
      })}
    </ul>
  );
}

function QueuePreview({ items, total }: { items: AnyApproval[]; total: number | null }) {
  const { t } = useTranslation();
  if (items.length === 0) return <EmptyState title={t("approvals.empty.pendingTitle")}>{t("approvals.empty.pendingBody")}</EmptyState>;
  const shown = items.slice(0, QUEUE_PREVIEW);
  const more = (total ?? items.length) - shown.length;
  return (
    <>
      <table className="data-table is-responsive">
        <thead>
          <tr>
            <th scope="col">{t("approvals.fields.requester")}</th>
            <th scope="col">{t("approvals.confirm.scope")}</th>
            <th scope="col">{t("approvals.fields.requested")}</th>
            <th scope="col">
              <span className="sr-only">{t("common.view")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {shown.map((approval) => {
            const operation = isOperationApproval(approval);
            return (
              <tr key={`${approval.kind}:${approvalKey(approval)}`}>
                <td data-label={t("approvals.fields.requester")} className="cell-lead">
                  <span className="cell-primary">
                    <span className="cell-title">{approvalRequester(approval)}</span>
                    <span className="cell-sub">{t(`approvals.kind.${approval.kind}`)}</span>
                  </span>
                </td>
                <td data-label={t("approvals.confirm.scope")}>
                  <code className="mono">{operation ? `${approval.verified_identity.action} · ${approval.verified_identity.unit}` : approval.secret_name}</code>
                </td>
                <td data-label={t("approvals.fields.requested")}>
                  {operation ? <Countdown expiresAt={approval.expires_at} /> : <Timestamp value={approval.created_at} relative />}
                </td>
                <td className="cell-actions">
                  <ButtonLink to={approvalPath(approval)} size="sm" iconEnd="arrow-up-right" aria-label={t("approvals.queue.open", { name: approvalRequester(approval) })}>
                    {t("overview.queue.review")}
                  </ButtonLink>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {more > 0 ? <p className="panel-foot">{t("overview.queue.more", { count: more })}</p> : null}
    </>
  );
}

function ActivityItem({ event }: { event: AuditEvent }) {
  const { t, i18n } = useTranslation();
  const { label, known } = eventLabel(event.event, t, i18n);
  return (
    <li className="activity-item">
      <Icon name={event.event.startsWith("fleet.") ? "nodes" : event.event.startsWith("exchange") ? "key" : "audit"} size={16} className="activity-icon" />
      <div className="activity-copy">
        <span className={known ? "activity-title" : "activity-title mono"}>{label}</span>
        <span className="activity-meta">
          {event.resource_id ? <code className="mono">{event.resource_id}</code> : null}
          {event.actor_id ? <span>{t("overview.activity.by", { actor: event.actor_id })}</span> : null}
        </span>
      </div>
      <Timestamp value={event.created_at} relative />
    </li>
  );
}

export default function OverviewPage() {
  const { t, i18n } = useTranslation();
  const { session, can, hasFleet } = useSession();
  const canApprovals = can("approvals.read");
  const canAgents = can("agents.read");
  const { count, error: countError, reload: reloadCount } = useApprovalCount();

  const queue = useResource(canApprovals ? `overview:queue:${hasFleet}` : null, () => approvalSource(hasFleet).list("pending", null), { poll: APPROVAL_POLL, enabled: canApprovals });
  const nodes = useResource(hasFleet ? "overview:nodes" : null, () => collectAll((cursor) => endpoints.nodes.list({ limit: 100, ...(cursor ? { cursor } : {}) })), { poll: { visibleMs: 30_000, hiddenMs: 120_000 }, enabled: hasFleet });
  const agents = useResource(canAgents ? "overview:agents" : null, () => collectAll((cursor) => endpoints.agents.list({ limit: 100, ...(cursor ? { cursor } : {}) })), { enabled: canAgents });
  const activity = useResource("overview:audit", () => endpoints.audit.list({ limit: ACTIVITY_PREVIEW }), { poll: { visibleMs: 15_000, hiddenMs: 60_000 } });

  const countState: ResourceState<number> =
    count !== null ? { status: "ready", data: count, refreshing: false } : countError ? { status: "error", error: countError, previous: null } : { status: "loading" };

  return (
    <div className="stack">
      <PageHeader
        eyebrow={t("overview.eyebrow")}
        title={t("overview.greeting", { name: session?.operator.display_name ?? "" })}
        description={t("overview.description")}
        actions={
          canApprovals ? (
            <ButtonLink to="/approvals" variant="primary" iconEnd="arrow-right">
              {t("overview.review")}
            </ButtonLink>
          ) : null
        }
      />

      <div className="stat-grid">
        {canApprovals ? (
          <StatCard
            testId="stat-pending"
            label={t("overview.stats.pending")}
            icon="approvals"
            value={<StatValue state={countState} onRetry={reloadCount} render={(value) => <span className={`stat-number${value > 0 ? " is-attention" : ""}`}>{formatNumber(value, i18n.language)}</span>} />}
            hint={t(hasFleet ? "overview.stats.pendingFleet" : "overview.stats.pendingExchange")}
          />
        ) : null}
        {hasFleet ? (
          <StatCard
            testId="stat-nodes"
            label={t("overview.stats.nodes")}
            icon="nodes"
            value={<StatValue state={nodes.state} onRetry={() => void nodes.reload()} render={(list) => <span className="stat-number">{formatNumber(list.length, i18n.language)}</span>} />}
            hint={nodes.state.status === "ready" ? undefined : t("overview.stats.nodesHint")}
            footer={nodes.state.status === "ready" ? (
              <>
                <NodeBreakdown nodes={nodes.state.data} />
                <p className="stat-hint">{t("overview.stats.nodesHint")}</p>
              </>
            ) : null}
          />
        ) : null}
        {canAgents ? (
          <StatCard
            testId="stat-agents"
            label={t("overview.stats.agents")}
            icon="agents"
            value={
              <StatValue
                state={agents.state}
                onRetry={() => void agents.reload()}
                render={(list) => (
                  <>
                    <span className="stat-number">{formatNumber(list.filter((agent) => agent.status === "active").length, i18n.language)}</span>
                    <span className="stat-of">{t("overview.stats.agentsOf", { total: formatNumber(list.length, i18n.language) })}</span>
                  </>
                )}
              />
            }
            hint={t("overview.stats.agentsHint")}
          />
        ) : null}
      </div>

      {canApprovals ? (
        <Panel
          title={t("overview.queue.title")}
          icon="approvals"
          flush
          meta={count !== null && count > 0 ? <span className="panel-count">{t("approvals.pendingCount", { count })}</span> : null}
          actions={
            <Link to="/approvals" className="text-link">
              {t("overview.queue.openAll")} <Icon name="arrow-right" size={14} />
            </Link>
          }
        >
          {queue.state.status === "loading" ? <Skeleton lines={3} className="panel-pad" /> : null}
          {queue.state.status === "error" ? (
            <div className="panel-pad">
              <ErrorState error={queue.state.error} onRetry={() => void queue.reload()} compact />
            </div>
          ) : null}
          {queue.state.status === "ready" ? <QueuePreview items={queue.state.data.items} total={queue.state.data.count ?? count} /> : null}
        </Panel>
      ) : null}

      <Panel
        title={t("overview.activity.title")}
        icon="audit"
        flush
        actions={
          <Link to="/audit" className="text-link">
            {t("overview.activity.viewAll")} <Icon name="arrow-right" size={14} />
          </Link>
        }
      >
        {activity.state.status === "loading" ? <Skeleton lines={4} className="panel-pad" /> : null}
        {activity.state.status === "error" ? (
          <div className="panel-pad">
            <ErrorState error={activity.state.error} onRetry={() => void activity.reload()} compact />
          </div>
        ) : null}
        {activity.state.status === "ready" ? (
          activity.state.data.items.length === 0 ? (
            <EmptyState icon="audit" title={t("overview.activity.emptyTitle")}>
              {t("overview.activity.emptyBody")}
            </EmptyState>
          ) : (
            <ul className="activity-list">
              {activity.state.data.items.map((event) => (
                <ActivityItem key={event.id} event={event} />
              ))}
            </ul>
          )
        ) : null}
      </Panel>
    </div>
  );
}
