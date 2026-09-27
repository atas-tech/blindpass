import { useCallback, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, Outlet, useMatch, useSearchParams } from "react-router";
import { isOperationApproval, type AnyApproval } from "../../api/types.js";
import { useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { APPROVAL_POLL, useApprovalCount } from "../../shell/approval-count.js";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../ui/feedback.js";
import { Icon } from "../../ui/icon.js";
import { PageHeader, Pager, SegmentedControl } from "../../ui/layout.js";
import { Countdown, Timestamp } from "../../ui/time.js";
import { approvalKey, approvalKind, approvalPath, approvalRequester, type ApprovalStatus } from "./model.js";
import { approvalSource } from "./source.js";
import { statusTone } from "./status.js";

function QueueItem({ approval, active }: { approval: AnyApproval; active: boolean }) {
  const { t } = useTranslation();
  const operation = isOperationApproval(approval);
  const requester = approvalRequester(approval);
  return (
    <li>
      <Link to={approvalPath(approval)} className={`queue-item${active ? " is-active" : ""}`} aria-current={active ? "page" : undefined} data-approval={approvalKey(approval)}>
        <span className="queue-item-top">
          <span className="queue-kind">
            <Icon name={operation ? "operations" : "key"} size={13} />
            {t(`approvals.kind.${approvalKind(approval)}`)}
          </span>
          {approval.status === "pending" && operation ? <Countdown expiresAt={approval.expires_at} /> : <StatusBadge tone={statusTone(approval.status)}>{t(`approvals.status.${approval.status}`)}</StatusBadge>}
        </span>
        <strong className="queue-item-title">{requester}</strong>
        <span className="queue-item-scope mono">{operation ? `${approval.verified_identity.action} · ${approval.verified_identity.unit}` : approval.secret_name}</span>
        <span className="queue-item-meta">
          {operation ? <span>{t("approvals.queue.operations", { count: approval.operation_ids.length })}</span> : null}
          <Timestamp value={approval.created_at} relative />
        </span>
      </Link>
    </li>
  );
}

export default function ApprovalsPage() {
  const { t } = useTranslation();
  const { hasFleet } = useSession();
  const { reload: reloadCount } = useApprovalCount();
  const source = useMemo(() => approvalSource(hasFleet), [hasFleet]);
  const [params, setParams] = useSearchParams();
  const statusParam = params.get("status") as ApprovalStatus | null;
  const status: ApprovalStatus = statusParam && source.statuses.includes(statusParam) ? statusParam : "pending";
  const [cursors, setCursors] = useState<Array<string | null>>([null]);
  const cursor = cursors[cursors.length - 1] ?? null;
  const detail = useMatch("/approvals/:kind/:id");
  const selected = detail?.params.id ? decodeURIComponent(detail.params.id) : null;

  const { state, reload } = useResource(`approvals:${hasFleet}:${status}:${cursor ?? ""}`, () => source.list(status, cursor), { poll: APPROVAL_POLL });

  const onStatus = (next: ApprovalStatus) => {
    setCursors([null]);
    setParams(next === "pending" ? {} : { status: next }, { replace: true });
  };

  const onChanged = useCallback(() => {
    void reload();
    reloadCount();
  }, [reload, reloadCount]);

  const items = state.status === "ready" ? state.data.items : state.status === "error" ? state.previous?.items ?? null : null;

  return (
    <div className="stack">
      <PageHeader eyebrow={t("approvals.eyebrow")} title={t("approvals.title")} description={t("approvals.description")} />
      <div className={`split${selected ? " has-selection" : ""}`}>
        <section className="split-list panel panel-flush" aria-labelledby="approval-queue-title">
          <header className="queue-header">
            <div>
              <h2 id="approval-queue-title" className="panel-title">
                {t("approvals.queue.label")}
              </h2>
              <p className="queue-order">{t("approvals.queue.order")}</p>
            </div>
            {state.status === "ready" && state.refreshing ? <span className="spinner is-small" aria-hidden="true" /> : null}
          </header>
          <div className="queue-filter">
            <SegmentedControl label={t("approvals.queue.statusLabel")} value={status} onChange={onStatus} options={source.statuses.map((value) => ({ value, label: t(`approvals.status.${value}`) }))} />
          </div>
          {state.status === "error" ? (
            <div className="queue-error">
              <ErrorState error={state.error} onRetry={() => void reload()} compact />
            </div>
          ) : null}
          {state.status === "loading" ? (
            <div className="queue-loading">
              <Skeleton lines={4} />
            </div>
          ) : null}
          {items && items.length === 0 && state.status === "ready" ? (
            status === "pending" ? (
              <EmptyState title={t("approvals.empty.pendingTitle")}>{t("approvals.empty.pendingBody")}</EmptyState>
            ) : (
              <EmptyState icon="info" title={t("approvals.empty.otherTitle")}>
                {t("approvals.empty.otherBody")}
              </EmptyState>
            )
          ) : null}
          {items && items.length > 0 ? (
            <ul className="queue" aria-label={t("approvals.queue.label")}>
              {items.map((approval) => (
                <QueueItem key={`${approval.kind}:${approvalKey(approval)}`} approval={approval} active={approvalKey(approval) === selected} />
              ))}
            </ul>
          ) : null}
          <div className="queue-pager">
            <Pager
              hasPrevious={cursors.length > 1}
              hasNext={state.status === "ready" && Boolean(state.data.next_cursor)}
              onPrevious={() => setCursors((list) => list.slice(0, -1))}
              onNext={() => state.status === "ready" && state.data.next_cursor && setCursors((list) => [...list, state.data.next_cursor])}
              busy={state.status === "loading"}
            />
          </div>
        </section>
        <div className="split-detail">
          {selected ? (
            <Outlet context={{ source, onChanged }} />
          ) : (
            <div className="panel split-placeholder">
              <EmptyState icon="approvals" title={t("approvals.select.title")}>
                {t("approvals.select.body")}
              </EmptyState>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
