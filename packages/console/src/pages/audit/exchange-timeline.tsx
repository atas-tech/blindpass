import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import * as endpoints from "../../api/endpoints.js";
import { useIsMe } from "../../lib/actor.js";
import { eventLabel } from "../../lib/events.js";
import { useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { ErrorState, Notice, Skeleton } from "../../ui/feedback.js";
import { Icon } from "../../ui/icon.js";
import { Identifier, PageHeader, Panel } from "../../ui/layout.js";
import { Timestamp } from "../../ui/time.js";
import { Metadata } from "./metadata.js";

export default function ExchangeTimelinePage() {
  const { t, i18n } = useTranslation();
  const isMe = useIsMe();
  const { id = "" } = useParams();
  const exchangeId = decodeURIComponent(id);
  const { can } = useSession();
  const { state, reload } = useResource(`audit-exchange:${exchangeId}`, () => endpoints.audit.exchange(exchangeId));
  const events = state.status === "ready" ? [...state.data.items].sort((a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id)) : [];
  const approvalRef = events.map((event) => event.metadata.approval_reference).find((value): value is string => typeof value === "string" && value.length > 0);

  return (
    <div className="stack">
      <nav className="breadcrumb" aria-label={t("audit.breadcrumb")}>
        <Link to="/audit">{t("nav.audit")}</Link>
        <Icon name="chevron-right" size={13} />
        <span aria-current="page">{t("audit.timeline.crumb")}</span>
      </nav>
      <PageHeader eyebrow={t("audit.timeline.eyebrow")} title={t("audit.timeline.title")} meta={<Identifier value={exchangeId} />} description={t("audit.timeline.description")} />
      {state.status === "loading" ? <Skeleton lines={5} /> : null}
      {state.status === "error" ? (
        state.error.kind === "not_found" ? (
          <Notice tone="neutral" title={t("audit.timeline.notFoundTitle")}>
            {t("audit.timeline.notFoundBody")}
          </Notice>
        ) : (
          <ErrorState error={state.error} onRetry={() => void reload()} />
        )
      ) : null}
      {state.status === "ready" ? (
        <>
          {approvalRef && can("approvals.read") ? (
            <Notice tone="info" icon="approvals" action={<Link className="text-link" to={`/approvals/exchange/${encodeURIComponent(approvalRef)}`}>{t("audit.timeline.openApproval")} <Icon name="arrow-right" size={14} /></Link>}>
              {t("audit.timeline.approvalNote", { reference: approvalRef })}
            </Notice>
          ) : null}
          <Panel title={t("audit.timeline.events", { count: events.length })} icon="audit">
            <ol className="timeline">
              {events.map((event) => {
                const { label, known } = eventLabel(event.event, t, i18n);
                return (
                  <li key={event.id} className="timeline-item" data-audit={event.id}>
                    <span className="timeline-dot" aria-hidden="true" />
                    <div className="timeline-body">
                      <div className="timeline-head">
                        <span className={known ? "timeline-title" : "timeline-title mono"}>{label}</span>
                        <Timestamp value={event.created_at} />
                      </div>
                      <p className="timeline-meta">
                        {event.actor_id ? (isMe(event.actor_id) ? t("overview.activity.byYou") : t("overview.activity.by", { actor: event.actor_id })) : t("audit.system")}
                        {known ? <code className="mono"> · {event.event}</code> : null}
                      </p>
                      <Metadata metadata={event.metadata} />
                    </div>
                  </li>
                );
              })}
            </ol>
          </Panel>
          <p className="muted small">{t("audit.timeline.boundary")}</p>
        </>
      ) : null}
    </div>
  );
}
