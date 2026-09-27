import { useMemo, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import * as endpoints from "../../api/endpoints.js";
import type { AuditEvent } from "../../api/types.js";
import { eventLabel } from "../../lib/events.js";
import { useIsMe } from "../../lib/actor.js";
import { useResource } from "../../lib/use-resource.js";
import { Button } from "../../ui/button.js";
import { EmptyState, ErrorState, Skeleton } from "../../ui/feedback.js";
import { SelectField, TextField } from "../../ui/field.js";
import { Icon } from "../../ui/icon.js";
import { PageHeader, Pager, Panel } from "../../ui/layout.js";
import { Timestamp } from "../../ui/time.js";
import { categoryOf, exchangeIdOf, EVENT_CATEGORIES, type EventCategory } from "./model.js";
import { Metadata } from "./metadata.js";

const PAGE_SIZE = 50;

function AuditRow({ event }: { event: AuditEvent }) {
  const isMe = useIsMe();
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const { label, known } = eventLabel(event.event, t, i18n);
  const exchangeId = exchangeIdOf(event);
  const hasMetadata = Object.keys(event.metadata).length > 0;
  const detailsId = `audit-meta-${event.id}`;
  return (
    <>
      <tr data-audit={event.id}>
        <td data-label={t("audit.columns.time")} className="cell-time">
          <Timestamp value={event.created_at} />
        </td>
        <td data-label={t("audit.columns.event")} className="cell-lead">
          <span className="cell-primary">
            <span className={known ? "cell-title" : "cell-title mono"}>{label}</span>
            {known ? <code className="cell-sub">{event.event}</code> : null}
          </span>
        </td>
        <td data-label={t("audit.columns.actor")}>{event.actor_id ? isMe(event.actor_id) ? <span title={event.actor_id}>{t("audit.you")}</span> : <code className="mono">{event.actor_id}</code> : <span className="muted">{t("audit.system")}</span>}</td>
        <td data-label={t("audit.columns.resource")} className="cell-text">
          {exchangeId ? (
            <Link to={`/audit/exchange/${encodeURIComponent(exchangeId)}`} className="row-link mono" title={event.resource_id ?? exchangeId}>
              <span className="truncate">{event.resource_id}</span>
              <Icon name="arrow-right" size={13} />
            </Link>
          ) : event.resource_id ? (
            <code className="mono truncate" title={event.resource_id}>
              {event.resource_id}
            </code>
          ) : (
            <span className="muted">—</span>
          )}
        </td>
        <td className="cell-actions">
          {hasMetadata ? (
            <Button size="sm" variant="quiet" icon={open ? "chevron-up" : "chevron-down"} aria-expanded={open} aria-controls={detailsId} onClick={() => setOpen((value) => !value)}>
              {t("audit.details")}
            </Button>
          ) : null}
        </td>
      </tr>
      {open ? (
        <tr className="detail-row" id={detailsId}>
          <td colSpan={5}>
            <Metadata metadata={event.metadata} />
          </td>
        </tr>
      ) : null}
    </>
  );
}

export default function AuditPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [cursors, setCursors] = useState<Array<string | null>>([null]);
  const cursor = cursors[cursors.length - 1] ?? null;
  const [category, setCategory] = useState<EventCategory>("all");
  const [query, setQuery] = useState("");
  const [lookup, setLookup] = useState("");
  const { state, reload } = useResource(`audit:${cursor ?? ""}`, () => endpoints.audit.list({ limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) }));

  const items = state.status === "ready" ? state.data.items : state.status === "error" ? state.previous?.items ?? null : null;
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (items ?? []).filter((event) => {
      if (category !== "all" && categoryOf(event.event) !== category) return false;
      if (!needle) return true;
      return [event.event, event.actor_id, event.resource_id].some((value) => value?.toLowerCase().includes(needle));
    });
  }, [items, category, query]);
  const filtering = category !== "all" || query.trim() !== "";

  const openTimeline = (event: FormEvent) => {
    event.preventDefault();
    const id = lookup.trim();
    if (id) navigate(`/audit/exchange/${encodeURIComponent(id)}`);
  };

  return (
    <div className="stack">
      <PageHeader
        eyebrow={t("audit.eyebrow")}
        title={t("audit.title")}
        description={t("audit.description")}
        actions={
          <Button icon="refresh" onClick={() => (cursors.length > 1 ? setCursors([null]) : void reload())} busy={state.status === "ready" && state.refreshing}>
            {t("audit.refresh")}
          </Button>
        }
      />
      <div className="audit-tools">
        <div className="audit-filters" role="search" aria-label={t("audit.filterLabel")}>
          <SelectField label={t("audit.category")} value={category} onChange={(event) => setCategory(event.currentTarget.value as EventCategory)}>
            {EVENT_CATEGORIES.map((value) => (
              <option key={value} value={value}>
                {t(`audit.categories.${value}`)}
              </option>
            ))}
          </SelectField>
          <TextField label={t("audit.search")} hint={t("audit.searchHint")} value={query} onChange={(event) => setQuery(event.currentTarget.value)} type="search" autoComplete="off" />
        </div>
        <form className="audit-lookup" onSubmit={openTimeline}>
          <TextField label={t("audit.lookup")} hint={t("audit.lookupHint")} value={lookup} onChange={(event) => setLookup(event.currentTarget.value)} mono autoComplete="off" spellCheck={false} />
          <Button type="submit" iconEnd="arrow-right" disabled={!lookup.trim()}>
            {t("audit.lookupSubmit")}
          </Button>
        </form>
      </div>
      <Panel flush meta={items ? t(filtering ? "audit.shownFiltered" : "audit.shown", { shown: filtered.length, total: items.length }) : null} title={t("audit.pageTitle", { page: cursors.length })}>
        {state.status === "loading" ? <Skeleton lines={6} className="panel-pad" /> : null}
        {state.status === "error" ? (
          <div className="panel-pad">
            <ErrorState error={state.error} onRetry={() => void reload()} />
          </div>
        ) : null}
        {items && items.length === 0 && state.status === "ready" ? (
          <EmptyState icon="audit" title={t("overview.activity.emptyTitle")}>
            {t("overview.activity.emptyBody")}
          </EmptyState>
        ) : null}
        {items && items.length > 0 && filtered.length === 0 ? (
          <EmptyState icon="info" title={t("audit.noMatch")}>
            {t("audit.noMatchBody")}
          </EmptyState>
        ) : null}
        {filtered.length > 0 ? (
          <table className="data-table is-responsive audit-table">
            <thead>
              <tr>
                <th scope="col">{t("audit.columns.time")}</th>
                <th scope="col">{t("audit.columns.event")}</th>
                <th scope="col">{t("audit.columns.actor")}</th>
                <th scope="col">{t("audit.columns.resource")}</th>
                <th scope="col">
                  <span className="sr-only">{t("audit.details")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((event) => (
                <AuditRow key={event.id} event={event} />
              ))}
            </tbody>
          </table>
        ) : null}
        <div className="panel-pager">
          <Pager
            hasPrevious={cursors.length > 1}
            hasNext={state.status === "ready" && Boolean(state.data.next_cursor)}
            onPrevious={() => setCursors((list) => list.slice(0, -1))}
            onNext={() => state.status === "ready" && state.data.next_cursor && setCursors((list) => [...list, state.data.next_cursor])}
            busy={state.status === "loading"}
          />
        </div>
      </Panel>
    </div>
  );
}
