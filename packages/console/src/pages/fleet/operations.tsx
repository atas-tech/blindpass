import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams, useSearchParams } from "react-router";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { GrantRevocationResult, Operation } from "../../api/types.js";
import { useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Dialog } from "../../ui/dialog.js";
import { ErrorState, Notice, Skeleton } from "../../ui/feedback.js";
import { SelectField } from "../../ui/field.js";
import { Icon } from "../../ui/icon.js";
import { Identifier, KeyValue, PageHeader, Panel, UntrustedText } from "../../ui/layout.js";
import { Countdown, Timestamp } from "../../ui/time.js";
import { Metadata } from "../audit/metadata.js";
import { FLEET_POLL, ListBody, NodeRef, OperationBadge, useNodeNames, usePagedList } from "./common.js";
import { RevocationOutcome } from "./grants.js";
import { ProvideSourcePanel } from "./provide-source.js";

const STATUSES = ["requested", "awaiting_approval", "granted", "executing", "completed", "failed", "uncertain", "denied", "revoked", "cancelled"] as const;
const CANCELLABLE = new Set<Operation["status"]>(["requested", "awaiting_approval", "granted", "executing"]);
// While a Source offer is awaited or live the page re-reads often, so the node's
// offer, the owner's link and the receipt show up within seconds.
const PROVISION_POLL = { visibleMs: 3_000, hiddenMs: 60_000 };
const PROVISION_LIVE = new Set(["awaiting_offer", "offer_ready", "link_issued"]);

export function OperationsPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const status = STATUSES.find((value) => value === params.get("status")) ?? null;
  const list = usePagedList(`operations:${status ?? ""}`, (cursor) => endpoints.operations.list({ limit: 50, ...(status ? { status } : {}), ...(cursor ? { cursor } : {}) }), { poll: FLEET_POLL });
  return (
    <div className="stack">
      <PageHeader eyebrow={t("fleet.eyebrow")} title={t("fleet.operation.title")} description={t("fleet.operation.description")} />
      <div className="toolbar">
        <SelectField
          label={t("fleet.fields.status")}
          value={status ?? ""}
          onChange={(event) => {
            setParams(event.currentTarget.value ? { status: event.currentTarget.value } : {}, { replace: true });
            list.reset();
          }}
        >
          <option value="">{t("fleet.operation.allStatuses")}</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {t(`fleet.operation.status.${value}`)}
            </option>
          ))}
        </SelectField>
      </div>
      <Panel flush>
        <ListBody state={list.state} items={list.items} onRetry={() => void list.reload()} emptyIcon="operations" emptyTitle={t("fleet.operation.empty")} emptyBody={t("fleet.operation.emptyBody")}>
          {(items) => (
            <table className="data-table is-responsive">
              <thead>
                <tr>
                  <th scope="col">{t("fleet.operation.fields.action")}</th>
                  <th scope="col">{t("fleet.fields.status")}</th>
                  <th scope="col">{t("fleet.fields.created")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("fleet.fields.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((operation) => (
                  <tr key={operation.id} data-operation={operation.id}>
                    <td className="cell-lead" data-label={t("fleet.operation.fields.action")}>
                      <span className="cell-primary">
                        <Link className="row-link mono" to={`/operations/${encodeURIComponent(operation.id)}`}>
                          {operation.action} · {t(`approvals.mode.${operation.mode}`)}
                        </Link>
                        <code className="cell-sub">{operation.workload_id}</code>
                      </span>
                    </td>
                    <td data-label={t("fleet.fields.status")}>
                      <OperationBadge status={operation.status} />
                    </td>
                    <td data-label={t("fleet.fields.created")}>
                      <Timestamp value={operation.created_at} relative />
                    </td>
                    <td className="cell-actions">
                      <Link className="text-link" to={`/operations/${encodeURIComponent(operation.id)}`} aria-label={t("fleet.operation.open", { id: operation.id })}>
                        {t("common.details")} <Icon name="arrow-right" size={14} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </ListBody>
        <div className="panel-pager">{list.pager}</div>
      </Panel>
    </div>
  );
}

function isRevocation(value: unknown): value is GrantRevocationResult {
  return typeof value === "object" && value !== null && "grant_id" in value && "consumer_lifetime_seconds" in value;
}

export function OperationDetailPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const operationId = decodeURIComponent(id);
  const { can } = useSession();
  const [provisioningLive, setProvisioningLive] = useState(false);
  const { state, reload, replace } = useResource(`operation:${operationId}`, () => endpoints.operations.get(operationId), { poll: provisioningLive ? PROVISION_POLL : FLEET_POLL });
  const lastProvisioning = (state.status === "ready" ? state.data : state.status === "error" ? state.previous : null)?.provisioning?.state;
  useEffect(() => setProvisioningLive(lastProvisioning !== undefined && PROVISION_LIVE.has(lastProvisioning)), [lastProvisioning]);
  const nodeName = useNodeNames();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revocation, setRevocation] = useState<GrantRevocationResult | null>(null);

  const crumb = (
    <nav className="breadcrumb" aria-label={t("audit.breadcrumb")}>
      <Link to="/operations">{t("nav.operations")}</Link>
      <Icon name="chevron-right" size={13} />
      <span aria-current="page">{operationId}</span>
    </nav>
  );
  if (state.status === "loading") return <div className="stack">{crumb}<Skeleton lines={6} /></div>;
  if (state.status === "error" && !state.previous) return <div className="stack">{crumb}<ErrorState error={state.error} onRetry={() => void reload()} /></div>;
  const operation = state.status === "ready" ? state.data : state.previous!;
  const canCancel = can("operations.cancel") && CANCELLABLE.has(operation.status);

  const cancel = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await endpoints.operations.cancel(operation.id);
      if (isRevocation(result)) {
        setRevocation(result);
        void reload();
      } else {
        replace(result as Operation);
        // The reply carries no Source state; read it again.
        void reload();
      }
      setConfirming(false);
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      if (apiError?.code === "operation_not_cancellable") setError(t("fleet.operation.errors.notCancellable"));
      else setError(apiError?.outcomeUnknown ? t("fleet.operation.errors.unknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" }));
      void reload();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      {crumb}
      <PageHeader
        eyebrow={t("fleet.operation.eyebrow")}
        title={`${operation.action} · ${t(`approvals.mode.${operation.mode}`)}`}
        meta={<OperationBadge status={operation.status} />}
        actions={
          canCancel ? (
            <Button variant="danger" icon="ban" onClick={() => setConfirming(true)}>
              {t(operation.status === "granted" || operation.status === "executing" ? "fleet.operation.cancel.revokeOpen" : "fleet.operation.cancel.open")}
            </Button>
          ) : null
        }
      />
      {revocation ? <RevocationOutcome result={revocation} /> : null}
      {operation.status === "uncertain" ? (
        <Notice tone="warn" title={t("fleet.operation.uncertainTitle")}>
          {t("fleet.operation.uncertainBody")}
        </Notice>
      ) : null}
      <ProvideSourcePanel operation={operation} onChanged={() => void reload()} />
      <div className="detail-grid">
        <Panel title={t("fleet.operation.scope")} icon="approvals">
          <KeyValue
            columns={1}
            items={[
              { label: t("fleet.operation.fields.id"), value: <Identifier value={operation.id} /> },
              { label: t("fleet.workload.fields.node"), value: <NodeRef id={operation.node_id} name={nodeName(operation.node_id)} /> },
              { label: t("fleet.operation.fields.workload"), value: <Link className="row-link mono" to={`/workloads/${encodeURIComponent(operation.workload_id)}`}>{operation.workload_id}</Link> },
              { label: t("fleet.operation.fields.resource"), value: <code className="mono">{operation.resource_id}</code> },
              { label: t("approvals.fields.policyVersion"), value: <span className="mono">v{operation.policy_version}</span> },
              { label: t("fleet.operation.fields.decision"), value: t(`fleet.policy.decision.${operation.decision}`) }
            ]}
          />
        </Panel>
        <Panel title={t("fleet.operation.lifecycle")} icon="clock">
          <KeyValue
            columns={1}
            items={[
              { label: t("fleet.fields.created"), value: <Timestamp value={operation.created_at} /> },
              { label: t("fleet.grant.fields.expires"), value: CANCELLABLE.has(operation.status) ? <Countdown expiresAt={operation.expires_at} /> : <Timestamp value={operation.expires_at} /> },
              { label: t("fleet.operation.fields.completed"), value: operation.completed_at ? <Timestamp value={operation.completed_at} /> : <span className="muted">—</span> },
              {
                label: t("fleet.operation.fields.approval"),
                value: operation.approval_id ? (
                  can("approvals.read") ? <Link className="row-link mono" to={`/approvals/operation/${encodeURIComponent(operation.approval_id)}`}>{operation.approval_id}</Link> : <code className="mono">{operation.approval_id}</code>
                ) : (
                  <span className="muted">—</span>
                )
              },
              { label: t("fleet.operation.fields.grant"), value: operation.grant_id ? <code className="mono">{operation.grant_id}</code> : <span className="muted">—</span> }
            ]}
          />
        </Panel>
      </div>
      <UntrustedText label={t("approvals.purpose.label")}>{operation.purpose}</UntrustedText>
      {operation.result ? (
        <Panel title={t("fleet.operation.result")} icon="terminal">
          <p className="section-body">{t("fleet.operation.resultNote")}</p>
          <Metadata metadata={operation.result} />
        </Panel>
      ) : null}
      <Dialog
        open={confirming}
        tone="danger"
        title={t(operation.status === "granted" || operation.status === "executing" ? "fleet.operation.cancel.revokeTitle" : "fleet.operation.cancel.title")}
        onClose={() => !busy && setConfirming(false)}
        dismissible={!busy}
        footer={
          <>
            <Button onClick={() => setConfirming(false)} disabled={busy} data-autofocus>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" icon="ban" busy={busy} onClick={() => void cancel()}>
              {t("fleet.operation.cancel.submit")}
            </Button>
          </>
        }
      >
        <dl className="confirm-scope">
          <div>
            <dt>{t("fleet.operation.fields.workload")}</dt>
            <dd className="mono">{operation.workload_id}</dd>
          </div>
          <div>
            <dt>{t("fleet.operation.fields.action")}</dt>
            <dd className="mono">
              {operation.action} · {operation.mode}
            </dd>
          </div>
        </dl>
        <p className="dialog-note">{t(operation.status === "granted" || operation.status === "executing" ? "fleet.operation.cancel.revokeBody" : "fleet.operation.cancel.body")}</p>
        {error ? <Notice tone="danger">{error}</Notice> : null}
      </Dialog>
    </div>
  );
}
