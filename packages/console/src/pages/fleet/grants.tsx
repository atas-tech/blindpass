import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { Grant, GrantRevocationResult } from "../../api/types.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Dialog } from "../../ui/dialog.js";
import { Notice, type Tone } from "../../ui/feedback.js";
import { SelectField } from "../../ui/field.js";
import { PageHeader, Panel } from "../../ui/layout.js";
import { Countdown, Timestamp } from "../../ui/time.js";
import { FLEET_POLL, GrantBadge, ListBody, NodeRef, useNodeNames, usePagedList } from "./common.js";

const STATUSES = ["issued", "delivered", "consumed", "revoked", "expired"] as const;
const RESULT_TONE: Record<GrantRevocationResult["status"], Tone> = { grant_revoked: "ok", not_revocable_offline: "warn", grant_revoked_after_consumption: "warn" };

/** What a revocation achieved, and who may still hold plaintext. */
export function RevocationOutcome({ result, grant }: { result: GrantRevocationResult; grant?: Grant | null }) {
  const { t } = useTranslation();
  return (
    <Notice tone={RESULT_TONE[result.status]} title={t(`fleet.grant.result.${result.status}.title`)}>
      {t(`fleet.grant.result.${result.status}.body`, { seconds: result.consumer_lifetime_seconds ?? "—", unit: grant?.unit ?? "", account: grant?.account ?? "" })}
    </Notice>
  );
}

export function RevokeGrantDialog({ grant, onClose, onDone }: { grant: Grant | null; onClose: () => void; onDone: (result: GrantRevocationResult) => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    if (!grant) return;
    setBusy(true);
    setError(null);
    try {
      onDone(await endpoints.grants.revoke(grant.id));
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      if (apiError?.code === "grant_not_revocable") setError(t("fleet.grant.errors.notRevocable"));
      else setError(apiError?.outcomeUnknown ? t("fleet.grant.errors.unknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={grant !== null}
      tone="danger"
      title={t("fleet.grant.revoke.title")}
      onClose={() => !busy && (setError(null), onClose())}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={onClose} disabled={busy} data-autofocus>
            {t("common.cancel")}
          </Button>
          <Button variant="danger" icon="ban" busy={busy} onClick={() => void run()}>
            {t("fleet.grant.revoke.submit")}
          </Button>
        </>
      }
    >
      {grant ? (
        <dl className="confirm-scope">
          <div>
            <dt>{t("approvals.confirm.recipient")}</dt>
            <dd className="mono">{t("approvals.confirm.operationRecipient", { node: grant.node_id })}</dd>
          </div>
          <div>
            <dt>{t("approvals.confirm.scope")}</dt>
            <dd className="mono">{t("approvals.confirm.operationScope", { action: grant.action, unit: grant.unit, account: grant.account, mode: t(`approvals.mode.${grant.mode}`) })}</dd>
          </div>
        </dl>
      ) : null}
      <p className="dialog-note">{t("fleet.grant.revoke.body")}</p>
      {error ? <Notice tone="danger">{error}</Notice> : null}
    </Dialog>
  );
}

export default function GrantsPage() {
  const { t } = useTranslation();
  const { can } = useSession();
  const [params, setParams] = useSearchParams();
  const status = STATUSES.find((value) => value === params.get("status")) ?? null;
  const node = params.get("node") ?? "";
  const nodeName = useNodeNames();
  const list = usePagedList(`grants:${status ?? ""}:${node}`, (cursor) => endpoints.grants.list({ limit: 50, ...(status ? { status } : {}), ...(node ? { node_id: node } : {}), ...(cursor ? { cursor } : {}) }), { poll: FLEET_POLL });
  const [revoking, setRevoking] = useState<Grant | null>(null);
  const [outcome, setOutcome] = useState<{ result: GrantRevocationResult; grant: Grant } | null>(null);
  const canRevoke = can("grants.revoke");

  const setFilter = (key: "status" | "node", value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
    list.reset();
  };

  return (
    <div className="stack">
      <PageHeader eyebrow={t("fleet.eyebrow")} title={t("fleet.grant.title")} description={t("fleet.grant.description")} />
      <div className="toolbar">
        <SelectField label={t("fleet.fields.status")} value={status ?? ""} onChange={(event) => setFilter("status", event.currentTarget.value)}>
          <option value="">{t("fleet.grant.allStatuses")}</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {t(`fleet.grant.status.${value}`)}
            </option>
          ))}
        </SelectField>
        {node ? (
          <div className="filter-chip">
            <span>{t("fleet.workload.filteredByNode")}</span>
            <code className="mono">{node}</code>
            <Button size="sm" variant="quiet" icon="close" aria-label={t("fleet.clearFilter")} onClick={() => setFilter("node", "")} />
          </div>
        ) : null}
      </div>
      {outcome ? <RevocationOutcome result={outcome.result} grant={outcome.grant} /> : null}
      <Panel flush>
        <ListBody state={list.state} items={list.items} onRetry={() => void list.reload()} emptyIcon="grants" emptyTitle={t("fleet.grant.empty")}>
          {(items) => (
            <table className="data-table is-responsive">
              <thead>
                <tr>
                  <th scope="col">{t("fleet.grant.fields.recipient")}</th>
                  <th scope="col">{t("fleet.fields.status")}</th>
                  <th scope="col">{t("fleet.grant.fields.issued")}</th>
                  <th scope="col">{t("fleet.grant.fields.expires")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("fleet.fields.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((grant) => (
                  <tr key={grant.id} data-grant={grant.id}>
                    <td className="cell-lead" data-label={t("fleet.grant.fields.recipient")}>
                      <span className="cell-primary">
                        <span className="cell-title mono">
                          {grant.unit} · {grant.account}
                        </span>
                        <NodeRef className="cell-sub" id={grant.node_id} name={nodeName(grant.node_id)} />
                        <Link className="cell-sub" to={`/operations/${encodeURIComponent(grant.operation_id)}`}>
                          {grant.operation_id}
                        </Link>
                      </span>
                    </td>
                    <td data-label={t("fleet.fields.status")}>
                      <GrantBadge status={grant.status} />
                      {grant.broker_revocation_outcome ? <span className="cell-sub">{grant.broker_revocation_outcome}</span> : null}
                    </td>
                    <td data-label={t("fleet.grant.fields.issued")}>
                      <Timestamp value={grant.issued_at} relative />
                    </td>
                    <td data-label={t("fleet.grant.fields.expires")}>{grant.status === "issued" || grant.status === "delivered" ? <Countdown expiresAt={grant.expires_at} /> : <Timestamp value={grant.expires_at} />}</td>
                    <td className="cell-actions">
                      {canRevoke && (grant.status === "issued" || grant.status === "delivered" || grant.status === "consumed") ? (
                        <Button size="sm" variant="ghost" icon="ban" onClick={() => setRevoking(grant)} aria-label={t("fleet.grant.revoke.label", { unit: grant.unit })}>
                          {t("fleet.grant.revoke.short")}
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </ListBody>
        <div className="panel-pager">{list.pager}</div>
      </Panel>
      <Notice tone="neutral" icon="info">
        {t("fleet.grant.boundary")}
      </Notice>
      <RevokeGrantDialog
        grant={revoking}
        onClose={() => setRevoking(null)}
        onDone={(result) => {
          if (revoking) setOutcome({ result, grant: revoking });
          setRevoking(null);
          void list.reload();
        }}
      />
    </div>
  );
}
