import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useOutletContext, useParams } from "react-router";
import type { ApiError } from "../../api/client.js";
import { isOperationApproval, type AnyApproval, type OperationApproval } from "../../api/types.js";
import { useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { APPROVAL_POLL } from "../../shell/approval-count.js";
import { Button, ButtonLink } from "../../ui/button.js";
import { Dialog } from "../../ui/dialog.js";
import { ErrorState, Notice, Skeleton, StatusBadge } from "../../ui/feedback.js";
import { Icon } from "../../ui/icon.js";
import { Identifier, KeyValue, UntrustedText, VerifiedBlock, type KeyValueItem } from "../../ui/layout.js";
import { Countdown, Timestamp } from "../../ui/time.js";
import { approvalPurpose, approvalRequester, decisionBlock, type ApprovalKind } from "./model.js";
import type { ApprovalSource } from "./source.js";
import { statusTone } from "./status.js";
import { useDecision, type DecisionState, type Verb } from "./use-decision.js";

interface DetailContext {
  source: ApprovalSource;
  onChanged: () => void;
}

function verifiedItems(approval: AnyApproval, t: (key: string, options?: Record<string, unknown>) => string): KeyValueItem[] {
  if (!isOperationApproval(approval)) {
    return [
      { label: t("approvals.fields.requester"), value: <code className="mono">{approval.requester_id}</code> },
      { label: t("approvals.fields.secret"), value: <code className="mono">{approval.secret_name}</code> },
      { label: t("approvals.fields.reference"), value: <Identifier value={approval.reference} /> },
      { label: t("approvals.fields.requested"), value: <Timestamp value={approval.created_at} /> }
    ];
  }
  const scope = approval.verified_identity;
  return [
    { label: t("approvals.fields.node"), value: <Identifier value={scope.node_id} /> },
    { label: t("approvals.fields.workload"), value: <Identifier value={scope.workload_id} /> },
    { label: t("approvals.fields.unit"), value: <code className="mono">{scope.unit}</code> },
    { label: t("approvals.fields.account"), value: <code className="mono">{scope.account}</code> },
    { label: t("approvals.fields.action"), value: <code className="mono">{scope.action}</code> },
    { label: t("approvals.fields.mode"), value: t(`approvals.mode.${scope.mode}`) },
    { label: t("approvals.fields.rule"), value: scope.rule_id ? <code className="mono">{scope.rule_id}</code> : <span className="muted">—</span> },
    { label: t("approvals.fields.policyVersion"), value: <span className="mono">v{scope.policy_version}</span> },
    { label: t("approvals.fields.requester"), value: <code className="mono">{approvalRequester(approval)}</code> },
    { label: t("approvals.fields.approvers"), value: <span className="chip-list">{approval.approver_ids.map((id) => <code key={id} className="chip mono">{id}</code>)}</span> },
    { label: t("approvals.fields.approval"), value: <Identifier value={approval.id} /> },
    { label: t("approvals.fields.requested"), value: <Timestamp value={approval.created_at} /> }
  ];
}

function Members({ approval }: { approval: OperationApproval }) {
  const { t } = useTranslation();
  if (!approval.operations?.length) return null;
  return (
    <section className="members" aria-labelledby="approval-members-title">
      <header className="members-header">
        <h3 id="approval-members-title" className="section-title">
          {t("approvals.members.title")} <span className="count-chip">{approval.operations.length}</span>
        </h3>
        <p className="section-body">{t("approvals.members.body")}</p>
      </header>
      <ol className="member-list">
        {approval.operations.map((operation) => (
          <li key={operation.id} className="member">
            <KeyValue
              columns={2}
              items={[
                { label: t("approvals.members.requestedBy"), value: <code className="mono">{operation.requested_by}</code> },
                { label: t("approvals.members.invocation"), value: <Identifier value={operation.invocation_id} /> },
                { label: t("approvals.members.resource"), value: <code className="mono">{operation.resource_id}</code> },
                { label: t("approvals.members.evidence"), value: operation.broker_event_key ? <Identifier value={operation.broker_event_key} /> : <span className="muted">{t("approvals.members.evidenceMissing")}</span> }
              ]}
            />
            <UntrustedText label={t("approvals.members.purpose")}>{operation.purpose}</UntrustedText>
          </li>
        ))}
      </ol>
    </section>
  );
}

function DecisionFeedback({ state, approval, onReconcile, onResend }: { state: DecisionState; approval: AnyApproval; onReconcile: () => void; onResend: () => void }) {
  const { t } = useTranslation();
  const operation = isOperationApproval(approval);
  switch (state.phase) {
    case "done":
      return state.verb === "approve" ? (
        <Notice tone="ok" title={t("approvals.outcome.approvedTitle")}>
          {t(operation ? "approvals.outcome.approvedOperation" : "approvals.outcome.approvedExchange")}
        </Notice>
      ) : (
        <Notice tone="neutral" title={t("approvals.outcome.rejectedTitle")}>
          {t("approvals.outcome.rejectedBody")}
        </Notice>
      );
    case "stale":
      return (
        <Notice tone="warn" title={t("approvals.errors.staleTitle")}>
          {t(state.beforeSend ? "approvals.errors.changedBeforeSend" : "approvals.errors.staleBody")}
        </Notice>
      );
    case "grant_blocked":
      return (
        <Notice tone="warn" title={t("approvals.errors.grantTitle")}>
          {t("approvals.errors.grantBody")}
        </Notice>
      );
    case "denied":
      return <DeniedNotice error={state.error} />;
    case "unknown":
    case "reconciling":
      return (
        <Notice
          tone="warn"
          title={t("approvals.errors.unknownTitle")}
          action={
            <Button size="sm" icon="refresh" onClick={onReconcile} busy={state.phase === "reconciling"}>
              {t("approvals.errors.checkStatus")}
            </Button>
          }
        >
          {t("approvals.errors.unknownBody")}
        </Notice>
      );
    case "still_pending":
      return (
        <Notice
          tone="warn"
          title={t("approvals.errors.stillPendingTitle")}
          action={
            <Button size="sm" variant={state.verb === "approve" ? "primary" : "danger"} onClick={onResend}>
              {t("approvals.errors.sendAgain")}
            </Button>
          }
        >
          {t("approvals.errors.stillPendingBody")}
        </Notice>
      );
    case "gone":
      return (
        <Notice tone="warn" title={t("approvals.errors.goneTitle")}>
          {t("approvals.errors.goneBody")}
        </Notice>
      );
    case "resolved":
      return (
        <Notice tone="info" title={t("approvals.errors.resolvedTitle")}>
          {t("approvals.errors.resolvedBody")}
        </Notice>
      );
    default:
      return null;
  }
}

function DeniedNotice({ error }: { error: ApiError }) {
  const { t } = useTranslation();
  if (error.code === "approval_scope_denied") {
    return (
      <Notice tone="danger" icon="lock" title={t("approvals.errors.scopeTitle")}>
        {t("approvals.errors.scopeBody")}
      </Notice>
    );
  }
  if (error.code === "self_approval_denied") {
    return (
      <Notice tone="danger" icon="lock" title={t("approvals.errors.selfTitle")}>
        {t("approvals.errors.selfBody")}
      </Notice>
    );
  }
  if (error.kind === "forbidden" || error.kind === "rate_limited" || error.kind === "unavailable") return <ErrorState error={error} compact />;
  return (
    <Notice tone="danger" title={t("approvals.errors.failedTitle")}>
      {t("approvals.errors.failedBody", { code: error.code ?? error.status })}
    </Notice>
  );
}

function ConfirmDecision({ verb, approval, busy, onCancel, onConfirm }: { verb: Verb | null; approval: AnyApproval; busy: DecisionState["phase"] | null; onCancel: () => void; onConfirm: () => void }) {
  const { t } = useTranslation();
  const operation = isOperationApproval(approval) ? approval : null;
  const scope = operation?.verified_identity;
  const title =
    verb === "reject" ? t("approvals.confirm.reject") : operation ? t("approvals.confirm.approveOperation", { count: operation.operation_ids.length }) : t("approvals.confirm.approveExchange");
  const recipient = scope ? t("approvals.confirm.operationRecipient", { node: scope.node_id }) : t("approvals.confirm.exchangeRecipient", { requester: approvalRequester(approval) });
  const scopeText = scope
    ? t("approvals.confirm.operationScope", { action: scope.action, unit: scope.unit, account: scope.account, mode: t(`approvals.mode.${scope.mode}`) })
    : t("approvals.confirm.exchangeScope", { secret: isOperationApproval(approval) ? "" : approval.secret_name });
  const working = busy === "checking" || busy === "sending";
  return (
    <Dialog
      open={verb !== null}
      title={title}
      onClose={onCancel}
      dismissible={!working}
      tone={verb === "reject" ? "danger" : "default"}
      footer={
        <>
          <Button onClick={onCancel} disabled={working} data-autofocus>
            {t("approvals.confirm.cancel")}
          </Button>
          <Button variant={verb === "reject" ? "danger" : "primary"} icon={verb === "reject" ? "cross" : "check"} busy={working} onClick={onConfirm}>
            {working ? t(busy === "checking" ? "approvals.confirm.checking" : "approvals.confirm.sending") : t(verb === "reject" ? "approvals.actions.reject" : "approvals.actions.approve")}
          </Button>
        </>
      }
    >
      <dl className="confirm-scope">
        <div>
          <dt>{t("approvals.confirm.recipient")}</dt>
          <dd className="mono">{recipient}</dd>
        </div>
        <div>
          <dt>{t("approvals.confirm.scope")}</dt>
          <dd className="mono">{scopeText}</dd>
        </div>
      </dl>
      <p className="dialog-note">{t(verb === "reject" ? "approvals.confirm.rejectBody" : "approvals.confirm.approveBody")}</p>
    </Dialog>
  );
}

export default function ApprovalDetail() {
  const { t } = useTranslation();
  const { kind, id } = useParams();
  const { source, onChanged } = useOutletContext<DetailContext>();
  const { session, can } = useSession();
  const approvalKind = (kind === "operation" ? "operation" : "exchange") as ApprovalKind;
  const approvalId = id ? decodeURIComponent(id) : "";
  const { state, reload, replace } = useResource(`approval:${approvalKind}:${approvalId}`, () => source.get(approvalKind, approvalId), { poll: APPROVAL_POLL });
  const onApproval = useCallback(
    (fresh: AnyApproval) => {
      replace(fresh);
      onChanged();
    },
    [replace, onChanged]
  );
  const decision = useDecision(source, onApproval);
  const [confirming, setConfirming] = useState<{ verb: Verb; snapshot: AnyApproval } | null>(null);

  const back = (
    <Link to="/approvals" className="back-link">
      <Icon name="chevron-left" size={15} />
      {t("approvals.detail.back")}
    </Link>
  );

  if (state.status === "loading") {
    return (
      <article className="panel approval-detail" aria-busy="true">
        {back}
        <Skeleton lines={6} />
      </article>
    );
  }
  if (state.status === "error" && !state.previous) {
    return (
      <article className="panel approval-detail">
        {back}
        {state.error.kind === "not_found" ? (
          <Notice tone="neutral" title={t("approvals.detail.notFoundTitle")}>
            {t("approvals.detail.notFoundBody")}
          </Notice>
        ) : (
          <ErrorState error={state.error} onRetry={() => void reload()} />
        )}
      </article>
    );
  }
  const approval = state.status === "ready" ? state.data : state.previous!;
  const gone = state.status === "error" && state.error.kind === "not_found";
  const operation = isOperationApproval(approval) ? approval : null;
  const canDecide = can("approvals.decide");
  const block = canDecide ? decisionBlock(approval, session) : null;
  const phase = decision.state.phase;
  const inFlight = phase === "checking" || phase === "sending" || phase === "reconciling";
  const awaitingReconcile = phase === "unknown" || phase === "still_pending" || phase === "reconciling";
  const activeVerb = phase !== "idle" ? decision.state.verb : null;
  const decidable = canDecide && !gone && !block && approval.status === "pending" && !inFlight && !awaitingReconcile;
  const title = operation
    ? t("approvals.detail.operationTitle", { action: operation.verified_identity.action, unit: operation.verified_identity.unit })
    : t("approvals.detail.exchangeTitle", { requester: approvalRequester(approval), secret: isOperationApproval(approval) ? "" : approval.secret_name });

  const openConfirm = (verb: Verb) => {
    decision.reset();
    setConfirming({ verb, snapshot: approval });
  };
  const onConfirm = async () => {
    if (!confirming) return;
    await decision.decide(confirming.verb, confirming.snapshot);
    setConfirming(null);
  };

  return (
    <article className="panel approval-detail" aria-labelledby="approval-title" data-approval-status={approval.status}>
      {back}
      <header className="approval-detail-top">
        <span className="eyebrow">
          <Icon name={operation ? "operations" : "key"} size={13} /> {t(`approvals.kind.${approval.kind}`)}
        </span>
        <span className="approval-detail-status">
          {operation && approval.status === "pending" ? (
            <span className="deadline">
              <span className="deadline-label">{t("approvals.detail.windowCloses")}</span>
              <Countdown expiresAt={operation.expires_at} />
            </span>
          ) : null}
          <StatusBadge tone={statusTone(approval.status)}>{t(`approvals.status.${approval.status}`)}</StatusBadge>
        </span>
      </header>
      <h2 id="approval-title" className="approval-title">
        {title}
      </h2>
      <p className="approval-subtitle">
        {t("approvals.detail.requested")} <Timestamp value={approval.created_at} relative />
        {state.status === "error" ? <span className="stale-tag">· {t("common.refreshing")}</span> : null}
      </p>

      {gone && phase !== "gone" ? (
        <Notice tone="warn" title={t("approvals.errors.goneTitle")}>
          {t("approvals.errors.goneBody")}
        </Notice>
      ) : state.status === "error" && !gone ? (
        <ErrorState error={state.error} onRetry={() => void reload()} compact />
      ) : null}

      <VerifiedBlock title={t("approvals.verified.title")} note={t(operation ? "approvals.verified.operationNote" : "approvals.verified.exchangeNote")}>
        <KeyValue items={verifiedItems(approval, t)} />
      </VerifiedBlock>

      <UntrustedText label={t("approvals.purpose.label")}>{approvalPurpose(approval)}</UntrustedText>

      {operation ? <Members approval={operation} /> : null}

      {approval.status !== "pending" && operation?.decided_by ? (
        <KeyValue
          items={[
            { label: t("approvals.fields.decidedBy"), value: <code className="mono">{operation.decided_by}</code> },
            { label: t("approvals.fields.decidedAt"), value: <Timestamp value={operation.decided_at} /> }
          ]}
        />
      ) : null}

      <Notice tone="neutral" icon="info">
        {t(operation ? "approvals.boundary.operation" : "approvals.boundary.exchange")}
      </Notice>

      <div aria-live="polite" className="decision-feedback">
        <DecisionFeedback state={decision.state} approval={approval} onReconcile={() => void decision.reconcile()} onResend={() => void decision.resend()} />
      </div>

      {canDecide && approval.status === "pending" && !gone ? (
        <footer className="decision-bar">
          <div className="decision-actions">
            <Button variant="primary" icon="check" onClick={() => openConfirm("approve")} disabled={!decidable} busy={inFlight && !confirming && activeVerb === "approve"}>
              {t("approvals.actions.approve")}
            </Button>
            <Button variant="secondary" icon="cross" onClick={() => openConfirm("reject")} disabled={!decidable} busy={inFlight && !confirming && activeVerb === "reject"}>
              {t("approvals.actions.reject")}
            </Button>
          </div>
          {block ? <p className="decision-block">{t(`approvals.blocked.${block.reason}`)}</p> : null}
        </footer>
      ) : null}
      {!canDecide ? <p className="decision-block">{t("approvals.blocked.viewer")}</p> : null}
      {operation && approval.status === "approved" && operation.operation_ids[0] ? (
        <div>
          <ButtonLink to={`/operations/${encodeURIComponent(operation.operation_ids[0])}`} size="sm" iconEnd="arrow-right">
            {t("approvals.outcome.viewOperation")}
          </ButtonLink>
        </div>
      ) : null}

      <ConfirmDecision verb={confirming?.verb ?? null} approval={confirming?.snapshot ?? approval} busy={confirming ? phase : null} onCancel={() => !inFlight && setConfirming(null)} onConfirm={() => void onConfirm()} />
    </article>
  );
}
