import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import { ApiError, newIdempotencyKey } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { Fulfillment, FulfillmentStatus, Workload } from "../../api/types.js";
import { collectAll, useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Dialog } from "../../ui/dialog.js";
import { ErrorState, Notice, Skeleton } from "../../ui/feedback.js";
import { Checkbox, SelectField, TextAreaField, TextField } from "../../ui/field.js";
import { KeyValue, PageHeader, Panel, UntrustedText, VerifiedBlock } from "../../ui/layout.js";
import { Countdown, Timestamp } from "../../ui/time.js";
import { useToast } from "../../ui/toast.js";
import { Fingerprint, FLEET_POLL, FulfillmentBadge, ListBody, usePagedList } from "./common.js";

const STATUSES: readonly FulfillmentStatus[] = ["awaiting_approval", "approved", "offered", "available", "recipient_consumed", "completed", "denied", "revoked", "expired", "failed", "uncertain"];
/** Not yet closed: the recipient's one slot is held and revoke still has something to stop. */
const REVOCABLE = new Set<FulfillmentStatus>(["awaiting_approval", "approved", "offered", "available", "recipient_consumed", "uncertain"]);
const COUNTS_DOWN = new Set<FulfillmentStatus>(["awaiting_approval", "approved", "offered", "available"]);
// Same rule the controller applies: letters, digits, _ - and ., not starting with a dot.
const CREDENTIAL = /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const MAX_PURPOSE = 512;

interface Lookups {
  /** Both lists have answered (or failed); names are best effort after that. */
  settled: boolean;
  failed: boolean;
  workloads: readonly Workload[];
  workloadName: (id: string) => string;
  nodeName: (id: string) => string;
}

/**
 * Workload and node names by ID. The list waits for these so each row and
 * each button label shows a name from the first paint; if a lookup fails the
 * IDs are shown instead, and the ID stays what every request is bound to.
 */
function useLookups(): Lookups {
  const workloads = useResource("fulfillment-workloads", () => collectAll((cursor) => endpoints.workloads.list({ limit: 100, ...(cursor ? { cursor } : {}) })));
  const nodes = useResource("fulfillment-nodes", () => collectAll((cursor) => endpoints.nodes.list({ limit: 100, ...(cursor ? { cursor } : {}) })));
  return useMemo(() => {
    const workloadList = workloads.state.status === "ready" ? workloads.state.data : [];
    const workloadNames = new Map(workloadList.map((item) => [item.id, item.name] as const));
    const nodeNames = new Map((nodes.state.status === "ready" ? nodes.state.data : []).map((item) => [item.id, item.name] as const));
    return {
      settled: workloads.state.status !== "loading" && nodes.state.status !== "loading",
      failed: workloads.state.status === "error" || nodes.state.status === "error",
      workloads: workloadList,
      workloadName: (id) => workloadNames.get(id) ?? id,
      nodeName: (id) => nodeNames.get(id) ?? id
    };
  }, [workloads.state, nodes.state]);
}

function ProviderNote({ value }: { value: Fulfillment["provider_revocation"] }) {
  const { t } = useTranslation();
  return <>{t(`fleet.fulfillment.provider.${value}`)}</>;
}

function createError(failure: unknown, t: (key: string, options?: Record<string, unknown>) => string): string {
  const apiError = failure instanceof ApiError ? failure : null;
  switch (apiError?.code) {
    case "cross_workload_denied":
      return t("fleet.fulfillment.errors.denied");
    case "recipient_busy":
      return t("fleet.fulfillment.errors.busy");
    case "party_unavailable":
      return t("fleet.fulfillment.errors.unavailable");
    case "fulfillments_disabled":
      return t("fleet.fulfillment.errors.disabled");
    case "same_party":
      return t("fleet.fulfillment.errors.sameParty");
    case "idempotency_conflict":
      return t("fleet.fulfillment.errors.idempotency");
    case "workload_not_found":
      return t("fleet.fulfillment.errors.workloadGone");
    case "prior_invalid":
      return t("fleet.fulfillment.errors.prior");
    case "invalid_fulfillment":
      return t("fleet.fulfillment.errors.invalid");
    default:
      return apiError?.outcomeUnknown ? t("fleet.fulfillment.errors.createUnknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" });
  }
}

function RequestDialog({ open, lookups, onClose, onCreated }: { open: boolean; lookups: Lookups; onClose: () => void; onCreated: () => void }) {
  const { t } = useTranslation();
  const [issuer, setIssuer] = useState("");
  const [recipient, setRecipient] = useState("");
  const [issuerCredential, setIssuerCredential] = useState("");
  const [recipientCredential, setRecipientCredential] = useState("");
  const [purpose, setPurpose] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A retry of the same request keeps its key so a lost reply can't create a second one.
  const attempt = useRef<{ signature: string; key: string } | null>(null);
  const active = useMemo(() => lookups.workloads.filter((item) => item.status === "active"), [lookups.workloads]);

  const reset = () => {
    setIssuer("");
    setRecipient("");
    setIssuerCredential("");
    setRecipientCredential("");
    setPurpose("");
    setSubmitted(false);
    setError(null);
    attempt.current = null;
  };
  const close = () => {
    if (busy) return;
    reset();
    onClose();
  };

  const issuerWorkload = active.find((item) => item.id === issuer);
  const recipientWorkload = active.find((item) => item.id === recipient);
  const errors: { issuer?: string; recipient?: string; issuerCredential?: string; recipientCredential?: string; purpose?: string } = {};
  if (!issuer) errors.issuer = t("fleet.fulfillment.errors.workload");
  if (!recipient) errors.recipient = t("fleet.fulfillment.errors.workload");
  else if (recipient === issuer) errors.recipient = t("fleet.fulfillment.errors.sameWorkload");
  else if (issuerWorkload && recipientWorkload && issuerWorkload.node_id === recipientWorkload.node_id) errors.recipient = t("fleet.fulfillment.errors.sameNode");
  if (!CREDENTIAL.test(issuerCredential)) errors.issuerCredential = t("fleet.fulfillment.errors.credential");
  if (!CREDENTIAL.test(recipientCredential)) errors.recipientCredential = t("fleet.fulfillment.errors.credential");
  if (!purpose.trim() || [...purpose].length > MAX_PURPOSE || CONTROL.test(purpose)) errors.purpose = t("fleet.fulfillment.errors.purpose");
  const shown = submitted ? errors : {};

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitted(true);
    if (Object.keys(errors).length > 0) return;
    const body = { issuer_workload_id: issuer, recipient_workload_id: recipient, issuer_credential: issuerCredential, recipient_credential: recipientCredential, purpose: purpose.trim() };
    const signature = JSON.stringify(body);
    const key = attempt.current?.signature === signature ? attempt.current.key : newIdempotencyKey();
    attempt.current = { signature, key };
    setBusy(true);
    setError(null);
    try {
      await endpoints.fulfillments.create(body, key);
      reset();
      onCreated();
    } catch (failure) {
      setError(createError(failure, t));
    } finally {
      setBusy(false);
    }
  };

  const options = (
    <>
      <option value="">{t("fleet.fulfillment.create.select")}</option>
      {active.map((item) => (
        <option key={item.id} value={item.id}>
          {`${item.name} · ${item.unit} (${lookups.nodeName(item.node_id)})`}
        </option>
      ))}
    </>
  );

  return (
    <Dialog
      open={open}
      size="lg"
      title={t("fleet.fulfillment.create.title")}
      description={t("fleet.fulfillment.create.body")}
      onClose={close}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={close} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" form="request-fulfillment" variant="primary" icon="link" busy={busy}>
            {t("fleet.fulfillment.create.submit")}
          </Button>
        </>
      }
    >
      <form id="request-fulfillment" className="form-grid form-grid-2" onSubmit={(event) => void submit(event)} noValidate>
        <SelectField label={t("fleet.fulfillment.fields.issuerWorkload")} value={issuer} onChange={(event) => setIssuer(event.currentTarget.value)} error={shown.issuer}>
          {options}
        </SelectField>
        <SelectField label={t("fleet.fulfillment.fields.recipientWorkload")} value={recipient} onChange={(event) => setRecipient(event.currentTarget.value)} error={shown.recipient}>
          {options}
        </SelectField>
        <TextField label={t("fleet.fulfillment.fields.issuerCredential")} hint={t("fleet.fulfillment.fields.issuerCredentialHint")} value={issuerCredential} onChange={(event) => setIssuerCredential(event.currentTarget.value)} error={shown.issuerCredential} mono autoComplete="off" spellCheck={false} />
        <TextField label={t("fleet.fulfillment.fields.recipientCredential")} hint={t("fleet.fulfillment.fields.recipientCredentialHint")} value={recipientCredential} onChange={(event) => setRecipientCredential(event.currentTarget.value)} error={shown.recipientCredential} mono autoComplete="off" spellCheck={false} />
        <div className="field-wide">
          <TextAreaField label={t("fleet.fulfillment.fields.purpose")} hint={t("fleet.fulfillment.fields.purposeHint")} value={purpose} onChange={(event) => setPurpose(event.currentTarget.value)} error={shown.purpose} rows={3} autoComplete="off" />
        </div>
        {error ? <Notice tone="danger">{error}</Notice> : null}
      </form>
    </Dialog>
  );
}

function decideError(failure: unknown, t: (key: string, options?: Record<string, unknown>) => string): string {
  const apiError = failure instanceof ApiError ? failure : null;
  switch (apiError?.code) {
    case "authorization_changed":
      return t("fleet.fulfillment.errors.changed");
    case "self_approval_denied":
      return t("fleet.fulfillment.errors.self");
    case "approval_scope_denied":
      return t("fleet.fulfillment.errors.scope");
    case "approval_conflict":
      return t("fleet.fulfillment.errors.conflict");
    case "if_match_required":
      return t("fleet.fulfillment.errors.stale");
    case "fingerprints_required":
      return t("fleet.fulfillment.errors.fingerprints");
    default:
      return apiError?.outcomeUnknown ? t("fleet.fulfillment.errors.decideUnknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" });
  }
}

function PartyFacts({ role, party, lookups }: { role: "issuer" | "recipient"; party: Fulfillment["issuer"]; lookups: Lookups }) {
  const { t } = useTranslation();
  return (
    <div className="fulfillment-party">
      <h3 className="section-title">{t(`fleet.fulfillment.review.${role}`)}</h3>
      <KeyValue
        columns={2}
        items={[
          {
            label: t("fleet.fulfillment.fields.workload"),
            value: (
              <>
                {lookups.workloadName(party.workload_id)} <code className="mono">{party.workload_id}</code>
              </>
            )
          },
          {
            label: t("fleet.fulfillment.fields.node"),
            value: (
              <>
                {lookups.nodeName(party.node_id)} <code className="mono">{party.node_id}</code>
              </>
            )
          },
          { label: t("fleet.fulfillment.fields.unit"), value: party.unit ? <code className="mono">{party.unit}</code> : <span className="muted">—</span> },
          { label: t("fleet.fulfillment.fields.credential"), value: <code className="mono">{party.credential}</code> },
          { label: t("fleet.fulfillment.fields.fingerprint"), value: <Fingerprint value={party.fingerprint} />, wide: true }
        ]}
      />
    </div>
  );
}

interface ReviewProps {
  lookups: Lookups;
  onClose: () => void;
  onDecided: (verb: "approve" | "reject") => void;
  onStale: () => void;
}

/** A fresh instance per fulfillment, so one review never shows another's keys. */
function ReviewDialog({ item, ...rest }: ReviewProps & { item: Fulfillment | null }) {
  if (!item) return <Dialog open={false} title="" onClose={rest.onClose} />;
  return <ReviewContent key={item.id} item={item} {...rest} />;
}

function ReviewContent({ item, lookups, onClose, onDecided, onStale }: ReviewProps & { item: Fulfillment }) {
  const { t } = useTranslation();
  const { session } = useSession();
  // Read the fulfillment fresh: the fingerprints shown, and sent back, are the keys enrolled right now.
  const detail = useResource(`fulfillment:${item.id}`, () => endpoints.fulfillments.get(item.id));
  const [confirmed, setConfirmed] = useState(false);
  const [confirmReject, setConfirmReject] = useState(false);
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const data = detail.state.status === "ready" ? detail.state.data : detail.state.status === "error" ? detail.state.previous : null;
  const bound = data ? `${data.version}:${data.issuer.fingerprint ?? ""}:${data.recipient.fingerprint ?? ""}` : "";

  // A different version or key is a different thing to approve: ask again.
  useEffect(() => {
    setConfirmed(false);
    setConfirmReject(false);
  }, [bound]);

  const pending = data?.status === "awaiting_approval";
  const own = Boolean(data && session && data.requested_by === session.operator.id);
  const issuerFingerprint = data?.issuer.fingerprint;
  const recipientFingerprint = data?.recipient.fingerprint;
  const hasKeys = Boolean(issuerFingerprint && recipientFingerprint);
  const decidable = Boolean(data && pending && !own);

  const decide = async (verb: "approve" | "reject") => {
    if (!data) return;
    setBusy(verb);
    setError(null);
    try {
      if (verb === "approve") await endpoints.fulfillments.approve(data.id, data.version, issuerFingerprint ?? "", recipientFingerprint ?? "");
      else await endpoints.fulfillments.reject(data.id, data.version);
      onDecided(verb);
    } catch (failure) {
      setError(decideError(failure, t));
      const code = failure instanceof ApiError ? failure.code : null;
      if (code === "authorization_changed" || code === "approval_conflict") {
        // What was reviewed is out of date: re-read the list and this request.
        onStale();
        void detail.reload();
      }
    } finally {
      setBusy(null);
    }
  };

  return (
    <Dialog
      open
      size="lg"
      title={t("fleet.fulfillment.review.title")}
      onClose={onClose}
      dismissible={!busy}
      footer={
        <>
          {confirmReject ? (
            <Button variant="danger" icon="cross" busy={busy === "reject"} disabled={Boolean(busy) || !decidable} onClick={() => void decide("reject")}>
              {t("fleet.fulfillment.review.confirmReject")}
            </Button>
          ) : (
            <Button variant="ghost" icon="cross" disabled={Boolean(busy) || !decidable} onClick={() => setConfirmReject(true)}>
              {t("fleet.fulfillment.review.reject")}
            </Button>
          )}
          <Button onClick={onClose} disabled={Boolean(busy)} data-autofocus>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" icon="check" busy={busy === "approve"} disabled={!decidable || !hasKeys || !confirmed || Boolean(busy)} onClick={() => void decide("approve")}>
            {t("fleet.fulfillment.review.approve")}
          </Button>
        </>
      }
    >
      {detail.state.status === "loading" ? <Skeleton lines={6} /> : null}
      {detail.state.status === "error" && !data ? <ErrorState error={detail.state.error} onRetry={() => void detail.reload()} /> : null}
      {data ? (
        <div className="stack-sm">
          {own ? (
            <Notice tone="neutral" icon="lock">
              {t("fleet.fulfillment.review.own")}
            </Notice>
          ) : null}
          {!pending ? <Notice tone="warn">{t("fleet.fulfillment.review.notPending")}</Notice> : null}
          <VerifiedBlock title={t("fleet.fulfillment.review.verifiedTitle")} note={t("fleet.fulfillment.review.verifiedNote")}>
            <div className="stack-sm">
              <PartyFacts role="issuer" party={data.issuer} lookups={lookups} />
              <PartyFacts role="recipient" party={data.recipient} lookups={lookups} />
              <KeyValue
                columns={2}
                items={[
                  { label: t("fleet.fulfillment.fields.mode"), value: t(`fleet.fulfillment.mode.${data.mode}`) },
                  { label: t("fleet.fulfillment.fields.requestedBy"), value: <code className="mono">{data.requested_by}</code> },
                  { label: t("fleet.fulfillment.fields.rule"), value: <code className="mono">{data.rule_id}</code>, hint: t("fleet.fulfillment.review.policyVersion", { version: data.policy_version }) },
                  {
                    label: t("fleet.fulfillment.fields.approvers"),
                    value:
                      data.approval.approver_ids.length > 0 ? (
                        <span className="chip-list">
                          {data.approval.approver_ids.map((approver) => (
                            <code key={approver} className="chip mono">
                              {approver}
                            </code>
                          ))}
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )
                  },
                  { label: t("fleet.fulfillment.fields.lifetime"), value: t("fleet.seconds", { count: data.ttl_seconds }) },
                  { label: t("fleet.fulfillment.fields.expires"), value: <Countdown expiresAt={data.expires_at} /> },
                  ...(data.prior_fulfillment_id ? [{ label: t("fleet.fulfillment.fields.prior"), value: <code className="mono">{data.prior_fulfillment_id}</code> }] : [])
                ]}
              />
            </div>
          </VerifiedBlock>
          <UntrustedText label={t("fleet.fulfillment.review.purpose")}>{data.purpose}</UntrustedText>
          {hasKeys ? (
            <Notice tone="info" icon="fingerprint" title={t("fleet.fulfillment.review.instructionTitle")}>
              {t("fleet.fulfillment.review.instruction")}
            </Notice>
          ) : (
            <Notice tone="warn" icon="fingerprint">
              {t("fleet.fulfillment.review.noKeys")}
            </Notice>
          )}
          <Checkbox checked={confirmed} disabled={!decidable || !hasKeys || Boolean(busy)} onChange={(event) => setConfirmed(event.currentTarget.checked)} label={t("fleet.fulfillment.review.confirm")} />
          {own ? <p className="dialog-note">{t("fleet.fulfillment.review.ownRevoke")}</p> : null}
          {error ? <Notice tone="danger">{error}</Notice> : null}
        </div>
      ) : null}
    </Dialog>
  );
}

function RevokeDialog({ item, lookups, onClose, onDone }: { item: Fulfillment | null; lookups: Lookups; onClose: () => void; onDone: (result: Fulfillment) => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    if (!item) return;
    setBusy(true);
    setError(null);
    try {
      onDone(await endpoints.fulfillments.revoke(item.id));
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      if (apiError?.code === "fulfillment_not_found") setError(t("fleet.fulfillment.errors.gone"));
      else setError(apiError?.outcomeUnknown ? t("fleet.fulfillment.errors.revokeUnknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={item !== null}
      tone="danger"
      title={t("fleet.fulfillment.revoke.title")}
      onClose={() => !busy && (setError(null), onClose())}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={onClose} disabled={busy} data-autofocus>
            {t("common.cancel")}
          </Button>
          <Button variant="danger" icon="ban" busy={busy} onClick={() => void run()}>
            {t("fleet.fulfillment.revoke.submit")}
          </Button>
        </>
      }
    >
      {item ? (
        <dl className="confirm-scope">
          <div>
            <dt>{t("fleet.fulfillment.review.issuer")}</dt>
            <dd className="mono">{lookups.workloadName(item.issuer.workload_id)}</dd>
          </div>
          <div>
            <dt>{t("fleet.fulfillment.review.recipient")}</dt>
            <dd className="mono">{lookups.workloadName(item.recipient.workload_id)}</dd>
          </div>
        </dl>
      ) : null}
      <ul className="dialog-list">
        <li>{t("fleet.fulfillment.revoke.ciphertext")}</li>
        <li>{t("fleet.fulfillment.revoke.nodes")}</li>
        <li>{t("fleet.fulfillment.revoke.recall")}</li>
        <li>{t("fleet.fulfillment.provider.unsupported")}</li>
      </ul>
      {error ? <Notice tone="danger">{error}</Notice> : null}
    </Dialog>
  );
}

function RevokeOutcome({ result }: { result: Fulfillment }) {
  const { t } = useTranslation();
  if (result.status !== "revoked") {
    return (
      <Notice tone="neutral" title={t("fleet.fulfillment.closed.title")}>
        {t("fleet.fulfillment.closed.body", { status: t(`fleet.fulfillment.status.${result.status}`) })}
      </Notice>
    );
  }
  return (
    <Notice tone="warn" title={t("fleet.fulfillment.revoked.title")}>
      {t("fleet.fulfillment.revoked.body")} <ProviderNote value={result.provider_revocation} />
    </Notice>
  );
}

export default function FulfillmentsPage() {
  const { t } = useTranslation();
  const { can } = useSession();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const status = STATUSES.find((value) => value === params.get("status")) ?? null;
  const lookups = useLookups();
  const list = usePagedList(`fulfillments:${status ?? ""}`, (cursor) => endpoints.fulfillments.list({ limit: 50, ...(status ? { status } : {}), ...(cursor ? { cursor } : {}) }), { poll: FLEET_POLL });
  const [requesting, setRequesting] = useState(false);
  const [reviewing, setReviewing] = useState<Fulfillment | null>(null);
  const [revoking, setRevoking] = useState<Fulfillment | null>(null);
  const [outcome, setOutcome] = useState<Fulfillment | null>(null);
  const canCreate = can("fulfillments.create");
  const canDecide = can("fulfillments.decide");
  const canRevoke = can("fulfillments.revoke");

  const setFilter = (value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set("status", value);
    else next.delete("status");
    setParams(next, { replace: true });
    list.reset();
  };

  return (
    <div className="stack">
      <PageHeader
        eyebrow={t("fleet.eyebrow")}
        title={t("fleet.fulfillment.title")}
        description={t("fleet.fulfillment.description")}
        actions={
          canCreate ? (
            <Button variant="primary" icon="plus" onClick={() => setRequesting(true)}>
              {t("fleet.fulfillment.create.open")}
            </Button>
          ) : null
        }
      />
      <div className="toolbar">
        <SelectField label={t("fleet.fields.status")} value={status ?? ""} onChange={(event) => setFilter(event.currentTarget.value)}>
          <option value="">{t("fleet.fulfillment.allStatuses")}</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {t(`fleet.fulfillment.status.${value}`)}
            </option>
          ))}
        </SelectField>
      </div>
      {outcome ? <RevokeOutcome result={outcome} /> : null}
      {lookups.failed ? <Notice tone="warn">{t("fleet.fulfillment.lookupsFailed")}</Notice> : null}
      <Panel flush>
        {lookups.settled ? (
          <ListBody state={list.state} items={list.items} onRetry={() => void list.reload()} emptyIcon="link" emptyTitle={t("fleet.fulfillment.empty")} emptyBody={canCreate ? t("fleet.fulfillment.emptyBody") : undefined}>
            {(items) => (
              <table className="data-table is-responsive">
                <thead>
                  <tr>
                    <th scope="col">{t("fleet.fulfillment.fields.parties")}</th>
                    <th scope="col">{t("fleet.fields.status")}</th>
                    <th scope="col">{t("fleet.fulfillment.fields.requested")}</th>
                    <th scope="col">{t("fleet.fulfillment.fields.expires")}</th>
                    <th scope="col">
                      <span className="sr-only">{t("fleet.fields.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => {
                    const recipientName = lookups.workloadName(item.recipient.workload_id);
                    return (
                      <tr key={item.id} data-fulfillment={item.id}>
                        <td className="cell-lead" data-label={t("fleet.fulfillment.fields.parties")}>
                          <span className="cell-primary">
                            <span className="cell-title">{t("fleet.fulfillment.parties", { issuer: lookups.workloadName(item.issuer.workload_id), recipient: recipientName })}</span>
                            <span className="cell-sub">{t("fleet.fulfillment.nodes", { issuer: lookups.nodeName(item.issuer.node_id), recipient: lookups.nodeName(item.recipient.node_id) })}</span>
                            <span className="cell-sub mono">{t("fleet.fulfillment.credentials", { issuer: item.issuer.credential, recipient: item.recipient.credential })}</span>
                          </span>
                        </td>
                        <td data-label={t("fleet.fields.status")}>
                          <FulfillmentBadge status={item.status} />
                          {item.status === "uncertain" ? (
                            <>
                              <span className="cell-sub">{t("fleet.fulfillment.uncertain.what")}</span>
                              <span className="cell-sub">{t("fleet.fulfillment.uncertain.slot")}</span>
                            </>
                          ) : null}
                          {item.failure_code ? (
                            <span className="cell-sub">
                              {t("fleet.fulfillment.failureCode")} <code className="mono reason">{item.failure_code}</code>
                            </span>
                          ) : null}
                          {item.revocation_reason ? (
                            <span className="cell-sub">
                              {t("fleet.fulfillment.revocationReason")} <code className="mono reason">{item.revocation_reason}</code>
                            </span>
                          ) : null}
                          {item.stored_at || item.status === "completed" || item.status === "recipient_consumed" ? (
                            <span className="cell-sub">
                              <ProviderNote value={item.provider_revocation} />
                            </span>
                          ) : null}
                        </td>
                        <td data-label={t("fleet.fulfillment.fields.requested")}>
                          <Timestamp value={item.created_at} relative />
                          <span className="cell-sub mono">{item.requested_by}</span>
                        </td>
                        <td data-label={t("fleet.fulfillment.fields.expires")}>{COUNTS_DOWN.has(item.status) ? <Countdown expiresAt={item.expires_at} /> : <Timestamp value={item.closed_at ?? item.expires_at} />}</td>
                        <td className="cell-actions">
                          {canDecide && item.status === "awaiting_approval" ? (
                            <Button size="sm" variant="secondary" icon="fingerprint" onClick={() => setReviewing(item)} aria-label={t("fleet.fulfillment.review.label", { name: recipientName })}>
                              {t("fleet.fulfillment.review.short")}
                            </Button>
                          ) : null}
                          {canRevoke && REVOCABLE.has(item.status) ? (
                            <Button size="sm" variant="ghost" icon="ban" onClick={() => setRevoking(item)} aria-label={t("fleet.fulfillment.revoke.label", { name: recipientName })}>
                              {t("fleet.fulfillment.revoke.short")}
                            </Button>
                          ) : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </ListBody>
        ) : (
          <Skeleton lines={4} className="panel-pad" />
        )}
        <div className="panel-pager">{list.pager}</div>
      </Panel>
      <Notice tone="neutral" icon="info">
        {t("fleet.fulfillment.boundary")}
      </Notice>
      <RequestDialog
        open={requesting}
        lookups={lookups}
        onClose={() => setRequesting(false)}
        onCreated={() => {
          setRequesting(false);
          toast.show({ tone: "ok", title: t("fleet.fulfillment.create.done") });
          list.reset();
          void list.reload();
        }}
      />
      <ReviewDialog
        item={reviewing}
        lookups={lookups}
        onClose={() => setReviewing(null)}
        onStale={() => void list.reload()}
        onDecided={(verb) => {
          setReviewing(null);
          toast.show({ tone: "ok", title: t(verb === "approve" ? "fleet.fulfillment.review.approved" : "fleet.fulfillment.review.rejected") });
          void list.reload();
        }}
      />
      <RevokeDialog
        item={revoking}
        lookups={lookups}
        onClose={() => setRevoking(null)}
        onDone={(result) => {
          setOutcome(result);
          setRevoking(null);
          void list.reload();
        }}
      />
    </div>
  );
}
