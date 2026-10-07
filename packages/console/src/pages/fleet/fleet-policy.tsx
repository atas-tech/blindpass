import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { FleetPolicy, FleetPolicyRule } from "../../api/types.js";
import { collectAll, useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { ErrorState, Notice, Skeleton, StatusBadge, type Tone } from "../../ui/feedback.js";
import { TextAreaField, TextField } from "../../ui/field.js";
import { PageHeader, Panel, SegmentedControl } from "../../ui/layout.js";
import { Timestamp } from "../../ui/time.js";
import { useToast } from "../../ui/toast.js";
import { CrossWorkloadPanel, crossErrors, sameCrossRules, toCrossRows, toCrossRules, type CrossRow } from "./cross-workload-rules.js";

/**
 * The controller allows one rule per (action, mode) and accepts only these pairs:
 * noop.marker with file or socket, and browser.session with browser_session.
 */
const RULES = [
  { action: "noop.marker", mode: "file", id: "noop-marker-file" },
  { action: "noop.marker", mode: "socket", id: "noop-marker-socket" },
  { action: "browser.session", mode: "browser_session", id: "browser-session" }
] as const;
const ACTIONS = ["noop.marker", "browser.session"] as const;
const MODES = RULES.map((rule) => rule.mode);
type Mode = (typeof RULES)[number]["mode"];
const ACTION_OF = Object.fromEntries(RULES.map((rule) => [rule.mode, rule.action])) as Record<Mode, (typeof ACTIONS)[number]>;
const ID_OF = Object.fromEntries(RULES.map((rule) => [rule.mode, rule.id])) as Record<Mode, string>;
type Decision = FleetPolicyRule["decision"] | "none";
const TONE: Record<Decision, Tone> = { allow: "ok", pending_approval: "warn", deny: "danger", none: "neutral" };
const APPROVER = /^[A-Za-z0-9_.@-]{1,128}$/;

interface Row {
  id: string;
  decision: Decision;
  ttl: string;
  approvers: string;
}

function toRows(policy: FleetPolicy): Record<Mode, Row> {
  const rows = {} as Record<Mode, Row>;
  for (const mode of MODES) {
    const rule = policy.rules.find((item) => item.action === ACTION_OF[mode] && item.mode === mode);
    rows[mode] = rule
      ? { id: rule.id, decision: rule.decision, ttl: String(rule.max_ttl_seconds), approvers: (rule.approver_ids ?? []).join("\n") }
      : { id: ID_OF[mode], decision: "none", ttl: "120", approvers: "" };
  }
  return rows;
}

function toRules(rows: Record<Mode, Row>, others: FleetPolicyRule[]): FleetPolicyRule[] {
  const rules = [...others];
  for (const mode of MODES) {
    const row = rows[mode];
    if (row.decision === "none") continue;
    const approvers = row.approvers.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    rules.push({
      id: row.id,
      action: ACTION_OF[mode],
      mode,
      decision: row.decision,
      approval_required: row.decision === "pending_approval",
      max_ttl_seconds: Number(row.ttl),
      ...(row.decision === "pending_approval" ? { approver_ids: [...new Set(approvers)] } : {})
    });
  }
  return rules;
}

function rowErrors(row: Row, t: (key: string) => string): { ttl?: string; approvers?: string } {
  if (row.decision === "none") return {};
  const errors: { ttl?: string; approvers?: string } = {};
  const ttl = Number(row.ttl);
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 3600) errors.ttl = t("fleet.policy.errors.ttl");
  if (row.decision === "pending_approval") {
    const approvers = row.approvers.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    if (approvers.length < 1 || approvers.length > 32 || !approvers.every((value) => APPROVER.test(value))) errors.approvers = t("fleet.policy.errors.approvers");
  }
  return errors;
}

export default function FleetPolicyPage() {
  const { t } = useTranslation();
  const { can, hasFulfillments } = useSession();
  const toast = useToast();
  const canWrite = can("fleetPolicy.write");
  const { state, reload, replace } = useResource("fleet-policy", () => endpoints.fleetPolicy.get());
  // Workloads name the selectors of the cross-workload rules; only fetched when that feature is on.
  const workloads = useResource(hasFulfillments ? "fleet-policy-workloads" : null, () => collectAll((cursor) => endpoints.workloads.list({ limit: 100, ...(cursor ? { cursor } : {}) })), { enabled: hasFulfillments });
  const [draft, setDraft] = useState<{ base: FleetPolicy; rows: Record<Mode, Row>; cross: CrossRow[]; matrixTouched: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const stored = state.status === "ready" ? state.data : state.status === "error" ? state.previous : null;
  // Rows keep their keys between renders; a rebuild here would remount every field while typing.
  const storedCross = useMemo(() => toCrossRows(stored?.cross_workload ?? []), [stored]);

  if (state.status === "loading") return <Skeleton lines={6} />;
  if (state.status === "error" && !state.previous) return <ErrorState error={state.error} onRetry={() => void reload()} />;
  const policy = state.status === "ready" ? state.data : state.previous!;
  const rows = draft?.rows ?? toRows(policy);
  const crossRows = draft?.cross ?? storedCross;
  const others = (draft?.base ?? policy).rules.filter((rule) => !RULES.some((known) => known.action === rule.action && known.mode === rule.mode));
  const errors = Object.fromEntries(MODES.map((mode) => [mode, rowErrors(rows[mode], t)])) as Record<Mode, ReturnType<typeof rowErrors>>;
  // The stored cross-workload rules are sent only when the operator changed them (omitted keeps them).
  const crossChanged = hasFulfillments && draft !== null && !sameCrossRules(toCrossRules(draft.cross), draft.base.cross_workload ?? []);
  const crossRowErrors = crossChanged ? crossErrors(crossRows, t) : null;
  const invalid = MODES.some((mode) => Object.keys(errors[mode]).length > 0) || Boolean(crossRowErrors?.some((item) => Object.keys(item).length > 0));

  const setRow = (mode: Mode, patch: Partial<Row>) =>
    setDraft((current) => ({ base: current?.base ?? policy, rows: { ...(current?.rows ?? toRows(policy)), [mode]: { ...(current?.rows ?? toRows(policy))[mode], ...patch } }, cross: current?.cross ?? storedCross, matrixTouched: true }));
  const setCross = (next: CrossRow[]) => setDraft((current) => ({ base: current?.base ?? policy, rows: current?.rows ?? toRows(policy), cross: next, matrixTouched: current?.matrixTouched ?? false }));

  const save = async () => {
    if (!draft) return;
    setSubmitted(true);
    if (invalid) return;
    setBusy(true);
    setError(null);
    try {
      // Rules the operator did not touch go back exactly as stored.
      const rules = draft.matrixTouched ? toRules(draft.rows, others) : draft.base.rules;
      const saved = await endpoints.fleetPolicy.save(rules, draft.base.version, crossChanged ? toCrossRules(draft.cross) : undefined);
      replace(saved);
      setDraft(null);
      setSubmitted(false);
      toast.show({ tone: "ok", title: t("fleet.policy.saved", { version: saved.version }) });
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      if (apiError?.code === "version_conflict" || apiError?.code === "policy_changed" || apiError?.status === 409) {
        setConflict(true);
        void reload();
      } else if (apiError?.code === "invalid_policy_rule") setError(t(crossChanged ? (draft.matrixTouched ? "fleet.policy.errors.invalidBoth" : "fleet.policy.errors.invalidCross") : "fleet.policy.errors.invalid"));
      else setError(apiError?.outcomeUnknown ? t("fleet.policy.errors.unknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <PageHeader
        eyebrow={t("fleet.policy.eyebrow", { version: policy.version })}
        title={t("fleet.policy.title")}
        description={t("fleet.policy.description")}
        meta={
          <span className="muted small">
            {policy.updated_by && policy.updated_at > 0 ? (
              <>
                {t("fleet.policy.updated", { by: policy.updated_by })} <Timestamp value={policy.updated_at} relative />
              </>
            ) : (
              t("fleet.policy.neverEdited")
            )}
          </span>
        }
      />
      {!canWrite ? (
        <Notice tone="neutral" icon="lock">
          {t("fleet.policy.readOnly")}
        </Notice>
      ) : null}
      {conflict ? (
        <Notice
          tone="warn"
          title={t("fleet.policy.conflictTitle")}
          action={
            <Button
              size="sm"
              onClick={() => {
                setConflict(false);
                setDraft(null);
              }}
            >
              {t("fleet.policy.loadLatest")}
            </Button>
          }
        >
          {t("fleet.policy.conflictBody", { version: policy.version })}
        </Notice>
      ) : null}
      {error ? <Notice tone="danger">{error}</Notice> : null}
      {ACTIONS.map((action) => (
        <Panel key={action} title={t("fleet.policy.matrix", { action })} icon="policy" flush>
          <div className="fleet-rules">
            {MODES.filter((mode) => ACTION_OF[mode] === action).map((mode) => {
              const row = rows[mode];
              const rowError = submitted ? errors[mode] : {};
              return (
                <section key={mode} className="fleet-rule" data-mode={mode} aria-labelledby={`fleet-rule-${mode}`}>
                  <header className="fleet-rule-head">
                    <h2 id={`fleet-rule-${mode}`} className="section-title">
                      <code className="mono">{action}</code> · {t(`approvals.mode.${mode}`)}
                    </h2>
                    <StatusBadge tone={TONE[row.decision]}>{t(`fleet.policy.decision.${row.decision}`)}</StatusBadge>
                  </header>
                  {canWrite ? (
                    <div className="fleet-rule-form">
                      <div className="field field-wide">
                        <span className="field-label">{t("fleet.policy.fields.decision")}</span>
                        <SegmentedControl<Decision>
                          label={t("fleet.policy.fields.decisionFor", { mode: t(`approvals.mode.${mode}`) })}
                          value={row.decision}
                          onChange={(decision) => setRow(mode, { decision })}
                          options={(["none", "allow", "pending_approval", "deny"] as const).map((value) => ({ value, label: t(`fleet.policy.decision.${value}`) }))}
                        />
                      </div>
                      {row.decision !== "none" ? <TextField label={t("fleet.policy.fields.ttl")} hint={t("fleet.policy.fields.ttlHint")} value={row.ttl} onChange={(event) => setRow(mode, { ttl: event.currentTarget.value })} error={rowError.ttl} type="number" min={1} max={3600} inputMode="numeric" /> : null}
                      {row.decision === "pending_approval" ? <TextAreaField label={t("fleet.policy.fields.approvers")} hint={t("fleet.policy.fields.approversHint")} value={row.approvers} onChange={(event) => setRow(mode, { approvers: event.currentTarget.value })} error={rowError.approvers} rows={2} mono spellCheck={false} /> : null}
                    </div>
                  ) : row.decision !== "none" ? (
                    <dl className="rule-grid">
                      <div>
                        <dt>{t("fleet.policy.fields.ttl")}</dt>
                        <dd>{t("fleet.seconds", { count: Number(row.ttl) })}</dd>
                      </div>
                      {row.decision === "pending_approval" ? (
                        <div>
                          <dt>{t("fleet.policy.fields.approvers")}</dt>
                          <dd className="chip-list">
                            {row.approvers.split("\n").filter(Boolean).map((value) => (
                              <code key={value} className="chip mono">
                                {value}
                              </code>
                            ))}
                          </dd>
                        </div>
                      ) : null}
                    </dl>
                  ) : (
                    <p className="section-body">{t("fleet.policy.noneBody")}</p>
                  )}
                </section>
              );
            })}
          </div>
        </Panel>
      ))}
      {others.length ? <Notice tone="neutral">{t("fleet.policy.otherRules", { count: others.length })}</Notice> : null}
      {hasFulfillments ? (
        <CrossWorkloadPanel
          rows={crossRows}
          onChange={setCross}
          workloads={workloads.state.status === "ready" ? workloads.state.data : []}
          canWrite={canWrite}
          errors={submitted ? crossRowErrors : null}
          workloadsFailed={workloads.state.status === "error"}
          loading={workloads.state.status === "loading"}
        />
      ) : null}
      <Notice tone="neutral" icon="info">
        {t("fleet.policy.boundary")}
      </Notice>
      {canWrite && draft ? (
        <div className="edit-bar" role="region" aria-label={t("policy.editBar")}>
          <span className="edit-bar-status">{t("policy.editingFrom", { version: draft.base.version })}</span>
          <span className="edit-bar-actions">
            <Button variant="ghost" onClick={() => (setDraft(null), setSubmitted(false))} disabled={busy}>
              {t("policy.discard")}
            </Button>
            <Button variant="primary" busy={busy} disabled={conflict} onClick={() => void save()}>
              {t("fleet.policy.save")}
            </Button>
          </span>
        </div>
      ) : null}
    </div>
  );
}
