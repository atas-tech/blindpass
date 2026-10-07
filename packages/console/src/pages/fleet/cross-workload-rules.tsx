import { useTranslation } from "react-i18next";
import type { CrossWorkloadRule, Workload } from "../../api/types.js";
import { Button } from "../../ui/button.js";
import { Notice, Skeleton, StatusBadge, type Tone } from "../../ui/feedback.js";
import { Checkbox, TextAreaField, TextField } from "../../ui/field.js";
import { Panel, SegmentedControl } from "../../ui/layout.js";

type Decision = CrossWorkloadRule["decision"];
const TONE: Record<Decision, Tone> = { allow: "ok", pending_approval: "warn", deny: "danger" };
const RULE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const APPROVER = /^[A-Za-z0-9_.@-]{1,128}$/;
const MAX_RULES = 64;
const MAX_SELECTORS = 16;
const MAX_TTL = 600;

/** A rule as the editor holds it. `key` is local; everything else is what is sent. */
export interface CrossRow {
  key: number;
  id: string;
  issuers: string[];
  recipients: string[];
  decision: Decision;
  ttl: string;
  approvers: string;
}

export interface CrossRowErrors {
  id?: string;
  issuers?: string;
  recipients?: string;
  ttl?: string;
  approvers?: string;
}

let nextKey = 1;

export function toCrossRows(rules: readonly CrossWorkloadRule[]): CrossRow[] {
  return rules.map((rule) => ({
    key: nextKey++,
    id: rule.id,
    issuers: [...rule.issuer_workload_ids],
    recipients: [...rule.recipient_workload_ids],
    decision: rule.decision,
    ttl: String(rule.max_ttl_seconds),
    approvers: (rule.approver_ids ?? []).join("\n")
  }));
}

function approverList(value: string): string[] {
  return [...new Set(value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean))];
}

/** The exact rules the controller stores. Approvers belong only to pending_approval. */
export function toCrossRules(rows: readonly CrossRow[]): CrossWorkloadRule[] {
  return rows.map((row) => ({
    id: row.id.trim(),
    issuer_workload_ids: [...row.issuers],
    recipient_workload_ids: [...row.recipients],
    decision: row.decision,
    max_ttl_seconds: Number(row.ttl),
    ...(row.decision === "pending_approval" ? { approver_ids: approverList(row.approvers) } : {})
  }));
}

export function crossErrors(rows: readonly CrossRow[], t: (key: string) => string): CrossRowErrors[] {
  const seen = new Set<string>();
  return rows.map((row) => {
    const errors: CrossRowErrors = {};
    const id = row.id.trim();
    if (!RULE_ID.test(id)) errors.id = t("fleet.policy.cross.errors.id");
    else if (seen.has(id)) errors.id = t("fleet.policy.cross.errors.duplicate");
    seen.add(id);
    if (row.issuers.length < 1 || row.issuers.length > MAX_SELECTORS) errors.issuers = t("fleet.policy.cross.errors.issuers");
    if (row.recipients.length < 1 || row.recipients.length > MAX_SELECTORS) errors.recipients = t("fleet.policy.cross.errors.recipients");
    const ttl = Number(row.ttl);
    if (!/^\d+$/.test(row.ttl.trim()) || ttl < 1 || ttl > MAX_TTL) errors.ttl = t("fleet.policy.cross.errors.ttl");
    if (row.decision === "pending_approval") {
      const approvers = approverList(row.approvers);
      if (approvers.length < 1 || approvers.length > 32 || !approvers.every((value) => APPROVER.test(value))) errors.approvers = t("fleet.policy.errors.approvers");
    }
    return errors;
  });
}

export function newCrossRow(existing: readonly CrossRow[]): CrossRow {
  const used = new Set(existing.map((row) => row.id));
  let n = 1;
  while (used.has(`cross-rule-${n}`)) n += 1;
  return { key: nextKey++, id: `cross-rule-${n}`, issuers: [], recipients: [], decision: "pending_approval", ttl: "300", approvers: "" };
}

/**
 * Whether two rule lists say the same thing. The order of the rules matters
 * (first match wins); the order of the IDs inside a selector does not, and the
 * controller stores them sorted.
 */
export function sameCrossRules(a: readonly CrossWorkloadRule[], b: readonly CrossWorkloadRule[]): boolean {
  const canon = (rules: readonly CrossWorkloadRule[]) =>
    JSON.stringify(rules.map((rule) => [rule.id, [...rule.issuer_workload_ids].sort(), [...rule.recipient_workload_ids].sort(), rule.decision, rule.max_ttl_seconds, rule.decision === "pending_approval" ? [...(rule.approver_ids ?? [])].sort() : []]));
  return canon(a) === canon(b);
}

interface Option {
  id: string;
  label: string;
  note?: string;
}

/** Registered workloads first; ids the rule names that are not (or no longer) active are kept visible so they round-trip. */
function selectorOptions(workloads: readonly Workload[], selected: readonly string[], lookupFailed: boolean, t: (key: string) => string): Option[] {
  const options: Option[] = workloads.filter((workload) => workload.status === "active").map((workload) => ({ id: workload.id, label: `${workload.name} · ${workload.unit}` }));
  const known = new Map(workloads.map((workload) => [workload.id, workload] as const));
  for (const id of selected) {
    if (options.some((option) => option.id === id)) continue;
    const workload = known.get(id);
    // With no workload list there is nothing to say about this ID except the ID itself.
    const note = lookupFailed ? undefined : t(workload ? "fleet.policy.cross.revoked" : "fleet.policy.cross.unknown");
    options.push({ id, label: workload ? `${workload.name} · ${workload.unit}` : id, ...(note ? { note } : {}) });
  }
  return options;
}

function workloadLabel(id: string, workloads: readonly Workload[]): string {
  const workload = workloads.find((item) => item.id === id);
  return workload ? `${workload.name} (${id})` : id;
}

function Selector({ legend, options, selected, onChange, error }: { legend: string; options: Option[]; selected: string[]; onChange: (next: string[]) => void; error?: string }) {
  const { t } = useTranslation();
  return (
    <fieldset className={`cross-selector${error ? " has-error" : ""}`}>
      <legend className="field-label">{legend}</legend>
      <div className="cross-selector-list">
        {options.map((option) => (
          <Checkbox
            key={option.id}
            checked={selected.includes(option.id)}
            onChange={() => onChange(selected.includes(option.id) ? selected.filter((id) => id !== option.id) : [...selected, option.id])}
            label={
              <>
                <span>{option.label}</span> <code className="mono cross-selector-id">{option.id}</code>
                {option.note ? <span className="muted"> — {option.note}</span> : null}
              </>
            }
          />
        ))}
        {options.length === 0 ? <p className="field-hint">{t("fleet.policy.cross.noWorkloads")}</p> : null}
      </div>
      {error ? <p className="field-error">{error}</p> : null}
    </fieldset>
  );
}

export function CrossWorkloadPanel({ rows, onChange, workloads, canWrite, errors, workloadsFailed, loading }: { rows: CrossRow[]; onChange: (rows: CrossRow[]) => void; workloads: readonly Workload[]; canWrite: boolean; errors: CrossRowErrors[] | null; workloadsFailed: boolean; loading: boolean }) {
  const { t } = useTranslation();
  const update = (index: number, patch: Partial<CrossRow>) => onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  const move = (index: number, by: -1 | 1) => {
    const next = [...rows];
    const [moved] = next.splice(index, 1);
    if (moved) next.splice(index + by, 0, moved);
    onChange(next);
  };

  return (
    <Panel
      title={t("fleet.policy.cross.title")}
      icon="link"
      flush
      actions={
        canWrite ? (
          <Button size="sm" icon="plus" disabled={loading || rows.length >= MAX_RULES} onClick={() => onChange([...rows, newCrossRow(rows)])}>
            {t("fleet.policy.cross.add")}
          </Button>
        ) : null
      }
    >
      <div className="panel-pad stack-sm">
        <p className="section-body">{t("fleet.policy.cross.description")}</p>
        {workloadsFailed ? <Notice tone="warn">{t("fleet.policy.cross.workloadsFailed")}</Notice> : null}
      </div>
      {loading ? <Skeleton lines={3} className="panel-pad" /> : null}
      {!loading && rows.length === 0 ? <p className="section-body panel-pad">{t("fleet.policy.cross.none")}</p> : null}
      <div className="fleet-rules">
        {(loading ? [] : rows).map((row, index) => {
          const rowErrors = errors?.[index] ?? {};
          return (
            <section key={row.key} className="fleet-rule" data-cross-rule={row.id} aria-label={t("fleet.policy.cross.ruleLabel", { id: row.id || "—" })}>
              <header className="fleet-rule-head">
                <h3 className="section-title">
                  <span className="muted">{index + 1}.</span> <code className="mono">{row.id || "—"}</code>
                </h3>
                <span className="fleet-rule-tools">
                  <StatusBadge tone={TONE[row.decision]}>{t(`fleet.policy.decision.${row.decision}`)}</StatusBadge>
                  {canWrite ? (
                    <>
                      <Button size="sm" variant="quiet" icon="chevron-up" disabled={index === 0} onClick={() => move(index, -1)} aria-label={t("fleet.policy.cross.moveUp", { id: row.id })} />
                      <Button size="sm" variant="quiet" icon="chevron-down" disabled={index === rows.length - 1} onClick={() => move(index, 1)} aria-label={t("fleet.policy.cross.moveDown", { id: row.id })} />
                      <Button size="sm" variant="ghost" icon="trash" onClick={() => onChange(rows.filter((_, i) => i !== index))} aria-label={t("fleet.policy.cross.remove", { id: row.id })}>
                        {t("fleet.policy.cross.removeShort")}
                      </Button>
                    </>
                  ) : null}
                </span>
              </header>
              {canWrite ? (
                <div className="cross-rule-form">
                  <TextField label={t("fleet.policy.cross.fields.id")} value={row.id} onChange={(event) => update(index, { id: event.currentTarget.value })} error={rowErrors.id} mono autoComplete="off" spellCheck={false} />
                  <TextField label={t("fleet.policy.cross.fields.ttl")} hint={t("fleet.policy.cross.fields.ttlHint")} value={row.ttl} onChange={(event) => update(index, { ttl: event.currentTarget.value })} error={rowErrors.ttl} type="text" inputMode="numeric" />
                  <Selector legend={t("fleet.policy.cross.fields.issuers")} options={selectorOptions(workloads, row.issuers, workloadsFailed, t)} selected={row.issuers} onChange={(issuers) => update(index, { issuers })} error={rowErrors.issuers} />
                  <Selector legend={t("fleet.policy.cross.fields.recipients")} options={selectorOptions(workloads, row.recipients, workloadsFailed, t)} selected={row.recipients} onChange={(recipients) => update(index, { recipients })} error={rowErrors.recipients} />
                  <div className="field field-wide">
                    <span className="field-label">{t("fleet.policy.fields.decision")}</span>
                    <SegmentedControl<Decision>
                      label={t("fleet.policy.cross.fields.decisionFor", { id: row.id })}
                      value={row.decision}
                      onChange={(decision) => update(index, { decision })}
                      options={(["allow", "pending_approval", "deny"] as const).map((value) => ({ value, label: t(`fleet.policy.decision.${value}`) }))}
                    />
                  </div>
                  {row.decision === "pending_approval" ? (
                    <div className="field-wide">
                      <TextAreaField label={t("fleet.policy.cross.fields.approvers")} hint={t("fleet.policy.cross.fields.approversHint")} value={row.approvers} onChange={(event) => update(index, { approvers: event.currentTarget.value })} error={rowErrors.approvers} rows={2} mono spellCheck={false} />
                    </div>
                  ) : null}
                </div>
              ) : (
                <dl className="rule-grid">
                  <div>
                    <dt>{t("fleet.policy.cross.fields.issuers")}</dt>
                    <dd className="chip-list">
                      {row.issuers.map((id) => (
                        <code key={id} className="chip mono" title={id}>
                          {workloadLabel(id, workloads)}
                        </code>
                      ))}
                    </dd>
                  </div>
                  <div>
                    <dt>{t("fleet.policy.cross.fields.recipients")}</dt>
                    <dd className="chip-list">
                      {row.recipients.map((id) => (
                        <code key={id} className="chip mono" title={id}>
                          {workloadLabel(id, workloads)}
                        </code>
                      ))}
                    </dd>
                  </div>
                  <div>
                    <dt>{t("fleet.policy.cross.fields.ttl")}</dt>
                    <dd>{t("fleet.seconds", { count: Number(row.ttl) })}</dd>
                  </div>
                  {row.decision === "pending_approval" ? (
                    <div>
                      <dt>{t("fleet.policy.cross.fields.approvers")}</dt>
                      <dd className="chip-list">
                        {approverList(row.approvers).map((value) => (
                          <code key={value} className="chip mono">
                            {value}
                          </code>
                        ))}
                      </dd>
                    </div>
                  ) : null}
                </dl>
              )}
            </section>
          );
        })}
      </div>
    </Panel>
  );
}
