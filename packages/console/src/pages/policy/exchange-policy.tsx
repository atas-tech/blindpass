import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { PolicyDocument } from "../../api/types.js";
import { useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { EmptyState, ErrorState, Notice, Skeleton, StatusBadge, type Tone } from "../../ui/feedback.js";
import { SelectField, TextAreaField, TextField } from "../../ui/field.js";
import { PageHeader, Panel, SegmentedControl } from "../../ui/layout.js";
import { useToast } from "../../ui/toast.js";
import {
  blankRule,
  diffDrafts,
  issuesFor,
  move,
  otherFields,
  parseIssue,
  parseList,
  readList,
  readString,
  REGISTRY_FIELDS,
  RULE_FIELDS,
  ruleMode,
  sameDocument,
  toDocument,
  toDraft,
  write,
  type DiffSummary,
  type Draft,
  type Issue,
  type Json,
  type RuleMode
} from "./model.js";

type Tab = "rules" | "registry" | "json";
const MODE_TONE: Record<RuleMode, Tone> = { allow: "ok", pending_approval: "warn", deny: "danger" };

interface Editing {
  base: PolicyDocument;
  draft: Draft;
  issues: Issue[];
  json: string;
  jsonError: string | null;
  phase: "idle" | "validating" | "saving";
  validated: boolean;
  conflict: PolicyDocument | null;
  unknown: boolean;
  formError: string | null;
}

function IdList({ values, anyLabel }: { values: string[] | null; anyLabel: string }) {
  if (!values || values.length === 0) {
    return (
      <span className="any-match">
        <StatusBadge tone="warn">{anyLabel}</StatusBadge>
      </span>
    );
  }
  return (
    <span className="chip-list">
      {values.map((value) => (
        <code key={value} className="chip mono">
          {value}
        </code>
      ))}
    </span>
  );
}

function fieldError({ issues, field }: { issues: Issue[]; field: string }) {
  const matching = issues.filter((issue) => issue.field === field);
  return matching.length ? matching.map((issue) => issue.message).join("; ") : undefined;
}

/** One id per line (commas also split). Keeps the operator's typing until blur. */
function ListField({ label, hint, values, error, onCommit }: { label: string; hint: string; values: string[] | null; error?: string; onCommit: (values: string[] | undefined) => void }) {
  const joined = (values ?? []).join("\n");
  const [text, setText] = useState(joined);
  const focused = useRef(false);
  useEffect(() => {
    if (!focused.current) setText(joined);
  }, [joined]);
  return (
    <TextAreaField
      label={label}
      hint={hint}
      mono
      rows={2}
      value={text}
      onFocus={() => (focused.current = true)}
      onChange={(event) => setText(event.currentTarget.value)}
      onBlur={() => {
        focused.current = false;
        onCommit(parseList(text));
      }}
      error={error}
      spellCheck={false}
    />
  );
}

function RuleView({ rule, index }: { rule: Json; index: number }) {
  const { t } = useTranslation();
  const mode = ruleMode(rule);
  const others = otherFields(rule, RULE_FIELDS);
  const reason = readString(rule, "reason");
  return (
    <article className="rule-card" data-rule={readString(rule, "ruleId")}>
      <header className="rule-head">
        <span className="rule-order mono" aria-label={t("policy.order", { n: index + 1 })}>
          {String(index + 1).padStart(2, "0")}
        </span>
        <h3 className="rule-id mono">{readString(rule, "ruleId") || "—"}</h3>
        <StatusBadge tone={MODE_TONE[mode]}>{t(`policy.mode.${mode}`)}</StatusBadge>
      </header>
      <dl className="rule-grid">
        <div>
          <dt>{t("policy.fields.secretName")}</dt>
          <dd>
            <code className="mono">{readString(rule, "secretName") || "—"}</code>
          </dd>
        </div>
        <div>
          <dt>{t("policy.fields.requesterIds")}</dt>
          <dd>
            <IdList values={readList(rule, "requesterIds")} anyLabel={t("policy.anyAgent")} />
          </dd>
        </div>
        <div>
          <dt>{t("policy.fields.fulfillerIds")}</dt>
          <dd>
            <IdList values={readList(rule, "fulfillerIds")} anyLabel={t("policy.anyAgent")} />
          </dd>
        </div>
        {mode === "pending_approval" ? (
          <div>
            <dt>{t("policy.fields.approverIds")}</dt>
            <dd>
              <IdList values={readList(rule, "approverIds")} anyLabel={t("policy.noApprovers")} />
            </dd>
          </div>
        ) : null}
      </dl>
      {reason ? <p className="rule-reason">{reason}</p> : null}
      {others.length ? <p className="rule-others">{t("policy.otherFields", { fields: others.join(", ") })}</p> : null}
    </article>
  );
}

function RuleEditor({ rule, index, count, registryNames, issues, onChange, onMove, onRemove }: { rule: Json; index: number; count: number; registryNames: string[]; issues: Issue[]; onChange: (rule: Json) => void; onMove: (delta: -1 | 1) => void; onRemove: () => void }) {
  const { t } = useTranslation();
  const mode = ruleMode(rule);
  const others = otherFields(rule, RULE_FIELDS);
  const secret = readString(rule, "secretName");
  const listField = (field: "requesterIds" | "fulfillerIds" | "approverIds", hint: string) => (
    <ListField label={t(`policy.fields.${field}`)} hint={hint} values={readList(rule, field)} error={fieldError({ issues, field })} onCommit={(values) => onChange(write(rule, field, values))} />
  );
  const general = issues.filter((issue) => !issue.field || !(RULE_FIELDS as readonly string[]).includes(issue.field));
  return (
    <article className={`rule-card is-editing${issues.length ? " has-issues" : ""}`} data-rule={readString(rule, "ruleId")}>
      <header className="rule-head">
        <span className="rule-order mono">{String(index + 1).padStart(2, "0")}</span>
        <span className="rule-head-title">{t("policy.ruleN", { n: index + 1 })}</span>
        <span className="rule-tools">
          <Button size="sm" variant="quiet" icon="chevron-up" onClick={() => onMove(-1)} disabled={index === 0} aria-label={t("policy.moveUp", { n: index + 1 })} />
          <Button size="sm" variant="quiet" icon="chevron-down" onClick={() => onMove(1)} disabled={index === count - 1} aria-label={t("policy.moveDown", { n: index + 1 })} />
          <Button size="sm" variant="ghost" icon="trash" onClick={onRemove} aria-label={t("policy.removeRule", { n: index + 1 })} />
        </span>
      </header>
      {general.length ? (
        <Notice tone="danger">
          {general.map((issue) => (
            <span key={issue.raw} className="issue-line">
              {issue.field ? `${issue.field}: ` : ""}
              {issue.message}
            </span>
          ))}
        </Notice>
      ) : null}
      <div className="rule-form">
        <TextField label={t("policy.fields.ruleId")} mono value={readString(rule, "ruleId")} onChange={(event) => onChange(write(rule, "ruleId", event.currentTarget.value))} error={fieldError({ issues, field: "ruleId" })} spellCheck={false} />
        <SelectField label={t("policy.fields.secretName")} value={secret} onChange={(event) => onChange(write(rule, "secretName", event.currentTarget.value))} error={fieldError({ issues, field: "secretName" })}>
          {secret && !registryNames.includes(secret) ? <option value={secret}>{secret}</option> : null}
          {!secret ? <option value="">{t("policy.chooseSecret")}</option> : null}
          {registryNames.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </SelectField>
        <div className="field field-wide">
          <span className="field-label" id={`mode-label-${index}`}>
            {t("policy.fields.mode")}
          </span>
          <SegmentedControl label={t("policy.fields.mode")} value={mode} onChange={(value) => onChange(write(rule, "mode", value))} options={(["allow", "pending_approval", "deny"] as const).map((value) => ({ value, label: t(`policy.mode.${value}`) }))} />
          {fieldError({ issues, field: "mode" }) ? <p className="field-error">{fieldError({ issues, field: "mode" })}</p> : null}
        </div>
        {listField("requesterIds", t("policy.hints.list"))}
        {listField("fulfillerIds", t("policy.hints.list"))}
        {mode === "pending_approval" ? listField("approverIds", t("policy.hints.approvers")) : null}
        <TextField label={t("policy.fields.reason")} optional={t("policy.optional")} value={readString(rule, "reason")} onChange={(event) => onChange(write(rule, "reason", event.currentTarget.value || undefined))} fieldClassName="field-wide" />
      </div>
      {others.length ? <p className="rule-others">{t("policy.otherFieldsEdit", { fields: others.join(", ") })}</p> : null}
    </article>
  );
}

function RegistryView({ registry, editing, issues, onChange }: { registry: Json[]; editing: boolean; issues: Issue[]; onChange: (registry: Json[]) => void }) {
  const { t } = useTranslation();
  if (!editing) {
    if (!registry.length) return <EmptyState icon="key" title={t("policy.registry.empty")} />;
    return (
      <table className="data-table is-responsive">
        <thead>
          <tr>
            <th scope="col">{t("policy.fields.secretName")}</th>
            <th scope="col">{t("policy.fields.classification")}</th>
            <th scope="col">{t("policy.fields.description")}</th>
          </tr>
        </thead>
        <tbody>
          {registry.map((entry, index) => (
            <tr key={`${readString(entry, "secretName")}-${index}`}>
              <td className="cell-lead" data-label={t("policy.fields.secretName")}>
                <code className="mono">{readString(entry, "secretName")}</code>
              </td>
              <td data-label={t("policy.fields.classification")}>{readString(entry, "classification")}</td>
              <td data-label={t("policy.fields.description")} className="cell-text">
                {readString(entry, "description") || <span className="muted">—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  return (
    <div className="registry-edit">
      {registry.map((entry, index) => {
        const entryIssues = issuesFor(issues, "secret_registry", index);
        return (
          <div key={index} className={`registry-row${entryIssues.length ? " has-issues" : ""}`}>
            <TextField label={t("policy.fields.secretName")} mono value={readString(entry, "secretName")} onChange={(event) => onChange(registry.map((item, i) => (i === index ? write(item, "secretName", event.currentTarget.value) : item)))} error={fieldError({ issues: entryIssues, field: "secretName" })} spellCheck={false} />
            <TextField label={t("policy.fields.classification")} value={readString(entry, "classification")} onChange={(event) => onChange(registry.map((item, i) => (i === index ? write(item, "classification", event.currentTarget.value) : item)))} error={fieldError({ issues: entryIssues, field: "classification" })} />
            <TextField label={t("policy.fields.description")} optional={t("policy.optional")} value={readString(entry, "description")} onChange={(event) => onChange(registry.map((item, i) => (i === index ? write(item, "description", event.currentTarget.value || undefined) : item)))} />
            <Button size="sm" variant="ghost" icon="trash" className="registry-remove" onClick={() => onChange(registry.filter((_, i) => i !== index))} aria-label={t("policy.registry.remove", { name: readString(entry, "secretName") || index + 1 })} />
            {otherFields(entry, REGISTRY_FIELDS).length ? <p className="rule-others">{t("policy.otherFieldsEdit", { fields: otherFields(entry, REGISTRY_FIELDS).join(", ") })}</p> : null}
          </div>
        );
      })}
      <div>
        <Button size="sm" icon="plus" onClick={() => onChange([...registry, { secretName: "", classification: "" }])}>
          {t("policy.registry.add")}
        </Button>
      </div>
    </div>
  );
}

function DiffList({ title, diff }: { title: string; diff: DiffSummary }) {
  const { t } = useTranslation();
  const rows: Array<[string, string[]]> = [
    [t("policy.conflict.added"), diff.added],
    [t("policy.conflict.removed"), diff.removed],
    [t("policy.conflict.changed"), diff.changed]
  ];
  if (rows.every(([, items]) => !items.length)) return null;
  return (
    <div className="diff-list">
      <p className="diff-title">{title}</p>
      {rows
        .filter(([, items]) => items.length)
        .map(([label, items]) => (
          <p key={label} className="diff-row">
            <span className="diff-label">{label}</span>
            {items.map((item) => (
              <code key={item} className="chip mono">
                {item}
              </code>
            ))}
          </p>
        ))}
    </div>
  );
}

function ConflictPanel({ editing, onDiscard, onKeep }: { editing: Editing; onDiscard: () => void; onKeep: () => void }) {
  const { t } = useTranslation();
  const latest = editing.conflict!;
  const theirs = diffDrafts(toDraft(editing.base.policy), toDraft(latest.policy));
  const mine = diffDrafts(toDraft(editing.base.policy), editing.draft);
  return (
    <Notice
      tone="warn"
      title={t("policy.conflict.title", { version: latest.version })}
      action={
        <span className="notice-actions">
          <Button size="sm" onClick={onKeep}>
            {t("policy.conflict.keep", { version: latest.version })}
          </Button>
          <Button size="sm" variant="ghost" onClick={onDiscard}>
            {t("policy.conflict.discard")}
          </Button>
        </span>
      }
    >
      <p>{t("policy.conflict.body", { base: editing.base.version, version: latest.version })}</p>
      <DiffList title={t("policy.conflict.theirs")} diff={theirs.rules} />
      <DiffList title={t("policy.conflict.theirsRegistry")} diff={theirs.registry} />
      <DiffList title={t("policy.conflict.mine")} diff={mine.rules} />
      <DiffList title={t("policy.conflict.mineRegistry")} diff={mine.registry} />
    </Notice>
  );
}

export default function ExchangePolicyPage() {
  const { t } = useTranslation();
  const { can } = useSession();
  const toast = useToast();
  const canWrite = can("exchangePolicy.write");
  const { state, reload, replace } = useResource("exchange-policy", () => endpoints.exchangePolicy.get());
  const [tab, setTab] = useState<Tab>("rules");
  const [editing, setEditing] = useState<Editing | null>(null);

  const current = state.status === "ready" ? state.data : state.status === "error" ? state.previous : null;
  const shown: Draft | null = editing ? editing.draft : current ? toDraft(current.policy) : null;
  const dirty = editing && current ? !sameDocument(editing.draft, toDraft(editing.base.policy)) : false;

  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  const update = (patch: Partial<Editing>) => setEditing((value) => (value ? { ...value, ...patch } : value));
  const setDraft = (draft: Draft) => update({ draft, json: JSON.stringify(toDocument(draft), null, 2), validated: false, jsonError: null });

  const startEdit = () => {
    if (!current) return;
    const draft = toDraft(current.policy);
    setEditing({ base: current, draft, issues: [], json: JSON.stringify(toDocument(draft), null, 2), jsonError: null, phase: "idle", validated: false, conflict: null, unknown: false, formError: null });
  };

  const onTab = (next: Tab) => {
    if (editing && tab === "json" && next !== "json") {
      try {
        const parsed = JSON.parse(editing.json) as { secret_registry?: unknown; exchange_policy?: unknown };
        if (!Array.isArray(parsed.secret_registry) || !Array.isArray(parsed.exchange_policy)) throw new Error("shape");
        update({ draft: toDraft(parsed as PolicyDocument["policy"]), jsonError: null });
      } catch {
        update({ jsonError: t("policy.json.invalid") });
        return;
      }
    }
    setTab(next);
  };

  /** The draft as the operator sees it; on the JSON tab, the parsed text. */
  const currentDraft = (): Draft | null => {
    if (!editing) return null;
    if (tab !== "json") return editing.draft;
    try {
      const parsed = JSON.parse(editing.json) as { secret_registry?: unknown; exchange_policy?: unknown };
      if (!Array.isArray(parsed.secret_registry) || !Array.isArray(parsed.exchange_policy)) throw new Error("shape");
      const draft = toDraft(parsed as PolicyDocument["policy"]);
      update({ draft, jsonError: null });
      return draft;
    } catch {
      update({ jsonError: t("policy.json.invalid") });
      return null;
    }
  };

  const validate = async (): Promise<boolean> => {
    const draft = currentDraft();
    if (!editing || !draft) return false;
    update({ phase: "validating", formError: null });
    try {
      const result = await endpoints.exchangePolicy.validate(toDocument(draft));
      update({ phase: "idle", issues: result.errors.map(parseIssue), validated: result.valid });
      return result.valid;
    } catch (error) {
      const failure = error instanceof ApiError ? error : null;
      update({ phase: "idle", formError: failure?.issues.length ? null : t("policy.errors.validateFailed", { code: failure?.code ?? "—" }), issues: failure?.issues.map(parseIssue) ?? [] });
      return false;
    }
  };

  const save = async () => {
    const draft = currentDraft();
    if (!editing || !draft) return;
    if (!(await validate())) return;
    update({ phase: "saving", formError: null, unknown: false });
    try {
      const saved = await endpoints.exchangePolicy.save(toDocument(draft), editing.base.version);
      replace(saved);
      setEditing(null);
      toast.show({ tone: "ok", title: t("policy.saved", { version: saved.version }) });
    } catch (error) {
      const failure = error instanceof ApiError ? error : new ApiError(0, "network", String(error));
      if (failure.code === "policy_version_conflict") {
        const latest = await endpoints.exchangePolicy.get().catch(() => null);
        update({ phase: "idle", conflict: latest, formError: latest ? null : t("policy.errors.conflictUnreadable") });
        return;
      }
      if (failure.outcomeUnknown) {
        // Read back: the save may have landed.
        const latest = await endpoints.exchangePolicy.get().catch(() => null);
        if (latest && sameDocument(toDraft(latest.policy), draft) && latest.version > editing.base.version) {
          replace(latest);
          setEditing(null);
          toast.show({ tone: "ok", title: t("policy.saved", { version: latest.version }) });
          return;
        }
        update({ phase: "idle", unknown: true, ...(latest && latest.version !== editing.base.version ? { conflict: latest } : {}) });
        return;
      }
      if (failure.code === "invalid_policy") {
        update({ phase: "idle", issues: failure.issues.map(parseIssue) });
        return;
      }
      update({ phase: "idle", formError: t("policy.errors.saveFailed", { code: failure.code ?? failure.status }) });
    }
  };

  const discard = () => {
    setEditing(null);
    void reload();
  };

  const registryNames = useMemo(() => (shown ? shown.registry.map((entry) => readString(entry, "secretName")).filter(Boolean) : []), [shown]);
  const unplaced = editing?.issues.filter((issue) => issue.section === null || issue.index === null) ?? [];
  const busy = editing?.phase === "validating" || editing?.phase === "saving";

  let body: ReactNode = null;
  if (state.status === "loading") body = <Skeleton lines={6} className="panel-pad" />;
  else if (!current && state.status === "error") body = <ErrorState error={state.error} onRetry={() => void reload()} />;
  else if (shown) {
    if (tab === "rules") {
      body = (
        <div className="rules">
          <p className="rules-note">{t("policy.evaluation")}</p>
          {shown.rules.length === 0 ? <EmptyState icon="policy" title={t("policy.emptyRules")}>{t("policy.emptyRulesBody")}</EmptyState> : null}
          {shown.rules.map((rule, index) =>
            editing ? (
              <RuleEditor
                key={index}
                rule={rule}
                index={index}
                count={shown.rules.length}
                registryNames={registryNames}
                issues={issuesFor(editing.issues, "exchange_policy", index)}
                onChange={(next) => setDraft({ ...editing.draft, rules: editing.draft.rules.map((item, i) => (i === index ? next : item)) })}
                onMove={(delta) => setDraft({ ...editing.draft, rules: move(editing.draft.rules, index, delta) })}
                onRemove={() => setDraft({ ...editing.draft, rules: editing.draft.rules.filter((_, i) => i !== index) })}
              />
            ) : (
              <RuleView key={index} rule={rule} index={index} />
            )
          )}
          {editing ? (
            <div>
              <Button icon="plus" onClick={() => setDraft({ ...editing.draft, rules: [...editing.draft.rules, blankRule(editing.draft)] })}>
                {t("policy.addRule")}
              </Button>
            </div>
          ) : null}
        </div>
      );
    } else if (tab === "registry") {
      body = <RegistryView registry={shown.registry} editing={Boolean(editing)} issues={editing?.issues ?? []} onChange={(registry) => editing && setDraft({ ...editing.draft, registry })} />;
    } else {
      body = editing ? (
        <TextAreaField
          label={t("policy.json.label")}
          hint={t("policy.json.hint")}
          mono
          rows={22}
          value={editing.json}
          onChange={(event) => update({ json: event.currentTarget.value, validated: false, jsonError: null })}
          error={editing.jsonError ?? undefined}
          spellCheck={false}
          className="json-editor"
        />
      ) : (
        <pre className="code-block json-view">{JSON.stringify(toDocument(shown), null, 2)}</pre>
      );
    }
  }

  return (
    <div className="stack">
      <PageHeader
        eyebrow={current ? t("policy.eyebrowVersion", { version: current.version }) : t("policy.eyebrow")}
        title={t("policy.title")}
        description={t("policy.description")}
        actions={
          canWrite && current && !editing ? (
            <Button variant="primary" icon="policy" onClick={startEdit}>
              {t("policy.edit")}
            </Button>
          ) : null
        }
      />
      {!canWrite ? (
        <Notice tone="neutral" icon="lock">
          {t("policy.readOnly")}
        </Notice>
      ) : null}
      {editing?.conflict ? (
        <ConflictPanel
          editing={editing}
          onDiscard={() => {
            replace(editing.conflict!);
            setEditing(null);
          }}
          onKeep={() => {
            replace(editing.conflict!);
            update({ base: editing.conflict!, conflict: null, validated: false });
          }}
        />
      ) : null}
      {editing?.unknown ? (
        <Notice tone="warn" title={t("policy.errors.unknownTitle")}>
          {t("policy.errors.unknownBody")}
        </Notice>
      ) : null}
      {editing?.formError ? <Notice tone="danger">{editing.formError}</Notice> : null}
      {editing && unplaced.length ? (
        <Notice tone="danger" title={t("policy.issuesTitle", { count: editing.issues.length })}>
          <ul className="issue-list">
            {unplaced.map((issue) => (
              <li key={issue.raw}>{issue.raw}</li>
            ))}
          </ul>
        </Notice>
      ) : null}
      {editing && editing.issues.length && !unplaced.length ? <Notice tone="danger" title={t("policy.issuesTitle", { count: editing.issues.length })}>{t("policy.issuesInline")}</Notice> : null}
      {editing?.validated && !editing.issues.length ? <Notice tone="ok">{t("policy.valid")}</Notice> : null}

      <Panel
        flush
        title={
          <SegmentedControl
            label={t("policy.view")}
            value={tab}
            onChange={onTab}
            options={[
              { value: "rules", label: t("policy.tabs.rules"), ...(shown ? { count: shown.rules.length } : {}) },
              { value: "registry", label: t("policy.tabs.registry"), ...(shown ? { count: shown.registry.length } : {}) },
              { value: "json", label: t("policy.tabs.json") }
            ]}
          />
        }
        meta={editing ? (dirty ? t("policy.unsaved") : t("policy.noChanges")) : null}
      >
        <div className={tab === "rules" ? "policy-body is-rules" : "policy-body"}>{body}</div>
      </Panel>

      {editing ? (
        <div className="edit-bar" role="region" aria-label={t("policy.editBar")}>
          <span className="edit-bar-status">{t("policy.editingFrom", { version: editing.base.version })}</span>
          <span className="edit-bar-actions">
            <Button variant="ghost" onClick={discard} disabled={busy}>
              {t("policy.discard")}
            </Button>
            <Button onClick={() => void validate()} busy={editing.phase === "validating"} disabled={busy} icon="check">
              {t("policy.validate")}
            </Button>
            <Button variant="primary" onClick={() => void save()} busy={editing.phase === "saving"} disabled={busy || (!dirty && tab !== "json") || Boolean(editing.conflict)}>
              {t("policy.save")}
            </Button>
          </span>
        </div>
      ) : null}
    </div>
  );
}
