import { useId, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { Operator, Role } from "../../api/types.js";
import { collectAll, useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Dialog } from "../../ui/dialog.js";
import { EmptyState, ErrorState, Notice, Skeleton, StatusBadge } from "../../ui/feedback.js";
import { TextField } from "../../ui/field.js";
import { Identifier, PageHeader, Panel } from "../../ui/layout.js";
import { SecretReveal } from "../../ui/reveal.js";
import { useToast } from "../../ui/toast.js";

const ROLES: Role[] = ["admin", "operator", "viewer"];
const USERNAME = /^[A-Za-z0-9._@-]{3,128}$/;

/**
 * The create contract requires an initial password, but no human should know
 * it: this one lives only in this call and is replaced at once by a server
 * temporary password that forces a change at first sign-in.
 */
function throwawayPassword(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, "");
}

function activeAdmins(operators: Operator[]): number {
  return operators.filter((operator) => operator.role === "admin" && !operator.disabled_at).length;
}

function RoleChoice({ value, current, onChange, disabled, legend }: { value: Role | null; current?: Role; onChange: (role: Role) => void; disabled?: boolean; legend?: string }) {
  const { t } = useTranslation();
  const name = useId();
  return (
    <fieldset className="role-choice" disabled={disabled}>
      <legend className="field-label">{legend ?? t("operators.fields.role")}</legend>
      {ROLES.map((role) => (
        <label key={role} className={value === role ? "role-option is-selected" : "role-option"}>
          <input type="radio" name={name} value={role} checked={value === role} onChange={() => onChange(role)} />
          <span className="role-option-copy">
            <span className="role-option-title">
              {t(`roles.${role}`)}
              {current === role ? <span className="role-option-current">{t("operators.role.current")}</span> : null}
            </span>
            <span className="role-option-hint">{t(`roles.${role}Hint`)}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

function failureCopy(error: unknown, t: (key: string, options?: Record<string, unknown>) => string): { message: string; refresh: boolean } {
  const failure = error instanceof ApiError ? error : null;
  if (failure?.code === "last_admin_required") return { message: t("operators.reasons.lastAdmin"), refresh: true };
  if (failure?.status === 404) return { message: t("operators.errors.gone"), refresh: true };
  if (failure?.outcomeUnknown) return { message: t("operators.errors.unknown"), refresh: true };
  return { message: t("operators.errors.failed", { code: failure?.code ?? "—" }), refresh: false };
}

function CreateOperatorDialog({ open, onClose, onIssued, onCreated }: { open: boolean; onClose: () => void; onIssued: (username: string, password: string) => void; onCreated: () => void }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<Role>("operator");
  const [errors, setErrors] = useState<{ username?: string; displayName?: string; form?: string }>({});
  const [busy, setBusy] = useState(false);
  const [orphan, setOrphan] = useState<Operator | null>(null);

  const reset = () => {
    setUsername("");
    setDisplayName("");
    setRole("operator");
    setErrors({});
    setOrphan(null);
  };
  const close = () => {
    if (busy) return;
    reset();
    onClose();
  };

  const issue = async (operator: Operator) => {
    try {
      const { temporary_password } = await endpoints.operators.resetPassword(operator.id);
      reset();
      onIssued(operator.username, temporary_password);
    } catch {
      setOrphan(operator);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (orphan) return;
    const name = username.trim();
    const display = displayName.trim();
    const next: typeof errors = {};
    if (!USERNAME.test(name)) next.username = t("operators.errors.username");
    if (!display || display.length > 160) next.displayName = t("operators.errors.displayName");
    setErrors(next);
    if (next.username || next.displayName) return;
    setBusy(true);
    try {
      const created = await endpoints.operators.create({ username: name, display_name: display, role, password: throwawayPassword() });
      onCreated();
      await issue(created);
    } catch (error) {
      const failure = error instanceof ApiError ? error : null;
      if (failure?.code === "username_unavailable") setErrors({ username: t("operators.errors.taken") });
      else if (failure?.outcomeUnknown) {
        setErrors({ form: t("operators.errors.createUnknown") });
        onCreated();
      } else setErrors({ form: t("operators.errors.failed", { code: failure?.code ?? "—" }) });
    } finally {
      setBusy(false);
    }
  };

  const retry = async () => {
    if (!orphan) return;
    setBusy(true);
    await issue(orphan);
    setBusy(false);
  };

  return (
    <Dialog
      open={open}
      title={t("operators.create.title")}
      description={t("operators.create.body")}
      onClose={close}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={close} disabled={busy}>
            {t("common.cancel")}
          </Button>
          {orphan ? (
            <Button variant="primary" icon="key" busy={busy} onClick={() => void retry()}>
              {t("operators.create.issue")}
            </Button>
          ) : (
            <Button type="submit" form="create-operator" variant="primary" icon="plus" busy={busy}>
              {t("operators.create.submit")}
            </Button>
          )}
        </>
      }
    >
      <form id="create-operator" className="form-grid" onSubmit={submit} noValidate>
        {orphan ? (
          <Notice tone="warn" title={t("operators.create.partialTitle", { username: orphan.username })}>
            {t("operators.create.partialBody")}
          </Notice>
        ) : null}
        {errors.form ? <Notice tone="danger">{errors.form}</Notice> : null}
        <TextField label={t("operators.fields.username")} hint={errors.username ? undefined : t("operators.fields.usernameHint")} value={username} onChange={(event) => setUsername(event.currentTarget.value)} error={errors.username} autoComplete="off" spellCheck={false} mono disabled={Boolean(orphan)} />
        <TextField label={t("operators.fields.displayName")} value={displayName} onChange={(event) => setDisplayName(event.currentTarget.value)} error={errors.displayName} autoComplete="off" disabled={Boolean(orphan)} />
        <RoleChoice value={role} onChange={setRole} disabled={Boolean(orphan) || busy} />
      </form>
    </Dialog>
  );
}

type Pending = { action: "role" | "reset" | "remove"; operator: Operator };
type DoneResult = { refresh: boolean; keepOpen?: boolean; reveal?: { username: string; password: string }; selfDemoted?: boolean };

function ActionDialog({ pending, isSelf, onCancel, onDone }: { pending: Pending | null; isSelf: boolean; onCancel: () => void; onDone: (result: DoneResult) => void }) {
  const { t } = useTranslation();
  const toast = useToast();
  const [role, setRole] = useState<Role | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const operator = pending?.operator ?? null;
  const action = pending?.action ?? null;

  const cancel = () => {
    if (busy) return;
    setRole(null);
    setError(null);
    onCancel();
  };

  if (!operator || !action) return null;
  const changed = role !== null && role !== operator.role;

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      if (action === "role" && role) {
        await endpoints.operators.update(operator.id, { role });
        toast.show({ tone: "ok", title: t("operators.role.done", { username: operator.username, role: t(`roles.${role}`) }) });
        setRole(null);
        onDone({ refresh: true, selfDemoted: isSelf && role !== "admin" });
      } else if (action === "reset") {
        const { temporary_password } = await endpoints.operators.resetPassword(operator.id);
        onDone({ refresh: false, reveal: { username: operator.username, password: temporary_password } });
      } else if (action === "remove") {
        await endpoints.operators.remove(operator.id);
        toast.show({ tone: "ok", title: t("operators.remove.done", { username: operator.username }) });
        onDone({ refresh: true });
      }
    } catch (caught) {
      const copy = failureCopy(caught, t);
      setError(copy.message);
      if (copy.refresh) onDone({ refresh: true, keepOpen: true });
    } finally {
      setBusy(false);
    }
  };

  const title =
    action === "role" ? (isSelf ? t("operators.role.titleSelf") : t("operators.role.title", { username: operator.username })) : action === "reset" ? t("operators.reset.title", { username: operator.username }) : t("operators.remove.title", { username: operator.username });
  const submitLabel = action === "role" ? t("operators.role.submit") : action === "reset" ? t("operators.reset.submit") : t("operators.remove.submit");

  return (
    <Dialog
      open
      title={title}
      onClose={cancel}
      dismissible={!busy}
      tone={action === "remove" ? "danger" : "default"}
      footer={
        <>
          <Button onClick={cancel} disabled={busy} data-autofocus>
            {t("common.cancel")}
          </Button>
          <Button variant={action === "remove" ? "danger" : "primary"} icon={action === "remove" ? "trash" : action === "reset" ? "key" : "check"} busy={busy} disabled={action === "role" && !changed} onClick={() => void confirm()}>
            {submitLabel}
          </Button>
        </>
      }
    >
      <dl className="confirm-scope">
        <div>
          <dt>{t("operators.fields.username")}</dt>
          <dd className="mono">{operator.username}</dd>
        </div>
        <div>
          <dt>{t("operators.fields.displayName")}</dt>
          <dd>{operator.display_name}</dd>
        </div>
        <div>
          <dt>{t("operators.fields.role")}</dt>
          <dd>{changed ? t("operators.role.transition", { from: t(`roles.${operator.role}`), to: t(`roles.${role}`) }) : t(`roles.${operator.role}`)}</dd>
        </div>
        <div>
          <dt>{t("operators.fields.id")}</dt>
          <dd className="mono">{operator.id}</dd>
        </div>
      </dl>
      {action === "role" ? (
        <>
          <RoleChoice value={role ?? operator.role} current={operator.role} onChange={setRole} disabled={busy} legend={t("operators.fields.newRole")} />
          <p className="dialog-note">{t("operators.role.effect")}</p>
          {isSelf && changed && role !== "admin" ? <Notice tone="warn">{t("operators.role.selfWarning")}</Notice> : null}
        </>
      ) : (
        <p className="dialog-note">{t(action === "reset" ? "operators.reset.body" : "operators.remove.body")}</p>
      )}
      {error ? <Notice tone="danger">{error}</Notice> : null}
    </Dialog>
  );
}

export default function OperatorsPage() {
  const { t } = useTranslation();
  const { session, reload: reloadSession } = useSession();
  const navigate = useNavigate();
  const reasonId = useId();
  const { state, reload } = useResource("operators", () => collectAll((cursor) => endpoints.operators.list({ limit: 100, ...(cursor ? { cursor } : {}) })));
  const [creating, setCreating] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [reveal, setReveal] = useState<{ username: string; password: string } | null>(null);

  const operators = state.status === "ready" ? state.data : state.status === "error" ? state.previous : null;
  const me = session?.operator.id;
  const admins = activeAdmins(operators ?? []);
  const sorted = [...(operators ?? [])].sort((a, b) => ROLES.indexOf(a.role) - ROLES.indexOf(b.role) || a.username.localeCompare(b.username));

  return (
    <div className="stack">
      <PageHeader
        eyebrow={t("operators.eyebrow")}
        title={t("operators.title")}
        description={t("operators.description")}
        actions={
          <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
            {t("operators.create.open")}
          </Button>
        }
      />
      <Panel flush>
        {state.status === "loading" ? <Skeleton lines={4} className="panel-pad" /> : null}
        {state.status === "error" ? (
          <div className="panel-pad">
            <ErrorState error={state.error} onRetry={() => void reload()} />
          </div>
        ) : null}
        {operators && operators.length === 0 ? <EmptyState icon="operators" title={t("operators.empty")} /> : null}
        {sorted.length > 0 ? (
          <table className="data-table is-responsive">
            <thead>
              <tr>
                <th scope="col">{t("operators.columns.operator")}</th>
                <th scope="col">{t("operators.columns.role")}</th>
                <th scope="col">
                  <span className="sr-only">{t("operators.columns.actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((operator, index) => {
                const self = operator.id === me;
                const lastAdmin = operator.role === "admin" && admins <= 1;
                const roleReason = lastAdmin ? "lastAdmin" : null;
                const removeReason = lastAdmin ? "lastAdmin" : self ? "selfRemove" : null;
                const resetReason = self ? "selfReset" : null;
                const reasons = [...new Set([roleReason, removeReason, resetReason].filter((reason): reason is string => reason !== null))];
                const reasonFor = (reason: string | null) => (reason ? `${reasonId}-${index}-${reason}` : undefined);
                return (
                  <tr key={operator.id} data-operator={operator.username}>
                    <td className="cell-lead" data-label={t("operators.columns.operator")}>
                      <span className="cell-primary">
                        <span className="cell-title">
                          <span>{operator.display_name}</span>
                          {self ? <span className="you-tag">{t("operators.you")}</span> : null}
                        </span>
                        <code className="cell-sub">{operator.username}</code>
                      </span>
                    </td>
                    <td data-label={t("operators.columns.role")}>
                      <span className="cell-stack">
                        <StatusBadge tone={operator.role === "admin" ? "info" : "neutral"} icon={operator.role === "admin" ? "lock" : operator.role === "operator" ? "approvals" : "eye"}>
                          {t(`roles.${operator.role}`)}
                        </StatusBadge>
                        <span className="cell-note">{t(`roles.${operator.role}Hint`)}</span>
                      </span>
                    </td>
                    <td className="cell-actions">
                      <div className="action-cluster">
                        <Button size="sm" icon="operators" disabled={Boolean(roleReason)} aria-describedby={reasonFor(roleReason)} aria-label={t("operators.role.label", { username: operator.username })} onClick={() => setPending({ action: "role", operator })}>
                          {t("operators.role.short")}
                        </Button>
                        <Button size="sm" icon="key" disabled={Boolean(resetReason)} aria-describedby={reasonFor(resetReason)} aria-label={t("operators.reset.label", { username: operator.username })} onClick={() => setPending({ action: "reset", operator })}>
                          {t("operators.reset.short")}
                        </Button>
                        <Button size="sm" variant="ghost" icon="trash" disabled={Boolean(removeReason)} aria-describedby={reasonFor(removeReason)} aria-label={t("operators.remove.label", { username: operator.username })} onClick={() => setPending({ action: "remove", operator })}>
                          {t("operators.remove.short")}
                        </Button>
                      </div>
                      {reasons.map((reason) => (
                        <p key={reason} id={reasonFor(reason)} className="action-reason">
                          {t(`operators.reasons.${reason}`)}
                        </p>
                      ))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : null}
      </Panel>
      <Notice tone="neutral" icon="info">
        {t("operators.boundary")}
      </Notice>

      <CreateOperatorDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={() => void reload()}
        onIssued={(username, password) => {
          setCreating(false);
          setReveal({ username, password });
          void reload();
        }}
      />
      <ActionDialog
        key={pending ? `${pending.action}:${pending.operator.id}` : "none"}
        pending={pending}
        isSelf={pending?.operator.id === me}
        onCancel={() => setPending(null)}
        onDone={(result) => {
          if (result.refresh) void reload();
          if (result.keepOpen) return;
          setPending(null);
          if (result.reveal) setReveal(result.reveal);
          if (result.selfDemoted) void reloadSession().then(() => navigate("/", { replace: true }));
        }}
      />
      <SecretReveal value={reveal?.password ?? null} title={t("operators.reveal.title", { username: reveal?.username ?? "" })} description={t("operators.reveal.body")} label={t("operators.reveal.label")} onClose={() => setReveal(null)} />
    </div>
  );
}
