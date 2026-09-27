import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { FleetNode, Workload } from "../../api/types.js";
import { collectAll, useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { Button, ButtonLink } from "../../ui/button.js";
import { Dialog } from "../../ui/dialog.js";
import { ErrorState, Notice, Skeleton, StatusBadge } from "../../ui/feedback.js";
import { SelectField, TextField } from "../../ui/field.js";
import { Icon } from "../../ui/icon.js";
import { Identifier, KeyValue, PageHeader, Panel, SegmentedControl } from "../../ui/layout.js";
import { Timestamp } from "../../ui/time.js";
import { useToast } from "../../ui/toast.js";
import { ListBody, NodeRef, useNodeNames, usePagedList } from "./common.js";

const ACCOUNT = /^(?:[a-z0-9_.-]{1,32}|uid:[1-9][0-9]{0,9})$/;

interface WorkloadForm {
  node_id: string;
  name: string;
  unit: string;
  account: string;
  consumption_mode: "file" | "socket";
  local_ceiling_seconds: string;
}

type FormErrors = Partial<Record<keyof WorkloadForm | "form", string>>;

function validate(form: WorkloadForm, t: (key: string) => string, creating: boolean): FormErrors {
  const errors: FormErrors = {};
  if (creating && !form.node_id) errors.node_id = t("fleet.workload.errors.node");
  if (creating && (!form.name.trim() || form.name.trim().length > 128)) errors.name = t("fleet.workload.errors.name");
  if (!form.unit.trim() || form.unit.trim().length > 256) errors.unit = t("fleet.workload.errors.unit");
  if (!ACCOUNT.test(form.account.trim())) errors.account = t("fleet.workload.errors.account");
  const ceiling = Number(form.local_ceiling_seconds);
  if (!Number.isInteger(ceiling) || ceiling < 1 || ceiling > 3600) errors.local_ceiling_seconds = t("fleet.workload.errors.ceiling");
  return errors;
}

function serverError(error: unknown, t: (key: string, options?: Record<string, unknown>) => string): FormErrors {
  const failure = error instanceof ApiError ? error : null;
  switch (failure?.code) {
    case "workload_unit_conflict":
      return { unit: t("fleet.workload.errors.unitConflict") };
    case "workload_mode_denied":
      return { consumption_mode: t("fleet.workload.errors.modeDenied") };
    case "workload_ceiling_invalid":
      return { local_ceiling_seconds: t("fleet.workload.errors.ceiling") };
    case "node_unavailable":
      return { node_id: t("fleet.workload.errors.nodeUnavailable") };
    case "workload_changed":
    case "version_conflict":
      return { form: t("fleet.workload.errors.changed") };
    default:
      return { form: failure?.outcomeUnknown ? t("fleet.workload.errors.unknown") : t("fleet.errors.actionFailed", { code: failure?.code ?? "—" }) };
  }
}

function WorkloadFields({ form, setForm, errors, nodes, creating }: { form: WorkloadForm; setForm: (form: WorkloadForm) => void; errors: FormErrors; nodes: FleetNode[] | null; creating: boolean }) {
  const { t } = useTranslation();
  const set = (key: keyof WorkloadForm) => (event: { currentTarget: { value: string } }) => setForm({ ...form, [key]: event.currentTarget.value });
  return (
    <>
      {creating ? (
        <>
          <SelectField label={t("fleet.workload.fields.node")} hint={t("fleet.workload.fields.nodeHint")} value={form.node_id} onChange={set("node_id")} error={errors.node_id}>
            <option value="">{nodes ? t("fleet.workload.chooseNode") : t("common.loading")}</option>
            {(nodes ?? []).map((node) => (
              <option key={node.id} value={node.id}>
                {node.name} · {t(`fleet.node.status.${node.status}`)}
              </option>
            ))}
          </SelectField>
          <TextField label={t("fleet.workload.fields.name")} value={form.name} onChange={set("name")} error={errors.name} autoComplete="off" />
        </>
      ) : null}
      <TextField label={t("fleet.workload.fields.unit")} hint={t("fleet.workload.fields.unitHint")} value={form.unit} onChange={set("unit")} error={errors.unit} mono autoComplete="off" spellCheck={false} />
      <TextField label={t("fleet.workload.fields.account")} hint={t("fleet.workload.fields.accountHint")} value={form.account} onChange={set("account")} error={errors.account} mono autoComplete="off" spellCheck={false} />
      <div className="field">
        <span className="field-label">{t("fleet.workload.fields.mode")}</span>
        <SegmentedControl label={t("fleet.workload.fields.mode")} value={form.consumption_mode} onChange={(value) => setForm({ ...form, consumption_mode: value })} options={[{ value: "file", label: t("approvals.mode.file") }, { value: "socket", label: t("approvals.mode.socket") }]} />
        {errors.consumption_mode ? <p className="field-error">{errors.consumption_mode}</p> : null}
      </div>
      <TextField label={t("fleet.workload.fields.ceiling")} hint={t("fleet.workload.fields.ceilingHint")} value={form.local_ceiling_seconds} onChange={set("local_ceiling_seconds")} error={errors.local_ceiling_seconds} inputMode="numeric" type="number" min={1} max={3600} />
    </>
  );
}

function CreateWorkload({ open, initialNode, onClose, onCreated }: { open: boolean; initialNode: string; onClose: () => void; onCreated: (workload: Workload) => void }) {
  const { t } = useTranslation();
  const nodes = useResource(open ? "workload-nodes" : null, () => collectAll((cursor) => endpoints.nodes.list({ limit: 100, ...(cursor ? { cursor } : {}) })), { enabled: open });
  const empty: WorkloadForm = { node_id: initialNode, name: "", unit: "", account: "", consumption_mode: "file", local_ceiling_seconds: "120" };
  const [form, setForm] = useState<WorkloadForm>(empty);
  const [errors, setErrors] = useState<FormErrors>({});
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) setForm((current) => ({ ...current, node_id: current.node_id || initialNode }));
  }, [open, initialNode]);
  const eligible = nodes.state.status === "ready" ? nodes.state.data.filter((node) => node.status !== "revoked") : null;
  const close = () => {
    if (busy) return;
    setForm(empty);
    setErrors({});
    onClose();
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const found = validate(form, t, true);
    setErrors(found);
    if (Object.keys(found).length) return;
    setBusy(true);
    try {
      const created = await endpoints.workloads.create({ node_id: form.node_id, name: form.name.trim(), unit: form.unit.trim(), account: form.account.trim(), consumption_mode: form.consumption_mode, local_ceiling_seconds: Number(form.local_ceiling_seconds) });
      setForm(empty);
      onCreated(created);
    } catch (failure) {
      setErrors(serverError(failure, t));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={open}
      size="lg"
      title={t("fleet.workload.create.title")}
      description={t("fleet.workload.create.body")}
      onClose={close}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={close} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" form="create-workload" variant="primary" icon="plus" busy={busy}>
            {t("fleet.workload.create.submit")}
          </Button>
        </>
      }
    >
      <form id="create-workload" className="form-grid form-grid-2" onSubmit={submit} noValidate>
        {errors.form ? <Notice tone="danger">{errors.form}</Notice> : null}
        {nodes.state.status === "error" ? <ErrorState error={nodes.state.error} onRetry={() => void nodes.reload()} compact /> : null}
        <WorkloadFields form={form} setForm={setForm} errors={errors} nodes={eligible} creating />
      </form>
    </Dialog>
  );
}

export function WorkloadsPage() {
  const { t } = useTranslation();
  const { can } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const nodeFilter = params.get("node") ?? "";
  const manage = can("workloads.manage");
  const list = usePagedList(`workloads:${nodeFilter}`, (cursor) => endpoints.workloads.list({ limit: 50, ...(nodeFilter ? { node_id: nodeFilter } : {}), ...(cursor ? { cursor } : {}) }));
  const nodeName = useNodeNames();
  const creating = manage && params.get("new") === "1";
  const setCreating = (value: boolean) => {
    const next = new URLSearchParams(params);
    if (value) next.set("new", "1");
    else next.delete("new");
    setParams(next, { replace: true });
  };
  return (
    <div className="stack">
      <PageHeader
        eyebrow={t("fleet.eyebrow")}
        title={t("fleet.workload.title")}
        description={t("fleet.workload.description")}
        actions={
          manage ? (
            <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
              {t("fleet.workload.create.open")}
            </Button>
          ) : null
        }
      />
      {nodeFilter ? (
        <div className="filter-chip">
          <span>{t("fleet.workload.filteredByNode")}</span>
          <code className="mono">{nodeFilter}</code>
          <Button size="sm" variant="quiet" icon="close" aria-label={t("fleet.clearFilter")} onClick={() => setParams({}, { replace: true })} />
        </div>
      ) : null}
      <Panel flush>
        <ListBody state={list.state} items={list.items} onRetry={() => void list.reload()} emptyIcon="workloads" emptyTitle={t("fleet.workload.empty")} emptyBody={manage ? t("fleet.workload.emptyBody") : undefined}>
          {(items) => (
            <table className="data-table is-responsive">
              <thead>
                <tr>
                  <th scope="col">{t("fleet.workload.fields.name")}</th>
                  <th scope="col">{t("fleet.workload.fields.unit")}</th>
                  <th scope="col">{t("fleet.workload.fields.account")}</th>
                  <th scope="col">{t("fleet.workload.fields.mode")}</th>
                  <th scope="col">{t("fleet.fields.status")}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((workload) => (
                  <tr key={workload.id} data-workload={workload.name}>
                    <td className="cell-lead" data-label={t("fleet.workload.fields.name")}>
                      <span className="cell-primary">
                        <Link className="row-link" to={`/workloads/${encodeURIComponent(workload.id)}`}>
                          {workload.name}
                        </Link>
                        <NodeRef className="cell-sub" id={workload.node_id} name={nodeName(workload.node_id)} />
                      </span>
                    </td>
                    <td data-label={t("fleet.workload.fields.unit")}>
                      <code className="mono">{workload.unit}</code>
                    </td>
                    <td data-label={t("fleet.workload.fields.account")}>
                      <code className="mono">{workload.account}</code>
                    </td>
                    <td data-label={t("fleet.workload.fields.mode")}>{t(`approvals.mode.${workload.consumption_mode}`)}</td>
                    <td data-label={t("fleet.fields.status")}>
                      <StatusBadge tone={workload.status === "active" ? "ok" : "neutral"}>{t(`fleet.workload.status.${workload.status}`)}</StatusBadge>
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
        {t("fleet.workload.boundary")}
      </Notice>
      <CreateWorkload
        open={creating}
        initialNode={nodeFilter}
        onClose={() => setCreating(false)}
        onCreated={(workload) => {
          toast.show({ tone: "ok", title: t("fleet.workload.create.done", { name: workload.name }) });
          navigate(`/workloads/${encodeURIComponent(workload.id)}`);
        }}
      />
    </div>
  );
}

export function WorkloadDetailPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const workloadId = decodeURIComponent(id);
  const { can } = useSession();
  const toast = useToast();
  const { state, reload, replace } = useResource(`workload:${workloadId}`, () => endpoints.workloads.get(workloadId));
  const nodeName = useNodeNames();
  const [editing, setEditing] = useState<WorkloadForm | null>(null);
  const [errors, setErrors] = useState<FormErrors>({});
  const [busy, setBusy] = useState<"save" | "revoke" | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  const crumb = (
    <nav className="breadcrumb" aria-label={t("audit.breadcrumb")}>
      <Link to="/workloads">{t("nav.workloads")}</Link>
      <Icon name="chevron-right" size={13} />
      <span aria-current="page">{state.status === "ready" ? state.data.name : workloadId}</span>
    </nav>
  );
  if (state.status === "loading") return <div className="stack">{crumb}<Skeleton lines={6} /></div>;
  if (state.status === "error" && !state.previous) return <div className="stack">{crumb}<ErrorState error={state.error} onRetry={() => void reload()} /></div>;
  const workload = state.status === "ready" ? state.data : state.previous!;
  const manage = can("workloads.manage") && workload.status === "active";

  const startEdit = () => {
    setErrors({});
    setEditing({ node_id: workload.node_id, name: workload.name, unit: workload.unit, account: workload.account, consumption_mode: workload.consumption_mode, local_ceiling_seconds: String(workload.local_ceiling_seconds) });
  };
  const identityChanged = editing ? editing.unit.trim() !== workload.unit || editing.account.trim() !== workload.account || editing.consumption_mode !== workload.consumption_mode : false;
  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!editing) return;
    const found = validate(editing, t, false);
    setErrors(found);
    if (Object.keys(found).length) return;
    const patch: Record<string, unknown> = {};
    if (editing.unit.trim() !== workload.unit) patch.unit = editing.unit.trim();
    if (editing.account.trim() !== workload.account) patch.account = editing.account.trim();
    if (editing.consumption_mode !== workload.consumption_mode) patch.consumption_mode = editing.consumption_mode;
    if (Number(editing.local_ceiling_seconds) !== workload.local_ceiling_seconds) patch.local_ceiling_seconds = Number(editing.local_ceiling_seconds);
    if (!Object.keys(patch).length) return setEditing(null);
    setBusy("save");
    try {
      const updated = await endpoints.workloads.update(workload.id, { ...patch, expected_version: workload.version });
      replace(updated);
      setEditing(null);
      toast.show({ tone: "ok", title: t("fleet.workload.edit.done", { version: updated.registration_version }) });
    } catch (failure) {
      setErrors(serverError(failure, t));
      if (failure instanceof ApiError && (failure.code === "workload_changed" || failure.code === "version_conflict")) void reload();
    } finally {
      setBusy(null);
    }
  };
  const revoke = async () => {
    setBusy("revoke");
    setRevokeError(null);
    try {
      replace(await endpoints.workloads.revoke(workload.id));
      setConfirmRevoke(false);
      toast.show({ tone: "warn", title: t("fleet.workload.revoke.done", { name: workload.name }) });
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      setRevokeError(apiError?.outcomeUnknown ? t("fleet.workload.errors.unknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" }));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="stack">
      {crumb}
      <PageHeader
        eyebrow={t("fleet.workload.eyebrow")}
        title={workload.name}
        meta={<StatusBadge tone={workload.status === "active" ? "ok" : "neutral"}>{t(`fleet.workload.status.${workload.status}`)}</StatusBadge>}
        actions={
          manage && !editing ? (
            <>
              <Button icon="policy" onClick={startEdit}>
                {t("fleet.workload.edit.open")}
              </Button>
              <Button variant="danger" icon="ban" onClick={() => setConfirmRevoke(true)}>
                {t("fleet.workload.revoke.open")}
              </Button>
            </>
          ) : null
        }
      />
      {editing ? (
        <Panel title={t("fleet.workload.edit.title")} icon="workloads">
          <form className="form-grid form-grid-2" onSubmit={save} noValidate>
            {errors.form ? <Notice tone="danger">{errors.form}</Notice> : null}
            <WorkloadFields form={editing} setForm={setEditing} errors={errors} nodes={null} creating={false} />
            {identityChanged ? (
              <Notice tone="warn" title={t("fleet.workload.edit.identityTitle")}>
                {t("fleet.workload.edit.identityBody")}
              </Notice>
            ) : null}
            <div className="form-actions">
              <Button onClick={() => setEditing(null)} disabled={busy === "save"}>
                {t("common.cancel")}
              </Button>
              <Button type="submit" variant="primary" busy={busy === "save"}>
                {t("fleet.workload.edit.submit")}
              </Button>
            </div>
          </form>
        </Panel>
      ) : (
        <Panel title={t("fleet.workload.registration")} icon="workloads" meta={t("fleet.workload.registrationVersion", { version: workload.registration_version })}>
          <KeyValue
            items={[
              { label: t("fleet.workload.fields.node"), value: <NodeRef id={workload.node_id} name={nodeName(workload.node_id)} /> },
              { label: t("fleet.workload.fields.id"), value: <Identifier value={workload.id} /> },
              { label: t("fleet.workload.fields.unit"), value: <code className="mono">{workload.unit}</code> },
              { label: t("fleet.workload.fields.account"), value: <code className="mono">{workload.account}</code> },
              { label: t("fleet.workload.fields.mode"), value: t(`approvals.mode.${workload.consumption_mode}`) },
              { label: t("fleet.workload.fields.ceiling"), value: t("fleet.seconds", { count: workload.local_ceiling_seconds }) },
              { label: t("fleet.fields.created"), value: <Timestamp value={workload.created_at} /> }
            ]}
          />
        </Panel>
      )}
      <Notice tone="neutral" icon="info">
        {t("fleet.workload.identityNote")}
      </Notice>
      {can("grants.read") ? (
        <div>
          <ButtonLink to={`/grants?node=${encodeURIComponent(workload.node_id)}`} size="sm" iconEnd="arrow-right">
            {t("fleet.workload.viewGrants")}
          </ButtonLink>
        </div>
      ) : null}
      <Dialog
        open={confirmRevoke}
        tone="danger"
        title={t("fleet.workload.revoke.title", { name: workload.name })}
        onClose={() => busy !== "revoke" && setConfirmRevoke(false)}
        dismissible={busy !== "revoke"}
        footer={
          <>
            <Button onClick={() => setConfirmRevoke(false)} disabled={busy === "revoke"} data-autofocus>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" icon="ban" busy={busy === "revoke"} onClick={() => void revoke()}>
              {t("fleet.workload.revoke.submit")}
            </Button>
          </>
        }
      >
        <dl className="confirm-scope">
          <div>
            <dt>{t("fleet.workload.fields.node")}</dt>
            <dd>
              {nodeName(workload.node_id) ? `${nodeName(workload.node_id)} · ` : null}
              <span className="mono">{workload.node_id}</span>
            </dd>
          </div>
          <div>
            <dt>{t("fleet.workload.fields.unit")}</dt>
            <dd className="mono">
              {workload.unit} · {workload.account}
            </dd>
          </div>
        </dl>
        <p className="dialog-note">{t("fleet.workload.revoke.body")}</p>
        {revokeError ? <Notice tone="danger">{revokeError}</Notice> : null}
      </Dialog>
    </div>
  );
}
