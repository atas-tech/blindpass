import { useMemo, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../api/client.js";
import * as endpoints from "../api/endpoints.js";
import type { Agent } from "../api/types.js";
import { collectAll, useResource } from "../lib/use-resource.js";
import { useSession } from "../session/session.js";
import { Button } from "../ui/button.js";
import { Dialog } from "../ui/dialog.js";
import { EmptyState, ErrorState, Notice, Skeleton, StatusBadge } from "../ui/feedback.js";
import { TextField } from "../ui/field.js";
import { Identifier, PageHeader, Panel, SegmentedControl } from "../ui/layout.js";
import { SecretReveal } from "../ui/reveal.js";
import { Timestamp } from "../ui/time.js";
import { useToast } from "../ui/toast.js";

type Filter = "all" | "active" | "revoked";
const AGENT_ID = /^[A-Za-z0-9._:@/-]{1,128}$/;

interface Reveal {
  key: string;
  agentId: string;
  kind: "bootstrap" | "replacement";
}

function CreateAgentDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (agent: Agent, key: string) => void }) {
  const { t } = useTranslation();
  const [agentId, setAgentId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [errors, setErrors] = useState<{ agentId?: string; displayName?: string; form?: string }>({});
  const [busy, setBusy] = useState(false);

  const close = () => {
    if (busy) return;
    setAgentId("");
    setDisplayName("");
    setErrors({});
    onClose();
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const id = agentId.trim();
    const name = displayName.trim();
    const next: typeof errors = {};
    if (!AGENT_ID.test(id)) next.agentId = t("agents.errors.agentId");
    if (!name) next.displayName = t("agents.errors.displayName");
    else if (name.length > 160) next.displayName = t("agents.errors.displayNameLong");
    setErrors(next);
    if (next.agentId || next.displayName) return;
    setBusy(true);
    try {
      const created = await endpoints.agents.create(id, name);
      setBusy(false);
      setAgentId("");
      setDisplayName("");
      onCreated(created.agent, created.bootstrap_api_key);
    } catch (error) {
      setBusy(false);
      const failure = error instanceof ApiError ? error : null;
      if (failure?.code === "agent_id_unavailable") setErrors({ agentId: t("agents.errors.taken") });
      else if (failure?.outcomeUnknown) setErrors({ form: t("agents.errors.unknown") });
      else setErrors({ form: t("agents.errors.createFailed", { code: failure?.code ?? "—" }) });
    }
  };

  return (
    <Dialog
      open={open}
      title={t("agents.create.title")}
      description={t("agents.create.body")}
      onClose={close}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={close} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" form="create-agent" variant="primary" icon="plus" busy={busy}>
            {t("agents.create.submit")}
          </Button>
        </>
      }
    >
      <form id="create-agent" className="form-grid" onSubmit={submit} noValidate>
        {errors.form ? <Notice tone="danger">{errors.form}</Notice> : null}
        <TextField label={t("agents.fields.agentId")} hint={t("agents.fields.agentIdHint")} value={agentId} onChange={(event) => setAgentId(event.currentTarget.value)} error={errors.agentId} autoComplete="off" spellCheck={false} mono />
        <TextField label={t("agents.fields.displayName")} value={displayName} onChange={(event) => setDisplayName(event.currentTarget.value)} error={errors.displayName} autoComplete="off" />
      </form>
    </Dialog>
  );
}

function ConfirmAgentAction({ action, agent, busy, error, onCancel, onConfirm }: { action: "rotate" | "revoke" | null; agent: Agent | null; busy: boolean; error: string | null; onCancel: () => void; onConfirm: () => void }) {
  const { t } = useTranslation();
  if (!agent) return null;
  return (
    <Dialog
      open={action !== null}
      title={t(action === "revoke" ? "agents.revoke.title" : "agents.rotate.title", { agent: agent.agent_id })}
      onClose={onCancel}
      dismissible={!busy}
      tone={action === "revoke" ? "danger" : "default"}
      footer={
        <>
          <Button onClick={onCancel} disabled={busy} data-autofocus>
            {t("common.cancel")}
          </Button>
          <Button variant={action === "revoke" ? "danger" : "primary"} icon={action === "revoke" ? "ban" : "rotate"} busy={busy} onClick={onConfirm}>
            {t(action === "revoke" ? "agents.revoke.submit" : "agents.rotate.submit")}
          </Button>
        </>
      }
    >
      <dl className="confirm-scope">
        <div>
          <dt>{t("agents.fields.agentId")}</dt>
          <dd className="mono">{agent.agent_id}</dd>
        </div>
        <div>
          <dt>{t("agents.fields.displayName")}</dt>
          <dd>{agent.display_name}</dd>
        </div>
      </dl>
      <p className="dialog-note">{t(action === "revoke" ? "agents.revoke.body" : "agents.rotate.body")}</p>
      {error ? <Notice tone="danger">{error}</Notice> : null}
    </Dialog>
  );
}

export default function AgentsPage() {
  const { t } = useTranslation();
  const { can } = useSession();
  const toast = useToast();
  const manage = can("agents.manage");
  const { state, reload } = useResource("agents", () => collectAll((cursor) => endpoints.agents.list({ limit: 100, ...(cursor ? { cursor } : {}) })));
  const [filter, setFilter] = useState<Filter>("active");
  const [creating, setCreating] = useState(false);
  const [reveal, setReveal] = useState<Reveal | null>(null);
  const [pending, setPending] = useState<{ action: "rotate" | "revoke"; agent: Agent } | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const agents = state.status === "ready" ? state.data : state.status === "error" ? state.previous : null;
  const counts = useMemo(() => {
    const list = agents ?? [];
    return { all: list.length, active: list.filter((agent) => agent.status === "active").length, revoked: list.filter((agent) => agent.status === "revoked").length };
  }, [agents]);
  const shown = (agents ?? []).filter((agent) => filter === "all" || agent.status === filter).sort((a, b) => a.agent_id.localeCompare(b.agent_id));

  const runAction = async () => {
    if (!pending) return;
    setBusy(true);
    setActionError(null);
    try {
      if (pending.action === "rotate") {
        const rotated = await endpoints.agents.rotate(pending.agent.id);
        setReveal({ key: rotated.bootstrap_api_key, agentId: rotated.agent.agent_id, kind: "replacement" });
      } else {
        await endpoints.agents.revoke(pending.agent.id);
        toast.show({ tone: "ok", title: t("agents.revoke.done", { agent: pending.agent.agent_id }) });
      }
      setPending(null);
      void reload();
    } catch (error) {
      const failure = error instanceof ApiError ? error : null;
      if (failure?.outcomeUnknown) {
        setActionError(t(pending.action === "rotate" ? "agents.errors.rotateUnknown" : "agents.errors.revokeUnknown"));
        void reload();
      } else if (failure?.status === 404) {
        setActionError(t("agents.errors.gone"));
        void reload();
      } else {
        setActionError(t("agents.errors.actionFailed", { code: failure?.code ?? "—" }));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <PageHeader
        eyebrow={t("agents.eyebrow")}
        title={t("agents.title")}
        description={t("agents.description")}
        actions={
          manage ? (
            <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
              {t("agents.create.open")}
            </Button>
          ) : null
        }
      />
      <div className="toolbar">
        <SegmentedControl
          label={t("agents.filter")}
          value={filter}
          onChange={setFilter}
          options={(["active", "revoked", "all"] as const).map((value) => ({ value, label: t(`agents.filters.${value}`), ...(agents ? { count: counts[value] } : {}) }))}
        />
      </div>
      <Panel flush>
        {state.status === "loading" ? <Skeleton lines={4} className="panel-pad" /> : null}
        {state.status === "error" ? (
          <div className="panel-pad">
            <ErrorState error={state.error} onRetry={() => void reload()} />
          </div>
        ) : null}
        {agents && shown.length === 0 && state.status === "ready" ? (
          <EmptyState icon="agents" title={t(filter === "revoked" ? "agents.empty.revoked" : "agents.empty.title")}>
            {filter === "revoked" ? null : t("agents.empty.body")}
          </EmptyState>
        ) : null}
        {shown.length > 0 ? (
          <table className="data-table is-responsive">
            <thead>
              <tr>
                <th scope="col">{t("agents.columns.agent")}</th>
                <th scope="col">{t("agents.columns.status")}</th>
                <th scope="col">{t("agents.columns.created")}</th>
                <th scope="col">
                  <span className="sr-only">{t("agents.columns.actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.map((agent) => (
                <tr key={agent.id} data-agent={agent.agent_id}>
                  <td className="cell-lead" data-label={t("agents.columns.agent")}>
                    <span className="cell-primary">
                      <span className="cell-title">{agent.display_name}</span>
                      <Identifier value={agent.agent_id} />
                    </span>
                  </td>
                  <td data-label={t("agents.columns.status")}>
                    {agent.status === "active" ? <StatusBadge tone="ok">{t("agents.status.active")}</StatusBadge> : <StatusBadge tone="neutral" icon="ban">{t("agents.status.revoked")}</StatusBadge>}
                    {agent.revoked_at ? (
                      <span className="cell-sub">
                        <Timestamp value={agent.revoked_at} />
                      </span>
                    ) : null}
                  </td>
                  <td data-label={t("agents.columns.created")}>
                    <Timestamp value={agent.created_at} />
                  </td>
                  <td className="cell-actions">
                    {manage && agent.status === "active" ? (
                      <>
                        <Button size="sm" icon="rotate" onClick={() => (setActionError(null), setPending({ action: "rotate", agent }))} aria-label={t("agents.rotate.label", { agent: agent.agent_id })}>
                          {t("agents.rotate.short")}
                        </Button>
                        <Button size="sm" variant="ghost" icon="ban" onClick={() => (setActionError(null), setPending({ action: "revoke", agent }))} aria-label={t("agents.revoke.label", { agent: agent.agent_id })}>
                          {t("agents.revoke.short")}
                        </Button>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </Panel>
      <Notice tone="neutral" icon="info">
        {t("agents.boundary")}
      </Notice>

      <CreateAgentDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(agent, key) => {
          setCreating(false);
          setReveal({ key, agentId: agent.agent_id, kind: "bootstrap" });
          void reload();
        }}
      />
      <ConfirmAgentAction action={pending?.action ?? null} agent={pending?.agent ?? null} busy={busy} error={actionError} onCancel={() => !busy && setPending(null)} onConfirm={() => void runAction()} />
      <SecretReveal
        value={reveal?.key ?? null}
        title={t(reveal?.kind === "replacement" ? "agents.reveal.replacementTitle" : "agents.reveal.bootstrapTitle", { agent: reveal?.agentId ?? "" })}
        description={t(reveal?.kind === "replacement" ? "agents.reveal.replacementBody" : "agents.reveal.bootstrapBody")}
        label={t("agents.reveal.label")}
        onClose={() => setReveal(null)}
      />
    </div>
  );
}
