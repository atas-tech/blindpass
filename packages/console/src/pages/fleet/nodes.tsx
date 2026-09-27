import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { FleetNode } from "../../api/types.js";
import { normalizeFingerprint } from "../../lib/format.js";
import { useResource } from "../../lib/use-resource.js";
import { useSession } from "../../session/session.js";
import { Button, ButtonLink } from "../../ui/button.js";
import { Dialog } from "../../ui/dialog.js";
import { ErrorState, Notice, Skeleton } from "../../ui/feedback.js";
import { TextField } from "../../ui/field.js";
import { Icon } from "../../ui/icon.js";
import { Identifier, KeyValue, PageHeader, Panel, UntrustedText } from "../../ui/layout.js";
import { Timestamp } from "../../ui/time.js";
import { useToast } from "../../ui/toast.js";
import { Fingerprint, FLEET_POLL, formatCapabilities, GrantBadge, ListBody, NodeStatusBadge, usePagedList } from "./common.js";

const KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function LastSeen({ node }: { node: FleetNode }) {
  const { t } = useTranslation();
  if (!node.last_seen_at) return <span className="muted">{t("fleet.node.neverSeen")}</span>;
  return <Timestamp value={node.last_seen_at} relative />;
}

export function NodesPage() {
  const { t } = useTranslation();
  const list = usePagedList("nodes", (cursor) => endpoints.nodes.list({ limit: 50, ...(cursor ? { cursor } : {}) }), { poll: FLEET_POLL });
  return (
    <div className="stack">
      <PageHeader eyebrow={t("fleet.eyebrow")} title={t("fleet.node.title")} description={t("fleet.node.description")} />
      <Panel flush>
        <ListBody state={list.state} items={list.items} onRetry={() => void list.reload()} emptyIcon="nodes" emptyTitle={t("fleet.node.empty")} emptyBody={t("fleet.node.emptyBody")}>
          {(items) => (
            <table className="data-table is-responsive">
              <thead>
                <tr>
                  <th scope="col">{t("fleet.node.fields.name")}</th>
                  <th scope="col">{t("fleet.fields.status")}</th>
                  <th scope="col">{t("fleet.node.fields.lastSeen")}</th>
                  <th scope="col">{t("fleet.node.fields.key")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("fleet.fields.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((node) => (
                  <tr key={node.id} data-node={node.name}>
                    <td className="cell-lead" data-label={t("fleet.node.fields.name")}>
                      <span className="cell-primary">
                        <Link className="row-link" to={`/nodes/${encodeURIComponent(node.id)}`}>
                          {node.name}
                        </Link>
                        <code className="cell-sub">{node.id}</code>
                      </span>
                    </td>
                    <td data-label={t("fleet.fields.status")}>
                      <NodeStatusBadge node={node} />
                    </td>
                    <td data-label={t("fleet.node.fields.lastSeen")}>
                      <LastSeen node={node} />
                    </td>
                    <td data-label={t("fleet.node.fields.key")}>
                      <span className="mono">v{node.key_version}</span>
                    </td>
                    <td className="cell-actions">
                      <ButtonLink to={`/nodes/${encodeURIComponent(node.id)}`} size="sm" iconEnd="arrow-right" aria-label={t("fleet.node.open", { name: node.name })}>
                        {t("common.details")}
                      </ButtonLink>
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
        {t("fleet.node.boundary")}
      </Notice>
    </div>
  );
}

function RevokeNode({ node, open, onClose, onDone }: { node: FleetNode; open: boolean; onClose: () => void; onDone: (node: FleetNode) => void }) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = () => {
    if (busy) return;
    setTyped("");
    setError(null);
    onClose();
  };
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      onDone(await endpoints.nodes.revoke(node.id));
      setTyped("");
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      setError(apiError?.outcomeUnknown ? t("fleet.node.revoke.unknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={open}
      tone="danger"
      title={t("fleet.node.revoke.title", { name: node.name })}
      onClose={close}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={close} disabled={busy} data-autofocus>
            {t("common.cancel")}
          </Button>
          <Button variant="danger" icon="ban" busy={busy} disabled={typed.trim() !== node.name} onClick={() => void run()}>
            {t("fleet.node.revoke.submit")}
          </Button>
        </>
      }
    >
      <div className="stack-sm">
        <p>{t("fleet.node.revoke.body")}</p>
        <dl className="confirm-scope">
          <div>
            <dt>{t("fleet.node.fields.id")}</dt>
            <dd className="mono">{node.id}</dd>
          </div>
          <div>
            <dt>{t("fleet.node.fields.signing")}</dt>
            <dd>
              <Fingerprint value={node.signing_fingerprint} />
            </dd>
          </div>
        </dl>
        <TextField label={t("fleet.node.revoke.typeName", { name: node.name })} value={typed} onChange={(event) => setTyped(event.currentTarget.value)} autoComplete="off" spellCheck={false} />
        {error ? <Notice tone="danger">{error}</Notice> : null}
      </div>
    </Dialog>
  );
}

function RotateNodeKey({ node, open, onClose, onDone }: { node: FleetNode; open: boolean; onClose: () => void; onDone: (node: FleetNode) => void }) {
  const { t } = useTranslation();
  const [values, setValues] = useState({ signing: "", recipient: "", fingerprint: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const valid = KEY_PATTERN.test(values.signing.trim()) && KEY_PATTERN.test(values.recipient.trim()) && /^[a-f0-9]{64}$/.test(normalizeFingerprint(values.fingerprint));
  const close = () => {
    if (busy) return;
    setValues({ signing: "", recipient: "", fingerprint: "" });
    setError(null);
    onClose();
  };
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const staged = await endpoints.nodes.rotateKey(node.id, {
        expected_key_version: node.key_version,
        expected_fingerprint: normalizeFingerprint(values.fingerprint),
        signing_pub: values.signing.trim(),
        recipient_pub: values.recipient.trim()
      });
      onDone(staged);
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      if (apiError?.code === "invalid_key_rotation") setError(t("fleet.node.rotate.invalid"));
      else if (apiError?.code === "node_key_changed" || apiError?.code === "node_changed") setError(t("fleet.node.rotate.changed"));
      else setError(apiError?.outcomeUnknown ? t("fleet.node.rotate.unknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" }));
    } finally {
      setBusy(false);
    }
  };
  const set = (key: keyof typeof values) => (event: React.ChangeEvent<HTMLInputElement>) => setValues((current) => ({ ...current, [key]: event.currentTarget.value }));
  return (
    <Dialog
      open={open}
      size="lg"
      title={t("fleet.node.rotate.title", { name: node.name })}
      description={t("fleet.node.rotate.body")}
      onClose={close}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={close} disabled={busy} data-autofocus>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" icon="rotate" busy={busy} disabled={!valid} onClick={() => void run()}>
            {t("fleet.node.rotate.submit")}
          </Button>
        </>
      }
    >
      <div className="form-grid">
        <pre className="code-block command-block">sudo blindpass-node rotate-prepare</pre>
        <TextField label={t("fleet.node.rotate.signing")} value={values.signing} onChange={set("signing")} mono autoComplete="off" spellCheck={false} />
        <TextField label={t("fleet.node.rotate.recipient")} value={values.recipient} onChange={set("recipient")} mono autoComplete="off" spellCheck={false} />
        <TextField label={t("fleet.node.rotate.fingerprint")} hint={t("fleet.node.rotate.fingerprintHint")} value={values.fingerprint} onChange={set("fingerprint")} mono autoComplete="off" spellCheck={false} />
        {error ? <Notice tone="danger">{error}</Notice> : null}
      </div>
    </Dialog>
  );
}

export function NodeDetailPage() {
  const { t } = useTranslation();
  const { id = "" } = useParams();
  const nodeId = decodeURIComponent(id);
  const { can } = useSession();
  const toast = useToast();
  const { state, reload, replace } = useResource(`node:${nodeId}`, () => endpoints.nodes.get(nodeId), { poll: FLEET_POLL });
  const workloads = useResource(`node-workloads:${nodeId}`, () => endpoints.workloads.list({ node_id: nodeId, limit: 100 }));
  const canGrants = can("grants.read");
  const grants = useResource(canGrants ? `node-grants:${nodeId}` : null, () => endpoints.grants.list({ node_id: nodeId, limit: 20 }), { enabled: canGrants });
  const [dialog, setDialog] = useState<"revoke" | "rotate" | null>(null);

  const crumb = (
    <nav className="breadcrumb" aria-label={t("audit.breadcrumb")}>
      <Link to="/nodes">{t("nav.nodes")}</Link>
      <Icon name="chevron-right" size={13} />
      <span aria-current="page">{state.status === "ready" ? state.data.name : nodeId}</span>
    </nav>
  );
  if (state.status === "loading") return <div className="stack">{crumb}<Skeleton lines={6} /></div>;
  if (state.status === "error" && !state.previous) {
    return (
      <div className="stack">
        {crumb}
        <ErrorState error={state.error} onRetry={() => void reload()} />
      </div>
    );
  }
  const node = state.status === "ready" ? state.data : state.previous!;
  const manage = can("nodes.manage") && node.status !== "revoked";

  return (
    <div className="stack">
      {crumb}
      <PageHeader
        eyebrow={t("fleet.node.eyebrow")}
        title={node.name}
        meta={<NodeStatusBadge node={node} />}
        actions={
          manage ? (
            <>
              <Button icon="rotate" onClick={() => setDialog("rotate")} disabled={node.rotation_pending}>
                {t("fleet.node.rotate.open")}
              </Button>
              <Button variant="danger" icon="ban" onClick={() => setDialog("revoke")}>
                {t("fleet.node.revoke.open")}
              </Button>
            </>
          ) : null
        }
      />
      {state.status === "error" ? <ErrorState error={state.error} onRetry={() => void reload()} compact /> : null}
      {node.revocation_pending ? (
        <Notice tone="warn" icon="clock" title={t("fleet.node.revocationPending")}>
          {t("fleet.node.revocationPendingBody")}
        </Notice>
      ) : node.status === "revoked" ? (
        <Notice tone="neutral" icon="ban" title={t("fleet.node.revokedTitle")}>
          {t("fleet.node.revokedBody")}
        </Notice>
      ) : null}
      {node.rotation_pending ? (
        <Notice tone="info" icon="rotate" title={t("fleet.node.rotationPending")}>
          {t("fleet.node.rotationPendingBody", { version: node.pending_key_version ?? "—" })}
        </Notice>
      ) : null}
      <div className="detail-grid">
        <Panel title={t("fleet.node.identity")} icon="fingerprint">
          <KeyValue
            columns={1}
            items={[
              { label: t("fleet.node.fields.id"), value: <Identifier value={node.id} /> },
              { label: t("fleet.node.fields.signing"), value: <Fingerprint value={node.signing_fingerprint} /> },
              { label: t("fleet.node.fields.recipient"), value: <Fingerprint value={node.recipient_fingerprint} /> },
              { label: t("fleet.node.fields.key"), value: <span className="mono">v{node.key_version}</span> }
            ]}
          />
        </Panel>
        <Panel title={t("fleet.node.connection")} icon="signal">
          <KeyValue
            columns={1}
            items={[
              { label: t("fleet.node.fields.lastSeen"), value: <LastSeen node={node} />, hint: t("fleet.node.lastSeenHint") },
              { label: t("fleet.node.fields.lastPoll"), value: node.last_poll_at ? <Timestamp value={node.last_poll_at} relative /> : <span className="muted">{t("fleet.node.neverSeen")}</span> },
              { label: t("fleet.fields.protocol"), value: <code className="mono">{node.protocol_version}</code> },
              { label: t("fleet.fields.created"), value: <Timestamp value={node.created_at} /> }
            ]}
          />
        </Panel>
      </div>
      <UntrustedText label={t("fleet.node.capabilities")}>{formatCapabilities(node.capabilities)}</UntrustedText>
      <Panel title={t("fleet.node.workloads")} icon="workloads" flush actions={can("workloads.manage") && node.status !== "revoked" ? <ButtonLink to={`/workloads?node=${encodeURIComponent(node.id)}&new=1`} size="sm" icon="plus">{t("fleet.workload.create.open")}</ButtonLink> : null}>
        <ListBody state={workloads.state} items={workloads.state.status === "ready" ? workloads.state.data.items : null} onRetry={() => void workloads.reload()} emptyIcon="workloads" emptyTitle={t("fleet.workload.emptyNode")}>
          {(items) => (
            <ul className="plain-list">
              {items.map((workload) => (
                <li key={workload.id}>
                  <Link to={`/workloads/${encodeURIComponent(workload.id)}`} className="plain-list-link">
                    <span className="cell-title">{workload.name}</span>
                    <code className="mono">{workload.unit}</code>
                    <span className="muted">{workload.status === "revoked" ? t("fleet.workload.status.revoked") : workload.account}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </ListBody>
      </Panel>
      {canGrants ? (
        <Panel title={t("fleet.node.grants")} icon="grants" flush actions={<Link className="text-link" to={`/grants?node=${encodeURIComponent(node.id)}`}>{t("fleet.node.allGrants")} <Icon name="arrow-right" size={14} /></Link>}>
          <ListBody state={grants.state} items={grants.state.status === "ready" ? grants.state.data.items : null} onRetry={() => void grants.reload()} emptyIcon="grants" emptyTitle={t("fleet.grant.emptyNode")}>
            {(items) => (
              <ul className="plain-list">
                {items.map((grant) => (
                  <li key={grant.id} className="plain-list-row">
                    <GrantBadge status={grant.status} />
                    <code className="mono">{grant.unit}</code>
                    <Timestamp value={grant.issued_at} relative />
                  </li>
                ))}
              </ul>
            )}
          </ListBody>
        </Panel>
      ) : null}
      <RevokeNode
        node={node}
        open={dialog === "revoke"}
        onClose={() => setDialog(null)}
        onDone={(revoked) => {
          setDialog(null);
          replace(revoked);
          toast.show({ tone: "warn", title: t("fleet.node.revoke.done", { name: node.name }) });
        }}
      />
      <RotateNodeKey
        node={node}
        open={dialog === "rotate"}
        onClose={() => setDialog(null)}
        onDone={(staged) => {
          setDialog(null);
          replace(staged);
          toast.show({ tone: "info", title: t("fleet.node.rotate.done", { name: node.name }) });
        }}
      />
    </div>
  );
}
