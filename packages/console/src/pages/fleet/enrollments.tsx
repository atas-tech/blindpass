import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { Enrollment } from "../../api/types.js";
import { normalizeFingerprint } from "../../lib/format.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Dialog } from "../../ui/dialog.js";
import { Notice } from "../../ui/feedback.js";
import { TextField } from "../../ui/field.js";
import { CopyButton, KeyValue, PageHeader, Panel, UntrustedText } from "../../ui/layout.js";
import { SecretReveal } from "../../ui/reveal.js";
import { Countdown, Timestamp } from "../../ui/time.js";
import { useToast } from "../../ui/toast.js";
import { EnrollmentBadge, Fingerprint, FLEET_POLL, formatCapabilities, ListBody, usePagedList } from "./common.js";
import { useIssuerFingerprint } from "./issuer.js";

function CreateEnrollment({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (created: { name: string; token: string; expiresAt: number }) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const close = () => {
    if (busy) return;
    setName("");
    setError(null);
    onClose();
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const value = name.trim();
    // eslint-disable-next-line no-control-regex
    if (!value || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) return setError(t("fleet.enrollment.errors.name"));
    setBusy(true);
    try {
      const created = await endpoints.enrollments.create(value);
      setName("");
      setError(null);
      onCreated({ name: value, token: created.token, expiresAt: created.expires_at });
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      setError(apiError?.outcomeUnknown ? t("fleet.enrollment.errors.createUnknown") : t("fleet.errors.actionFailed", { code: apiError?.code ?? "—" }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={open}
      title={t("fleet.enrollment.create.title")}
      description={t("fleet.enrollment.create.body")}
      onClose={close}
      dismissible={!busy}
      footer={
        <>
          <Button onClick={close} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" form="create-enrollment" variant="primary" icon="plus" busy={busy}>
            {t("fleet.enrollment.create.submit")}
          </Button>
        </>
      }
    >
      <form id="create-enrollment" className="form-grid" onSubmit={submit} noValidate>
        <TextField label={t("fleet.enrollment.fields.name")} hint={t("fleet.enrollment.fields.nameHint")} value={name} onChange={(event) => setName(event.currentTarget.value)} error={error ?? undefined} autoComplete="off" />
      </form>
    </Dialog>
  );
}

/** Approve only after the operator enters the fingerprint the node printed and it matches exactly. */
function ReviewEnrollment({ enrollment, onClose, onDecided }: { enrollment: Enrollment | null; onClose: () => void; onDecided: (verb: "approve" | "reject") => void }) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmReject, setConfirmReject] = useState(false);
  useEffect(() => {
    setTyped("");
    setError(null);
    setConfirmReject(false);
  }, [enrollment?.id]);
  if (!enrollment) return <Dialog open={false} title="" onClose={onClose} />;
  const expected = enrollment.fingerprint ?? "";
  const normalized = normalizeFingerprint(typed);
  const complete = normalized.length === 64;
  const matches = complete && normalized === expected;

  const decide = async (verb: "approve" | "reject") => {
    setBusy(verb);
    setError(null);
    try {
      await endpoints.enrollments.decide(enrollment.id, verb, verb === "approve" ? normalized : expected, enrollment.version);
      onDecided(verb);
    } catch (failure) {
      const apiError = failure instanceof ApiError ? failure : null;
      const code = apiError?.code ?? "";
      if (code === "enrollment_changed") setError(t("fleet.enrollment.errors.changed"));
      else if (code === "enrollment_key_reused") setError(t("fleet.enrollment.errors.keyReused"));
      else if (code === "enrollment_expired" || apiError?.status === 410) setError(t("fleet.enrollment.errors.expired"));
      else if (apiError?.outcomeUnknown) setError(t("fleet.enrollment.errors.decideUnknown"));
      else setError(t("fleet.errors.actionFailed", { code: code || "—" }));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Dialog
      open
      size="lg"
      title={t("fleet.enrollment.review.title", { name: enrollment.name })}
      onClose={onClose}
      dismissible={!busy}
      footer={
        <>
          {confirmReject ? (
            <Button variant="danger" icon="cross" busy={busy === "reject"} disabled={Boolean(busy)} onClick={() => void decide("reject")}>
              {t("fleet.enrollment.review.confirmReject")}
            </Button>
          ) : (
            <Button variant="ghost" icon="cross" disabled={Boolean(busy)} onClick={() => setConfirmReject(true)}>
              {t("fleet.enrollment.review.reject")}
            </Button>
          )}
          <Button onClick={onClose} disabled={Boolean(busy)} data-autofocus>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" icon="check" busy={busy === "approve"} disabled={!matches || Boolean(busy)} onClick={() => void decide("approve")}>
            {t("fleet.enrollment.review.approve")}
          </Button>
        </>
      }
    >
      <div className="stack-sm">
        <KeyValue
          items={[
            { label: t("fleet.enrollment.fields.name"), value: enrollment.name },
            { label: t("fleet.fields.protocol"), value: <code className="mono">{enrollment.protocol_version ?? "—"}</code> },
            { label: t("fleet.fields.submitted"), value: <Timestamp value={enrollment.created_at} /> },
            { label: t("fleet.enrollment.fields.expires"), value: <Countdown expiresAt={enrollment.expires_at} /> }
          ]}
        />
        {enrollment.capabilities ? <UntrustedText label={t("fleet.enrollment.review.capabilities")}>{formatCapabilities(enrollment.capabilities)}</UntrustedText> : null}
        <Notice tone="info" icon="fingerprint" title={t("fleet.enrollment.review.instructionTitle")}>
          {t("fleet.enrollment.review.instruction")}
        </Notice>
        <TextField
          label={t("fleet.enrollment.review.fingerprintLabel")}
          hint={t("fleet.enrollment.review.fingerprintHint")}
          value={typed}
          onChange={(event) => setTyped(event.currentTarget.value)}
          mono
          autoComplete="off"
          spellCheck={false}
          error={complete && !matches ? t("fleet.enrollment.review.mismatch") : undefined}
        />
        {matches ? (
          <Notice tone="ok" title={t("fleet.enrollment.review.matchTitle")}>
            <Fingerprint value={expected} />
          </Notice>
        ) : null}
        {error ? <Notice tone="danger">{error}</Notice> : null}
      </div>
    </Dialog>
  );
}

export default function EnrollmentsPage() {
  const { t } = useTranslation();
  const { can } = useSession();
  const toast = useToast();
  const manage = can("enrollments.manage");
  const issuer = useIssuerFingerprint();
  const list = usePagedList("enrollments", (cursor) => endpoints.enrollments.list({ limit: 50, ...(cursor ? { cursor } : {}) }), { poll: FLEET_POLL });
  const [creating, setCreating] = useState(false);
  const [reveal, setReveal] = useState<{ name: string; token: string; expiresAt: number } | null>(null);
  const [reviewing, setReviewing] = useState<Enrollment | null>(null);
  const command = `sudo blindpass-node enroll --controller ${window.location.origin} --issuer-fingerprint ${issuer.value ?? "<issuer-fingerprint>"} --token-stdin`;

  return (
    <div className="stack">
      <PageHeader
        eyebrow={t("fleet.eyebrow")}
        title={t("fleet.enrollment.title")}
        description={t("fleet.enrollment.description")}
        actions={
          manage ? (
            <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
              {t("fleet.enrollment.create.open")}
            </Button>
          ) : null
        }
      />
      <Panel flush>
        <ListBody state={list.state} items={list.items} onRetry={() => void list.reload()} emptyIcon="enrollments" emptyTitle={t("fleet.enrollment.empty")} emptyBody={manage ? t("fleet.enrollment.emptyBody") : undefined}>
          {(items) => (
            <table className="data-table is-responsive">
              <thead>
                <tr>
                  <th scope="col">{t("fleet.enrollment.fields.name")}</th>
                  <th scope="col">{t("fleet.fields.status")}</th>
                  <th scope="col">{t("fleet.fields.created")}</th>
                  <th scope="col">{t("fleet.enrollment.fields.expires")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("fleet.fields.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((enrollment) => (
                  <tr key={enrollment.id} data-enrollment={enrollment.name}>
                    <td className="cell-lead" data-label={t("fleet.enrollment.fields.name")}>
                      <span className="cell-primary">
                        <span className="cell-title">{enrollment.name}</span>
                        <code className="cell-sub">{enrollment.id}</code>
                      </span>
                    </td>
                    <td data-label={t("fleet.fields.status")}>
                      <EnrollmentBadge status={enrollment.status} />
                    </td>
                    <td data-label={t("fleet.fields.created")}>
                      <Timestamp value={enrollment.created_at} relative />
                    </td>
                    <td data-label={t("fleet.enrollment.fields.expires")}>{enrollment.status === "issued" || enrollment.status === "submitted" ? <Countdown expiresAt={enrollment.expires_at} /> : <span className="muted">—</span>}</td>
                    <td className="cell-actions">
                      {manage && enrollment.status === "submitted" ? (
                        <Button size="sm" variant="primary" icon="fingerprint" onClick={() => setReviewing(enrollment)} aria-label={t("fleet.enrollment.review.open", { name: enrollment.name })}>
                          {t("fleet.enrollment.review.short")}
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
        {t("fleet.enrollment.boundary")}
      </Notice>

      <CreateEnrollment
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(created) => {
          setCreating(false);
          setReveal(created);
          void list.reload();
        }}
      />
      <SecretReveal value={reveal?.token ?? null} title={t("fleet.enrollment.reveal.title", { name: reveal?.name ?? "" })} description={t("fleet.enrollment.reveal.body")} label={t("fleet.enrollment.reveal.label")} onClose={() => setReveal(null)}>
        <div className="reveal-steps">
          <p className="reveal-label">{t("fleet.enrollment.reveal.command")}</p>
          <pre className="code-block command-block">{command}</pre>
          <CopyButton value={command} label={t("fleet.enrollment.reveal.copyCommand")} variant="secondary" />
          {issuer.value ? (
            <p className="field-hint">{t("fleet.enrollment.reveal.issuer")}</p>
          ) : (
            <Notice tone="warn">{t(issuer.state === "unavailable" ? "fleet.enrollment.reveal.issuerUnavailable" : "fleet.enrollment.reveal.issuerLoading")}</Notice>
          )}
          {reveal ? (
            <p className="field-hint">
              {t("fleet.enrollment.reveal.expires")} <Countdown expiresAt={reveal.expiresAt} />
            </p>
          ) : null}
        </div>
      </SecretReveal>
      <ReviewEnrollment
        enrollment={reviewing}
        onClose={() => setReviewing(null)}
        onDecided={(verb) => {
          const name = reviewing?.name ?? "";
          setReviewing(null);
          toast.show({ tone: verb === "approve" ? "ok" : "info", title: t(verb === "approve" ? "fleet.enrollment.review.approved" : "fleet.enrollment.review.rejected", { name }) });
          void list.reload();
        }}
      />
    </div>
  );
}
