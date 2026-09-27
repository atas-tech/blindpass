import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { ApiError } from "../../api/client.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Notice } from "../../ui/feedback.js";
import { TextField } from "../../ui/field.js";
import { Gate } from "./gate.js";
import { validateNewPassword } from "./validation.js";

type Translate = (key: string, options?: Record<string, unknown>) => string;

export function changePasswordError(error: unknown, t: Translate): string {
  const failure = error instanceof ApiError ? error : null;
  if (failure?.code === "invalid_credentials") return t("password.errors.current");
  if (failure?.code === "invalid_password") return t("auth.errors.passwordShort");
  if (failure?.kind === "unauthorized") return t("password.errors.session");
  if (failure?.kind === "csrf") return t("auth.errors.origin.body");
  return t("password.errors.failed");
}

export function PasswordForm({ onDone, submitLabel }: { onDone: () => void; submitLabel: string }) {
  const { t } = useTranslation();
  const { changePassword } = useSession();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const errors = {
    current: current ? null : t("password.errors.currentMissing"),
    next: validateNewPassword(next, t) ?? (next === current && next ? t("password.errors.same") : null),
    confirm: confirm !== next ? t("auth.errors.mismatch") : null
  };

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    setError(null);
    if (Object.values(errors).some(Boolean)) return;
    setBusy(true);
    try {
      await changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setTouched(false);
      onDone();
    } catch (caught) {
      setError(changePasswordError(caught, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="form-grid" onSubmit={onSubmit} noValidate>
      {error ? <Notice tone="danger">{error}</Notice> : null}
      <TextField label={t("password.fields.current")} type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} error={touched ? errors.current : null} disabled={busy} />
      <TextField label={t("auth.fields.newPassword")} type="password" autoComplete="new-password" value={next} onChange={(event) => setNext(event.target.value)} hint={t("auth.passwordRule")} error={touched ? errors.next : null} disabled={busy} />
      <TextField label={t("auth.fields.confirmPassword")} type="password" autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} error={touched ? errors.confirm : null} disabled={busy} />
      <div className="form-actions">
        <Button type="submit" variant="primary" busy={busy}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}

/** Standalone screen used when a temporary password confines the session. */
export default function ChangePasswordPage() {
  const { t } = useTranslation();
  const { session, logout } = useSession();
  const navigate = useNavigate();
  const forced = Boolean(session?.must_change_password);
  return (
    <Gate single>
      <div className="gate-card">
        <div className="gate-card-head">
          <p className="eyebrow">{forced ? t("password.forced.eyebrow") : t("password.eyebrow")}</p>
          <h1 className="gate-card-title">{t("password.title")}</h1>
          <p className="gate-card-body">{forced ? t("password.forced.body", { name: session?.operator.username ?? "" }) : t("password.body")}</p>
        </div>
        <PasswordForm submitLabel={forced ? t("password.forced.submit") : t("password.submit")} onDone={() => navigate("/", { replace: true })} />
        <Button
          variant="quiet"
          icon="logout"
          onClick={() =>
            void logout()
              .then(() => navigate("/login", { replace: true, state: { signedOut: true } }))
              .catch(() => undefined)
          }
        >
          {t("auth.signOut")}
        </Button>
      </div>
    </Gate>
  );
}
