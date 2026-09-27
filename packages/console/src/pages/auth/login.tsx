import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useNavigate } from "react-router";
import { ApiError } from "../../api/client.js";
import { safeReturnPath } from "../../lib/routing.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Notice } from "../../ui/feedback.js";
import { TextField } from "../../ui/field.js";
import { Icon } from "../../ui/icon.js";
import { Gate } from "./gate.js";

export default function LoginPage() {
  const { t } = useTranslation();
  const { login, state } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<"credentials" | "origin" | "rate" | "failed" | "missing" | null>(null);
  const reason = state.status === "anonymous" ? state.reason : null;

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!username.trim() || !password) {
      setError("missing");
      return;
    }
    setBusy(true);
    try {
      const session = await login(username.trim(), password);
      setPassword("");
      const next = new URLSearchParams(location.search).get("next");
      navigate(session.must_change_password ? "/change-password" : safeReturnPath(next), { replace: true });
    } catch (caught) {
      setPassword("");
      const failure = caught instanceof ApiError ? caught : null;
      if (failure?.kind === "unauthorized") setError("credentials");
      else if (failure?.kind === "csrf") setError("origin");
      else if (failure?.kind === "rate_limited") setError("rate");
      else setError("failed");
    } finally {
      setBusy(false);
    }
  };

  const intro = (
    <>
      <p className="eyebrow">{t("login.eyebrow")}</p>
      <h1 className="gate-title">
        {t("login.titleLead")} <span>{t("login.titleAccent")}</span>
      </h1>
      <p className="gate-lead">{t("login.lead")}</p>
      <ul className="gate-points">
        {(["verified", "decide", "audit"] as const).map((point, index) => (
          <li key={point}>
            <span className="step">{String(index + 1).padStart(2, "0")}</span>
            <span>
              <strong>{t(`login.points.${point}.title`)}</strong>
              {t(`login.points.${point}.body`)}
            </span>
          </li>
        ))}
      </ul>
    </>
  );

  return (
    <Gate intro={intro}>
      <form className="gate-card" onSubmit={onSubmit} noValidate aria-labelledby="login-title">
        <div className="gate-card-head">
          <h2 className="gate-card-title" id="login-title">
            {t("auth.signIn")}
          </h2>
          <p className="gate-card-body">{t("login.formBody")}</p>
        </div>
        {reason === "expired" ? <Notice tone="warn">{t("login.expired")}</Notice> : null}
        {reason === "signed_out" || (location.state as { signedOut?: boolean } | null)?.signedOut ? <Notice tone="neutral">{t("login.signedOut")}</Notice> : null}
        {error === "credentials" ? <Notice tone="danger">{t("login.errors.credentials")}</Notice> : null}
        {error === "missing" ? <Notice tone="danger">{t("login.errors.missing")}</Notice> : null}
        {error === "origin" ? <Notice tone="danger" title={t("auth.errors.origin.title")}>{t("auth.errors.origin.body")}</Notice> : null}
        {error === "rate" ? <Notice tone="warn">{t("login.errors.rate")}</Notice> : null}
        {error === "failed" ? <Notice tone="danger">{t("login.errors.failed")}</Notice> : null}
        <TextField
          label={t("auth.fields.username")}
          autoComplete="username"
          autoCapitalize="off"
          spellCheck={false}
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          disabled={busy}
          data-autofocus
        />
        <TextField
          label={t("auth.fields.password")}
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          disabled={busy}
        />
        <Button type="submit" variant="primary" busy={busy} iconEnd="arrow-right">
          {busy ? t("login.submitting") : t("auth.signIn")}
        </Button>
        <details className="disclosure">
          <summary>
            <Icon name="chevron-right" size={15} className="disclosure-icon" />
            {t("login.recovery.title")}
          </summary>
          <div className="disclosure-body">
            <p>{t("login.recovery.admin")}</p>
            <p>{t("login.recovery.host")}</p>
            <pre className="code-block">blindpass admin reset-password &lt;operator-id&gt;</pre>
            <p className="muted">{t("login.recovery.noEmail")}</p>
          </div>
        </details>
      </form>
    </Gate>
  );
}
