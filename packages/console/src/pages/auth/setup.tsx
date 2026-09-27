import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Notice } from "../../ui/feedback.js";
import { TextField } from "../../ui/field.js";
import { Gate } from "./gate.js";
import { validateAccountName, validateNewPassword } from "./validation.js";

type SetupError = { kind: "token" | "raced" | "origin" | "invalid" | "failed"; code?: string | null } | null;

export default function SetupPage() {
  const { t } = useTranslation();
  const { bootstrap, reload } = useSession();
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<SetupError>(null);

  const errors = {
    token: token.trim().length < 32 ? t("setup.errors.token") : null,
    username: validateAccountName(username.trim(), t),
    displayName: !displayName.trim() ? t("setup.errors.displayName") : displayName.trim().length > 160 ? t("setup.errors.displayNameLong") : null,
    password: validateNewPassword(password, t),
    confirm: confirm !== password ? t("auth.errors.mismatch") : null
  };
  const invalid = Object.values(errors).some(Boolean);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    setError(null);
    if (invalid) return;
    setBusy(true);
    try {
      await bootstrap(token.trim(), { username: username.trim(), display_name: displayName.trim(), password });
      setToken("");
      setPassword("");
      setConfirm("");
      navigate("/", { replace: true });
    } catch (caught) {
      const failure = caught instanceof ApiError ? caught : null;
      if (failure?.status === 409) {
        // Either the token is spent or another administrator won the race.
        // Only the controller knows which; ask it before saying anything.
        setToken("");
        const capabilities = await endpoints.capabilities().catch(() => null);
        if (capabilities && !capabilities.setup_required) {
          setError({ kind: "raced" });
        } else {
          setError({ kind: "token" });
        }
      } else if (failure?.kind === "csrf" || failure?.code === "origin_denied") {
        setError({ kind: "origin" });
      } else if (failure?.kind === "invalid") {
        setError({ kind: "invalid" });
      } else {
        setError({ kind: "failed", code: failure?.code ?? null });
      }
    } finally {
      setBusy(false);
    }
  };

  const intro = (
    <>
      <p className="eyebrow">{t("setup.eyebrow")}</p>
      <h1 className="gate-title">
        {t("setup.titleLead")} <span>{t("setup.titleAccent")}</span>
      </h1>
      <p className="gate-lead">{t("setup.lead")}</p>
      <ol className="gate-points">
        <li>
          <span className="step">01</span>
          <span>
            <strong>{t("setup.steps.token.title")}</strong>
            {t("setup.steps.token.body")}
            <code className="command-line">blindpass admin bootstrap-token</code>
          </span>
        </li>
        <li>
          <span className="step">02</span>
          <span>
            <strong>{t("setup.steps.account.title")}</strong>
            {t("setup.steps.account.body")}
          </span>
        </li>
        <li>
          <span className="step">03</span>
          <span>
            <strong>{t("setup.steps.done.title")}</strong>
            {t("setup.steps.done.body")}
          </span>
        </li>
      </ol>
    </>
  );

  return (
    <Gate intro={intro}>
      <form className="gate-card" onSubmit={onSubmit} noValidate aria-labelledby="setup-title">
        <div className="gate-card-head">
          <h2 className="gate-card-title" id="setup-title">
            {t("setup.formTitle")}
          </h2>
          <p className="gate-card-body">{t("setup.formBody")}</p>
        </div>

        {error?.kind === "raced" ? (
          <Notice
            tone="warn"
            title={t("setup.raced.title")}
            action={
              <Button size="sm" onClick={() => void reload().then(() => navigate("/login", { replace: true }))}>
                {t("auth.signIn")}
              </Button>
            }
          >
            {t("setup.raced.body")}
          </Notice>
        ) : null}
        {error?.kind === "token" ? (
          <Notice tone="danger" title={t("setup.tokenSpent.title")}>
            {t("setup.tokenSpent.body")}
          </Notice>
        ) : null}
        {error?.kind === "origin" ? <Notice tone="danger" title={t("auth.errors.origin.title")}>{t("auth.errors.origin.body")}</Notice> : null}
        {error?.kind === "invalid" ? <Notice tone="danger">{t("setup.errors.rejected")}</Notice> : null}
        {error?.kind === "failed" ? <Notice tone="danger" title={t("errors.server.title")}>{t("setup.errors.failed")}</Notice> : null}

        <TextField
          label={t("setup.fields.token")}
          type="password"
          mono
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="off"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          hint={t("setup.fields.tokenHint")}
          error={touched ? errors.token : null}
          disabled={busy || error?.kind === "raced"}
          data-autofocus
        />
        <div className="form-grid-2">
          <TextField
            label={t("auth.fields.username")}
            autoComplete="username"
            autoCapitalize="off"
            spellCheck={false}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            error={touched ? errors.username : null}
            disabled={busy || error?.kind === "raced"}
          />
          <TextField
            label={t("setup.fields.displayName")}
            autoComplete="name"
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
            error={touched ? errors.displayName : null}
            disabled={busy || error?.kind === "raced"}
          />
        </div>
        <TextField
          label={t("auth.fields.newPassword")}
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          hint={t("auth.passwordRule")}
          error={touched ? errors.password : null}
          disabled={busy || error?.kind === "raced"}
        />
        <TextField
          label={t("auth.fields.confirmPassword")}
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
          error={touched ? errors.confirm : null}
          disabled={busy || error?.kind === "raced"}
        />
        <Button type="submit" variant="primary" busy={busy} disabled={error?.kind === "raced"} iconEnd="arrow-right">
          {busy ? t("setup.submitting") : t("setup.submit")}
        </Button>
      </form>
    </Gate>
  );
}
