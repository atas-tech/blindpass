import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import { setLocale, SUPPORTED_LOCALES, type SupportedLocale } from "../../i18n/index.js";
import { useSession } from "../../session/session.js";
import { Button } from "../../ui/button.js";
import { Notice } from "../../ui/feedback.js";
import { TextField } from "../../ui/field.js";
import { Identifier, KeyValue, PageHeader, Panel, SegmentedControl } from "../../ui/layout.js";
import { Timestamp } from "../../ui/time.js";
import { useToast } from "../../ui/toast.js";
import { PasswordForm } from "../auth/change-password.js";

function ProfilePanel() {
  const { t } = useTranslation();
  const { session, can, reload } = useSession();
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(session?.operator.display_name ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!session) return null;
  const operator = session.operator;
  const canEdit = can("operators.manage");

  const onSave = async (event: FormEvent) => {
    event.preventDefault();
    const trimmed = name.trim();
    if (!trimmed || trimmed.length > 160) {
      setError(t("setup.errors.displayName"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await endpoints.operators.update(operator.id, { display_name: trimmed });
      await reload();
      setEditing(false);
      toast.show({ tone: "ok", title: t("settings.profile.saved") });
    } catch (caught) {
      setError(caught instanceof ApiError && caught.kind === "forbidden" ? t("errors.forbidden.body") : t("settings.profile.saveFailed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title={t("settings.profile.title")} icon="user">
      {editing ? (
        <form className="form-grid" onSubmit={onSave} noValidate>
          {error ? <Notice tone="danger">{error}</Notice> : null}
          <TextField label={t("setup.fields.displayName")} value={name} onChange={(event) => setName(event.target.value)} autoComplete="name" disabled={busy} data-autofocus />
          <div className="form-actions">
            <Button type="submit" variant="primary" busy={busy}>
              {t("common.save")}
            </Button>
            <Button
              onClick={() => {
                setEditing(false);
                setName(operator.display_name);
                setError(null);
              }}
              disabled={busy}
            >
              {t("common.cancel")}
            </Button>
          </div>
        </form>
      ) : (
        <div className="stack-sm">
          <KeyValue
            items={[
              { label: t("setup.fields.displayName"), value: operator.display_name },
              { label: t("auth.fields.username"), value: <span className="mono">{operator.username}</span> },
              { label: t("settings.profile.role"), value: t(`roles.${operator.role}`), hint: t(`roles.${operator.role}Hint`) },
              { label: t("settings.profile.id"), value: <Identifier value={operator.id} /> }
            ]}
          />
          {canEdit ? (
            <div>
              <Button size="sm" icon="settings" onClick={() => setEditing(true)}>
                {t("settings.profile.edit")}
              </Button>
            </div>
          ) : (
            <p className="field-hint">{t("settings.profile.adminOnly")}</p>
          )}
        </div>
      )}
    </Panel>
  );
}

export default function SettingsPage() {
  const { t, i18n } = useTranslation();
  const { session } = useSession();
  const toast = useToast();
  return (
    <div className="stack">
      <PageHeader eyebrow={t("settings.eyebrow")} title={t("settings.title")} description={t("settings.description")} />
      <div className="settings-grid">
        <ProfilePanel />
        <Panel title={t("settings.language.title")} icon="globe">
          <div className="stack-sm">
            <p className="muted">{t("settings.language.body")}</p>
            <SegmentedControl<SupportedLocale>
              label={t("locale.label")}
              value={i18n.language as SupportedLocale}
              options={SUPPORTED_LOCALES.map((locale) => ({ value: locale, label: t(`locale.${locale}`) }))}
              onChange={(locale) => setLocale(locale)}
            />
          </div>
        </Panel>
        <Panel title={t("settings.password.title")} icon="key">
          <PasswordForm submitLabel={t("password.submit")} onDone={() => toast.show({ tone: "ok", title: t("password.changed") })} />
        </Panel>
        <Panel title={t("settings.session.title")} icon="clock">
          <KeyValue
            columns={1}
            items={[
              { label: t("settings.session.expires"), value: <Timestamp value={session?.expires_at} />, hint: t("settings.session.expiresHint") },
              { label: t("settings.session.idle"), value: t("settings.session.idleValue") }
            ]}
          />
        </Panel>
      </div>
    </div>
  );
}
