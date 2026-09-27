import { useTranslation } from "react-i18next";
import { useSession } from "../session/session.js";
import { ButtonLink } from "../ui/button.js";
import { Icon } from "../ui/icon.js";
import { PageHeader } from "../ui/layout.js";
import { Gate } from "./auth/gate.js";

export function NotFoundPage() {
  const { t } = useTranslation();
  return (
    <div className="stack">
      <PageHeader eyebrow={t("system.notFound.eyebrow")} title={t("system.notFound.title")} description={t("system.notFound.body")} />
      <div>
        <ButtonLink to="/" icon="overview">
          {t("system.backToOverview")}
        </ButtonLink>
      </div>
    </div>
  );
}

export function ForbiddenPage() {
  const { t } = useTranslation();
  const { session } = useSession();
  return (
    <div className="stack">
      <PageHeader eyebrow={t("system.forbidden.eyebrow")} title={t("system.forbidden.title")} description={t("system.forbidden.body", { role: session ? t(`roles.${session.operator.role}`) : "—" })} />
      <div>
        <ButtonLink to="/" icon="overview">
          {t("system.backToOverview")}
        </ButtonLink>
      </div>
    </div>
  );
}

/** Stable docs-vault record of the retired hosted features. A plain link: nothing is fetched. */
const FREEZE_REGISTER = "https://github.com/tuthan/docs-vault/blob/main/blindpass/docs/product/Roadmap.md#freeze-register";

/**
 * Hosted-product paths (billing, analytics, public offers, signup, email
 * reset). The local controller has none of them; show that plainly with no
 * controls and no redirect to an external offer.
 */
export function UnavailableFeaturePage() {
  const { t } = useTranslation();
  const { state } = useSession();
  const signedIn = state.status === "authenticated";
  return (
    <Gate single>
      <div className="gate-card unavailable-card" data-testid="unavailable-feature">
        <span className="empty-state-mark" aria-hidden="true">
          <Icon name="ban" size={22} />
        </span>
        <div className="gate-card-head">
          <h1 className="gate-card-title">{t("system.removed.title")}</h1>
          <p className="gate-card-body">{t("system.removed.body")}</p>
        </div>
        <a className="text-link" href={FREEZE_REGISTER} rel="noreferrer noopener" target="_blank">
          {t("system.removed.docs")}
          <Icon name="arrow-up-right" size={14} />
        </a>
        <ButtonLink to={signedIn ? "/" : "/login"} variant="secondary" icon={signedIn ? "overview" : "arrow-right"}>
          {signedIn ? t("system.backToOverview") : t("auth.signIn")}
        </ButtonLink>
      </div>
    </Gate>
  );
}
