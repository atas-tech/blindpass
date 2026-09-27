import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { BrandMark, LocaleSelect } from "../../shell/app-shell.js";

/** Full-page layout for setup, sign-in and other pre-shell screens. */
export function Gate({ intro, children, single = false }: { intro?: ReactNode; children: ReactNode; single?: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="gate">
      <header className="gate-top">
        <BrandMark />
        <LocaleSelect />
      </header>
      <main className={`gate-main${single || !intro ? " is-single" : ""}`} id="main">
        {intro ? <section className="gate-intro">{intro}</section> : null}
        {children}
      </main>
      <footer className="gate-foot">
        <span>{t("gate.footLabel")}</span>
        <span>{t("gate.footDetail")}</span>
      </footer>
    </div>
  );
}
