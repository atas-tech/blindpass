import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { setLocale, SUPPORTED_LOCALES, type SupportedLocale } from "../i18n/index.js";
import { useSession } from "../session/session.js";
import { Button } from "../ui/button.js";
import { Icon } from "../ui/icon.js";
import { useToast } from "../ui/toast.js";
import { formatCountdown } from "../lib/format.js";
import { useNow } from "../ui/time.js";
import { useApprovalCount } from "./approval-count.js";
import { visibleGroups } from "./nav.js";

export function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <span className={`brand${compact ? " is-compact" : ""}`}>
      <span className="brand-mark" aria-hidden="true">
        <i />
        <i />
        <i />
        <i />
      </span>
      <span className="brand-word">
        blindpass<span className="brand-dot">.</span>
      </span>
    </span>
  );
}

export function LocaleSelect({ className }: { className?: string }) {
  const { t, i18n } = useTranslation();
  return (
    <label className={`locale-select${className ? ` ${className}` : ""}`}>
      <Icon name="globe" size={16} />
      <span className="sr-only">{t("locale.label")}</span>
      <select value={i18n.language} onChange={(event) => setLocale(event.target.value as SupportedLocale)}>
        {SUPPORTED_LOCALES.map((locale) => (
          <option key={locale} value={locale}>
            {t(`locale.${locale}`)}
          </option>
        ))}
      </select>
    </label>
  );
}

function ApprovalPill() {
  const { t } = useTranslation();
  const { count, error } = useApprovalCount();
  if (error) {
    return (
      <span className="count-pill is-unknown" data-testid="approval-pill" title={t("approvals.countUnavailable")}>
        ?<span className="sr-only">{t("approvals.countUnavailable")}</span>
      </span>
    );
  }
  if (count === null || count === 0) return null;
  return (
    <span className="count-pill" data-testid="approval-pill">
      {count}
      <span className="sr-only">{t("approvals.pendingCount", { count })}</span>
    </span>
  );
}

function Navigation({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useTranslation();
  const { can, hasFleet } = useSession();
  return (
    <nav className="nav" aria-label={t("nav.label")}>
      {visibleGroups(can, hasFleet).map((group) => (
        <div className="nav-group" key={group.labelKey}>
          <p className="nav-group-label">{t(group.labelKey)}</p>
          <ul>
            {group.items.map((item) => (
              <li key={item.to}>
                <NavLink to={item.to} end={item.end} className="nav-link" onClick={onNavigate}>
                  <Icon name={item.icon} size={17} />
                  <span className="nav-link-label">{t(item.labelKey)}</span>
                  {item.badge === "approvals" ? <ApprovalPill /> : null}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function SidebarFooter() {
  const { t } = useTranslation();
  const { session, logout } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  if (!session) return null;
  const onLogout = async () => {
    setBusy(true);
    try {
      await logout();
      navigate("/login", { replace: true, state: { signedOut: true } });
    } catch {
      toast.show({ tone: "danger", title: t("auth.logoutFailed.title"), body: t("auth.logoutFailed.body") });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="sidebar-footer">
      <div className="operator-card">
        <span className="operator-avatar" aria-hidden="true">
          {(session.operator.display_name || session.operator.username).slice(0, 1).toUpperCase()}
        </span>
        <span className="operator-copy">
          <span className="operator-name">{session.operator.display_name || session.operator.username}</span>
          <span className="operator-role">{t(`roles.${session.operator.role}`)}</span>
        </span>
      </div>
      <Button variant="quiet" icon="logout" onClick={onLogout} busy={busy} className="logout-button" aria-label={t("auth.signOut")} title={t("auth.signOut")} />
    </div>
  );
}

function ControllerCard() {
  const { t } = useTranslation();
  const { capabilities, hasFleet } = useSession();
  if (!capabilities) return null;
  return (
    <div className="controller-card">
      <span className="controller-icon" aria-hidden="true">
        <Icon name="terminal" size={16} />
      </span>
      <span className="controller-copy">
        <span className="controller-name">{t("shell.controller")}</span>
        <span className="controller-meta mono">
          v{capabilities.version} · {hasFleet ? t("shell.fleetEnabled") : t("shell.exchangeOnly")}
        </span>
      </span>
    </div>
  );
}

function SessionExpiryBanner() {
  const { t } = useTranslation();
  const { session, extend } = useSession();
  const toast = useToast();
  const now = useNow(1000);
  const [busy, setBusy] = useState(false);
  if (!session) return null;
  const remaining = session.expires_at - now;
  if (remaining > 60_000 || remaining <= 0) return null;
  const onExtend = async () => {
    setBusy(true);
    try {
      await extend();
    } catch {
      toast.show({ tone: "danger", title: t("session.extendFailed") });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="session-banner" role="status">
      <Icon name="clock" size={16} />
      <p>{t("session.expiresSoon", { time: formatCountdown(remaining) })}</p>
      <Button size="sm" variant="primary" onClick={onExtend} busy={busy}>
        {t("session.staySignedIn")}
      </Button>
    </div>
  );
}

export function AppShell() {
  const { t } = useTranslation();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const drawer = useRef<HTMLDivElement>(null);
  const main = useRef<HTMLElement>(null);
  const location = useLocation();

  // Move focus to the new page heading on navigation so screen-reader and
  // keyboard users land on the content, not at the top of the sidebar.
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    const heading = main.current?.querySelector<HTMLElement>("[data-page-title]");
    (heading ?? main.current)?.focus({ preventScroll: false });
  }, [location.pathname]);

  useEffect(() => {
    if (!drawerOpen) return;
    drawer.current?.querySelector<HTMLElement>("a, button")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDrawerOpen(false);
        menuButton.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [drawerOpen]);

  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(min-width: 960px)");
    const onChange = () => query.matches && setDrawerOpen(false);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  const closeDrawer = () => {
    if (!drawerOpen) return;
    setDrawerOpen(false);
    menuButton.current?.focus();
  };

  return (
    <div className={`shell${drawerOpen ? " drawer-open" : ""}`}>
      <a className="skip-link" href="#main">
        {t("shell.skipToContent")}
      </a>
      <aside className="sidebar" aria-label={t("shell.sidebar")}>
        <div className="sidebar-brand">
          <BrandMark />
        </div>
        <ControllerCard />
        <Navigation />
        <SidebarFooter />
      </aside>

      <div
        className="drawer"
        id="mobile-navigation"
        ref={drawer}
        role="dialog"
        aria-modal="true"
        aria-label={t("nav.label")}
        hidden={!drawerOpen}
      >
        <div className="drawer-head">
          <BrandMark compact />
          <Button variant="quiet" icon="close" onClick={closeDrawer} aria-label={t("nav.close")} />
        </div>
        <ControllerCard />
        <Navigation onNavigate={closeDrawer} />
        <SidebarFooter />
      </div>
      {drawerOpen ? <div className="drawer-scrim" onClick={closeDrawer} aria-hidden="true" /> : null}

      <div className="main-column" inert={drawerOpen || undefined}>
        <header className="topbar">
          <Button
            ref={menuButton}
            variant="ghost"
            icon="menu"
            className="menu-button"
            onClick={() => setDrawerOpen(true)}
            aria-expanded={drawerOpen}
            aria-controls="mobile-navigation"
            aria-label={t("nav.open")}
          />
          <span className="topbar-brand">
            <BrandMark compact />
          </span>
          <div className="topbar-spacer" />
          <LocaleSelect />
        </header>
        <SessionExpiryBanner />
        <main id="main" ref={main} className="main" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
