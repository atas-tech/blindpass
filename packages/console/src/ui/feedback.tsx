import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { ApiError } from "../api/client.js";
import { Button } from "./button.js";
import { Icon, type IconName } from "./icon.js";

export type Tone = "ok" | "warn" | "danger" | "info" | "neutral" | "lime";

const TONE_ICON: Record<Tone, IconName> = {
  ok: "check",
  lime: "dot",
  warn: "alert",
  danger: "alert",
  info: "info",
  neutral: "info"
};

/** A status is always an icon plus words; colour is never the only signal. */
export function StatusBadge({ tone, children, icon }: { tone: Tone; children: ReactNode; icon?: IconName }) {
  return (
    <span className={`badge badge-${tone}`}>
      <Icon name={icon ?? TONE_ICON[tone]} size={13} />
      <span>{children}</span>
    </span>
  );
}

export function Notice({ tone = "info", title, children, action, icon }: { tone?: Tone; title?: ReactNode; children?: ReactNode; action?: ReactNode; icon?: IconName }) {
  return (
    <div className={`notice notice-${tone}`} role={tone === "danger" ? "alert" : undefined}>
      <Icon name={icon ?? TONE_ICON[tone]} size={18} className="notice-icon" />
      <div className="notice-body">
        {title ? <p className="notice-title">{title}</p> : null}
        {children ? <div className="notice-text">{children}</div> : null}
      </div>
      {action ? <div className="notice-action">{action}</div> : null}
    </div>
  );
}

export function EmptyState({ icon = "check", title, children, action }: { icon?: IconName; title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <span className="empty-state-mark" aria-hidden="true">
        <Icon name={icon} size={22} />
      </span>
      <p className="empty-state-title">{title}</p>
      {children ? <div className="empty-state-body">{children}</div> : null}
      {action ? <div className="empty-state-action">{action}</div> : null}
    </div>
  );
}

/** Translate a failed read into truthful copy. It never reads as "none". */
export function errorCopy(error: ApiError, t: (key: string, options?: Record<string, unknown>) => string): { title: string; body: string } {
  switch (error.kind) {
    case "forbidden":
      return { title: t("errors.forbidden.title"), body: t("errors.forbidden.body") };
    case "not_found":
      return { title: t("errors.notFound.title"), body: t("errors.notFound.body") };
    case "rate_limited":
      return {
        title: t("errors.rateLimited.title"),
        body: error.retryAfterSeconds ? t("errors.rateLimited.bodyAfter", { seconds: error.retryAfterSeconds }) : t("errors.rateLimited.body")
      };
    case "timeout":
      return { title: t("errors.timeout.title"), body: t("errors.timeout.body") };
    case "network":
      return { title: t("errors.network.title"), body: t("errors.network.body") };
    case "unavailable":
      return error.code === "controller_clock_fenced"
        ? { title: t("errors.clockFenced.title"), body: t("errors.clockFenced.body") }
        : { title: t("errors.unavailable.title"), body: t("errors.unavailable.body") };
    case "password_change_required":
      return { title: t("errors.passwordChange.title"), body: t("errors.passwordChange.body") };
    default:
      return { title: t("errors.server.title"), body: t("errors.server.body", { status: error.status || "—" }) };
  }
}

export function ErrorState({ error, onRetry, compact = false }: { error: ApiError; onRetry?: () => void; compact?: boolean }) {
  const { t } = useTranslation();
  const copy = errorCopy(error, t);
  const retryable = error.kind !== "forbidden" && error.kind !== "not_found";
  return (
    <div className={`error-state${compact ? " is-compact" : ""}`} role="alert" data-error-kind={error.kind}>
      <span className="error-state-mark" aria-hidden="true">
        <Icon name={error.kind === "forbidden" ? "lock" : "alert"} size={compact ? 16 : 20} />
      </span>
      <div className="error-state-copy">
        <p className="error-state-title">{copy.title}</p>
        <p className="error-state-body">{copy.body}</p>
        {error.code && error.kind !== "network" && error.kind !== "timeout" ? <p className="error-state-code mono">{error.code}</p> : null}
      </div>
      {onRetry && retryable ? (
        <Button size="sm" icon="refresh" onClick={onRetry}>
          {t("common.retry")}
        </Button>
      ) : null}
    </div>
  );
}

export function Skeleton({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={`skeleton${className ? ` ${className}` : ""}`} aria-hidden="true">
      {Array.from({ length: lines }, (_, index) => (
        <span key={index} className="skeleton-line" />
      ))}
    </div>
  );
}

export function LoadingBlock({ label }: { label?: string }) {
  const { t } = useTranslation();
  return (
    <div className="loading-block" role="status">
      <span className="spinner" aria-hidden="true" />
      <span>{label ?? t("common.loading")}</span>
    </div>
  );
}
