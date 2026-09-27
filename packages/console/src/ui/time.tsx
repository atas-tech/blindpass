import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { serverNow } from "../api/client.js";
import { formatCountdown, formatDateTime, formatIsoUtc, formatRelative, toMs } from "../lib/format.js";
import { Icon } from "./icon.js";

/** Re-render on an interval using the controller-corrected clock. */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => serverNow());
  useEffect(() => {
    const timer = setInterval(() => setNow(serverNow()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);
  return now;
}

export function Timestamp({ value, relative = false }: { value: number | string | null | undefined; relative?: boolean }) {
  const { i18n } = useTranslation();
  const now = useNow(relative ? 15_000 : 3_600_000);
  const ms = toMs(value);
  if (ms === null) return <span className="muted">—</span>;
  const absolute = formatDateTime(ms, i18n.language);
  return (
    <time dateTime={formatIsoUtc(ms)} title={absolute} className="timestamp">
      {relative ? formatRelative(ms, now, i18n.language) : absolute}
    </time>
  );
}

/**
 * Remaining time to a controller deadline. The clock is corrected by the
 * controller's Date header; the value is an estimate and the controller's
 * own expiry check is final.
 */
export function Countdown({ expiresAt, warnBelowMs = 60_000 }: { expiresAt: number | string | null | undefined; warnBelowMs?: number }) {
  const { t } = useTranslation();
  const now = useNow(1000);
  const ms = toMs(expiresAt);
  if (ms === null) return <span className="muted">—</span>;
  const remaining = ms - now;
  if (remaining <= 0) {
    return (
      <span className="countdown is-expired">
        <Icon name="clock" size={13} />
        {t("time.expired")}
      </span>
    );
  }
  return (
    <span className={`countdown${remaining < warnBelowMs ? " is-urgent" : ""}`} title={t("time.estimateNote")}>
      <Icon name="clock" size={13} />
      <span className="sr-only">{t("time.remaining")}</span>
      <span className="mono">{formatCountdown(remaining)}</span>
    </span>
  );
}
