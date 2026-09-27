// Time and identifier formatting. Controller timestamps arrive as Unix
// milliseconds, Unix seconds or ISO strings depending on the route, so all
// display code goes through toMs().

export function toMs(value: number | string | null | undefined): number | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return null;
    return value < 100_000_000_000 ? value * 1000 : value;
  }
  const numeric = Number(value);
  if (Number.isFinite(numeric) && /^\d+$/.test(value)) return toMs(numeric);
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

const dateTimeCache = new Map<string, Intl.DateTimeFormat>();

function dateTimeFormat(locale: string, options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  const key = `${locale}|${JSON.stringify(options)}`;
  let format = dateTimeCache.get(key);
  if (!format) {
    format = new Intl.DateTimeFormat(locale, options);
    dateTimeCache.set(key, format);
  }
  return format;
}

export function formatDateTime(value: number | string | null | undefined, locale: string): string {
  const ms = toMs(value);
  if (ms === null) return "—";
  return dateTimeFormat(locale, { dateStyle: "medium", timeStyle: "medium" }).format(ms);
}

export function formatTime(value: number | string | null | undefined, locale: string): string {
  const ms = toMs(value);
  if (ms === null) return "—";
  return dateTimeFormat(locale, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(ms);
}

export function formatIsoUtc(value: number | string | null | undefined): string {
  const ms = toMs(value);
  return ms === null ? "" : new Date(ms).toISOString();
}

const UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 365 * 24 * 3600_000],
  ["month", 30 * 24 * 3600_000],
  ["day", 24 * 3600_000],
  ["hour", 3600_000],
  ["minute", 60_000],
  ["second", 1000]
];

export function formatRelative(value: number | string | null | undefined, now: number, locale: string): string {
  const ms = toMs(value);
  if (ms === null) return "—";
  const delta = ms - now;
  const format = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  for (const [unit, size] of UNITS) {
    if (Math.abs(delta) >= size || unit === "second") {
      return format.format(Math.round(delta / size), unit);
    }
  }
  return format.format(0, "second");
}

/** mm:ss or h:mm:ss for a remaining duration; never negative. */
export function formatCountdown(remainingMs: number): string {
  const total = Math.max(0, Math.floor(remainingMs / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const mmss = `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  return hours > 0 ? `${hours}:${mmss}` : mmss;
}

export function formatDurationSeconds(seconds: number | null | undefined, locale: string): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  const parts: string[] = [];
  let rest = Math.max(0, Math.round(seconds));
  const units: Array<[Intl.NumberFormatOptions["unit"], number]> = [
    ["day", 86_400],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1]
  ];
  for (const [unit, size] of units) {
    const count = Math.floor(rest / size);
    if (count > 0 || (unit === "second" && parts.length === 0)) {
      parts.push(new Intl.NumberFormat(locale, { style: "unit", unit, unitDisplay: "short" }).format(count));
    }
    rest -= count * size;
    if (parts.length === 2) break;
  }
  return parts.join(" ");
}

export function formatNumber(value: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(value);
}

/** Group a hex fingerprint into blocks of four for comparison by eye. */
export function groupFingerprint(value: string | null | undefined): string {
  if (!value) return "—";
  const clean = value.replace(/[^0-9a-f]/gi, "").toLowerCase();
  if (!clean) return value;
  return clean.match(/.{1,4}/g)?.join(" ") ?? clean;
}

/** Compare fingerprints ignoring case, spaces and colons. */
export function normalizeFingerprint(value: string): string {
  return value.replace(/[\s:-]/g, "").toLowerCase();
}

export function shortId(value: string | null | undefined, keep = 8): string {
  if (!value) return "—";
  return value.length <= keep + 3 ? value : `${value.slice(0, keep)}…`;
}
