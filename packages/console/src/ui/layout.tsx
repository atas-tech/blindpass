import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { revealControls } from "../lib/format.js";
import { Button } from "./button.js";
import { Icon, type IconName } from "./icon.js";

export function PageHeader({ eyebrow, title, description, actions, meta }: { eyebrow?: ReactNode; title: ReactNode; description?: ReactNode; actions?: ReactNode; meta?: ReactNode }) {
  const ref = useRef<HTMLHeadingElement>(null);
  return (
    <header className="page-header">
      <div className="page-header-copy">
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1 ref={ref} className="page-title" tabIndex={-1} data-page-title>
          {title}
        </h1>
        {description ? <p className="page-description">{description}</p> : null}
        {meta ? <div className="page-meta">{meta}</div> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function Panel({ title, icon, meta, actions, children, className, flush = false, as: As = "section", labelledBy }: { title?: ReactNode; icon?: IconName; meta?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; flush?: boolean; as?: "section" | "div" | "article"; labelledBy?: string }) {
  return (
    <As className={`panel${flush ? " panel-flush" : ""}${className ? ` ${className}` : ""}`} aria-labelledby={labelledBy}>
      {title || actions || meta ? (
        <header className="panel-header">
          <div className="panel-heading">
            {icon ? <Icon name={icon} size={17} className="panel-icon" /> : null}
            {title ? (
              <h2 className="panel-title" id={labelledBy}>
                {title}
              </h2>
            ) : null}
            {meta ? <span className="panel-meta">{meta}</span> : null}
          </div>
          {actions ? <div className="panel-actions">{actions}</div> : null}
        </header>
      ) : null}
      <div className="panel-body">{children}</div>
    </As>
  );
}

export interface KeyValueItem {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  wide?: boolean;
}

export function KeyValue({ items, columns = 2 }: { items: KeyValueItem[]; columns?: 1 | 2 | 3 }) {
  return (
    <dl className={`kv kv-cols-${columns}`}>
      {items.map((item, index) => (
        <div key={index} className={`kv-item${item.wide ? " is-wide" : ""}`}>
          <dt>{item.label}</dt>
          <dd>
            {item.value}
            {item.hint ? <span className="kv-hint">{item.hint}</span> : null}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Monospaced identifier with a copy action. Never used for secrets. */
export function Identifier({ value, display, copy = true, className }: { value: string | null | undefined; display?: string; copy?: boolean; className?: string }) {
  if (!value) return <span className="muted">—</span>;
  return (
    <span className={`identifier${className ? ` ${className}` : ""}`}>
      <code title={value}>{display ?? value}</code>
      {copy ? <CopyButton value={value} /> : null}
    </span>
  );
}

export function CopyButton({ value, label, variant = "quiet" }: { value: string; label?: string; variant?: "quiet" | "secondary" }) {
  const { t } = useTranslation();
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => setState("idle"), 2000);
    return () => clearTimeout(timer);
  }, [state]);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
  };
  const text = state === "copied" ? t("common.copied") : state === "failed" ? t("common.copyFailed") : label ?? t("common.copy");
  return (
    <Button variant={variant} size="sm" icon={state === "copied" ? "check" : "copy"} onClick={onCopy} aria-label={label ? undefined : text} className="copy-button">
      {label ? text : null}
      {!label ? <span className="sr-only" aria-live="polite">{state === "idle" ? "" : text}</span> : null}
    </Button>
  );
}

/**
 * Text supplied by a requester, agent or node. Rendered as a text node
 * with whitespace preserved; never Markdown, never HTML. Invisible control
 * and bidi characters are shown as code points and the block is isolated,
 * so the text can't reorder what surrounds it.
 */
export function UntrustedText({ label, children, empty }: { label: ReactNode; children: string | null | undefined; empty?: ReactNode }) {
  const { t } = useTranslation();
  return (
    <figure className="untrusted">
      <figcaption className="untrusted-label">
        <Icon name="alert" size={14} />
        <span>{label}</span>
        <span className="untrusted-tag">{t("trust.notVerified")}</span>
      </figcaption>
      <blockquote className="untrusted-text" dir="auto">
        {children ? revealControls(children) : <span className="muted">{empty ?? t("trust.empty")}</span>}
      </blockquote>
    </figure>
  );
}

/** Facts the controller established itself, shown apart from requester text. */
export function VerifiedBlock({ title, children, note }: { title: ReactNode; children: ReactNode; note?: ReactNode }) {
  return (
    <section className="verified">
      <header className="verified-label">
        <Icon name="approvals" size={15} />
        <span>{title}</span>
      </header>
      <div className="verified-body">{children}</div>
      {note ? <p className="verified-note">{note}</p> : null}
    </section>
  );
}

export function SegmentedControl<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: Array<{ value: T; label: ReactNode; count?: number }>; onChange: (value: T) => void }) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          aria-checked={option.value === value}
          className={option.value === value ? "is-active" : undefined}
          onClick={() => onChange(option.value)}
          onKeyDown={(event) => {
            if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
            event.preventDefault();
            const index = options.findIndex((item) => item.value === value);
            const next = options[(index + (event.key === "ArrowRight" ? 1 : options.length - 1)) % options.length];
            if (next) {
              onChange(next.value);
              const buttons = (event.currentTarget.parentElement?.querySelectorAll("button") ?? []) as NodeListOf<HTMLButtonElement>;
              buttons[options.indexOf(next)]?.focus();
            }
          }}
          tabIndex={option.value === value ? 0 : -1}
        >
          {option.label}
          {option.count !== undefined ? <span className="segmented-count">{option.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

export function Pager({ hasPrevious, hasNext, onPrevious, onNext, busy }: { hasPrevious: boolean; hasNext: boolean; onPrevious: () => void; onNext: () => void; busy?: boolean }) {
  const { t } = useTranslation();
  if (!hasPrevious && !hasNext) return null;
  return (
    <nav className="pager" aria-label={t("pager.label")}>
      <Button size="sm" icon="chevron-left" onClick={onPrevious} disabled={!hasPrevious || busy}>
        {t("pager.newer")}
      </Button>
      <Button size="sm" iconEnd="chevron-right" onClick={onNext} disabled={!hasNext || busy}>
        {t("pager.older")}
      </Button>
    </nav>
  );
}
