import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "./button.js";
import { Dialog } from "./dialog.js";
import { Checkbox } from "./field.js";
import { Notice } from "./feedback.js";
import { CopyButton } from "./layout.js";

/**
 * One-time reveal of a credential the controller will never return again.
 * The value lives only in the caller's state for as long as this dialog is
 * open; it is not logged, toasted or kept in any list. Closing requires the
 * operator to confirm they stored it, and Escape cannot skip that step.
 */
export function SecretReveal({ value, title, description, label, onClose, children }: { value: string | null; title: ReactNode; description: ReactNode; label: string; onClose: () => void; children?: ReactNode }) {
  const { t } = useTranslation();
  const [stored, setStored] = useState(false);
  useEffect(() => {
    if (value) setStored(false);
  }, [value]);
  return (
    <Dialog
      open={value !== null}
      title={title}
      onClose={() => stored && onClose()}
      dismissible={stored}
      size="md"
      footer={
        <Button variant="primary" icon="check" disabled={!stored} onClick={onClose}>
          {t("reveal.done")}
        </Button>
      }
    >
      <div className="reveal-box" data-testid="secret-reveal">
        <Notice tone="warn" title={t("reveal.onceTitle")}>
          {description}
        </Notice>
        <div className="reveal-label">{label}</div>
        <code className="reveal-value" data-secret-reveal>
          {value}
        </code>
        <div className="reveal-actions">{value ? <CopyButton value={value} label={t("reveal.copy")} variant="secondary" /> : null}</div>
        {children}
        <Checkbox label={t("reveal.confirm")} checked={stored} onChange={(event) => setStored(event.currentTarget.checked)} data-autofocus />
      </div>
    </Dialog>
  );
}
