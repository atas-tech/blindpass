import { useEffect, useId, useRef, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "./button.js";

interface DialogProps {
  open: boolean;
  title: ReactNode;
  description?: ReactNode;
  onClose: () => void;
  children?: ReactNode;
  footer?: ReactNode;
  /** Block Escape and backdrop dismissal while a write is in flight. */
  dismissible?: boolean;
  size?: "sm" | "md" | "lg";
  tone?: "default" | "danger";
  initialFocus?: "first" | "none";
}

/**
 * Modal dialog on the native <dialog> element: the browser makes the rest
 * of the page inert, Escape cancels, and focus returns to the opener.
 */
export function Dialog({ open, title, description, onClose, children, footer, dismissible = true, size = "md", tone = "default", initialFocus = "first" }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const opener = useRef<Element | null>(null);
  const titleId = useId();
  const descriptionId = useId();
  const { t } = useTranslation();
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const dismissibleRef = useRef(dismissible);
  dismissibleRef.current = dismissible;

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      opener.current = document.activeElement;
      dialog.showModal();
      if (initialFocus === "first") {
        const target =
          dialog.querySelector<HTMLElement>("[data-autofocus]:not([disabled])") ??
          dialog.querySelector<HTMLElement>(".dialog-body input:not([type=hidden]):not([disabled]), .dialog-body textarea:not([disabled]), .dialog-body select:not([disabled]), .dialog-body button:not([disabled])") ??
          dialog.querySelector<HTMLElement>("button:not([disabled])");
        target?.focus();
      } else {
        dialog.querySelector<HTMLElement>(".dialog-title")?.focus();
      }
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open, initialFocus]);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    const onCancel = (event: Event) => {
      event.preventDefault();
      if (dismissibleRef.current) onCloseRef.current();
    };
    const onNativeClose = () => {
      const target = opener.current;
      if (target instanceof HTMLElement && target.isConnected) target.focus();
    };
    const onPointer = (event: MouseEvent) => {
      if (event.target === dialog && dismissibleRef.current) onCloseRef.current();
    };
    dialog.addEventListener("cancel", onCancel);
    dialog.addEventListener("close", onNativeClose);
    dialog.addEventListener("click", onPointer);
    return () => {
      dialog.removeEventListener("cancel", onCancel);
      dialog.removeEventListener("close", onNativeClose);
      dialog.removeEventListener("click", onPointer);
    };
  }, []);

  return (
    <dialog
      ref={ref}
      className={`dialog dialog-${size}${tone === "danger" ? " dialog-danger" : ""}`}
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
    >
      {open ? (
        <div className="dialog-surface">
          <header className="dialog-header">
            <h2 className="dialog-title" id={titleId} tabIndex={-1}>
              {title}
            </h2>
            <Button variant="quiet" size="sm" icon="close" onClick={onClose} disabled={!dismissible} aria-label={t("common.close")} className="dialog-close" />
          </header>
          {description ? (
            <div className="dialog-description" id={descriptionId}>
              {description}
            </div>
          ) : null}
          {children ? <div className="dialog-body">{children}</div> : null}
          {footer ? <footer className="dialog-footer">{footer}</footer> : null}
        </div>
      ) : null}
    </dialog>
  );
}
