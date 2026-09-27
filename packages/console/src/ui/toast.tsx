import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "./icon.js";

export type ToastTone = "ok" | "info" | "warn" | "danger";

interface ToastItem {
  id: number;
  tone: ToastTone;
  title: string;
  body?: string;
}

interface ToastApi {
  /** Toasts carry metadata only; never pass a key, token or secret. */
  show: (toast: Omit<ToastItem, "id">) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const ICONS = { ok: "check", info: "info", warn: "alert", danger: "alert" } as const;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(1);
  const { t } = useTranslation();

  const dismiss = useCallback((id: number) => setToasts((current) => current.filter((toast) => toast.id !== id)), []);
  const show = useCallback(
    (toast: Omit<ToastItem, "id">) => {
      const id = nextId.current++;
      setToasts((current) => [...current.slice(-3), { ...toast, id }]);
      setTimeout(() => dismiss(id), toast.tone === "danger" ? 9000 : 6000);
    },
    [dismiss]
  );
  const value = useMemo(() => ({ show }), [show]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-region" role="region" aria-label={t("common.notifications")}>
        <ol aria-live="polite" aria-relevant="additions">
          {toasts.map((toast) => (
            <li key={toast.id} className={`toast toast-${toast.tone}`}>
              <Icon name={ICONS[toast.tone]} size={17} className="toast-icon" />
              <div className="toast-copy">
                <p className="toast-title">{toast.title}</p>
                {toast.body ? <p className="toast-body">{toast.body}</p> : null}
              </div>
              <button type="button" className="toast-close" onClick={() => dismiss(toast.id)} aria-label={t("common.dismiss")}>
                <Icon name="close" size={15} />
              </button>
            </li>
          ))}
        </ol>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used inside ToastProvider");
  return value;
}
