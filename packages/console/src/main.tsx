import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../../../assets/ui/fonts.css";
import "../../../assets/ui/tokens.css";
import "./styles/base.css";
import "./styles/components.css";
import "./styles/shell.css";
import "./styles/pages.css";
import "./styles/daily.css";
import "./styles/admin.css";
import { App } from "./app.js";
import { initI18n } from "./i18n/index.js";
import { SessionProvider } from "./session/session.js";
import { ToastProvider } from "./ui/toast.js";

await initI18n();

const root = document.getElementById("root");
if (!root) throw new Error("console root element is missing");

createRoot(root).render(
  <StrictMode>
    <ToastProvider>
      <SessionProvider>
        <App />
      </SessionProvider>
    </ToastProvider>
  </StrictMode>
);
