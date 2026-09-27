import { useTranslation } from "react-i18next";
import { useSession } from "../session/session.js";
import { PageHeader } from "../ui/layout.js";

export default function OverviewPage() {
  const { t } = useTranslation();
  const { session } = useSession();
  return (
    <div className="stack">
      <PageHeader eyebrow={t("overview.eyebrow")} title={t("overview.greeting", { name: session?.operator.display_name ?? "" })} description={t("overview.description")} />
    </div>
  );
}
