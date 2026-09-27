import { useTranslation } from "react-i18next";

function display(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

/**
 * Audit metadata as key/value text. Values can carry requester-supplied
 * text (a purpose, a hint), so they are rendered as text nodes only.
 */
export function Metadata({ metadata }: { metadata: Record<string, unknown> }) {
  const { t } = useTranslation();
  const entries = Object.entries(metadata);
  if (!entries.length) return <p className="muted">{t("audit.noMetadata")}</p>;
  return (
    <dl className="metadata">
      {entries.map(([key, value]) => (
        <div key={key} className="metadata-row">
          <dt className="mono">{key}</dt>
          <dd className={typeof value === "string" ? "metadata-text" : "metadata-json mono"}>{display(value)}</dd>
        </div>
      ))}
    </dl>
  );
}
