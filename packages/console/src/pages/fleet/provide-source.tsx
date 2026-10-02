import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../../api/client.js";
import * as endpoints from "../../api/endpoints.js";
import type { Operation } from "../../api/types.js";
import { Button } from "../../ui/button.js";
import { LoadingBlock, Notice } from "../../ui/feedback.js";
import { Panel } from "../../ui/layout.js";
import { Countdown } from "../../ui/time.js";

const KEY_PREFIX = "console-source-";
const KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

/**
 * One Source link exists per operation, and an exact retry returns it only for
 * the same key, so the key is derived from the operation alone: a second click,
 * a second tab or a retry after a lost reply all ask for the same link. An id
 * too long to fit the controller's key limit is hashed instead.
 */
export async function provisioningKey(operationId: string): Promise<string> {
  const direct = `${KEY_PREFIX}${operationId}`;
  if (KEY_PATTERN.test(direct)) return direct;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(operationId));
  return `${KEY_PREFIX}h-${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

const FLEET_PARAMETERS = ["kind", "id", "metadata_sig", "submit_sig"];

/**
 * Only the controller's fixed same-origin fleet input path may be opened: the
 * link carries capabilities, so anything else (another origin, another path,
 * extra parameters) is refused rather than followed.
 */
export function inputPageUrl(inputPath: unknown, origin: string = window.location.origin): string | null {
  if (typeof inputPath !== "string" || !inputPath.startsWith("/?kind=fleet&id=")) return null;
  let url: URL;
  try {
    url = new URL(inputPath, origin);
  } catch {
    return null;
  }
  const names = [...url.searchParams.keys()];
  const exact = names.length === FLEET_PARAMETERS.length && FLEET_PARAMETERS.every((name) => names.filter((key) => key === name).length === 1);
  if (url.origin !== origin || url.pathname !== "/" || url.hash !== "" || !exact || url.searchParams.get("kind") !== "fleet") return null;
  return url.toString();
}

type Failure = "pending" | "owner" | "gone" | "conflict" | "unknown" | "failed";

function classify(error: unknown): { key: Failure; code: string } {
  if (!(error instanceof ApiError)) return { key: "failed", code: "invalid_link" };
  if (error.outcomeUnknown) return { key: "unknown", code: error.code ?? "network" };
  if (error.code === "provisioning_offer_pending") return { key: "pending", code: error.code };
  if (error.code === "provisioning_owner_required") return { key: "owner", code: error.code };
  if (error.status === 410) return { key: "gone", code: error.code ?? "gone" };
  if (error.code === "provisioning_link_conflict") return { key: "conflict", code: error.code };
  return { key: "failed", code: error.code ?? String(error.status) };
}

/**
 * Where Source collection stands for a browser operation, and the one action
 * the named owner has. The state comes from the controller's own authority
 * checks; the controller still decides when the button is pressed. The Source is
 * typed on the separate input page: nothing here sees, stores or logs it.
 */
export function ProvideSourcePanel({ operation, onChanged }: { operation: Operation; onChanged: () => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ key: Failure; code: string } | null>(null);
  const [opened, setOpened] = useState(false);
  const provisioning = operation.provisioning;
  if (!provisioning || provisioning.state === "not_applicable") return null;

  const provide = async () => {
    setBusy(true);
    setFailure(null);
    setOpened(false);
    try {
      const link = await endpoints.operations.provisioningLink(operation.id, await provisioningKey(operation.id));
      const url = inputPageUrl(link.input_path);
      if (!url) {
        setFailure({ key: "failed", code: "invalid_link" });
      } else {
        // The link lives only in this call: it is not rendered, kept or logged.
        window.open(url, "_blank", "noopener,noreferrer");
        setOpened(true);
      }
    } catch (error) {
      setFailure(classify(error));
    } finally {
      setBusy(false);
      onChanged();
    }
  };

  const live = provisioning.state === "offer_ready" || provisioning.state === "link_issued";
  return (
    <Panel title={t("fleet.provision.title")} icon="key" labelledBy="provision-title" className="provision-panel">
      <div className="stack" data-provisioning={provisioning.state}>
        {provisioning.state === "awaiting_offer" ? (
          <>
            <LoadingBlock label={t("fleet.provision.awaiting")} />
            <p className="section-body">{t("fleet.provision.awaitingNote")}</p>
          </>
        ) : null}
        {live ? (
          <>
            <p className="section-body">{t(provisioning.state === "link_issued" ? "fleet.provision.issuedBody" : "fleet.provision.readyBody")}</p>
            <p className="deadline">
              <span className="deadline-label">{t("fleet.provision.endsIn")} </span>
              <Countdown expiresAt={provisioning.offer_expires_at_ms} />
            </p>
            {provisioning.can_provide ? (
              <>
                <div>
                  <Button variant="primary" icon="external" busy={busy} onClick={() => void provide()}>
                    {t(provisioning.state === "link_issued" ? "fleet.provision.reopen" : "fleet.provision.provide")}
                  </Button>
                </div>
                <p className="section-body">{t("fleet.provision.opensNote")}</p>
              </>
            ) : (
              <p className="section-body">{t("fleet.provision.ownerOnly")}</p>
            )}
          </>
        ) : null}
        {provisioning.state === "submitted" ? (
          <Notice tone="ok" title={t("fleet.provision.submittedTitle")}>
            {t("fleet.provision.submittedBody")}
          </Notice>
        ) : null}
        {provisioning.state === "expired" ? (
          <Notice tone="warn" title={t("fleet.provision.expiredTitle")}>
            {t("fleet.provision.expiredBody")}
          </Notice>
        ) : null}
        <div aria-live="polite">
          {opened ? <Notice tone="info">{t("fleet.provision.opened")}</Notice> : null}
          {failure ? (
            <Notice tone={failure.key === "pending" || failure.key === "unknown" ? "warn" : "danger"}>
              {t(`fleet.provision.errors.${failure.key}`, { code: failure.code })}
            </Notice>
          ) : null}
        </div>
      </div>
    </Panel>
  );
}
