import type { AuditEvent } from "../../api/types.js";

export const EVENT_CATEGORIES = ["all", "exchange", "agent", "policy", "fleet", "other"] as const;
export type EventCategory = (typeof EVENT_CATEGORIES)[number];

export function categoryOf(event: string): Exclude<EventCategory, "all"> {
  if (event.startsWith("fleet.")) return "fleet";
  if (event.startsWith("exchange")) return "exchange";
  if (event.startsWith("agent")) return "agent";
  if (event.startsWith("policy")) return "policy";
  return "other";
}

/** Events whose resource is an exchange id (the audit body omits resource type). */
const EXCHANGE_RESOURCE_EVENTS = new Set(["exchange_requested", "exchange_reserved", "exchange_submitted", "exchange_retrieved", "exchange_revoked"]);

export function exchangeIdOf(event: AuditEvent): string | null {
  const fromMetadata = event.metadata.exchange_id;
  if (typeof fromMetadata === "string" && fromMetadata) return fromMetadata;
  return EXCHANGE_RESOURCE_EVENTS.has(event.event) && event.resource_id ? event.resource_id : null;
}
