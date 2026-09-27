import type { Tone } from "../../ui/feedback.js";
import type { ApprovalStatus } from "./model.js";

export function statusTone(status: ApprovalStatus): Tone {
  switch (status) {
    case "pending":
      return "warn";
    case "approved":
      return "ok";
    case "rejected":
      return "danger";
    default:
      return "neutral";
  }
}
