import type { IconName } from "../ui/icon.js";
import type { Permission } from "../session/session.js";

export interface NavItem {
  to: string;
  labelKey: string;
  icon: IconName;
  permission?: Permission;
  fleet?: boolean;
  badge?: "approvals";
  end?: boolean;
}

export interface NavGroup {
  labelKey: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    labelKey: "nav.groups.access",
    items: [
      { to: "/", labelKey: "nav.overview", icon: "overview", end: true },
      { to: "/approvals", labelKey: "nav.approvals", icon: "approvals", permission: "approvals.read", badge: "approvals" },
      { to: "/audit", labelKey: "nav.audit", icon: "audit", permission: "audit.read" }
    ]
  },
  {
    labelKey: "nav.groups.fleet",
    items: [
      { to: "/enrollments", labelKey: "nav.enrollments", icon: "enrollments", permission: "enrollments.read", fleet: true },
      { to: "/nodes", labelKey: "nav.nodes", icon: "nodes", permission: "nodes.read", fleet: true },
      { to: "/workloads", labelKey: "nav.workloads", icon: "workloads", permission: "workloads.read", fleet: true },
      { to: "/grants", labelKey: "nav.grants", icon: "grants", permission: "grants.read", fleet: true },
      { to: "/operations", labelKey: "nav.operations", icon: "operations", permission: "operations.read", fleet: true }
    ]
  },
  {
    labelKey: "nav.groups.admin",
    items: [
      { to: "/agents", labelKey: "nav.agents", icon: "agents", permission: "agents.read" },
      { to: "/policy", labelKey: "nav.policy", icon: "policy", permission: "exchangePolicy.read", end: true },
      { to: "/policy/fleet", labelKey: "nav.fleetPolicy", icon: "lock", permission: "fleetPolicy.read", fleet: true },
      { to: "/settings/operators", labelKey: "nav.operators", icon: "operators", permission: "operators.manage" },
      { to: "/settings", labelKey: "nav.settings", icon: "settings", end: true }
    ]
  }
];

export function visibleGroups(can: (permission: Permission) => boolean, hasFleet: boolean): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => (!item.permission || can(item.permission)) && (!item.fleet || hasFleet))
  })).filter((group) => group.items.length > 0);
}
