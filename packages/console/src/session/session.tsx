import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, onSessionError, setCsrfToken } from "../api/client.js";
import * as endpoints from "../api/endpoints.js";
import type { AdminSession, Capabilities, Role } from "../api/types.js";

export type SessionEndReason = "expired" | "signed_out" | "revoked" | null;

export type SessionState =
  | { status: "loading" }
  | { status: "unreachable"; error: ApiError }
  | { status: "setup"; capabilities: Capabilities }
  | { status: "anonymous"; capabilities: Capabilities; reason: SessionEndReason }
  | { status: "authenticated"; capabilities: Capabilities; session: AdminSession };

/**
 * Console permissions, mirroring the controller's enforced role matrix
 * (crates/blindpass-controller/tests/fleet_roles.rs and the admin routes).
 * They only choose what to render; every route still handles 403.
 */
export const PERMISSIONS = {
  "approvals.read": ["admin", "operator"],
  "approvals.decide": ["admin", "operator"],
  "agents.read": ["admin"],
  "agents.manage": ["admin"],
  "exchangePolicy.read": ["admin", "operator", "viewer"],
  "exchangePolicy.write": ["admin"],
  "fleetPolicy.read": ["admin", "operator", "viewer"],
  "fleetPolicy.write": ["admin"],
  "audit.read": ["admin", "operator", "viewer"],
  "enrollments.read": ["admin", "operator", "viewer"],
  "enrollments.manage": ["admin"],
  "nodes.read": ["admin", "operator", "viewer"],
  "nodes.manage": ["admin"],
  "workloads.read": ["admin", "operator", "viewer"],
  "workloads.manage": ["admin"],
  "grants.read": ["admin", "operator"],
  "grants.revoke": ["admin", "operator"],
  "fulfillments.read": ["admin", "operator"],
  "fulfillments.create": ["admin", "operator"],
  "fulfillments.decide": ["admin", "operator"],
  "fulfillments.revoke": ["admin", "operator"],
  "operations.read": ["admin", "operator"],
  "operations.cancel": ["admin", "operator"],
  "operators.manage": ["admin"]
} as const satisfies Record<string, readonly Role[]>;

export type Permission = keyof typeof PERMISSIONS;

export function roleCan(role: Role | undefined, permission: Permission): boolean {
  return role !== undefined && (PERMISSIONS[permission] as readonly Role[]).includes(role);
}

interface SessionApi {
  state: SessionState;
  capabilities: Capabilities | null;
  session: AdminSession | null;
  hasFleet: boolean;
  /** fleet.v3 and the controller's fleet_fulfillments flag; a missing flag is off. */
  hasFulfillments: boolean;
  can: (permission: Permission) => boolean;
  reload: () => Promise<void>;
  login: (username: string, password: string) => Promise<AdminSession>;
  bootstrap: (token: string, body: { username: string; display_name: string; password: string }) => Promise<AdminSession>;
  changePassword: (current: string, next: string) => Promise<void>;
  extend: () => Promise<void>;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionApi | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const capabilitiesRef = useRef<Capabilities | null>(null);

  const adopt = useCallback((capabilities: Capabilities, session: AdminSession) => {
    setCsrfToken(session.csrf_token);
    setState({ status: "authenticated", capabilities, session });
  }, []);

  const toAnonymous = useCallback((reason: SessionEndReason) => {
    setCsrfToken(null);
    const capabilities = capabilitiesRef.current;
    if (capabilities) setState({ status: "anonymous", capabilities, reason });
  }, []);

  const reload = useCallback(async () => {
    let capabilities: Capabilities;
    try {
      capabilities = await endpoints.capabilities();
    } catch (error) {
      setState({ status: "unreachable", error: error instanceof ApiError ? error : new ApiError(0, "network", "unreachable") });
      return;
    }
    capabilitiesRef.current = capabilities;
    if (capabilities.setup_required) {
      setCsrfToken(null);
      setState({ status: "setup", capabilities });
      return;
    }
    try {
      adopt(capabilities, await endpoints.session.current());
    } catch (error) {
      if (error instanceof ApiError && error.kind === "unauthorized") {
        setCsrfToken(null);
        setState({ status: "anonymous", capabilities, reason: error.code === "session_expired" ? "expired" : null });
        return;
      }
      setState({ status: "unreachable", error: error instanceof ApiError ? error : new ApiError(0, "network", "unreachable") });
    }
  }, [adopt]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Any authenticated call that returns 401 ends the local view of the
  // session; a forced password change re-reads the session so the router
  // can confine the operator to /change-password.
  useEffect(
    () =>
      onSessionError((error) => {
        if (error.kind === "unauthorized") toAnonymous("expired");
        else if (error.kind === "password_change_required") void reload();
      }),
    [reload, toAnonymous]
  );

  const login = useCallback(
    async (username: string, password: string) => {
      const session = await endpoints.session.login(username, password);
      const capabilities = capabilitiesRef.current ?? (await endpoints.capabilities());
      capabilitiesRef.current = capabilities;
      adopt(capabilities, session);
      return session;
    },
    [adopt]
  );

  const bootstrap = useCallback(
    async (token: string, body: { username: string; display_name: string; password: string }) => {
      const session = await endpoints.session.bootstrap(token, body);
      const capabilities = await endpoints.capabilities().catch(() => capabilitiesRef.current);
      if (!capabilities) throw new ApiError(0, "network", "unreachable");
      capabilitiesRef.current = capabilities;
      adopt(capabilities, session);
      return session;
    },
    [adopt]
  );

  const changePassword = useCallback(
    async (current: string, next: string) => {
      await endpoints.session.changePassword(current, next);
      await reload();
    },
    [reload]
  );

  const extend = useCallback(async () => {
    const capabilities = capabilitiesRef.current;
    const session = await endpoints.session.refresh();
    if (capabilities) adopt(capabilities, session);
  }, [adopt]);

  const logout = useCallback(async () => {
    try {
      await endpoints.session.logout();
    } catch (error) {
      // An already-expired session is logged out; anything else must not
      // pretend the server-side session ended.
      if (!(error instanceof ApiError && error.kind === "unauthorized")) throw error;
    }
    toAnonymous("signed_out");
  }, [toAnonymous]);

  const value = useMemo<SessionApi>(() => {
    const capabilities = state.status === "loading" || state.status === "unreachable" ? null : state.capabilities;
    const session = state.status === "authenticated" ? state.session : null;
    return {
      state,
      capabilities,
      session,
      hasFleet: Boolean(capabilities?.api.includes("fleet.v3")),
      hasFulfillments: Boolean(capabilities?.api.includes("fleet.v3") && capabilities.features?.fleet_fulfillments === true),
      can: (permission) => roleCan(session?.operator.role, permission),
      reload,
      login,
      bootstrap,
      changePassword,
      extend,
      logout
    };
  }, [state, reload, login, bootstrap, changePassword, extend, logout]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionApi {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}
