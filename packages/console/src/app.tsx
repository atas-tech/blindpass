import { lazy, Suspense, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation } from "react-router";
import { useSession, type Permission } from "./session/session.js";
import { AppShell } from "./shell/app-shell.js";
import { ApprovalCountProvider } from "./shell/approval-count.js";
import { ErrorState, LoadingBlock } from "./ui/feedback.js";
import { Gate } from "./pages/auth/gate.js";
import { ForbiddenPage, NotFoundPage, UnavailableFeaturePage } from "./pages/system.js";
import { Button } from "./ui/button.js";
import { safeReturnPath } from "./lib/routing.js";

const SetupPage = lazy(() => import("./pages/auth/setup.js"));
const LoginPage = lazy(() => import("./pages/auth/login.js"));
const ChangePasswordPage = lazy(() => import("./pages/auth/change-password.js"));
const OverviewPage = lazy(() => import("./pages/overview.js"));
const SettingsPage = lazy(() => import("./pages/settings/settings.js"));
const OperatorsPage = lazy(() => import("./pages/settings/operators.js"));
const ApprovalsPage = lazy(() => import("./pages/approvals/approvals.js"));
const ApprovalDetail = lazy(() => import("./pages/approvals/detail.js"));
const AgentsPage = lazy(() => import("./pages/agents.js"));
const ExchangePolicyPage = lazy(() => import("./pages/policy/exchange-policy.js"));
const AuditPage = lazy(() => import("./pages/audit/audit.js"));
const ExchangeTimelinePage = lazy(() => import("./pages/audit/exchange-timeline.js"));
const EnrollmentsPage = lazy(() => import("./pages/fleet/enrollments.js"));
const NodesPage = lazy(() => import("./pages/fleet/nodes.js").then((module) => ({ default: module.NodesPage })));
const NodeDetailPage = lazy(() => import("./pages/fleet/nodes.js").then((module) => ({ default: module.NodeDetailPage })));
const WorkloadsPage = lazy(() => import("./pages/fleet/workloads.js").then((module) => ({ default: module.WorkloadsPage })));
const WorkloadDetailPage = lazy(() => import("./pages/fleet/workloads.js").then((module) => ({ default: module.WorkloadDetailPage })));
const FleetPolicyPage = lazy(() => import("./pages/fleet/fleet-policy.js"));
const GrantsPage = lazy(() => import("./pages/fleet/grants.js"));
const FulfillmentsPage = lazy(() => import("./pages/fleet/fulfillments.js"));
const OperationsPage = lazy(() => import("./pages/fleet/operations.js").then((module) => ({ default: module.OperationsPage })));
const OperationDetailPage = lazy(() => import("./pages/fleet/operations.js").then((module) => ({ default: module.OperationDetailPage })));

/** A fleet route exists only when the controller reports fleet.v3 (DR-E25). */
function fleetRoute(path: string, permission: Permission, page: ReactNode, feature?: "fulfillments") {
  return { path, element: <RequirePermission permission={permission} fleet feature={feature}><Lazy>{page}</Lazy></RequirePermission> };
}

/** Hosted-product paths that the local controller does not provide. */
export const REMOVED_ROUTES = ["/billing", "/analytics", "/public-offers", "/public/*", "/register", "/signup", "/verify", "/forgot-password", "/reset-password", "/members"];

function FullPage({ children }: { children: ReactNode }) {
  return <div className="full-page">{children}</div>;
}

function Unreachable() {
  const { t } = useTranslation();
  const { state, reload } = useSession();
  if (state.status !== "unreachable") return null;
  return (
    <Gate single>
      <div className="gate-card">
        <ErrorState error={state.error} />
        <p className="gate-card-body">{t("system.unreachable.body")}</p>
        <Button variant="primary" icon="refresh" onClick={() => void reload()}>
          {t("common.retry")}
        </Button>
      </div>
    </Gate>
  );
}

/** Routes for a signed-out visitor. */
function PublicOnly() {
  const { state } = useSession();
  const location = useLocation();
  if (state.status === "setup") return location.pathname === "/setup" ? <Outlet /> : <Navigate to="/setup" replace />;
  if (state.status === "authenticated") {
    const next = new URLSearchParams(location.search).get("next");
    return <Navigate to={state.session.must_change_password ? "/change-password" : safeReturnPath(next)} replace />;
  }
  if (location.pathname === "/setup") return <Navigate to="/login" replace />;
  return <Outlet />;
}

/** Routes that require a session; a temporary password confines the operator. */
function RequireSession() {
  const { state } = useSession();
  const location = useLocation();
  if (state.status === "setup") return <Navigate to="/setup" replace />;
  if (state.status === "anonymous") {
    const next = `${location.pathname}${location.search}`;
    const keepReturn = state.reason !== "signed_out" && next !== "/";
    return <Navigate to={keepReturn ? `/login?next=${encodeURIComponent(next)}` : "/login"} replace />;
  }
  if (state.status !== "authenticated") return null;
  if (state.session.must_change_password && location.pathname !== "/change-password") {
    return <Navigate to="/change-password" replace />;
  }
  return <Outlet />;
}

export function RequirePermission({ permission, fleet = false, feature, children }: { permission?: Permission; fleet?: boolean; feature?: "fulfillments"; children: ReactNode }) {
  const { can, hasFleet, hasFulfillments } = useSession();
  if (fleet && !hasFleet) return <NotFoundPage />;
  // An optional feature the controller does not report has no route at all.
  if (feature === "fulfillments" && !hasFulfillments) return <NotFoundPage />;
  if (permission && !can(permission)) return <ForbiddenPage />;
  return <>{children}</>;
}

function Lazy({ children }: { children: ReactNode }) {
  return <Suspense fallback={<LoadingBlock />}>{children}</Suspense>;
}

function ShellLayout() {
  return (
    <ApprovalCountProvider>
      <AppShell />
    </ApprovalCountProvider>
  );
}

function Root() {
  const { state } = useSession();
  if (state.status === "loading") {
    return (
      <FullPage>
        <LoadingBlock />
      </FullPage>
    );
  }
  if (state.status === "unreachable") return <Unreachable />;
  return <Outlet />;
}

export const routes = [
  {
    element: <Root />,
    children: [
      ...REMOVED_ROUTES.map((path) => ({ path, element: <UnavailableFeaturePage /> })),
      {
        element: <PublicOnly />,
        children: [
          { path: "/setup", element: <Lazy><SetupPage /></Lazy> },
          { path: "/login", element: <Lazy><LoginPage /></Lazy> }
        ]
      },
      {
        element: <RequireSession />,
        children: [
          { path: "/change-password", element: <Lazy><ChangePasswordPage /></Lazy> },
          {
            element: <ShellLayout />,
            children: [
              { path: "/", element: <Lazy><OverviewPage /></Lazy> },
              {
                path: "/approvals",
                element: <RequirePermission permission="approvals.read"><Lazy><ApprovalsPage /></Lazy></RequirePermission>,
                children: [{ path: ":kind/:id", element: <Lazy><ApprovalDetail /></Lazy> }]
              },
              { path: "/agents", element: <RequirePermission permission="agents.read"><Lazy><AgentsPage /></Lazy></RequirePermission> },
              { path: "/policy", element: <RequirePermission permission="exchangePolicy.read"><Lazy><ExchangePolicyPage /></Lazy></RequirePermission> },
              { path: "/audit", element: <RequirePermission permission="audit.read"><Lazy><AuditPage /></Lazy></RequirePermission> },
              { path: "/audit/exchange/:id", element: <RequirePermission permission="audit.read"><Lazy><ExchangeTimelinePage /></Lazy></RequirePermission> },
              fleetRoute("/enrollments", "enrollments.read", <EnrollmentsPage />),
              fleetRoute("/nodes", "nodes.read", <NodesPage />),
              fleetRoute("/nodes/:id", "nodes.read", <NodeDetailPage />),
              fleetRoute("/workloads", "workloads.read", <WorkloadsPage />),
              fleetRoute("/workloads/:id", "workloads.read", <WorkloadDetailPage />),
              fleetRoute("/policy/fleet", "fleetPolicy.read", <FleetPolicyPage />),
              fleetRoute("/grants", "grants.read", <GrantsPage />),
              fleetRoute("/fulfillments", "fulfillments.read", <FulfillmentsPage />, "fulfillments"),
              fleetRoute("/operations", "operations.read", <OperationsPage />),
              fleetRoute("/operations/:id", "operations.read", <OperationDetailPage />),
              { path: "/settings", element: <Lazy><SettingsPage /></Lazy> },
              { path: "/settings/operators", element: <RequirePermission permission="operators.manage"><Lazy><OperatorsPage /></Lazy></RequirePermission> },
              { path: "*", element: <NotFoundPage /> }
            ]
          }
        ]
      }
    ]
  }
];

export function App() {
  const [router] = useState(() => createBrowserRouter(routes));
  return <RouterProvider router={router} />;
}
