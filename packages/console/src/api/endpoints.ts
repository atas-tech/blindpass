// Typed controller routes consumed by the console. Every path segment taken
// from data is encoded; nothing here builds a URL containing a credential.
import { api, newIdempotencyKey } from "./client.js";
import type {
  AdminSession,
  Agent,
  AgentCreated,
  AgentList,
  AnyApproval,
  ApprovalCount,
  AuditList,
  Capabilities,
  Enrollment,
  EnrollmentCreated,
  EnrollmentList,
  ExchangeApproval,
  ExchangeApprovalList,
  ExchangeDecision,
  FleetNode,
  FleetPolicy,
  FleetPolicyRule,
  Grant,
  GrantList,
  GrantRevocationResult,
  NodeList,
  Operation,
  OperationList,
  Operator,
  OperatorList,
  PolicyDocument,
  PolicyDocumentInput,
  PolicyValidation,
  Role,
  TemporaryPassword,
  UnifiedApprovalList,
  Workload,
  WorkloadInput,
  WorkloadList,
  WorkloadUpdateInput
} from "./types.js";

const seg = encodeURIComponent;

export interface PageQuery {
  cursor?: string | null;
  limit?: number;
}

export const capabilities = () => api.get<Capabilities>("/api/v3/capabilities", { authenticated: false });

export const session = {
  current: () => api.get<AdminSession>("/api/v3/admin/session", { authenticated: false }),
  login: (username: string, password: string) =>
    api.post<AdminSession>("/api/v3/admin/session/login", { username, password }, { authenticated: false, csrf: "pre-session" }),
  bootstrap: (token: string, body: { username: string; display_name: string; password: string }) =>
    api.post<AdminSession>("/api/v3/admin/bootstrap", body, {
      authenticated: false,
      csrf: "none",
      headers: { "x-blindpass-bootstrap-token": token }
    }),
  refresh: () => api.post<AdminSession>("/api/v3/admin/session/refresh", undefined, { authenticated: false }),
  logout: () => api.post<void>("/api/v3/admin/session/logout", undefined, { authenticated: false }),
  changePassword: (current_password: string, new_password: string) =>
    api.post<void>("/api/v3/admin/session/change-password", { current_password, new_password }, { authenticated: false })
};

export const operators = {
  list: (query: PageQuery = {}) => api.get<OperatorList>("/api/v3/admin/operators", { query: { ...query } }),
  create: (body: { username: string; display_name: string; role: Role; password: string }) =>
    api.post<Operator>("/api/v3/admin/operators", body),
  update: (id: string, body: { display_name?: string; role?: Role }) => api.patch<Operator>(`/api/v3/admin/operators/${seg(id)}`, body),
  remove: (id: string) => api.delete<void>(`/api/v3/admin/operators/${seg(id)}`),
  resetPassword: (id: string) => api.post<TemporaryPassword>(`/api/v3/admin/operators/${seg(id)}/reset-password`)
};

export const agents = {
  list: (query: PageQuery = {}) => api.get<AgentList>("/api/v3/admin/agents", { query: { ...query } }),
  create: (agent_id: string, display_name: string) => api.post<AgentCreated>("/api/v3/admin/agents", { agent_id, display_name }),
  rotate: (id: string) => api.post<AgentCreated>(`/api/v3/admin/agents/${seg(id)}/rotate-key`),
  revoke: (id: string) => api.delete<Agent>(`/api/v3/admin/agents/${seg(id)}`)
};

export const exchangePolicy = {
  get: () => api.get<PolicyDocument>("/api/v3/admin/policy"),
  validate: (policy: PolicyDocumentInput) => api.post<PolicyValidation>("/api/v3/admin/policy/validate", policy),
  save: (policy: PolicyDocumentInput, version: number) => api.put<PolicyDocument>("/api/v3/admin/policy", policy, { ifMatch: version })
};

export type DecisionVerb = "approve" | "reject";

/** Exchange-only approval routes, used when the controller has no fleet group. */
export const exchangeApprovals = {
  list: (query: PageQuery & { status?: "pending" | "approved" | "rejected" } = {}) =>
    api.get<ExchangeApprovalList>("/api/v3/admin/approvals", { query: { ...query } }),
  count: () => api.get<ApprovalCount>("/api/v3/admin/approvals/count"),
  get: (reference: string) => api.get<ExchangeApproval>(`/api/v3/admin/approvals/${seg(reference)}`),
  decide: (reference: string, verb: DecisionVerb, idempotencyKey = newIdempotencyKey()) =>
    api.post<ExchangeDecision>(`/api/v3/admin/approvals/${seg(reference)}/${verb}`, { expected_status: "pending" }, { idempotencyKey })
};

/** Unified exchange + operation approvals (fleet.v3). */
export const unifiedApprovals = {
  list: (query: PageQuery & { status?: "pending" | "approved" | "rejected" | "expired" } = {}) =>
    api.get<UnifiedApprovalList>("/api/v3/approvals", { query: { ...query } }),
  count: () => api.get<ApprovalCount>("/api/v3/approvals/count"),
  get: (id: string) => api.get<AnyApproval>(`/api/v3/approvals/${seg(id)}`),
  decide: (approval: AnyApproval, verb: DecisionVerb, idempotencyKey = newIdempotencyKey()) => {
    if (approval.kind === "operation" && "operation_ids" in approval) {
      return api.post<unknown>(
        `/api/v3/approvals/${seg(approval.id)}/${verb}`,
        { expected_status: "pending", expected_version: approval.version, operation_ids: approval.operation_ids },
        { idempotencyKey, ifMatch: approval.version }
      );
    }
    // The unified route treats an exchange approval as version 1 and
    // refuses the decision without the matching If-Match.
    const reference = (approval as ExchangeApproval).reference;
    return api.post<unknown>(`/api/v3/approvals/${seg(reference)}/${verb}`, { expected_status: "pending", expected_version: 1 }, { idempotencyKey, ifMatch: 1 });
  }
};

export const audit = {
  list: (query: PageQuery = {}) => api.get<AuditList>("/api/v3/admin/audit", { query: { ...query } }),
  exchange: (id: string) => api.get<AuditList>(`/api/v3/admin/audit/exchange/${seg(id)}`)
};

export const enrollments = {
  list: (query: PageQuery = {}) => api.get<EnrollmentList>("/api/v3/enrollments", { query: { ...query } }),
  get: (id: string) => api.get<Enrollment>(`/api/v3/enrollments/${seg(id)}`),
  create: (name: string) => api.post<EnrollmentCreated>("/api/v3/enrollments", { name }),
  decide: (id: string, verb: DecisionVerb, expected_fingerprint: string, expected_version: number) =>
    api.post<Enrollment | FleetNode>(`/api/v3/enrollments/${seg(id)}/${verb}`, { expected_fingerprint, expected_version })
};

export const nodes = {
  list: (query: PageQuery = {}) => api.get<NodeList>("/api/v3/nodes", { query: { ...query } }),
  get: (id: string) => api.get<FleetNode>(`/api/v3/nodes/${seg(id)}`),
  revoke: (id: string) => api.delete<FleetNode>(`/api/v3/nodes/${seg(id)}`)
};

export const workloads = {
  list: (query: PageQuery & { node_id?: string } = {}) => api.get<WorkloadList>("/api/v3/workloads", { query: { ...query } }),
  get: (id: string) => api.get<Workload>(`/api/v3/workloads/${seg(id)}`),
  create: (body: WorkloadInput) => api.post<Workload>("/api/v3/workloads", body),
  update: (id: string, body: WorkloadUpdateInput) =>
    api.patch<Workload>(`/api/v3/workloads/${seg(id)}`, body, { ifMatch: body.expected_version }),
  revoke: (id: string) => api.delete<Workload>(`/api/v3/workloads/${seg(id)}`)
};

export const fleetPolicy = {
  get: () => api.get<FleetPolicy>("/api/v3/policies"),
  save: (rules: FleetPolicyRule[], expected_version: number) =>
    api.put<FleetPolicy>("/api/v3/policies", { expected_version, rules }, { ifMatch: expected_version })
};

export const grants = {
  list: (query: PageQuery & { node_id?: string; status?: Grant["status"] } = {}) => api.get<GrantList>("/api/v3/grants", { query: { ...query } }),
  get: (id: string) => api.get<Grant>(`/api/v3/grants/${seg(id)}`),
  revoke: (id: string) => api.delete<GrantRevocationResult>(`/api/v3/grants/${seg(id)}`)
};

export const operations = {
  list: (query: PageQuery & { status?: string } = {}) => api.get<OperationList>("/api/v3/operations", { query: { ...query } }),
  get: (id: string) => api.get<Operation>(`/api/v3/operations/${seg(id)}`),
  cancel: (id: string) => api.delete<Operation | GrantRevocationResult>(`/api/v3/operations/${seg(id)}`)
};
