// Aliases over the generated OpenAPI declarations. Screens import from here
// so a contract rename surfaces as one compile error rather than many.
import type { components } from "./generated/controller.js";

type Schemas = components["schemas"];

export type Capabilities = Schemas["CapabilitiesResponse"];
export type AdminSession = Schemas["AdminSession"];
export type Operator = Schemas["Operator"];
export type Role = Operator["role"];
export type OperatorList = Schemas["OperatorList"];
export type TemporaryPassword = Schemas["TemporaryPassword"];
export type Agent = Schemas["Agent"];
export type AgentList = Schemas["AgentList"];
export type AgentCreated = Schemas["AgentCreated"];
export type PolicyDocument = Schemas["PolicyDocument"];
export type PolicyDocumentInput = Schemas["PolicyDocumentInput"];
export type PolicyValidation = Schemas["PolicyValidation"];
export type ExchangeApproval = Schemas["Approval"];
export type ExchangeApprovalList = Schemas["ApprovalList"];
export type ApprovalCount = Schemas["ApprovalCount"];
export type ExchangeDecision = Schemas["ApprovalDecision"];
export type OperationApproval = Schemas["OperationApproval"];
export type OperationApprovalMember = Schemas["OperationApprovalMember"];
export type OperationApprovalScope = Schemas["OperationApprovalScope"];
export type UnifiedApprovalList = Schemas["UnifiedApprovalList"];
export type AuditEvent = Schemas["AuditEvent"];
export type AuditList = Schemas["AuditList"];
export type Enrollment = Schemas["Enrollment"];
export type EnrollmentList = Schemas["EnrollmentList"];
export type EnrollmentCreated = Schemas["EnrollmentCreated"];
export type FleetNode = Schemas["Node"];
export type NodeList = Schemas["NodeList"];
export type NodeStatus = Schemas["NodeStatus"];
export type Workload = Schemas["Workload"];
export type WorkloadList = Schemas["WorkloadList"];
export type WorkloadInput = Schemas["WorkloadInput"];
export type WorkloadUpdateInput = Schemas["WorkloadUpdateInput"];
export type FleetPolicy = Schemas["FleetPolicy"];
export type FleetPolicyRule = Schemas["FleetPolicyRule"];
export type Grant = Schemas["Grant"];
export type GrantList = Schemas["GrantList"];
export type GrantRevocationResult = Schemas["GrantRevocationResult"];
export type Operation = Schemas["Operation"];
export type OperationList = Schemas["OperationList"];
export type OperationProvisioning = Schemas["OperationProvisioning"];
export type ProvisioningState = OperationProvisioning["state"];
export type ProvisioningLink = Schemas["ProvisioningLink"];

export type AnyApproval = ExchangeApproval | OperationApproval;

export function isOperationApproval(approval: AnyApproval): approval is OperationApproval {
  return approval.kind === "operation";
}

export function approvalId(approval: AnyApproval): string {
  return isOperationApproval(approval) ? approval.id : approval.reference;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}
