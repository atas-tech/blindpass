export const AGENT_IDS = {
  requester: "contract-requester",
  fulfiller: "contract-fulfiller",
  observer: "contract-observer",
  rotatable: "contract-rotatable",
  revocable: "contract-revocable"
} as const;

export const SECRET_NAMES = {
  allowed: "stripe.api_key.prod",
  approval: "restricted.secret",
  denied: "denied.secret"
} as const;

export const CANARIES = {
  ciphertext: "Q0FOQVJZX0NJUEhFUl9QMDA"
} as const;

export const POLICY_DOCUMENT = {
  secret_registry: [
    {
      secretName: SECRET_NAMES.allowed,
      classification: "finance",
      description: "A dummy finance canary, never a live credential."
    },
    {
      secretName: SECRET_NAMES.approval,
      classification: "sensitive",
      description: "A dummy approval canary, never a live credential."
    },
    {
      secretName: SECRET_NAMES.denied,
      classification: "restricted",
      description: "A dummy denied canary, never a live credential."
    }
  ],
  exchange_policy: [
    {
      ruleId: "contract-allow",
      secretName: SECRET_NAMES.allowed,
      requesterIds: [AGENT_IDS.requester],
      fulfillerIds: [AGENT_IDS.fulfiller],
      mode: "allow",
      reason: "contract allow fixture"
    },
    {
      ruleId: "contract-approval",
      secretName: SECRET_NAMES.approval,
      requesterIds: [AGENT_IDS.requester],
      fulfillerIds: [AGENT_IDS.fulfiller],
      approverIds: [AGENT_IDS.observer],
      mode: "pending_approval",
      reason: "contract approval fixture"
    },
    {
      ruleId: "contract-deny",
      secretName: SECRET_NAMES.denied,
      mode: "deny",
      reason: "contract deny fixture"
    }
  ]
} as const;

export type AgentId = keyof typeof AGENT_IDS;

export interface ContractAgent {
  agentId: string;
  apiKey: string;
  accessToken: string;
  accessTokenExpiresAt: number;
}

export interface ContractFixture {
  workspaceId: string;
  userId: string;
  adminAccessToken?: string;
  adminSession?: { cookie: string; csrfToken: string };
  agentRecordIds?: Record<string, string>;
  agents: Record<AgentId, ContractAgent>;
  baseUrl: string;
  hmacSecret: string;
  seedToken: string;
  canaries: string[];
}

export function fixtureCanaries(): string[] {
  return Object.values(CANARIES);
}

export function addCanaries(fixture: ContractFixture, ...values: Array<string | null | undefined>): void {
  for (const value of values) {
    if (value && !fixture.canaries.includes(value)) {
      fixture.canaries.push(value);
    }
  }
}
