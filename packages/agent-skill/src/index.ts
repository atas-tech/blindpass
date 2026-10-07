import { decrypt, destroyKeyPair, encrypt, generateKeyPair } from "./key-manager.js";
import { SecretStore } from "./secret-store.js";
import { SpsClient } from "./sps-client.js";
import {
  createFulfillmentTransportEnvelope,
  type FulfillmentTransport,
  type FulfillmentTransportEnvelope
} from "./transport.js";

export * from "./key-manager.js";
export * from "./secret-store.js";
export * from "./sps-client.js";
export * from "./transport.js";

export interface AgentSecretRuntimeOptions {
  spsBaseUrl: string;
  gatewayBearerToken?: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
  agentId?: string;
}

export interface RequestExchangeParams {
  secretName: string;
  purpose: string;
  fulfillerHint: string;
  priorExchangeId?: string;
  deliverToken?: (fulfillmentToken: string, envelope: FulfillmentTransportEnvelope) => Promise<void>;
  transport?: FulfillmentTransport;
  reservedTimeoutMs?: number;
}

export class SecretMissingError extends Error {
  constructor(secretName: string) {
    super(`Secret '${secretName}' is missing from memory. Use the 'request_secret' tool with 're_request: true' to ask the user to re-enter it.`);
    this.name = 'SecretMissingError';
  }
}

export class AgentSecretRuntime {
  readonly store = new SecretStore();

  private readonly client: SpsClient;
  private readonly agentId: string | null;

  constructor(options: AgentSecretRuntimeOptions) {
    this.client = new SpsClient({
      baseUrl: options.spsBaseUrl,
      gatewayBearerToken: options.gatewayBearerToken,
      bootstrapApiKey: options.apiKey,
      fetchImpl: options.fetchImpl
    });
    this.agentId = options.agentId ?? null;
  }

  checkSecretOrThrow(secretName: string): Buffer {
    const value = this.store.get(secretName);
    if (!value) {
      throw new SecretMissingError(secretName);
    }
    return value;
  }

  async requestAndStoreSecret(secretName: string, description: string): Promise<{ requestId: string; confirmationCode: string; secretUrl: string }> {
    const keyPair = await generateKeyPair();

    try {
      const request = await this.client.requestSecret({
        description,
        publicKey: keyPair.publicKey
      });

      const pollResult = await this.client.pollStatus(request.requestId);
      const retrieved = await this.client.retrieveSecret(request.requestId);

      if (Date.now() > pollResult.retrieveByMs) {
        throw new Error("Secret no longer available");
      }

      const plaintext = await decrypt(keyPair.privateKey, retrieved.enc, retrieved.ciphertext);
      this.store.storeSecret(secretName, plaintext);

      return request;
    } finally {
      destroyKeyPair(keyPair);
    }
  }

  async requestAndStoreExchangeSecret(params: RequestExchangeParams): Promise<{ exchangeId: string; fulfilledBy: string | null }> {
    if (!params.transport && !params.deliverToken) {
      throw new Error("Either transport or deliverToken must be provided for exchange requests.");
    }

    const keyPair = await generateKeyPair();

    try {
      let created = await this.client.createExchangeRequest({
        publicKey: keyPair.publicKey,
        secretName: params.secretName,
        purpose: params.purpose,
        fulfillerHint: params.fulfillerHint,
        priorExchangeId: params.priorExchangeId
      });

      while (created.status === "pending_approval") {
        await new Promise(resolve => setTimeout(resolve, 3000));
        created = await this.client.createExchangeRequest({
          publicKey: keyPair.publicKey,
          secretName: params.secretName,
          purpose: params.purpose,
          fulfillerHint: params.fulfillerHint,
          priorExchangeId: params.priorExchangeId
        });
      }

      const envelope = createFulfillmentTransportEnvelope({
        exchangeId: created.exchangeId,
        requesterId: this.agentId,
        fulfillerId: params.fulfillerHint,
        secretName: params.secretName,
        purpose: params.purpose,
        fulfillmentToken: created.fulfillmentToken
      });

      try {
        if (params.transport) {
          await params.transport.deliverFulfillmentToken(envelope);
        } else {
          await params.deliverToken!(created.fulfillmentToken, envelope);
        }
      } catch (error) {
        await this.client.revokeExchange(created.exchangeId).catch(() => undefined);
        throw error;
      }

      await this.client.pollExchangeStatus(created.exchangeId, 1000, 180000, params.reservedTimeoutMs ?? 30000);

      const retrieved = await this.client.retrieveExchange(created.exchangeId);
      const plaintext = await decrypt(keyPair.privateKey, retrieved.enc, retrieved.ciphertext);
      this.store.storeSecret(params.secretName, plaintext);

      return {
        exchangeId: created.exchangeId,
        fulfilledBy: retrieved.fulfilledBy
      };
    } finally {
      destroyKeyPair(keyPair);
    }
  }

  async fulfillExchange(fulfillmentToken: string): Promise<{ exchangeId: string; secretName: string }> {
    const reservation = await this.client.fulfillExchange(fulfillmentToken);
    const secret = this.store.get(reservation.secretName);
    if (!secret) {
      throw new SecretMissingError(reservation.secretName);
    }

    const sealed = await encrypt(reservation.requesterPublicKey, secret);
    await this.client.submitExchange(reservation.exchangeId, sealed);

    return {
      exchangeId: reservation.exchangeId,
      secretName: reservation.secretName
    };
  }
}
