import { Redis } from "ioredis";
import type { ExchangeLifecycleRecord, RequestStore, StoredApprovalRequest, StoredExchange, StoredRequest } from "../types.js";

function keyForRequest(requestId: string): string {
  return `sps:request:${requestId}`;
}

function keyForExchange(exchangeId: string): string {
  return `sps:exchange:${exchangeId}`;
}

function keyForApproval(approvalReference: string): string {
  return `sps:approval:${approvalReference}`;
}

function keyForExchangeLifecycle(exchangeId: string): string {
  return `sps:exchange-lifecycle:${exchangeId}`;
}

function keyForApprovalLifecycle(approvalReference: string): string {
  return `sps:approval-lifecycle:${approvalReference}`;
}

export class RedisRequestStore implements RequestStore {
  private readonly redis: Redis;

  constructor(redis: Redis) {
    this.redis = redis;
  }

  async ping(): Promise<void> {
    await this.redis.ping();
  }

  async setRequest(data: StoredRequest, ttlSeconds: number): Promise<void> {
    await this.redis.set(keyForRequest(data.requestId), JSON.stringify(data), "EX", ttlSeconds);
  }

  async getRequest(requestId: string): Promise<StoredRequest | null> {
    const raw = await this.redis.get(keyForRequest(requestId));
    return raw ? (JSON.parse(raw) as StoredRequest) : null;
  }

  async updateRequest(
    requestId: string,
    patch: Partial<StoredRequest>,
    ttlSeconds?: number,
    expectedStatus?: StoredRequest["status"]
  ): Promise<StoredRequest | null> {
    const script = `
      local key = KEYS[1]
      local patch = cjson.decode(ARGV[1])
      local ttl_ms = ARGV[2]
      local expected_status = ARGV[3]

      local raw = redis.call('GET', key)
      if not raw then
        return nil
      end

      local data = cjson.decode(raw)
      if expected_status ~= '' and data["status"] ~= expected_status then
        return nil
      end

      for field, value in pairs(patch) do
        data[field] = value
      end

      local encoded = cjson.encode(data)
      if ttl_ms ~= '' then
        redis.call('SET', key, encoded, 'PX', tonumber(ttl_ms))
      else
        local pttl = redis.call('PTTL', key)
        if pttl > 0 then
          redis.call('SET', key, encoded, 'PX', pttl)
        else
          redis.call('SET', key, encoded)
        end
      end

      return encoded
    `;

    const raw = await this.redis.eval(
      script,
      1,
      keyForRequest(requestId),
      JSON.stringify(patch),
      typeof ttlSeconds === "number" ? String(ttlSeconds * 1000) : "",
      expectedStatus ?? ""
    );
    if (typeof raw !== "string") {
      return null;
    }

    return JSON.parse(raw) as StoredRequest;
  }

  async atomicRetrieveAndDelete(requestId: string, requesterId?: string, workspaceId?: string): Promise<StoredRequest | null> {
    const script = `
      local key = KEYS[1]
      local requester_id = ARGV[1]
      local workspace_id = ARGV[2]
      local data = redis.call('GET', key)
      if data then
        local decoded = cjson.decode(data)
        if requester_id ~= '' and decoded["requesterId"] ~= requester_id then
          return nil
        end
        if workspace_id ~= '' and decoded["workspaceId"] ~= workspace_id then
          return nil
        end
        redis.call('DEL', key)
        return data
      else
        return nil
      end
    `;

    const raw = await this.redis.eval(script, 1, keyForRequest(requestId), requesterId ?? "", workspaceId ?? "");
    if (typeof raw !== "string") {
      return null;
    }

    return JSON.parse(raw) as StoredRequest;
  }

  async deleteRequest(requestId: string, requesterId?: string, workspaceId?: string): Promise<boolean> {
    if (!requesterId && !workspaceId) {
      return (await this.redis.del(keyForRequest(requestId))) > 0;
    }

    const script = `
      local key = KEYS[1]
      local requester_id = ARGV[1]
      local workspace_id = ARGV[2]
      local data = redis.call('GET', key)
      if not data then
        return 0
      end
      local decoded = cjson.decode(data)
      if requester_id ~= '' and decoded["requesterId"] ~= requester_id then
        return 0
      end
      if workspace_id ~= '' and decoded["workspaceId"] ~= workspace_id then
        return 0
      end
      redis.call('DEL', key)
      return 1
    `;

    return Number(await this.redis.eval(script, 1, keyForRequest(requestId), requesterId ?? "", workspaceId ?? "")) > 0;
  }

  async setExchange(data: StoredExchange, ttlSeconds: number): Promise<void> {
    await this.redis.set(keyForExchange(data.exchangeId), JSON.stringify(data), "EX", ttlSeconds);
  }

  async getExchange(exchangeId: string): Promise<StoredExchange | null> {
    const raw = await this.redis.get(keyForExchange(exchangeId));
    return raw ? (JSON.parse(raw) as StoredExchange) : null;
  }

  async revokeExchange(exchangeId: string, ttlSeconds: number): Promise<StoredExchange | null> {
    const current = await this.getExchange(exchangeId);
    if (!current) {
      return null;
    }

    const next: StoredExchange = {
      ...current,
      status: "revoked"
    };

    await this.redis.set(keyForExchange(exchangeId), JSON.stringify(next), "EX", ttlSeconds);
    return next;
  }

  async reserveExchange(exchangeId: string, fulfillerId: string): Promise<StoredExchange | null> {
    const script = `
      local key = KEYS[1]
      local fulfiller_id = ARGV[1]
      local ttl = redis.call('PTTL', key)
      if ttl <= 0 then
        return nil
      end

      local raw = redis.call('GET', key)
      if not raw then
        return nil
      end

      local data = cjson.decode(raw)
      if data["status"] ~= "pending" then
        return nil
      end

      data["status"] = "reserved"
      data["fulfilledBy"] = fulfiller_id
      local encoded = cjson.encode(data)
      redis.call('SET', key, encoded, 'PX', ttl)
      return encoded
    `;

    const raw = await this.redis.eval(script, 1, keyForExchange(exchangeId), fulfillerId);
    if (typeof raw !== "string") {
      return null;
    }

    return JSON.parse(raw) as StoredExchange;
  }

  async submitExchange(
    exchangeId: string,
    fulfillerId: string,
    enc: string,
    ciphertext: string,
    expiresAt: number,
    ttlSeconds: number
  ): Promise<StoredExchange | null> {
    const script = `
      local key = KEYS[1]
      local fulfiller_id = ARGV[1]
      local enc = ARGV[2]
      local ciphertext = ARGV[3]
      local expires_at = tonumber(ARGV[4])
      local ttl_ms = tonumber(ARGV[5])

      local raw = redis.call('GET', key)
      if not raw then
        return nil
      end

      local data = cjson.decode(raw)
      if data["status"] ~= "reserved" then
        return nil
      end
      if data["fulfilledBy"] ~= fulfiller_id then
        return nil
      end

      data["status"] = "submitted"
      data["enc"] = enc
      data["ciphertext"] = ciphertext
      data["expiresAt"] = expires_at
      local encoded = cjson.encode(data)
      redis.call('SET', key, encoded, 'PX', ttl_ms)
      return encoded
    `;

    const raw = await this.redis.eval(
      script,
      1,
      keyForExchange(exchangeId),
      fulfillerId,
      enc,
      ciphertext,
      String(expiresAt),
      String(ttlSeconds * 1000)
    );
    if (typeof raw !== "string") {
      return null;
    }

    return JSON.parse(raw) as StoredExchange;
  }

  async atomicRetrieveExchange(exchangeId: string, requesterId: string, workspaceId?: string): Promise<StoredExchange | null> {
    const script = `
      local key = KEYS[1]
      local requester_id = ARGV[1]
      local workspace_id = ARGV[2]
      local raw = redis.call('GET', key)
      if not raw then
        return nil
      end

      local data = cjson.decode(raw)
      if data["requesterId"] ~= requester_id then
        return nil
      end
      if workspace_id ~= '' and data["workspaceId"] ~= workspace_id then
        return nil
      end
      if data["status"] ~= "submitted" then
        return nil
      end

      redis.call('DEL', key)
      return raw
    `;

    const raw = await this.redis.eval(script, 1, keyForExchange(exchangeId), requesterId, workspaceId ?? "");
    if (typeof raw !== "string") {
      return null;
    }

    return JSON.parse(raw) as StoredExchange;
  }

  async setApprovalRequest(data: StoredApprovalRequest, ttlSeconds: number): Promise<void> {
    await this.redis.set(keyForApproval(data.approvalReference), JSON.stringify(data), "EX", ttlSeconds);
  }

  async getApprovalRequest(approvalReference: string): Promise<StoredApprovalRequest | null> {
    const raw = await this.redis.get(keyForApproval(approvalReference));
    return raw ? (JSON.parse(raw) as StoredApprovalRequest) : null;
  }

  async updateApprovalRequest(
    approvalReference: string,
    patch: Partial<StoredApprovalRequest>,
    ttlSeconds?: number,
    expectedStatus?: StoredApprovalRequest["status"]
  ): Promise<StoredApprovalRequest | null> {
    const script = `
      local key = KEYS[1]
      local patch = cjson.decode(ARGV[1])
      local ttl_ms = ARGV[2]
      local expected_status = ARGV[3]

      local raw = redis.call('GET', key)
      if not raw then
        return nil
      end

      local data = cjson.decode(raw)
      if expected_status ~= '' and data["status"] ~= expected_status then
        return nil
      end

      for field, value in pairs(patch) do
        data[field] = value
      end

      local encoded = cjson.encode(data)
      if ttl_ms ~= '' then
        redis.call('SET', key, encoded, 'PX', tonumber(ttl_ms))
      else
        local pttl = redis.call('PTTL', key)
        if pttl > 0 then
          redis.call('SET', key, encoded, 'PX', pttl)
        else
          redis.call('SET', key, encoded)
        end
      end

      return encoded
    `;

    const raw = await this.redis.eval(
      script,
      1,
      keyForApproval(approvalReference),
      JSON.stringify(patch),
      typeof ttlSeconds === "number" ? String(ttlSeconds * 1000) : "",
      expectedStatus ?? ""
    );
    if (typeof raw !== "string") {
      return null;
    }

    return JSON.parse(raw) as StoredApprovalRequest;
  }

  async appendLifecycleRecord(record: ExchangeLifecycleRecord): Promise<void> {
    const encoded = JSON.stringify(record);
    if (record.exchangeId) {
      await this.redis.rpush(keyForExchangeLifecycle(record.exchangeId), encoded);
    }
    if (record.approvalReference) {
      await this.redis.rpush(keyForApprovalLifecycle(record.approvalReference), encoded);
    }
  }

  async listLifecycleRecordsByExchange(exchangeId: string): Promise<ExchangeLifecycleRecord[]> {
    const entries = await this.redis.lrange(keyForExchangeLifecycle(exchangeId), 0, -1);
    return entries.map((entry) => JSON.parse(entry) as ExchangeLifecycleRecord);
  }

  async listLifecycleRecordsByApproval(approvalReference: string): Promise<ExchangeLifecycleRecord[]> {
    const entries = await this.redis.lrange(keyForApprovalLifecycle(approvalReference), 0, -1);
    return entries.map((entry) => JSON.parse(entry) as ExchangeLifecycleRecord);
  }
}

export class InMemoryRequestStore implements RequestStore {
  private readonly data = new Map<string, StoredRequest>();
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly exchanges = new Map<string, StoredExchange>();
  private readonly exchangeTimers = new Map<string, NodeJS.Timeout>();
  private readonly approvals = new Map<string, StoredApprovalRequest>();
  private readonly approvalTimers = new Map<string, NodeJS.Timeout>();
  private readonly exchangeLifecycle = new Map<string, ExchangeLifecycleRecord[]>();
  private readonly approvalLifecycle = new Map<string, ExchangeLifecycleRecord[]>();

  async setRequest(data: StoredRequest, ttlSeconds: number): Promise<void> {
    this.data.set(data.requestId, data);
    this.scheduleExpiry(data.requestId, ttlSeconds);
  }

  async getRequest(requestId: string): Promise<StoredRequest | null> {
    return this.data.get(requestId) ?? null;
  }

  async updateRequest(
    requestId: string,
    patch: Partial<StoredRequest>,
    ttlSeconds?: number,
    expectedStatus?: StoredRequest["status"]
  ): Promise<StoredRequest | null> {
    const current = this.data.get(requestId);
    if (!current || (expectedStatus && current.status !== expectedStatus)) {
      return null;
    }

    const next = { ...current, ...patch };
    this.data.set(requestId, next);
    if (typeof ttlSeconds === "number") {
      this.scheduleExpiry(requestId, ttlSeconds);
    }

    return next;
  }

  async atomicRetrieveAndDelete(requestId: string, requesterId?: string, workspaceId?: string): Promise<StoredRequest | null> {
    const current = this.data.get(requestId);
    if (
      !current ||
      (requesterId && current.requesterId !== requesterId) ||
      (workspaceId && current.workspaceId !== workspaceId)
    ) {
      return null;
    }
    this.clearExpiry(requestId);
    this.data.delete(requestId);
    return current;
  }

  async deleteRequest(requestId: string, requesterId?: string, workspaceId?: string): Promise<boolean> {
    const current = this.data.get(requestId);
    if (
      !current ||
      (requesterId && current.requesterId !== requesterId) ||
      (workspaceId && current.workspaceId !== workspaceId)
    ) {
      return false;
    }

    const existed = this.data.delete(requestId);
    this.clearExpiry(requestId);
    return existed;
  }

  clearAll(): void {
    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }
    this.timers.clear();
    this.data.clear();
    for (const timer of this.exchangeTimers.values()) {
      clearTimeout(timer);
    }
    this.exchangeTimers.clear();
    this.exchanges.clear();
    for (const timer of this.approvalTimers.values()) {
      clearTimeout(timer);
    }
    this.approvalTimers.clear();
    this.approvals.clear();
    this.exchangeLifecycle.clear();
    this.approvalLifecycle.clear();
  }

  async setExchange(data: StoredExchange, ttlSeconds: number): Promise<void> {
    this.exchanges.set(data.exchangeId, data);
    this.scheduleExchangeExpiry(data.exchangeId, ttlSeconds);
  }

  async getExchange(exchangeId: string): Promise<StoredExchange | null> {
    return this.exchanges.get(exchangeId) ?? null;
  }

  async revokeExchange(exchangeId: string, ttlSeconds: number): Promise<StoredExchange | null> {
    const current = this.exchanges.get(exchangeId);
    if (!current) {
      return null;
    }

    const next: StoredExchange = {
      ...current,
      status: "revoked"
    };
    this.exchanges.set(exchangeId, next);
    this.scheduleExchangeExpiry(exchangeId, ttlSeconds);
    return next;
  }

  async reserveExchange(exchangeId: string, fulfillerId: string): Promise<StoredExchange | null> {
    const current = this.exchanges.get(exchangeId);
    if (!current || current.status !== "pending") {
      return null;
    }

    const next: StoredExchange = {
      ...current,
      status: "reserved",
      fulfilledBy: fulfillerId
    };
    this.exchanges.set(exchangeId, next);
    return next;
  }

  async submitExchange(
    exchangeId: string,
    fulfillerId: string,
    enc: string,
    ciphertext: string,
    expiresAt: number,
    ttlSeconds: number
  ): Promise<StoredExchange | null> {
    const current = this.exchanges.get(exchangeId);
    if (!current || current.status !== "reserved" || current.fulfilledBy !== fulfillerId) {
      return null;
    }

    const next: StoredExchange = {
      ...current,
      status: "submitted",
      enc,
      ciphertext,
      expiresAt
    };
    this.exchanges.set(exchangeId, next);
    this.scheduleExchangeExpiry(exchangeId, ttlSeconds);
    return next;
  }

  async atomicRetrieveExchange(exchangeId: string, requesterId: string, workspaceId?: string): Promise<StoredExchange | null> {
    const current = this.exchanges.get(exchangeId);
    if (
      !current ||
      current.requesterId !== requesterId ||
      (workspaceId && current.workspaceId !== workspaceId) ||
      current.status !== "submitted"
    ) {
      return null;
    }

    this.clearExchangeExpiry(exchangeId);
    this.exchanges.delete(exchangeId);
    return current;
  }

  async setApprovalRequest(data: StoredApprovalRequest, ttlSeconds: number): Promise<void> {
    this.approvals.set(data.approvalReference, data);
    this.scheduleApprovalExpiry(data.approvalReference, ttlSeconds);
  }

  async getApprovalRequest(approvalReference: string): Promise<StoredApprovalRequest | null> {
    return this.approvals.get(approvalReference) ?? null;
  }

  async updateApprovalRequest(
    approvalReference: string,
    patch: Partial<StoredApprovalRequest>,
    ttlSeconds?: number,
    expectedStatus?: StoredApprovalRequest["status"]
  ): Promise<StoredApprovalRequest | null> {
    const current = this.approvals.get(approvalReference);
    if (!current || (expectedStatus && current.status !== expectedStatus)) {
      return null;
    }

    const next = { ...current, ...patch };
    this.approvals.set(approvalReference, next);
    if (typeof ttlSeconds === "number") {
      this.scheduleApprovalExpiry(approvalReference, ttlSeconds);
    }

    return next;
  }

  async appendLifecycleRecord(record: ExchangeLifecycleRecord): Promise<void> {
    if (record.exchangeId) {
      const records = this.exchangeLifecycle.get(record.exchangeId) ?? [];
      records.push(record);
      this.exchangeLifecycle.set(record.exchangeId, records);
    }
    if (record.approvalReference) {
      const records = this.approvalLifecycle.get(record.approvalReference) ?? [];
      records.push(record);
      this.approvalLifecycle.set(record.approvalReference, records);
    }
  }

  async listLifecycleRecordsByExchange(exchangeId: string): Promise<ExchangeLifecycleRecord[]> {
    return [...(this.exchangeLifecycle.get(exchangeId) ?? [])];
  }

  async listLifecycleRecordsByApproval(approvalReference: string): Promise<ExchangeLifecycleRecord[]> {
    return [...(this.approvalLifecycle.get(approvalReference) ?? [])];
  }

  private scheduleExpiry(requestId: string, ttlSeconds: number): void {
    this.clearExpiry(requestId);
    const timer = setTimeout(() => {
      this.data.delete(requestId);
      this.timers.delete(requestId);
    }, ttlSeconds * 1000);
    timer.unref();
    this.timers.set(requestId, timer);
  }

  private clearExpiry(requestId: string): void {
    const timer = this.timers.get(requestId);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(requestId);
    }
  }

  private scheduleExchangeExpiry(exchangeId: string, ttlSeconds: number): void {
    this.clearExchangeExpiry(exchangeId);
    const timer = setTimeout(() => {
      this.exchanges.delete(exchangeId);
      this.exchangeTimers.delete(exchangeId);
    }, ttlSeconds * 1000);
    timer.unref();
    this.exchangeTimers.set(exchangeId, timer);
  }

  private clearExchangeExpiry(exchangeId: string): void {
    const timer = this.exchangeTimers.get(exchangeId);
    if (timer) {
      clearTimeout(timer);
      this.exchangeTimers.delete(exchangeId);
    }
  }

  private scheduleApprovalExpiry(approvalReference: string, ttlSeconds: number): void {
    this.clearApprovalExpiry(approvalReference);
    const timer = setTimeout(() => {
      this.approvals.delete(approvalReference);
      this.approvalTimers.delete(approvalReference);
    }, ttlSeconds * 1000);
    timer.unref();
    this.approvalTimers.set(approvalReference, timer);
  }

  private clearApprovalExpiry(approvalReference: string): void {
    const timer = this.approvalTimers.get(approvalReference);
    if (timer) {
      clearTimeout(timer);
      this.approvalTimers.delete(approvalReference);
    }
  }
}

export function createRedisClient(url = process.env.REDIS_URL ?? "redis://127.0.0.1:6379"): Redis {
  const testKeyPrefix = process.env.NODE_ENV === "test" ? process.env.SPS_REDIS_KEY_PREFIX : undefined;
  return new Redis(url, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    keyPrefix: testKeyPrefix || undefined
  });
}
