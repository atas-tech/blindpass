import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { expect } from "vitest";
import { normalizeHttpResult, normalizeSnapshotValue, stableJson } from "./normalization.js";

const SNAPSHOT_FILE = path.resolve(new URL("../fixtures/snapshots/ts-baseline.json", import.meta.url).pathname);
const RUST_PENDING_FILE = path.resolve(new URL("../fixtures/rust-pending.json", import.meta.url).pathname);

function normalizeRecordName(name: string): string {
  return name
    .replace(/[0-9a-f]{64}/gi, "<id>")
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi, "<uuid>");
}

type SnapshotRecord = Record<string, unknown>;

function objectAt(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid TypeScript baseline field: ${name}`);
  }
  return value as Record<string, unknown>;
}

// Keep the full P00 TypeScript baseline immutable for the SPS gate. Rust has
// reviewed response differences in readiness (no Redis check or error code),
// CORS implementation details and audit volume, so compare an explicit
// projection of those legacy observations. All other retained cases still
// compare their complete normalized snapshots.
export function projectRustSharedSnapshot(name: string, value: unknown): unknown {
  if (name === "CT01.readyz.up" || name === "CT18.error.503") {
    const response = objectAt(value, name);
    const body = objectAt(response.body, `${name}.body`);
    const checks = objectAt(body.checks, `${name}.body.checks`);
    return { status: response.status, ok: body.ok, database: checks.database };
  }
  if (name.startsWith("CT16.cors.")) {
    const response = objectAt(value, name);
    const headers = response.headers === undefined ? {} : objectAt(response.headers, `${name}.headers`);
    const allowOrigin = headers["access-control-allow-origin"] ?? null;
    if (name === "CT16.cors.disallowed") {
      return { allow_origin: allowOrigin };
    }
    if (name === "CT16.cors.disallowed-simple") {
      return { status: response.status, allow_origin: allowOrigin };
    }
    return {
      status: response.status,
      allow_origin: allowOrigin,
      allow_credentials: headers["access-control-allow-credentials"] ?? null
    };
  }
  if (name === "CT17.audit") {
    const response = objectAt(value, name);
    const body = objectAt(response.body, `${name}.body`);
    if (!Array.isArray(body.records) || body.records.length === 0) {
      throw new Error("Invalid TypeScript baseline audit records");
    }
    const records = body.records.map((record, index) => objectAt(record, `${name}.body.records[${index}]`));
    const eventTypes = new Set(records.map((record) => record.event_type));
    const requiredEvents = ["agent_token_minted", "exchange_pending_approval", "exchange_rejected"];
    if (!requiredEvents.every((event) => eventTypes.has(event))) {
      throw new Error("Required audit events missing from TypeScript baseline");
    }
    return {
      status: response.status,
      content_type: response.content_type,
      record_shape: Object.keys(records[0]!).sort(),
      required_events: requiredEvents
    };
  }
  return value;
}

async function loadSnapshots(snapshotFile: string): Promise<SnapshotRecord> {
  try {
    return JSON.parse(await readFile(snapshotFile, "utf8")) as SnapshotRecord;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {};
    }
    throw error;
  }
}

export class SnapshotRecorder {
  private readonly records: SnapshotRecord = {};

  constructor(
    private readonly snapshotFile = process.env.CONTRACT_SNAPSHOT_FILE?.trim() || SNAPSHOT_FILE
  ) {}

  record(name: string, result: { status: number; contentType: string | null; headers?: Headers; body: unknown }): void {
    this.recordUnique(name, normalizeHttpResult(result));
  }

  recordValue(name: string, value: unknown): void {
    this.recordUnique(name, normalizeSnapshotValue(value));
  }

  private recordUnique(name: string, value: unknown): void {
    const key = normalizeRecordName(name);
    if (Object.hasOwn(this.records, key)) {
      throw new Error(`Duplicate contract snapshot name: ${key}`);
    }
    this.records[key] = value;
  }

  async finish(): Promise<void> {
    // Focused contract runs intentionally execute only a subset of the cases
    // that populate the shared TypeScript baseline snapshot.
    if (process.env.CONTRACT_SKIP_SNAPSHOT_CHECK === "1") {
      return;
    }

    const existing = await loadSnapshots(this.snapshotFile);
    if (process.env.UPDATE_CONTRACT_SNAPSHOTS === "1") {
      if (process.env.SUT === "rust" && this.snapshotFile === SNAPSHOT_FILE) {
        throw new Error("Rust cannot update the P00 TypeScript baseline snapshot");
      }
      await mkdir(path.dirname(this.snapshotFile), { recursive: true });
      await writeFile(this.snapshotFile, `${stableJson(this.records)}\n`);
      return;
    }

    if (Object.keys(existing).length === 0) {
      throw new Error(`No contract snapshots found at ${this.snapshotFile}. Run UPDATE_CONTRACT_SNAPSHOTS=1 with disposable fixtures.`);
    }

    const actual = { ...this.records };
    const expected = process.env.SUT === "rust"
      ? Object.fromEntries(Object.entries(existing).map(([name, value]) => [name, projectRustSharedSnapshot(name, value)]))
      : { ...existing };
    if (process.env.SUT === "rust") {
      const manifest = JSON.parse(await readFile(RUST_PENDING_FILE, "utf8")) as { pendingIds?: unknown; excludedIds?: unknown };
      if (!Array.isArray(manifest.pendingIds) || !manifest.pendingIds.every((id) => typeof id === "string")
        || !Array.isArray(manifest.excludedIds) || !manifest.excludedIds.every((id) => typeof id === "string")) {
        throw new Error(`Invalid pending contract manifest at ${RUST_PENDING_FILE}`);
      }
      for (const id of [...manifest.pendingIds as string[], ...manifest.excludedIds as string[]]) {
        for (const records of [actual, expected]) {
          for (const key of Object.keys(records)) {
            if (key === id || key.startsWith(`${id}.`)) {
              delete records[key];
            }
          }
        }
      }
    }

    expect(actual).toEqual(expected);
  }
}

export { SNAPSHOT_FILE };
