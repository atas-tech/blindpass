import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { expect } from "vitest";
import { normalizeHttpResult, normalizeSnapshotValue, stableJson } from "./normalization.js";

const SNAPSHOT_FILE = path.resolve(new URL("../fixtures/snapshots/ts-baseline.json", import.meta.url).pathname);

function normalizeRecordName(name: string): string {
  return name
    .replace(/[0-9a-f]{64}/gi, "<id>")
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi, "<uuid>");
}

type SnapshotRecord = Record<string, unknown>;

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

  constructor(private readonly snapshotFile = SNAPSHOT_FILE) {}

  record(name: string, result: { status: number; contentType: string | null; headers?: Headers; body: unknown }): void {
    this.records[normalizeRecordName(name)] = normalizeHttpResult(result);
  }

  recordValue(name: string, value: unknown): void {
    this.records[normalizeRecordName(name)] = normalizeSnapshotValue(value);
  }

  async finish(): Promise<void> {
    const existing = await loadSnapshots(this.snapshotFile);
    if (process.env.UPDATE_CONTRACT_SNAPSHOTS === "1") {
      await mkdir(path.dirname(this.snapshotFile), { recursive: true });
      await writeFile(this.snapshotFile, `${stableJson(this.records)}\n`);
      return;
    }

    if (Object.keys(existing).length === 0) {
      throw new Error(`No contract snapshots found at ${this.snapshotFile}. Run UPDATE_CONTRACT_SNAPSHOTS=1 with disposable fixtures.`);
    }

    expect(this.records).toEqual(existing);
  }
}

export { SNAPSHOT_FILE };
