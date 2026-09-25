import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { SNAPSHOT_FILE, SnapshotRecorder, projectRustSharedSnapshot } from "../src/snapshots.js";

describe("contract snapshot failure detection", () => {
  it("projects reviewed Rust differences from the unchanged full TypeScript baseline", async () => {
    const baseline = JSON.parse(await readFile(SNAPSHOT_FILE, "utf8")) as Record<string, unknown>;
    expect(projectRustSharedSnapshot("CT01.readyz.up", baseline["CT01.readyz.up"])).toEqual({
      status: 200, ok: true, database: "up"
    });
    expect(projectRustSharedSnapshot("CT18.error.503", baseline["CT18.error.503"])).toEqual({
      status: 503, ok: false, database: "down"
    });
    expect(projectRustSharedSnapshot("CT16.cors.disallowed", baseline["CT16.cors.disallowed"])).toEqual({
      allow_origin: null
    });
    expect(projectRustSharedSnapshot("CT17.audit", baseline["CT17.audit"])).toEqual({
      status: 200,
      content_type: "application/json",
      record_shape: ["actor_id", "actor_type", "created_at", "event_type", "id", "ip_address", "metadata", "resource_id", "workspace_id"],
      required_events: ["agent_token_minted", "exchange_pending_approval", "exchange_rejected"]
    });
    expect((baseline["CT17.audit"] as { body: { records: unknown[] } }).body.records.length).toBeGreaterThan(50);
  });

  it("prevents Rust from rewriting the TypeScript baseline", async () => {
    const previousSut = process.env.SUT;
    const previousUpdate = process.env.UPDATE_CONTRACT_SNAPSHOTS;
    process.env.SUT = "rust";
    process.env.UPDATE_CONTRACT_SNAPSHOTS = "1";
    try {
      const recorder = new SnapshotRecorder(SNAPSHOT_FILE);
      recorder.recordValue("CT01.healthz", { status: 200 });
      await expect(recorder.finish()).rejects.toThrow("Rust cannot update");
    } finally {
      if (previousSut === undefined) delete process.env.SUT;
      else process.env.SUT = previousSut;
      if (previousUpdate === undefined) delete process.env.UPDATE_CONTRACT_SNAPSHOTS;
      else process.env.UPDATE_CONTRACT_SNAPSHOTS = previousUpdate;
    }
  });
  it("rejects duplicate names before one observation can overwrite another", () => {
    const recorder = new SnapshotRecorder();
    recorder.recordValue("CT12.same", { status: 200 });
    expect(() => recorder.recordValue("CT12.same", { status: 403 })).toThrow("Duplicate contract snapshot name");
  });
  it("P00-I06 fails on an intentionally mismatched committed snapshot", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "p00-snapshot-fault-"));
    const snapshotFile = path.join(tempDir, "snapshot.json");
    const priorUpdateFlag = process.env.UPDATE_CONTRACT_SNAPSHOTS;
    delete process.env.UPDATE_CONTRACT_SNAPSHOTS;

    try {
      await writeFile(snapshotFile, JSON.stringify({ "CT18.injected": { status: 200 } }));
      const recorder = new SnapshotRecorder(snapshotFile);
      recorder.recordValue("CT18.injected", { status: 201 });

      await expect(recorder.finish()).rejects.toThrow();
      await expect(readFile(snapshotFile, "utf8")).resolves.toContain('"status":200');
    } finally {
      if (priorUpdateFlag === undefined) delete process.env.UPDATE_CONTRACT_SNAPSHOTS;
      else process.env.UPDATE_CONTRACT_SNAPSHOTS = priorUpdateFlag;
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("compares Rust against retained snapshots while excluding hosted user auth", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "p02-snapshot-scope-"));
    const snapshotFile = path.join(tempDir, "snapshot.json");
    const priorSut = process.env.SUT;
    const priorUpdateFlag = process.env.UPDATE_CONTRACT_SNAPSHOTS;
    process.env.SUT = "rust";
    delete process.env.UPDATE_CONTRACT_SNAPSHOTS;
    try {
      await writeFile(snapshotFile, JSON.stringify({ "CT01.healthz": { status: 200 }, "CT14.refresh.valid": { status: 200 } }));
      const recorder = new SnapshotRecorder(snapshotFile);
      recorder.recordValue("CT01.healthz", { status: 200 });
      await expect(recorder.finish()).resolves.toBeUndefined();
    } finally {
      if (priorSut === undefined) delete process.env.SUT;
      else process.env.SUT = priorSut;
      if (priorUpdateFlag === undefined) delete process.env.UPDATE_CONTRACT_SNAPSHOTS;
      else process.env.UPDATE_CONTRACT_SNAPSHOTS = priorUpdateFlag;
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
