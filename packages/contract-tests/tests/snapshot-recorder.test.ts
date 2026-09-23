import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { SnapshotRecorder } from "../src/snapshots.js";

describe("contract snapshot failure detection", () => {
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
});
