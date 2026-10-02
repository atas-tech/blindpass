// Fail-closed canary scanner for test artifacts (P05-PV06-S GUI portion).
//
// A scan proves absence only if it could have found the value, so:
//   * it throws when a root is missing, unreadable or yields no files;
//   * every file is searched for the canary in the encodings a leak could take
//     (raw UTF-8, URL-encoded, JSON-escaped, hex, and base64/base64url at all
//     three alignments), and ZIP archives such as Playwright traces are
//     inflated and each entry is searched too;
//   * an archive cut off before its central directory (Playwright leaves one when
//     a test times out) is read entry by entry; one with nothing readable at all
//     is reported as a finding, not skipped;
//   * `scannerDetects()` is a positive control that plants the canary in each
//     encoding, including inside a deflated ZIP entry, and must see all of them.
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";

export interface Finding {
  file: string;
  entry?: string;
  reason: string;
}

export interface ScanReport {
  files: number;
  bytes: number;
  archives: number;
  /** Archives with no central directory (a test timed out mid-write); read entry by entry instead. */
  partialArchives: number;
  findings: Finding[];
}

const alignedBase64 = (token: Buffer, urlSafe: boolean): string[] => {
  const variants: string[] = [];
  for (let shift = 0; shift < 3; shift += 1) {
    const encoded = Buffer.concat([Buffer.alloc(shift), token]).toString(urlSafe ? "base64url" : "base64");
    // Characters before `start` mix in the padding bytes and the last one may
    // be partial: keep only the characters wholly determined by the token.
    const start = Math.ceil((shift * 8) / 6);
    const usableBits = token.length * 8 - (start * 6 - shift * 8);
    variants.push(encoded.slice(start, start + Math.floor(usableBits / 6)));
  }
  return variants;
};

/** Every encoding of `canary` a leak could plausibly take, as search needles. */
export function needlesFor(canary: string): Buffer[] {
  const token = Buffer.from(canary, "utf8");
  const text = new Set<string>([
    canary,
    encodeURIComponent(canary),
    JSON.stringify(canary).slice(1, -1),
    JSON.stringify(canary).slice(1, -1).replace(/[\u007f-￿]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`),
    token.toString("hex"),
    ...alignedBase64(token, false),
    ...alignedBase64(token, true)
  ]);
  const wide = Buffer.from(canary, "utf16le");
  return [...[...text].filter((value) => value.length >= 8).map((value) => Buffer.from(value, "utf8")), wide];
}

/** Whether `text` contains the canary in any encoding `needlesFor` knows. */
export function mentions(text: string, canary: string): boolean {
  const haystack = Buffer.from(text, "utf8");
  return needlesFor(canary).some((needle) => haystack.includes(needle));
}

interface Entry {
  name: string;
  data: Buffer;
}

/** Minimal ZIP reader (stored and deflate) so trace archives are searched, not skipped. */
function zipEntries(buffer: Buffer): Entry[] {
  let end = -1;
  for (let at = buffer.length - 22; at >= Math.max(0, buffer.length - 22 - 0xffff); at -= 1) {
    if (buffer.readUInt32LE(at) === 0x06054b50) {
      end = at;
      break;
    }
  }
  if (end < 0) throw new Error("no ZIP end record");
  const count = buffer.readUInt16LE(end + 10);
  let at = buffer.readUInt32LE(end + 16);
  const entries: Entry[] = [];
  for (let index = 0; index < count; index += 1) {
    if (buffer.readUInt32LE(at) !== 0x02014b50) throw new Error("bad ZIP central directory");
    const method = buffer.readUInt16LE(at + 10);
    const compressed = buffer.readUInt32LE(at + 20);
    const nameLength = buffer.readUInt16LE(at + 28);
    const extraLength = buffer.readUInt16LE(at + 30);
    const commentLength = buffer.readUInt16LE(at + 32);
    const local = buffer.readUInt32LE(at + 42);
    const name = buffer.subarray(at + 46, at + 46 + nameLength).toString("utf8");
    if (buffer.readUInt32LE(local) !== 0x04034b50) throw new Error("bad ZIP local header");
    const dataStart = local + 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28);
    const raw = buffer.subarray(dataStart, dataStart + compressed);
    if (method === 0) entries.push({ name, data: Buffer.from(raw) });
    else if (method === 8) entries.push({ name, data: zlib.inflateRawSync(raw) });
    else throw new Error(`unsupported ZIP method ${method}`);
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/**
 * Best-effort read of a ZIP without a central directory: walk the local headers
 * and inflate each entry's stream, which yields what was written before the cut.
 * An entry whose stream can't be inflated is searched as raw bytes instead.
 */
function recoverEntries(buffer: Buffer): Entry[] {
  const signature = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  const entries: Entry[] = [];
  let at = buffer.indexOf(signature);
  while (at >= 0 && at + 30 <= buffer.length) {
    const flags = buffer.readUInt16LE(at + 6);
    const method = buffer.readUInt16LE(at + 8);
    const compressed = buffer.readUInt32LE(at + 18);
    const nameLength = buffer.readUInt16LE(at + 26);
    const extraLength = buffer.readUInt16LE(at + 28);
    const start = at + 30 + nameLength + extraLength;
    if (start > buffer.length) break;
    const name = buffer.subarray(at + 30, at + 30 + nameLength).toString("utf8");
    let data: Buffer;
    try {
      if (method === 0 && (flags & 8) === 0) data = Buffer.from(buffer.subarray(start, start + compressed));
      else if (method === 8) data = zlib.inflateRawSync(buffer.subarray(start), { finishFlush: zlib.constants.Z_SYNC_FLUSH });
      else data = Buffer.from(buffer.subarray(start));
    } catch {
      data = Buffer.from(buffer.subarray(start));
    }
    entries.push({ name, data });
    at = buffer.indexOf(signature, start);
  }
  return entries;
}

async function files(root: string): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) found.push(...(await files(full)));
    else if (entry.isFile()) found.push(full);
  }
  return found;
}

function search(data: Buffer, needles: Buffer[], where: Omit<Finding, "reason">, findings: Finding[]): void {
  for (const needle of needles) {
    if (data.includes(needle)) findings.push({ ...where, reason: `contains ${createHash("sha256").update(needle).digest("hex").slice(0, 8)}-needle` });
  }
}

/**
 * Search every file under `roots` for `canary`. Throws, rather than returning a
 * clean report, when it could not have found anything: a missing root, an
 * unreadable file, or no files at all.
 */
export async function scanForCanary(roots: string[], canary: string): Promise<ScanReport> {
  const needles = needlesFor(canary);
  const report: ScanReport = { files: 0, bytes: 0, archives: 0, partialArchives: 0, findings: [] };
  for (const root of roots) {
    if (!(await stat(root)).isDirectory()) throw new Error(`scan root is not a directory: ${root}`);
    for (const file of await files(root)) {
      const data = await readFile(file);
      report.files += 1;
      report.bytes += data.length;
      search(data, needles, { file }, report.findings);
      search(Buffer.from(path.basename(file)), needles, { file, entry: "(file name)" }, report.findings);
      if (/\.zip$/.test(file) || (data.length >= 4 && data.readUInt32LE(0) === 0x04034b50)) {
        report.archives += 1;
        let entries: Entry[];
        try {
          entries = zipEntries(data);
        } catch (error) {
          entries = recoverEntries(data);
          if (entries.length === 0) {
            report.findings.push({ file, reason: `archive could not be read: ${(error as Error).message}` });
            continue;
          }
          report.partialArchives += 1;
        }
        for (const entry of entries) {
          report.bytes += entry.data.length;
          search(entry.data, needles, { file, entry: entry.name }, report.findings);
          search(Buffer.from(entry.name), needles, { file, entry: "(entry name)" }, report.findings);
        }
      }
    }
  }
  if (report.files === 0) throw new Error("the scan found no files, so it proves nothing");
  return report;
}

function crc32(data: Buffer): number {
  return zlib.crc32(data) >>> 0;
}

/** A one-entry deflated ZIP, only for the positive control. */
function zipOf(name: string, data: Buffer, options: { truncated?: boolean } = {}): Buffer {
  const deflated = zlib.deflateRawSync(data);
  const nameBytes = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(crc32(data), 14);
  local.writeUInt32LE(deflated.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(8, 10);
  central.writeUInt32LE(crc32(data), 16);
  central.writeUInt32LE(deflated.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  const body = Buffer.concat([local, nameBytes, deflated]);
  if (options.truncated) return body;
  const directory = Buffer.concat([central, nameBytes]);
  const endRecord = Buffer.alloc(22);
  endRecord.writeUInt32LE(0x06054b50, 0);
  endRecord.writeUInt16LE(1, 8);
  endRecord.writeUInt16LE(1, 10);
  endRecord.writeUInt32LE(directory.length, 12);
  endRecord.writeUInt32LE(body.length, 16);
  return Buffer.concat([body, directory, endRecord]);
}

/**
 * Positive control: plant a different canary in each encoding and inside a
 * deflated ZIP entry, plus a clean file, in a scratch directory. The scanner must
 * report each planted file and leave the clean one alone. Returns the planted
 * file names it found.
 */
export async function scannerDetects(canary: string): Promise<string[]> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "blindpass-scan-control-"));
  try {
    const token = Buffer.from(canary, "utf8");
    const planted: Record<string, Buffer> = {
      "raw.txt": Buffer.from(`before ${canary} after`),
      "url.txt": Buffer.from(`/?q=${encodeURIComponent(canary)}`),
      "json.json": Buffer.from(JSON.stringify({ typed: canary })),
      "base64-0.txt": Buffer.from(`x${token.toString("base64")}x`),
      "base64-1.txt": Buffer.from(`y${Buffer.concat([Buffer.from("a"), token]).toString("base64")}y`),
      "base64-2.txt": Buffer.from(`z${Buffer.concat([Buffer.from("ab"), token]).toString("base64url")}z`),
      "hex.txt": Buffer.from(token.toString("hex")),
      "utf16.bin": Buffer.from(canary, "utf16le"),
      "trace.zip": zipOf("0-trace.network", Buffer.from(`{"postData":"${canary}"}`.repeat(4))),
      // A trace cut off before its central directory, as a timed-out test leaves it.
      "cut.zip": zipOf("0-trace.network", Buffer.from(`{"postData":"${canary}"}`.repeat(4)), { truncated: true })
    };
    for (const [name, data] of Object.entries(planted)) await writeFile(path.join(directory, name), data);
    await writeFile(path.join(directory, "clean.txt"), Buffer.from("nothing secret here"));
    await writeFile(path.join(directory, "clean.zip"), zipOf("clean.txt", Buffer.from("nothing secret here")));
    const report = await scanForCanary([directory], canary);
    const hit = new Set(report.findings.map((finding) => path.basename(finding.file)));
    const missed = Object.keys(planted).filter((name) => !hit.has(name));
    if (missed.length) throw new Error(`the scanner missed planted canaries in: ${missed.join(", ")}`);
    if (hit.has("clean.txt") || hit.has("clean.zip")) throw new Error("the scanner flagged a clean file");
    if (!report.findings.some((finding) => finding.entry === "0-trace.network")) throw new Error("the scanner did not look inside the ZIP entry");
    return [...hit].sort();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
