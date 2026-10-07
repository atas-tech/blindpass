// Protected backup of the files a migration will change (P09-D4). The copies hold the ORIGINAL
// PLAINTEXT by design: they are what makes rollback possible, they are inventoried in the journal and
// manifest, and nothing here deletes them or claims they were erased.
import { createHash } from "node:crypto";
import { BACKUP_ROOT_NAME } from "./constants.mjs";
import { PreflightError } from "./errors.mjs";
import { UnsafePathError } from "./safe-fs.mjs";

const MANIFEST = "MANIFEST.json";
const MAX_BACKUP_FILE_BYTES = 2 * 1024 * 1024;

function sha256(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

async function openOrCreatePrivateDir(parent, name) {
    try {
        return { dir: await parent.openDir(name), created: false };
    } catch (error) {
        if (error instanceof UnsafePathError && error.reason === "not-found") {
            return { dir: await parent.makePrivateDir(name), created: true };
        }
        throw error;
    }
}

export async function createBackup(dir, { migrationId, release, files, now = () => new Date() }) {
    const backupRoot = (await openOrCreatePrivateDir(dir, BACKUP_ROOT_NAME)).dir;
    try {
        const { dir: inner } = await openOrCreatePrivateDir(backupRoot, migrationId);
        try {
            for (const file of files) {
                const existing = await inner.statName(file.name);
                if (existing === null) {
                    await inner.createFileExclusive(file.name, file.bytes);
                }
                const written = await inner.readFile(file.name, { maxBytes: MAX_BACKUP_FILE_BYTES });
                if (written.sha256 !== file.sha256) {
                    throw new PreflightError("backup-conflict", `${file.name} in an existing backup differs from the file being migrated`);
                }
            }
            const summary = Object.fromEntries(files.map((file) => [file.name, { sha256: file.sha256 }]));
            if ((await inner.statName(MANIFEST)) === null) {
                await inner.createFileExclusive(
                    MANIFEST,
                    `${JSON.stringify({
                        version: 1,
                        migrationId,
                        release,
                        createdAt: now().toISOString(),
                        contains: "unencrypted plaintext copies of the files listed below; protect, inventory and delete deliberately",
                        files: summary,
                    }, null, 2)}\n`,
                );
            }
            return { relDir: `${BACKUP_ROOT_NAME}/${migrationId}`, files: summary };
        } finally {
            await inner.close();
        }
    } finally {
        await backupRoot.close();
    }
}

export async function loadBackup(dir, relDir) {
    let current = dir;
    const opened = [];
    try {
        for (const part of relDir.split("/")) {
            current = await current.openDir(part);
            opened.push(current);
        }
        const manifest = JSON.parse((await current.readFile(MANIFEST, { maxBytes: 65536 })).bytes.toString("utf8"));
        const files = {};
        for (const [name, meta] of Object.entries(manifest.files ?? {})) {
            const read = await current.readFile(name, { maxBytes: MAX_BACKUP_FILE_BYTES });
            if (read.sha256 !== meta.sha256) {
                throw new PreflightError("backup-damaged", `${name} in the backup does not match its recorded hash`);
            }
            files[name] = { bytes: read.bytes, sha256: read.sha256 };
        }
        return { manifest, files };
    } catch (error) {
        if (error instanceof PreflightError) {
            throw error;
        }
        if (error instanceof UnsafePathError || error instanceof SyntaxError) {
            throw new PreflightError("backup-damaged", `the backup could not be read (${error.reason ?? "unparsable manifest"})`);
        }
        throw error;
    } finally {
        for (const handle of opened.reverse()) {
            await handle.close();
        }
    }
}
