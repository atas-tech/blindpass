import path from "node:path";
import { PreflightError } from "./errors.mjs";
import { runDryRun } from "./inventory.mjs";
import { isMigrationId } from "./journal.mjs";
import { migrationStatus, rollbackMigration, runMigration } from "./migrate.mjs";
import { nativeReload } from "./native.mjs";
import { PINNED_RELEASES } from "./registry.mjs";
import {
    printable, renderMigrationText, renderPlanJson, renderPlanText, renderRollbackText, renderStatusText,
} from "./render.mjs";
import { UnsafePathError } from "./safe-fs.mjs";
import { acknowledgeKeyBackup, initStore } from "./store.mjs";

export const EXIT = Object.freeze({ OK: 0, FAILED: 1, USAGE: 2, REFUSED: 3 });

const USAGE = `Usage: blindpass-openclaw-migrate <mode> [options]

Modes (exactly one is required; nothing is ever changed implicitly):
  --dry-run              Masked inventory of the OpenClaw credentials this tool can migrate.
                         Creates no file, key, store or lock and runs no other program.
  --init-store           Create the SOPS/age store and key if missing (a distinct, explicit setup step).
  --ack-backup <file>    Prove the key backup <file> can decrypt the store, then clear the
                         bootstrap_backup_pending flag that blocks --apply.
  --apply                Back up, import into the store, rewrite openclaw.json through the native
                         \`openclaw secrets apply\`, verify. Resumes an interrupted run.
  --status               Show the migration journal (stages, backup location, residual files).
  --rollback             Restore what the migration changed; keeps store entries and the backup.
  --reload               Run \`openclaw secrets reload\` after a migration or rollback.

Options:
  --config-dir <path>    Absolute path of the OpenClaw state directory (contains openclaw.json).
                         No symlinks; owned by the current user; not group/other writable.
  --store <path>         Absolute path of the encrypted store (default <config-dir>/blindpass/secrets.enc.json).
                         With --dry-run, naming a store also reports its key and backup state (read-only).
  --resolver-command <p> Absolute path of the blindpass-resolver executable. It must be a real file
                         (not a symlink), owned by you and not group/other writable (OpenClaw's rule).
  --openclaw-bin <path>  Absolute path of the openclaw executable (release ${PINNED_RELEASES.at(-1)}).
  --migration-id <id>    With --rollback: roll back an earlier, archived migration.
  --json                 Print the result as JSON (the same fields, never a value).
  --release <version>    OpenClaw release to validate against (default ${PINNED_RELEASES.at(-1)};
                         reviewed releases: ${PINNED_RELEASES.join(", ")}).
  --provider-alias <a>   Exec provider alias for the references (default blindpass).
  -h, --help             Show this help.
`;

class UsageError extends Error { }

const MODES = { "--dry-run": "dry-run", "--init-store": "init-store", "--apply": "apply", "--status": "status", "--rollback": "rollback", "--reload": "reload" };
const VALUE_FLAGS = {

    "--config-dir": "configDir",
    "--store": "storePath",
    "--resolver-command": "resolverCommand",
    "--openclaw-bin": "openclawBin",
    "--migration-id": "migrationId",
    "--release": "release",
    "--provider-alias": "providerAlias",
};
// --config-dir is validated by the safe filesystem layer (relative-path refusal, exit 3).
const flagName = (field) => (field === "backupPath" ? "--ack-backup" : Object.keys(VALUE_FLAGS).find((name) => VALUE_FLAGS[name] === field));
const ABSOLUTE = new Set(["storePath", "resolverCommand", "openclawBin", "backupPath"]);
const REQUIRED = {
    "dry-run": ["configDir"],
    apply: ["configDir", "resolverCommand", "openclawBin"],
    rollback: ["configDir"],
    status: ["configDir"],
    reload: ["configDir", "openclawBin"],
    "init-store": [],
    "ack-backup": ["backupPath"],
};

function parseArgs(argv) {
    const options = { json: false, release: PINNED_RELEASES.at(-1) };
    const modes = [];
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === "-h" || arg === "--help") {
            return { help: true };
        }
        if (Object.hasOwn(MODES, arg)) {
            modes.push(MODES[arg]);
        } else if (arg === "--json") {
            options.json = true;
        } else if (arg === "--ack-backup") {
            modes.push("ack-backup");
            const value = argv[i + 1];
            if (value === undefined || value.startsWith("--")) {
                throw new UsageError("--ack-backup needs a value");
            }
            options.backupPath = value;
            i += 1;
        } else if (Object.hasOwn(VALUE_FLAGS, arg)) {
            const value = argv[i + 1];
            if (value === undefined || value.startsWith("--")) {
                throw new UsageError(`${arg} needs a value`);
            }
            options[VALUE_FLAGS[arg]] = value;
            i += 1;
        } else {
            throw new UsageError(`unknown argument ${JSON.stringify(arg.slice(0, 40))}`);
        }
    }
    if (modes.length !== 1) {
        throw new UsageError("choose exactly one mode");
    }
    const mode = modes[0];
    const explicitStore = options.storePath !== undefined;
    for (const field of REQUIRED[mode]) {
        if (!options[field]) {
            throw new UsageError(`${flagName(field)} is required with --${mode}`);
        }
    }
    for (const field of ABSOLUTE) {
        if (options[field] !== undefined && !path.isAbsolute(options[field])) {
            throw new UsageError(`${flagName(field)} must be an absolute path`);
        }
    }
    if (options.migrationId !== undefined && (mode !== "rollback" || !isMigrationId(options.migrationId))) {
        throw new UsageError("--migration-id must be a migration id and is only valid with --rollback");
    }
    if ((mode === "init-store" || mode === "ack-backup") && !options.storePath && !options.configDir) {
        throw new UsageError(`--store or --config-dir is required with --${mode}`);
    }
    if (!options.storePath && options.configDir && path.isAbsolute(options.configDir)) {
        options.storePath = path.join(options.configDir, "blindpass", "secrets.enc.json");
    }
    // The dry run only reads a store the operator names; the default location is not assumed.
    options.checkStore = explicitStore;
    return { mode, options };
}

async function execute(mode, options, io) {
    const { stdout, stderr } = io;
    const emit = (value, text) => stdout.write(options.json ? `${JSON.stringify(value, null, 2)}\n` : text);
    switch (mode) {
        case "dry-run": {
            const { plan } = await runDryRun({
                configDir: options.configDir,
                release: options.release,
                providerAlias: options.providerAlias,
                storePath: options.checkStore ? options.storePath : undefined,
            });
            stdout.write(options.json ? renderPlanJson(plan) : renderPlanText(plan));
            return;
        }
        case "init-store": {
            const result = await initStore({ storePath: options.storePath, stderr });
            const text = result.created
                ? `Store created at ${printable(options.storePath)} with a new age key (${printable(result.ageKeyPath)}).\nBack up that key file, then run --ack-backup <key backup file> before --apply.\n`
                : `Store already exists at ${printable(options.storePath)}; nothing was created.\n`;
            emit({ created: result.created, storePath: options.storePath }, text);
            return;
        }
        case "ack-backup": {
            const result = await acknowledgeKeyBackup({ storePath: options.storePath, backupPath: options.backupPath });
            const text = result.updated
                ? "Key backup acknowledged: the backup key was shown to decrypt the store on its own, and the bootstrap_backup_pending flag is cleared. --apply is now allowed.\n"
                : `Nothing changed: ${result.reason === "already-acknowledged" ? "the key backup was already acknowledged" : printable(result.reason ?? "no update")}.\n`;
            emit(result, text);
            return;
        }
        case "apply": {
            const result = await runMigration(options);
            emit(result, renderMigrationText(result));
            return;
        }
        case "status": {
            const status = await migrationStatus(options);
            emit(status, renderStatusText(status));
            return;
        }
        case "rollback": {
            const result = await rollbackMigration(options);
            emit(result, renderRollbackText(result));
            return;
        }
        case "reload": {
            const result = await nativeReload(options.openclawBin, { configDir: options.configDir });
            const text = result.state === "ok"
                ? "Reload accepted by the gateway. Confirm with an authenticated request: the migration is complete only when the runtime has used the new references.\n"
                : `Reload ${result.state}${result.detail ? `: ${printable(result.detail)}` : ""}. Verify with an authenticated request; the reload exit status alone does not prove activation.\n`;
            emit(result, text);
            return;
        }
        default:
            throw new UsageError("unknown mode");
    }
}

export async function main(argv, { stdout = process.stdout, stderr = process.stderr } = {}) {
    let parsed;
    try {
        parsed = parseArgs(argv);
    } catch (error) {
        if (!(error instanceof UsageError)) {
            throw error;
        }
        stderr.write(`error: ${error.message}\n\n${USAGE}`);
        return EXIT.USAGE;
    }
    if (parsed.help) {
        stdout.write(USAGE);
        return EXIT.OK;
    }

    try {
        await execute(parsed.mode, parsed.options, { stdout, stderr });
        return EXIT.OK;
    } catch (error) {
        if (error instanceof PreflightError && error.stage) {
            stderr.write(`failed during the ${error.stage} stage: ${printable(error.message)}\nRun --status to inspect, --apply to resume, or --rollback to restore the original.\n`);
            return EXIT.FAILED;
        }
        if (error instanceof PreflightError || error instanceof UnsafePathError || ["JournalError", "LockHeldError"].includes(error?.name)) {
            stderr.write(`refused: ${printable(error.message)}\n`);
            return EXIT.REFUSED;
        }
        if (/^Unsupported OpenClaw release/.test(error?.message ?? "")) {
            stderr.write(`refused: ${error.message}\n`);
            return EXIT.REFUSED;
        }
        stderr.write(`error: ${error?.code ?? error?.name ?? "failed"}\n`);
        return EXIT.FAILED;
    }
}
