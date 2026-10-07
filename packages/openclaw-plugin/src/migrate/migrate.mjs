// Migration orchestrator (P09-D4): inventory → backup → import → rewrite → commit, each stage
// journaled with an intent before its effect and a completion after. A rerun reconciles real file and
// store state instead of trusting the journal; rollback restores only what this migration changed.
//
// Plaintext lifetime: values are read from the protected backup copy of openclaw.json into memory for
// the import stage only, handed to the SOPS store and the resolver check, and dropped. They are never
// written to the journal, the apply plan, stdout, stderr or an error message.
import { classifySecretInput } from "./classify.mjs";
import { acquireMigrationLock, Journal, isMigrationId } from "./journal.mjs";
import { archivedJournalName, DEFAULT_PROVIDER_ALIAS, MAX_FILE_BYTES, PLAN_NAME } from "./constants.mjs";
import { changedPaths, deleteAt, getAt, hasAt, isMap, isRef, sameConfig } from "./config-edit.mjs";
import { PreflightError } from "./errors.mjs";
import { collectInventory, scanResidual } from "./inventory.mjs";
import { applyPlan, assertSupportedNative, nativeAudit } from "./native.mjs";
import { buildApplyPlan, providerDefinition } from "./plan.mjs";
import { createBackup, loadBackup } from "./backup.mjs";
import { PINNED_RELEASES, loadRegistry } from "./registry.mjs";
import { checkResolverCommand } from "./resolver-trust.mjs";
import { openTrustedRoot } from "./safe-fs.mjs";
import { importEntries, inspectStore, verifyViaResolver } from "./store.mjs";

const CONFIG = "openclaw.json";
const MIN_SCANNABLE_LENGTH = 8;
const REJECTED_REASON = "runtime-does-not-accept-target";

function normalize(options) {
    const release = options.release ?? PINNED_RELEASES.at(-1);
    loadRegistry(release);
    const ctx = {
        configDir: options.configDir,
        release,
        providerAlias: options.providerAlias ?? DEFAULT_PROVIDER_ALIAS,
        resolverCommand: options.resolverCommand,
        storePath: options.storePath,
        openclawBin: options.openclawBin,
        hooks: options.hooks,
        now: options.now ?? (() => new Date()),
        uid: options.uid,
    };
    for (const [name, value] of [["resolverCommand", ctx.resolverCommand], ["storePath", ctx.storePath], ["openclawBin", ctx.openclawBin]]) {
        if (typeof value !== "string" || !value.startsWith("/")) {
            throw new PreflightError("invalid-option", `${name} must be an absolute path`);
        }
    }
    return ctx;
}

const openRoot = (ctx) => openTrustedRoot(ctx.configDir, ctx.uid === undefined ? {} : { uid: ctx.uid });

async function hook(ctx, point) {
    if (ctx.hooks?.at) {
        await ctx.hooks.at(point);
    }
}

function parseConfig(bytes) {
    let value;
    try {
        value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
        throw new PreflightError("config-unreadable", "openclaw.json is not strict JSON");
    }
    if (!isMap(value)) {
        throw new PreflightError("config-unreadable", "openclaw.json is not an object");
    }
    return value;
}

async function readConfig(dir) {
    const file = await dir.readFile(CONFIG, { maxBytes: MAX_FILE_BYTES });
    return { ...file, config: parseConfig(file.bytes) };
}

function indentOf(bytes) {
    const match = /\n([ \t]+)\S/.exec(bytes.toString("utf8"));
    return match ? match[1] : "  ";
}

async function putPlan(dir, plan) {
    if ((await dir.statName(PLAN_NAME)) !== null) {
        await dir.removeFile(PLAN_NAME);
    }
    await dir.createFileExclusive(PLAN_NAME, `${JSON.stringify(plan, null, 2)}\n`);
}

async function dropPlan(dir) {
    if ((await dir.statName(PLAN_NAME)) !== null) {
        await dir.removeFile(PLAN_NAME);
    }
}

function expectedProvider(ctx) {
    return providerDefinition({ resolverCommand: ctx.resolverCommand, storePath: ctx.storePath });
}

function assertProviderCompatible(ctx, config) {
    const existing = getAt(config, ["secrets", "providers", ctx.providerAlias]);
    if (existing !== undefined && !sameConfig(existing, expectedProvider(ctx))) {
        throw new PreflightError(
            "provider-alias-conflict",
            `secrets.providers.${ctx.providerAlias} already exists with a different definition; choose another --provider-alias`,
        );
    }
}

function otherExecProviders(ctx, config) {
    const providers = getAt(config, ["secrets", "providers"]);
    if (!isMap(providers)) {
        return [];
    }
    return Object.keys(providers).filter((alias) => alias !== ctx.providerAlias && providers[alias]?.source === "exec").sort();
}

function assertJournalMatches(ctx, journal) {
    const state = journal.state;
    for (const [field, value] of [
        ["release", ctx.release],
        ["providerAlias", ctx.providerAlias],
        ["storePath", ctx.storePath],
        ["resolverCommand", ctx.resolverCommand],
    ]) {
        if (state[field] !== value) {
            throw new PreflightError("journal-mismatch", `the unfinished migration ${state.migrationId} was started with a different ${field}; use the same settings or roll it back`);
        }
    }
}

async function preflightStore(ctx) {
    const store = await inspectStore({ storePath: ctx.storePath });
    if (store.state === "missing") {
        throw new PreflightError("store-missing", "the destination store does not exist; run --init-store first");
    }
    if (store.backupPending) {
        throw new PreflightError("key-backup-pending", "the store key backup has not been acknowledged; run --ack-backup first");
    }
    return store;
}

// Which of the inventory's migratable targets the installed runtime accepts. The whole plan is tried
// first; only a rejection triggers the per-target check, so a runtime that knows every target costs
// one native call.
async function partitionByRuntime(ctx, dir, targets) {
    const planPath = `${ctx.configDir}/${PLAN_NAME}`;
    const redact = targets.map((target) => target.value);
    const dryRun = async (subset) => {
        await putPlan(dir, buildApplyPlan({ targets: subset, providerAlias: ctx.providerAlias, resolverCommand: ctx.resolverCommand, storePath: ctx.storePath }));
        await applyPlan(ctx.openclawBin, planPath, { configDir: ctx.configDir, dryRun: true, allowExec: false, redact });
    };
    try {
        await dryRun(targets);
        return { accepted: targets, rejected: [] };
    } catch (error) {
        if (!(error instanceof PreflightError) || error.reason !== "native-plan-rejected") {
            throw error;
        }
    }
    const accepted = [];
    const rejected = [];
    for (const target of targets) {
        try {
            await dryRun([target]);
            accepted.push(target);
        } catch (error) {
            if (!(error instanceof PreflightError) || error.reason !== "native-plan-rejected") {
                throw error;
            }
            rejected.push(target);
        }
    }
    return { accepted, rejected };
}

function describeTargets(targets) {
    return targets.map((target) => ({ path: target.path, registryId: target.registryId, segments: target.segments, ref: target.ref }));
}

function buildResult(journal, status) {
    const state = journal.state;
    const unsupported = [...(state.unsupported ?? []), ...(state.rejected ?? [])];
    const residual = state.residual ?? [];
    const nextSteps = [
        "Make the runtime resolve the new references: a gateway that watches openclaw.json restarts itself when it sees this change; otherwise restart it or run `openclaw secrets reload` (or this tool with --reload). Secrets you later change in the store only are not live until a reload. Confirm with an authenticated request.",
    ];
    if (residual.length > 0) {
        nextSteps.push(`${residual.length} file(s) still hold plaintext copies of migrated values (${residual.join(", ")}). This tool does not delete them; remove or protect them deliberately.`);
    }
    if (state.backupDir) {
        nextSteps.push(`The protected backup ${state.backupDir} holds the original plaintext; keep or remove it under your retention policy.`);
    }
    if (unsupported.length > 0) {
        nextSteps.push(`${unsupported.length} credential field(s) were not migrated and remain as they were.`);
    }
    return {
        status,
        migrationId: state.migrationId,
        migrated: state.targets.map((target) => ({ path: target.path, reference: target.ref.id })),
        unsupported,
        residual,
        warnings: state.warnings ?? [],
        backupDir: state.backupDir ?? null,
        nextSteps,
    };
}

export async function runMigration(options) {
    const ctx = normalize(options);
    const dir = await openRoot(ctx);
    try {
        await checkResolverCommand(ctx.resolverCommand, ctx.uid === undefined ? {} : { uid: ctx.uid });
        await assertSupportedNative(ctx.openclawBin, { configDir: ctx.configDir, release: ctx.release });

        const peek = await Journal.load(dir);
        if (peek?.state.status === "rollback-in-progress") {
            throw new PreflightError("rollback-unfinished", `migration ${peek.state.migrationId} is being rolled back; run --rollback to finish it`);
        }
        const resuming = peek !== null && (peek.state.status === "in-progress" || peek.state.status === "failed");
        if (resuming) {
            assertJournalMatches(ctx, peek);
        }
        await preflightStore(ctx);

        const inventory = await collectInventory({ dir, configDir: ctx.configDir, release: ctx.release, providerAlias: ctx.providerAlias });
        if (inventory.config) {
            assertProviderCompatible(ctx, inventory.config);
        }
        if (!resuming) {
            if (inventory.migratable.length === 0) {
                return nothingToMigrate(inventory);
            }
            const conflicts = (await inspectStore({
                storePath: ctx.storePath,
                check: inventory.migratable.map((target) => ({ name: target.ref.id, value: target.value })),
            })).conflicts ?? [];
            if (conflicts.length > 0) {
                throw new PreflightError("store-name-conflict", `${conflicts.length} store name(s) already hold a different value`, { names: conflicts });
            }
        }

        const lock = await acquireMigrationLock(dir);
        try {
            return await execute(ctx, dir);
        } finally {
            await lock.release();
        }
    } finally {
        await dir.close();
    }
}

function nothingToMigrate(inventory) {
    return {
        status: "nothing-to-migrate",
        migrationId: null,
        migrated: [],
        unsupported: inventory.plan.rows.filter((row) => row.status === "unsupported").map((row) => ({ path: row.keyPath, reason: row.reason })),
        residual: [],
        warnings: inventory.plan.warnings,
        backupDir: null,
        nextSteps: [],
    };
}

async function execute(ctx, dir) {
    let journal = await Journal.load(dir);
    if (journal && (journal.state.status === "committed" || journal.state.status === "rolled-back")) {
        await journal.archive();
        journal = null;
    }
    if (journal === null) {
        journal = await Journal.create(dir, {
            release: ctx.release,
            providerAlias: ctx.providerAlias,
            storePath: ctx.storePath,
            resolverCommand: ctx.resolverCommand,
            now: ctx.now,
        });
    } else {
        assertJournalMatches(ctx, journal);
        if (journal.state.status === "failed") {
            await journal.setField("failure", null, ctx.now());
            await journal.setStatus("in-progress", ctx.now());
        }
    }
    const notes = journal.staleness(ctx.now());
    if (notes) {
        await journal.setField("warnings", [...new Set([...(journal.state.warnings ?? []), notes])], ctx.now());
    }

    let stage = "inventory";
    const runStage = async (name, effect) => {
        stage = name;
        if (journal.state.stages[name]?.done) {
            return;
        }
        await journal.stageIntent(name, ctx.now());
        await hook(ctx, `${name}:after-intent`);
        const outcome = await effect();
        await hook(ctx, `${name}:after-effect`);
        await journal.stageDone(name, ctx.now());
        return outcome;
    };

    try {
        const empty = await runStage("inventory", () => inventoryStage(ctx, dir, journal));
        if (empty === "nothing") {
            await dropPlan(dir);
            await journal.remove();
            return { status: "nothing-to-migrate", migrationId: null, migrated: [], unsupported: [], residual: [], warnings: [], backupDir: null, nextSteps: [] };
        }
        await runStage("backup", () => backupStage(ctx, dir, journal));
        await runStage("import", () => importStage(ctx, dir, journal));
        await runStage("rewrite", () => rewriteStage(ctx, dir, journal));
        await runStage("commit", () => commitStage(ctx, dir, journal));
        if (journal.state.status !== "committed") {
            await journal.setStatus("committed", ctx.now());
        }
        return buildResult(journal, "committed");
    } catch (error) {
        await recordFailure(ctx, journal, stage, error);
        if (error !== null && typeof error === "object") {
            error.stage = stage;
        }
        throw error;
    }
}

async function recordFailure(ctx, journal, stage, error) {
    try {
        await journal.setField("failure", { stage, reason: String(error?.reason ?? error?.name ?? "failed").slice(0, 80) }, ctx.now());
        await journal.setStatus("failed", ctx.now());
    } catch {
        // The original error is the one to surface; a journal that cannot be updated stays as it was.
    }
}

async function inventoryStage(ctx, dir, journal) {
    const inventory = await collectInventory({ dir, configDir: ctx.configDir, release: ctx.release, providerAlias: ctx.providerAlias });
    if (inventory.migratable.length === 0) {
        return "nothing";
    }
    const { accepted, rejected } = await partitionByRuntime(ctx, dir, inventory.migratable);
    await dropPlan(dir);
    if (accepted.length === 0) {
        return "nothing";
    }
    await journal.setTargets(describeTargets(accepted), ctx.now());
    await journal.setField("rejected", rejected.map((target) => ({ path: target.path, reason: REJECTED_REASON })), ctx.now());
    await journal.setField(
        "unsupported",
        inventory.plan.rows.filter((row) => row.status === "unsupported" && row.file === CONFIG).map((row) => ({ path: row.keyPath, reason: row.reason })),
        ctx.now(),
    );
    await journal.setFiles({ [CONFIG]: { sha256: inventory.configSha256 } }, ctx.now());
    return "ok";
}

async function backupStage(ctx, dir, journal) {
    const current = await readConfig(dir);
    // The backup is the source of truth from here on: only targets that still hold a plaintext value in
    // the bytes being backed up are migrated, so a change between inventory and backup is harmless.
    const still = journal.state.targets.filter((target) => classifySecretInput(getAt(current.config, target.segments)).kind === "plaintext");
    if (still.length === 0) {
        throw new PreflightError("config-changed", "no credential to migrate remains in openclaw.json");
    }
    const backup = await createBackup(dir, {
        migrationId: journal.state.migrationId,
        release: ctx.release,
        files: [{ name: CONFIG, bytes: current.bytes, sha256: current.sha256 }],
        now: ctx.now,
    });
    await journal.setField("backupDir", backup.relDir, ctx.now());
    await journal.setFiles({ [CONFIG]: { sha256: current.sha256 } }, ctx.now());
    await journal.setTargets(still, ctx.now());
}

async function backedUpConfig(dir, journal) {
    const backup = await loadBackup(dir, journal.state.backupDir);
    const file = backup.files[CONFIG];
    if (!file) {
        throw new PreflightError("backup-damaged", "the backup holds no openclaw.json");
    }
    return { ...file, config: parseConfig(file.bytes) };
}

async function importStage(ctx, dir, journal) {
    const { config } = await backedUpConfig(dir, journal);
    const entries = journal.state.targets.map((target) => {
        const value = getAt(config, target.segments);
        if (typeof value !== "string" || value === "") {
            throw new PreflightError("config-changed", `${target.path} no longer holds a migratable value in the backup`);
        }
        return { name: target.ref.id, value, source: `openclaw.json:${target.path}` };
    });
    await importEntries({ storePath: ctx.storePath, entries, migrationId: journal.state.migrationId });
    await verifyViaResolver({ resolverCommand: ctx.resolverCommand, storePath: ctx.storePath, entries, providerAlias: ctx.providerAlias });
    await journal.setImported(entries.map((entry) => entry.name), ctx.now());
}

async function rewriteStage(ctx, dir, journal) {
    const targets = journal.state.targets;
    const backup = await backedUpConfig(dir, journal);
    const current = await readConfig(dir);

    const changed = [];
    let applied = 0;
    for (const target of targets) {
        const value = getAt(current.config, target.segments);
        if (isRef(value, target.ref)) {
            applied += 1;
        } else if (value !== getAt(backup.config, target.segments)) {
            changed.push(target.path);
        }
    }
    if (changed.length > 0) {
        throw new PreflightError("config-changed", `${changed.length} credential field(s) changed after the backup; the migration will not overwrite them`, { paths: changed });
    }

    const providerOk = sameConfig(getAt(current.config, ["secrets", "providers", ctx.providerAlias]), expectedProvider(ctx));
    if (!(applied === targets.length && providerOk)) {
        const plan = buildApplyPlan({ targets, providerAlias: ctx.providerAlias, resolverCommand: ctx.resolverCommand, storePath: ctx.storePath });
        await putPlan(dir, plan);
        const planPath = `${ctx.configDir}/${PLAN_NAME}`;
        // Resolvability first (the native dry run runs the resolver), then the real write. Any native
        // output that is quoted back has the migrated values masked first.
        const redact = targets.map((target) => getAt(backup.config, target.segments)).filter((value) => typeof value === "string");
        await applyPlan(ctx.openclawBin, planPath, { configDir: ctx.configDir, dryRun: true, allowExec: true, redact });
        await applyPlan(ctx.openclawBin, planPath, { configDir: ctx.configDir, dryRun: false, allowExec: true, redact });
    }

    const after = await readConfig(dir);
    for (const target of targets) {
        if (!isRef(getAt(after.config, target.segments), target.ref)) {
            throw new PreflightError("rewrite-verification-failed", `${target.path} does not hold its reference after the rewrite`);
        }
    }
    if (!sameConfig(getAt(after.config, ["secrets", "providers", ctx.providerAlias]), expectedProvider(ctx))) {
        throw new PreflightError("rewrite-verification-failed", "the exec provider is not configured as planned");
    }
    const outside = changedPaths(backup.config, after.config, [
        ...targets.map((target) => target.segments),
        ["secrets", "providers", ctx.providerAlias],
        ["meta"],
    ]);
    const warnings = [...new Set([
        ...(journal.state.warnings ?? []),
        ...(outside.length > 0 ? [`config-changed-outside-plan: ${outside.slice(0, 20).join(", ")}${outside.length > 20 ? ", ..." : ""}`] : []),
    ])];
    await journal.setField("warnings", warnings, ctx.now());
    // A byte-for-byte restore is only valid when the config being rewritten was exactly the backed-up
    // one; after any edit in between (or a resumed run) rollback restores path by path instead.
    if (current.sha256 === backup.sha256) {
        await journal.setField("afterSha256", after.sha256, ctx.now());
    }
}

async function commitStage(ctx, dir, journal) {
    const backup = await backedUpConfig(dir, journal);
    const values = journal.state.targets
        .map((target) => getAt(backup.config, target.segments))
        .filter((value) => typeof value === "string" && value.length >= MIN_SCANNABLE_LENGTH);
    const warnings = [...(journal.state.warnings ?? [])];
    const residual = (await scanResidual(dir, values, warnings, { includeEnv: true })).map((entry) => entry.file);
    const skipped = journal.state.targets.filter((target) => String(getAt(backup.config, target.segments)).length < MIN_SCANNABLE_LENGTH);
    if (skipped.length > 0) {
        warnings.push(`short-value-not-scanned: ${skipped.length} value(s) shorter than ${MIN_SCANNABLE_LENGTH} characters were not searched for in other files`);
    }

    const current = await readConfig(dir);
    const others = otherExecProviders(ctx, current.config);
    if (others.length > 0) {
        warnings.push(`native-audit-skipped: other exec providers are configured (${others.join(", ")}) and --allow-exec would run them`);
    } else {
        const audit = await nativeAudit(ctx.openclawBin, { configDir: ctx.configDir, allowExec: true, redact: values });
        const summary = audit.summary ?? {};
        if ((summary.unresolvedRefCount ?? 0) > 0) {
            throw new PreflightError("verify-unresolved-refs", `OpenClaw cannot resolve ${summary.unresolvedRefCount} reference(s)`);
        }
        if ((summary.plaintextCount ?? 0) > 0) {
            warnings.push(`native-audit-plaintext: ${summary.plaintextCount} plaintext finding(s) remain (fields this tool did not migrate)`);
        }
    }
    await dropPlan(dir);
    await journal.setField("residual", residual.sort(), ctx.now());
    await journal.setField("warnings", [...new Set(warnings)].sort(), ctx.now());
}

export async function migrationStatus(options) {
    const ctx = { configDir: options.configDir, uid: options.uid, now: options.now ?? (() => new Date()) };
    const dir = await openRoot(ctx);
    try {
        const journal = await Journal.load(dir);
        if (journal === null) {
            return { status: "none" };
        }
        const state = journal.state;
        const warnings = [...(state.warnings ?? [])];
        if (state.status === "in-progress" || state.status === "failed" || state.status === "rollback-in-progress") {
            const stale = journal.staleness(ctx.now());
            if (stale) {
                warnings.push(stale);
            }
        }
        return {
            status: state.status,
            migrationId: state.migrationId,
            release: state.release,
            startedAt: state.startedAt,
            updatedAt: state.updatedAt,
            stages: state.stages,
            targets: state.targets.map((target) => ({ path: target.path, reference: target.ref.id })),
            unsupported: [...(state.unsupported ?? []), ...(state.rejected ?? [])],
            backupDir: state.backupDir ?? null,
            residual: state.residual ?? [],
            warnings,
            failure: state.failure ?? null,
            rollback: state.rollback ?? null,
        };
    } finally {
        await dir.close();
    }
}

async function loadJournalFor(dir, migrationId) {
    if (migrationId !== undefined && !isMigrationId(migrationId)) {
        throw new PreflightError("invalid-migration-id", "the migration id is malformed");
    }
    const active = await Journal.load(dir);
    if (migrationId === undefined || active?.state.migrationId === migrationId) {
        return active;
    }
    return Journal.load(dir, archivedJournalName(migrationId));
}

// Restores what this migration changed. If the config still has the exact post-migration bytes the
// original is restored byte for byte; otherwise only the paths that still hold this migration's
// references are restored, so unrelated later edits survive. The store and the backup are kept.
export async function rollbackMigration(options) {
    const ctx = { configDir: options.configDir, uid: options.uid, hooks: options.hooks, now: options.now ?? (() => new Date()) };
    const dir = await openRoot(ctx);
    try {
        const peek = await loadJournalFor(dir, options.migrationId);
        if (peek === null) {
            throw new PreflightError("no-migration", "no migration journal was found in this config directory");
        }
        const lock = await acquireMigrationLock(dir);
        try {
            const journal = await loadJournalFor(dir, options.migrationId);
            if (journal.state.status === "rolled-back") {
                return { status: "already-rolled-back", migrationId: journal.state.migrationId };
            }
            return await rollbackLocked(ctx, dir, journal);
        } finally {
            await lock.release();
        }
    } finally {
        await dir.close();
    }
}

async function rollbackLocked(ctx, dir, journal) {
    const state = journal.state;
    if (state.status !== "rollback-in-progress") {
        await journal.setStatus("rollback-in-progress", ctx.now());
    }
    await hook(ctx, "rollback:after-intent");

    let method = "none";
    const restored = [];
    const left = [];
    if (state.stages.rewrite?.intent) {
        if (!state.backupDir) {
            throw new PreflightError("backup-unavailable", "the journal records no backup to restore from");
        }
        const backup = await backedUpConfig(dir, journal);
        const current = await readConfig(dir);
        const beforeSha = state.files[CONFIG]?.sha256;
        if (current.sha256 === beforeSha) {
            method = "unchanged";
        } else if (state.afterSha256 && current.sha256 === state.afterSha256) {
            await dir.replaceFile(CONFIG, backup.bytes, { expectedSha256: current.sha256 });
            method = "byte-for-byte";
            restored.push(...state.targets.map((target) => target.path));
        } else {
            const config = structuredClone(current.config);
            for (const target of state.targets) {
                if (isRef(getAt(config, target.segments), target.ref)) {
                    const parent = getAt(config, target.segments.slice(0, -1));
                    parent[target.segments.at(-1)] = getAt(backup.config, target.segments);
                    restored.push(target.path);
                } else {
                    left.push(target.path);
                }
            }
            const providerPath = ["secrets", "providers", state.providerAlias];
            const ours = { source: "exec", command: state.resolverCommand, args: ["--store", state.storePath] };
            const provider = getAt(config, providerPath);
            const stillReferenced = JSON.stringify(config).includes(`"provider":"${state.providerAlias}"`);
            let touched = restored.length > 0;
            if (
                provider !== undefined
                && !hasAt(backup.config, providerPath)
                && provider.command === ours.command
                && sameConfig(provider.args, ours.args)
                && !stillReferenced
            ) {
                deleteAt(config, providerPath);
                if (!hasAt(backup.config, ["secrets", "providers"]) && sameConfig(getAt(config, ["secrets", "providers"]), {})) {
                    deleteAt(config, ["secrets", "providers"]);
                }
                if (!hasAt(backup.config, ["secrets"]) && sameConfig(getAt(config, ["secrets"]), {})) {
                    deleteAt(config, ["secrets"]);
                }
                touched = true;
            }
            if (touched) {
                const text = `${JSON.stringify(config, null, indentOf(current.bytes))}\n`;
                await dir.replaceFile(CONFIG, text, { expectedSha256: current.sha256 });
                method = "per-path";
            } else {
                method = "unchanged";
            }
        }
        await hook(ctx, "rollback:after-restore");

        const verified = await readConfig(dir);
        for (const target of state.targets) {
            if (restored.includes(target.path) && isRef(getAt(verified.config, target.segments), target.ref)) {
                throw new PreflightError("rollback-verification-failed", `${target.path} still holds its migration reference`);
            }
        }
    } else {
        await hook(ctx, "rollback:after-restore");
    }

    await dropPlan(dir);
    await journal.setField("rollback", { method, restored: restored.sort(), left: left.sort() }, ctx.now());
    await journal.setStatus("rolled-back", ctx.now());
    return {
        status: "rolled-back",
        migrationId: state.migrationId,
        method,
        restored: restored.sort(),
        left: left.sort(),
        backupDir: state.backupDir ?? null,
        nextSteps: [
            "Reload the runtime so it stops using the migration's references: run `openclaw secrets reload`.",
            "Encrypted store entries and the protected plaintext backup were kept; removing them is a separate, deliberate action.",
        ],
    };
}
