// Builds the `openclaw secrets apply` plan (version 1, protocolVersion 1). The plan holds references
// only, never a value. Both scrub passes are off: removing plaintext originals other than the
// rewritten config fields is a separate operator action (see the contract).
import { PreflightError } from "./errors.mjs";

const ALIAS = /^[a-z][a-z0-9_-]{0,63}$/;
const STORE_ID = /^[A-Za-z0-9._-]{1,128}$/;
const MAX_PLAN_BYTES = 1024 * 1024;

function compare(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

export function providerDefinition({ resolverCommand, storePath }) {
    return {
        source: "exec",
        command: resolverCommand,
        args: ["--store", storePath],
        passEnv: ["PATH"],
        jsonOnly: true,
    };
}

export function buildApplyPlan({ targets, providerAlias, resolverCommand, storePath }) {
    if (typeof providerAlias !== "string" || !ALIAS.test(providerAlias)) {
        throw new PreflightError("invalid-provider-alias", "the alias must match ^[a-z][a-z0-9_-]{0,63}$");
    }
    if (typeof resolverCommand !== "string" || !resolverCommand.startsWith("/")) {
        throw new PreflightError("invalid-plan", "the resolver command must be an absolute path");
    }
    if (typeof storePath !== "string" || !storePath.startsWith("/")) {
        throw new PreflightError("invalid-plan", "the store path must be an absolute path");
    }
    if (!Array.isArray(targets) || targets.length === 0) {
        throw new PreflightError("invalid-plan", "at least one target is required");
    }
    const seen = new Set();
    for (const target of targets) {
        if (seen.has(target.path)) {
            throw new PreflightError("invalid-plan", "duplicate target path");
        }
        seen.add(target.path);
        const ref = target.ref;
        if (ref?.source !== "exec" || ref.provider !== providerAlias || typeof ref.id !== "string" || !STORE_ID.test(ref.id)) {
            throw new PreflightError("invalid-plan", "a target reference is not a valid reference to the migration provider");
        }
    }
    const plan = {
        version: 1,
        protocolVersion: 1,
        scrubEnv: false,
        scrubAuthProfilesForProviderTargets: false,
        providerUpserts: { [providerAlias]: providerDefinition({ resolverCommand, storePath }) },
        targets: [...targets]
            .sort((a, b) => compare(a.path, b.path))
            .map((target) => ({
                type: target.registryId,
                path: target.path,
                pathSegments: [...target.segments],
                ref: { source: "exec", provider: target.ref.provider, id: target.ref.id },
            })),
    };
    if (Buffer.byteLength(JSON.stringify(plan)) > MAX_PLAN_BYTES) {
        throw new PreflightError("invalid-plan", "the plan is too large");
    }
    return plan;
}
