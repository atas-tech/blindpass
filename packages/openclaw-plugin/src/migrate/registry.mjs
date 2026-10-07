// Supported-target registry for the one OpenClaw release this migration has been reviewed against.
// The matrix is OpenClaw's own machine-readable credential surface for the release, vendored
// unmodified (see docs/product/openclaw-migration.md for provenance); wildcards stand for map keys.
import matrix20268035 from "./registry/openclaw-2026.8.35.credential-matrix.json" with { type: "json" };

export const PINNED_RELEASES = Object.freeze(["2026.8.35"]);

const MATRICES = { "2026.8.35": matrix20268035 };
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);

export function loadRegistry(release) {
    if (typeof release !== "string" || !Object.hasOwn(MATRICES, release)) {
        throw new Error(
            `Unsupported OpenClaw release '${release ?? ""}'. Reviewed releases: ${PINNED_RELEASES.join(", ")}.`,
        );
    }
    const matrix = MATRICES[release];
    const configTargets = [];
    const sqliteAuthProfileSurfaces = [];
    for (const entry of matrix.entries) {
        if (entry.configFile === "openclaw.json") {
            configTargets.push({
                id: entry.id,
                path: entry.path,
                segments: Object.freeze(entry.path.split(".")),
                shape: entry.secretShape,
            });
        } else if (entry.configFile === "auth-profile-store") {
            sqliteAuthProfileSurfaces.push({ id: entry.id, path: entry.path });
        }
    }
    return Object.freeze({
        release,
        configTargets: Object.freeze(configTargets),
        sqliteAuthProfileSurfaces: Object.freeze(sqliteAuthProfileSurfaces),
        excludedRuntimeManaged: Object.freeze([...matrix.excludedMutableOrRuntimeManaged]),
    });
}

function isMap(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function ownValue(node, key) {
    return Object.getOwnPropertyDescriptor(node, key)?.value;
}

function compareCodeUnits(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

export function enumerateConfigTargets(config, registry) {
    const targets = new Map();
    const problems = [];

    const walk = (node, pattern, index, trail, taint, entry) => {
        if (index === pattern.length) {
            return;
        }
        if (!isMap(node)) {
            return;
        }
        const segment = pattern[index];
        const last = index === pattern.length - 1;

        const visit = (key, childTaint) => {
            if (!Object.hasOwn(node, key)) {
                return;
            }
            const nextTrail = [...trail, key];
            if (last) {
                const path = nextTrail.join(".");
                if (childTaint) {
                    problems.push({ path, reason: childTaint });
                } else if (!targets.has(path)) {
                    targets.set(path, {
                        registryId: entry.id,
                        path,
                        segments: nextTrail,
                        value: ownValue(node, key),
                    });
                }
                return;
            }
            walk(ownValue(node, key), pattern, index + 1, nextTrail, childTaint, entry);
        };

        if (segment !== "*") {
            visit(segment, taint);
            return;
        }
        for (const key of Object.keys(node).sort(compareCodeUnits)) {
            let childTaint = taint;
            if (FORBIDDEN_SEGMENTS.has(key)) {
                childTaint = "forbidden-path-segment";
            } else if (key === "" || key.includes(".")) {
                childTaint = childTaint ?? "ambiguous-path-segment";
            }
            visit(key, childTaint);
        }
    };

    for (const entry of registry.configTargets) {
        walk(config, entry.segments, 0, [], null, entry);
    }

    return {
        targets: [...targets.values()].sort((a, b) => compareCodeUnits(a.path, b.path)),
        problems: problems.sort((a, b) => compareCodeUnits(a.path, b.path)),
    };
}
