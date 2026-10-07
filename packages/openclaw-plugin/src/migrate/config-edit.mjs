// Own-property navigation of parsed config, shared by verification and rollback. Paths come from the
// reviewed registry and journal, never from the config itself, and prototype-polluting keys are
// refused earlier, but access still goes through own-property descriptors.
import { isDeepStrictEqual } from "node:util";

export function isMap(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function getAt(root, segments) {
    let node = root;
    for (const segment of segments) {
        if (!isMap(node) || !Object.hasOwn(node, segment)) {
            return undefined;
        }
        node = Object.getOwnPropertyDescriptor(node, segment).value;
    }
    return node;
}

export function hasAt(root, segments) {
    return getAt(root, segments) !== undefined;
}

export function setAt(root, segments, value) {
    let node = root;
    for (const segment of segments.slice(0, -1)) {
        if (!isMap(node) || !Object.hasOwn(node, segment)) {
            return false;
        }
        node = Object.getOwnPropertyDescriptor(node, segment).value;
    }
    if (!isMap(node)) {
        return false;
    }
    node[segments.at(-1)] = value;
    return true;
}

export function deleteAt(root, segments) {
    const parent = getAt(root, segments.slice(0, -1));
    if (isMap(parent) && Object.hasOwn(parent, segments.at(-1))) {
        delete parent[segments.at(-1)];
        return true;
    }
    return false;
}

export function isRef(value, ref) {
    return isMap(value)
        && Object.keys(value).length === 3
        && value.source === ref.source
        && value.provider === ref.provider
        && value.id === ref.id;
}

export function sameConfig(a, b) {
    return isDeepStrictEqual(a, b);
}

export function countRefsToProvider(node, alias) {
    if (Array.isArray(node)) {
        return node.reduce((sum, item) => sum + countRefsToProvider(item, alias), 0);
    }
    if (!isMap(node)) {
        return 0;
    }
    if (node.source === "exec" && node.provider === alias && typeof node.id === "string") {
        return 1;
    }
    return Object.values(node).reduce((sum, item) => sum + countRefsToProvider(item, alias), 0);
}

// Dotted paths where two configs differ, descending into objects and treating arrays as leaves.
// `ignore` lists path prefixes (as segment arrays) whose differences are expected. Returns paths
// only, never values.
export function changedPaths(before, after, ignore = [], prefix = []) {
    const ignored = (segments) => ignore.some((entry) => entry.length <= segments.length && entry.every((part, index) => segments[index] === part));
    const out = [];
    const keys = new Set([...(isMap(before) ? Object.keys(before) : []), ...(isMap(after) ? Object.keys(after) : [])]);
    for (const key of [...keys].sort()) {
        const segments = [...prefix, key];
        if (ignored(segments)) {
            continue;
        }
        const a = isMap(before) && Object.hasOwn(before, key) ? before[key] : undefined;
        const b = isMap(after) && Object.hasOwn(after, key) ? after[key] : undefined;
        if (isMap(a) && isMap(b)) {
            out.push(...changedPaths(a, b, ignore, segments));
        } else if (!isDeepStrictEqual(a, b)) {
            out.push(segments.join("."));
        }
    }
    return out;
}
