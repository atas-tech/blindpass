// Classifies one config value found at a SecretRef-capable path of the pinned OpenClaw release.
// The result never contains the value: callers keep the raw value in memory when they need it.

const SECRETREF_SOURCES = new Set(["env", "file", "exec", "store"]);
const ENV_SHORTHAND = /^(?:\$\{[A-Z][A-Z0-9_]*\}|\$[A-Z][A-Z0-9_]*)$/;

function isPlainObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function classifySecretInput(value) {
    if (typeof value === "string") {
        if (value.trim() === "") {
            return { kind: "empty" };
        }
        if (value === "__OPENCLAW_REDACTED__" || /^oc-sent-v\d+\./.test(value)) {
            return { kind: "reserved-marker" };
        }
        if (value.startsWith("secretref-env:")) {
            return { kind: "legacy-marker" };
        }
        if (ENV_SHORTHAND.test(value)) {
            return { kind: "env-shorthand" };
        }
        return { kind: "plaintext" };
    }

    if (isPlainObject(value)) {
        if (Object.hasOwn(value, "source")) {
            const wellFormed = SECRETREF_SOURCES.has(value.source)
                && typeof value.provider === "string" && value.provider !== ""
                && typeof value.id === "string" && value.id !== "";
            return wellFormed
                ? { kind: "secretref" }
                : { kind: "unsupported", reason: "malformed-secretref" };
        }
        return { kind: "unsupported", reason: "structured-value" };
    }

    if (Array.isArray(value)) {
        return { kind: "unsupported", reason: "structured-value" };
    }
    return { kind: "unsupported", reason: "non-string-value" };
}
