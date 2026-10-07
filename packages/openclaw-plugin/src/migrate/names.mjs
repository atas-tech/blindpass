import { createHash } from "node:crypto";

const NAME_PREFIX = "openclaw.";
const MAX_NAME_LENGTH = 128; // the resolver accepts [A-Za-z0-9._-]{1,128}

// Deterministic, collision-free store name for a config path. Paths that need sanitising or
// truncation get a hash suffix of the original path, so two different paths never share a name.
export function storeNameFor(configPath) {
    const base = `${NAME_PREFIX}${configPath}`;
    const sanitized = base.replace(/[^A-Za-z0-9._-]/g, "_");
    if (sanitized === base && base.length <= MAX_NAME_LENGTH) {
        return base;
    }
    const suffix = createHash("sha256").update(configPath).digest("hex").slice(0, 8);
    return `${sanitized.slice(0, MAX_NAME_LENGTH - suffix.length - 1)}-${suffix}`;
}
