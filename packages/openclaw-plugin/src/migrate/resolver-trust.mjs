// OpenClaw runs an exec provider's `command` directly and refuses one that is a symlink, is group- or
// world-writable, or is not owned by the user running it. Checking the same properties here, before
// any change, turns a gateway that would fail to start into a refusal.
import path from "node:path";
import { PreflightError } from "./errors.mjs";
import { UnsafePathError, openTrustedRoot } from "./safe-fs.mjs";

export async function checkResolverCommand(command, { uid = process.geteuid() } = {}) {
    const refuse = (detail) => new PreflightError("resolver-untrusted", detail);
    if (typeof command !== "string" || !path.isAbsolute(command)) {
        throw refuse("the resolver command must be an absolute path");
    }
    if (path.posix.normalize(command) !== command || command.endsWith("/")) {
        throw refuse("the resolver command path must be canonical");
    }
    let dir;
    try {
        dir = await openTrustedRoot(path.dirname(command), { uid, rootUids: [0, uid] });
    } catch (error) {
        if (error instanceof UnsafePathError) {
            throw refuse(`its directory is not trustworthy (${error.reason})`);
        }
        throw error;
    }
    try {
        const info = await dir.statName(path.basename(command));
        if (info === null) {
            throw refuse("the resolver command does not exist");
        }
        if (info.isSymbolicLink()) {
            throw refuse("the resolver command is a symlink; OpenClaw refuses it, so give the real file path");
        }
        if (!info.isFile()) {
            throw refuse("the resolver command is not a regular file");
        }
        if (info.uid !== uid) {
            throw refuse("the resolver command must be owned by the user that runs OpenClaw");
        }
        if ((info.mode & 0o022) !== 0) {
            throw refuse("the resolver command is writable by group or others");
        }
        if ((info.mode & 0o100) === 0) {
            throw refuse("the resolver command is not executable");
        }
        return { path: command };
    } finally {
        await dir.close();
    }
}
