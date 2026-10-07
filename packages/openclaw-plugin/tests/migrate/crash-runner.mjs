// Child process for the P09-I02 interruption tests: runs one migration action and SIGKILLs itself at
// the named hook point, so a stage is interrupted exactly the way a power loss or OOM kill would.
import { rollbackMigration, runMigration } from "../../src/migrate/migrate.mjs";

const spec = JSON.parse(process.argv[2]);
const hooks = {
    async at(point) {
        if (point === spec.crashAt) {
            process.kill(process.pid, "SIGKILL");
            await new Promise(() => { });
        }
    },
};

try {
    const result = spec.action === "rollback"
        ? await rollbackMigration({ ...spec.options, hooks })
        : await runMigration({ ...spec.options, hooks });
    process.stdout.write(`${JSON.stringify({ status: result.status })}\n`);
} catch (error) {
    process.stderr.write(`${error?.reason ?? error?.name ?? "failed"}\n`);
    process.exitCode = 1;
}
