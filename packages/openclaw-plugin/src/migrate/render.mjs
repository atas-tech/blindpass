// Output rules (P09-D6): rows carry the fixed literal [REDACTED] and never a length, prefix,
// suffix or hash of a value. Text output replaces control characters so a hostile key name cannot
// inject terminal escapes.

export const REDACTED = "[REDACTED]";

export function printable(text) {
    return String(text).replace(/[\u0000-\u001f\u007f-\u009f]/g, "?");
}

export function renderPlanJson(plan) {
    return `${JSON.stringify(plan, null, 2)}\n`;
}

function refText(ref) {
    return ref ? `${ref.source}:${ref.provider}:${ref.id}` : "-";
}

export function renderPlanText(plan) {
    const lines = [];
    lines.push(`OpenClaw credential migration: ${plan.mode} (release ${plan.release})`);
    lines.push(`Config directory: ${printable(plan.configDir)}`);
    lines.push("");

    const header = ["FILE", "KEY PATH", "VALUE", "STATUS", "PROPOSED REFERENCE"];
    const body = plan.rows.map((row) => [
        printable(row.file),
        printable(row.keyPath),
        row.value,
        row.reason ? `${row.status} (${row.reason})` : row.status,
        refText(row.proposedRef),
    ]);
    if (body.length === 0) {
        lines.push("No credential fields were found.");
    } else {
        const widths = header.map((title, column) => Math.max(title.length, ...body.map((row) => row[column].length)));
        const format = (cells) => cells.map((cell, column) => cell.padEnd(widths[column])).join("  ").trimEnd();
        lines.push(format(header));
        for (const row of body) {
            lines.push(format(row));
        }
    }

    if (plan.residual.length > 0) {
        lines.push("");
        lines.push("Residual plaintext (this tool does not change these files):");
        for (const entry of plan.residual) {
            lines.push(`  ${printable(entry.file)}  ${entry.reason}`);
        }
    }
    if (plan.warnings.length > 0) {
        lines.push("");
        lines.push("Warnings:");
        for (const warning of plan.warnings) {
            lines.push(`  ${printable(warning)}`);
        }
    }

    const s = plan.summary;
    lines.push("");
    lines.push(
        `Summary: ${s.migratable} migratable, ${s.alreadyReference} already references, ${s.envReference} env references, `
        + `${s.empty} empty, ${s.unsupported} unsupported, ${s.residual} residual, ${s.envNonCredential} non-credential env entries.`,
    );
    if (plan.mode === "dry-run") {
        lines.push("This was a dry run: no file, key, store or runtime state was changed.");
    }
    return `${lines.join("\n")}\n`;
}

function list(lines, title, items, format) {
    if (items.length > 0) {
        lines.push("", title);
        for (const item of items) {
            lines.push(`  ${format(item)}`);
        }
    }
}

export function renderMigrationText(result) {
    if (result.status === "nothing-to-migrate") {
        const lines = ["Nothing to migrate: no supported plaintext credential remains in openclaw.json (or the installed OpenClaw accepts none of them)."];
        list(lines, "Not migrated:", result.unsupported, (entry) => `${printable(entry.path)} (${printable(entry.reason)})`);
        list(lines, "Warnings:", result.warnings, printable);
        return `${lines.join("\n")}\n`;
    }
    const lines = [`Migration ${result.migrationId} committed: ${result.migrated.length} credential(s) now reference the encrypted store.`];
    list(lines, "Migrated:", result.migrated, (entry) => `${printable(entry.path)}  ->  exec:${printable(entry.reference)}`);
    list(lines, "Not migrated (left exactly as they were):", result.unsupported, (entry) => `${printable(entry.path)} (${printable(entry.reason)})`);
    list(lines, "Residual plaintext (this tool does not change these files):", result.residual, printable);
    list(lines, "Warnings:", result.warnings, printable);
    list(lines, "Next steps:", result.nextSteps, (step) => `- ${printable(step)}`);
    return `${lines.join("\n")}\n`;
}

export function renderRollbackText(result) {
    if (result.status === "already-rolled-back") {
        return `Migration ${result.migrationId} was already rolled back.\n`;
    }
    const lines = [`Migration ${result.migrationId} rolled back (${result.method}).`];
    list(lines, "Restored:", result.restored, printable);
    list(lines, "Left as found (no longer this migration's reference):", result.left, printable);
    list(lines, "Next steps:", result.nextSteps, (step) => `- ${printable(step)}`);
    return `${lines.join("\n")}\n`;
}

export function renderStatusText(status) {
    if (status.status === "none") {
        return "No migration journal in this config directory.\n";
    }
    const lines = [`Migration ${status.migrationId}: ${status.status} (release ${status.release}, updated ${status.updatedAt})`];
    for (const [stage, info] of Object.entries(status.stages)) {
        lines.push(`  ${stage}: ${info.done ? "done" : "started"}`);
    }
    if (status.failure) {
        lines.push(`Failed at ${printable(status.failure.stage)}: ${printable(status.failure.reason)}`);
    }
    list(lines, "Migrated:", status.targets, (entry) => `${printable(entry.path)}  ->  ${printable(entry.reference)}`);
    list(lines, "Not migrated:", status.unsupported, (entry) => `${printable(entry.path)} (${printable(entry.reason)})`);
    list(lines, "Residual plaintext:", status.residual, printable);
    if (status.backupDir) {
        lines.push("", `Protected backup (holds the original plaintext): ${printable(status.backupDir)}`);
    }
    list(lines, "Warnings:", status.warnings, printable);
    return `${lines.join("\n")}\n`;
}
