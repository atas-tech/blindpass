// Reads a .env file the way OpenClaw does. OpenClaw loads these files with dotenv 17.4.2 (the
// version installed under the pinned release), so this mirrors dotenv's line grammar and value
// rules exactly instead of inventing a stricter dialect: the value we import or compare must be the
// value the runtime sees. Nothing is expanded or executed ($VAR and $(cmd) stay literal text).
//
// Diagnostics carry a line number and a reason only, never line content.

const LINE = /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/gm;

function lineNumberAt(text, index) {
    let line = 1;
    for (let i = 0; i < index; i += 1) {
        if (text.charCodeAt(i) === 10) {
            line += 1;
        }
    }
    return line;
}

export function parseDotenv(source) {
    const text = String(source ?? "").replace(/\r\n?/g, "\n");
    const entries = [];
    const problems = [];
    const covered = new Set();

    LINE.lastIndex = 0;
    let match;
    while ((match = LINE.exec(text)) !== null) {
        if (match[0] === "") {
            LINE.lastIndex += 1;
            continue;
        }
        const key = match[1];
        const rawValue = (match[2] ?? "").trim();
        const quoteChar = rawValue[0];
        const quoted = quoteChar === "'" || quoteChar === '"' || quoteChar === "`";
        const closed = quoted && rawValue.length >= 2 && rawValue.endsWith(quoteChar);

        let value = rawValue.replace(/^(['"`])([\s\S]*)\1$/gm, "$2");
        if (quoteChar === '"') {
            value = value.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
        }

        const firstNonSpace = match.index + match[0].search(/\S/);
        const startLine = lineNumberAt(text, firstNonSpace);
        const endLine = startLine + (rawValue.match(/\n/g)?.length ?? 0);
        for (let line = startLine; line <= endLine; line += 1) {
            covered.add(line);
        }

        if (quoted && !closed) {
            problems.push({ line: startLine, reason: "unbalanced-quote" });
        }
        entries.push({
            key,
            value,
            line: startLine,
            quote: !quoted ? "none" : quoteChar === "'" ? "single" : quoteChar === '"' ? "double" : "backtick",
            multiline: value.includes("\n") || endLine > startLine,
        });
    }

    text.split("\n").forEach((rawLine, index) => {
        const trimmed = rawLine.trim();
        if (trimmed !== "" && !trimmed.startsWith("#") && !covered.has(index + 1)) {
            problems.push({ line: index + 1, reason: "unparsed-line" });
        }
    });
    problems.sort((a, b) => a.line - b.line);

    const effective = new Map();
    const seen = new Set();
    const duplicates = [];
    for (const entry of entries) {
        if (seen.has(entry.key) && !duplicates.includes(entry.key)) {
            duplicates.push(entry.key);
        }
        seen.add(entry.key);
        effective.set(entry.key, entry.value);
    }

    return { entries, problems, duplicates, effective };
}
