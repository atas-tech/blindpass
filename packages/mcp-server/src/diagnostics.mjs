// SPDX-License-Identifier: MIT
import { closeSync, constants, fchmodSync, fstatSync, openSync, renameSync, statSync, writeSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

// Optional diagnostics sink. It writes one fixed-vocabulary metadata line per
// event to a file under the workload state directory (systemd STATE_DIRECTORY,
// or an explicit directory): never URLs, codes, cookies, endpoints, tool names,
// arguments or any upstream/exception text. Every field is looked up in a closed
// vocabulary below; anything else is recorded as "unknown". Stdout stays
// protocol-only and stderr stays empty whether or not the sink is enabled.
export const DIAGNOSTIC_FILE = 'mcp-diagnostics.log';
const DEFAULT_MAX_BYTES = 65_536;
const STAGES = new Set(['startup', 'transport', 'protocol', 'tool', 'delivery']);
const STATUSES = new Set(['error', 'denied', 'skipped', 'selected', 'completed', 'failed']);
const REASONS = new Set(['parse', 'invalid_message', 'message_too_large', 'repeat_initialize', 'unsupported_version', 'closed', 'io', 'internal',
  'failed', 'interrupted', 'signal', 'not_configured', 'unreviewed', 'protocol', 'capability', 'host', 'authentication', 'selected',
  'uncertain', 'definite_failure', 'delivered', 'declined', 'cancelled']);
const PROVIDERS = new Set(['url_elicitation', 'openclaw', 'telegram', 'local_open', 'operator_app']);
const COMPLETED = new Set(['delivered', 'declined', 'cancelled']);
const FAILED = new Set(['uncertain', 'definite_failure']);
const known = (set, value) => (typeof value === 'string' && set.has(value) ? value : 'unknown');

// Classification uses only the error's structure. The message, cause, data and
// every other property are never read into the output.
function classify(error) {
  try {
    if (error === null || typeof error !== 'object') return 'internal';
    if (Array.isArray(error.issues) || error.name === 'ZodError') return 'invalid_message';
    if (error instanceof SyntaxError) return 'parse';
    if (typeof error.message === 'string' && error.message.startsWith('ReadBuffer exceeded maximum size')) return 'message_too_large';
    if (error.name === 'UnsupportedProtocolVersionError') return 'unsupported_version';
    if (typeof error.code === 'string' && /^(?:EPIPE|ERR_STREAM_[A-Z_]+|ECONNRESET)$/.test(error.code)) return 'io';
  } catch { /* hostile getters fall through */ }
  return 'internal';
}

function directoryFrom(directory, env) {
  const configured = directory !== undefined ? directory : env?.STATE_DIRECTORY;
  if (typeof configured !== 'string') return undefined;
  // systemd joins several state directories with ':'; the first one is used.
  const first = directory !== undefined ? configured : configured.split(':')[0];
  if (!first || first.length > 1024 || first.includes('\0') || !isAbsolute(first)) return undefined;
  try { return statSync(first).isDirectory() ? first : undefined; } catch { return undefined; }
}

export function createDiagnostics({ directory, env = process.env, maxBytes = DEFAULT_MAX_BYTES, now = Date.now } = {}) {
  const base = directoryFrom(directory, env);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 256 || maxBytes > 1_048_576 || typeof now !== 'function') throw new Error('invalid_diagnostics_configuration');
  let enabled = base !== undefined; let fd; let size = 0;
  const path = base && join(base, DIAGNOSTIC_FILE);
  // O_NOFOLLOW refuses a planted symlink; the file must be a single-link regular
  // file owned by this process and is forced to 0600.
  const open = () => {
    fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
    const info = fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1 || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('diagnostics_file_refused');
    if ((info.mode & 0o777) !== 0o600) fchmodSync(fd, 0o600);
    size = info.size;
  };
  const disable = () => { enabled = false; try { if (fd !== undefined) closeSync(fd); } catch { /* best effort */ } fd = undefined; };
  const write = line => {
    if (!enabled) return;
    try {
      const bytes = Buffer.from(`${line}\n`, 'utf8');
      if (fd === undefined) open();
      if (size + bytes.length > maxBytes) {
        // Bounded storage: keep the previous window as ".1" and start over.
        closeSync(fd); fd = undefined;
        renameSync(path, `${path}.1`);
        open();
      }
      size += writeSync(fd, bytes);
    } catch { disable(); }
  };
  const record = (stage, status, reason, provider) => {
    if (!enabled) return;
    let when; try { when = new Date(now()).toISOString(); } catch { when = '1970-01-01T00:00:00.000Z'; }
    write(`${when} stage=${known(STAGES, stage)} status=${known(STATUSES, status)} reason=${known(REASONS, reason)}${provider === undefined ? '' : ` provider=${known(PROVIDERS, provider)}`}`);
  };
  const onerror = error => { if (enabled) record('transport', 'error', classify(error)); };
  const audit = item => {
    if (!enabled) return;
    let provider; let decision;
    try { provider = item?.provider; decision = item?.decision; } catch { /* unknown */ }
    const status = decision === 'selected' ? 'selected' : COMPLETED.has(decision) ? 'completed' : FAILED.has(decision) ? 'failed' : 'skipped';
    record('delivery', status, decision, provider === undefined ? 'unknown' : provider);
  };
  return Object.freeze({ get enabled() { return enabled; }, record, onerror, audit });
}
