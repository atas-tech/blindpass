// SPDX-License-Identifier: AGPL-3.0-only
// Disposable guest assertions only. Paths come from the observed manager, never
// a model request. Preserve the existing five-second BOOTTIME cleanup bound.
import { readFile, lstat } from 'node:fs/promises';

export async function waitRuntimeRemoval({ cgroup, profile, now, startedAt, read = readFile, inspect = lstat,
  delay = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  const before = startedAt ?? await now();
  while (true) {
    let empty = false;
    try { empty = (await read(cgroup, 'utf8')).trim() === ''; }
    catch (error) { if (error.code === 'ENOENT') empty = true; else throw new Error('cleanup_cgroup'); }
    let removed = false;
    try { await inspect(profile); }
    catch (error) { if (error.code === 'ENOENT') removed = true; else throw new Error('cleanup_profile'); }
    const elapsed = await now() - before;
    if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed >= 5000) throw new Error('cleanup_deadline');
    if (empty && removed) return elapsed;
    await delay(25);
  }
}
