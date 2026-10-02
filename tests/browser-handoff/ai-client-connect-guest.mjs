// SPDX-License-Identifier: AGPL-3.0-only
// Fixed Root SSH connector. No caller can choose an endpoint or read a private
// Source/session file; info contains only the approved report location.
import { connect } from 'node:net';
import { lstat, readFile } from 'node:fs/promises';
try {
  const [name, kind] = process.argv.slice(2);
  if (process.getuid() !== 0 || process.argv.length !== 4 || !['claude', 'codex'].includes(name) || !['info', 'model', 'result'].includes(kind)) throw new Error();
  const directory = '/run/p05-ai-client'; const parent = await lstat(directory);
  if (!parent.isDirectory() || parent.uid !== 0 || (parent.mode & 0o7777) !== 0o700) throw new Error();
  if (kind === 'info') {
    const path = `${directory}/${name}.info.json`; const stat = await lstat(path);
    if (!stat.isFile() || stat.uid !== 0 || (stat.mode & 0o7777) !== 0o600 || stat.size > 4096) throw new Error();
    const value = JSON.parse(await readFile(path, 'utf8'));
    if (Object.keys(value).sort().join(',') !== 'origin,ready,reportPath' || value.ready !== true
      || typeof value.origin !== 'string' || !/^https:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(value.origin) || value.reportPath !== '/d/p05-primary') throw new Error();
    process.stdout.write(JSON.stringify(value) + '\n');
  } else {
    const path = `${directory}/${name}.${kind}.sock`; const stat = await lstat(path);
    if (!stat.isSocket() || stat.uid !== 0 || (stat.mode & 0o7777) !== 0o600) throw new Error();
    const socket = connect({ path }); socket.setTimeout(240000, () => socket.destroy());
    socket.on('error', () => { process.exitCode = 70; process.stdin.unpipe(socket); process.stdin.pause(); });
    socket.on('connect', () => { process.stdin.pipe(socket); socket.pipe(process.stdout); });
    socket.on('close', () => { process.stdin.unpipe(socket); process.stdin.pause(); });
    process.stdout.on('error', () => socket.destroy());
  }
} catch { process.exitCode = 70; }
