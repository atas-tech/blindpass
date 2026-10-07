// SPDX-License-Identifier: AGPL-3.0-only
// P07-D2: SSH-signature scheme for SHA256SUMS. Every key here is generated in a
// temporary directory; no real release key exists in or is read by these tests.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SIGN = path.join(ROOT, 'scripts/release/sign.sh');
const VERIFY = path.join(ROOT, 'scripts/release/verify.sh');
const NAMESPACE = 'blindpass-release-v1';

function run(script, args, options = {}) {
  const result = spawnSync('bash', [script, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH, ...options.env }, cwd: options.cwd });
  return { status: result.status, out: `${result.stdout}${result.stderr}` };
}

function keygen(directory, name, type = 'ed25519') {
  const file = path.join(directory, name);
  const result = spawnSync('ssh-keygen', ['-q', '-t', type, '-N', '', '-C', 'throwaway-test-key', '-f', file], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const fingerprint = spawnSync('ssh-keygen', ['-lf', `${file}.pub`], { encoding: 'utf8' }).stdout.split(' ')[1];
  return { private: file, public: `${file}.pub`, fingerprint };
}

async function fixture() {
  const dir = await mkdtemp(path.join(tmpdir(), 'blindpass-release-sign-'));
  const key = keygen(dir, 'release');
  const sums = path.join(dir, 'SHA256SUMS');
  await writeFile(sums, `${'a'.repeat(64)}  blindpass-controller-0.1.0-linux-x86_64.tar.zst\n`);
  return { dir, key, sums, sig: `${sums}.sig`, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

async function signed() {
  const f = await fixture();
  const result = run(SIGN, ['--key', f.key.private, f.sums]);
  if (result.status !== 0) await f.cleanup(); // never leave the throwaway private key behind on a failed sign
  assert.equal(result.status, 0, result.out);
  return f;
}

test('P07-D2: a signature made by the release key verifies against its pinned fingerprint', async () => {
  const f = await signed();
  try {
    const result = run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, f.key.public]);
    assert.equal(result.status, 0, result.out);
    assert.match(result.out, /signature OK/);
    assert.match(result.out, new RegExp(NAMESPACE));
  } finally { await f.cleanup(); }
});

test('P07-D2: signing never prints the private key and refuses to replace an existing signature', async () => {
  const f = await signed();
  try {
    const privateText = await readFile(f.key.private, 'utf8');
    const again = run(SIGN, ['--key', f.key.private, f.sums]);
    assert.notEqual(again.status, 0);
    assert.match(again.out, /refusing to replace/);
    for (const text of [again.out, run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, f.key.public]).out]) {
      assert.ok(!text.includes(privateText.split('\n')[1]), 'private key body leaked');
    }
  } finally { await f.cleanup(); }
});

test('P07-D2: a tampered SHA256SUMS is rejected', async () => {
  const f = await signed();
  try {
    await writeFile(f.sums, `${'b'.repeat(64)}  blindpass-controller-0.1.0-linux-x86_64.tar.zst\n`);
    const result = run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, f.key.public]);
    assert.notEqual(result.status, 0);
    assert.match(result.out, /signature verification FAILED/);
  } finally { await f.cleanup(); }
});

test('P07-D2: a signature under another namespace is rejected even from the release key', async () => {
  const f = await fixture();
  try {
    for (const namespace of ['git', 'file', 'blindpass-release-v2']) {
      const sign = spawnSync('ssh-keygen', ['-Y', 'sign', '-q', '-f', f.key.private, '-n', namespace, f.sums], { encoding: 'utf8' });
      assert.equal(sign.status, 0, sign.stderr);
      const result = run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, f.key.public]);
      assert.notEqual(result.status, 0, `namespace ${namespace} accepted`);
      await rm(f.sig);
    }
  } finally { await f.cleanup(); }
});

test('P07-D2: the signer identity is bound by the verifier, not by the key file', async () => {
  const f = await signed();
  try {
    // The documented manual command pins identity and namespace in allowed_signers.
    const pub = (await readFile(f.key.public, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
    const allowed = path.join(f.dir, 'allowed_signers');
    await writeFile(allowed, `blindpass-release namespaces="${NAMESPACE}" ${pub}\n`);
    const manual = (identity) => spawnSync('ssh-keygen', ['-Y', 'verify', '-f', allowed, '-I', identity, '-n', NAMESPACE, '-s', f.sig],
      { input: spawnSync('cat', [f.sums]).stdout, encoding: 'utf8' });
    assert.equal(manual('blindpass-release').status, 0);
    assert.notEqual(manual('somebody-else').status, 0, 'a different identity must not verify');
    // verify.sh refuses a key file that tries to widen the allowed-signers entry.
    for (const [label, content] of [
      ['namespace override', `namespaces="*" ${pub}\n`],
      ['cert-authority option', `cert-authority ${pub}\n`],
      ['two keys', `${pub}\n${pub}\n`],
      ['empty file', ''],
      ['wrong type', `ssh-rsa AAAAB3NzaC1yc2E\n`],
    ]) {
      const bad = path.join(f.dir, `bad-${label.replace(/ /g, '-')}.pub`);
      await writeFile(bad, content);
      const result = run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, bad]);
      assert.notEqual(result.status, 0, label);
      assert.match(result.out, /release public key/, label);
    }
  } finally { await f.cleanup(); }
});

test('P07-D2: a signature by an unlisted key is rejected', async () => {
  const f = await fixture();
  try {
    const other = keygen(f.dir, 'attacker');
    const sign = run(SIGN, ['--key', other.private, f.sums]);
    assert.equal(sign.status, 0, sign.out);
    const result = run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, f.key.public]);
    assert.notEqual(result.status, 0);
    assert.match(result.out, /signature verification FAILED/);
  } finally { await f.cleanup(); }
});

test('P07-D2: the independently published fingerprint must match the key file', async () => {
  const f = await signed();
  try {
    const other = keygen(f.dir, 'swapped');
    // An attacker who replaces RELEASE_KEY.pub and re-signs passes ssh-keygen but not the pin.
    const resign = path.join(f.dir, 'SHA256SUMS.sig');
    await rm(resign);
    assert.equal(run(SIGN, ['--key', other.private, f.sums]).status, 0);
    const swapped = run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, other.public]);
    assert.notEqual(swapped.status, 0);
    assert.match(swapped.out, /fingerprint does not match/);
    const missing = run(VERIFY, [f.sums, f.sig, other.public]);
    assert.notEqual(missing.status, 0);
    assert.match(missing.out, /fingerprint is required/);
    const fromEnvironment = run(VERIFY, [f.sums, f.sig, other.public], { env: { BLINDPASS_RELEASE_KEY_FINGERPRINT: other.fingerprint } });
    assert.equal(fromEnvironment.status, 0, fromEnvironment.out);
    const malformed = run(VERIFY, ['--fingerprint', 'sha256:nope', f.sums, f.sig, other.public]);
    assert.notEqual(malformed.status, 0);
  } finally { await f.cleanup(); }
});

test('P07-D2: a revoked key is rejected, by option and by the file beside the key', async () => {
  const f = await signed();
  try {
    const revoked = path.join(f.dir, 'REVOKED_KEYS');
    await writeFile(revoked, await readFile(f.key.public, 'utf8'));
    const explicit = run(VERIFY, ['--fingerprint', f.key.fingerprint, '--revoked', revoked, f.sums, f.sig, f.key.public]);
    assert.notEqual(explicit.status, 0);
    assert.match(explicit.out, /signature verification FAILED/);
    // REVOKED_KEYS next to the public key is applied without being named.
    const implicit = run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, f.key.public]);
    assert.notEqual(implicit.status, 0);
    // An unrelated revocation list does not block the good key.
    const unrelated = keygen(f.dir, 'old');
    await writeFile(revoked, await readFile(unrelated.public, 'utf8'));
    assert.equal(run(VERIFY, ['--fingerprint', f.key.fingerprint, f.sums, f.sig, f.key.public]).status, 0);
    // An unreadable explicit revocation file is a failure, not a silent skip.
    const missing = run(VERIFY, ['--fingerprint', f.key.fingerprint, '--revoked', path.join(f.dir, 'absent'), f.sums, f.sig, f.key.public]);
    assert.notEqual(missing.status, 0);
  } finally { await f.cleanup(); }
});

test('P07-D2: missing, empty or unsafe inputs fail closed', async () => {
  const f = await signed();
  try {
    const pin = ['--fingerprint', f.key.fingerprint];
    assert.notEqual(run(VERIFY, [...pin, path.join(f.dir, 'absent'), f.sig, f.key.public]).status, 0);
    assert.notEqual(run(VERIFY, [...pin, f.sums, path.join(f.dir, 'absent.sig'), f.key.public]).status, 0);
    // The repository's real key file is not created by this phase; its absence must fail loudly.
    const absent = run(VERIFY, [...pin, f.sums, f.sig, path.join(f.dir, 'RELEASE_KEY.pub')]);
    assert.notEqual(absent.status, 0);
    assert.match(absent.out, /release public key/);
    assert.notEqual(run(VERIFY, [...pin, f.sums, f.sig]).status, 0);
    assert.notEqual(run(VERIFY, []).status, 0);
    const empty = path.join(f.dir, 'empty-sums');
    await writeFile(empty, '');
    assert.notEqual(run(SIGN, ['--key', f.key.private, empty]).status, 0);
    assert.notEqual(run(SIGN, ['--key', path.join(f.dir, 'absent-key'), f.sums]).status, 0);
    const linked = path.join(f.dir, 'linked-sums');
    await symlink(f.sums, linked);
    assert.notEqual(run(VERIFY, [...pin, linked, f.sig, f.key.public]).status, 0, 'symlinked SHA256SUMS accepted');
    await writeFile(f.sig, '');
    assert.notEqual(run(VERIFY, [...pin, f.sums, f.sig, f.key.public]).status, 0, 'empty signature accepted');
  } finally { await f.cleanup(); }
});

test('P07-D2: signing refuses a non-Ed25519 or group-readable key', async () => {
  const f = await fixture();
  try {
    const rsa = keygen(f.dir, 'rsa', 'rsa');
    const refused = run(SIGN, ['--key', rsa.private, f.sums]);
    assert.notEqual(refused.status, 0);
    assert.match(refused.out, /Ed25519/);
    await chmod(f.key.private, 0o640);
    const open = run(SIGN, ['--key', f.key.private, f.sums]);
    assert.notEqual(open.status, 0);
    assert.match(open.out, /permissions/);
  } finally { await f.cleanup(); }
});

test('P07-E01: --check-dir verifies listed assets and rejects tampering, omissions and extras', async () => {
  const f = await fixture();
  try {
    const assets = path.join(f.dir, 'assets');
    spawnSync('mkdir', [assets]);
    const asset = path.join(assets, 'blindpass-controller-0.1.0-linux-x86_64.tar.zst');
    await writeFile(asset, 'candidate bytes');
    const digest = spawnSync('sha256sum', [asset], { encoding: 'utf8' }).stdout.split(' ')[0];
    const sums = path.join(assets, 'SHA256SUMS');
    await writeFile(sums, `${digest}  blindpass-controller-0.1.0-linux-x86_64.tar.zst\n`);
    assert.equal(run(SIGN, ['--key', f.key.private, sums]).status, 0);
    const args = ['--fingerprint', f.key.fingerprint, '--check-dir', assets, sums, `${sums}.sig`, f.key.public];
    const good = run(VERIFY, args);
    assert.equal(good.status, 0, good.out);
    assert.match(good.out, /1 file\(s\) match/);

    await writeFile(path.join(assets, 'extra.txt'), 'unlisted');
    const extra = run(VERIFY, args);
    assert.notEqual(extra.status, 0);
    assert.match(extra.out, /not listed/);
    await rm(path.join(assets, 'extra.txt'));

    await writeFile(asset, 'tampered bytes');
    const tampered = run(VERIFY, args);
    assert.notEqual(tampered.status, 0);
    assert.match(tampered.out, /checksum check FAILED/);
    await rm(asset);
    const omitted = run(VERIFY, args);
    assert.notEqual(omitted.status, 0);

    // A signed inventory naming a path outside the directory is refused before any hashing.
    await writeFile(sums, `${digest}  ../escape\n`);
    await rm(`${sums}.sig`);
    assert.equal(run(SIGN, ['--key', f.key.private, sums]).status, 0);
    const escape = run(VERIFY, args);
    assert.notEqual(escape.status, 0);
    assert.match(escape.out, /unsafe/);
  } finally { await f.cleanup(); }
});

test('P07-D2: scripts have no debug tracing that could echo key material', async () => {
  for (const script of [SIGN, VERIFY]) {
    const text = await readFile(script, 'utf8');
    assert.ok(!/set -[a-z]*x/.test(text), `${path.basename(script)} enables xtrace`);
    assert.ok(!/echo .*\$\{?key/i.test(text), `${path.basename(script)} echoes a key variable`);
  }
});
