// SPDX-License-Identifier: AGPL-3.0-only
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Generate a disposable CA rather than committing a TLS private key or disabling verification.
// Defaults give a one-day leaf for localhost/127.0.0.1. Options produce the negative variants used by the
// pin tests: other SAN names/IPs (wrong host) and a leaf whose validity ended in the past (expired).
export async function createTestTls({ dnsNames = ['localhost'], ipAddresses = ['127.0.0.1'], expired = false } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'blindpass-p05-tls-'));
  const run = (args) => execFileSync('openssl', args, { cwd: directory, stdio: 'ignore' });
  const san = [...dnsNames.map((name) => `DNS:${name}`), ...ipAddresses.map((address) => `IP:${address}`)].join(',');
  if (!/^[A-Za-z0-9.:,-]+$/.test(san)) throw new Error('Disposable fixture TLS setup failed');
  try {
    run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=BlindPass disposable P05 test CA', '-keyout', 'ca.key', '-out', 'ca.pem',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    run(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
      '-keyout', 'server.key', '-out', 'server.csr',
      '-addext', `subjectAltName=${san}`,
      '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'basicConstraints=critical,CA:FALSE']);
    if (expired) {
      // `openssl ca` accepts explicit validity dates on every supported OpenSSL release.
      await writeFile(join(directory, 'ca.cnf'), ['[ca]', 'default_ca = CA_default', '[CA_default]', 'dir = .', 'database = index.txt',
        'new_certs_dir = .', 'serial = serial.txt', 'default_md = sha256', 'policy = policy_any', 'copy_extensions = copy',
        'unique_subject = no', '[policy_any]', 'commonName = supplied', ''].join('\n'));
      await writeFile(join(directory, 'index.txt'), ''); await writeFile(join(directory, 'serial.txt'), '01\n');
      run(['ca', '-batch', '-config', 'ca.cnf', '-cert', 'ca.pem', '-keyfile', 'ca.key', '-in', 'server.csr',
        '-out', 'server.pem', '-notext', '-startdate', '20200101000000Z', '-enddate', '20200102000000Z']);
    } else {
      run(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
        '-CAcreateserial', '-days', '1', '-copy_extensions', 'copy', '-out', 'server.pem']);
    }
    const [ca, cert, key] = await Promise.all(['ca.pem', 'server.pem', 'server.key']
      .map((name) => readFile(join(directory, name))));
    return { ca, cert, key, close: () => rm(directory, { recursive: true, force: true }) };
  } catch {
    await rm(directory, { recursive: true, force: true });
    throw new Error('Disposable fixture TLS setup failed');
  }
}
