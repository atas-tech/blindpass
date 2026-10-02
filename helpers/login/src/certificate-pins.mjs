// SPDX-License-Identifier: AGPL-3.0-only
import { createHash, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';

// Chromium's --ignore-certificate-errors-spki-list ADDS trust: a certificate whose
// SPKI hash is listed is accepted even when it fails hostname, validity or chain
// checks. It does not restrict a connection to the pin. The helper therefore
// verifies the certificate Chromium actually used, before any credential is
// typed: the served leaf's SPKI must equal a configured pin AND the leaf must
// match the origin's hostname/IP and be inside its validity period. This is the
// same rule session-revoker.mjs applies to its own TLS connection. The chain is
// not validated against a CA: for a pinned service the pin is the trust anchor.
const rejected = () => new Error('certificate_rejected');

export function certificateSpkiPin(certificate) {
  return createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
}

// chain: base64 DER certificates as returned by CDP Network.getCertificate,
// leaf first. Only the leaf is evaluated.
export function verifyPinnedLeaf({ chain, origin, pins, now = Date.now() }) {
  try {
    if (!Array.isArray(pins) || !pins.length || !Array.isArray(chain) || !chain.length || chain.length > 10
      || typeof chain[0] !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(chain[0]) || !Number.isFinite(now)) throw rejected();
    const leaf = new X509Certificate(Buffer.from(chain[0], 'base64'));
    const url = new URL(origin);
    if (url.protocol !== 'https:') throw rejected();
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (isIP(host) ? leaf.checkIP(host) === undefined : leaf.checkHost(host, { wildcards: true, partialWildcards: false }) === undefined) throw rejected();
    const from = Date.parse(leaf.validFrom); const to = Date.parse(leaf.validTo);
    if (!Number.isFinite(from) || !Number.isFinite(to) || now < from || now >= to) throw rejected();
    if (!pins.includes(certificateSpkiPin(leaf))) throw rejected();
  } catch { throw rejected(); }
}
