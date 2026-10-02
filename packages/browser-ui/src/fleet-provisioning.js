// SPDX-License-Identifier: MIT
// Fleet binding is independent of the legacy exchange path. Its caller must
// verify the enrolled broker's signed offer before displaying/sealing input.
import { AeadId, CipherSuite, KdfId, KemId } from 'hpke-js';

const suite = new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Chacha20Poly1305 });
const fields = ['version', 'purpose', 'offer_id', 'node_key_version', 'source_unit', 'credential', 'recipient_public', 'issued_at_ms', 'expires_at_ms', 'grant'];
const grantFields = ['id', 'operation_id', 'node_id', 'workload_id', 'invocation_id', 'unit', 'account', 'resource_id', 'recipient_key_id',
  'registration_version', 'policy_version', 'request_event_key', 'action', 'mode', 'audience', 'issuer_epoch', 'issued_at_ms', 'expires_at_ms', 'local_ceiling_seconds'];
const invalid = () => { throw new Error('invalid_provisioning_binding'); };
const plain = value => value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
  && Object.values(Object.getOwnPropertyDescriptors(value)).every(descriptor => Object.hasOwn(descriptor, 'value'));
const exact = (value, required, optional = []) => plain(value) && required.every(key => Object.hasOwn(value, key))
  && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const number = value => Number.isSafeInteger(value) && value > 0;
const unit = value => typeof value === 'string' && value.length <= 255 && /^[A-Za-z0-9_@:-][A-Za-z0-9_.@:-]*\.service$/.test(value);
const account = value => typeof value === 'string' && (/^[a-z0-9_.-]{1,32}$/.test(value)
  || /^uid:[1-9][0-9]{0,9}$/.test(value) && Number(value.slice(4)) <= 4_294_967_295);
const atom = value => typeof value === 'string' && /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/.test(value);
const sorted = value => plain(value) ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
function encode(bytes) {
  let text = ''; for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function publicBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) invalid();
  let bytes; try { bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='), c => c.charCodeAt(0)); }
  catch { invalid(); }
  if (bytes.length !== 32 || bytes.every(byte => byte === 0) || encode(bytes) !== value) invalid();
  return bytes;
}
function validate(binding) {
  if (!exact(binding, fields)) invalid();
  const g = binding.grant;
  if (binding.version !== 1 || binding.purpose !== 'browser_source' || !id(binding.offer_id) || binding.offer_id.length < 16
    || !number(binding.node_key_version) || !unit(binding.source_unit) || !atom(binding.credential)
    || !number(binding.issued_at_ms) || !number(binding.expires_at_ms)
    || !exact(g, grantFields, ['approval_reference'])) invalid();
  publicBytes(binding.recipient_public);
  for (const key of ['id', 'operation_id', 'node_id', 'workload_id', 'resource_id', 'recipient_key_id', 'request_event_key']) if (!id(g[key])) invalid();
  for (const key of ['registration_version', 'policy_version', 'issuer_epoch', 'issued_at_ms', 'expires_at_ms', 'local_ceiling_seconds']) if (!number(g[key])) invalid();
  if (typeof g.invocation_id !== 'string' || !/^[a-f0-9]{32}$/.test(g.invocation_id) || !unit(g.unit) || !account(g.account)
    || g.action !== 'browser.session' || g.mode !== 'browser_session' || g.audience !== 'blindpass-node'
    || g.recipient_key_id !== `${g.node_id}-${binding.node_key_version}`
    || g.local_ceiling_seconds > 3600 || g.expires_at_ms <= g.issued_at_ms || g.expires_at_ms - g.issued_at_ms > 120_000
    || g.request_event_key.length < 16 || g.approval_reference !== undefined && !id(g.approval_reference)
    || binding.issued_at_ms < g.issued_at_ms || binding.expires_at_ms > g.expires_at_ms
    || binding.expires_at_ms <= binding.issued_at_ms || binding.expires_at_ms - binding.issued_at_ms > 180_000) invalid();
  const json = JSON.stringify(sorted(binding));
  if (new TextEncoder().encode(json).length > 16_384) invalid();
  return json;
}
export function browserProvisioningAad(binding) {
  try { return new TextEncoder().encode(`blindpass:fleet-browser-source:v1\0${validate(binding)}`); }
  catch { invalid(); }
}
export async function sealBrowserSource(binding, plaintext, nowMs = Date.now()) {
  let snapshot; let aad;
  try {
    const json = validate(binding); snapshot = JSON.parse(json);
    aad = new TextEncoder().encode(`blindpass:fleet-browser-source:v1\0${json}`);
  } catch { invalid(); }
  if (!number(nowMs) || nowMs < snapshot.issued_at_ms || nowMs >= snapshot.expires_at_ms) invalid();
  if (typeof plaintext !== 'string') throw new Error('invalid_provisioning_source');
  const bytes = new TextEncoder().encode(plaintext);
  if (!bytes.length || bytes.length > 65_536) { bytes.fill(0); throw new Error('invalid_provisioning_source'); }
  try {
    const key = await suite.kem.deserializePublicKey(publicBytes(snapshot.recipient_public).buffer);
    const sealed = await suite.seal({ recipientPublicKey: key }, bytes.buffer, aad.buffer);
    return { enc: encode(new Uint8Array(sealed.enc)), ciphertext: encode(new Uint8Array(sealed.ct)) };
  } catch { throw new Error('provisioning_encryption_failed'); }
  finally { bytes.fill(0); }
}

function decodeSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value)) invalid();
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '=='), c => c.charCodeAt(0));
  if (bytes.length !== 64 || encode(bytes) !== value) invalid();
  return bytes;
}
const invalidOffer = () => { throw new Error('invalid_provisioning_offer'); };
// `expected` is independently trusted enrollment + authorized operation data.
// Never construct it from the offer. The current caller/session and receiver
// must separately enforce authorization, cancellation and one-use custody.
export async function verifyBrowserRecipientOffer(offer, expected, nowMs = Date.now()) {
  try {
    if (!exact(offer, ['v', 'kind', 'kid', 'epoch', 'body', 'sig'])
      || !exact(expected, ['grant', 'node_key_version', 'source_unit', 'credential', 'signing_public'])) invalidOffer();
    const bodyJson = validate(offer.body); const binding = JSON.parse(bodyJson);
    if (offer.v !== 1 || offer.kind !== 'recipient_offer' || offer.epoch !== binding.node_key_version
      || offer.epoch !== expected.node_key_version || offer.kid !== `${binding.grant.node_id}-${binding.node_key_version}`
      || offer.kid !== `${expected.grant.node_id}-${expected.node_key_version}`
      || bodyJson.length > 16_384 || JSON.stringify(sorted(expected.grant)) !== JSON.stringify(sorted(binding.grant))
      || expected.source_unit !== binding.source_unit || expected.credential !== binding.credential
      || !number(nowMs) || nowMs < binding.issued_at_ms || nowMs >= binding.expires_at_ms) invalidOffer();
    const keyBytes = publicBytes(expected.signing_public);
    const signature = decodeSignature(offer.sig);
    const unsigned = { body: binding, epoch: offer.epoch, kid: offer.kid, kind: offer.kind, v: offer.v };
    const message = new TextEncoder().encode(`blindpass:fleet-document:v1\0${JSON.stringify(sorted(unsigned))}`);
    const key = await globalThis.crypto.subtle.importKey('raw', keyBytes, { name: 'Ed25519' }, false, ['verify']);
    if (!await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, key, signature, message)) invalidOffer();
    Object.freeze(binding.grant); return Object.freeze(binding);
  } catch { invalidOffer(); }
}
export async function sealVerifiedBrowserSource(offer, expected, plaintext, nowMs = Date.now()) {
  const binding = await verifyBrowserRecipientOffer(offer, expected, nowMs);
  return sealBrowserSource(binding, plaintext, nowMs);
}
