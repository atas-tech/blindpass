import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

const suite = new CipherSuite({
  kem: KemId.DhkemX25519HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Chacha20Poly1305
});

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Seal the UTF-8 bytes of `plaintext` for the request's public key. */
export async function sealBase64(publicKeyB64, plaintext) {
  const publicKey = await suite.kem.deserializePublicKey(base64ToBytes(publicKeyB64).buffer);
  const sealed = await suite.seal({ recipientPublicKey: publicKey }, new TextEncoder().encode(plaintext).buffer);
  return {
    enc: bytesToBase64(new Uint8Array(sealed.enc)),
    ciphertext: bytesToBase64(new Uint8Array(sealed.ct))
  };
}
