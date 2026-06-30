import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

const SIGNING_DOMAIN = 'matchlock-sign-v1';
const encoder = new TextEncoder();

export type SigningPublicKey = string & { readonly __brand: 'SigningPublicKey' };
export type SigningPrivateKey = string & { readonly __brand: 'SigningPrivateKey' };
export type Signature = string & { readonly __brand: 'Signature' };

const HEX_64 = /^[0-9a-fA-F]{64}$/;
const HEX_128 = /^[0-9a-fA-F]{128}$/;

export function isValidSigningPublicKey(key: string): key is SigningPublicKey {
  return HEX_64.test(key);
}

export function isValidSignature(sig: string): sig is Signature {
  return HEX_128.test(sig);
}

export function generateSigningKeypair(): { signingPublicKey: SigningPublicKey; signingPrivateKey: SigningPrivateKey } {
  const privateKey = ed25519.utils.randomPrivateKey();
  return {
    signingPublicKey: bytesToHex(ed25519.getPublicKey(privateKey)) as SigningPublicKey,
    signingPrivateKey: bytesToHex(privateKey) as SigningPrivateKey,
  };
}

export function sign(message: string, signingPrivateKey: SigningPrivateKey): Signature {
  const messageHash = sha256(concatBytes(encoder.encode(SIGNING_DOMAIN), encoder.encode(message)));
  return bytesToHex(ed25519.sign(messageHash, hexToBytes(signingPrivateKey))) as Signature;
}

export function verify(message: string, signature: Signature, signingPublicKey: SigningPublicKey): boolean {
  try {
    const messageHash = sha256(concatBytes(encoder.encode(SIGNING_DOMAIN), encoder.encode(message)));
    return ed25519.verify(hexToBytes(signature), messageHash, hexToBytes(signingPublicKey));
  } catch { return false; }
}

export function createSignedRequest(action: string, poolId: string, signingPrivateKey: SigningPrivateKey): { signature: Signature; timestamp: number } {
  const timestamp = Date.now();
  return { signature: sign(`${action}:${poolId}:${timestamp}`, signingPrivateKey), timestamp };
}

export function verifySignedRequest(action: string, poolId: string, signature: Signature, timestamp: number, signingPublicKey: SigningPublicKey, maxAgeMs = 5 * 60 * 1000): boolean {
  if (Math.abs(Date.now() - timestamp) > maxAgeMs) return false;
  return verify(`${action}:${poolId}:${timestamp}`, signature, signingPublicKey);
}
