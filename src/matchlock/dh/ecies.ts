import { x25519 } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import type { PublicKey, PrivateKey } from '../types.js';
import { isValidPublicKey, isValidPrivateKey } from '../types.js';
import { InvalidKeyError, DecryptionError } from '../errors.js';

const ENCRYPTION_DOMAIN = 'matchlock-encrypt-v1';
const encoder = new TextEncoder();

export interface EncryptedBox {
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

export function encryptForPublicKey(plaintext: string, recipientPublicKey: PublicKey): EncryptedBox {
  if (!isValidPublicKey(recipientPublicKey)) throw new InvalidKeyError('invalid recipient public key');
  const ephemeralPrivateKey = randomBytes(32);
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
  const sharedSecret = x25519.scalarMult(ephemeralPrivateKey, hexToBytes(recipientPublicKey));
  const nonce = randomBytes(24);
  const key = hkdf(sha256, sharedSecret, nonce, encoder.encode(ENCRYPTION_DOMAIN), 32);
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(encoder.encode(plaintext));
  return { ephemeralPublicKey: bytesToHex(ephemeralPublicKey), nonce: bytesToHex(nonce), ciphertext: bytesToHex(ciphertext) };
}

export function decryptWithPrivateKey(box: EncryptedBox, recipientPrivateKey: PrivateKey): string {
  if (!isValidPrivateKey(recipientPrivateKey)) throw new InvalidKeyError('invalid recipient private key');
  if (!isValidPublicKey(box.ephemeralPublicKey as PublicKey)) throw new InvalidKeyError('invalid ephemeral public key');
  const sharedSecret = x25519.scalarMult(hexToBytes(recipientPrivateKey), hexToBytes(box.ephemeralPublicKey));
  const nonce = hexToBytes(box.nonce);
  const key = hkdf(sha256, sharedSecret, nonce, encoder.encode(ENCRYPTION_DOMAIN), 32);
  try {
    return new TextDecoder().decode(xchacha20poly1305(key, nonce).decrypt(hexToBytes(box.ciphertext)));
  } catch {
    throw new DecryptionError('decryption failed: authentication tag mismatch');
  }
}

export function serializeEncryptedBox(box: EncryptedBox): string {
  return btoa(JSON.stringify(box));
}

export function deserializeEncryptedBox(serialized: string): EncryptedBox {
  let parsed: unknown;
  try {
    parsed = JSON.parse(atob(serialized));
  } catch {
    throw new Error('deserializeEncryptedBox: invalid base64 or JSON');
  }
  const obj = parsed as Record<string, unknown>;
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    typeof obj.ephemeralPublicKey !== 'string' ||
    typeof obj.nonce !== 'string' ||
    typeof obj.ciphertext !== 'string'
  ) {
    throw new Error('deserializeEncryptedBox: missing required fields');
  }
  return parsed as EncryptedBox;
}
