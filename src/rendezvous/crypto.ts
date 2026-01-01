/**
 * Rendezvous - Private Mutual Matching
 * Cryptographic primitives for match token derivation
 *
 * Core insight: Diffie-Hellman produces the same shared secret from either side.
 *
 * Alice wants Bob:
 *   shared = DH(alice_private, bob_public)
 *   token = H(shared || pool_id || "rendezvous-match-v1")
 *
 * Bob wants Alice:
 *   shared = DH(bob_private, alice_public)  // Same shared secret!
 *   token = H(shared || pool_id || "rendezvous-match-v1")  // Same token!
 */

import { x25519, ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { MatchToken, CommitHash, PublicKey, PrivateKey } from './types.js';

// Domain separation constants
const MATCH_DOMAIN = 'rendezvous-match-v1';
const NULLIFIER_DOMAIN = 'rendezvous-nullifier-v1';
const ENCRYPTION_DOMAIN = 'rendezvous-encrypt-v1';
const SIGNING_DOMAIN = 'rendezvous-sign-v1';

/**
 * Generate a new X25519 keypair for matching.
 * These keys are separate from Ed25519 signing keys.
 */
export function generateKeypair(): { publicKey: PublicKey; privateKey: PrivateKey } {
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);

  return {
    publicKey: bytesToHex(publicKey),
    privateKey: bytesToHex(privateKey),
  };
}

/**
 * Derive match token for a (me, them, pool) tuple.
 *
 * The key property: both parties derive the same token when they
 * select each other, enabling mutual match detection without
 * revealing unilateral preferences.
 *
 * @param myPrivateKey - My X25519 private key (hex)
 * @param theirPublicKey - Their X25519 public key (hex)
 * @param poolId - The pool identifier
 * @returns Match token (hex-encoded SHA-256 hash)
 */
export function deriveMatchToken(
  myPrivateKey: PrivateKey,
  theirPublicKey: PublicKey,
  poolId: string,
): MatchToken {
  const privateKeyBytes = hexToBytes(myPrivateKey);
  const publicKeyBytes = hexToBytes(theirPublicKey);

  // X25519 Diffie-Hellman - both parties derive same shared secret
  const shared = x25519.scalarMult(privateKeyBytes, publicKeyBytes);

  // Domain-separated hash: H(shared || pool_id || domain)
  const encoder = new TextEncoder();
  const input = new Uint8Array([
    ...shared,
    ...encoder.encode(poolId),
    ...encoder.encode(MATCH_DOMAIN),
  ]);

  return bytesToHex(sha256(input));
}

/**
 * Derive multiple match tokens for selecting multiple parties.
 *
 * @param myPrivateKey - My X25519 private key (hex)
 * @param theirPublicKeys - Array of their X25519 public keys (hex)
 * @param poolId - The pool identifier
 * @returns Array of match tokens
 */
export function deriveMatchTokens(
  myPrivateKey: PrivateKey,
  theirPublicKeys: PublicKey[],
  poolId: string,
): MatchToken[] {
  return theirPublicKeys.map((pubKey) => deriveMatchToken(myPrivateKey, pubKey, poolId));
}

/**
 * Create a commitment for the commit-reveal scheme.
 * This prevents timing attacks by hiding the actual token
 * until the reveal phase.
 *
 * @param matchToken - The match token to commit to
 * @returns Commitment hash (hex-encoded SHA-256)
 */
export function commitToken(matchToken: MatchToken): CommitHash {
  const encoder = new TextEncoder();
  return bytesToHex(sha256(encoder.encode(matchToken)));
}

/**
 * Create commitments for multiple match tokens.
 *
 * @param matchTokens - Array of match tokens
 * @returns Array of commitment hashes
 */
export function commitTokens(matchTokens: MatchToken[]): CommitHash[] {
  return matchTokens.map(commitToken);
}

/**
 * Verify that a revealed token matches its commitment.
 *
 * @param matchToken - The revealed match token
 * @param commitHash - The previously submitted commitment
 * @returns True if the token matches the commitment
 */
export function verifyCommitment(matchToken: MatchToken, commitHash: CommitHash): boolean {
  const computedHash = commitToken(matchToken);
  return constantTimeEqual(computedHash, commitHash);
}

/**
 * Derive a nullifier for a participant in a specific pool.
 * The nullifier prevents submitting multiple preference sets
 * while remaining unlinkable across pools.
 *
 * @param privateKey - Participant's private key (hex)
 * @param poolId - The pool identifier
 * @returns Nullifier (hex-encoded SHA-256)
 */
export function deriveNullifier(privateKey: PrivateKey, poolId: string): string {
  const encoder = new TextEncoder();
  const input = new Uint8Array([
    ...hexToBytes(privateKey),
    ...encoder.encode(poolId),
    ...encoder.encode(NULLIFIER_DOMAIN),
  ]);

  return bytesToHex(sha256(input));
}

/**
 * Generate random hex string of specified byte length.
 *
 * @param bytes - Number of random bytes
 * @returns Hex-encoded random string
 */
export function randomHex(bytes: number): string {
  return bytesToHex(randomBytes(bytes));
}

/**
 * Hash arbitrary data using SHA-256.
 *
 * @param data - Data to hash (string or Uint8Array)
 * @returns Hex-encoded SHA-256 hash
 */
export function hash(data: string | Uint8Array): string {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha256(input));
}

/**
 * Constant-time string comparison to prevent timing attacks.
 *
 * @param a - First string
 * @param b - Second string
 * @returns True if strings are equal
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Validate that a string is a valid hex-encoded X25519 public key.
 *
 * @param key - The key to validate
 * @returns True if valid
 */
export function isValidPublicKey(key: string): boolean {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(key)) {
      return false;
    }
    // X25519 public keys are always 32 bytes
    const bytes = hexToBytes(key);
    return bytes.length === 32;
  } catch {
    return false;
  }
}

/**
 * Validate that a string is a valid hex-encoded X25519 private key.
 *
 * @param key - The key to validate
 * @returns True if valid
 */
export function isValidPrivateKey(key: string): boolean {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(key)) {
      return false;
    }
    const bytes = hexToBytes(key);
    if (bytes.length !== 32) {
      return false;
    }
    // Try to derive public key to validate
    x25519.getPublicKey(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate that a string is a valid match token (SHA-256 hash).
 *
 * @param token - The token to validate
 * @returns True if valid format
 */
export function isValidMatchToken(token: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(token);
}

/**
 * Encrypted box structure for ECIES encryption.
 * Contains ephemeral public key, nonce, and ciphertext.
 */
export interface EncryptedBox {
  /** Ephemeral public key used for key agreement (hex) */
  ephemeralPublicKey: string;
  /** Random nonce for encryption (hex) */
  nonce: string;
  /** Encrypted ciphertext with auth tag (hex) */
  ciphertext: string;
}

/**
 * Encrypt data for a recipient using ECIES (Elliptic Curve Integrated Encryption Scheme).
 * Uses X25519 for key agreement, HKDF for key derivation, and XOR with hash stream
 * (simplified authenticated encryption for portability).
 *
 * @param plaintext - Data to encrypt (string)
 * @param recipientPublicKey - Recipient's X25519 public key (hex)
 * @returns Encrypted box containing ephemeral key, nonce, and ciphertext
 */
export function encryptForPublicKey(plaintext: string, recipientPublicKey: PublicKey): EncryptedBox {
  // Generate ephemeral keypair
  const ephemeralPrivateKey = randomBytes(32);
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

  // Derive shared secret via X25519
  const recipientPubBytes = hexToBytes(recipientPublicKey);
  const sharedSecret = x25519.scalarMult(ephemeralPrivateKey, recipientPubBytes);

  // Generate random nonce
  const nonce = randomBytes(24);

  // Derive encryption key using HKDF
  const encoder = new TextEncoder();
  const info = encoder.encode(ENCRYPTION_DOMAIN);
  const encryptionKey = hkdf(sha256, sharedSecret, nonce, info, 32);

  // Encrypt plaintext using XChaCha20-style stream (simplified: hash-based stream cipher)
  const plaintextBytes = encoder.encode(plaintext);
  const ciphertext = new Uint8Array(plaintextBytes.length + 32); // +32 for auth tag

  // Generate keystream and XOR
  for (let i = 0; i < plaintextBytes.length; i += 32) {
    const blockIndex = Math.floor(i / 32);
    const blockKey = sha256(new Uint8Array([...encryptionKey, ...new Uint8Array([blockIndex >> 24, blockIndex >> 16, blockIndex >> 8, blockIndex])]));
    for (let j = 0; j < 32 && i + j < plaintextBytes.length; j++) {
      ciphertext[i + j] = plaintextBytes[i + j] ^ blockKey[j];
    }
  }

  // Compute authentication tag: H(key || nonce || ciphertext)
  const authInput = new Uint8Array([...encryptionKey, ...nonce, ...ciphertext.slice(0, plaintextBytes.length)]);
  const authTag = sha256(authInput);
  ciphertext.set(authTag, plaintextBytes.length);

  return {
    ephemeralPublicKey: bytesToHex(ephemeralPublicKey),
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
  };
}

/**
 * Decrypt data encrypted with encryptForPublicKey.
 *
 * @param box - Encrypted box from encryptForPublicKey
 * @param recipientPrivateKey - Recipient's X25519 private key (hex)
 * @returns Decrypted plaintext string
 * @throws Error if authentication fails
 */
export function decryptWithPrivateKey(box: EncryptedBox, recipientPrivateKey: PrivateKey): string {
  const ephemeralPubBytes = hexToBytes(box.ephemeralPublicKey);
  const privateKeyBytes = hexToBytes(recipientPrivateKey);
  const nonce = hexToBytes(box.nonce);
  const ciphertext = hexToBytes(box.ciphertext);

  // Derive shared secret via X25519
  const sharedSecret = x25519.scalarMult(privateKeyBytes, ephemeralPubBytes);

  // Derive encryption key using HKDF
  const encoder = new TextEncoder();
  const info = encoder.encode(ENCRYPTION_DOMAIN);
  const encryptionKey = hkdf(sha256, sharedSecret, nonce, info, 32);

  // Extract auth tag (last 32 bytes)
  const authTag = ciphertext.slice(ciphertext.length - 32);
  const encryptedData = ciphertext.slice(0, ciphertext.length - 32);

  // Verify authentication tag
  const authInput = new Uint8Array([...encryptionKey, ...nonce, ...encryptedData]);
  const expectedTag = sha256(authInput);
  if (!constantTimeEqual(bytesToHex(authTag), bytesToHex(expectedTag))) {
    throw new Error('Decryption failed: authentication tag mismatch');
  }

  // Decrypt using XOR with keystream
  const plaintext = new Uint8Array(encryptedData.length);
  for (let i = 0; i < encryptedData.length; i += 32) {
    const blockIndex = Math.floor(i / 32);
    const blockKey = sha256(new Uint8Array([...encryptionKey, ...new Uint8Array([blockIndex >> 24, blockIndex >> 16, blockIndex >> 8, blockIndex])]));
    for (let j = 0; j < 32 && i + j < encryptedData.length; j++) {
      plaintext[i + j] = encryptedData[i + j] ^ blockKey[j];
    }
  }

  return new TextDecoder().decode(plaintext);
}

/**
 * Serialize an EncryptedBox to a base64 string for transport.
 */
export function serializeEncryptedBox(box: EncryptedBox): string {
  return Buffer.from(JSON.stringify(box)).toString('base64');
}

/**
 * Deserialize a base64 string back to an EncryptedBox.
 */
export function deserializeEncryptedBox(serialized: string): EncryptedBox {
  return JSON.parse(Buffer.from(serialized, 'base64').toString('utf-8'));
}

// ============================================================================
// Ed25519 Signing (for owner authentication)
// ============================================================================

/** Hex-encoded Ed25519 public key (64 chars) */
export type SigningPublicKey = string;

/** Hex-encoded Ed25519 private key (64 chars) */
export type SigningPrivateKey = string;

/** Hex-encoded Ed25519 signature (128 chars) */
export type Signature = string;

/**
 * Generate a new Ed25519 keypair for signing.
 * These are separate from X25519 matching keys.
 *
 * @returns Ed25519 keypair (hex-encoded)
 */
export function generateSigningKeypair(): {
  signingPublicKey: SigningPublicKey;
  signingPrivateKey: SigningPrivateKey;
} {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);

  return {
    signingPublicKey: bytesToHex(publicKey),
    signingPrivateKey: bytesToHex(privateKey),
  };
}

/**
 * Sign a message with an Ed25519 private key.
 * The message is prefixed with a domain separator to prevent cross-protocol attacks.
 *
 * @param message - Message to sign (will be hashed with domain separator)
 * @param signingPrivateKey - Ed25519 private key (hex)
 * @returns Signature (hex)
 */
export function sign(message: string, signingPrivateKey: SigningPrivateKey): Signature {
  const privateKeyBytes = hexToBytes(signingPrivateKey);
  const encoder = new TextEncoder();

  // Domain-separated hash of the message
  const messageHash = sha256(
    new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)])
  );

  const signature = ed25519.sign(messageHash, privateKeyBytes);
  return bytesToHex(signature);
}

/**
 * Verify an Ed25519 signature.
 *
 * @param message - Original message that was signed
 * @param signature - Signature to verify (hex)
 * @param signingPublicKey - Ed25519 public key (hex)
 * @returns True if signature is valid
 */
export function verify(
  message: string,
  signature: Signature,
  signingPublicKey: SigningPublicKey
): boolean {
  try {
    const publicKeyBytes = hexToBytes(signingPublicKey);
    const signatureBytes = hexToBytes(signature);
    const encoder = new TextEncoder();

    // Domain-separated hash of the message (must match sign())
    const messageHash = sha256(
      new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)])
    );

    return ed25519.verify(signatureBytes, messageHash, publicKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Create a signed request payload for owner authentication.
 * Includes timestamp to prevent replay attacks.
 *
 * @param action - Action being performed (e.g., "psi-setup", "psi-pending")
 * @param poolId - Pool ID
 * @param signingPrivateKey - Owner's Ed25519 private key
 * @returns Object with signature and timestamp
 */
export function createSignedRequest(
  action: string,
  poolId: string,
  signingPrivateKey: SigningPrivateKey
): { signature: Signature; timestamp: number } {
  const timestamp = Date.now();
  const message = `${action}:${poolId}:${timestamp}`;
  const signature = sign(message, signingPrivateKey);
  return { signature, timestamp };
}

/**
 * Verify a signed request from pool owner.
 * Checks signature validity and timestamp freshness.
 *
 * @param action - Expected action
 * @param poolId - Expected pool ID
 * @param signature - Signature from request
 * @param timestamp - Timestamp from request
 * @param signingPublicKey - Owner's Ed25519 public key
 * @param maxAgeMs - Maximum age of request in milliseconds (default: 5 minutes)
 * @returns True if signature is valid and timestamp is fresh
 */
export function verifySignedRequest(
  action: string,
  poolId: string,
  signature: Signature,
  timestamp: number,
  signingPublicKey: SigningPublicKey,
  maxAgeMs: number = 5 * 60 * 1000
): boolean {
  // Check timestamp freshness
  const now = Date.now();
  if (Math.abs(now - timestamp) > maxAgeMs) {
    return false;
  }

  // Verify signature
  const message = `${action}:${poolId}:${timestamp}`;
  return verify(message, signature, signingPublicKey);
}

/**
 * Validate that a string is a valid Ed25519 public key.
 *
 * @param key - The key to validate
 * @returns True if valid
 */
export function isValidSigningPublicKey(key: string): boolean {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(key)) {
      return false;
    }
    // Ed25519 public keys are 32 bytes
    const bytes = hexToBytes(key);
    return bytes.length === 32;
  } catch {
    return false;
  }
}
