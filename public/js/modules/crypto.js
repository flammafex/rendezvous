/**
 * Cryptographic functions for Rendezvous
 * Uses noble.js libraries for X25519 key exchange, Ed25519 signing, and hashing
 */

import { x25519, ed25519 } from 'https://esm.run/@noble/curves@1.7.0/ed25519';
import { sha256 } from 'https://esm.run/@noble/hashes@1.6.0/sha256';
import { bytesToHex, hexToBytes, randomBytes } from 'https://esm.run/@noble/hashes@1.6.0/utils';

// Domain separator for Ed25519 signatures (must match backend)
const SIGNING_DOMAIN = 'rendezvous-sign-v1';

/**
 * Generate a new X25519 keypair
 * @returns {{publicKey: string, privateKey: string}} Hex-encoded keypair
 */
export function generateKeypair() {
  const privateKey = randomBytes(32);
  return {
    publicKey: bytesToHex(x25519.getPublicKey(privateKey)),
    privateKey: bytesToHex(privateKey)
  };
}

/**
 * Derive a public key from a private key
 * @param {string} privateKey - Hex-encoded private key
 * @returns {string} Hex-encoded public key
 */
export function getPublicKey(privateKey) {
  return bytesToHex(x25519.getPublicKey(hexToBytes(privateKey)));
}

/**
 * Derive a match token from keypair and pool ID
 * This token is used to identify mutual matches without revealing preferences
 * @param {string} myPrivateKey - Hex-encoded private key
 * @param {string} theirPublicKey - Hex-encoded public key of the other participant
 * @param {string} poolId - Pool identifier
 * @returns {string} Hex-encoded match token
 */
export function deriveMatchToken(myPrivateKey, theirPublicKey, poolId) {
  const shared = x25519.scalarMult(hexToBytes(myPrivateKey), hexToBytes(theirPublicKey));
  const encoder = new TextEncoder();
  return bytesToHex(sha256(new Uint8Array([
    ...shared,
    ...encoder.encode(poolId),
    ...encoder.encode('rendezvous-match-v1')
  ])));
}

/**
 * Derive a nullifier from private key and pool ID
 * Used to prevent double-voting without revealing identity
 * @param {string} privateKey - Hex-encoded private key
 * @param {string} poolId - Pool identifier
 * @returns {string} Hex-encoded nullifier
 */
export function deriveNullifier(privateKey, poolId) {
  const encoder = new TextEncoder();
  return bytesToHex(sha256(new Uint8Array([
    ...hexToBytes(privateKey),
    ...encoder.encode(poolId),
    ...encoder.encode('rendezvous-nullifier-v1')
  ])));
}

/**
 * Encrypt reveal data using match token as key (AES-256-GCM)
 * @param {object} data - Data to encrypt
 * @param {string} matchToken - Hex-encoded match token used as encryption key
 * @returns {Promise<string>} Base64-encoded encrypted data
 */
export async function encryptRevealData(data, matchToken) {
  const tokenBytes = hexToBytes(matchToken);
  const key = await crypto.subtle.importKey(
    'raw',
    tokenBytes.slice(0, 32),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(JSON.stringify(data))
  );
  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...result));
}

/**
 * Decrypt reveal data using match token as key
 * @param {string} encryptedBase64 - Base64-encoded encrypted data
 * @param {string} matchToken - Hex-encoded match token used as decryption key
 * @returns {Promise<object|null>} Decrypted data or null if decryption fails
 */
export async function decryptRevealData(encryptedBase64, matchToken) {
  try {
    const tokenBytes = hexToBytes(matchToken);
    const data = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const key = await crypto.subtle.importKey(
      'raw',
      tokenBytes.slice(0, 32),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch (e) {
    return null;
  }
}

/**
 * Generate random decoy tokens for privacy
 * @param {number} count - Number of decoy tokens to generate
 * @returns {string[]} Array of hex-encoded random tokens
 */
export function generateDecoyTokens(count) {
  const tokens = [];
  for (let i = 0; i < count; i++) {
    const randomData = new Uint8Array(32);
    crypto.getRandomValues(randomData);
    tokens.push(Array.from(randomData).map(b => b.toString(16).padStart(2, '0')).join(''));
  }
  return tokens;
}

/**
 * Shuffle an array in place using Fisher-Yates algorithm
 * @param {Array} array - Array to shuffle
 * @returns {Array} The same array, shuffled
 */
export function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

// ============================================================================
// Ed25519 Signing Functions (for owner authentication)
// ============================================================================

/**
 * Generate a new Ed25519 signing keypair
 * @returns {{signingPublicKey: string, signingPrivateKey: string}} Hex-encoded keypair
 */
export function generateSigningKeypair() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    signingPublicKey: bytesToHex(publicKey),
    signingPrivateKey: bytesToHex(privateKey)
  };
}

/**
 * Sign a message with Ed25519
 * @param {string} message - Message to sign
 * @param {string} signingPrivateKey - Hex-encoded private key
 * @returns {string} Hex-encoded signature
 */
export function sign(message, signingPrivateKey) {
  const privateKeyBytes = hexToBytes(signingPrivateKey);
  const encoder = new TextEncoder();

  // Domain-separated hash of the message (must match backend)
  const messageHash = sha256(
    new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)])
  );

  const signature = ed25519.sign(messageHash, privateKeyBytes);
  return bytesToHex(signature);
}

/**
 * Create a signed request for authenticated API calls
 * @param {string} action - Action identifier (e.g., 'pool-close')
 * @param {string} poolId - Pool ID
 * @param {string} signingPrivateKey - Hex-encoded signing private key
 * @returns {{signature: string, timestamp: number}} Signature and timestamp for the request
 */
export function createSignedRequest(action, poolId, signingPrivateKey) {
  const timestamp = Date.now();
  const message = `${action}:${poolId}:${timestamp}`;
  const signature = sign(message, signingPrivateKey);
  return { signature, timestamp };
}
