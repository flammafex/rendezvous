/**
 * Rendezvous crypto compatibility facade.
 *
 * Matchlock now owns the extracted cryptographic primitives. Rendezvous keeps
 * this module path as the stable import surface for existing application code.
 */

export {
  generateKeypair,
  deriveMatchToken,
  deriveMatchTokens,
  commitToken,
  commitTokens,
  verifyCommitment,
  deriveNullifier,
  randomHex,
  hash,
  constantTimeEqual,
  isValidPublicKey,
  isValidPrivateKey,
  isValidMatchToken,
  isValidCommitHash,
  isValidNullifier,
  encryptForPublicKey,
  decryptWithPrivateKey,
  serializeEncryptedBox,
  deserializeEncryptedBox,
  generateSigningKeypair,
  sign,
  verify,
  createSignedRequest,
  verifySignedRequest,
  isValidSigningPublicKey,
  isValidSignature,
} from '../matchlock/index.js';

export type {
  EncryptedBox,
  SigningPublicKey,
  SigningPrivateKey,
  Signature,
} from '../matchlock/index.js';
