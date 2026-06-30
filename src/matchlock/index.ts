// Errors
export { MatchlockError, InvalidKeyError, InvalidTokenError, DecryptionError } from './errors.js';

// DH primitives
export { generateKeypair, deriveMatchToken, deriveMatchTokens } from './dh/index.js';
export { commitToken, commitTokens, verifyCommitment } from './dh/commit.js';
export { deriveNullifier } from './dh/nullifier.js';
export {
  encryptForPublicKey,
  decryptWithPrivateKey,
  serializeEncryptedBox,
  deserializeEncryptedBox,
} from './dh/ecies.js';
export type { EncryptedBox } from './dh/ecies.js';
export {
  generateSigningKeypair,
  sign,
  verify,
  createSignedRequest,
  verifySignedRequest,
} from './dh/signing.js';
export type { SigningPublicKey, SigningPrivateKey, Signature } from './dh/signing.js';
export { isValidSigningPublicKey, isValidSignature } from './dh/signing.js';

// Primitive types
export type { MatchToken, CommitHash, PublicKey, PrivateKey, Nullifier } from './types.js';
export { isValidPublicKey, isValidPrivateKey, isValidMatchToken, isValidCommitHash, isValidNullifier } from './types.js';

// Utilities
export { randomHex, hash, constantTimeEqual } from './dh/utils.js';

// PSI
export { PsiService } from './psi/index.js';
export type {
  PsiClientRequest,
  PsiJoinResponse,
  PsiResult,
  OwnerHeldPsiSetup,
  PendingPsiRequest,
  PsiResponseRecord,
  OwnerPsiProcessingResult,
  CreatePsiSetupRequest,
  PsiClientSession,
} from './psi/index.js';
