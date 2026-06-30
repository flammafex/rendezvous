/**
 * PSI types for private set intersection operations.
 *
 * Note: PsiJoinRequest (with authToken) is an application concern and
 * lives in the consuming app. Matchlock exposes only PSI primitives.
 */

/** PSI client request — the serialized blind query */
export interface PsiClientRequest {
  psiRequest: string;
}

/** Response to a PSI query */
export interface PsiJoinResponse {
  psiSetup: string;
  psiResponse: string;
}

/** Result of PSI intersection computation (client-side only) */
export interface PsiResult {
  intersection: string[];
  cardinality: number;
}

/**
 * Owner-encrypted PSI setup stored in database.
 * The server CANNOT decrypt encryptedServerKey — only the pool owner can.
 */
export interface OwnerHeldPsiSetup {
  poolId: string;
  /** Serialized PSI server setup message (base64) — PUBLIC */
  setupMessage: string;
  /** PSI server key encrypted to pool owner's X25519 public key (serialized EncryptedBox) */
  encryptedServerKey: string;
  ownerPublicKey: string;
  fpr: number;
  maxClientElements: number;
  dataStructure: 'GCS' | 'BloomFilter';
  createdAt: number;
}

/** Pending PSI request queued for pool owner processing */
export interface PendingPsiRequest {
  id: string;
  poolId: string;
  psiRequest: string;
  status: 'pending' | 'processing' | 'completed' | 'expired';
  createdAt: number;
  /** Hash of auth token (for auditing without revealing identity) */
  authTokenHash?: string;
}

/** PSI response record after owner processes a request */
export interface PsiResponseRecord {
  id: string;
  requestId: string;
  poolId: string;
  psiSetup: string;
  psiResponse: string;
  createdAt: number;
  expiresAt: number;
}

/** Owner's batch processing result */
export interface OwnerPsiProcessingResult {
  requestId: string;
  psiResponse: string;
}

/** Request to create a new PSI setup for a pool */
export interface CreatePsiSetupRequest {
  poolId: string;
  matchTokens: string[];
  fpr?: number;
  maxClientElements?: number;
}

/**
 * Opaque client session returned by PsiService.createRequest.
 * Pass the whole object to computeIntersection / computeCardinality —
 * never reassemble it manually. This prevents the inputs-mismatch footgun.
 */
export interface PsiClientSession {
  readonly clientKey: string;
  readonly inputs: readonly string[];
}
