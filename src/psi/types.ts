/**
 * Types for Private Set Intersection integration
 *
 * PSI allows two parties to compute the intersection of their sets
 * without revealing non-intersecting elements.
 */

/**
 * PSI setup stored with a pool (created by pool owner)
 */
export interface PsiPoolSetup {
  /** Serialized PSI server setup message (base64) */
  setupMessage: string;
  /** Encrypted PSI server private key for processing requests */
  encryptedServerKey: string;
  /** False positive rate (e.g., 0.001 = 0.1%) */
  fpr: number;
  /** Maximum client elements this setup supports */
  maxClientElements: number;
  /** Data structure used (GCS or BloomFilter) */
  dataStructure: 'GCS' | 'BloomFilter';
}

/**
 * Request to create PSI setup for a pool
 */
export interface CreatePsiSetupRequest {
  /** Pool ID */
  poolId: string;
  /** Match tokens to include in PSI set */
  matchTokens: string[];
  /** False positive rate (default: 0.001) */
  fpr?: number;
  /** Max expected client elements (default: 10000) */
  maxClientElements?: number;
}

/**
 * PSI join request from a client
 */
export interface PsiJoinRequest {
  /** Pool to compute intersection with */
  poolId: string;
  /** Freebird anonymous auth token */
  authToken: string;
  /** Serialized PSI client request (base64) */
  psiRequest: string;
}

/**
 * Response to PSI join request
 */
export interface PsiJoinResponse {
  /** Serialized PSI setup message (base64) - client needs this */
  psiSetup: string;
  /** Serialized PSI response (base64) */
  psiResponse: string;
}

/**
 * Result of PSI computation (client-side only)
 */
export interface PsiResult {
  /** Elements in the intersection */
  intersection: string[];
  /** Number of matches */
  cardinality: number;
}

/**
 * PSI server state (for pool owners)
 */
export interface PsiServerState {
  /** Private key bytes (sensitive!) */
  privateKey: Uint8Array;
  /** Whether to reveal intersection or just cardinality */
  revealIntersection: boolean;
}

/**
 * PSI client state (for joiners)
 */
export interface PsiClientState {
  /** Private key bytes */
  privateKey: Uint8Array;
  /** Original inputs for intersection computation */
  inputs: string[];
  /** Whether to reveal intersection or just cardinality */
  revealIntersection: boolean;
}

// ============================================================================
// Owner-Held PSI Key Types (Option B - Pool Owner Holds Key)
// ============================================================================

/**
 * Owner-encrypted PSI setup stored in database.
 * The server CANNOT decrypt encryptedServerKey - only the pool owner can.
 */
export interface OwnerHeldPsiSetup {
  /** Pool ID this setup belongs to */
  poolId: string;
  /** Serialized PSI server setup message (base64) - PUBLIC */
  setupMessage: string;
  /** PSI server key encrypted to pool owner's public key (serialized EncryptedBox) */
  encryptedServerKey: string;
  /** Pool owner's public key (for verification) */
  ownerPublicKey: string;
  /** False positive rate */
  fpr: number;
  /** Maximum client elements */
  maxClientElements: number;
  /** Data structure used */
  dataStructure: 'GCS' | 'BloomFilter';
  /** When setup was created (unix timestamp ms) */
  createdAt: number;
}

/**
 * Pending PSI request waiting for owner processing.
 * Server queues these until the pool owner polls and processes them.
 */
export interface PendingPsiRequest {
  /** Unique request ID */
  id: string;
  /** Pool ID */
  poolId: string;
  /** Serialized PSI client request (base64) */
  psiRequest: string;
  /** Request status */
  status: 'pending' | 'processing' | 'completed' | 'expired';
  /** Request timestamp (unix timestamp ms) */
  createdAt: number;
  /** Hash of auth token (for auditing without revealing identity) */
  authTokenHash?: string;
}

/**
 * PSI response from pool owner after processing a request.
 */
export interface PsiResponseRecord {
  /** Unique response ID */
  id: string;
  /** Request ID this response is for */
  requestId: string;
  /** Pool ID */
  poolId: string;
  /** Serialized PSI setup message (base64) */
  psiSetup: string;
  /** Serialized PSI response (base64) */
  psiResponse: string;
  /** When response was created (unix timestamp ms) */
  createdAt: number;
  /** When response expires (unix timestamp ms) */
  expiresAt: number;
}

/**
 * Owner's response after processing PSI requests locally
 */
export interface OwnerPsiProcessingResult {
  /** Request ID */
  requestId: string;
  /** Serialized PSI response (base64) */
  psiResponse: string;
}
