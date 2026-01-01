/**
 * Rendezvous - Private Mutual Matching
 * Core type definitions
 */

// ============================================================================
// Basic Types
// ============================================================================

/** Hex-encoded public key (64 chars for X25519) */
export type PublicKey = string;

/** Hex-encoded private key (64 chars for X25519) */
export type PrivateKey = string;

/** Hex-encoded match token (64 chars SHA-256) */
export type MatchToken = string;

/** Hex-encoded commitment hash (64 chars SHA-256) */
export type CommitHash = string;

/** Pool status throughout its lifecycle */
export type PoolStatus = 'open' | 'commit' | 'reveal' | 'closed';

// ============================================================================
// Pool Types
// ============================================================================

/**
 * A matching pool where participants submit preferences.
 * Supports optional commit-reveal phases to prevent timing attacks.
 */
export interface Pool {
  /** Unique pool identifier (UUID) */
  id: string;

  /** Human-readable name */
  name: string;

  /** Optional description of the pool's purpose */
  description?: string;

  /** Public key of pool creator (X25519 for matching) */
  creatorPublicKey: PublicKey;

  /** Signing public key of pool creator (Ed25519 for authentication) */
  creatorSigningKey: string;

  /**
   * Deadline for commit phase (optional).
   * If set, participants must first commit H(token) before this deadline.
   */
  commitDeadline?: Date;

  /**
   * Deadline for reveal phase.
   * After this, no more submissions are accepted and matches are computed.
   */
  revealDeadline: Date;

  /** Eligibility requirements (gate configuration) */
  eligibilityGate: VoterGate;

  /** Maximum preferences per participant (anti-fishing) */
  maxPreferencesPerParticipant?: number;

  /** Ephemeral mode - auto-delete participant profiles after pool closes */
  ephemeral?: boolean;

  /** Require Freebird invite token to join this pool */
  requiresInviteToJoin?: boolean;

  /** Current pool status */
  status: PoolStatus;

  /** Pool creation timestamp */
  createdAt: Date;

  /** Last update timestamp */
  updatedAt: Date;

  /**
   * PSI setup - created automatically when pool closes.
   * Contains all submitted tokens in PSI-queryable format.
   * Participants query this to learn their matches privately.
   */
  psiSetup?: {
    /** Serialized PSI server setup message (base64) */
    setupMessage: string;
    /** Encrypted PSI server key (for processing queries) */
    encryptedServerKey: string;
  };
}

/** Request to create a new pool */
export interface CreatePoolRequest {
  name: string;
  description?: string;
  creatorPublicKey: PublicKey;
  /** Ed25519 signing public key for owner authentication */
  creatorSigningKey: string;
  commitDeadline?: Date;
  revealDeadline: Date;
  eligibilityGate?: VoterGate;
  maxPreferencesPerParticipant?: number;
  /** Ephemeral mode - auto-delete participant profiles after pool closes */
  ephemeral?: boolean;
  /** Require Freebird invite token to join this pool */
  requiresInviteToJoin?: boolean;
}

// ============================================================================
// Preference Types
// ============================================================================

/**
 * A submitted preference (match token).
 * The token is derived from DH(my_private, their_public, pool_id).
 */
export interface Preference {
  /** Unique preference ID */
  id: string;

  /** Pool this preference belongs to */
  poolId: string;

  /**
   * The match token: H(DH_shared || pool_id || "rendezvous-match-v1")
   * Same for both parties if they select each other.
   */
  matchToken: MatchToken;

  /**
   * Commitment hash for commit phase: H(matchToken)
   * Required if pool has commitDeadline.
   */
  commitHash?: CommitHash;

  /** Whether this preference has been revealed (for commit-reveal pools) */
  revealed: boolean;

  /** Submission timestamp */
  submittedAt: Date;

  /** Freebird eligibility proof (unlinkable) */
  eligibilityProof?: FreebirdProof;

  /**
   * Nullifier to prevent duplicate preference sets per participant.
   * Derived from participant's identity + pool_id.
   */
  nullifier: string;

  /**
   * Encrypted contact info revealed only to mutual matches.
   * Encrypted with the match token as the key (AES-256-GCM).
   * Format: base64(IV || ciphertext || authTag)
   */
  encryptedReveal?: string;
}

/** Encrypted reveal data for a specific selection */
export interface RevealDataEntry {
  /** The match token this reveal data is encrypted for */
  matchToken: MatchToken;
  /** Encrypted contact info (base64 encoded AES-256-GCM ciphertext) */
  encryptedReveal: string;
}

/** Request to submit preferences to a pool */
export interface SubmitPreferencesRequest {
  poolId: string;
  /** Match tokens for each selected party */
  matchTokens: MatchToken[];
  /** Commit hashes if in commit phase */
  commitHashes?: CommitHash[];
  /** Freebird proof of eligibility */
  eligibilityProof?: FreebirdProof;
  /** Nullifier for this participant + pool */
  nullifier: string;
  /** Optional encrypted contact info for each selection (revealed only on match) */
  revealData?: RevealDataEntry[];
}

/** Request to reveal previously committed preferences */
export interface RevealPreferencesRequest {
  poolId: string;
  /** The actual match tokens (must hash to previously submitted commits) */
  matchTokens: MatchToken[];
  /** Nullifier to identify which commitments to reveal */
  nullifier: string;
}

// ============================================================================
// Match Types
// ============================================================================

/**
 * Result of match detection for a pool.
 * Contains tokens that appeared exactly twice (mutual matches).
 */
export interface MatchResult {
  /** Pool ID */
  poolId: string;

  /** Tokens that appeared exactly twice (mutual selections) */
  matchedTokens: MatchToken[];

  /** Total number of tokens submitted */
  totalSubmissions: number;

  /** Number of unique participants */
  uniqueParticipants: number;

  /** When detection was performed */
  detectedAt: Date;

  /** Optional witness attestation of results */
  witnessProof?: WitnessProof;
}

/**
 * A discovered match for a specific participant.
 * Computed locally by the participant, never sent to server.
 */
export interface DiscoveredMatch {
  /** The matched party's public key */
  matchedPublicKey: PublicKey;

  /** The match token (for verification) */
  matchToken: MatchToken;

  /** Pool where match occurred */
  poolId: string;

  /** Encrypted contact info from matched party (if they shared it) */
  encryptedReveal?: string;
}

// ============================================================================
// Gate Types (Eligibility)
// ============================================================================

/** Gate type for eligibility checking */
export type VoterGateType =
  | 'open'           // Anyone can participate
  | 'invite-list'    // Specific public keys allowed
  | 'freebird'       // Must have valid Freebird token from issuer
  | 'composite';     // Combination of gates

/** Base gate configuration */
export interface VoterGateBase {
  type: VoterGateType;
}

/** Open gate - anyone can participate */
export interface OpenGate extends VoterGateBase {
  type: 'open';
}

/** Invite list gate - only specific public keys allowed */
export interface InviteListGate extends VoterGateBase {
  type: 'invite-list';
  allowedKeys: PublicKey[];
}

/** Freebird gate - must have valid token from specified issuer */
export interface FreebirdGate extends VoterGateBase {
  type: 'freebird';
  /** Issuer ID to accept tokens from */
  issuerId: string;
}

/** Composite gate - logical combination of gates */
export interface CompositeGate extends VoterGateBase {
  type: 'composite';
  operator: 'and' | 'or';
  gates: VoterGate[];
}

/** Union type for all gate configurations */
export type VoterGate =
  | OpenGate
  | InviteListGate
  | FreebirdGate
  | CompositeGate;

// ============================================================================
// External Service Types
// ============================================================================

/** Freebird eligibility proof (unlinkable token) */
export interface FreebirdProof {
  /** Base64-encoded token value */
  tokenValue: string;
  /** Token expiration timestamp (ms) */
  expiration: number;
  /** Issuer identifier */
  issuerId: string;
  /** Epoch for key rotation (day-based) */
  epoch?: number;
}

/** Witness timestamp attestation */
export interface WitnessProof {
  /** Hash of attested data (hex) */
  hash: string;
  /** Attestation timestamp (seconds) */
  timestamp: number;
  /** Network ID for verification */
  networkId: string;
  /** Sequence number for ordering */
  sequence: number;
  /** Witness signatures (multi-sig or aggregated) */
  signatures: WitnessSignature[] | WitnessAggregatedSignature;
}

/** BLS aggregated signature */
export interface WitnessAggregatedSignature {
  /** Aggregated signature bytes (hex) */
  signature: string;
  /** List of witness IDs that signed */
  signers: string[];
}

/** Individual witness signature */
export interface WitnessSignature {
  witnessId: string;
  signature: string;
}

// ============================================================================
// Participant Types
// ============================================================================

/**
 * A participant registered in a pool.
 * Contains their public key and profile information.
 */
export interface Participant {
  /** Unique participant ID */
  id: string;

  /** Pool this participant is registered in */
  poolId: string;

  /** Participant's public key for matching */
  publicKey: PublicKey;

  /** Display name */
  displayName: string;

  /** Optional bio/description */
  bio?: string;

  /** Optional avatar URL */
  avatarUrl?: string;

  /** Optional additional profile fields */
  profileData?: Record<string, string>;

  /** Registration timestamp */
  registeredAt: Date;
}

/** Request to register as a participant in a pool */
export interface RegisterParticipantRequest {
  poolId: string;
  publicKey: PublicKey;
  displayName: string;
  bio?: string;
  avatarUrl?: string;
  profileData?: Record<string, string>;
}

/** Filter options for querying participants */
export interface ParticipantFilter {
  poolId?: string;
  publicKey?: PublicKey;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Storage Types
// ============================================================================

/** Filter options for querying pools */
export interface PoolFilter {
  status?: PoolStatus;
  creatorPublicKey?: PublicKey;
  limit?: number;
  offset?: number;
}

/** Filter options for querying preferences */
export interface PreferenceFilter {
  poolId?: string;
  nullifier?: string;
  revealed?: boolean;
}

// ============================================================================
// Error Types
// ============================================================================

/** Error codes for Rendezvous operations */
export enum RendezvousErrorCode {
  // Pool errors
  POOL_NOT_FOUND = 'POOL_NOT_FOUND',
  POOL_CLOSED = 'POOL_CLOSED',
  POOL_NOT_IN_COMMIT_PHASE = 'POOL_NOT_IN_COMMIT_PHASE',
  POOL_NOT_IN_REVEAL_PHASE = 'POOL_NOT_IN_REVEAL_PHASE',

  // Registration errors
  ALREADY_REGISTERED = 'ALREADY_REGISTERED',
  PARTICIPANT_NOT_FOUND = 'PARTICIPANT_NOT_FOUND',

  // Submission errors
  DUPLICATE_NULLIFIER = 'DUPLICATE_NULLIFIER',
  PREFERENCE_LIMIT_EXCEEDED = 'PREFERENCE_LIMIT_EXCEEDED',
  INVALID_ELIGIBILITY_PROOF = 'INVALID_ELIGIBILITY_PROOF',

  // Reveal errors
  COMMITMENT_NOT_FOUND = 'COMMITMENT_NOT_FOUND',
  COMMITMENT_MISMATCH = 'COMMITMENT_MISMATCH',

  // Crypto errors
  INVALID_PUBLIC_KEY = 'INVALID_PUBLIC_KEY',
  INVALID_PRIVATE_KEY = 'INVALID_PRIVATE_KEY',

  // General errors
  INVALID_INPUT = 'INVALID_INPUT',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
}

/** Custom error class for Rendezvous operations */
export class RendezvousError extends Error {
  constructor(
    public readonly code: RendezvousErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'RendezvousError';
  }
}
