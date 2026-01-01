/**
 * Federation Types
 *
 * Types for federated Rendezvous instances using HyperToken patterns.
 * Pools can be discovered and joined across federated instances.
 */

/**
 * Unique identifier for a federated instance
 */
export interface InstanceId {
  /** Unique instance identifier (UUID) */
  id: string;
  /** Human-readable instance name */
  name: string;
  /** WebSocket endpoint for federation protocol */
  endpoint: string;
  /** Instance public key for authentication */
  publicKey: string;
}

/**
 * Pool metadata shared across federated instances via CRDT
 */
export interface FederatedPoolMetadata {
  /** Pool ID (unique across federation) */
  poolId: string;
  /** Instance that created/owns the pool */
  ownerInstance: string;
  /** Owner instance's public key for encrypting join requests (hex X25519) */
  ownerPublicKey: string;
  /** Pool name */
  name: string;
  /** Pool description */
  description?: string;
  /** Reveal deadline timestamp */
  revealDeadline: number;
  /** Current phase */
  phase: 'open' | 'commit' | 'reveal' | 'closed';
  /** Participant count (updated periodically) */
  participantCount: number;
  /** Gate type for eligibility */
  gateType: string;
  /** When this metadata was last updated */
  updatedAt: number;
}

/**
 * CRDT document structure for federation state
 * This is synchronized across all federated instances using Automerge
 */
export interface FederationState {
  /** Known instances in the federation */
  instances: { [key: string]: InstanceId };
  /** Pools announced to the federation */
  pools: { [key: string]: FederatedPoolMetadata };
  /** Federation protocol version */
  version: number;
  /** Index signature for Automerge compatibility */
  [key: string]: unknown;
}

/**
 * Message types for federation protocol
 */
export type FederationMessageType =
  | 'sync'           // Automerge sync message
  | 'pool_announce'  // New pool announcement
  | 'pool_update'    // Pool metadata update
  | 'join_request'   // Cross-instance join request
  | 'join_response'  // Response to join request
  | 'token_relay'    // Relay match tokens to owner instance
  | 'result_notify'  // Notify of match results
  | 'ping'           // Keepalive
  | 'pong';          // Keepalive response

/**
 * Base federation message
 */
export interface FederationMessage {
  type: FederationMessageType;
  /** Sender instance ID */
  from: string;
  /** Message timestamp */
  timestamp: number;
  /** Message ID for tracking */
  messageId: string;
}

/**
 * Automerge sync message for CRDT replication
 */
export interface SyncMessage extends FederationMessage {
  type: 'sync';
  /** Base64-encoded Automerge sync message */
  syncData: string;
}

/**
 * Pool announcement message
 */
export interface PoolAnnounceMessage extends FederationMessage {
  type: 'pool_announce';
  pool: FederatedPoolMetadata;
}

/**
 * Encrypted join request payload (decryptable only by pool owner)
 */
export interface JoinRequestPayload {
  /** Display name */
  displayName: string;
  /** Optional bio */
  bio?: string;
  /** Freebird proof if required */
  freebirdProof?: string;
}

/**
 * Cross-instance join request
 * Privacy: Profile data is encrypted so only the pool owner can read it.
 * Intermediate relay instances cannot see displayName, bio, or proofs.
 */
export interface JoinRequestMessage extends FederationMessage {
  type: 'join_request';
  poolId: string;
  /** Participant's public key (visible for routing) */
  publicKey: string;
  /** Encrypted payload containing displayName, bio, freebirdProof (base64 EncryptedBox) */
  encryptedPayload: string;
}

/**
 * Join response
 * Privacy note: Participant lists are NOT included here to prevent intermediate
 * instances from learning pool membership. Clients should fetch participants
 * directly from the pool owner instance via /api/pools/:id/participants
 */
export interface JoinResponseMessage extends FederationMessage {
  type: 'join_response';
  poolId: string;
  publicKey: string;
  success: boolean;
  error?: string;
}

/**
 * Relay match tokens to the pool's owner instance
 */
export interface TokenRelayMessage extends FederationMessage {
  type: 'token_relay';
  poolId: string;
  /** Match tokens to submit */
  matchTokens: string[];
  /** Nullifier for replay protection */
  nullifier: string;
}

/**
 * Notify federated instances of match results
 */
export interface ResultNotifyMessage extends FederationMessage {
  type: 'result_notify';
  poolId: string;
  /** Matched tokens (for participants to discover their matches) */
  matchedTokens: string[];
  /** Witness attestation proof */
  witnessProof?: {
    hash: string;
    timestamp: number;
    signatures: Array<{ witnessId: string; signature: string }>;
  };
}

/**
 * Peer connection state
 */
export interface PeerState {
  instance: InstanceId;
  /** WebSocket connection */
  connected: boolean;
  /** Last sync state for Automerge */
  syncState?: unknown;
  /** Last successful ping time */
  lastPing: number;
  /** Connection retry count */
  retryCount: number;
}

/**
 * Federation configuration
 *
 * Federation requires Freebird for anonymous messaging - this is by design.
 * All federated messages use unlinkable tokens instead of instance IDs.
 */
export interface FederationConfig {
  /** This instance's identity */
  instance: InstanceId;
  /** Known peer instances to connect to */
  peers: string[];
  /** Enable federation (default: false) */
  enabled: boolean;
  /** Sync interval in ms (default: 30000) */
  syncInterval?: number;
  /** Connection timeout in ms (default: 10000) */
  connectionTimeout?: number;
  /** Freebird issuer URL (required for federation) */
  freebirdIssuerUrl: string;
  /** Freebird verifier URL (defaults to issuer URL) */
  freebirdVerifierUrl?: string;
}

// ============================================================================
// Anonymous Federation Messages (using Freebird tokens instead of instance IDs)
// ============================================================================

/**
 * Base anonymous federation message - no 'from' field!
 * Uses Freebird token for authorization without identification.
 */
export interface AnonymousFederationMessage {
  type: FederationMessageType;
  /** Freebird auth token (serialized) - proves authorization without revealing identity */
  authToken: string;
  /** Message timestamp */
  timestamp: number;
  /** Message ID for tracking */
  messageId: string;
}

/**
 * Anonymous token relay message
 * Privacy: Sender's instance is not revealed - only the auth token proves authorization.
 */
export interface AnonymousTokenRelayMessage extends AnonymousFederationMessage {
  type: 'token_relay';
  poolId: string;
  /** Match tokens to submit */
  matchTokens: string[];
  /** Nullifier for replay protection */
  nullifier: string;
}

/**
 * Anonymous join request
 * Privacy: Both sender instance AND profile data are protected.
 * - Sender instance hidden via Freebird token
 * - Profile data encrypted for pool owner only
 */
export interface AnonymousJoinRequestMessage extends AnonymousFederationMessage {
  type: 'join_request';
  poolId: string;
  /** Participant's public key (visible for routing) */
  publicKey: string;
  /** Encrypted payload containing displayName, bio, freebirdProof (base64 EncryptedBox) */
  encryptedPayload: string;
}

/**
 * Type guard to check if a message is anonymous
 */
export function isAnonymousMessage(
  msg: FederationMessage | AnonymousFederationMessage
): msg is AnonymousFederationMessage {
  return 'authToken' in msg && !('from' in msg);
}

/**
 * Union type for all federation messages (both identified and anonymous)
 */
export type AnyFederationMessage = FederationMessage | AnonymousFederationMessage;
