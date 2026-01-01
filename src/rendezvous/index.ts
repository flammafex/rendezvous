/**
 * Rendezvous - Private Mutual Matching
 *
 * Two parties can discover if they mutually selected each other
 * without revealing:
 * - Who you selected (if not mutual)
 * - Who rejected you
 * - That you even participated
 *
 * Use cases: dating, hiring, roommate matching, mentor pairing,
 * any N↔N selection where privacy matters.
 */

import { RendezvousStore, SQLiteStore, InMemoryStore } from './storage.js';
import { PoolManager } from './pool.js';
import { SubmissionManager, SubmissionResult, RevealResult } from './submission.js';
import { MatchDetector, MatchStats, VerificationResult } from './detection.js';
import { GateSystem, FreebirdAdapter, WitnessAdapter } from './gates/index.js';
import {
  Pool,
  CreatePoolRequest,
  SubmitPreferencesRequest,
  RevealPreferencesRequest,
  MatchResult,
  DiscoveredMatch,
  Participant,
  RegisterParticipantRequest,
  ParticipantFilter,
  PoolFilter,
  PublicKey,
  PrivateKey,
  MatchToken,
  VoterGate,
  RendezvousError,
  RendezvousErrorCode,
} from './types.js';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from './crypto.js';

// Re-export types and utilities
export * from './types.js';
export * from './crypto.js';
export * from './storage.js';
export * from './pool.js';
export * from './submission.js';
export * from './detection.js';
export * from './gates/index.js';

/**
 * Configuration for Rendezvous instance.
 */
export interface RendezvousConfig {
  /** Path to SQLite database (or ':memory:' for in-memory) */
  dbPath?: string;

  /** Freebird adapter for proof verification */
  freebird?: FreebirdAdapter;

  /** Witness adapter for timestamp attestation */
  witness?: WitnessAdapter;
}

/**
 * Main Rendezvous class - the public API for the matching system.
 */
export class Rendezvous {
  private _store: RendezvousStore;

  /**
   * Access to the underlying storage layer.
   * Used for PSI owner-held key operations.
   */
  get store(): RendezvousStore {
    return this._store;
  }
  private poolManager: PoolManager;
  private submissionManager: SubmissionManager;
  private matchDetector: MatchDetector;
  private gateSystem: GateSystem;

  constructor(config: RendezvousConfig = {}) {
    // Initialize storage
    this._store = config.dbPath
      ? new SQLiteStore(config.dbPath)
      : new InMemoryStore();

    // Initialize managers
    this.poolManager = new PoolManager(this._store);
    this.submissionManager = new SubmissionManager(this._store, this.poolManager);
    this.matchDetector = new MatchDetector(this._store, this.poolManager, config.witness);
    this.gateSystem = new GateSystem(config.freebird);
  }

  // =========================================================================
  // Pool Management
  // =========================================================================

  /**
   * Create a new matching pool.
   *
   * @param request - Pool creation parameters
   * @returns The created pool
   */
  createPool(request: CreatePoolRequest): Pool {
    return this.poolManager.createPool(request);
  }

  /**
   * Get a pool by ID.
   *
   * @param id - Pool ID
   * @returns The pool or undefined
   */
  getPool(id: string): Pool | undefined {
    return this.poolManager.getPool(id);
  }

  /**
   * List pools with optional filters.
   *
   * @param filter - Filter options
   * @returns Array of pools
   */
  listPools(filter?: PoolFilter): Pool[] {
    return this.poolManager.listPools(filter);
  }

  /**
   * Manually close a pool.
   *
   * @param poolId - Pool ID
   * @returns Updated pool
   */
  closePool(poolId: string): Pool {
    return this.poolManager.closePool(poolId);
  }

  /**
   * Get pool phase information.
   *
   * @param poolId - Pool ID
   * @returns Phase info
   */
  getPoolPhase(poolId: string): ReturnType<PoolManager['getPhaseInfo']> {
    const pool = this.poolManager.requirePool(poolId);
    return this.poolManager.getPhaseInfo(pool);
  }

  // =========================================================================
  // Participant Registration
  // =========================================================================

  /**
   * Register as a participant in a pool.
   * Must provide a public key and profile information.
   *
   * @param request - Registration request with profile info
   * @returns The created participant
   */
  registerParticipant(request: RegisterParticipantRequest): Participant {
    // Verify pool exists and is open
    const pool = this.poolManager.requirePool(request.poolId);
    if (pool.status === 'closed') {
      throw new RendezvousError(
        RendezvousErrorCode.POOL_CLOSED,
        'Cannot register for a closed pool',
      );
    }

    // Check if already registered
    const existing = this._store.getParticipantByPublicKey(request.poolId, request.publicKey);
    if (existing) {
      throw new RendezvousError(
        RendezvousErrorCode.ALREADY_REGISTERED,
        'Already registered in this pool',
      );
    }

    const participant: Participant = {
      id: uuidv4(),
      poolId: request.poolId,
      publicKey: request.publicKey,
      displayName: request.displayName,
      bio: request.bio,
      avatarUrl: request.avatarUrl,
      profileData: request.profileData,
      registeredAt: new Date(),
    };

    this._store.insertParticipant(participant);
    return participant;
  }

  /**
   * Get a participant by ID.
   *
   * @param id - Participant ID
   * @returns The participant or undefined
   */
  getParticipant(id: string): Participant | undefined {
    return this._store.getParticipant(id);
  }

  /**
   * Get a participant by their public key in a pool.
   *
   * @param poolId - Pool ID
   * @param publicKey - Public key
   * @returns The participant or undefined
   */
  getParticipantByPublicKey(poolId: string, publicKey: string): Participant | undefined {
    return this._store.getParticipantByPublicKey(poolId, publicKey);
  }

  /**
   * List participants in a pool.
   *
   * @param poolId - Pool ID
   * @param filter - Optional filter options
   * @returns Array of participants
   */
  listParticipants(poolId: string, filter?: Omit<ParticipantFilter, 'poolId'>): Participant[] {
    return this._store.getParticipants({ poolId, ...filter });
  }

  /**
   * Get participant count for a pool.
   *
   * @param poolId - Pool ID
   * @returns Number of registered participants
   */
  getParticipantCount(poolId: string): number {
    return this._store.countParticipantsByPoolId(poolId);
  }

  /**
   * Delete all participants in a pool.
   * Used for ephemeral pool cleanup after match detection.
   *
   * @param poolId - Pool ID
   * @returns Number of deleted participants
   */
  deletePoolParticipants(poolId: string): number {
    return this._store.deleteParticipantsByPoolId(poolId);
  }

  // =========================================================================
  // Preference Submission
  // =========================================================================

  /**
   * Submit preferences to a pool.
   *
   * In a commit-reveal pool, this submits commitments.
   * In an open pool, this submits tokens directly.
   *
   * @param request - Submission request
   * @returns Submission result
   */
  submitPreferences(request: SubmitPreferencesRequest): SubmissionResult {
    return this.submissionManager.submitPreferences(request);
  }

  /**
   * Reveal previously committed preferences.
   *
   * @param request - Reveal request
   * @returns Reveal result
   */
  revealPreferences(request: RevealPreferencesRequest): RevealResult {
    return this.submissionManager.revealPreferences(request);
  }

  /**
   * Check if participant has already submitted to a pool.
   *
   * @param poolId - Pool ID
   * @param nullifier - Participant's nullifier
   * @returns True if already submitted
   */
  hasSubmitted(poolId: string, nullifier: string): boolean {
    return this.submissionManager.hasSubmitted(poolId, nullifier);
  }

  /**
   * Get all preferences for a pool.
   * Used to retrieve encrypted reveal data for matched tokens.
   *
   * @param poolId - Pool ID
   * @returns Array of preferences
   */
  getPreferencesByPool(poolId: string): import('./types.js').Preference[] {
    return this._store.getPreferencesByPoolId(poolId);
  }

  // =========================================================================
  // Match Detection
  // =========================================================================

  /**
   * Detect matches in a closed pool.
   *
   * @param poolId - Pool ID
   * @returns Match result
   */
  async detectMatches(poolId: string): Promise<MatchResult> {
    return this.matchDetector.detectMatches(poolId);
  }

  /**
   * Get match result for a pool.
   *
   * @param poolId - Pool ID
   * @returns Match result or undefined
   */
  getMatchResult(poolId: string): MatchResult | undefined {
    return this.matchDetector.getMatchResult(poolId);
  }

  /**
   * Get match statistics for a pool.
   *
   * @param poolId - Pool ID
   * @returns Match statistics
   */
  getMatchStats(poolId: string): MatchStats {
    return this.matchDetector.getMatchStats(poolId);
  }

  /**
   * Verify integrity of match results.
   *
   * @param poolId - Pool ID
   * @returns Verification result
   */
  verifyMatchIntegrity(poolId: string): VerificationResult {
    return this.matchDetector.verifyMatchIntegrity(poolId);
  }

  // =========================================================================
  // Local Discovery (Client-Side)
  // =========================================================================

  /**
   * Discover which of your selections were mutual matches.
   *
   * This is computed locally and never reveals to the server
   * which matches you found.
   *
   * @param poolId - Pool ID
   * @param myPrivateKey - Your X25519 private key
   * @param selectedPublicKeys - Public keys you selected
   * @returns Array of discovered matches
   */
  discoverMyMatches(
    poolId: string,
    myPrivateKey: PrivateKey,
    selectedPublicKeys: PublicKey[],
  ): DiscoveredMatch[] {
    return this.matchDetector.discoverMyMatches(poolId, myPrivateKey, selectedPublicKeys);
  }

  /**
   * Check if you matched with a specific party.
   *
   * @param poolId - Pool ID
   * @param myPrivateKey - Your X25519 private key
   * @param theirPublicKey - Their public key
   * @returns True if mutual match exists
   */
  checkMatch(poolId: string, myPrivateKey: PrivateKey, theirPublicKey: PublicKey): boolean {
    return this.matchDetector.checkMatch(poolId, myPrivateKey, theirPublicKey);
  }

  // =========================================================================
  // Eligibility
  // =========================================================================

  /**
   * Check if a participant is eligible for a pool.
   *
   * @param poolId - Pool ID
   * @param participantKey - Participant's public key
   * @returns Gate result
   */
  async checkEligibility(
    poolId: string,
    participantKey?: PublicKey,
  ): Promise<{ eligible: boolean; reason: string }> {
    const pool = this.poolManager.requirePool(poolId);
    const result = await this.gateSystem.evaluate(pool.eligibilityGate, {
      participantKey,
      poolId,
    });
    return { eligible: result.eligible, reason: result.reason };
  }

  // =========================================================================
  // Crypto Utilities
  // =========================================================================

  /**
   * Generate a new X25519 keypair.
   */
  generateKeypair = crypto.generateKeypair;

  /**
   * Derive match token(s) for selected parties.
   */
  deriveMatchToken = crypto.deriveMatchToken;
  deriveMatchTokens = crypto.deriveMatchTokens;

  /**
   * Create commitment(s) for commit-reveal.
   */
  commitToken = crypto.commitToken;
  commitTokens = crypto.commitTokens;

  /**
   * Derive nullifier for a pool.
   */
  deriveNullifier = crypto.deriveNullifier;

  // =========================================================================
  // Lifecycle
  // =========================================================================

  /**
   * Close the Rendezvous instance and release resources.
   */
  close(): void {
    this._store.close();
  }
}

/**
 * Create a production Rendezvous instance with SQLite storage.
 *
 * @param configOrDbPath - Configuration object or path to SQLite database
 * @returns Rendezvous instance
 */
export function createRendezvous(
  configOrDbPath: RendezvousConfig | string,
): Rendezvous {
  if (typeof configOrDbPath === 'string') {
    return new Rendezvous({ dbPath: configOrDbPath });
  }
  return new Rendezvous(configOrDbPath);
}

/**
 * Create a test Rendezvous instance with in-memory storage.
 *
 * @returns Rendezvous instance
 */
export function createTestRendezvous(): Rendezvous {
  return new Rendezvous();
}
