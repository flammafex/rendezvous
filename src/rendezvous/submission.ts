/**
 * Rendezvous - Private Mutual Matching
 * Submission handling: commit-reveal, nullifier enforcement, preference limits
 */

import { v4 as uuidv4 } from 'uuid';
import {
  Preference,
  SubmitPreferencesRequest,
  RevealPreferencesRequest,
  Pool,
  RendezvousError,
  RendezvousErrorCode,
} from './types.js';
import { RendezvousStore } from './storage.js';
import { PoolManager } from './pool.js';
import { commitToken, verifyCommitment, isValidMatchToken, randomHex } from './crypto.js';

// Decoy token configuration
// Adding random decoy tokens hides the true number of preferences from observers
const DECOY_MIN = 3;
const DECOY_MAX = 8;

/**
 * Generate random decoy tokens to pad submissions.
 * Decoys are indistinguishable from real tokens (random 32-byte hex strings).
 * They will only appear once in the pool, so they won't affect match detection.
 */
function generateDecoyTokens(): string[] {
  const count = DECOY_MIN + Math.floor(Math.random() * (DECOY_MAX - DECOY_MIN + 1));
  const decoys: string[] = [];
  for (let i = 0; i < count; i++) {
    decoys.push(randomHex(32)); // 32 bytes = 64 hex chars, same as SHA-256 hash
  }
  return decoys;
}

/**
 * Result of a preference submission.
 */
export interface SubmissionResult {
  success: boolean;
  preferenceIds: string[];
  phase: 'commit' | 'reveal';
  message: string;
}

/**
 * Result of a preference reveal.
 */
export interface RevealResult {
  success: boolean;
  revealedCount: number;
  message: string;
}

/**
 * Submission manager handles preference submissions:
 * - Commit phase: Accept H(token) commitments
 * - Reveal phase: Accept actual tokens and verify against commitments
 * - Nullifier enforcement: One submission set per participant per pool
 * - Preference limits: Anti-fishing protection
 */
export class SubmissionManager {
  constructor(
    private store: RendezvousStore,
    private poolManager: PoolManager,
  ) {}

  /**
   * Submit preferences to a pool.
   *
   * Behavior depends on pool phase:
   * - Commit phase: Stores H(token) commitments
   * - Open/Reveal phase: Stores actual tokens directly
   *
   * @param request - Submission request
   * @returns Submission result
   */
  submitPreferences(request: SubmitPreferencesRequest): SubmissionResult {
    const pool = this.poolManager.requirePool(request.poolId);
    this.poolManager.updatePoolStatus(pool.id);

    // Validate request
    this.validateSubmission(request, pool);

    // Check if this is a commit or direct reveal
    const status = this.poolManager.getEffectiveStatus(pool);

    if (status === 'commit') {
      return this.handleCommitSubmission(request, pool);
    } else if (status === 'open' || status === 'reveal') {
      return this.handleDirectSubmission(request, pool);
    } else {
      throw new RendezvousError(RendezvousErrorCode.POOL_CLOSED, 'Pool is closed for submissions');
    }
  }

  /**
   * Reveal previously committed preferences.
   *
   * @param request - Reveal request
   * @returns Reveal result
   */
  revealPreferences(request: RevealPreferencesRequest): RevealResult {
    const pool = this.poolManager.requirePool(request.poolId);
    this.poolManager.updatePoolStatus(pool.id);

    const status = this.poolManager.getEffectiveStatus(pool);

    if (status !== 'reveal') {
      if (status === 'commit') {
        throw new RendezvousError(
          RendezvousErrorCode.POOL_NOT_IN_REVEAL_PHASE,
          'Pool is still in commit phase',
        );
      }
      if (status === 'closed') {
        throw new RendezvousError(RendezvousErrorCode.POOL_CLOSED, 'Pool is closed');
      }
      // Open pools don't need reveals
      throw new RendezvousError(
        RendezvousErrorCode.POOL_NOT_IN_REVEAL_PHASE,
        'Pool does not use commit-reveal',
      );
    }

    return this.handleReveal(request, pool);
  }

  /**
   * Get preferences submitted by a participant (by nullifier).
   *
   * @param poolId - Pool ID
   * @param nullifier - Participant's nullifier
   * @returns Array of preferences
   */
  getPreferencesByNullifier(poolId: string, nullifier: string): Preference[] {
    return this.store.getPreferencesByNullifier(poolId, nullifier);
  }

  /**
   * Check if a participant has already submitted to a pool.
   *
   * @param poolId - Pool ID
   * @param nullifier - Participant's nullifier
   * @returns True if already submitted
   */
  hasSubmitted(poolId: string, nullifier: string): boolean {
    return this.store.countPreferencesByNullifier(poolId, nullifier) > 0;
  }

  // Private methods

  private validateSubmission(request: SubmitPreferencesRequest, pool: Pool): void {
    // Validate nullifier
    if (!request.nullifier || request.nullifier.length === 0) {
      throw new RendezvousError(RendezvousErrorCode.INVALID_INPUT, 'Nullifier is required');
    }

    // Check for duplicate submission
    if (this.hasSubmitted(pool.id, request.nullifier)) {
      throw new RendezvousError(
        RendezvousErrorCode.DUPLICATE_NULLIFIER,
        'Already submitted preferences to this pool',
      );
    }

    // Validate tokens/commitments
    if (!request.matchTokens || request.matchTokens.length === 0) {
      throw new RendezvousError(RendezvousErrorCode.INVALID_INPUT, 'At least one preference required');
    }

    // Check preference limit
    if (pool.maxPreferencesPerParticipant) {
      if (request.matchTokens.length > pool.maxPreferencesPerParticipant) {
        throw new RendezvousError(
          RendezvousErrorCode.PREFERENCE_LIMIT_EXCEEDED,
          `Preference limit exceeded: max ${pool.maxPreferencesPerParticipant}, got ${request.matchTokens.length}`,
        );
      }
    }

    // Validate token format
    for (const token of request.matchTokens) {
      if (!isValidMatchToken(token)) {
        throw new RendezvousError(
          RendezvousErrorCode.INVALID_INPUT,
          `Invalid match token format: ${token.substring(0, 16)}...`,
        );
      }
    }

    // For commit phase, validate commit hashes if provided
    if (this.poolManager.getEffectiveStatus(pool) === 'commit') {
      if (request.commitHashes) {
        if (request.commitHashes.length !== request.matchTokens.length) {
          throw new RendezvousError(
            RendezvousErrorCode.INVALID_INPUT,
            'Commit hash count must match token count',
          );
        }
      }
    }
  }

  private handleCommitSubmission(
    request: SubmitPreferencesRequest,
    pool: Pool,
  ): SubmissionResult {
    const now = new Date();
    const preferenceIds: string[] = [];
    const realTokenCount = request.matchTokens.length;

    // Build a map of matchToken -> encryptedReveal for quick lookup
    const revealDataMap = new Map<string, string>();
    if (request.revealData) {
      for (const entry of request.revealData) {
        revealDataMap.set(entry.matchToken, entry.encryptedReveal);
      }
    }

    // For commit phase, we store the commitment hash, not the actual token
    // The token is stored but not revealed until reveal phase
    for (let i = 0; i < request.matchTokens.length; i++) {
      const token = request.matchTokens[i];
      const commit = request.commitHashes?.[i] || commitToken(token);

      const preference: Preference = {
        id: uuidv4(),
        poolId: pool.id,
        matchToken: token, // Store actual token (hidden until reveal)
        commitHash: commit,
        revealed: false, // Not revealed yet
        submittedAt: now,
        eligibilityProof: request.eligibilityProof,
        nullifier: request.nullifier,
        encryptedReveal: revealDataMap.get(token),
      };

      this.store.insertPreference(preference);
      preferenceIds.push(preference.id);
    }

    // Add decoy tokens to obscure the true preference count
    // Decoys are random tokens that won't match anything
    const decoys = generateDecoyTokens();
    for (const decoyToken of decoys) {
      const decoyCommit = commitToken(decoyToken);
      const preference: Preference = {
        id: uuidv4(),
        poolId: pool.id,
        matchToken: decoyToken,
        commitHash: decoyCommit,
        revealed: false,
        submittedAt: now,
        eligibilityProof: request.eligibilityProof,
        nullifier: request.nullifier,
        // No encryptedReveal for decoys
      };

      this.store.insertPreference(preference);
      // Don't add decoy IDs to preferenceIds - they're internal
    }

    return {
      success: true,
      preferenceIds,
      phase: 'commit',
      message: `Committed ${realTokenCount} preferences. Remember to reveal before deadline.`,
    };
  }

  private handleDirectSubmission(
    request: SubmitPreferencesRequest,
    pool: Pool,
  ): SubmissionResult {
    const now = new Date();
    const preferenceIds: string[] = [];
    const realTokenCount = request.matchTokens.length;

    // Build a map of matchToken -> encryptedReveal for quick lookup
    const revealDataMap = new Map<string, string>();
    if (request.revealData) {
      for (const entry of request.revealData) {
        revealDataMap.set(entry.matchToken, entry.encryptedReveal);
      }
    }

    // For open/reveal pools without commit phase, tokens are directly revealed
    for (const token of request.matchTokens) {
      const preference: Preference = {
        id: uuidv4(),
        poolId: pool.id,
        matchToken: token,
        commitHash: undefined,
        revealed: true, // Directly revealed
        submittedAt: now,
        eligibilityProof: request.eligibilityProof,
        nullifier: request.nullifier,
        encryptedReveal: revealDataMap.get(token),
      };

      this.store.insertPreference(preference);
      preferenceIds.push(preference.id);
    }

    // Add decoy tokens to obscure the true preference count
    // Decoys are random tokens that won't match anything
    const decoys = generateDecoyTokens();
    for (const decoyToken of decoys) {
      const preference: Preference = {
        id: uuidv4(),
        poolId: pool.id,
        matchToken: decoyToken,
        commitHash: undefined,
        revealed: true, // Directly revealed (same as real tokens)
        submittedAt: now,
        eligibilityProof: request.eligibilityProof,
        nullifier: request.nullifier,
        // No encryptedReveal for decoys
      };

      this.store.insertPreference(preference);
      // Don't add decoy IDs to preferenceIds - they're internal
    }

    return {
      success: true,
      preferenceIds,
      phase: 'reveal',
      message: `Submitted ${realTokenCount} preferences.`,
    };
  }

  private handleReveal(request: RevealPreferencesRequest, pool: Pool): RevealResult {
    // Get committed preferences for this nullifier
    const committed = this.store.getPreferencesByNullifier(pool.id, request.nullifier);

    if (committed.length === 0) {
      throw new RendezvousError(
        RendezvousErrorCode.COMMITMENT_NOT_FOUND,
        'No commitments found for this nullifier',
      );
    }

    // Check if already revealed
    const unrevealed = committed.filter((p) => !p.revealed);
    if (unrevealed.length === 0) {
      return {
        success: true,
        revealedCount: 0,
        message: 'All preferences already revealed',
      };
    }

    // Match user's tokens to commitments
    // Note: The server also added decoy tokens that the user doesn't know about.
    // These will be auto-revealed since we already have their token values stored.
    const tokenSet = new Set(request.matchTokens);
    let revealedCount = 0;
    const unmatched: Preference[] = [];

    for (const pref of unrevealed) {
      // Find a matching token from the user's submission
      let matchedToken: string | null = null;

      for (const token of tokenSet) {
        if (pref.commitHash && verifyCommitment(token, pref.commitHash)) {
          matchedToken = token;
          break;
        }
      }

      if (matchedToken) {
        // User provided a matching token - reveal it
        this.store.updatePreferenceRevealed(pref.id, matchedToken);
        tokenSet.delete(matchedToken);
        revealedCount++;
      } else {
        // No user token matched - this is likely a decoy
        // We can verify by checking if the stored token matches its own commitment
        if (pref.commitHash && pref.matchToken && verifyCommitment(pref.matchToken, pref.commitHash)) {
          // This is a decoy (or unrevealed real token) - auto-reveal using stored token
          this.store.updatePreferenceRevealed(pref.id, pref.matchToken);
          revealedCount++;
        } else {
          // Commitment doesn't match - shouldn't happen with valid data
          unmatched.push(pref);
        }
      }
    }

    // If user provided tokens that didn't match any commitment, that's an error
    if (tokenSet.size > 0) {
      throw new RendezvousError(
        RendezvousErrorCode.COMMITMENT_MISMATCH,
        `${tokenSet.size} revealed token(s) did not match any commitment`,
      );
    }

    return {
      success: true,
      revealedCount,
      message: `Revealed ${revealedCount} preferences`,
    };
  }
}
