/**
 * Rendezvous - Private Mutual Matching
 * Match detection: count token occurrences, extract mutual matches
 *
 * Core algorithm:
 * 1. Count occurrences of each token in pool
 * 2. Tokens appearing exactly twice = mutual matches
 * 3. Store results with optional witness attestation
 */

import {
  MatchResult,
  DiscoveredMatch,
  Pool,
  MatchToken,
  PublicKey,
  PrivateKey,
  RendezvousError,
  RendezvousErrorCode,
} from './types.js';
import { RendezvousStore } from './storage.js';
import { PoolManager } from './pool.js';
import { deriveMatchToken } from './crypto.js';
import { WitnessAdapter } from './gates/types.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * Match detection handles finding mutual selections:
 * - Token counting after pool closes
 * - Extracting duplicates (mutual matches)
 * - Local discovery (participant-side match finding)
 */
export class MatchDetector {
  constructor(
    private store: RendezvousStore,
    private poolManager: PoolManager,
    private witness?: WitnessAdapter,
  ) {}

  /**
   * Detect matches in a closed pool.
   *
   * Tokens appearing exactly twice indicate mutual selection:
   * - Alice submitted H(DH(alice_priv, bob_pub) || pool || domain)
   * - Bob submitted H(DH(bob_priv, alice_pub) || pool || domain)
   * - Same token → mutual match!
   *
   * @param poolId - Pool ID to analyze
   * @returns Match result with all matched tokens
   */
  async detectMatches(poolId: string): Promise<MatchResult> {
    const pool = this.poolManager.requirePool(poolId);
    this.poolManager.updatePoolStatus(pool.id);

    // Pool must be closed for match detection
    if (!this.poolManager.isClosed(pool)) {
      throw new RendezvousError(
        RendezvousErrorCode.POOL_CLOSED,
        'Pool must be closed before detecting matches',
      );
    }

    // Check if we already have results
    const existingResult = this.store.getMatchResult(poolId);
    if (existingResult) {
      return existingResult;
    }

    // Count token occurrences
    const tokenCounts = this.store.countTokenOccurrences(poolId);

    // Extract tokens that appear exactly twice (mutual matches)
    const matchedTokens: MatchToken[] = [];
    for (const [token, count] of tokenCounts) {
      if (count === 2) {
        matchedTokens.push(token);
      }
    }

    // Count unique participants (by nullifier)
    const preferences = this.store.getPreferencesByPoolId(poolId);
    const uniqueNullifiers = new Set(preferences.map((p) => p.nullifier));

    // Create hash of the match data for witness attestation
    const matchDataHash = this.computeMatchDataHash(poolId, matchedTokens, uniqueNullifiers.size);

    // Get witness attestation if adapter is configured
    let witnessProof = undefined;
    if (this.witness) {
      witnessProof = await this.witness.attest(matchDataHash);
    }

    // Create result
    const result: MatchResult = {
      poolId,
      matchedTokens,
      totalSubmissions: preferences.filter((p) => p.revealed).length,
      uniqueParticipants: uniqueNullifiers.size,
      detectedAt: new Date(),
      witnessProof,
    };

    // Store result
    this.store.insertMatchResult(result);

    return result;
  }

  /**
   * Compute a hash of the match data for witness attestation.
   * This creates a deterministic commitment to the results.
   */
  private computeMatchDataHash(poolId: string, matchedTokens: MatchToken[], participantCount: number): string {
    const data = JSON.stringify({
      poolId,
      matchedTokens: matchedTokens.sort(), // Ensure deterministic ordering
      participantCount,
      version: 'rendezvous-v1',
    });
    return bytesToHex(sha256(new TextEncoder().encode(data)));
  }

  /**
   * Get previously computed match results for a pool.
   *
   * @param poolId - Pool ID
   * @returns Match result or undefined if not yet computed
   */
  getMatchResult(poolId: string): MatchResult | undefined {
    return this.store.getMatchResult(poolId);
  }

  /**
   * Discover which of my selections were mutual matches.
   *
   * This is a LOCAL computation performed by the participant.
   * It reveals which of your preferences were reciprocated without
   * telling the server which specific matches you found.
   *
   * @param poolId - Pool ID
   * @param myPrivateKey - My X25519 private key
   * @param selectedPublicKeys - Public keys I selected
   * @returns Array of discovered matches
   */
  discoverMyMatches(
    poolId: string,
    myPrivateKey: PrivateKey,
    selectedPublicKeys: PublicKey[],
  ): DiscoveredMatch[] {
    // Get match result for the pool
    const result = this.getMatchResult(poolId);
    if (!result) {
      throw new RendezvousError(
        RendezvousErrorCode.POOL_NOT_FOUND,
        'Match results not yet available for this pool',
      );
    }

    // Create a set of matched tokens for fast lookup
    const matchedTokenSet = new Set(result.matchedTokens);

    // Check each of my selections
    const discoveries: DiscoveredMatch[] = [];

    for (const theirPubKey of selectedPublicKeys) {
      // Derive the token I would have submitted
      const token = deriveMatchToken(myPrivateKey, theirPubKey, poolId);

      // If it's in the matched set, we have a mutual match!
      if (matchedTokenSet.has(token)) {
        discoveries.push({
          matchedPublicKey: theirPubKey,
          matchToken: token,
          poolId,
        });
      }
    }

    return discoveries;
  }

  /**
   * Check if a specific pair matched in a pool.
   *
   * This requires knowing both parties' keys, so it's typically
   * used by participants checking their own matches.
   *
   * @param poolId - Pool ID
   * @param myPrivateKey - My X25519 private key
   * @param theirPublicKey - Their X25519 public key
   * @returns True if mutual match exists
   */
  checkMatch(poolId: string, myPrivateKey: PrivateKey, theirPublicKey: PublicKey): boolean {
    const result = this.getMatchResult(poolId);
    if (!result) {
      return false;
    }

    const token = deriveMatchToken(myPrivateKey, theirPublicKey, poolId);
    return result.matchedTokens.includes(token);
  }

  /**
   * Get statistics about a pool's matches.
   *
   * @param poolId - Pool ID
   * @returns Match statistics
   */
  getMatchStats(poolId: string): MatchStats {
    const result = this.getMatchResult(poolId);
    const pool = this.poolManager.getPool(poolId);

    if (!result || !pool) {
      throw new RendezvousError(RendezvousErrorCode.POOL_NOT_FOUND, 'Pool or results not found');
    }

    const preferences = this.store.getPreferencesByPoolId(poolId);
    const revealed = preferences.filter((p) => p.revealed);
    const tokenCounts = this.store.countTokenOccurrences(poolId);

    // Count tokens by occurrence
    let singleOccurrences = 0;
    let doubleOccurrences = 0;
    let tripleOrMore = 0;

    for (const count of tokenCounts.values()) {
      if (count === 1) singleOccurrences++;
      else if (count === 2) doubleOccurrences++;
      else tripleOrMore++;
    }

    return {
      poolId,
      poolName: pool.name,
      totalParticipants: result.uniqueParticipants,
      totalPreferences: revealed.length,
      uniqueTokens: tokenCounts.size,
      mutualMatches: doubleOccurrences,
      unilateralSelections: singleOccurrences,
      anomalousTokens: tripleOrMore, // >2 occurrences (shouldn't happen normally)
      matchRate: result.uniqueParticipants > 0
        ? (doubleOccurrences * 2) / result.uniqueParticipants
        : 0,
      detectedAt: result.detectedAt,
    };
  }

  /**
   * Verify integrity of match detection results.
   *
   * Checks that:
   * - All matched tokens actually appear exactly twice
   * - No tokens appear more than twice
   * - Results are consistent with stored preferences
   *
   * @param poolId - Pool ID
   * @returns Verification result
   */
  verifyMatchIntegrity(poolId: string): VerificationResult {
    const result = this.getMatchResult(poolId);
    if (!result) {
      return { valid: false, errors: ['No match results found'] };
    }

    const errors: string[] = [];
    const tokenCounts = this.store.countTokenOccurrences(poolId);

    // Verify each matched token appears exactly twice
    for (const token of result.matchedTokens) {
      const count = tokenCounts.get(token);
      if (count !== 2) {
        errors.push(`Matched token ${token.substring(0, 16)}... has count ${count}, expected 2`);
      }
    }

    // Check for anomalies (tokens appearing > 2 times)
    for (const [token, count] of tokenCounts) {
      if (count > 2) {
        errors.push(
          `Token ${token.substring(0, 16)}... appears ${count} times (anomaly)`,
        );
      }
    }

    // Verify all tokens with count=2 are in matched list
    const matchedSet = new Set(result.matchedTokens);
    for (const [token, count] of tokenCounts) {
      if (count === 2 && !matchedSet.has(token)) {
        errors.push(`Token ${token.substring(0, 16)}... has count=2 but not in matched list`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      tokenCounts: Object.fromEntries(tokenCounts),
    };
  }
}

/**
 * Statistics about pool matches.
 */
export interface MatchStats {
  poolId: string;
  poolName: string;
  totalParticipants: number;
  totalPreferences: number;
  uniqueTokens: number;
  mutualMatches: number;
  unilateralSelections: number;
  anomalousTokens: number;
  matchRate: number;
  detectedAt: Date;
}

/**
 * Result of integrity verification.
 */
export interface VerificationResult {
  valid: boolean;
  errors: string[];
  tokenCounts?: Record<string, number>;
}
