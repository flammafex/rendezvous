/**
 * Rendezvous - Private Mutual Matching
 * Gate types for eligibility checking
 *
 * Gates determine who can participate in a pool.
 * Ported from Prestige's voter gate system.
 */

import { PublicKey, VoterGate, FreebirdProof } from '../types.js';

/**
 * Context for gate evaluation.
 * Contains information about the participant and pool.
 */
export interface GateContext {
  /** Participant's public key (if known) */
  participantKey?: PublicKey;

  /** Freebird proof for unlinkable eligibility */
  freebirdProof?: FreebirdProof;

  /** Pool ID for context-specific checks */
  poolId: string;

  /** Additional metadata from external services */
  metadata?: Record<string, unknown>;
}

/**
 * Result of gate evaluation.
 */
export interface GateResult {
  /** Whether the gate check passed */
  eligible: boolean;

  /** Human-readable reason for the result */
  reason: string;

  /** Additional details about the check */
  details?: Record<string, unknown>;
}

/**
 * Interface for gate evaluators.
 * Each gate type has a corresponding evaluator.
 */
export interface GateEvaluator {
  /**
   * Evaluate eligibility against this gate.
   *
   * @param gate - Gate configuration
   * @param context - Evaluation context
   * @returns Gate result
   */
  evaluate(gate: VoterGate, context: GateContext): Promise<GateResult>;

  /**
   * Check if this evaluator handles the given gate type.
   *
   * @param gate - Gate configuration
   * @returns True if this evaluator handles the gate type
   */
  handles(gate: VoterGate): boolean;
}

/**
 * Adapter interface for Freebird proof verification.
 */
export interface FreebirdAdapter {
  /**
   * Verify a Freebird proof.
   *
   * @param proof - Freebird proof to verify
   * @returns True if proof is valid
   */
  verify(proof: FreebirdProof): Promise<boolean>;

  /**
   * Check if proof is expired.
   *
   * @param proof - Freebird proof
   * @returns True if expired
   */
  isExpired(proof: FreebirdProof): boolean;
}

/**
 * Adapter interface for Witness timestamp attestation.
 */
export interface WitnessAdapter {
  /**
   * Create a witness attestation for data.
   *
   * @param data - Data to attest (hash of match results)
   * @param freebirdProof - Optional Freebird token for Sybil resistance
   * @returns Witness proof with timestamp and signatures
   */
  attest(data: string, freebirdProof?: FreebirdProof): Promise<WitnessProof>;

  /**
   * Verify a witness attestation.
   *
   * @param proof - Witness proof to verify
   * @param data - Original data that was attested
   * @returns True if proof is valid
   */
  verify(proof: WitnessProof, data: string): Promise<boolean>;
}

import { WitnessProof } from '../types.js';
