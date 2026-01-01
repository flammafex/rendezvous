/**
 * Rendezvous - Private Mutual Matching
 * Gate evaluation system
 *
 * Evaluates eligibility gates to determine who can participate in a pool.
 * Supports gate types: open, invite-list, freebird, composite.
 */

import {
  VoterGate,
  OpenGate,
  InviteListGate,
  FreebirdGate,
  CompositeGate,
  FreebirdProof,
  WitnessProof,
} from '../types.js';
import {
  GateContext,
  GateResult,
  GateEvaluator,
  FreebirdAdapter,
  WitnessAdapter,
} from './types.js';

export * from './types.js';

/**
 * Main gate evaluator that delegates to type-specific evaluators.
 */
export class GateSystem {
  private evaluators: GateEvaluator[] = [];

  constructor(private freebird?: FreebirdAdapter) {
    // Register built-in evaluators
    this.evaluators.push(new OpenGateEvaluator());
    this.evaluators.push(new InviteListGateEvaluator());
    this.evaluators.push(new FreebirdGateEvaluator(freebird));
    this.evaluators.push(new CompositeGateEvaluator(this));
  }

  /**
   * Evaluate a gate with the given context.
   *
   * @param gate - Gate configuration
   * @param context - Evaluation context
   * @returns Gate result
   */
  async evaluate(gate: VoterGate, context: GateContext): Promise<GateResult> {
    // Verify Freebird proof if provided
    if (context.freebirdProof && this.freebird) {
      const proofValid = await this.freebird.verify(context.freebirdProof);
      if (!proofValid) {
        return {
          eligible: false,
          reason: 'Invalid Freebird proof',
        };
      }

      if (this.freebird.isExpired(context.freebirdProof)) {
        return {
          eligible: false,
          reason: 'Freebird proof expired',
        };
      }
    }

    // Find appropriate evaluator
    const evaluator = this.evaluators.find((e) => e.handles(gate));
    if (!evaluator) {
      return {
        eligible: false,
        reason: `Unknown gate type: ${gate.type}`,
      };
    }

    return evaluator.evaluate(gate, context);
  }

  /**
   * Register a custom gate evaluator.
   *
   * @param evaluator - Evaluator to register
   */
  registerEvaluator(evaluator: GateEvaluator): void {
    this.evaluators.push(evaluator);
  }
}

/**
 * Evaluator for open gates - always allows participation.
 */
class OpenGateEvaluator implements GateEvaluator {
  handles(gate: VoterGate): boolean {
    return gate.type === 'open';
  }

  async evaluate(_gate: VoterGate, _context: GateContext): Promise<GateResult> {
    return {
      eligible: true,
      reason: 'Open gate - all participants eligible',
    };
  }
}

/**
 * Evaluator for invite-list gates - checks if key is in allowed list.
 */
class InviteListGateEvaluator implements GateEvaluator {
  handles(gate: VoterGate): boolean {
    return gate.type === 'invite-list';
  }

  async evaluate(gate: VoterGate, context: GateContext): Promise<GateResult> {
    const inviteGate = gate as InviteListGate;

    if (!context.participantKey) {
      return {
        eligible: false,
        reason: 'Participant key required for invite-list gate',
      };
    }

    const isAllowed = inviteGate.allowedKeys.includes(context.participantKey);

    return {
      eligible: isAllowed,
      reason: isAllowed ? 'Key found in invite list' : 'Key not in invite list',
      details: {
        allowedCount: inviteGate.allowedKeys.length,
      },
    };
  }
}

/**
 * Evaluator for Freebird gates - requires valid token from specified issuer.
 */
class FreebirdGateEvaluator implements GateEvaluator {
  constructor(private freebird?: FreebirdAdapter) {}

  handles(gate: VoterGate): boolean {
    return gate.type === 'freebird';
  }

  async evaluate(gate: VoterGate, context: GateContext): Promise<GateResult> {
    const freebirdGate = gate as FreebirdGate;

    if (!this.freebird) {
      return {
        eligible: false,
        reason: 'Freebird adapter not configured',
      };
    }

    if (!context.freebirdProof) {
      return {
        eligible: false,
        reason: 'Freebird token required for this pool',
        details: {
          issuerId: freebirdGate.issuerId,
        },
      };
    }

    // Check issuer matches
    if (context.freebirdProof.issuerId !== freebirdGate.issuerId) {
      return {
        eligible: false,
        reason: `Token must be from issuer: ${freebirdGate.issuerId}`,
        details: {
          expectedIssuerId: freebirdGate.issuerId,
          providedIssuerId: context.freebirdProof.issuerId,
        },
      };
    }

    // Check expiration
    if (this.freebird.isExpired(context.freebirdProof)) {
      return {
        eligible: false,
        reason: 'Freebird token has expired',
      };
    }

    // Verify with Freebird service
    try {
      const isValid = await this.freebird.verify(context.freebirdProof);
      if (isValid) {
        return {
          eligible: true,
          reason: 'Valid Freebird token',
          details: {
            issuerId: freebirdGate.issuerId,
          },
        };
      } else {
        return {
          eligible: false,
          reason: 'Invalid Freebird token',
        };
      }
    } catch (error) {
      return {
        eligible: false,
        reason: `Freebird verification failed: ${error}`,
      };
    }
  }
}

/**
 * Evaluator for composite gates - combines multiple gates with AND/OR logic.
 */
class CompositeGateEvaluator implements GateEvaluator {
  constructor(private gateSystem: GateSystem) {}

  handles(gate: VoterGate): boolean {
    return gate.type === 'composite';
  }

  async evaluate(gate: VoterGate, context: GateContext): Promise<GateResult> {
    const compositeGate = gate as CompositeGate;

    if (compositeGate.gates.length === 0) {
      return {
        eligible: false,
        reason: 'Composite gate has no sub-gates',
      };
    }

    const results: GateResult[] = [];

    for (const subGate of compositeGate.gates) {
      const result = await this.gateSystem.evaluate(subGate, context);
      results.push(result);

      // Short-circuit evaluation
      if (compositeGate.operator === 'and' && !result.eligible) {
        return {
          eligible: false,
          reason: `AND gate failed: ${result.reason}`,
          details: {
            operator: 'and',
            failedGate: subGate.type,
            results: results.map((r) => ({ eligible: r.eligible, reason: r.reason })),
          },
        };
      }

      if (compositeGate.operator === 'or' && result.eligible) {
        return {
          eligible: true,
          reason: `OR gate passed: ${result.reason}`,
          details: {
            operator: 'or',
            passedGate: subGate.type,
            results: results.map((r) => ({ eligible: r.eligible, reason: r.reason })),
          },
        };
      }
    }

    // Final result based on operator
    if (compositeGate.operator === 'and') {
      return {
        eligible: true,
        reason: 'All AND sub-gates passed',
        details: {
          operator: 'and',
          results: results.map((r) => ({ eligible: r.eligible, reason: r.reason })),
        },
      };
    } else {
      return {
        eligible: false,
        reason: 'No OR sub-gates passed',
        details: {
          operator: 'or',
          results: results.map((r) => ({ eligible: r.eligible, reason: r.reason })),
        },
      };
    }
  }
}

// ============================================================================
// Mock Adapters for Testing
// ============================================================================

/**
 * Mock Freebird adapter for testing.
 */
export class MockFreebirdAdapter implements FreebirdAdapter {
  private validProofs = new Set<string>();

  addValidProof(proof: FreebirdProof): void {
    this.validProofs.add(proof.tokenValue);
  }

  async verify(proof: FreebirdProof): Promise<boolean> {
    return this.validProofs.has(proof.tokenValue);
  }

  isExpired(proof: FreebirdProof): boolean {
    return Date.now() > proof.expiration;
  }
}

/**
 * Mock Witness adapter for testing.
 * In production, this would connect to an actual Witness service.
 */
export class MockWitnessAdapter implements WitnessAdapter {
  private attestations = new Map<string, WitnessProof>();
  private sequence = 0;

  async attest(data: string): Promise<WitnessProof> {
    const proof: WitnessProof = {
      hash: data,
      timestamp: Math.floor(Date.now() / 1000),
      networkId: 'mock-network',
      sequence: this.sequence++,
      signatures: [{
        witnessId: 'mock-witness-1',
        signature: 'mock-signature-' + Date.now(),
      }],
    };
    this.attestations.set(data, proof);
    return proof;
  }

  async verify(proof: WitnessProof, data: string): Promise<boolean> {
    // In production, verify signatures against known witness keys
    const sigCount = Array.isArray(proof.signatures)
      ? proof.signatures.length
      : proof.signatures.signers.length;
    return proof.hash === data && sigCount > 0;
  }
}
