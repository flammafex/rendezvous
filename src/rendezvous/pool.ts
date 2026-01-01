/**
 * Rendezvous - Private Mutual Matching
 * Pool management: creation, status transitions, deadline enforcement
 */

import { v4 as uuidv4 } from 'uuid';
import {
  Pool,
  CreatePoolRequest,
  PoolStatus,
  PoolFilter,
  VoterGate,
  RendezvousError,
  RendezvousErrorCode,
} from './types.js';
import { RendezvousStore } from './storage.js';

/**
 * Pool manager handles pool lifecycle:
 * - Creation with eligibility gates
 * - Status transitions (open → commit → reveal → closed)
 * - Deadline enforcement
 */
export class PoolManager {
  constructor(private store: RendezvousStore) {}

  /**
   * Create a new matching pool.
   *
   * @param request - Pool creation parameters
   * @returns The created pool
   */
  createPool(request: CreatePoolRequest): Pool {
    this.validateCreateRequest(request);

    const now = new Date();

    // Default to invite-list gate with creator as the first allowed key
    // This ensures pools are invitation-based by default (like Clout)
    const defaultGate: VoterGate = {
      type: 'invite-list',
      allowedKeys: [request.creatorPublicKey],
    };

    const pool: Pool = {
      id: uuidv4(),
      name: request.name,
      description: request.description,
      creatorPublicKey: request.creatorPublicKey,
      creatorSigningKey: request.creatorSigningKey,
      commitDeadline: request.commitDeadline,
      revealDeadline: request.revealDeadline,
      eligibilityGate: request.eligibilityGate || defaultGate,
      maxPreferencesPerParticipant: request.maxPreferencesPerParticipant,
      ephemeral: request.ephemeral,
      requiresInviteToJoin: request.requiresInviteToJoin,
      status: this.determineInitialStatus(request),
      createdAt: now,
      updatedAt: now,
    };

    this.store.insertPool(pool);
    return pool;
  }

  /**
   * Get a pool by ID.
   *
   * @param id - Pool ID
   * @returns The pool or undefined if not found
   */
  getPool(id: string): Pool | undefined {
    return this.store.getPool(id);
  }

  /**
   * Get a pool by ID, throwing if not found.
   *
   * @param id - Pool ID
   * @returns The pool
   * @throws RendezvousError if pool not found
   */
  requirePool(id: string): Pool {
    const pool = this.getPool(id);
    if (!pool) {
      throw new RendezvousError(RendezvousErrorCode.POOL_NOT_FOUND, `Pool not found: ${id}`);
    }
    return pool;
  }

  /**
   * List pools with optional filters.
   *
   * @param filter - Filter options
   * @returns Array of matching pools
   */
  listPools(filter?: PoolFilter): Pool[] {
    return this.store.getPools(filter);
  }

  /**
   * Get the current effective status of a pool based on deadlines.
   * This may differ from the stored status if deadlines have passed.
   *
   * @param pool - The pool to check
   * @returns Current effective status
   */
  getEffectiveStatus(pool: Pool): PoolStatus {
    const now = new Date();

    // Already closed
    if (pool.status === 'closed') {
      return 'closed';
    }

    // Check if reveal deadline passed
    if (now >= pool.revealDeadline) {
      return 'closed';
    }

    // Check commit deadline if present
    if (pool.commitDeadline) {
      if (now >= pool.commitDeadline) {
        return 'reveal';
      }
      return 'commit';
    }

    // No commit phase - pool is open until reveal deadline
    return 'open';
  }

  /**
   * Update pool status based on deadlines.
   * Call this periodically or before operations to keep status current.
   *
   * @param poolId - Pool ID to update
   * @returns Updated pool
   */
  updatePoolStatus(poolId: string): Pool {
    const pool = this.requirePool(poolId);
    const effectiveStatus = this.getEffectiveStatus(pool);

    if (pool.status !== effectiveStatus) {
      this.store.updatePoolStatus(poolId, effectiveStatus);
      pool.status = effectiveStatus;
      pool.updatedAt = new Date();
    }

    return pool;
  }

  /**
   * Check if pool accepts commits (in commit phase).
   *
   * @param pool - Pool to check
   * @returns True if commits are accepted
   */
  acceptsCommits(pool: Pool): boolean {
    const status = this.getEffectiveStatus(pool);
    return status === 'commit';
  }

  /**
   * Check if pool accepts reveals (in reveal phase or open without commit phase).
   *
   * @param pool - Pool to check
   * @returns True if reveals/direct submissions are accepted
   */
  acceptsReveals(pool: Pool): boolean {
    const status = this.getEffectiveStatus(pool);
    // Open pools without commit phase accept direct submissions
    // Reveal phase accepts reveals
    return status === 'open' || status === 'reveal';
  }

  /**
   * Check if pool is closed and ready for match detection.
   *
   * @param pool - Pool to check
   * @returns True if pool is closed
   */
  isClosed(pool: Pool): boolean {
    const status = this.getEffectiveStatus(pool);
    return status === 'closed';
  }

  /**
   * Manually close a pool (admin action).
   *
   * @param poolId - Pool ID to close
   * @returns Updated pool
   */
  closePool(poolId: string): Pool {
    const pool = this.requirePool(poolId);
    this.store.updatePoolStatus(poolId, 'closed');
    pool.status = 'closed';
    pool.updatedAt = new Date();
    return pool;
  }

  /**
   * Get time remaining until next phase transition.
   *
   * @param pool - Pool to check
   * @returns Object with phase info and time remaining in ms
   */
  getPhaseInfo(pool: Pool): PhaseInfo {
    const now = new Date();
    const status = this.getEffectiveStatus(pool);

    switch (status) {
      case 'commit':
        return {
          currentPhase: 'commit',
          nextPhase: 'reveal',
          deadline: pool.commitDeadline!,
          remainingMs: pool.commitDeadline!.getTime() - now.getTime(),
        };

      case 'open':
      case 'reveal':
        return {
          currentPhase: status,
          nextPhase: 'closed',
          deadline: pool.revealDeadline,
          remainingMs: pool.revealDeadline.getTime() - now.getTime(),
        };

      case 'closed':
        return {
          currentPhase: 'closed',
          nextPhase: null,
          deadline: pool.revealDeadline,
          remainingMs: 0,
        };
    }
  }

  /**
   * Check if a pool has a commit phase.
   *
   * @param pool - Pool to check
   * @returns True if pool uses commit-reveal
   */
  hasCommitPhase(pool: Pool): boolean {
    return pool.commitDeadline !== undefined;
  }

  // Private methods

  private validateCreateRequest(request: CreatePoolRequest): void {
    if (!request.name || request.name.trim().length === 0) {
      throw new RendezvousError(RendezvousErrorCode.INVALID_INPUT, 'Pool name is required');
    }

    if (request.name.length > 200) {
      throw new RendezvousError(RendezvousErrorCode.INVALID_INPUT, 'Pool name too long (max 200 chars)');
    }

    if (!request.creatorPublicKey) {
      throw new RendezvousError(RendezvousErrorCode.INVALID_INPUT, 'Creator public key is required');
    }

    if (!request.creatorSigningKey) {
      throw new RendezvousError(RendezvousErrorCode.INVALID_INPUT, 'Creator signing key is required');
    }

    if (!request.revealDeadline) {
      throw new RendezvousError(RendezvousErrorCode.INVALID_INPUT, 'Reveal deadline is required');
    }

    const now = new Date();
    if (request.revealDeadline <= now) {
      throw new RendezvousError(RendezvousErrorCode.INVALID_INPUT, 'Reveal deadline must be in the future');
    }

    if (request.commitDeadline) {
      if (request.commitDeadline <= now) {
        throw new RendezvousError(
          RendezvousErrorCode.INVALID_INPUT,
          'Commit deadline must be in the future',
        );
      }

      if (request.commitDeadline >= request.revealDeadline) {
        throw new RendezvousError(
          RendezvousErrorCode.INVALID_INPUT,
          'Commit deadline must be before reveal deadline',
        );
      }
    }

    if (request.maxPreferencesPerParticipant !== undefined) {
      if (request.maxPreferencesPerParticipant < 1) {
        throw new RendezvousError(
          RendezvousErrorCode.INVALID_INPUT,
          'Max preferences must be at least 1',
        );
      }
    }

    if (request.eligibilityGate) {
      this.validateGate(request.eligibilityGate);
    }
  }

  private validateGate(gate: VoterGate): void {
    switch (gate.type) {
      case 'open':
        break;

      case 'invite-list':
        if (!gate.allowedKeys || gate.allowedKeys.length === 0) {
          throw new RendezvousError(
            RendezvousErrorCode.INVALID_INPUT,
            'Invite list gate requires at least one allowed key',
          );
        }
        break;

      case 'freebird':
        if (!gate.issuerId) {
          throw new RendezvousError(
            RendezvousErrorCode.INVALID_INPUT,
            'Freebird gate requires issuer ID',
          );
        }
        break;

      case 'composite':
        if (!gate.gates || gate.gates.length === 0) {
          throw new RendezvousError(
            RendezvousErrorCode.INVALID_INPUT,
            'Composite gate requires at least one sub-gate',
          );
        }
        for (const subGate of gate.gates) {
          this.validateGate(subGate);
        }
        break;
    }
  }

  private determineInitialStatus(request: CreatePoolRequest): PoolStatus {
    // If commit deadline is set, start in commit phase
    if (request.commitDeadline) {
      return 'commit';
    }
    // Otherwise, start as open (direct submissions)
    return 'open';
  }
}

/**
 * Information about a pool's current phase.
 */
export interface PhaseInfo {
  currentPhase: PoolStatus;
  nextPhase: PoolStatus | null;
  deadline: Date;
  remainingMs: number;
}
