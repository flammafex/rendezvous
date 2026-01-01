/**
 * PSI Module - Private Set Intersection for Rendezvous
 *
 * Enables private matching where:
 * - Pool owners never learn joiners' full preference sets
 * - Joiners learn only the intersection (mutual matches)
 * - Federation relays learn nothing (via Freebird tokens)
 */

export * from './types.js';
export * from './service.js';
