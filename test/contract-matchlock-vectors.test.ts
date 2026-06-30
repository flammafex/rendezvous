/**
 * Contract conformance test for the Rendezvous -> Matchlock seam.
 *
 * Rendezvous exposes Matchlock crypto through src/rendezvous/crypto.ts. This
 * test pins that facade to the root sophia/v1 Matchlock known-answer vectors so
 * token, commitment, and nullifier derivation cannot drift silently.
 */

import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  commitToken,
  deriveMatchToken,
  deriveMatchTokens,
  deriveNullifier,
} from '../src/rendezvous/index.js';

interface MatchlockVectors {
  contract_version: string;
  artifact_type: string;
  token_derivation: {
    alice_priv: string;
    alice_pub: string;
    bob_priv: string;
    bob_pub: string;
    pool_id: string;
    token: string;
  };
  commitment: {
    token_bytes: string;
    commitment: string;
  };
  nullifier: {
    priv_key: string;
    pool_id: string;
    nullifier: string;
  };
}

function loadVectors(): MatchlockVectors {
  const contractsDir = process.env.SOPHIADOS_CONTRACTS_DIR
    ?? resolve(process.cwd(), '../sophiados/contracts');
  const vectorPath = resolve(contractsDir, 'vectors/matchlock-vectors.json');
  return JSON.parse(readFileSync(vectorPath, 'utf8')) as MatchlockVectors;
}

describe('Sophia contract: Rendezvous Matchlock vectors', () => {
  const vectors = loadVectors();

  it('loads the canonical sophia/v1 Matchlock vector set', () => {
    expect(vectors.contract_version).toBe('sophia/v1');
    expect(vectors.artifact_type).toBe('vectors.matchlock');
  });

  it('derives the canonical mutual match token in both directions', () => {
    const { alice_priv, alice_pub, bob_priv, bob_pub, pool_id, token } = vectors.token_derivation;

    expect(deriveMatchToken(alice_priv, bob_pub, pool_id)).toBe(token);
    expect(deriveMatchToken(bob_priv, alice_pub, pool_id)).toBe(token);
    expect(deriveMatchTokens(alice_priv, [bob_pub], pool_id)).toEqual([token]);
  });

  it('commits to raw token bytes, not the token hex string', () => {
    expect(commitToken(vectors.commitment.token_bytes)).toBe(vectors.commitment.commitment);
  });

  it('derives the canonical pool-scoped nullifier', () => {
    expect(deriveNullifier(vectors.nullifier.priv_key, vectors.nullifier.pool_id)).toBe(
      vectors.nullifier.nullifier,
    );
  });
});
