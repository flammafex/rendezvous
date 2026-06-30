/**
 * Live service seam for Rendezvous.
 *
 * This file is intentionally outside the default Jest testMatch. Run it with
 * `npm run test:live` while Freebird and Witness are available.
 */

import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  GateSystem,
  Rendezvous,
  deriveMatchToken,
  deriveNullifier,
  type FreebirdProof,
} from '../src/rendezvous/index.js';
import { HttpFreebirdAdapter } from '../src/rendezvous/adapters/freebird.js';
import { HttpWitnessAdapter } from '../src/rendezvous/adapters/witness.js';

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
}

const serviceUrls = {
  freebirdIssuer: process.env.FREEBIRD_ISSUER_URL ?? 'http://127.0.0.1:18081',
  freebirdVerifier: process.env.FREEBIRD_VERIFIER_URL ?? 'http://127.0.0.1:18082',
  witness: process.env.WITNESS_GATEWAY_URL ?? 'http://127.0.0.1:18080',
};

function loadVectors(): MatchlockVectors {
  const contractsDir = process.env.SOPHIADOS_CONTRACTS_DIR
    ?? resolve(process.cwd(), '../sophiados/contracts');
  const vectorPath = resolve(contractsDir, 'vectors/matchlock-vectors.json');
  return JSON.parse(readFileSync(vectorPath, 'utf8')) as MatchlockVectors;
}

function loadFreebirdToken(): string {
  const tokenFile = process.env.FREEBIRD_TOKEN_FILE;
  if (!tokenFile) {
    throw new Error('FREEBIRD_TOKEN_FILE is required for the Rendezvous live seam');
  }

  const raw = JSON.parse(readFileSync(tokenFile, 'utf8')) as {
    token_b64?: unknown;
    tokenValue?: unknown;
    token?: unknown;
  };
  const token = raw.token_b64 ?? raw.tokenValue ?? raw.token;
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error(`Freebird token file ${tokenFile} must contain token_b64`);
  }
  return token;
}

async function fetchIssuerId(): Promise<string> {
  const response = await fetch(`${serviceUrls.freebirdIssuer}/.well-known/issuer`);
  if (!response.ok) {
    throw new Error(`Freebird issuer metadata failed: ${response.status}`);
  }

  const body = await response.json() as { issuer_id?: unknown; issuerId?: unknown };
  const issuerId = body.issuer_id ?? body.issuerId;
  if (typeof issuerId !== 'string' || issuerId.length === 0) {
    throw new Error('Freebird issuer metadata must include issuer_id');
  }
  return issuerId;
}

function expectCanonicalWitness(proof: {
  hash: string;
  networkId: string;
  sequence: number;
  canonical?: any;
}) {
  expect(proof.canonical).toMatchObject({
    contract_version: 'sophia/v1',
    artifact_type: 'witness.signed_attestation',
  });
  expect(proof.canonical.attestation).toMatchObject({
    hash: proof.hash,
    network_id: proof.networkId,
    sequence: proof.sequence,
  });
  expect(['multisig', 'aggregated']).toContain(
    proof.canonical.signatures.kind
  );
}

describe('Rendezvous live service seam', () => {
  jest.setTimeout(30000);

  let rendezvous: Rendezvous | null = null;

  afterEach(() => {
    rendezvous?.close();
    rendezvous = null;
  });

  it('accepts one live Freebird V4 proof through the Freebird gate', async () => {
    const issuerId = await fetchIssuerId();
    const proof: FreebirdProof = {
      tokenValue: loadFreebirdToken(),
      issuerId,
      expiration: Date.now() + 60 * 60 * 1000,
    };

    const gateSystem = new GateSystem(new HttpFreebirdAdapter({
      verifierUrl: serviceUrls.freebirdVerifier,
    }));

    await expect(gateSystem.evaluate(
      { type: 'freebird', issuerId },
      { poolId: 'rendezvous-live-freebird', freebirdProof: proof },
    )).resolves.toMatchObject({
      eligible: true,
    });
  });

  it('detects a Matchlock mutual match and timestamps the result through live Witness', async () => {
    const vectors = loadVectors();
    const { alice_priv, alice_pub, bob_priv, bob_pub, pool_id, token } = vectors.token_derivation;

    expect(vectors.contract_version).toBe('sophia/v1');
    expect(vectors.artifact_type).toBe('vectors.matchlock');
    expect(deriveMatchToken(alice_priv, bob_pub, pool_id)).toBe(token);
    expect(deriveMatchToken(bob_priv, alice_pub, pool_id)).toBe(token);

    const witness = new HttpWitnessAdapter({ gatewayUrl: serviceUrls.witness });
    rendezvous = new Rendezvous({ witness });

    const pool = rendezvous.createPool({
      name: 'Rendezvous live seam',
      creatorPublicKey: alice_pub,
      creatorSigningKey: 'rendezvous-live-seam-creator',
      revealDeadline: new Date(Date.now() + 60 * 1000),
      eligibilityGate: { type: 'open' },
      maxPreferencesPerParticipant: 2,
    });

    rendezvous.registerParticipant({
      poolId: pool.id,
      publicKey: alice_pub,
      displayName: 'Alice',
    });
    rendezvous.registerParticipant({
      poolId: pool.id,
      publicKey: bob_pub,
      displayName: 'Bob',
    });

    const aliceToken = deriveMatchToken(alice_priv, bob_pub, pool.id);
    const bobToken = deriveMatchToken(bob_priv, alice_pub, pool.id);
    expect(aliceToken).toBe(bobToken);

    const aliceSubmission = rendezvous.submitPreferences({
      poolId: pool.id,
      matchTokens: [aliceToken],
      nullifier: deriveNullifier(alice_priv, pool.id),
    });
    const bobSubmission = rendezvous.submitPreferences({
      poolId: pool.id,
      matchTokens: [bobToken],
      nullifier: deriveNullifier(bob_priv, pool.id),
    });

    expect(aliceSubmission.success).toBe(true);
    expect(bobSubmission.success).toBe(true);

    rendezvous.closePool(pool.id);
    const result = await rendezvous.detectMatches(pool.id);

    expect(result.matchedTokens).toContain(aliceToken);
    expect(result.uniqueParticipants).toBe(2);
    expect(result.witnessProof).toBeDefined();
    expect(result.witnessProof?.networkId).toBe('sophia-smoke-network');
    expect(result.witnessProof?.hash).toMatch(/^[0-9a-f]{64}$/);
    expectCanonicalWitness(result.witnessProof!);
    await expect(witness.verify(result.witnessProof!, result.witnessProof!.hash)).resolves.toBe(true);

    const integrity = rendezvous.verifyMatchIntegrity(pool.id);
    expect(integrity.valid).toBe(true);

    const discoveries = rendezvous.discoverMyMatches(pool.id, alice_priv, [bob_pub]);
    expect(discoveries).toEqual([
      expect.objectContaining({
        matchedPublicKey: bob_pub,
        matchToken: aliceToken,
        poolId: pool.id,
      }),
    ]);
  });
});
