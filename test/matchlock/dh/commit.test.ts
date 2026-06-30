import { generateKeypair, deriveMatchToken } from '../../../src/matchlock/dh/index.js';
import { commitToken, commitTokens, verifyCommitment } from '../../../src/matchlock/dh/commit.js';
import type { MatchToken } from '../../../src/matchlock/types.js';

describe('commit-reveal', () => {
  it('commitment is deterministic', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    expect(commitToken(token)).toBe(commitToken(token));
  });

  it('commitment differs from the token itself', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    expect(commitToken(token)).not.toBe(token);
  });

  it('verifyCommitment accepts correct token', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    expect(verifyCommitment(token, commitToken(token))).toBe(true);
  });

  it('verifyCommitment rejects wrong token', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const carol = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    const wrongToken = deriveMatchToken(alice.privateKey, carol.publicKey, 'pool-1');
    expect(verifyCommitment(wrongToken, commitToken(token))).toBe(false);
  });

  it('commitTokens returns one commitment per token', () => {
    const alice = generateKeypair();
    const others = [generateKeypair(), generateKeypair()];
    const tokens = others.map(k => deriveMatchToken(alice.privateKey, k.publicKey, 'pool-1'));
    const commits = commitTokens(tokens);
    expect(commits).toHaveLength(2);
    commits.forEach(c => expect(c).toMatch(/^[0-9a-f]{64}$/));
  });

  it('hashes raw bytes not hex string (known vector)', () => {
    // 32 zero bytes hex-encoded
    const zeroToken = '00'.repeat(32) as unknown as MatchToken;
    const commit = commitToken(zeroToken);
    // Must match SHA-256 of 32 zero bytes, not SHA-256 of the ASCII string '000...0'
    expect(commit).toHaveLength(64);
    // Sanity: commitment of all-zeros token should be a known value
    // SHA-256(32 zero bytes) = 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
    expect(commit).toBe('66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925');
  });

  // --- error paths ---

  it('throws on malformed token hex', () => {
    expect(() => commitToken('not-valid-hex' as unknown as MatchToken)).toThrow();
  });

  it('verifyCommitment rejects manipulated commitment (bit flip)', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    const commit = commitToken(token);
    const flipped = (commit[0] === 'a' ? 'b' : 'a') + commit.slice(1);
    expect(verifyCommitment(token, flipped as typeof commit)).toBe(false);
  });

  it('mutual-token commitments match for both parties', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const aliceToken = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    const bobToken = deriveMatchToken(bob.privateKey, alice.publicKey, 'pool-1');
    expect(commitToken(aliceToken)).toBe(commitToken(bobToken));
  });
});
