/**
 * Rendezvous Crypto Tests
 *
 * Critical test: Both parties must derive the same match token.
 * This is the core property that makes mutual matching work.
 */

import {
  generateKeypair,
  deriveMatchToken,
  deriveMatchTokens,
  commitToken,
  commitTokens,
  verifyCommitment,
  deriveNullifier,
  randomHex,
  hash,
  constantTimeEqual,
  isValidPublicKey,
  isValidPrivateKey,
  isValidMatchToken,
} from '../src/rendezvous/crypto.js';

describe('Crypto Module', () => {
  describe('generateKeypair', () => {
    it('should generate valid keypairs', () => {
      const keypair = generateKeypair();

      expect(keypair.publicKey).toHaveLength(64);
      expect(keypair.privateKey).toHaveLength(64);
      expect(isValidPublicKey(keypair.publicKey)).toBe(true);
      expect(isValidPrivateKey(keypair.privateKey)).toBe(true);
    });

    it('should generate unique keypairs', () => {
      const keypair1 = generateKeypair();
      const keypair2 = generateKeypair();

      expect(keypair1.publicKey).not.toBe(keypair2.publicKey);
      expect(keypair1.privateKey).not.toBe(keypair2.privateKey);
    });
  });

  describe('deriveMatchToken - CRITICAL TEST', () => {
    it('should derive the SAME token for both parties (mutual selection)', () => {
      // Alice and Bob both want to match with each other
      const alice = generateKeypair();
      const bob = generateKeypair();
      const poolId = 'test-pool-123';

      // Alice derives token for Bob
      const aliceToken = deriveMatchToken(alice.privateKey, bob.publicKey, poolId);

      // Bob derives token for Alice
      const bobToken = deriveMatchToken(bob.privateKey, alice.publicKey, poolId);

      // CRITICAL: Both tokens MUST be identical
      expect(aliceToken).toBe(bobToken);
      expect(aliceToken).toHaveLength(64); // SHA-256 hex
    });

    it('should derive DIFFERENT tokens for different pools', () => {
      const alice = generateKeypair();
      const bob = generateKeypair();

      const token1 = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
      const token2 = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-2');

      expect(token1).not.toBe(token2);
    });

    it('should derive DIFFERENT tokens for different parties', () => {
      const alice = generateKeypair();
      const bob = generateKeypair();
      const charlie = generateKeypair();
      const poolId = 'test-pool';

      const tokenBob = deriveMatchToken(alice.privateKey, bob.publicKey, poolId);
      const tokenCharlie = deriveMatchToken(alice.privateKey, charlie.publicKey, poolId);

      expect(tokenBob).not.toBe(tokenCharlie);
    });

    it('should work with multiple selections', () => {
      const alice = generateKeypair();
      const bob = generateKeypair();
      const charlie = generateKeypair();
      const poolId = 'test-pool';

      // Alice selects both Bob and Charlie
      const aliceTokens = deriveMatchTokens(
        alice.privateKey,
        [bob.publicKey, charlie.publicKey],
        poolId,
      );

      // Bob selects Alice
      const bobToken = deriveMatchToken(bob.privateKey, alice.publicKey, poolId);

      // Charlie does NOT select Alice (no token generated)

      // Alice-Bob should match
      expect(aliceTokens[0]).toBe(bobToken);

      // Alice-Charlie would only match if Charlie also selected Alice
      // The token exists but won't appear twice in the pool
    });
  });

  describe('Commit-Reveal Scheme', () => {
    it('should create valid commitments', () => {
      const token = randomHex(32);
      const commitment = commitToken(token);

      expect(commitment).toHaveLength(64);
      expect(isValidMatchToken(commitment)).toBe(true);
    });

    it('should verify correct commitments', () => {
      const token = randomHex(32);
      const commitment = commitToken(token);

      expect(verifyCommitment(token, commitment)).toBe(true);
    });

    it('should reject incorrect commitments', () => {
      const token1 = randomHex(32);
      const token2 = randomHex(32);
      const commitment = commitToken(token1);

      expect(verifyCommitment(token2, commitment)).toBe(false);
    });

    it('should handle multiple commitments', () => {
      const tokens = [randomHex(32), randomHex(32), randomHex(32)];
      const commitments = commitTokens(tokens);

      expect(commitments).toHaveLength(3);
      for (let i = 0; i < tokens.length; i++) {
        expect(verifyCommitment(tokens[i], commitments[i])).toBe(true);
      }
    });
  });

  describe('Nullifiers', () => {
    it('should derive deterministic nullifiers', () => {
      const keypair = generateKeypair();
      const poolId = 'test-pool';

      const nullifier1 = deriveNullifier(keypair.privateKey, poolId);
      const nullifier2 = deriveNullifier(keypair.privateKey, poolId);

      expect(nullifier1).toBe(nullifier2);
      expect(nullifier1).toHaveLength(64);
    });

    it('should derive different nullifiers for different pools', () => {
      const keypair = generateKeypair();

      const nullifier1 = deriveNullifier(keypair.privateKey, 'pool-1');
      const nullifier2 = deriveNullifier(keypair.privateKey, 'pool-2');

      expect(nullifier1).not.toBe(nullifier2);
    });

    it('should derive different nullifiers for different participants', () => {
      const alice = generateKeypair();
      const bob = generateKeypair();
      const poolId = 'test-pool';

      const aliceNullifier = deriveNullifier(alice.privateKey, poolId);
      const bobNullifier = deriveNullifier(bob.privateKey, poolId);

      expect(aliceNullifier).not.toBe(bobNullifier);
    });
  });

  describe('Utility Functions', () => {
    it('should generate random hex of specified length', () => {
      const hex16 = randomHex(16);
      const hex32 = randomHex(32);

      expect(hex16).toHaveLength(32); // 16 bytes = 32 hex chars
      expect(hex32).toHaveLength(64); // 32 bytes = 64 hex chars
    });

    it('should hash data consistently', () => {
      const data = 'test data';
      const hash1 = hash(data);
      const hash2 = hash(data);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });

    it('should perform constant-time comparison', () => {
      const a = 'abcdef123456';
      const b = 'abcdef123456';
      const c = 'abcdef123457';

      expect(constantTimeEqual(a, b)).toBe(true);
      expect(constantTimeEqual(a, c)).toBe(false);
      expect(constantTimeEqual(a, 'short')).toBe(false);
    });
  });

  describe('Key Validation', () => {
    it('should validate correct public keys', () => {
      const keypair = generateKeypair();
      expect(isValidPublicKey(keypair.publicKey)).toBe(true);
    });

    it('should reject invalid public keys', () => {
      expect(isValidPublicKey('')).toBe(false);
      expect(isValidPublicKey('not-hex')).toBe(false);
      expect(isValidPublicKey('abc123')).toBe(false);
      expect(isValidPublicKey('a'.repeat(63))).toBe(false); // Too short
      expect(isValidPublicKey('a'.repeat(65))).toBe(false); // Too long
    });

    it('should validate correct private keys', () => {
      const keypair = generateKeypair();
      expect(isValidPrivateKey(keypair.privateKey)).toBe(true);
    });

    it('should validate correct match tokens', () => {
      const token = randomHex(32);
      expect(isValidMatchToken(token)).toBe(true);
    });
  });
});

describe('End-to-End Mutual Matching', () => {
  it('should correctly identify mutual matches in a simulated pool', () => {
    // Simulate a pool with 5 participants
    const participants = Array.from({ length: 5 }, () => generateKeypair());
    const poolId = 'e2e-test-pool';

    // Define selections (who selects whom)
    // Alice (0) selects Bob (1) and Charlie (2)
    // Bob (1) selects Alice (0) - MUTUAL with Alice
    // Charlie (2) selects Diana (3) - NOT mutual with Alice
    // Diana (3) selects Alice (0) - NOT mutual (Alice didn't select Diana)
    // Eve (4) selects Bob (1) - NOT mutual (Bob didn't select Eve)

    const selections: Record<number, number[]> = {
      0: [1, 2],      // Alice -> Bob, Charlie
      1: [0],         // Bob -> Alice
      2: [3],         // Charlie -> Diana
      3: [0],         // Diana -> Alice
      4: [1],         // Eve -> Bob
    };

    // Generate all tokens
    const allTokens: string[] = [];
    for (const [fromIdx, toIndices] of Object.entries(selections)) {
      const from = participants[parseInt(fromIdx)];
      for (const toIdx of toIndices) {
        const to = participants[toIdx];
        const token = deriveMatchToken(from.privateKey, to.publicKey, poolId);
        allTokens.push(token);
      }
    }

    // Count token occurrences (simulating server-side detection)
    const tokenCounts = new Map<string, number>();
    for (const token of allTokens) {
      tokenCounts.set(token, (tokenCounts.get(token) || 0) + 1);
    }

    // Find tokens that appear exactly twice (mutual matches)
    const matchedTokens = Array.from(tokenCounts.entries())
      .filter(([_, count]) => count === 2)
      .map(([token, _]) => token);

    // Verify: Only Alice-Bob should be a mutual match
    expect(matchedTokens.length).toBe(1);

    // Verify Alice can discover the match locally
    const aliceDiscoveredTokens = deriveMatchTokens(
      participants[0].privateKey,
      [participants[1].publicKey, participants[2].publicKey], // Bob, Charlie
      poolId,
    );

    // Alice's token for Bob should be in matched set
    expect(matchedTokens.includes(aliceDiscoveredTokens[0])).toBe(true);

    // Alice's token for Charlie should NOT be in matched set
    expect(matchedTokens.includes(aliceDiscoveredTokens[1])).toBe(false);
  });

  it('should support polyamorous matching (multiple mutual matches)', () => {
    // All three participants mutually select each other
    const alice = generateKeypair();
    const bob = generateKeypair();
    const charlie = generateKeypair();
    const poolId = 'poly-pool';

    // Everyone selects everyone else
    const tokens = [
      // Alice's selections
      deriveMatchToken(alice.privateKey, bob.publicKey, poolId),
      deriveMatchToken(alice.privateKey, charlie.publicKey, poolId),
      // Bob's selections
      deriveMatchToken(bob.privateKey, alice.publicKey, poolId),
      deriveMatchToken(bob.privateKey, charlie.publicKey, poolId),
      // Charlie's selections
      deriveMatchToken(charlie.privateKey, alice.publicKey, poolId),
      deriveMatchToken(charlie.privateKey, bob.publicKey, poolId),
    ];

    // Count occurrences
    const counts = new Map<string, number>();
    for (const token of tokens) {
      counts.set(token, (counts.get(token) || 0) + 1);
    }

    // Should have exactly 3 mutual matches (Alice-Bob, Alice-Charlie, Bob-Charlie)
    const matchedTokens = Array.from(counts.entries())
      .filter(([_, count]) => count === 2)
      .map(([token, _]) => token);

    expect(matchedTokens.length).toBe(3);

    // Each participant should discover 2 matches
    const aliceMatches = deriveMatchTokens(
      alice.privateKey,
      [bob.publicKey, charlie.publicKey],
      poolId,
    ).filter((t) => matchedTokens.includes(t));

    expect(aliceMatches.length).toBe(2);
  });
});
