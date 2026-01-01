/**
 * Rendezvous Integration Tests
 *
 * Tests the full workflow: pool creation, submission, detection, discovery.
 */

import {
  Rendezvous,
  createTestRendezvous,
  generateKeypair,
  generateSigningKeypair,
  deriveMatchTokens,
  deriveNullifier,
  RendezvousError,
  RendezvousErrorCode,
} from '../src/rendezvous/index.js';

// Helper to create pool with required signing key
function createTestPool(rv: Rendezvous, name: string, options: {
  creatorPublicKey: string;
  description?: string;
  commitDeadline?: Date;
  revealDeadline?: Date;
  maxPreferencesPerParticipant?: number;
}) {
  const signingKeypair = generateSigningKeypair();
  return rv.createPool({
    name,
    description: options.description,
    creatorPublicKey: options.creatorPublicKey,
    creatorSigningKey: signingKeypair.signingPublicKey,
    commitDeadline: options.commitDeadline,
    revealDeadline: options.revealDeadline ?? new Date(Date.now() + 3600000),
    maxPreferencesPerParticipant: options.maxPreferencesPerParticipant,
  });
}

describe('Rendezvous Integration', () => {
  let rv: Rendezvous;

  beforeEach(() => {
    rv = createTestRendezvous();
  });

  afterEach(() => {
    rv.close();
  });

  describe('Pool Management', () => {
    it('should create a pool', () => {
      const creator = generateKeypair();
      const pool = createTestPool(rv, 'Test Pool', {
        description: 'A test matching pool',
        creatorPublicKey: creator.publicKey,
      });

      expect(pool.id).toBeDefined();
      expect(pool.name).toBe('Test Pool');
      expect(pool.status).toBe('open');
    });

    it('should create a pool with commit-reveal', () => {
      const creator = generateKeypair();
      const pool = createTestPool(rv, 'Commit-Reveal Pool', {
        creatorPublicKey: creator.publicKey,
        commitDeadline: new Date(Date.now() + 1800000),
        revealDeadline: new Date(Date.now() + 3600000),
      });

      expect(pool.status).toBe('commit');
      expect(pool.commitDeadline).toBeDefined();
    });

    it('should list pools', () => {
      const creator = generateKeypair();

      createTestPool(rv, 'Pool 1', { creatorPublicKey: creator.publicKey });
      createTestPool(rv, 'Pool 2', { creatorPublicKey: creator.publicKey });

      const pools = rv.listPools();
      expect(pools.length).toBe(2);
    });

    it('should close a pool', () => {
      const creator = generateKeypair();
      const pool = createTestPool(rv, 'Test Pool', {
        creatorPublicKey: creator.publicKey,
      });

      const closed = rv.closePool(pool.id);
      expect(closed.status).toBe('closed');
    });
  });

  describe('Preference Submission', () => {
    it('should submit preferences to an open pool', () => {
      const creator = generateKeypair();
      const participant = generateKeypair();
      const target = generateKeypair();

      const pool = createTestPool(rv, 'Test Pool', {
        creatorPublicKey: creator.publicKey,
      });

      const matchTokens = deriveMatchTokens(
        participant.privateKey,
        [target.publicKey],
        pool.id,
      );

      const nullifier = deriveNullifier(participant.privateKey, pool.id);

      const result = rv.submitPreferences({
        poolId: pool.id,
        matchTokens,
        nullifier,
      });

      expect(result.success).toBe(true);
      expect(result.phase).toBe('reveal');
      expect(result.preferenceIds.length).toBe(1);
    });

    it('should prevent duplicate submissions (nullifier check)', () => {
      const creator = generateKeypair();
      const participant = generateKeypair();
      const target = generateKeypair();

      const pool = createTestPool(rv, 'Test Pool', {
        creatorPublicKey: creator.publicKey,
      });

      const matchTokens = deriveMatchTokens(
        participant.privateKey,
        [target.publicKey],
        pool.id,
      );

      const nullifier = deriveNullifier(participant.privateKey, pool.id);

      // First submission
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens,
        nullifier,
      });

      // Second submission should fail
      expect(() => {
        rv.submitPreferences({
          poolId: pool.id,
          matchTokens,
          nullifier,
        });
      }).toThrow(RendezvousError);
    });

    it('should enforce preference limits', () => {
      const creator = generateKeypair();
      const participant = generateKeypair();
      const targets = Array.from({ length: 5 }, () => generateKeypair());

      const pool = createTestPool(rv, 'Limited Pool', {
        creatorPublicKey: creator.publicKey,
        maxPreferencesPerParticipant: 3,
      });

      const matchTokens = deriveMatchTokens(
        participant.privateKey,
        targets.map((t) => t.publicKey),
        pool.id,
      );

      const nullifier = deriveNullifier(participant.privateKey, pool.id);

      expect(() => {
        rv.submitPreferences({
          poolId: pool.id,
          matchTokens,
          nullifier,
        });
      }).toThrow(RendezvousError);
    });
  });

  describe('Match Detection', () => {
    it('should detect mutual matches', async () => {
      const creator = generateKeypair();
      const alice = generateKeypair();
      const bob = generateKeypair();

      const pool = createTestPool(rv, 'Match Test Pool', {
        creatorPublicKey: creator.publicKey,
      });

      // Alice selects Bob
      const aliceTokens = deriveMatchTokens(alice.privateKey, [bob.publicKey], pool.id);
      const aliceNullifier = deriveNullifier(alice.privateKey, pool.id);
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: aliceTokens,
        nullifier: aliceNullifier,
      });

      // Bob selects Alice
      const bobTokens = deriveMatchTokens(bob.privateKey, [alice.publicKey], pool.id);
      const bobNullifier = deriveNullifier(bob.privateKey, pool.id);
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: bobTokens,
        nullifier: bobNullifier,
      });

      // Close and detect
      rv.closePool(pool.id);
      const result = await rv.detectMatches(pool.id);

      expect(result.matchedTokens.length).toBe(1);
      // totalSubmissions includes decoy tokens (3-8 per submission)
      expect(result.totalSubmissions).toBeGreaterThanOrEqual(2);
      expect(result.uniqueParticipants).toBe(2);
    });

    it('should NOT detect unilateral selections as matches', async () => {
      const creator = generateKeypair();
      const alice = generateKeypair();
      const bob = generateKeypair();

      const pool = createTestPool(rv, 'Unilateral Test Pool', {
        creatorPublicKey: creator.publicKey,
      });

      // Alice selects Bob
      const aliceTokens = deriveMatchTokens(alice.privateKey, [bob.publicKey], pool.id);
      const aliceNullifier = deriveNullifier(alice.privateKey, pool.id);
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: aliceTokens,
        nullifier: aliceNullifier,
      });

      // Bob does NOT select Alice

      // Close and detect
      rv.closePool(pool.id);
      const result = await rv.detectMatches(pool.id);

      // Should be no matches since only Alice submitted
      expect(result.matchedTokens.length).toBe(0);
      // totalSubmissions includes decoy tokens
      expect(result.totalSubmissions).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Local Discovery', () => {
    it('should allow participants to discover their matches', async () => {
      const creator = generateKeypair();
      const alice = generateKeypair();
      const bob = generateKeypair();
      const charlie = generateKeypair();

      const pool = createTestPool(rv, 'Discovery Test Pool', {
        creatorPublicKey: creator.publicKey,
      });

      // Alice selects Bob and Charlie
      const aliceTokens = deriveMatchTokens(
        alice.privateKey,
        [bob.publicKey, charlie.publicKey],
        pool.id,
      );
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: aliceTokens,
        nullifier: deriveNullifier(alice.privateKey, pool.id),
      });

      // Bob selects Alice (MATCH)
      const bobTokens = deriveMatchTokens(bob.privateKey, [alice.publicKey], pool.id);
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: bobTokens,
        nullifier: deriveNullifier(bob.privateKey, pool.id),
      });

      // Charlie does NOT select Alice (NO MATCH)
      const charlieTokens = deriveMatchTokens(charlie.privateKey, [bob.publicKey], pool.id);
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: charlieTokens,
        nullifier: deriveNullifier(charlie.privateKey, pool.id),
      });

      // Close and detect
      rv.closePool(pool.id);
      await rv.detectMatches(pool.id);

      // Alice discovers her matches locally
      const aliceMatches = rv.discoverMyMatches(
        pool.id,
        alice.privateKey,
        [bob.publicKey, charlie.publicKey],
      );

      // Alice should only have matched with Bob
      expect(aliceMatches.length).toBe(1);
      expect(aliceMatches[0].matchedPublicKey).toBe(bob.publicKey);
    });

    it('should check individual matches', async () => {
      const creator = generateKeypair();
      const alice = generateKeypair();
      const bob = generateKeypair();

      const pool = createTestPool(rv, 'Check Test Pool', {
        creatorPublicKey: creator.publicKey,
      });

      // Mutual selection
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(alice.privateKey, [bob.publicKey], pool.id),
        nullifier: deriveNullifier(alice.privateKey, pool.id),
      });
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(bob.privateKey, [alice.publicKey], pool.id),
        nullifier: deriveNullifier(bob.privateKey, pool.id),
      });

      rv.closePool(pool.id);
      await rv.detectMatches(pool.id);

      // Check from Alice's perspective
      expect(rv.checkMatch(pool.id, alice.privateKey, bob.publicKey)).toBe(true);

      // Check from Bob's perspective
      expect(rv.checkMatch(pool.id, bob.privateKey, alice.publicKey)).toBe(true);
    });
  });

  describe('Complex Scenarios', () => {
    it('should handle large pools with multiple matches', async () => {
      const creator = generateKeypair();
      const pool = createTestPool(rv, 'Large Pool', {
        creatorPublicKey: creator.publicKey,
      });

      // Create 10 participants
      const participants = Array.from({ length: 10 }, () => generateKeypair());

      // 0 -> 1 (mutual)
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(participants[0].privateKey, [participants[1].publicKey], pool.id),
        nullifier: deriveNullifier(participants[0].privateKey, pool.id),
      });

      // 1 -> 0 (mutual)
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(participants[1].privateKey, [participants[0].publicKey], pool.id),
        nullifier: deriveNullifier(participants[1].privateKey, pool.id),
      });

      // 2 -> 3 (mutual)
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(participants[2].privateKey, [participants[3].publicKey], pool.id),
        nullifier: deriveNullifier(participants[2].privateKey, pool.id),
      });

      // 3 -> 2 (mutual)
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(participants[3].privateKey, [participants[2].publicKey], pool.id),
        nullifier: deriveNullifier(participants[3].privateKey, pool.id),
      });

      // 4 -> 5 (unilateral)
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(participants[4].privateKey, [participants[5].publicKey], pool.id),
        nullifier: deriveNullifier(participants[4].privateKey, pool.id),
      });

      // 5 -> 6 (not selecting 4)
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(participants[5].privateKey, [participants[6].publicKey], pool.id),
        nullifier: deriveNullifier(participants[5].privateKey, pool.id),
      });

      rv.closePool(pool.id);
      const result = await rv.detectMatches(pool.id);

      // Should have exactly 2 mutual matches
      expect(result.matchedTokens.length).toBe(2);
      expect(result.uniqueParticipants).toBe(6);
    });

    it('should support polyamorous configurations', async () => {
      const creator = generateKeypair();
      const pool = createTestPool(rv, 'Poly Pool', {
        creatorPublicKey: creator.publicKey,
      });

      // Three people all select each other
      const alice = generateKeypair();
      const bob = generateKeypair();
      const charlie = generateKeypair();

      // Alice selects Bob and Charlie
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(
          alice.privateKey,
          [bob.publicKey, charlie.publicKey],
          pool.id,
        ),
        nullifier: deriveNullifier(alice.privateKey, pool.id),
      });

      // Bob selects Alice and Charlie
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(
          bob.privateKey,
          [alice.publicKey, charlie.publicKey],
          pool.id,
        ),
        nullifier: deriveNullifier(bob.privateKey, pool.id),
      });

      // Charlie selects Alice and Bob
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(
          charlie.privateKey,
          [alice.publicKey, bob.publicKey],
          pool.id,
        ),
        nullifier: deriveNullifier(charlie.privateKey, pool.id),
      });

      rv.closePool(pool.id);
      const result = await rv.detectMatches(pool.id);

      // Should have 3 mutual matches: Alice-Bob, Alice-Charlie, Bob-Charlie
      expect(result.matchedTokens.length).toBe(3);

      // Each person should discover 2 matches
      const aliceMatches = rv.discoverMyMatches(
        pool.id,
        alice.privateKey,
        [bob.publicKey, charlie.publicKey],
      );
      expect(aliceMatches.length).toBe(2);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty pools', async () => {
      const creator = generateKeypair();
      const pool = createTestPool(rv, 'Empty Pool', {
        creatorPublicKey: creator.publicKey,
      });

      rv.closePool(pool.id);
      const result = await rv.detectMatches(pool.id);

      expect(result.matchedTokens.length).toBe(0);
      expect(result.totalSubmissions).toBe(0);
      expect(result.uniqueParticipants).toBe(0);
    });

    it('should handle single participant', async () => {
      const creator = generateKeypair();
      const pool = createTestPool(rv, 'Solo Pool', {
        creatorPublicKey: creator.publicKey,
      });

      const participant = generateKeypair();
      const target = generateKeypair();

      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(participant.privateKey, [target.publicKey], pool.id),
        nullifier: deriveNullifier(participant.privateKey, pool.id),
      });

      rv.closePool(pool.id);
      const result = await rv.detectMatches(pool.id);

      expect(result.matchedTokens.length).toBe(0);
      expect(result.uniqueParticipants).toBe(1);
    });

    it('should verify match integrity', async () => {
      const creator = generateKeypair();
      const alice = generateKeypair();
      const bob = generateKeypair();

      const pool = createTestPool(rv, 'Integrity Test Pool', {
        creatorPublicKey: creator.publicKey,
      });

      // Mutual selection
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(alice.privateKey, [bob.publicKey], pool.id),
        nullifier: deriveNullifier(alice.privateKey, pool.id),
      });
      rv.submitPreferences({
        poolId: pool.id,
        matchTokens: deriveMatchTokens(bob.privateKey, [alice.publicKey], pool.id),
        nullifier: deriveNullifier(bob.privateKey, pool.id),
      });

      rv.closePool(pool.id);
      await rv.detectMatches(pool.id);

      const verification = rv.verifyMatchIntegrity(pool.id);
      expect(verification.valid).toBe(true);
      expect(verification.errors.length).toBe(0);
    });
  });
});
