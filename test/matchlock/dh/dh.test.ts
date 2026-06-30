import { generateKeypair, deriveMatchToken, deriveMatchTokens } from '../../../src/matchlock/dh/index.js';
import type { PublicKey, PrivateKey } from '../../../src/matchlock/types.js';
import { InvalidKeyError } from '../../../src/matchlock/errors.js';

describe('DH token derivation', () => {
  it('mutual selection produces equal tokens', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const poolId = 'pool-1';
    const aliceToken = deriveMatchToken(alice.privateKey, bob.publicKey, poolId);
    const bobToken = deriveMatchToken(bob.privateKey, alice.publicKey, poolId);
    expect(aliceToken).toBe(bobToken);
  });

  it('unilateral selection produces different tokens', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const carol = generateKeypair();
    const aliceSelectsBob = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    const bobSelectsCarol = deriveMatchToken(bob.privateKey, carol.publicKey, 'pool-1');
    expect(aliceSelectsBob).not.toBe(bobSelectsCarol);
  });

  it('tokens are pool-scoped', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token1 = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-a');
    const token2 = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-b');
    expect(token1).not.toBe(token2);
  });

  it('deriveMatchTokens returns one token per public key', () => {
    const alice = generateKeypair();
    const others = [generateKeypair(), generateKeypair(), generateKeypair()];
    const tokens = deriveMatchTokens(alice.privateKey, others.map(k => k.publicKey), 'pool-1');
    expect(tokens).toHaveLength(3);
    tokens.forEach(t => expect(t).toMatch(/^[0-9a-f]{64}$/));
  });

  it('tokens are 64-char hex strings', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    expect(deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1')).toMatch(/^[0-9a-f]{64}$/);
  });

  // --- error paths ---

  it('throws InvalidKeyError on malformed private key hex', () => {
    const { publicKey } = generateKeypair();
    expect(() => deriveMatchToken('not-valid-hex' as PrivateKey, publicKey, 'pool-1')).toThrow(InvalidKeyError);
  });

  it('throws InvalidKeyError on malformed public key hex', () => {
    const { privateKey } = generateKeypair();
    expect(() => deriveMatchToken(privateKey, 'zzzz' as PublicKey, 'pool-1')).toThrow(InvalidKeyError);
  });

  it('throws InvalidKeyError on odd-length hex private key', () => {
    const { publicKey } = generateKeypair();
    expect(() => deriveMatchToken('abc' as PrivateKey, publicKey, 'pool-1')).toThrow(InvalidKeyError);
  });

  // --- known-answer test (cross-implementation vector) ---

  it('produces correct token for RFC 7748 X25519 test vectors (KAT)', () => {
    // Private keys from RFC 7748 §6.1; public keys derived deterministically.
    // Expected token computed by this implementation — pin it to catch domain/hash regressions.
    const alicePriv = '77076d0a7318a57d3c16c17251b26645c6c2f6929f0a4b5745a0435c9b7bd30d' as PrivateKey;
    const bobPub    = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f' as PublicKey;
    const token = deriveMatchToken(alicePriv, bobPub, 'test-pool');
    // SHA-256( X25519(alice_priv, bob_pub) || "test-pool" || "matchlock-match-v1" )
    expect(token).toBe('bbfee0cd9a72d348a1a4dafee9ad8c055f02c79e0d341ff4aa425583030492bf');
  });

  // --- commutativity property with multiple key pairs ---

  it('commutativity holds for multiple fresh key pairs', () => {
    for (let i = 0; i < 5; i++) {
      const a = generateKeypair();
      const b = generateKeypair();
      expect(deriveMatchToken(a.privateKey, b.publicKey, 'pool-x')).toBe(
        deriveMatchToken(b.privateKey, a.publicKey, 'pool-x'),
      );
    }
  });
});
