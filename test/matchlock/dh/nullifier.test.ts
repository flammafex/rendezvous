import { generateKeypair } from '../../../src/matchlock/dh/index.js';
import { deriveNullifier } from '../../../src/matchlock/dh/nullifier.js';
import type { PrivateKey, Nullifier } from '../../../src/matchlock/types.js';

describe('nullifier', () => {
  it('same key + same pool = same nullifier', () => {
    const { privateKey } = generateKeypair();
    expect(deriveNullifier(privateKey, 'pool-1')).toBe(deriveNullifier(privateKey, 'pool-1'));
  });

  it('same key + different pool = different nullifier', () => {
    const { privateKey } = generateKeypair();
    expect(deriveNullifier(privateKey, 'pool-1')).not.toBe(deriveNullifier(privateKey, 'pool-2'));
  });

  it('different keys + same pool = different nullifier', () => {
    const a = generateKeypair();
    const b = generateKeypair();
    expect(deriveNullifier(a.privateKey, 'pool-1')).not.toBe(deriveNullifier(b.privateKey, 'pool-1'));
  });

  it('nullifier is 64-char hex', () => {
    const { privateKey } = generateKeypair();
    expect(deriveNullifier(privateKey, 'pool-1')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('return value is branded Nullifier type (structural check)', () => {
    const { privateKey } = generateKeypair();
    const n: Nullifier = deriveNullifier(privateKey, 'pool-1');
    expect(typeof n).toBe('string');
  });

  // --- known-answer test (cross-implementation vector) ---

  it('produces correct nullifier for known private key (KAT)', () => {
    // Private key from RFC 7748 §6.1 (Alice's scalar)
    // Expected: SHA-256( priv_bytes || "test-pool" || "matchlock-nullifier-v1" )
    const priv = '77076d0a7318a57d3c16c17251b26645c6c2f6929f0a4b5745a0435c9b7bd30d' as PrivateKey;
    expect(deriveNullifier(priv, 'test-pool')).toBe(
      '9728a87b7ef7fb92a1438c557b5621c0c2f7c67e1d9847e8f6e31dd6e8e05d0c',
    );
  });

  // --- error paths ---

  it('throws on malformed private key hex', () => {
    expect(() => deriveNullifier('not-hex' as PrivateKey, 'pool-1')).toThrow();
  });

  it('throws on odd-length hex', () => {
    expect(() => deriveNullifier('abc' as PrivateKey, 'pool-1')).toThrow();
  });
});
