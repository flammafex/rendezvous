import { generateSigningKeypair, sign, verify, createSignedRequest, verifySignedRequest } from '../../../src/matchlock/dh/signing.js';
import type { SigningPrivateKey, SigningPublicKey, Signature } from '../../../src/matchlock/dh/signing.js';

describe('Ed25519 signing', () => {
  it('sign + verify round-trip', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    expect(verify('hello', sign('hello', signingPrivateKey), signingPublicKey)).toBe(true);
  });

  it('verify rejects wrong message', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    expect(verify('world', sign('hello', signingPrivateKey), signingPublicKey)).toBe(false);
  });

  it('verify rejects wrong key', () => {
    const { signingPrivateKey } = generateSigningKeypair();
    const { signingPublicKey: wrongPub } = generateSigningKeypair();
    expect(verify('hello', sign('hello', signingPrivateKey), wrongPub)).toBe(false);
  });

  it('createSignedRequest + verifySignedRequest round-trip', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const { signature, timestamp } = createSignedRequest('psi-setup', 'pool-1', signingPrivateKey);
    expect(verifySignedRequest('psi-setup', 'pool-1', signature, timestamp, signingPublicKey)).toBe(true);
  });

  it('verifySignedRequest rejects stale timestamp', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const staleTimestamp = Date.now() - 10 * 60 * 1000;
    expect(verifySignedRequest('psi-setup', 'pool-1', sign(`psi-setup:pool-1:${staleTimestamp}`, signingPrivateKey), staleTimestamp, signingPublicKey)).toBe(false);
  });

  // --- known-answer test (cross-implementation vector) ---

  it('produces correct signature for known private key (KAT)', () => {
    // Fixed private key; message is a realistic signed-request payload with a fixed timestamp.
    // Expected: ed25519.sign( SHA-256( "matchlock-sign-v1" || message ), priv )
    const sigPriv = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55' as SigningPrivateKey;
    const sigPub  = '700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41' as SigningPublicKey;
    const message = 'psi-setup:test-pool:1700000000000';
    const sig = sign(message, sigPriv);
    expect(sig).toBe(
      '5da3e36456cd5ad371048aa66d494832d5e5d28f34400c1a0d604e09a017c4e5' +
      '2dde6c80c3326962420a5b7aa480bd6e4f0412aaae45170612165b8c4e149b01',
    );
    expect(verify(message, sig, sigPub)).toBe(true);
  });

  // --- error paths ---

  it('verify returns false (not throw) on malformed signature hex', () => {
    const { signingPublicKey } = generateSigningKeypair();
    expect(verify('hello', 'not-valid-hex' as Signature, signingPublicKey)).toBe(false);
  });

  it('verify returns false on malformed public key hex', () => {
    const { signingPrivateKey } = generateSigningKeypair();
    const sig = sign('hello', signingPrivateKey);
    expect(verify('hello', sig, 'not-valid-hex' as SigningPublicKey)).toBe(false);
  });

  it('verify rejects tampered signature (single byte flip)', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const sig = sign('hello', signingPrivateKey);
    const tampered = sig.slice(0, -2) + (sig.slice(-2) === 'ff' ? '00' : 'ff') as Signature;
    expect(verify('hello', tampered, signingPublicKey)).toBe(false);
  });

  it('sign throws on malformed private key hex', () => {
    expect(() => sign('hello', 'not-hex' as SigningPrivateKey)).toThrow();
  });

  it('signatures differ across keys', () => {
    const { signingPrivateKey: k1 } = generateSigningKeypair();
    const { signingPrivateKey: k2 } = generateSigningKeypair();
    expect(sign('msg', k1)).not.toBe(sign('msg', k2));
  });

  it('verifySignedRequest rejects wrong action', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const { signature, timestamp } = createSignedRequest('psi-setup', 'pool-1', signingPrivateKey);
    expect(verifySignedRequest('psi-join', 'pool-1', signature, timestamp, signingPublicKey)).toBe(false);
  });

  it('verifySignedRequest rejects wrong pool', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const { signature, timestamp } = createSignedRequest('psi-setup', 'pool-1', signingPrivateKey);
    expect(verifySignedRequest('psi-setup', 'pool-2', signature, timestamp, signingPublicKey)).toBe(false);
  });
});
