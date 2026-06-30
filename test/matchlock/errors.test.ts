import { deriveMatchToken, deriveMatchTokens } from '../../src/matchlock/dh/index.js';
import { commitToken } from '../../src/matchlock/dh/commit.js';
import { deriveNullifier } from '../../src/matchlock/dh/nullifier.js';
import { encryptForPublicKey, decryptWithPrivateKey } from '../../src/matchlock/dh/ecies.js';
import { generateKeypair } from '../../src/matchlock/dh/index.js';
import { MatchlockError, InvalidKeyError, InvalidTokenError, DecryptionError } from '../../src/matchlock/errors.js';
import type { PrivateKey, PublicKey, MatchToken } from '../../src/matchlock/types.js';

const BAD_KEY = 'not-valid-hex' as PrivateKey;
const BAD_PUB = 'zzzz' as PublicKey;
const BAD_TOKEN = 'short' as MatchToken;

describe('typed errors', () => {
  describe('deriveMatchToken', () => {
    it('throws InvalidKeyError on bad private key', () => {
      const { publicKey } = generateKeypair();
      expect(() => deriveMatchToken(BAD_KEY, publicKey, 'pool')).toThrow(InvalidKeyError);
    });

    it('throws InvalidKeyError on bad public key', () => {
      const { privateKey } = generateKeypair();
      expect(() => deriveMatchToken(privateKey, BAD_PUB, 'pool')).toThrow(InvalidKeyError);
    });

    it('InvalidKeyError has correct code', () => {
      const { publicKey } = generateKeypair();
      try {
        deriveMatchToken(BAD_KEY, publicKey, 'pool');
      } catch (e) {
        expect(e).toBeInstanceOf(InvalidKeyError);
        expect((e as InvalidKeyError).code).toBe('INVALID_KEY');
      }
    });

    it('InvalidKeyError is instanceof MatchlockError', () => {
      const { publicKey } = generateKeypair();
      expect(() => deriveMatchToken(BAD_KEY, publicKey, 'pool')).toThrow(MatchlockError);
    });
  });

  describe('deriveMatchTokens', () => {
    it('throws InvalidKeyError on bad private key', () => {
      const { publicKey } = generateKeypair();
      expect(() => deriveMatchTokens(BAD_KEY, [publicKey], 'pool')).toThrow(InvalidKeyError);
    });
  });

  describe('commitToken', () => {
    it('throws InvalidTokenError on bad token', () => {
      expect(() => commitToken(BAD_TOKEN)).toThrow(InvalidTokenError);
    });

    it('InvalidTokenError has correct code', () => {
      try {
        commitToken(BAD_TOKEN);
      } catch (e) {
        expect(e).toBeInstanceOf(InvalidTokenError);
        expect((e as InvalidTokenError).code).toBe('INVALID_TOKEN');
      }
    });

    it('InvalidTokenError is instanceof MatchlockError', () => {
      expect(() => commitToken(BAD_TOKEN)).toThrow(MatchlockError);
    });
  });

  describe('deriveNullifier', () => {
    it('throws InvalidKeyError on bad key', () => {
      expect(() => deriveNullifier(BAD_KEY, 'pool')).toThrow(InvalidKeyError);
    });

    it('InvalidKeyError is instanceof MatchlockError', () => {
      expect(() => deriveNullifier(BAD_KEY, 'pool')).toThrow(MatchlockError);
    });
  });

  describe('encryptForPublicKey', () => {
    it('throws InvalidKeyError on bad public key', () => {
      expect(() => encryptForPublicKey('hello', BAD_PUB)).toThrow(InvalidKeyError);
    });

    it('InvalidKeyError is instanceof MatchlockError', () => {
      expect(() => encryptForPublicKey('hello', BAD_PUB)).toThrow(MatchlockError);
    });
  });

  describe('decryptWithPrivateKey', () => {
    it('throws InvalidKeyError on bad private key', () => {
      const { publicKey } = generateKeypair();
      const box = encryptForPublicKey('hello', publicKey);
      expect(() => decryptWithPrivateKey(box, BAD_KEY)).toThrow(InvalidKeyError);
    });

    it('throws DecryptionError on tampered ciphertext', () => {
      const { publicKey, privateKey } = generateKeypair();
      const box = encryptForPublicKey('hello', publicKey);
      // Flip a byte in the ciphertext
      const tampered = { ...box, ciphertext: box.ciphertext.slice(0, -2) + '00' };
      expect(() => decryptWithPrivateKey(tampered, privateKey)).toThrow(DecryptionError);
    });

    it('DecryptionError has correct code', () => {
      const { publicKey, privateKey } = generateKeypair();
      const box = encryptForPublicKey('hello', publicKey);
      const tampered = { ...box, ciphertext: box.ciphertext.slice(0, -2) + '00' };
      try {
        decryptWithPrivateKey(tampered, privateKey);
      } catch (e) {
        expect(e).toBeInstanceOf(DecryptionError);
        expect((e as DecryptionError).code).toBe('DECRYPTION_FAILED');
      }
    });

    it('DecryptionError is instanceof MatchlockError', () => {
      const { publicKey, privateKey } = generateKeypair();
      const box = encryptForPublicKey('hello', publicKey);
      const tampered = { ...box, ciphertext: box.ciphertext.slice(0, -2) + '00' };
      expect(() => decryptWithPrivateKey(tampered, privateKey)).toThrow(MatchlockError);
    });
  });

  describe('error .name properties', () => {
    it('MatchlockError has correct name', () => {
      const e = new MatchlockError('test', 'TEST');
      expect(e.name).toBe('MatchlockError');
    });

    it('InvalidKeyError has correct name', () => {
      const e = new InvalidKeyError('test');
      expect(e.name).toBe('InvalidKeyError');
    });

    it('InvalidTokenError has correct name', () => {
      const e = new InvalidTokenError('test');
      expect(e.name).toBe('InvalidTokenError');
    });

    it('DecryptionError has correct name', () => {
      const e = new DecryptionError('test');
      expect(e.name).toBe('DecryptionError');
    });
  });
});
