import {
  isValidPublicKey,
  isValidPrivateKey,
  isValidMatchToken,
  isValidCommitHash,
  isValidNullifier,
} from '../../../src/matchlock/types.js';
import { isValidSigningPublicKey, isValidSignature } from '../../../src/matchlock/dh/signing.js';

const VALID_64 = 'a'.repeat(64);
const VALID_128 = 'a'.repeat(128);

describe('isValidPublicKey', () => {
  it('accepts valid lowercase hex', () => expect(isValidPublicKey(VALID_64)).toBe(true));
  it('accepts valid uppercase hex', () => expect(isValidPublicKey('A'.repeat(64))).toBe(true));
  it('accepts mixed case hex', () => expect(isValidPublicKey('aAbBcCdD'.repeat(8))).toBe(true));
  it('rejects too short', () => expect(isValidPublicKey('a'.repeat(63))).toBe(false));
  it('rejects too long', () => expect(isValidPublicKey('a'.repeat(65))).toBe(false));
  it('rejects non-hex chars', () => expect(isValidPublicKey('g'.repeat(64))).toBe(false));
  it('rejects empty string', () => expect(isValidPublicKey('')).toBe(false));
});

describe('isValidPrivateKey', () => {
  it('accepts valid lowercase hex', () => expect(isValidPrivateKey(VALID_64)).toBe(true));
  it('accepts valid uppercase hex', () => expect(isValidPrivateKey('B'.repeat(64))).toBe(true));
  it('rejects too short', () => expect(isValidPrivateKey('a'.repeat(63))).toBe(false));
  it('rejects too long', () => expect(isValidPrivateKey('a'.repeat(65))).toBe(false));
  it('rejects non-hex chars', () => expect(isValidPrivateKey('z'.repeat(64))).toBe(false));
  it('rejects empty string', () => expect(isValidPrivateKey('')).toBe(false));
});

describe('isValidMatchToken', () => {
  it('accepts valid hex', () => expect(isValidMatchToken(VALID_64)).toBe(true));
  it('accepts uppercase hex', () => expect(isValidMatchToken('F'.repeat(64))).toBe(true));
  it('rejects wrong length', () => expect(isValidMatchToken('a'.repeat(32))).toBe(false));
  it('rejects non-hex', () => expect(isValidMatchToken('x'.repeat(64))).toBe(false));
});

describe('isValidCommitHash', () => {
  it('accepts valid hex', () => expect(isValidCommitHash(VALID_64)).toBe(true));
  it('rejects wrong length', () => expect(isValidCommitHash('a'.repeat(63))).toBe(false));
  it('rejects non-hex', () => expect(isValidCommitHash('!'.repeat(64))).toBe(false));
});

describe('isValidNullifier', () => {
  it('accepts valid hex', () => expect(isValidNullifier(VALID_64)).toBe(true));
  it('rejects wrong length', () => expect(isValidNullifier('a'.repeat(65))).toBe(false));
  it('rejects non-hex', () => expect(isValidNullifier(' '.repeat(64))).toBe(false));
});

describe('isValidSigningPublicKey', () => {
  it('accepts valid lowercase hex', () => expect(isValidSigningPublicKey(VALID_64)).toBe(true));
  it('accepts uppercase hex', () => expect(isValidSigningPublicKey('C'.repeat(64))).toBe(true));
  it('rejects too short', () => expect(isValidSigningPublicKey('a'.repeat(63))).toBe(false));
  it('rejects too long', () => expect(isValidSigningPublicKey('a'.repeat(65))).toBe(false));
  it('rejects non-hex', () => expect(isValidSigningPublicKey('p'.repeat(64))).toBe(false));
  it('rejects empty string', () => expect(isValidSigningPublicKey('')).toBe(false));
});

describe('isValidSignature', () => {
  it('accepts valid 128-char hex', () => expect(isValidSignature(VALID_128)).toBe(true));
  it('accepts uppercase hex', () => expect(isValidSignature('D'.repeat(128))).toBe(true));
  it('rejects 64-char hex (too short)', () => expect(isValidSignature(VALID_64)).toBe(false));
  it('rejects 130-char hex (too long)', () => expect(isValidSignature('a'.repeat(130))).toBe(false));
  it('rejects non-hex', () => expect(isValidSignature('z'.repeat(128))).toBe(false));
  it('rejects empty string', () => expect(isValidSignature('')).toBe(false));
});
