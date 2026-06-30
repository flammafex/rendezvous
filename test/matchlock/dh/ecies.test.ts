import { generateKeypair } from '../../../src/matchlock/dh/index.js';
import {
  encryptForPublicKey,
  decryptWithPrivateKey,
  serializeEncryptedBox,
  deserializeEncryptedBox,
} from '../../../src/matchlock/dh/ecies.js';
import type { PublicKey } from '../../../src/matchlock/types.js';

describe('ECIES', () => {
  it('encrypts and decrypts round-trip', () => {
    const { publicKey, privateKey } = generateKeypair();
    expect(decryptWithPrivateKey(encryptForPublicKey('hello matchlock', publicKey), privateKey)).toBe('hello matchlock');
  });

  it('produces different ciphertext each call', () => {
    const { publicKey } = generateKeypair();
    const box1 = encryptForPublicKey('same', publicKey);
    const box2 = encryptForPublicKey('same', publicKey);
    expect(box1.ciphertext).not.toBe(box2.ciphertext);
  });

  it('throws on tampered ciphertext', () => {
    const { publicKey, privateKey } = generateKeypair();
    const box = encryptForPublicKey('secret', publicKey);
    const tampered = { ...box, ciphertext: box.ciphertext.slice(0, -2) + (box.ciphertext.slice(-2) === 'ff' ? '00' : 'ff') };
    expect(() => decryptWithPrivateKey(tampered, privateKey)).toThrow();
  });

  it('throws with wrong private key', () => {
    const { publicKey } = generateKeypair();
    const { privateKey: wrongKey } = generateKeypair();
    expect(() => decryptWithPrivateKey(encryptForPublicKey('secret', publicKey), wrongKey)).toThrow();
  });

  it('serialize/deserialize round-trip', () => {
    const { publicKey, privateKey } = generateKeypair();
    const box = encryptForPublicKey('serialize me', publicKey);
    expect(decryptWithPrivateKey(deserializeEncryptedBox(serializeEncryptedBox(box)), privateKey)).toBe('serialize me');
  });

  // --- error paths ---

  it('deserializeEncryptedBox throws on invalid base64', () => {
    expect(() => deserializeEncryptedBox('not!valid!base64!!!')).toThrow('deserializeEncryptedBox');
  });

  it('deserializeEncryptedBox throws on valid base64 but missing fields', () => {
    const bad = btoa(JSON.stringify({ ephemeralPublicKey: 'abc' })); // missing nonce, ciphertext
    expect(() => deserializeEncryptedBox(bad)).toThrow('deserializeEncryptedBox');
  });

  it('deserializeEncryptedBox throws on non-object JSON', () => {
    expect(() => deserializeEncryptedBox(btoa('"just a string"'))).toThrow('deserializeEncryptedBox');
  });

  it('decryptWithPrivateKey throws on malformed ephemeralPublicKey hex', () => {
    const { privateKey } = generateKeypair();
    const { publicKey } = generateKeypair();
    const box = encryptForPublicKey('test', publicKey);
    expect(() => decryptWithPrivateKey({ ...box, ephemeralPublicKey: 'zzzz' }, privateKey)).toThrow();
  });

  it('encryptForPublicKey throws on malformed public key', () => {
    expect(() => encryptForPublicKey('test', 'not-valid-hex' as PublicKey)).toThrow();
  });

  it('handles empty plaintext', () => {
    const { publicKey, privateKey } = generateKeypair();
    expect(decryptWithPrivateKey(encryptForPublicKey('', publicKey), privateKey)).toBe('');
  });

  it('handles unicode plaintext', () => {
    const { publicKey, privateKey } = generateKeypair();
    const msg = '🔑 matchlock protocol ∞';
    expect(decryptWithPrivateKey(encryptForPublicKey(msg, publicKey), privateKey)).toBe(msg);
  });
});
