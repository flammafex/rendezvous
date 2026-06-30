import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes, concatBytes } from '@noble/hashes/utils';
import type { MatchToken, PublicKey, PrivateKey } from '../types.js';
import { isValidPrivateKey, isValidPublicKey } from '../types.js';
import { InvalidKeyError } from '../errors.js';

const MATCH_DOMAIN = 'matchlock-match-v1';
const encoder = new TextEncoder();

export function generateKeypair(): { publicKey: PublicKey; privateKey: PrivateKey } {
  const privateKey = randomBytes(32);
  return {
    publicKey: bytesToHex(x25519.getPublicKey(privateKey)) as PublicKey,
    privateKey: bytesToHex(privateKey) as PrivateKey,
  };
}

export function deriveMatchToken(myPrivateKey: PrivateKey, theirPublicKey: PublicKey, poolId: string): MatchToken {
  if (!isValidPrivateKey(myPrivateKey)) throw new InvalidKeyError('invalid private key');
  if (!isValidPublicKey(theirPublicKey)) throw new InvalidKeyError('invalid public key');
  const shared = x25519.scalarMult(hexToBytes(myPrivateKey), hexToBytes(theirPublicKey));
  const input = concatBytes(shared, encoder.encode(poolId), encoder.encode(MATCH_DOMAIN));
  return bytesToHex(sha256(input)) as MatchToken;
}

export function deriveMatchTokens(myPrivateKey: PrivateKey, theirPublicKeys: PublicKey[], poolId: string): MatchToken[] {
  return theirPublicKeys.map(pk => deriveMatchToken(myPrivateKey, pk, poolId));
}
