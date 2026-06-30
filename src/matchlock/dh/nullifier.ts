import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';
import type { PrivateKey, Nullifier } from '../types.js';
import { isValidPrivateKey } from '../types.js';
import { InvalidKeyError } from '../errors.js';

const NULLIFIER_DOMAIN = 'matchlock-nullifier-v1';
const encoder = new TextEncoder();

export function deriveNullifier(privateKey: PrivateKey, poolId: string): Nullifier {
  if (!isValidPrivateKey(privateKey)) throw new InvalidKeyError('invalid private key');
  const input = concatBytes(hexToBytes(privateKey), encoder.encode(poolId), encoder.encode(NULLIFIER_DOMAIN));
  return bytesToHex(sha256(input)) as Nullifier;
}
