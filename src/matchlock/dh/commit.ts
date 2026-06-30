import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type { MatchToken, CommitHash } from '../types.js';
import { isValidMatchToken } from '../types.js';
import { InvalidTokenError } from '../errors.js';

export function commitToken(matchToken: MatchToken): CommitHash {
  if (!isValidMatchToken(matchToken)) throw new InvalidTokenError('invalid match token');
  // Hash the 32 raw bytes, not the 64-char hex encoding
  return bytesToHex(sha256(hexToBytes(matchToken))) as CommitHash;
}

export function commitTokens(matchTokens: MatchToken[]): CommitHash[] {
  return matchTokens.map(commitToken);
}

export function verifyCommitment(matchToken: MatchToken, commitHash: CommitHash): boolean {
  const computed = commitToken(matchToken);
  if (computed.length !== commitHash.length) return false;
  let result = 0;
  for (let i = 0; i < computed.length; i++) {
    result |= computed.charCodeAt(i) ^ commitHash.charCodeAt(i);
  }
  return result === 0;
}
