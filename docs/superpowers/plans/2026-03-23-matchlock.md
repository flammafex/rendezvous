# Matchlock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the DH mutual-match primitive from Rendezvous into a standalone TypeScript library (`~/dev/matchlock/`), then update Rendezvous to consume it as a dependency.

**Architecture:** New sibling repo at `~/dev/matchlock/` with two modules: `dh/` (X25519 token derivation, hardened ECIES, Ed25519 signing) and `psi/` (owner-held key PSI). Rendezvous drops its local `crypto.ts` and `psi/` directory and imports from `matchlock` instead.

**Tech Stack:** TypeScript ESM, `@noble/curves`, `@noble/hashes`, `@noble/ciphers` (XChaCha20-Poly1305), `@openmined/psi.js` (WASM), Jest + ts-jest ESM preset.

---

## File Map

### New repo: `~/dev/matchlock/`

| File | Purpose |
|------|---------|
| `src/types.ts` | Primitive types: MatchToken, CommitHash, PublicKey, PrivateKey |
| `src/dh/index.ts` | deriveMatchToken, deriveMatchTokens, generateKeypair |
| `src/dh/commit.ts` | commitToken, commitTokens, verifyCommitment |
| `src/dh/nullifier.ts` | deriveNullifier |
| `src/dh/ecies.ts` | EncryptedBox, encryptForPublicKey, decryptWithPrivateKey, serialize/deserialize (XChaCha20-Poly1305) |
| `src/dh/signing.ts` | generateSigningKeypair, sign, verify, createSignedRequest, verifySignedRequest |
| `src/psi/types.ts` | PSI-only types (no authToken) |
| `src/psi/service.ts` | PsiService — owner-held key path only |
| `src/psi/index.ts` | Re-exports PsiService and PSI types |
| `src/index.ts` | Top-level barrel re-export |
| `test/dh/dh.test.ts` | DH token derivation tests |
| `test/dh/commit.test.ts` | Commit-reveal tests |
| `test/dh/nullifier.test.ts` | Nullifier tests |
| `test/dh/ecies.test.ts` | ECIES encrypt/decrypt tests |
| `test/dh/signing.test.ts` | Ed25519 signing tests |
| `test/psi/psi.test.ts` | PSI integration test (owner-held key flow) |
| `examples/mutual-match.ts` | End-to-end DH + PSI example |
| `README.md` | Protocol explanation |
| `PROTOCOL.md` | Formal spec: security properties, threat model |

### Modified in `~/dev/rendezvous/`

| File | Change |
|------|--------|
| `package.json` | Add `matchlock` dependency |
| `src/rendezvous/types.ts` | Remove 4 primitive types, import from `matchlock` |
| `src/rendezvous/index.ts` | Replace `export * from './crypto.js'` with named exports from `matchlock` |
| `src/rendezvous/detection.ts` | Update import of `deriveMatchToken` |
| `src/rendezvous/submission.ts` | Update imports of `commitToken`, `verifyCommitment`, `isValidMatchToken`, `randomHex` |
| `src/federation/manager.ts` | Update imports of `encryptForPublicKey`, `serializeEncryptedBox` |
| `src/scripts/seed.ts` | Update imports of `deriveMatchTokens`, `deriveMatchToken`, `deriveNullifier` |
| `src/server/index.ts` | Update imports of `decryptWithPrivateKey`, `deserializeEncryptedBox`, `hash`, `verifySignedRequest`; update PSI imports |
| `src/rendezvous/storage.ts` | Update import from `psi/types.js` |

### Deleted in `~/dev/rendezvous/`

- `src/rendezvous/crypto.ts`
- `src/psi/` (entire directory)

---

## Task 1: Initialize matchlock repo

**Files:**
- Create: `~/dev/matchlock/package.json`
- Create: `~/dev/matchlock/tsconfig.json`
- Create: `~/dev/matchlock/jest.config.js`
- Create: `~/dev/matchlock/.gitignore`

- [ ] **Step 1: Create the directory and git repo**

```bash
mkdir ~/dev/matchlock && cd ~/dev/matchlock
git init
```

- [ ] **Step 2: Create `package.json`**

```json
{
  "name": "matchlock",
  "version": "0.1.0",
  "description": "Privacy-preserving mutual match: DH token derivation + PSI with owner-held keys",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "scripts": {
    "build": "tsc",
    "test": "node --experimental-vm-modules node_modules/.bin/jest"
  },
  "dependencies": {
    "@noble/ciphers": "^1.0.0",
    "@noble/curves": "^1.7.0",
    "@noble/hashes": "^1.6.0",
    "@openmined/psi.js": "^1.1.3"
  },
  "devDependencies": {
    "@types/jest": "^29.0.0",
    "@types/node": "^20.0.0",
    "jest": "^29.7.0",
    "ts-jest": "^29.2.5",
    "typescript": "^5.7.2"
  }
}
```

- [ ] **Step 3: Create `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "isolatedModules": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "test"]
}
```

- [ ] **Step 4: Create `jest.config.js`**

```js
/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { useESM: true }],
  },
  testMatch: ['**/test/**/*.test.ts'],
  testTimeout: 30000,
};
```

- [ ] **Step 5: Create `.gitignore`**

```
node_modules/
dist/
coverage/
```

- [ ] **Step 6: Install dependencies**

```bash
npm install
```

Expected: `node_modules/` created, no errors.

- [ ] **Step 7: Create src directories**

```bash
mkdir -p src/dh src/psi test/dh test/psi examples
```

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "chore: init matchlock repo"
```

---

## Task 2: Primitive types

**Files:**
- Create: `src/types.ts`

- [ ] **Step 1: Create `src/types.ts`**

```typescript
/** Hex-encoded X25519 public key (64 chars) */
export type PublicKey = string;

/** Hex-encoded X25519 private key (64 chars) */
export type PrivateKey = string;

/** Hex-encoded match token — SHA-256 of DH shared secret (64 chars) */
export type MatchToken = string;

/** Hex-encoded commitment hash — SHA-256 of a MatchToken (64 chars) */
export type CommitHash = string;
```

- [ ] **Step 2: Commit**

```bash
git add src/types.ts
git commit -m "feat: primitive types"
```

---

## Task 3: DH token derivation

**Files:**
- Create: `src/dh/index.ts`
- Create: `test/dh/dh.test.ts`

The core insight: `DH(alice_priv, bob_pub) == DH(bob_priv, alice_pub)`. Both parties derive the same token only when they mutually select each other.

- [ ] **Step 1: Write the failing test**

`test/dh/dh.test.ts`:
```typescript
import { generateKeypair, deriveMatchToken, deriveMatchTokens } from '../../src/dh/index.js';

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
    const poolId = 'pool-1';

    const aliceSelectsBob = deriveMatchToken(alice.privateKey, bob.publicKey, poolId);
    const bobSelectsCarol = deriveMatchToken(bob.privateKey, carol.publicKey, poolId);

    expect(aliceSelectsBob).not.toBe(bobSelectsCarol);
  });

  it('tokens are pool-scoped — same pair, different pool = different token', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();

    const token1 = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-a');
    const token2 = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-b');

    expect(token1).not.toBe(token2);
  });

  it('deriveMatchTokens returns one token per public key', () => {
    const alice = generateKeypair();
    const others = [generateKeypair(), generateKeypair(), generateKeypair()];
    const poolId = 'pool-1';

    const tokens = deriveMatchTokens(alice.privateKey, others.map(k => k.publicKey), poolId);
    expect(tokens).toHaveLength(3);
    tokens.forEach(t => expect(t).toMatch(/^[0-9a-f]{64}$/));
  });

  it('tokens are 64-char hex strings', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npm test -- test/dh/dh.test.ts
```

Expected: FAIL — `Cannot find module '../../src/dh/index.js'`

- [ ] **Step 3: Implement `src/dh/index.ts`**

```typescript
import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import type { MatchToken, PublicKey, PrivateKey } from '../types.js';

const MATCH_DOMAIN = 'rendezvous-match-v1';

export function generateKeypair(): { publicKey: PublicKey; privateKey: PrivateKey } {
  const privateKey = randomBytes(32);
  return {
    publicKey: bytesToHex(x25519.getPublicKey(privateKey)),
    privateKey: bytesToHex(privateKey),
  };
}

export function deriveMatchToken(
  myPrivateKey: PrivateKey,
  theirPublicKey: PublicKey,
  poolId: string,
): MatchToken {
  const shared = x25519.scalarMult(hexToBytes(myPrivateKey), hexToBytes(theirPublicKey));
  const encoder = new TextEncoder();
  const input = new Uint8Array([
    ...shared,
    ...encoder.encode(poolId),
    ...encoder.encode(MATCH_DOMAIN),
  ]);
  return bytesToHex(sha256(input));
}

export function deriveMatchTokens(
  myPrivateKey: PrivateKey,
  theirPublicKeys: PublicKey[],
  poolId: string,
): MatchToken[] {
  return theirPublicKeys.map(pk => deriveMatchToken(myPrivateKey, pk, poolId));
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npm test -- test/dh/dh.test.ts
```

Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
git add src/dh/index.ts test/dh/dh.test.ts
git commit -m "feat: DH token derivation"
```

---

## Task 4: Commit-reveal

**Files:**
- Create: `src/dh/commit.ts`
- Create: `test/dh/commit.test.ts`

- [ ] **Step 1: Write the failing test**

`test/dh/commit.test.ts`:
```typescript
import { generateKeypair, deriveMatchToken } from '../../src/dh/index.js';
import { commitToken, commitTokens, verifyCommitment } from '../../src/dh/commit.js';

describe('commit-reveal', () => {
  it('commitment is deterministic', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');

    expect(commitToken(token)).toBe(commitToken(token));
  });

  it('commitment differs from the token itself', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');

    expect(commitToken(token)).not.toBe(token);
  });

  it('verifyCommitment accepts correct token', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    const commit = commitToken(token);

    expect(verifyCommitment(token, commit)).toBe(true);
  });

  it('verifyCommitment rejects wrong token', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const carol = generateKeypair();
    const token = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
    const wrongToken = deriveMatchToken(alice.privateKey, carol.publicKey, 'pool-1');
    const commit = commitToken(token);

    expect(verifyCommitment(wrongToken, commit)).toBe(false);
  });

  it('commitTokens returns one commitment per token', () => {
    const alice = generateKeypair();
    const others = [generateKeypair(), generateKeypair()];
    const tokens = others.map(k => deriveMatchToken(alice.privateKey, k.publicKey, 'pool-1'));

    const commits = commitTokens(tokens);
    expect(commits).toHaveLength(2);
    commits.forEach(c => expect(c).toMatch(/^[0-9a-f]{64}$/));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npm test -- test/dh/commit.test.ts
```

Expected: FAIL — `Cannot find module '../../src/dh/commit.js'`

- [ ] **Step 3: Implement `src/dh/commit.ts`**

```typescript
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type { MatchToken, CommitHash } from '../types.js';

export function commitToken(matchToken: MatchToken): CommitHash {
  return bytesToHex(sha256(new TextEncoder().encode(matchToken)));
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
```

- [ ] **Step 4: Run tests**

```bash
npm test -- test/dh/commit.test.ts
```

Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
git add src/dh/commit.ts test/dh/commit.test.ts
git commit -m "feat: commit-reveal"
```

---

## Task 5: Nullifier

**Files:**
- Create: `src/dh/nullifier.ts`
- Create: `test/dh/nullifier.test.ts`

- [ ] **Step 1: Write the failing test**

`test/dh/nullifier.test.ts`:
```typescript
import { generateKeypair } from '../../src/dh/index.js';
import { deriveNullifier } from '../../src/dh/nullifier.js';

describe('nullifier', () => {
  it('same key + same pool = same nullifier (deterministic)', () => {
    const { privateKey } = generateKeypair();
    expect(deriveNullifier(privateKey, 'pool-1')).toBe(deriveNullifier(privateKey, 'pool-1'));
  });

  it('same key + different pool = different nullifier (pool-scoped)', () => {
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
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npm test -- test/dh/nullifier.test.ts
```

Expected: FAIL.

- [ ] **Step 3: Implement `src/dh/nullifier.ts`**

```typescript
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type { PrivateKey } from '../types.js';

const NULLIFIER_DOMAIN = 'rendezvous-nullifier-v1';

export function deriveNullifier(privateKey: PrivateKey, poolId: string): string {
  const encoder = new TextEncoder();
  const input = new Uint8Array([
    ...hexToBytes(privateKey),
    ...encoder.encode(poolId),
    ...encoder.encode(NULLIFIER_DOMAIN),
  ]);
  return bytesToHex(sha256(input));
}
```

- [ ] **Step 4: Run tests**

```bash
npm test -- test/dh/nullifier.test.ts
```

Expected: PASS — 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/dh/nullifier.ts test/dh/nullifier.test.ts
git commit -m "feat: nullifier"
```

---

## Task 6: Hardened ECIES

**Files:**
- Create: `src/dh/ecies.ts`
- Create: `test/dh/ecies.test.ts`

Replaces the hand-rolled stream cipher in Rendezvous's `crypto.ts` with XChaCha20-Poly1305 from `@noble/ciphers`. Wire-format break — intentional, no prior consumers.

- [ ] **Step 1: Write the failing test**

`test/dh/ecies.test.ts`:
```typescript
import { generateKeypair } from '../../src/dh/index.js';
import {
  encryptForPublicKey,
  decryptWithPrivateKey,
  serializeEncryptedBox,
  deserializeEncryptedBox,
} from '../../src/dh/ecies.js';

describe('ECIES', () => {
  it('encrypts and decrypts round-trip', () => {
    const { publicKey, privateKey } = generateKeypair();
    const plaintext = 'hello matchlock';
    const box = encryptForPublicKey(plaintext, publicKey);
    expect(decryptWithPrivateKey(box, privateKey)).toBe(plaintext);
  });

  it('produces different ciphertext each call (random ephemeral key)', () => {
    const { publicKey } = generateKeypair();
    const box1 = encryptForPublicKey('same', publicKey);
    const box2 = encryptForPublicKey('same', publicKey);
    expect(box1.ciphertext).not.toBe(box2.ciphertext);
    expect(box1.ephemeralPublicKey).not.toBe(box2.ephemeralPublicKey);
  });

  it('throws on tampered ciphertext (auth failure)', () => {
    const { publicKey, privateKey } = generateKeypair();
    const box = encryptForPublicKey('secret data', publicKey);
    // Flip last byte of ciphertext
    const tampered = {
      ...box,
      ciphertext: box.ciphertext.slice(0, -2) + (box.ciphertext.slice(-2) === 'ff' ? '00' : 'ff'),
    };
    expect(() => decryptWithPrivateKey(tampered, privateKey)).toThrow();
  });

  it('throws when decrypting with wrong private key', () => {
    const { publicKey } = generateKeypair();
    const { privateKey: wrongPrivateKey } = generateKeypair();
    const box = encryptForPublicKey('secret', publicKey);
    expect(() => decryptWithPrivateKey(box, wrongPrivateKey)).toThrow();
  });

  it('serializes and deserializes round-trip', () => {
    const { publicKey, privateKey } = generateKeypair();
    const box = encryptForPublicKey('serialize me', publicKey);
    const serialized = serializeEncryptedBox(box);
    const deserialized = deserializeEncryptedBox(serialized);
    expect(decryptWithPrivateKey(deserialized, privateKey)).toBe('serialize me');
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npm test -- test/dh/ecies.test.ts
```

Expected: FAIL.

- [ ] **Step 3: Implement `src/dh/ecies.ts`**

```typescript
import { x25519 } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import type { PublicKey, PrivateKey } from '../types.js';

const ENCRYPTION_DOMAIN = 'rendezvous-encrypt-v1';

export interface EncryptedBox {
  /** Ephemeral X25519 public key (hex) */
  ephemeralPublicKey: string;
  /** Random 24-byte nonce for XChaCha20-Poly1305 (hex) */
  nonce: string;
  /** Ciphertext with 16-byte Poly1305 auth tag appended (hex) */
  ciphertext: string;
}

export function encryptForPublicKey(plaintext: string, recipientPublicKey: PublicKey): EncryptedBox {
  const ephemeralPrivateKey = randomBytes(32);
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
  const sharedSecret = x25519.scalarMult(ephemeralPrivateKey, hexToBytes(recipientPublicKey));
  const nonce = randomBytes(24);
  const key = hkdf(sha256, sharedSecret, nonce, new TextEncoder().encode(ENCRYPTION_DOMAIN), 32);

  const ciphertext = xchacha20poly1305(key, nonce).encrypt(new TextEncoder().encode(plaintext));

  return {
    ephemeralPublicKey: bytesToHex(ephemeralPublicKey),
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
  };
}

export function decryptWithPrivateKey(box: EncryptedBox, recipientPrivateKey: PrivateKey): string {
  const sharedSecret = x25519.scalarMult(hexToBytes(recipientPrivateKey), hexToBytes(box.ephemeralPublicKey));
  const nonce = hexToBytes(box.nonce);
  const key = hkdf(sha256, sharedSecret, nonce, new TextEncoder().encode(ENCRYPTION_DOMAIN), 32);

  // xchacha20poly1305.decrypt throws if auth tag fails
  const plaintext = xchacha20poly1305(key, nonce).decrypt(hexToBytes(box.ciphertext));
  return new TextDecoder().decode(plaintext);
}

export function serializeEncryptedBox(box: EncryptedBox): string {
  return Buffer.from(JSON.stringify(box)).toString('base64');
}

export function deserializeEncryptedBox(serialized: string): EncryptedBox {
  return JSON.parse(Buffer.from(serialized, 'base64').toString('utf-8')) as EncryptedBox;
}
```

- [ ] **Step 4: Run tests**

```bash
npm test -- test/dh/ecies.test.ts
```

Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
git add src/dh/ecies.ts test/dh/ecies.test.ts
git commit -m "feat: ECIES with XChaCha20-Poly1305"
```

---

## Task 7: Ed25519 signing

**Files:**
- Create: `src/dh/signing.ts`
- Create: `test/dh/signing.test.ts`

- [ ] **Step 1: Write the failing test**

`test/dh/signing.test.ts`:
```typescript
import {
  generateSigningKeypair,
  sign,
  verify,
  createSignedRequest,
  verifySignedRequest,
} from '../../src/dh/signing.js';

describe('Ed25519 signing', () => {
  it('sign + verify round-trip', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const sig = sign('hello', signingPrivateKey);
    expect(verify('hello', sig, signingPublicKey)).toBe(true);
  });

  it('verify rejects wrong message', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const sig = sign('hello', signingPrivateKey);
    expect(verify('world', sig, signingPublicKey)).toBe(false);
  });

  it('verify rejects wrong key', () => {
    const { signingPrivateKey } = generateSigningKeypair();
    const { signingPublicKey: wrongPub } = generateSigningKeypair();
    const sig = sign('hello', signingPrivateKey);
    expect(verify('hello', sig, wrongPub)).toBe(false);
  });

  it('createSignedRequest + verifySignedRequest round-trip', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const { signature, timestamp } = createSignedRequest('psi-setup', 'pool-1', signingPrivateKey);
    expect(verifySignedRequest('psi-setup', 'pool-1', signature, timestamp, signingPublicKey)).toBe(true);
  });

  it('verifySignedRequest rejects stale timestamp', () => {
    const { signingPublicKey, signingPrivateKey } = generateSigningKeypair();
    const staleTimestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago
    const message = `psi-setup:pool-1:${staleTimestamp}`;
    const sig = sign(message, signingPrivateKey);
    expect(verifySignedRequest('psi-setup', 'pool-1', sig, staleTimestamp, signingPublicKey)).toBe(false);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npm test -- test/dh/signing.test.ts
```

Expected: FAIL.

- [ ] **Step 3: Implement `src/dh/signing.ts`**

```typescript
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const SIGNING_DOMAIN = 'rendezvous-sign-v1';

export type SigningPublicKey = string;
export type SigningPrivateKey = string;
export type Signature = string;

export function generateSigningKeypair(): {
  signingPublicKey: SigningPublicKey;
  signingPrivateKey: SigningPrivateKey;
} {
  const privateKey = ed25519.utils.randomPrivateKey();
  return {
    signingPublicKey: bytesToHex(ed25519.getPublicKey(privateKey)),
    signingPrivateKey: bytesToHex(privateKey),
  };
}

export function sign(message: string, signingPrivateKey: SigningPrivateKey): Signature {
  const encoder = new TextEncoder();
  const messageHash = sha256(new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)]));
  return bytesToHex(ed25519.sign(messageHash, hexToBytes(signingPrivateKey)));
}

export function verify(message: string, signature: Signature, signingPublicKey: SigningPublicKey): boolean {
  try {
    const encoder = new TextEncoder();
    const messageHash = sha256(new Uint8Array([...encoder.encode(SIGNING_DOMAIN), ...encoder.encode(message)]));
    return ed25519.verify(hexToBytes(signature), messageHash, hexToBytes(signingPublicKey));
  } catch {
    return false;
  }
}

export function createSignedRequest(
  action: string,
  poolId: string,
  signingPrivateKey: SigningPrivateKey,
): { signature: Signature; timestamp: number } {
  const timestamp = Date.now();
  return { signature: sign(`${action}:${poolId}:${timestamp}`, signingPrivateKey), timestamp };
}

export function verifySignedRequest(
  action: string,
  poolId: string,
  signature: Signature,
  timestamp: number,
  signingPublicKey: SigningPublicKey,
  maxAgeMs = 5 * 60 * 1000,
): boolean {
  if (Math.abs(Date.now() - timestamp) > maxAgeMs) return false;
  return verify(`${action}:${poolId}:${timestamp}`, signature, signingPublicKey);
}
```

- [ ] **Step 4: Run tests**

```bash
npm test -- test/dh/signing.test.ts
```

Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
git add src/dh/signing.ts test/dh/signing.test.ts
git commit -m "feat: Ed25519 signing"
```

---

## Task 8: PSI types

**Files:**
- Create: `src/psi/types.ts`

PSI types cleaned up: `PsiJoinRequest` is split — the `authToken` field (Freebird-specific) stays in Rendezvous. Matchlock exports only the PSI-level `PsiClientRequest`. The server-held key types (`PsiPoolSetup`, `PsiServerState`) are removed since that path is being dropped.

- [ ] **Step 1: Create `src/psi/types.ts`**

```typescript
/**
 * PSI types for private set intersection operations.
 *
 * Note: PsiJoinRequest (with authToken) is an application concern and
 * lives in the consuming app. Matchlock exposes only the PSI primitives.
 */

/** PSI client request — the serialized blind query */
export interface PsiClientRequest {
  /** Serialized PSI client request (base64) */
  psiRequest: string;
}

/** Response to a PSI query */
export interface PsiJoinResponse {
  /** Serialized PSI setup message (base64) */
  psiSetup: string;
  /** Serialized PSI response (base64) */
  psiResponse: string;
}

/** Result of PSI intersection computation (client-side only) */
export interface PsiResult {
  intersection: string[];
  cardinality: number;
}

/**
 * Owner-encrypted PSI setup stored in database.
 * The server CANNOT decrypt encryptedServerKey — only the pool owner can.
 */
export interface OwnerHeldPsiSetup {
  poolId: string;
  /** Serialized PSI server setup message (base64) — PUBLIC */
  setupMessage: string;
  /** PSI server key encrypted to pool owner's X25519 public key (serialized EncryptedBox) */
  encryptedServerKey: string;
  ownerPublicKey: string;
  fpr: number;
  maxClientElements: number;
  dataStructure: 'GCS' | 'BloomFilter';
  createdAt: number;
}

/** Pending PSI request queued for pool owner processing */
export interface PendingPsiRequest {
  id: string;
  poolId: string;
  psiRequest: string;
  status: 'pending' | 'processing' | 'completed' | 'expired';
  createdAt: number;
  authTokenHash?: string;
}

/** PSI response record after owner processes a request */
export interface PsiResponseRecord {
  id: string;
  requestId: string;
  poolId: string;
  psiSetup: string;
  psiResponse: string;
  createdAt: number;
  expiresAt: number;
}

/** Owner's batch processing result */
export interface OwnerPsiProcessingResult {
  requestId: string;
  psiResponse: string;
}

/** Request to create a new PSI setup for a pool */
export interface CreatePsiSetupRequest {
  poolId: string;
  matchTokens: string[];
  fpr?: number;
  maxClientElements?: number;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/psi/types.ts
git commit -m "feat: PSI types (owner-held key only)"
```

---

## Task 9: PsiService

**Files:**
- Create: `src/psi/service.ts`
- Create: `src/psi/index.ts`
- Create: `test/psi/psi.test.ts`

The server-held key path (`createSetup`, `processRequest`) is removed. Only the owner-held key architecture is exposed. Test loads WASM — expect ~5–10s initialization.

- [ ] **Step 1: Write the failing integration test**

`test/psi/psi.test.ts`:
```typescript
import { generateKeypair } from '../../src/dh/index.js';
import { PsiService } from '../../src/psi/service.js';

describe('PsiService — owner-held key flow', () => {
  let psi: PsiService;

  beforeAll(async () => {
    psi = new PsiService();
    await psi.init(); // loads WASM — slow on first call
  });

  it('full owner-held key round-trip: setup → request → process → intersect', async () => {
    const ownerKeypair = generateKeypair();

    // Pool owner creates setup with their tokens, server key encrypted to owner
    const ownerTokens = ['token-alice-bob', 'token-alice-carol', 'token-alice-dave'];
    const setup = await psi.createOwnerEncryptedSetup(
      { poolId: 'test-pool', matchTokens: ownerTokens },
      ownerKeypair.publicKey,
    );

    expect(setup.encryptedServerKey).toBeTruthy();
    expect(setup.setupMessage).toBeTruthy();
    expect(setup.ownerPublicKey).toBe(ownerKeypair.publicKey);

    // Joiner creates PSI request with their tokens
    const joinerTokens = ['token-alice-bob', 'token-joiner-eve']; // one overlap
    const { request: psiRequest, clientKey } = await psi.createRequest(joinerTokens);

    // Owner decrypts server key and processes the request
    const { decryptWithPrivateKey, deserializeEncryptedBox } = await import('../../src/dh/ecies.js');
    const box = deserializeEncryptedBox(setup.encryptedServerKey);
    const decryptedServerKey = decryptWithPrivateKey(box, ownerKeypair.privateKey);
    const psiResponse = await psi.processRequestWithDecryptedKey(decryptedServerKey, psiRequest);

    // Joiner computes intersection locally
    const result = await psi.computeIntersection(clientKey, joinerTokens, setup.setupMessage, psiResponse);

    expect(result.intersection).toContain('token-alice-bob');
    expect(result.cardinality).toBe(1);
  });

  it('cardinality-only mode does not reveal intersection elements', async () => {
    const ownerKeypair = generateKeypair();
    const setup = await psi.createOwnerEncryptedSetup(
      { poolId: 'test-pool-2', matchTokens: ['a', 'b', 'c'] },
      ownerKeypair.publicKey,
    );

    const { request, clientKey } = await psi.createRequest(['a', 'b', 'x']);
    const { decryptWithPrivateKey, deserializeEncryptedBox } = await import('../../src/dh/ecies.js');
    const serverKey = decryptWithPrivateKey(deserializeEncryptedBox(setup.encryptedServerKey), ownerKeypair.privateKey);
    const response = await psi.processRequestWithDecryptedKey(serverKey, request);

    const count = await psi.computeCardinality(clientKey, ['a', 'b', 'x'], setup.setupMessage, response);
    expect(count).toBe(2);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npm test -- test/psi/psi.test.ts
```

Expected: FAIL — `Cannot find module '../../src/psi/service.js'`

- [ ] **Step 3: Create `src/psi/service.ts`**

Copy `src/psi/service.ts` from Rendezvous (`~/dev/rendezvous/src/psi/service.ts`) and make these changes:
1. Remove `createSetup()` and `processRequest()` methods (the server-held key path with TODO comments)
2. Update the import of `encryptForPublicKey` and `serializeEncryptedBox`: change from `'../rendezvous/crypto.js'` to `'../dh/ecies.js'`
3. Update the import of `CreatePsiSetupRequest` and related types: change from `'./types.js'` (same file already)

The file should retain only: `init()`, `getPsi()`, `createOwnerEncryptedSetup()`, `processRequestWithDecryptedKey()`, `createRequest()`, `computeIntersection()`, `computeCardinality()`, and the singleton `getPsiService()`.

- [ ] **Step 4: Create `src/psi/index.ts`**

```typescript
export { PsiService, getPsiService } from './service.js';
export type {
  PsiClientRequest,
  PsiJoinResponse,
  PsiResult,
  OwnerHeldPsiSetup,
  PendingPsiRequest,
  PsiResponseRecord,
  OwnerPsiProcessingResult,
  CreatePsiSetupRequest,
} from './types.js';
```

- [ ] **Step 5: Run tests**

```bash
npm test -- test/psi/psi.test.ts
```

Expected: PASS — 2 tests. (Allow ~15s for WASM load.)

- [ ] **Step 6: Commit**

```bash
git add src/psi/ test/psi/
git commit -m "feat: PsiService with owner-held key architecture"
```

---

## Task 10: Barrel exports and build

**Files:**
- Create: `src/index.ts`

- [ ] **Step 1: Create `src/index.ts`**

```typescript
// DH primitives
export { generateKeypair, deriveMatchToken, deriveMatchTokens } from './dh/index.js';
export { commitToken, commitTokens, verifyCommitment } from './dh/commit.js';
export { deriveNullifier } from './dh/nullifier.js';
export {
  encryptForPublicKey,
  decryptWithPrivateKey,
  serializeEncryptedBox,
  deserializeEncryptedBox,
} from './dh/ecies.js';
export type { EncryptedBox } from './dh/ecies.js';
export {
  generateSigningKeypair,
  sign,
  verify,
  createSignedRequest,
  verifySignedRequest,
} from './dh/signing.js';
export type { SigningPublicKey, SigningPrivateKey, Signature } from './dh/signing.js';

// Primitive types
export type { MatchToken, CommitHash, PublicKey, PrivateKey } from './types.js';

// PSI
export { PsiService, getPsiService } from './psi/index.js';
export type {
  PsiClientRequest,
  PsiJoinResponse,
  PsiResult,
  OwnerHeldPsiSetup,
  PendingPsiRequest,
  PsiResponseRecord,
  OwnerPsiProcessingResult,
  CreatePsiSetupRequest,
} from './psi/index.js';
```

- [ ] **Step 2: Run the full test suite**

```bash
npm test
```

Expected: PASS — all tests.

- [ ] **Step 3: Build**

```bash
npm run build
```

Expected: `dist/` created, no TypeScript errors.

- [ ] **Step 4: Verify dist exports**

```bash
ls dist/
```

Expected: `index.js`, `index.d.ts`, `dh/`, `psi/`, `types.js`, `types.d.ts`.

- [ ] **Step 5: Commit**

Note: `dist/` is committed here because Rendezvous links to matchlock via `file:../matchlock` — the built artifacts need to be present. This is intentional for local development. If matchlock is later published to npm, add `dist/` to `.gitignore` and use a `prepare` script instead.

```bash
git add src/index.ts dist/
git commit -m "feat: barrel exports and build"
```

---

## Task 11: Example

**Files:**
- Create: `examples/mutual-match.ts`

- [ ] **Step 1: Create `examples/mutual-match.ts`**

```typescript
/**
 * Matchlock — end-to-end mutual match example
 *
 * Shows the full DH + PSI flow:
 * 1. Alice and Bob each generate keypairs
 * 2. Alice selects Bob (and Carol); Bob selects Alice (and Dave)
 * 3. Both derive the same match token for their mutual selection
 * 4. Pool owner uses PSI to let Bob discover the match without
 *    learning Alice's non-matching selections
 */

import { generateKeypair, deriveMatchToken } from '../src/dh/index.js';
import { commitToken } from '../src/dh/commit.js';
import { deriveNullifier } from '../src/dh/nullifier.js';
import { decryptWithPrivateKey, deserializeEncryptedBox } from '../src/dh/ecies.js';
import { PsiService } from '../src/psi/service.js';

async function main() {
  const poolId = 'example-pool';

  // --- Key generation ---
  const alice = generateKeypair();
  const bob = generateKeypair();
  const carol = generateKeypair();
  const dave = generateKeypair();

  console.log('Alice public key:', alice.publicKey.slice(0, 16) + '...');
  console.log('Bob public key:  ', bob.publicKey.slice(0, 16) + '...');

  // --- Token derivation (client-side, no server involved) ---
  // Alice selects Bob and Carol
  const aliceSelectsBob = deriveMatchToken(alice.privateKey, bob.publicKey, poolId);
  const aliceSelectsCarol = deriveMatchToken(alice.privateKey, carol.publicKey, poolId);

  // Bob selects Alice and Dave
  const bobSelectsAlice = deriveMatchToken(bob.privateKey, alice.publicKey, poolId);
  const bobSelectsDave = deriveMatchToken(bob.privateKey, dave.publicKey, poolId);

  // The mutual match token is identical
  console.log('\nDH mutual match:');
  console.log('Alice→Bob token:', aliceSelectsBob.slice(0, 16) + '...');
  console.log('Bob→Alice token:', bobSelectsAlice.slice(0, 16) + '...');
  console.log('Tokens equal?  ', aliceSelectsBob === bobSelectsAlice); // true

  // --- Commit phase (prevents timing attacks) ---
  const aliceCommit = commitToken(aliceSelectsBob);
  console.log('\nAlice commits:', aliceCommit.slice(0, 16) + '...');

  // --- Nullifier (prevents double-submission) ---
  const aliceNullifier = deriveNullifier(alice.privateKey, poolId);
  console.log('Alice nullifier:', aliceNullifier.slice(0, 16) + '...');

  // --- PSI phase: pool owner detects matches without learning unilateral selections ---
  console.log('\nInitializing PSI (loads WASM)...');
  const psi = new PsiService();
  await psi.init();

  // Pool owner (here: Alice acting as pool owner) creates setup
  const ownerKeypair = generateKeypair(); // pool owner keypair
  const allPoolTokens = [aliceSelectsBob, aliceSelectsCarol]; // all submitted tokens
  const setup = await psi.createOwnerEncryptedSetup(
    { poolId, matchTokens: allPoolTokens },
    ownerKeypair.publicKey,
  );

  // Bob creates a PSI query with his tokens
  const { request, clientKey } = await psi.createRequest([bobSelectsAlice, bobSelectsDave]);

  // Owner decrypts key and processes query (server learns nothing)
  const serverKey = decryptWithPrivateKey(
    deserializeEncryptedBox(setup.encryptedServerKey),
    ownerKeypair.privateKey,
  );
  const response = await psi.processRequestWithDecryptedKey(serverKey, request);

  // Bob computes intersection locally
  const result = await psi.computeIntersection(
    clientKey,
    [bobSelectsAlice, bobSelectsDave],
    setup.setupMessage,
    response,
  );

  console.log('\nPSI result:');
  console.log('Matches found:', result.cardinality); // 1
  console.log('Match token:  ', result.intersection[0]?.slice(0, 16) + '...');
  console.log('Is alice-bob? ', result.intersection[0] === aliceSelectsBob); // true
  console.log('\nBob learned about the mutual match with Alice.');
  console.log('Bob did NOT learn that Alice also selected Carol.');
}

main().catch(console.error);
```

- [ ] **Step 2: Verify the example runs**

```bash
npx tsx examples/mutual-match.ts
```

Expected: output showing matching tokens equal, PSI finds 1 match.

(If `tsx` isn't available: `npm install -D tsx` first.)

- [ ] **Step 3: Commit**

```bash
git add examples/mutual-match.ts
git commit -m "feat: end-to-end example"
```

---

## Task 12: README and PROTOCOL.md

**Files:**
- Create: `README.md`
- Create: `PROTOCOL.md`

- [ ] **Step 1: Create `README.md`**

```markdown
# Matchlock

Privacy-preserving mutual match: detect when two parties select each other without revealing unilateral selections to anyone.

## The problem

Every existing matching platform — dating apps, hiring platforms, roommate finders — operates as a trusted intermediary that sees all preferences. They know who you selected and who selected you, including rejections. This is a structural surveillance problem, not an implementation detail.

## How Matchlock works

Matchlock composes two primitives:

**1. DH token derivation**

Two parties independently derive *identical* match tokens when they mutually select each other, using X25519 Diffie-Hellman:

```
Alice selects Bob:
  token = SHA256(DH(alice_priv, bob_pub) || poolId || "rendezvous-match-v1")

Bob selects Alice:
  token = SHA256(DH(bob_priv, alice_pub) || poolId || "rendezvous-match-v1")

// DH commutativity: same shared secret → same token
```

Tokens are derived locally. No server interaction required. The server never sees your selections — only the derived tokens you choose to submit.

**2. Private Set Intersection (PSI)**

PSI allows the server to detect overlapping tokens without learning which tokens each participant submitted. Built on [OpenMined's PSI.js](https://github.com/OpenMined/PSI) with an owner-held key architecture: the PSI server key is encrypted to the pool owner's public key, so the server cannot process queries without owner participation.

Together, these two layers ensure:

| Party | Learns | Does NOT learn |
|-------|--------|----------------|
| Server | Set sizes, timing | Your selections or matches |
| You | Your matches only | Who rejected you, or who others selected |
| Pool owner | Match token hashes | Whose key belongs to whom |

## Installation

```bash
npm install matchlock
```

## Usage

```typescript
import { generateKeypair, deriveMatchToken, PsiService } from 'matchlock';

// Each participant generates a keypair
const alice = generateKeypair();
const bob = generateKeypair();

// Both derive the same token (DH commutativity)
const tokenA = deriveMatchToken(alice.privateKey, bob.publicKey, 'pool-1');
const tokenB = deriveMatchToken(bob.privateKey, alice.publicKey, 'pool-1');
console.log(tokenA === tokenB); // true — mutual match

// Use PSI to detect matches without revealing unilateral selections
// See examples/mutual-match.ts for the full flow
```

See [`examples/mutual-match.ts`](examples/mutual-match.ts) for a complete end-to-end walkthrough.

## Security properties

- **Zero server knowledge**: The server sees only opaque hash values. It cannot determine who selected whom without breaking SHA-256.
- **Unilateral privacy**: If Alice selects Bob but Bob doesn't select Alice, Bob learns nothing about Alice's selection. Alice's token `DH(alice_priv, bob_pub)` is computationally indistinguishable from random from Bob's perspective without Alice's private key.
- **Pool isolation**: Tokens are scoped to a pool ID. Cross-pool linkability requires breaking the hash.
- **Replay protection**: Nullifiers (`deriveNullifier`) prevent re-submission across rounds within a pool.
- **Owner-held PSI keys**: The PSI server key is ECIES-encrypted to the pool owner's public key. The infrastructure operator cannot process PSI queries independently.

## Reference implementation

[Rendezvous](https://github.com/sophiaDOS/rendezvous) — a full matching application built on Matchlock, Freebird (anonymous authorization), and Witness (threshold timestamping).

## Part of SophiaDOS

Matchlock is one of three cryptographic primitives in the [SophiaDOS](https://github.com/sophiaDOS) ecosystem:

- **Matchlock** — privacy-preserving mutual matching (this library)
- **[Freebird](https://github.com/sophiaDOS/freebird)** — anonymous authorization via VOPRF blind signatures
- **[Witness](https://github.com/sophiaDOS/witness)** — threshold timestamping via BLS12-381

## License

Apache-2.0
```

- [ ] **Step 2: Create `PROTOCOL.md`**

```markdown
# Matchlock Protocol Specification

## Overview

Matchlock is a protocol for mutual preference detection. Two parties can discover they mutually selected each other without either party or the server learning about unilateral (non-mutual) selections.

## Participants

- **Participant**: A user with an X25519 keypair. Derives match tokens locally.
- **Pool owner**: Holds the PSI server key (encrypted). Processes PSI queries.
- **Server**: Stores encrypted PSI setup and queues PSI requests. Learns nothing about preferences.

## Protocol

### Phase 1: Key generation

Each participant generates an X25519 keypair out-of-band:

```
(priv_i, pub_i) ← X25519.keygen()
```

Public keys are published to the pool (e.g., in a participant directory).

### Phase 2: Token derivation

For each participant j that participant i wants to select:

```
shared_ij = X25519(priv_i, pub_j)
token_ij  = SHA256(shared_ij || pool_id || "rendezvous-match-v1")
```

By X25519 commutativity: `shared_ij == shared_ji`, therefore `token_ij == token_ji`.

A match token is identical for both parties iff and only iff both derived it — which requires both to have selected each other.

### Phase 3: Commitment (optional, prevents timing attacks)

```
commit_ij = SHA256(token_ij)
```

Participants submit commitments first, then reveal tokens after a deadline. This prevents early reveals from influencing late submissions.

### Phase 4: Nullifier generation

```
nullifier_i = SHA256(priv_i || pool_id || "rendezvous-nullifier-v1")
```

Nullifiers are submitted with preferences and checked for uniqueness. This prevents a participant from submitting multiple preference sets within a pool while remaining unlinkable across pools.

### Phase 5: PSI setup (pool owner)

The pool owner creates a PSI server from the collected match tokens:

```
(psi_server_key, setup_msg) ← PSI.server_setup(all_tokens)
encrypted_key = ECIES_encrypt(psi_server_key, owner_pub)
```

`setup_msg` is public. `encrypted_key` is stored on the server but the server cannot decrypt it.

### Phase 6: PSI query (participant)

A querying participant creates a blind PSI request:

```
(psi_request, client_key) ← PSI.client_request(my_tokens)
```

Submitted to the server. The server learns the size of the request but not its contents.

### Phase 7: PSI processing (pool owner)

The pool owner decrypts the server key and processes the request:

```
psi_server_key = ECIES_decrypt(encrypted_key, owner_priv)
psi_response   = PSI.process_request(psi_server_key, psi_request)
```

The server relays `psi_response` to the querier.

### Phase 8: Intersection computation (participant)

The querier computes their matches locally:

```
matches = PSI.compute_intersection(client_key, my_tokens, setup_msg, psi_response)
```

Only the querier learns the result. The server and pool owner learn nothing new.

## Cryptographic primitives

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| Key agreement | X25519 | @noble/curves |
| Token hashing | SHA-256 | @noble/hashes |
| Commitment | SHA-256 | @noble/hashes |
| Asymmetric encryption | X25519 + HKDF + XChaCha20-Poly1305 | @noble/curves, @noble/hashes, @noble/ciphers |
| PSI | ECDH-based PSI (OpenMined) | @openmined/psi.js |
| Signing (owner auth) | Ed25519 | @noble/curves |

## Security properties

**Unilateral privacy**: A match token `T_ij = SHA256(DH(priv_i, pub_j) || ...)` is computationally indistinguishable from a random 256-bit value to anyone who does not hold `priv_i` or `priv_j`. If only Alice selects Bob, Bob cannot derive `T_ij` (he doesn't know `priv_i`) and the PSI response reveals nothing about tokens outside the intersection.

**Server opacity**: The server stores only commitments and base64-encoded PSI artifacts. It cannot interpret tokens without breaking SHA-256.

**Owner-held key trust model**: The PSI server key never exists in plaintext on the server. Even a fully compromised server operator cannot process PSI queries retroactively without the pool owner's private key.

**Pool isolation**: The `pool_id` domain separator in token derivation ensures tokens from different pools are independent. Linking a participant across pools requires their private key.

## Out of scope

- Sybil resistance (use Freebird for anonymous rate-limited authorization)
- Timestamping and ordering (use Witness for threshold timestamps)
- Transport security (use TLS)
- Metadata privacy (timing, IP, message sizes)
```

- [ ] **Step 3: Commit**

```bash
git add README.md PROTOCOL.md
git commit -m "docs: README and protocol specification"
```

---

## Task 13: Rendezvous — add dependency and split types.ts

**Working directory: `~/dev/rendezvous/`**

- [ ] **Step 1: Link matchlock locally**

```bash
cd ~/dev/matchlock && npm link
cd ~/dev/rendezvous && npm link matchlock
```

Or add it via a local path in `package.json` (update after publishing to npm):

```json
"matchlock": "file:../matchlock"
```

Then run:
```bash
npm install
```

- [ ] **Step 2: Build matchlock first**

```bash
cd ~/dev/matchlock && npm run build
```

Expected: `dist/` up to date.

- [ ] **Step 3: Split `src/rendezvous/types.ts`**

Remove the four primitive type definitions from the top of the file and replace them with an import:

```typescript
// Remove these four type definitions:
// export type PublicKey = string;
// export type PrivateKey = string;
// export type MatchToken = string;
// export type CommitHash = string;

// Replace with:
export type { PublicKey, PrivateKey, MatchToken, CommitHash } from 'matchlock';
```

The rest of the file (`PoolStatus`, `Pool`, `Preference`, `Participant`, etc.) is unchanged.

- [ ] **Step 4: Verify types.ts compiles**

```bash
cd ~/dev/rendezvous && npx tsc --noEmit
```

Fix any type errors before continuing.

- [ ] **Step 5: Commit**

```bash
git add src/rendezvous/types.ts package.json package-lock.json
git commit -m "chore: add matchlock dependency, split primitive types"
```

---

## Task 14: Rendezvous — update all import sites

**Update each file. For each: edit → build check → next.**

- [ ] **Step 1: Update `src/rendezvous/detection.ts`**

Change:
```typescript
import { deriveMatchToken } from './crypto.js';
```
To:
```typescript
import { deriveMatchToken } from 'matchlock';
```

- [ ] **Step 2: Update `src/rendezvous/submission.ts`**

Change the import from `./crypto.js` to:
```typescript
import { commitToken, verifyCommitment } from 'matchlock';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
```

Then add these two inline helpers (they are local utilities, not part of the matchlock primitive surface):

```typescript
function isValidMatchToken(token: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(token);
}
function randomHex(bytes: number): string {
  return bytesToHex(randomBytes(bytes));
}
```

- [ ] **Step 3: Update `src/federation/manager.ts`**

Change the import from `../rendezvous/crypto.js` to:
```typescript
import { encryptForPublicKey, serializeEncryptedBox } from 'matchlock';
```

- [ ] **Step 4: Update `src/scripts/seed.ts`**

Change the import from `../rendezvous/crypto.js` to:
```typescript
import { deriveMatchTokens, deriveMatchToken, deriveNullifier } from 'matchlock';
```

- [ ] **Step 5: Update `src/server/index.ts`**

Change:
```typescript
import { decryptWithPrivateKey, deserializeEncryptedBox, hash, verifySignedRequest } from '../rendezvous/crypto.js';
import { getPsiService, PsiJoinRequest, PsiJoinResponse, OwnerHeldPsiSetup, PendingPsiRequest, PsiResponseRecord, OwnerPsiProcessingResult } from '../psi/index.js';
```
To:
```typescript
import { decryptWithPrivateKey, deserializeEncryptedBox, verifySignedRequest } from 'matchlock';
import { getPsiService } from 'matchlock';
import type { PsiJoinResponse, OwnerHeldPsiSetup, PendingPsiRequest, PsiResponseRecord, OwnerPsiProcessingResult } from 'matchlock';
```

`hash` is used in two places in `server/index.ts` (for `authTokenHash`). It is a local utility, not part of the matchlock surface. Add this inline definition immediately after the imports:

```typescript
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
function hash(data: string | Uint8Array): string {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha256(input));
}
```

Also define `PsiJoinRequest` locally (since it has the Rendezvous-specific `authToken`):
```typescript
interface PsiJoinRequest {
  poolId: string;
  authToken: string;
  psiRequest: string;
}
```

- [ ] **Step 6: Update `src/rendezvous/storage.ts`**

Change the import from `../psi/types.js` to:
```typescript
import type { OwnerHeldPsiSetup, PendingPsiRequest, PsiResponseRecord } from 'matchlock';
```

- [ ] **Step 7: Update `src/rendezvous/index.ts`**

Replace `export * from './crypto.js'` with named exports from matchlock:
```typescript
export {
  generateKeypair,
  deriveMatchToken,
  deriveMatchTokens,
  commitToken,
  commitTokens,
  verifyCommitment,
  deriveNullifier,
  encryptForPublicKey,
  decryptWithPrivateKey,
  serializeEncryptedBox,
  deserializeEncryptedBox,
  generateSigningKeypair,
  sign,
  verify,
  createSignedRequest,
  verifySignedRequest,
} from 'matchlock';
export type {
  MatchToken,
  CommitHash,
  PublicKey,
  PrivateKey,
  EncryptedBox,
  SigningPublicKey,
  SigningPrivateKey,
  Signature,
} from 'matchlock';
```

Remove the `import * as crypto from './crypto.js'` line.

- [ ] **Step 8: Verify full build**

```bash
npx tsc --noEmit
```

Expected: no errors. Fix any that appear before continuing.

- [ ] **Step 9: Commit**

```bash
git add src/
git commit -m "chore: update all import sites to use matchlock"
```

---

## Task 15: Delete old files and verify

- [ ] **Step 1: Delete the extracted files**

```bash
rm ~/dev/rendezvous/src/rendezvous/crypto.ts
rm -rf ~/dev/rendezvous/src/psi/
```

- [ ] **Step 2: Verify no stale imports remain**

```bash
cd ~/dev/rendezvous
grep -r "rendezvous/crypto" src/
grep -r "from '../psi/" src/
grep -r "from './psi/" src/
grep -r "psi/types" src/
```

Expected: no matches.

- [ ] **Step 3: Full build**

```bash
npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 4: Run tests**

```bash
npm test
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: remove extracted crypto.ts and psi/ — now consumed from matchlock"
```

---

## Verification Checklist

Before declaring done:

- [ ] `~/dev/matchlock/` builds cleanly (`npm run build`)
- [ ] All matchlock tests pass (`npm test`)
- [ ] `~/dev/rendezvous/` builds cleanly (`npx tsc --noEmit`)
- [ ] All rendezvous tests pass (`npm test`)
- [ ] No grep matches for `rendezvous/crypto` or `../psi/` in rendezvous src
- [ ] `examples/mutual-match.ts` runs end-to-end
- [ ] `README.md` and `PROTOCOL.md` exist in matchlock repo
