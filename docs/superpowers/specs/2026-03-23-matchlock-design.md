# Matchlock Design Spec

**Date:** 2026-03-23
**Status:** Approved
**Goal:** Extract the DH mutual-match primitive from Rendezvous into a standalone library so it can be recognized, adopted, and built upon independently.

---

## Problem

Rendezvous contains a novel cryptographic primitive — DH-based mutual match token derivation combined with PSI and an owner-held key architecture — that is buried inside an application. The novelty is invisible because the primitive has no independent identity, documentation, or distribution. Recognition and adoption require the primitive to stand on its own.

---

## Solution

Create a new sibling repository `~/dev/matchlock/` containing the extracted primitive as a publishable TypeScript library. Rendezvous becomes the reference application that consumes Matchlock, mirroring the existing relationship between Rendezvous and Freebird/Witness.

---

## What Matchlock Is

A TypeScript library (not an HTTP service). Pure local computation — no Docker, no server, no HTTP. Consumers import it and call functions.

**Runtime target: Node.js only.** The PSI layer requires `@openmined/psi.js` which loads WASM via Node's dynamic import. Browser support is out of scope.

### The primitive

**DH layer:** Two parties derive identical match tokens when they mutually select each other, using X25519 Diffie-Hellman with domain-separated hashing. Tokens are locally derived — no server interaction required.

```
Alice selects Bob:  token = H(DH(alice_priv, bob_pub) || poolId || "rendezvous-match-v1")
Bob selects Alice:  token = H(DH(bob_priv, alice_pub) || poolId || "rendezvous-match-v1")
// Same shared secret → same token
```

**PSI layer:** Private Set Intersection (via `@openmined/psi.js`) allows the server to process match queries without learning which tokens a participant submitted. The owner-held key architecture encrypts the PSI server key to the pool owner's X25519 public key — the server cannot process requests without owner participation.

Together these two layers form a complete privacy-preserving matching stack.

---

## Package Structure

```
~/dev/matchlock/
├── src/
│   ├── dh/
│   │   ├── index.ts          # deriveMatchToken, deriveMatchTokens
│   │   ├── commit.ts         # commitToken, verifyCommitment, commitTokens
│   │   ├── nullifier.ts      # deriveNullifier
│   │   ├── ecies.ts          # EncryptedBox, encryptForPublicKey, decryptWithPrivateKey,
│   │   │                     # serializeEncryptedBox, deserializeEncryptedBox (hardened)
│   │   └── signing.ts        # generateSigningKeypair, sign, verify,
│   │                         # createSignedRequest, verifySignedRequest
│   ├── psi/
│   │   ├── index.ts          # PsiService
│   │   ├── service.ts        # moved from rendezvous/src/psi/service.ts (pruned)
│   │   └── types.ts          # PSI-only types (see Type Boundary section)
│   ├── types.ts              # MatchToken, CommitHash, PublicKey, PrivateKey
│   └── index.ts              # re-exports everything
├── examples/
│   └── mutual-match.ts       # end-to-end DH + PSI flow, ~50 lines
├── README.md                 # protocol explanation — primary recognition artifact
├── PROTOCOL.md               # formal spec: security properties, threat model
├── package.json
└── tsconfig.json
```

---

## Type Boundary

`rendezvous/src/rendezvous/types.ts` mixes primitive types and application types. It must be split:

**Moves to Matchlock (`src/types.ts`):**
- `MatchToken`
- `CommitHash`
- `PublicKey`
- `PrivateKey`

**Stays in Rendezvous:**
- `Pool`, `Preference`, `Participant`, `VoterGate`, `FreebirdProof`, `WitnessProof`, and all other application types

Rendezvous imports the four primitive types from `matchlock`.

**`PsiJoinRequest` is split:** The PSI-specific fields move to Matchlock as `PsiClientRequest { psiRequest: string }`. Rendezvous defines its own `PsiJoinRequest` extending that with `authToken: string` (the Freebird proof field). This keeps Matchlock free of any dependency on the concept of Freebird tokens.

---

## PsiService: Owner-Held Key Path Only

The `PsiService` class currently has two parallel paths:

- **Server-held path:** `createSetup()` / `processRequest()` — has an unresolved `TODO: encrypt this!` and stores the PSI key in plaintext. This path is not called anywhere in Rendezvous.
- **Owner-held path:** `createOwnerEncryptedSetup()` / `processRequestWithDecryptedKey()` — the correct architecture, fully implemented.

The server-held path will be **removed** during extraction. Matchlock exports only the owner-held key architecture. This is a clean break with no migration needed (new library, no prior consumers).

---

## Hardening Required

The current ECIES in `crypto.ts` uses a hand-rolled stream cipher (XOR with SHA-256 blocks). Replace with **XChaCha20-Poly1305** from `@noble/ciphers` — consistent with the existing `@noble/*` dependency pattern. XChaCha20-Poly1305 is chosen over ChaCha20-Poly1305 to preserve the existing 24-byte nonce size.

This is a wire-format break. Since Matchlock is a new library with no prior deployed consumers, no migration path is needed — state this clearly in the changelog.

---

## Rendezvous Changes

**Removed:**
- `src/rendezvous/crypto.ts`
- `src/psi/` (entire directory)

**Split:**
- `src/rendezvous/types.ts` — primitive types removed, application types remain; add `import { MatchToken, CommitHash, PublicKey, PrivateKey } from 'matchlock'`

**Import sites requiring update** (all updated to `import { ... } from 'matchlock'`):
- `src/scripts/seed.ts` — imports `deriveMatchTokens`, `deriveMatchToken`, `deriveNullifier`
- `src/federation/manager.ts` — imports `encryptForPublicKey`, `serializeEncryptedBox`
- `src/server/index.ts` — imports from both crypto and psi
- `src/rendezvous/storage.ts` — imports from `psi/types.ts`
- `src/rendezvous/detection.ts` — imports `deriveMatchToken`
- `src/rendezvous/submission.ts` — imports `commitToken`, `verifyCommitment`, `isValidMatchToken`, `randomHex`
- `src/rendezvous/index.ts` — barrel re-exports `export * from './crypto.js'`; update to `export * from 'matchlock'` to preserve the existing public API surface
- `src/psi/service.ts` — imports `encryptForPublicKey`, `serializeEncryptedBox`; covered implicitly by the `src/psi/` directory removal, but noted here for completeness

Verify completeness after migration by grepping for `../rendezvous/crypto` and `../psi/` — there should be no matches.

**`package.json`:** Add `matchlock` as a dependency.

**README:** Add a "Built on" section listing Matchlock, Freebird, and Witness as the three primitives Rendezvous composes.

**Unchanged:** All application code — pools, federation, storage, gates, server, submissions.

---

## Documentation as Primary Artifact

The README and PROTOCOL.md in the Matchlock repo are not afterthoughts — they are the mechanism for recognition. They must:

- Name and explain the DH insight clearly
- State the security properties and what each party learns / does not learn
- Describe the threat model
- Explain the owner-held key architecture and why it matters
- Give usage examples (with a pointer to `examples/mutual-match.ts`)

The worked example in `examples/mutual-match.ts` is a cleaned-up version of the relevant logic from `rendezvous/src/scripts/seed.ts`. It shows the full DH + PSI flow end-to-end.

---

## Dependency Graph After

```
Rendezvous ──► Matchlock (DH + PSI)
Rendezvous ──► Freebird  (anonymous auth)
Rendezvous ──► Witness   (timestamping)
```

Matchlock joins Freebird and Witness as a SophiaDOS primitive with independent identity.

---

## NLNet Positioning

Matchlock is the fundable unit. Rendezvous is evidence it works in production. A future NLNet proposal frames it as: "a reusable privacy-preserving mutual match protocol — formal spec + hardened reference implementation — demonstrated in a working application."
