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

### The primitive

**DH layer:** Two parties derive identical match tokens when they mutually select each other, using X25519 Diffie-Hellman with domain-separated hashing. Tokens are locally derived — no server interaction required.

```
Alice selects Bob:  token = H(DH(alice_priv, bob_pub) || poolId || "rendezvous-match-v1")
Bob selects Alice:  token = H(DH(bob_priv, alice_pub) || poolId || "rendezvous-match-v1")
// Same shared secret → same token
```

**PSI layer:** Private Set Intersection (via `@openmined/psi.js`) allows the server to process match queries without learning which tokens a participant submitted. Combines with the owner-held key architecture: the PSI server key is encrypted to the pool owner's X25519 public key, so the server cannot process requests without owner participation.

Together these two layers form a complete privacy-preserving matching stack.

---

## Package Structure

```
~/dev/matchlock/
├── src/
│   ├── dh/
│   │   ├── index.ts          # deriveMatchToken, deriveMatchTokens
│   │   ├── commit.ts         # commitToken, verifyCommitment
│   │   ├── nullifier.ts      # deriveNullifier
│   │   ├── ecies.ts          # encryptForPublicKey, decryptWithPrivateKey (hardened)
│   │   └── signing.ts        # generateSigningKeypair, sign, verify, createSignedRequest
│   ├── psi/
│   │   ├── index.ts          # PsiService
│   │   ├── service.ts        # moved from rendezvous/src/psi/service.ts
│   │   └── types.ts          # moved from rendezvous/src/psi/types.ts
│   └── index.ts              # re-exports everything
├── README.md                 # protocol explanation — primary recognition artifact
├── PROTOCOL.md               # formal spec: security properties, threat model
├── package.json
└── tsconfig.json
```

---

## Hardening Required

The current `crypto.ts` uses a hand-rolled stream cipher (XOR with SHA-256 blocks). This must be replaced with a proper AEAD before the library is published. Use `@noble/ciphers` (ChaCha20-Poly1305) — consistent with the existing `@noble/*` dependency pattern across the SophiaDOS ecosystem.

The `TODO: encrypt this!` comment in `psi/service.ts:135` (the simpler server-held key path) should be resolved — either fully implement it or remove the path in favor of the owner-held key architecture exclusively.

---

## Rendezvous Changes

**Removed:**
- `src/rendezvous/crypto.ts`
- `src/psi/` (entire directory)

**Changed:**
- All imports from the above files updated to `import { ... } from 'matchlock'`
- `package.json` adds `matchlock` as a dependency
- README gets a "Built on" section listing Matchlock, Freebird, and Witness

**Unchanged:**
- All application code: pools, federation, storage, gates, server, submissions

---

## Documentation as Primary Artifact

The README and PROTOCOL.md in the Matchlock repo are not afterthoughts — they are the mechanism for recognition. They must:

- Name and explain the DH insight clearly
- State the security properties and what each party learns/does not learn
- Describe the threat model
- Explain the owner-held key architecture and why it matters
- Give usage examples

This is where the privacy/crypto community and potential funders land.

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
