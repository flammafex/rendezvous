# AGENTS.md

Guidance for Codex / AI coding agents working in this repository. Read this before making changes.

## What this is

Rendezvous is a privacy-preserving mutual-matching platform: two parties discover they mutually
selected each other via Diffie-Hellman-derived match tokens, without revealing unilateral selections.
It is the application layer of a sibling-repo ecosystem ("Sophia v1"): `matchlock` owns all crypto/PSI,
`sophiados` owns contract test vectors + external services, `rendezvous` is the app/server/UI.

## Repo layout

```
src/
  index.ts                 # package entry; re-exports src/rendezvous/index.ts
  rendezvous/
    index.ts               # Rendezvous class — the public API facade
    types.ts               # core domain types (imports PublicKey/MatchToken/etc from matchlock)
    crypto.ts              # PURE RE-EXPORT facade over matchlock — no crypto implemented here
    storage.ts             # RendezvousStore interface + SQLiteStore + InMemoryStore
    pool.ts                # pool lifecycle / phase management
    submission.ts          # commit-reveal, nullifier enforcement, decoy token padding
    detection.ts           # token-counting match detection, local discovery, integrity checks
    gates/                 # eligibility gates (open / invite-list / freebird / composite)
    adapters/              # freebird.ts, witness.ts — HTTP clients for external services
  psi/
    service.ts             # PSI facade; extends matchlock's PsiService
    types.ts               # PSI types
  federation/
    manager.ts             # CRDT sync (Automerge) over WebSocket; anonymous Freebird messaging
    freebird-client.ts     # anonymous auth tokens
    types.ts
  server/index.ts          # Express REST API + WebSocket + auto-close scheduler (1681 lines)
  cli/index.ts             # commander-based CLI
  scripts/seed.ts          # demo data seeder
public/                     # static web UI (vanilla JS, PWA)
  js/modules/               # api, browse, crypto, discover, pools, keys, qr, state, sync, theme, ui
  sw.js, manifest.json
test/                       # jest (ESM): rendezvous, crypto, contract-matchlock-vectors, live-services
docs/                       # ANONYMOUS_FEDERATION_TOKENS.md, PSI_INTEGRATION.md, superpowers/{specs,plans}/
.forgejo/workflows/ci.yml   # CI: build + test on Node 20
```

## Setup

Requires Node.js >= 20 and the sibling `../matchlock` repo present (declared as `"matchlock": "file:../matchlock"`).
`matchlock` must be built (`dist/` present) before rendezvous can build.

```bash
npm install        # will fail if ../matchlock is missing
npm run build      # tsc -> dist/
```

## Run / test / lint / build

```bash
npm run build           # tsc (required before server/seed/cli; tests use ts-jest on the fly)
npm run dev             # tsc --watch
npm run server          # node dist/server/index.js  (HTTP :3000, federation WS :3001 if enabled)
npm run seed            # seed demo pools; prints a test keypair for guaranteed matches
npm run cli             # CLI entrypoint
npm test                # jest ESM via --experimental-vm-modules (43 tests, 3 suites)
npm run test:contracts  # sophia/v1 KAT conformance — REQUIRES ../sophiados present
npm run test:live       # live Freebird+Witness seam; not in default testMatch; needs services running
npm run test:watch
npm run clean           # rm -rf dist data
```

### Lint is currently non-functional
`npm run lint` runs `eslint src/` but eslint is not in devDependencies and there is no eslint config
file in the repo. Do not assume lint passes; do not add lint-only changes to a PR without first
restoring the toolchain. CI does not run lint.

## Coding conventions

- **Strict TypeScript**, ES2022, NodeNext module resolution. ESM (`"type": "module"`).
- **Always use `.js` extensions in relative imports** even for `.ts` sources (NodeNext requirement):
  `from './storage.js'`, not `from './storage'`.
- **Facade pattern for crypto/PSI:** `src/rendezvous/crypto.ts` and `src/psi/service.ts` only re-export
  `matchlock`. Never implement crypto here — add it to `matchlock` and re-export.
- **Storage:** `RendezvousStore` interface with two impls (`SQLiteStore` for prod, `InMemoryStore` for
  tests). New persistence needs go through the interface and both impls.
- **Manager classes** (`PoolManager`, `SubmissionManager`, `MatchDetector`, `GateSystem`) are wired in
  the `Rendezvous` constructor in `src/rendezvous/index.ts`.
- **Typed errors:** throw `RendezvousError` with a `RendezvousErrorCode` enum value; the server maps
  these to HTTP 400.
- **Owner auth:** owner-only mutations require Ed25519 signed requests with timestamp, verified via
  `verifyOwnerSignature` in `src/server/index.ts`.
- **Privacy invariants are load-bearing.** Before changing any of these, read the surrounding comments
  and confirm you understand the threat model:
  - Decoy tokens (3–8 random tokens per submission) in `submission.ts`
  - 8KB response padding middleware in `server/index.ts`
  - 30s–3min random privacy delay before match computation (manual close + auto-close scheduler)
  - Fail-closed Freebird connectivity checks (pool creation blocked if verifier unreachable)
  - Ephemeral pool cleanup (deletes participant profiles after detection)
- JSDoc on public methods; `// ===` section dividers in longer files.
- Contract versioning: cross-repo artifacts carry `contract_version: 'sophia/v1'` and `artifact_type`.

## Testing expectations

- Default `npm test` runs: `crypto.test.ts`, `rendezvous.test.ts`, `contract-matchlock-vectors.test.ts`.
- Tests are **library-layer only** — they exercise the `Rendezvous` class via `createTestRendezvous()`
  (in-memory store). There are **no HTTP/server tests**; the Express layer, padding middleware,
  fail-closed logic, and auto-close scheduler are untested.
- `test:contracts` loads known-answer vectors from `../sophiados/contracts/vectors/matchlock-vectors.json`.
  If `SOPHIADOS_CONTRACTS_DIR` is unset and `../sophiados` is absent, this test throws at import time.
- `test:live` is intentionally outside the default testMatch; it needs live Freebird + Witness services.
- When adding features, prefer tests at the library layer using `createTestRendezvous()`. Match-detection
  tests should cover mutual, unilateral, empty, and polyamorous cases (see existing patterns).

## PR / review expectations

- Keep changes minimal and focused. Don't refactor unrelated code in the same PR.
- `npm run build && npm test` must pass before requesting review (CI runs the same).
- If your change touches crypto behavior, it likely belongs in `matchlock`, not here — flag this in the
  PR description and confirm the contract KAT vectors still pass.
- If your change touches privacy invariants (decoys, padding, delays, fail-closed checks), call out the
  threat model in the PR description and add/adjust a test.
- Don't commit `data/`, `dist/`, `*.db`, `*.key`, `*_sk.bin`, or `.env` (see `.gitignore`).
- Match existing commit message style (no specific convention enforced; keep it descriptive).

## Constraints — do not touch without asking

1. **`matchlock` dependency** (`"file:../matchlock"`): do not change to a published version or alter
  the symlink without explicit instruction. Changes to crypto belong in matchlock, not rendezvous.
2. **Privacy invariants** listed above — changing decoy counts, padding size, delay ranges, or fail-closed
  behavior can break the threat model. Ask first.
3. **`src/rendezvous/crypto.ts`** is a re-export facade only. Do not add logic here.
4. **Contract vectors** (`../sophiados/contracts/`) are owned by another repo. Do not edit or vendor them.
5. **`src/server/index.ts`** is 1681 lines and central. Splitting it is reasonable but should be a
  dedicated, reviewed PR — don't opportunistically split while doing unrelated work.
6. **Environment / external services:** Freebird, Witness, and federation require live services and env
  vars (see README). Don't hardcode service URLs; use the existing env-var pattern.
7. **The `npm run lint` script** is broken (no eslint, no config). Don't "fix" it as a drive-by; it's a
  separate task that needs a config decision.

## Definition of done for a change

A change is complete when all of these hold:
- [ ] `npm run build` succeeds with no new TS errors.
- [ ] `npm test` passes (and `npm run test:contracts` if crypto/PSI is touched).
- [ ] New behavior has a test (library-layer via `createTestRendezvous()` unless HTTP-specific).
- [ ] No privacy invariant is weakened; if one is intentionally changed, the PR description explains why.
- [ ] Public API additions are reflected in `src/rendezvous/index.ts` re-exports if they should be public.
- [ ] No secrets, `data/`, `dist/`, or `.env` files are committed.
- [ ] README/docs updated if user-facing behavior or commands changed.
- [ ] If the change depends on `matchlock` or `sophiados`, that dependency is noted in the PR description.
