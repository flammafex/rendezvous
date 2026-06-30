# 🤝 Rendezvous

Two parties can discover if they mutually selected each other without revealing:
- Who the person selected (if not mutual)
- Who rejected whom
- That you even participated

**Use cases:** Dating, co-founder matching, hackathon team building, roommate search, mentor pairing, any N-to-N selection where privacy matters.

## How It Works

The key insight: Diffie-Hellman produces the same shared secret from either side.

```
Alice wants Bob:
  shared = DH(alice_private, bob_public)
  token = H(shared || pool_id || "match")

Bob wants Alice:
  shared = DH(bob_private, alice_public)  // Same shared secret!
  token = H(shared || pool_id || "match")  // Same token!
```

If both submit, the token appears twice → match detected.
If only one submits, token appears once → no information leaked.

## Features

### Core Privacy
- **Privacy-preserving matching** - Only mutual matches are revealed
- **Reveal on match** - Encrypted contact info decryptable only by mutual matches
- **Privacy delay** - Random 30s-3min delay before match computation prevents timing analysis
- **Decoy tokens** - Hides your true selection count from the server
- **Response padding** - All API responses padded to 8KB blocks to prevent size analysis
- **Ephemeral mode** - Auto-delete participant profiles after pool closes

### Private Set Intersection (PSI)
- **Owner-held key PSI** - Pool owners can use PSI to process match queries without learning joiner preferences
- **Provided by matchlock** - PSI operations are implemented in the `matchlock` package (which wraps `@openmined/psi.js` internally)
- **Cardinality-only mode** - Option to reveal only match count, not identities

### Federation
- **Cross-instance pools** - Discover and join pools across federated Rendezvous servers
- **Peer-to-peer sync** - Rendezvous instances connect directly via WebSocket (default port 3001)
- **Automerge CRDTs** - Pool metadata synced using conflict-free replicated data types
- **Anonymous messaging** - All federation messages use unlinkable Freebird tokens
- **Timing noise** - Random delays on federation messages to frustrate traffic analysis

### Access Control
- **Freebird integration** - Unlinkable eligibility proofs for pool creation and joining
- **Witness integration** - Timestamp attestation for match results
- **Invite-gated pools** - Require valid invite codes to join
- **Owner signatures** - Pool actions verified via Ed25519 signatures

### User Experience
- **QR code invites** - Share pools via scannable QR codes
- **Multi-device sync** - Transfer keys between devices via encrypted QR
- **PWA support** - Install as a mobile app, works offline

## Installation

```bash
npm install
npm run build
```

Requires Node.js 20+.

## Quick Start

```bash
# Seed the database with sample pools
npm run seed

# Start the web server
npm run server

# Open http://localhost:3000
```

The seed script creates demo pools with participants who have pre-selected the test user. Use the keypair printed by the seed script to get guaranteed matches.

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP server port | `3000` |
| `RENDEZVOUS_DATA_DIR` | Database directory | `./data` |
| `FREEBIRD_VERIFIER_URL` | Freebird verifier for invite codes | _(disabled)_ |
| `WITNESS_GATEWAY_URL` | Witness gateway for timestamps | _(disabled)_ |
| `FEDERATION_ENABLED` | Enable federation | `false` |
| `FEDERATION_PORT` | WebSocket port for federation | `3001` |
| `FEDERATION_PEERS` | Comma-separated peer endpoints | _(none)_ |
| `FREEBIRD_ISSUER_URL` | Required for federation auth | _(none)_ |

When `FREEBIRD_VERIFIER_URL` is set, pool creation requires a valid invite code. When unset, pool creation is open (development mode).

## Web UI

The web interface provides a complete flow:

1. **Pools** - Browse and create matching pools
2. **Join** - Register, browse participants, and make selections
3. **Discover** - Find your mutual matches after pool closes
4. **Keys** - Generate keypairs, manage identities, sync across devices

### Reveal on Match

When confirming your selections, you can add contact info and a message. This data is encrypted using the match token as the key—only someone who mutually selected you can decrypt it. The server stores only encrypted blobs.

## Programmatic Usage

```typescript
import {
  createRendezvous,
  generateKeypair,
  deriveMatchTokens,
  deriveNullifier
} from 'rendezvous';

// Create instance with optional adapters
const rv = createRendezvous({
  dbPath: './data/rendezvous.db',
  // freebird: new HttpFreebirdAdapter({ verifierUrl: '...' }),
  // witness: new HttpWitnessAdapter({ gatewayUrl: '...' }),
});

// Create a pool
const pool = rv.createPool({
  name: 'Team Matching',
  creatorPublicKey: creatorKey,
  creatorSigningKey: signingKey,
  revealDeadline: new Date(Date.now() + 24 * 3600000),
  ephemeral: true,
});

// Generate your keypair
const me = generateKeypair();

// Submit preferences
const theirKeys = ['abc...', 'def...'];
const tokens = deriveMatchTokens(me.privateKey, theirKeys, pool.id);
const nullifier = deriveNullifier(me.privateKey, pool.id);

rv.submitPreferences({
  poolId: pool.id,
  matchTokens: tokens,
  nullifier,
  revealData: [
    { matchToken: tokens[0], encryptedReveal: '...' },
  ],
});

// After pool closes, detect matches (async for witness attestation)
rv.closePool(pool.id);
const result = await rv.detectMatches(pool.id);

// Discover your matches locally
const myMatches = rv.discoverMyMatches(pool.id, me.privateKey, theirKeys);
for (const match of myMatches) {
  console.log(`Matched with: ${match.matchedPublicKey}`);
}
```

## Protocol Phases

1. **Pool Creation**: Operator creates pool with eligibility rules and deadline
2. **Commit Phase** (optional): Participants submit H(tokens) to prevent timing attacks
3. **Reveal Phase**: Participants submit actual tokens (+ optional encrypted contact info)
4. **Privacy Delay**: Random 30s-3min delay before match computation
5. **Detection**: Count token occurrences. Duplicates = matches.
6. **Discovery**: Each participant locally checks which of their tokens matched

## Privacy Features

### Decoy Tokens
When submitting preferences, clients add random decoy tokens. This hides your true selection count from the server.

### Privacy Delay
After a pool closes, match computation is delayed by a random 30s-3min interval. This prevents timing analysis that could correlate submission times with results.

### Response Padding
All API responses are padded to 8KB block boundaries. This prevents attackers from inferring information based on response sizes.

### Pseudonym Rotation
Generate a fresh keypair for each pool. This prevents correlation of your identity across pools—even if someone is in multiple pools with you, they can't link your profiles.

### Ephemeral Pools
Pool creators can enable ephemeral mode, which deletes all participant profiles after match detection. Only anonymous match tokens remain.

## Anti-Gaming Measures

- **Fishing attacks**: Limited by `maxPreferencesPerParticipant`
- **Timing attacks**: Prevented by commit-reveal phases and privacy delay
- **Sybil attacks**: Freebird nullifiers ensure one submission per identity
- **Eligibility gates**: Freebird tokens, invite lists, composite rules

## Project Structure

```
src/
├── rendezvous/
│   ├── types.ts          # Core type definitions
│   ├── crypto.ts         # DH tokens, encryption, signatures
│   ├── storage.ts        # SQLite persistence
│   ├── pool.ts           # Pool management
│   ├── submission.ts     # Preference submission
│   ├── detection.ts      # Match detection
│   ├── gates/            # Eligibility gates
│   ├── adapters/         # Freebird & Witness HTTP clients
│   └── index.ts          # Public API
├── psi/
│   ├── types.ts          # PSI type definitions
│   └── service.ts        # PSI operations (via matchlock)
├── federation/
│   ├── types.ts          # Federation message types
│   ├── manager.ts        # CRDT sync & peer management
│   └── freebird-client.ts # Anonymous auth tokens
├── server/
│   └── index.ts          # REST API & WebSocket server
├── scripts/
│   └── seed.ts           # Demo data seeder
├── cli/
│   └── index.ts          # CLI commands
└── index.ts              # Main entry point
public/
├── index.html            # Web UI
├── js/modules/           # Modular frontend components
├── css/                  # Stylesheets
├── sw.js                 # Service worker for PWA
└── manifest.json         # PWA manifest
```

## Testing

```bash
npm test
```

## API Endpoints

### Pools
- `GET /api/pools` - List pools
- `POST /api/pools` - Create pool (requires invite if Freebird configured)
- `GET /api/pools/:id` - Get pool details
- `POST /api/pools/:id/close` - Close pool (owner-only, signed)

### Participants
- `POST /api/pools/:id/participants` - Register in pool
- `GET /api/pools/:id/participants` - List participants

### Preferences
- `POST /api/pools/:id/submit` - Submit match tokens
- `POST /api/pools/:id/reveal` - Reveal committed preferences

### PSI (Owner-Held Key)
- `POST /api/pools/:id/psi/owner-setup` - Owner creates PSI setup
- `POST /api/pools/:id/psi/request` - Client submits PSI request
- `GET /api/pools/:id/psi/pending` - Owner polls pending requests
- `POST /api/pools/:id/psi/responses` - Owner submits responses
- `GET /api/psi/response/:requestId` - Client polls for result

### PSI Client Helpers
- `POST /api/psi/create-request` - Create PSI request from inputs
- `POST /api/psi/compute-intersection` - Compute intersection locally
- `POST /api/psi/compute-cardinality` - Compute match count only (more private)

### Federation
- `GET /api/federation` - Federation status
- `GET /api/federation/pools` - List federated pools
- `POST /api/federation/announce/:poolId` - Announce pool to federation
- `POST /api/federation/join/:poolId` - Join federated pool

## License

Apache-2.0
