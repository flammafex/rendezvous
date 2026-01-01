# Anonymous Federation Tokens with Freebird

## Problem

Currently, federation messages include a `from` field that identifies the source instance:

```typescript
interface FederationMessage {
  from: string;  // Instance ID - enables tracking!
  timestamp: number;
  messageId: string;
}
```

This allows:
- Intermediate relays to track which instances users come from
- Traffic analysis correlating users to their home instances
- Building social graphs of instance relationships

## Solution: Freebird VOPRF Tokens

Replace instance identification with **unlinkable Freebird tokens** that prove authorization without revealing identity.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ISSUANCE (one-time)                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Instance A                         Freebird Issuer         │
│  ┌─────────┐                        ┌─────────────┐         │
│  │ User    │ ──── blind(input) ───→ │   VOPRF     │         │
│  │         │ ←── evaluate(blind) ── │   Server    │         │
│  │         │     + DLEQ proof       │             │         │
│  │         │                        └─────────────┘         │
│  │         │ finalize() → token                             │
│  └─────────┘ (unlinkable to issuance)                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    FEDERATION MESSAGE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Instance A              Relay B              Instance C    │
│  ┌─────────┐            ┌───────┐            ┌─────────┐   │
│  │  User   │ ─────────→ │       │ ─────────→ │  Pool   │   │
│  │         │            │       │            │  Owner  │   │
│  └─────────┘            └───────┘            └─────────┘   │
│                                                             │
│  Message contains:                                          │
│  {                                                          │
│    authToken: "freebird:v1:...",  // Proves authorization   │
│    // NO 'from' field - origin is hidden!                   │
│    poolId: "...",                                           │
│    encryptedPayload: "..."                                  │
│  }                                                          │
│                                                             │
│  Relay B can verify token is valid but CANNOT:              │
│  - Identify which instance/user sent it                     │
│  - Correlate with previous messages (unlinkable)            │
│  - Learn anything about the sender                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Token Properties

| Property | How Freebird Provides It |
|----------|-------------------------|
| **Authorization** | Valid VOPRF token = authorized to participate |
| **Unlinkability** | Each token uses random blinding factor |
| **Non-correlation** | Issuer can't link issuance to redemption |
| **Replay protection** | Nullifier prevents double-use |
| **Verifiable** | DLEQ proof ensures honest evaluation |

## Implementation

### 1. New Types

```typescript
// src/federation/types.ts

/**
 * Anonymous federation message - no 'from' field
 */
interface AnonymousFederationMessage {
  type: FederationMessageType;
  /** Freebird token proving authorization (replaces 'from') */
  authToken: string;
  /** Message timestamp */
  timestamp: number;
  /** Unique message ID */
  messageId: string;
}

/**
 * Token relay with anonymous sender
 */
interface AnonymousTokenRelayMessage extends AnonymousFederationMessage {
  type: 'token_relay';
  poolId: string;
  matchTokens: string[];
  nullifier: string;
  // Note: NO 'from' field!
}

/**
 * Anonymous join request
 */
interface AnonymousJoinRequestMessage extends AnonymousFederationMessage {
  type: 'join_request';
  poolId: string;
  publicKey: string;
  encryptedPayload: string;
  // Note: NO 'from' field!
}
```

### 2. Freebird Client Integration

```typescript
// src/federation/freebird-client.ts

import { FreebirdClient } from '@freebird/client';

export class FederationAuthProvider {
  private client: FreebirdClient;
  private tokenCache: Map<string, { token: string; expires: number }> = new Map();

  constructor(issuerUrl: string) {
    this.client = new FreebirdClient({ issuerUrl });
  }

  /**
   * Get an anonymous auth token for federation
   * Each call returns an unlinkable token
   */
  async getAuthToken(scope: string = 'federation'): Promise<string> {
    // Generate fresh input for unlinkability
    const input = `${scope}:${crypto.randomUUID()}`;

    // VOPRF blind → evaluate → finalize
    const { blindedInput, blindState } = await this.client.blind(input);
    const evaluation = await this.client.evaluate(blindedInput);
    const token = await this.client.finalize(evaluation, blindState);

    return token.serialize(); // Base64 token string
  }

  /**
   * Verify an incoming auth token
   */
  async verifyAuthToken(token: string): Promise<boolean> {
    return this.client.verify(token);
  }
}
```

### 3. Updated Federation Manager

```typescript
// src/federation/manager.ts (modified)

export class FederationManager extends EventEmitter {
  private authProvider: FederationAuthProvider;

  constructor(config: FederationConfig) {
    super();
    this.config = config;

    // Initialize Freebird auth provider
    if (config.freebirdIssuerUrl) {
      this.authProvider = new FederationAuthProvider(config.freebirdIssuerUrl);
    }
  }

  /**
   * Relay tokens anonymously - no instance identification
   */
  async relayTokensAnonymous(
    poolId: string,
    matchTokens: string[],
    nullifier: string
  ): Promise<void> {
    const pool = this.doc.pools[poolId];
    if (!pool) throw new Error('Pool not found');

    // Get fresh anonymous auth token
    const authToken = await this.authProvider.getAuthToken('token-relay');

    // Random delay for timing privacy
    await new Promise(r => setTimeout(r, this.getTimingNoise()));

    const relay: AnonymousTokenRelayMessage = {
      type: 'token_relay',
      authToken,  // Anonymous! Not instance ID
      timestamp: Date.now(),
      messageId: uuid(),
      poolId,
      matchTokens,
      nullifier,
      // NO 'from' field!
    };

    await this.sendToPeer(pool.ownerInstance, relay);
  }

  /**
   * Handle incoming anonymous message
   */
  private async handleAnonymousMessage(msg: AnonymousFederationMessage): Promise<void> {
    // Verify the Freebird token
    const isValid = await this.authProvider.verifyAuthToken(msg.authToken);
    if (!isValid) {
      console.warn('Invalid auth token, dropping message');
      return;
    }

    // Process message - we don't know who sent it, and that's the point!
    switch (msg.type) {
      case 'token_relay':
        this.emit('tokens:relayed', msg as AnonymousTokenRelayMessage);
        break;
      case 'join_request':
        this.emit('join:request', msg as AnonymousJoinRequestMessage);
        break;
    }
  }
}
```

### 4. Server Handler Updates

```typescript
// src/server/index.ts (modified)

// Handle anonymous token relays
federation.on('tokens:relayed', async (relay: AnonymousTokenRelayMessage) => {
  // Note: We don't know which instance this came from!
  console.log(`Received anonymous token relay for pool ${relay.poolId}`);

  try {
    rv.submitPreferences({
      poolId: relay.poolId,
      matchTokens: relay.matchTokens,
      nullifier: relay.nullifier,
    });
  } catch (err) {
    console.error('Failed to process anonymous tokens:', err);
  }
});
```

## Configuration

```bash
# Environment variables
FEDERATION_ENABLED=true
FREEBIRD_ISSUER_URL=https://freebird.example.com
FREEBIRD_VERIFIER_URL=https://freebird.example.com/verify

# Optional: Multiple issuers for federation trust
FREEBIRD_TRUSTED_ISSUERS=issuer1.example.com,issuer2.example.com
```

## Privacy Comparison

| Aspect | Before (Instance ID) | After (Freebird Token) |
|--------|---------------------|------------------------|
| **Sender Identity** | Visible to all relays | Hidden from everyone |
| **Cross-message Linking** | Easy (same `from`) | Impossible (unlinkable tokens) |
| **Traffic Analysis** | Instance patterns visible | Only token validity visible |
| **Replay Protection** | Via message ID | Via nullifier |
| **Authorization** | Implicit (connected = authorized) | Explicit (valid token) |

## Security Considerations

1. **Token Freshness**: Generate new token per message for unlinkability
2. **Nullifier Management**: Track nullifiers to prevent replay
3. **Issuer Trust**: Only accept tokens from trusted Freebird issuers
4. **Rate Limiting**: Issuers should rate-limit token issuance (Sybil resistance)

## Migration Path

1. **Phase 1**: Add Freebird token support alongside existing `from` field
2. **Phase 2**: Prefer anonymous tokens when both parties support it
3. **Phase 3**: Deprecate `from` field for privacy-sensitive messages
4. **Phase 4**: Remove `from` field entirely (breaking change)

## Effort Estimate

| Task | Effort |
|------|--------|
| Freebird client integration | 4-6 hours |
| New message types | 2 hours |
| Manager updates | 4 hours |
| Server handler updates | 2 hours |
| Testing | 4 hours |
| **Total** | **~2 days** |

## Dependencies

- Freebird issuer deployed and accessible
- `@freebird/client` npm package (or HTTP client)
- Trusted issuer configuration
