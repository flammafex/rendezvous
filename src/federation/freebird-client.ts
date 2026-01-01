/**
 * Freebird Client for Anonymous Federation Tokens
 *
 * Provides anonymous authorization tokens using Freebird's VOPRF protocol.
 * Tokens prove authorization without revealing identity.
 */

/**
 * Issuer metadata from /.well-known/issuer
 */
interface IssuerMetadata {
  issuer_id: string;
  voprf: {
    suite: string;
    kid: string;
    pubkey: string;
    exp_sec: number;
  };
  current_epoch: number;
}

/**
 * Token issuance response
 */
interface IssueResponse {
  token: string;
  proof: string;
  kid: string;
  exp: number;
  epoch: number;
}

/**
 * Token verification response
 */
interface VerifyResponse {
  ok: boolean;
  error?: string;
  verified_at: number;
}

/**
 * A Freebird token with its metadata
 */
export interface FreebirdToken {
  /** Base64url-encoded token */
  token: string;
  /** Issuer ID */
  issuerId: string;
  /** Expiration timestamp (Unix seconds) */
  exp: number;
  /** Epoch for key rotation */
  epoch: number;
}

/**
 * Serialized token for transport in federation messages
 */
export interface SerializedFreebirdToken {
  /** Format version */
  v: 1;
  /** Token data */
  t: string;
  /** Issuer ID */
  i: string;
  /** Expiration */
  e: number;
  /** Epoch */
  p: number;
}

/**
 * Freebird client for anonymous token operations
 */
export class FreebirdClient {
  private issuerUrl: string;
  private verifierUrl: string;
  private metadata: IssuerMetadata | null = null;
  private metadataExpiry: number = 0;

  constructor(config: { issuerUrl: string; verifierUrl?: string }) {
    this.issuerUrl = config.issuerUrl.replace(/\/$/, '');
    this.verifierUrl = config.verifierUrl?.replace(/\/$/, '') || this.issuerUrl;
  }

  /**
   * Get issuer metadata (cached)
   */
  async getMetadata(): Promise<IssuerMetadata> {
    const now = Date.now();
    if (this.metadata && this.metadataExpiry > now) {
      return this.metadata;
    }

    const response = await fetch(`${this.issuerUrl}/.well-known/issuer`);
    if (!response.ok) {
      throw new Error(`Failed to fetch issuer metadata: ${response.status}`);
    }

    this.metadata = await response.json() as IssuerMetadata;
    // Cache for 5 minutes
    this.metadataExpiry = now + 5 * 60 * 1000;
    return this.metadata!;
  }

  /**
   * Request a new anonymous token
   *
   * Note: This simplified implementation calls the issuer's token endpoint directly.
   * For maximum privacy (issuer can't link request to token), client-side VOPRF
   * blinding should be implemented. This can be added later with a WASM binding
   * or pure JS P-256 implementation.
   */
  async requestToken(scope: string = 'federation'): Promise<FreebirdToken> {
    // Generate random input for unlinkability
    const input = new Uint8Array(32);
    crypto.getRandomValues(input);

    // For now, use the simple token endpoint if available
    // This is less private but works without client-side VOPRF
    const response = await fetch(`${this.issuerUrl}/v1/token/simple`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope,
        input_b64: Buffer.from(input).toString('base64url'),
      }),
    });

    if (!response.ok) {
      // Fall back to OPRF endpoint with server-side blinding
      return this.requestTokenViaOprf(scope);
    }

    const data = await response.json() as IssueResponse;
    const metadata = await this.getMetadata();

    return {
      token: data.token,
      issuerId: metadata.issuer_id,
      exp: data.exp,
      epoch: data.epoch,
    };
  }

  /**
   * Request token via full OPRF protocol
   * Requires server to handle blinding (less private but functional)
   */
  private async requestTokenViaOprf(scope: string): Promise<FreebirdToken> {
    // Generate random input
    const input = new Uint8Array(32);
    crypto.getRandomValues(input);
    const inputB64 = Buffer.from(input).toString('base64url');

    // Request server-side blinding and issuance
    // This endpoint handles the full OPRF flow server-side
    const response = await fetch(`${this.issuerUrl}/v1/oprf/issue-simple`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        input_b64: inputB64,
        scope,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token issuance failed: ${response.status}`);
    }

    const data = await response.json() as IssueResponse & { finalized_token?: string };
    const metadata = await this.getMetadata();

    return {
      token: data.finalized_token || data.token,
      issuerId: metadata.issuer_id,
      exp: data.exp,
      epoch: data.epoch,
    };
  }

  /**
   * Verify a token
   */
  async verifyToken(token: FreebirdToken): Promise<boolean> {
    const response = await fetch(`${this.verifierUrl}/v1/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token_b64: token.token,
        issuer_id: token.issuerId,
        exp: token.exp,
        epoch: token.epoch,
      }),
    });

    if (!response.ok) {
      return false;
    }

    const data = await response.json() as VerifyResponse;
    return data.ok;
  }

  /**
   * Serialize a token for transport in federation messages
   */
  static serializeToken(token: FreebirdToken): string {
    const data: SerializedFreebirdToken = {
      v: 1,
      t: token.token,
      i: token.issuerId,
      e: token.exp,
      p: token.epoch,
    };
    return Buffer.from(JSON.stringify(data)).toString('base64url');
  }

  /**
   * Deserialize a token from federation message
   */
  static deserializeToken(serialized: string): FreebirdToken {
    const data: SerializedFreebirdToken = JSON.parse(
      Buffer.from(serialized, 'base64url').toString('utf-8')
    );

    if (data.v !== 1) {
      throw new Error(`Unsupported token version: ${data.v}`);
    }

    return {
      token: data.t,
      issuerId: data.i,
      exp: data.e,
      epoch: data.p,
    };
  }
}

/**
 * Federation auth provider using Freebird tokens
 */
export class FederationAuthProvider {
  private client: FreebirdClient;
  private cachedToken: FreebirdToken | null = null;
  private tokenExpiry: number = 0;

  constructor(issuerUrl: string, verifierUrl?: string) {
    this.client = new FreebirdClient({ issuerUrl, verifierUrl });
  }

  /**
   * Get a fresh anonymous auth token for a federation message
   * Each call can return a new unlinkable token for maximum privacy
   */
  async getAuthToken(freshToken: boolean = true): Promise<string> {
    // For maximum privacy, always get a fresh token
    if (freshToken || !this.cachedToken || this.tokenExpiry < Date.now()) {
      this.cachedToken = await this.client.requestToken('federation');
      // Cache until 1 minute before expiry
      this.tokenExpiry = this.cachedToken.exp * 1000 - 60_000;
    }

    return FreebirdClient.serializeToken(this.cachedToken);
  }

  /**
   * Verify an incoming auth token
   */
  async verifyAuthToken(serializedToken: string): Promise<boolean> {
    try {
      const token = FreebirdClient.deserializeToken(serializedToken);

      // Check expiry locally first
      if (token.exp * 1000 < Date.now()) {
        return false;
      }

      return this.client.verifyToken(token);
    } catch {
      return false;
    }
  }
}
