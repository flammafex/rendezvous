/**
 * Freebird Client for Anonymous Federation Tokens
 *
 * Provides anonymous authorization tokens using Freebird's VOPRF protocol.
 * Tokens prove authorization without revealing identity.
 *
 * This implementation wraps the vendored Freebird SDK
 * (vendor/freebird-sdk) for client-side VOPRF token issuance, replacing the
 * removed server-side "simple" endpoints (/v1/token/simple and
 * /v1/oprf/issue-simple) with the SDK's real VOPRF blind-issue-unblind flow.
 */

import { FreebirdClient as SdkFreebirdClient } from '../vendor/freebird-sdk/src/index.js';
import type { FreebirdToken as SdkFreebirdToken } from '../vendor/freebird-sdk/src/types.js';

/**
 * Issuer metadata from /.well-known/issuer
 */
interface IssuerMetadata {
  issuer_id: string;
  voprf: {
    suite: string;
    kid: string;
    pubkey: string;
  };
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
  private sdk: SdkFreebirdClient;
  private issuerUrl: string;
  private metadata: IssuerMetadata | null = null;
  private metadataExpiry: number = 0;

  constructor(config: { issuerUrl: string; verifierUrl?: string }) {
    this.issuerUrl = config.issuerUrl.replace(/\/$/, '');
    // The SDK requires a verifier scope; default to the issuer URL like the
    // previous implementation did.
    const verifierUrl = config.verifierUrl?.replace(/\/$/, '') || this.issuerUrl;
    this.sdk = new SdkFreebirdClient({ issuerUrl: this.issuerUrl, verifierUrl });
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
   * Request a new anonymous token.
   *
   * Uses the vendored SDK's client-side VOPRF issuance for unlinkability
   * (the issuer never sees the unblinded token). The `scope` argument is
   * accepted for API compatibility; the SDK binds tokens to the verifier
   * scope discovered from the verifier's metadata.
   */
  async requestToken(scope: string = 'federation'): Promise<FreebirdToken> {
    const sdkToken = await this.sdk.issueToken();
    return this.mapSdkToken(sdkToken);
  }

  /**
   * Map an SDK token into the Rendezvous FreebirdToken shape.
   *
   * The SDK token carries no exp/epoch, so we set sensible defaults:
   * exp = now + 24h (Unix seconds), epoch = 0.
   */
  private mapSdkToken(sdkToken: SdkFreebirdToken): FreebirdToken {
    return {
      token: sdkToken.tokenValue,
      issuerId: sdkToken.issuerId,
      exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
      epoch: 0,
    };
  }

  /**
   * Verify a token
   */
  async verifyToken(token: FreebirdToken): Promise<boolean> {
    const sdkToken: SdkFreebirdToken = {
      tokenValue: token.token,
      issuerId: token.issuerId,
    };
    return this.sdk.verifyToken(sdkToken);
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
