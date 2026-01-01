/**
 * Freebird HTTP Adapter
 *
 * Connects to a Freebird verifier service for token verification.
 * Uses VOPRF (Verifiable Oblivious Pseudorandom Function) for
 * anonymous, unlinkable eligibility proofs.
 *
 * Token flow:
 * 1. User obtains blinded token from issuer (POST /v1/oprf/issue)
 * 2. User unblinds to create final token locally
 * 3. User presents token to verifier for validation (POST /v1/verify)
 *
 * Updated for Freebird API as of Dec 2025.
 */

import { FreebirdAdapter } from '../gates/types.js';
import { FreebirdProof } from '../types.js';

export interface FreebirdConfig {
  /** URL of the Freebird verifier (e.g., http://localhost:8082) */
  verifierUrl: string;
  /** Request timeout in ms (default: 5000) */
  timeout?: number;
}

/** Response from POST /v1/verify */
interface VerifyResponse {
  ok: boolean;
  verified_at: number;
  error?: string;
}

/**
 * HTTP-based Freebird adapter for production use.
 * Compatible with Freebird verifier API (Dec 2025).
 */
export class HttpFreebirdAdapter implements FreebirdAdapter {
  private verifierUrl: string;
  private timeout: number;

  constructor(config: FreebirdConfig) {
    this.verifierUrl = config.verifierUrl.replace(/\/$/, '');
    this.timeout = config.timeout ?? 5000;
  }

  /**
   * Verify a VOPRF token.
   *
   * @param proof - Contains token_b64, issuer_id, expiration, and epoch
   * @returns True if token is valid and not replayed
   */
  async verify(proof: FreebirdProof): Promise<boolean> {
    if (this.isExpired(proof)) {
      return false;
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      // Freebird API expects: token_b64, issuer_id, exp, epoch
      const response = await fetch(`${this.verifierUrl}/v1/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token_b64: proof.tokenValue,
          issuer_id: proof.issuerId,
          exp: Math.floor(proof.expiration / 1000), // Convert ms to seconds
          epoch: proof.epoch ?? this.currentEpoch(),
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const status = response.status;
        if (status === 401) {
          console.error('Freebird: token verification failed or replayed');
        } else if (status === 400) {
          console.error('Freebird: invalid token format or epoch');
        }
        return false;
      }

      const result = (await response.json()) as VerifyResponse;
      return result.ok === true;
    } catch (error) {
      console.error('Freebird verification error:', error);
      return false;
    }
  }

  isExpired(proof: FreebirdProof): boolean {
    // Add 5 minute clock skew tolerance
    const clockSkewMs = 5 * 60 * 1000;
    return Date.now() > proof.expiration + clockSkewMs;
  }

  /**
   * Verify a raw invite code (base64 token string).
   *
   * This is a convenience method that constructs a FreebirdProof from
   * a raw token string using default issuer and current epoch.
   *
   * @param inviteCode - Base64-encoded VOPRF token
   * @param issuerId - Issuer ID (default: 'default')
   * @returns True if token is valid
   */
  async verifyInviteCode(inviteCode: string, issuerId: string = 'default'): Promise<boolean> {
    // Construct a FreebirdProof from the raw token
    // Tokens are typically valid for 24 hours from issue
    const proof = {
      tokenValue: inviteCode,
      issuerId,
      expiration: Date.now() + 86400000, // Assume valid for 24h
      epoch: this.currentEpoch(),
    };

    return this.verify(proof);
  }

  /**
   * Calculate current epoch (day-based by default).
   * Epochs are used for key rotation and token scoping.
   */
  private currentEpoch(): number {
    const epochDurationSec = 86400; // 1 day
    return Math.floor(Date.now() / 1000 / epochDurationSec);
  }
}
