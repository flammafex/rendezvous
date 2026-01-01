/**
 * Witness HTTP Adapter
 *
 * Connects to a Witness gateway for timestamp attestation.
 * Witness provides cryptographic proof that data existed at a specific time.
 *
 * API endpoints:
 * - POST /v1/timestamp - Submit hash for timestamping (optional Freebird token)
 * - GET /v1/timestamp/:hash - Retrieve existing timestamp
 * - POST /v1/verify - Verify attestation
 * - GET /v1/config - Get network configuration
 *
 * Updated for Witness API as of Dec 2025 (BLS aggregation, Freebird auth).
 */

import { WitnessAdapter } from '../gates/types.js';
import { FreebirdProof, WitnessProof, WitnessSignature, WitnessAggregatedSignature } from '../types.js';

export interface WitnessConfig {
  /** Base URL of the Witness gateway (e.g., http://localhost:8080) */
  gatewayUrl: string;
  /** Request timeout in ms (default: 10000) */
  timeout?: number;
}

/** Freebird token for Witness authentication */
interface FreebirdTokenPayload {
  token_b64: string;
  issuer_id: string;
  exp: number;
}

/** Witness attestation structure */
interface WitnessAttestation {
  hash: number[]; // 32-byte array
  timestamp: number;
  network_id: string;
  sequence: number;
}

/** Multi-sig format */
interface MultiSigSignatures {
  signatures: Array<{
    witness_id: string;
    signature: number[]; // Ed25519 signature bytes
  }>;
}

/** BLS aggregated format */
interface AggregatedSignatures {
  signature: number[]; // Aggregated BLS signature bytes
  signers: string[];
}

/** Response from POST /v1/timestamp */
interface TimestampResponse {
  attestation: {
    attestation: WitnessAttestation;
    signatures: MultiSigSignatures | AggregatedSignatures;
  };
}

/** Response from POST /v1/verify */
interface VerifyResponse {
  valid: boolean;
  verified_signatures: number;
  required_signatures: number;
  message: string;
}

/**
 * HTTP-based Witness adapter for production use.
 * Compatible with Witness gateway API (Dec 2025).
 */
export class HttpWitnessAdapter implements WitnessAdapter {
  private gatewayUrl: string;
  private timeout: number;

  constructor(config: WitnessConfig) {
    this.gatewayUrl = config.gatewayUrl.replace(/\/$/, '');
    this.timeout = config.timeout ?? 10000;
  }

  /**
   * Request timestamp attestation for a hash.
   *
   * @param data - Hex-encoded SHA-256 hash to timestamp
   * @param freebirdProof - Optional Freebird token for Sybil resistance
   */
  async attest(data: string, freebirdProof?: FreebirdProof): Promise<WitnessProof> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      // Build request body
      const body: { hash: string; freebird_token?: FreebirdTokenPayload } = { hash: data };

      if (freebirdProof) {
        body.freebird_token = {
          token_b64: freebirdProof.tokenValue,
          issuer_id: freebirdProof.issuerId,
          exp: Math.floor(freebirdProof.expiration / 1000), // Convert ms to seconds
        };
      }

      const response = await fetch(`${this.gatewayUrl}/v1/timestamp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const status = response.status;
        if (status === 401) {
          throw new Error('Freebird token required');
        } else if (status === 403) {
          throw new Error('Freebird token invalid or already used');
        }
        throw new Error(`Witness attestation failed: ${status}`);
      }

      const result = await response.json() as TimestampResponse;
      const signed = result.attestation;
      const att = signed.attestation;

      // Convert hash bytes array to hex string
      const hashHex = Array.from(att.hash)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      // Determine signature format and convert
      const sigs = signed.signatures;
      let signatures: WitnessSignature[] | WitnessAggregatedSignature;

      if ('signatures' in sigs) {
        // Multi-sig format
        signatures = sigs.signatures.map(sig => ({
          witnessId: sig.witness_id,
          signature: Array.from(sig.signature)
            .map(b => b.toString(16).padStart(2, '0'))
            .join(''),
        }));
      } else {
        // BLS aggregated format
        signatures = {
          signature: Array.from(sigs.signature)
            .map(b => b.toString(16).padStart(2, '0'))
            .join(''),
          signers: sigs.signers,
        };
      }

      return {
        hash: hashHex,
        timestamp: att.timestamp,
        networkId: att.network_id,
        sequence: att.sequence,
        signatures,
      };
    } catch (error) {
      clearTimeout(timeoutId);
      throw new Error(`Witness attestation error: ${error}`);
    }
  }

  /**
   * Verify a witness attestation.
   *
   * @param proof - The WitnessProof to verify
   * @param _data - Original data (unused, hash is in proof)
   */
  async verify(proof: WitnessProof, _data: string): Promise<boolean> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      // Convert hex hash string to byte array
      const hashBytes = [];
      for (let i = 0; i < proof.hash.length; i += 2) {
        hashBytes.push(parseInt(proof.hash.substr(i, 2), 16));
      }

      // Determine signature format and convert back to API format
      let signatures: MultiSigSignatures | AggregatedSignatures;

      if (Array.isArray(proof.signatures)) {
        // Multi-sig format
        signatures = {
          signatures: proof.signatures.map(sig => ({
            witness_id: sig.witnessId,
            signature: this.hexToBytes(sig.signature),
          })),
        };
      } else {
        // BLS aggregated format
        signatures = {
          signature: this.hexToBytes(proof.signatures.signature),
          signers: proof.signatures.signers,
        };
      }

      const attestation = {
        attestation: {
          hash: hashBytes,
          timestamp: proof.timestamp,
          network_id: proof.networkId,
          sequence: proof.sequence,
        },
        signatures,
      };

      const response = await fetch(`${this.gatewayUrl}/v1/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attestation }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return false;
      }

      const result = await response.json() as VerifyResponse;
      return result.valid === true;
    } catch (error) {
      clearTimeout(timeoutId);
      console.error('Witness verification error:', error);
      return false;
    }
  }

  private hexToBytes(hex: string): number[] {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
  }
}
