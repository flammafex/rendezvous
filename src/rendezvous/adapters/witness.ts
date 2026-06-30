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
import {
  FreebirdProof,
  WitnessProof,
  WitnessSignature,
  WitnessAggregatedSignature,
  SophiaWitnessSignedAttestation,
} from '../types.js';

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
  epoch: number;
}

/** Witness attestation structure */
interface WitnessAttestation {
  hash: string;
  timestamp: number;
  network_id: string;
  sequence: number;
}

/** Multi-sig format */
interface MultiSigSignatures {
  signatures: Array<{
    witness_id: string;
    signature: string;
  }>;
}

/** BLS aggregated format */
interface AggregatedSignatures {
  signature: string;
  signers: string[];
}

/** Response from POST /v1/timestamp */
interface TimestampResponse {
  attestation: {
    attestation: WitnessAttestation;
    signatures: MultiSigSignatures | AggregatedSignatures;
  };
  status?: 'confirmed' | 'pending' | 'rejected';
}

/** Response from POST /v1/verify */
interface VerifyResponse {
  valid: boolean;
  verified_signatures: number;
  required_signatures: number;
  message: string;
}

const CONTRACT_VERSION = 'sophia/v1' as const;

function lowerHex(value: string, name: string): string {
  const normalized = value.toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error(`${name} must be lowercase hex`);
  }
  return normalized;
}

function sha256Hex(value: string, name: string): string {
  const normalized = lowerHex(value, name);
  if (normalized.length !== 64) {
    throw new Error(`${name} must be a 32-byte SHA-256 hex value`);
  }
  return normalized;
}

function normalizeSignatureSet(signatures: MultiSigSignatures | AggregatedSignatures | SophiaWitnessSignedAttestation['signatures']): SophiaWitnessSignedAttestation['signatures'] {
  if ('kind' in signatures) {
    if (signatures.kind === 'multisig') {
      return {
        kind: 'multisig',
        signatures: signatures.signatures.map((signature, index) => ({
          witness_id: signature.witness_id,
          signature: lowerHex(signature.signature, `signatures[${index}].signature`),
        })),
      };
    }
    return {
      kind: 'aggregated',
      signature: lowerHex(signatures.signature, 'signatures.signature'),
      signers: [...signatures.signers],
    };
  }

  if ('signatures' in signatures) {
    return {
      kind: 'multisig',
      signatures: signatures.signatures.map((signature, index) => ({
        witness_id: signature.witness_id,
        signature: lowerHex(signature.signature, `signatures[${index}].signature`),
      })),
    };
  }

  return {
    kind: 'aggregated',
    signature: lowerHex(signatures.signature, 'signatures.signature'),
    signers: [...signatures.signers],
  };
}

function normalizeSignedAttestation(raw: TimestampResponse['attestation'] | SophiaWitnessSignedAttestation): SophiaWitnessSignedAttestation {
  const attestation = raw.attestation;
  return {
    contract_version: CONTRACT_VERSION,
    artifact_type: 'witness.signed_attestation',
    attestation: {
      hash: sha256Hex(attestation.hash, 'attestation.hash'),
      timestamp: attestation.timestamp,
      network_id: attestation.network_id,
      sequence: attestation.sequence,
    },
    signatures: normalizeSignatureSet(raw.signatures),
  };
}

function toWireSignedAttestation(canonical: SophiaWitnessSignedAttestation): TimestampResponse['attestation'] {
  const signatures = canonical.signatures.kind === 'multisig'
    ? {
        signatures: canonical.signatures.signatures.map(signature => ({
          witness_id: signature.witness_id,
          signature: signature.signature,
        })),
      }
    : {
        signature: canonical.signatures.signature,
        signers: [...canonical.signatures.signers],
      };

  return {
    attestation: { ...canonical.attestation },
    signatures,
  };
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
        if (freebirdProof.epoch === undefined) {
          throw new Error('Freebird token epoch required for Witness authentication');
        }

        body.freebird_token = {
          token_b64: freebirdProof.tokenValue,
          issuer_id: freebirdProof.issuerId,
          exp: Math.floor(freebirdProof.expiration / 1000), // Convert ms to seconds
          epoch: freebirdProof.epoch,
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
      return this.toWitnessProof(normalizeSignedAttestation(result.attestation));
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
      const attestation = toWireSignedAttestation(this.toCanonicalSignedAttestation(proof));

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

  private toWitnessProof(canonical: SophiaWitnessSignedAttestation): WitnessProof {
    const { attestation, signatures } = canonical;
    let proofSignatures: WitnessSignature[] | WitnessAggregatedSignature;

    if (signatures.kind === 'multisig') {
      proofSignatures = signatures.signatures.map(signature => ({
        witnessId: signature.witness_id,
        signature: signature.signature,
      }));
    } else {
      proofSignatures = {
        signature: signatures.signature,
        signers: [...signatures.signers],
      };
    }

    return {
      hash: attestation.hash,
      timestamp: attestation.timestamp,
      networkId: attestation.network_id,
      sequence: attestation.sequence,
      signatures: proofSignatures,
      canonical,
    };
  }

  private toCanonicalSignedAttestation(proof: WitnessProof): SophiaWitnessSignedAttestation {
    if (proof.canonical) {
      return normalizeSignedAttestation(proof.canonical);
    }

    if (Array.isArray(proof.signatures)) {
      return {
        contract_version: CONTRACT_VERSION,
        artifact_type: 'witness.signed_attestation',
        attestation: {
          hash: sha256Hex(proof.hash, 'attestation.hash'),
          timestamp: proof.timestamp,
          network_id: proof.networkId,
          sequence: proof.sequence,
        },
        signatures: {
          kind: 'multisig',
          signatures: proof.signatures.map(signature => ({
            witness_id: signature.witnessId,
            signature: signature.signature,
          })),
        },
      };
    }

    return {
      contract_version: CONTRACT_VERSION,
      artifact_type: 'witness.signed_attestation',
      attestation: {
        hash: sha256Hex(proof.hash, 'attestation.hash'),
        timestamp: proof.timestamp,
        network_id: proof.networkId,
        sequence: proof.sequence,
      },
      signatures: {
        kind: 'aggregated',
        signature: proof.signatures.signature,
        signers: proof.signatures.signers,
      },
    };
  }

}
