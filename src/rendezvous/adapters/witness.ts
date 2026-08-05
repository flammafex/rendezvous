/**
 * Witness HTTP Adapter
 *
 * Connects to a Witness gateway for timestamp attestation.
 * Witness provides cryptographic proof that data existed at a specific time.
 *
 * API endpoints:
 * - POST /v1/attestations - Create an attestation job (optional Freebird token)
 * - GET /v1/attestations/:hash - Poll attestation job status
 * - POST /v1/verify - Verify attestation
 * - GET /v1/config - Get network configuration
 *
 * Updated for Witness API v0.7.0 (async attestation job model, Freebird auth).
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

/** Response from POST /v1/attestations and GET /v1/attestations/:hash */
interface AttestationJobResponse {
  attestation: WitnessAttestation;
  status: 'pending' | 'retryable' | 'confirmed' | 'failed';
  signed_attestation?: {
    attestation: WitnessAttestation;
    signatures: MultiSigSignatures | AggregatedSignatures;
  };
  attempts?: number;
  next_attempt_at?: number;
  last_error?: string | null;
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

function normalizeSignedAttestation(raw: NonNullable<AttestationJobResponse['signed_attestation']> | SophiaWitnessSignedAttestation): SophiaWitnessSignedAttestation {
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

function toWireSignedAttestation(canonical: SophiaWitnessSignedAttestation): AttestationJobResponse['signed_attestation'] {
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
   * Creates an attestation job and polls until it is confirmed or fails.
   *
   * @param data - Hex-encoded SHA-256 hash to timestamp
   * @param freebirdProof - Optional Freebird token for Sybil resistance
   */
  async attest(data: string, freebirdProof?: FreebirdProof): Promise<WitnessProof> {
    const pollIntervalMs = 500;
    const pollTimeoutMs = 30000;

    // Build request body
    const body: { hash: string; freebird_token?: FreebirdTokenPayload } = { hash: data };

    if (freebirdProof) {
      body.freebird_token = {
        token_b64: freebirdProof.tokenValue,
      };
    }

    const postResponse = await this.request('/v1/attestations', {
      method: 'POST',
      body: JSON.stringify(body),
    });

    let result = postResponse as AttestationJobResponse;

    // Async job model: poll until confirmed or failed.
    if (result.status === 'pending' || result.status === 'retryable') {
      const deadline = Date.now() + pollTimeoutMs;
      while (Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
        result = await this.request(`/v1/attestations/${data}`, { method: 'GET' }) as AttestationJobResponse;
        if (result.status === 'confirmed' || result.status === 'failed') {
          break;
        }
      }
    }

    if (result.status === 'failed') {
      throw new Error(`Witness attestation failed: ${result.last_error ?? 'unknown error'}`);
    }

    if (result.status !== 'confirmed' || !result.signed_attestation) {
      throw new Error('Witness attestation timed out waiting for confirmation');
    }

    return this.toWitnessProof(normalizeSignedAttestation(result.signed_attestation));
  }

  /**
   * Perform an HTTP request against the Witness gateway, handling auth errors.
   */
  private async request(path: string, init: { method: 'POST' | 'GET'; body?: string }): Promise<unknown> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.gatewayUrl}${path}`, {
        method: init.method,
        headers: { 'Content-Type': 'application/json' },
        body: init.body,
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

      return await response.json();
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
