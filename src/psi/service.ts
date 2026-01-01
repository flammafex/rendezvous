/**
 * PSI Service - Wrapper for @openmined/psi.js
 *
 * Provides private set intersection for matching without revealing
 * non-intersecting preferences.
 */

import type {
  PsiPoolSetup,
  CreatePsiSetupRequest,
  PsiJoinRequest,
  PsiJoinResponse,
  PsiResult,
  OwnerHeldPsiSetup,
} from './types.js';
import {
  encryptForPublicKey,
  serializeEncryptedBox,
} from '../rendezvous/crypto.js';

// PSI.js types (the library doesn't export these well)
interface PsiLibrary {
  server: {
    createWithNewKey(revealIntersection: boolean): PsiServer;
    createFromKey(key: Uint8Array, revealIntersection: boolean): PsiServer;
  };
  client: {
    createWithNewKey(revealIntersection: boolean): PsiClient;
    createFromKey(key: Uint8Array, revealIntersection: boolean): PsiClient;
  };
  serverSetup: {
    deserializeBinary(bytes: Uint8Array): PsiServerSetup;
  };
  request: {
    deserializeBinary(bytes: Uint8Array): PsiRequest;
  };
  response: {
    deserializeBinary(bytes: Uint8Array): PsiResponse;
  };
  dataStructure: {
    GCS: number;
    BloomFilter: number;
  };
}

interface PsiServer {
  createSetupMessage(
    fpr: number,
    numClientElements: number,
    inputs: string[],
    dataStructure: number
  ): PsiServerSetup;
  processRequest(request: PsiRequest): PsiResponse;
  getPrivateKeyBytes(): Uint8Array;
}

interface PsiClient {
  createRequest(inputs: string[]): PsiRequest;
  getIntersection(setup: PsiServerSetup, response: PsiResponse): string[];
  getIntersectionSize(setup: PsiServerSetup, response: PsiResponse): number;
  getPrivateKeyBytes(): Uint8Array;
}

interface PsiServerSetup {
  serializeBinary(): Uint8Array;
}

interface PsiRequest {
  serializeBinary(): Uint8Array;
}

interface PsiResponse {
  serializeBinary(): Uint8Array;
}

/**
 * PSI Service for private set intersection operations
 */
export class PsiService {
  private psi: PsiLibrary | null = null;
  private initPromise: Promise<void> | null = null;

  /**
   * Initialize the PSI library (loads WASM)
   */
  async init(): Promise<void> {
    if (this.psi) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      // Dynamic import to handle WASM loading
      const PSI = await import('@openmined/psi.js');
      this.psi = await PSI.default();
    })();

    return this.initPromise;
  }

  /**
   * Ensure PSI is initialized
   */
  private async getPsi(): Promise<PsiLibrary> {
    await this.init();
    if (!this.psi) throw new Error('PSI library not initialized');
    return this.psi;
  }

  /**
   * Create PSI setup for a pool (server side)
   *
   * Called by pool owner when creating or updating a pool.
   * The setup message is public, but the server key must be kept secret.
   */
  async createSetup(request: CreatePsiSetupRequest): Promise<PsiPoolSetup> {
    const psi = await this.getPsi();
    const fpr = request.fpr ?? 0.001;
    const maxClientElements = request.maxClientElements ?? 10000;

    // Create server with new key
    const server = psi.server.createWithNewKey(true);

    // Create setup message from owner's tokens
    const setup = server.createSetupMessage(
      fpr,
      maxClientElements,
      request.matchTokens,
      psi.dataStructure.GCS
    );

    // Get private key (must be encrypted before storage!)
    const privateKey = server.getPrivateKeyBytes();

    return {
      setupMessage: uint8ArrayToBase64(setup.serializeBinary()),
      encryptedServerKey: uint8ArrayToBase64(privateKey), // TODO: encrypt this!
      fpr,
      maxClientElements,
      dataStructure: 'GCS',
    };
  }

  /**
   * Process a PSI request (server side)
   *
   * Called when a joiner submits their PSI request.
   * Server learns NOTHING about the joiner's inputs.
   */
  async processRequest(
    setup: PsiPoolSetup,
    psiRequestBase64: string
  ): Promise<PsiJoinResponse> {
    const psi = await this.getPsi();

    // Restore server from key
    const serverKey = base64ToUint8Array(setup.encryptedServerKey); // TODO: decrypt
    const server = psi.server.createFromKey(serverKey, true);

    // Deserialize client request
    const requestBytes = base64ToUint8Array(psiRequestBase64);
    const request = psi.request.deserializeBinary(requestBytes);

    // Process request - server learns nothing!
    const response = server.processRequest(request);

    return {
      psiSetup: setup.setupMessage,
      psiResponse: uint8ArrayToBase64(response.serializeBinary()),
    };
  }

  /**
   * Create a PSI request (client side)
   *
   * Called by joiner to create request from their tokens.
   * Returns the request to send and state needed to compute intersection.
   */
  async createRequest(inputs: string[]): Promise<{
    request: string;
    clientKey: string;
  }> {
    const psi = await this.getPsi();

    // Create client with new key
    const client = psi.client.createWithNewKey(true);

    // Create request from joiner's tokens
    const request = client.createRequest(inputs);

    return {
      request: uint8ArrayToBase64(request.serializeBinary()),
      clientKey: uint8ArrayToBase64(client.getPrivateKeyBytes()),
    };
  }

  /**
   * Compute intersection (client side)
   *
   * Called by joiner after receiving server response.
   * Only the joiner learns the intersection!
   */
  async computeIntersection(
    clientKey: string,
    inputs: string[],
    psiSetupBase64: string,
    psiResponseBase64: string
  ): Promise<PsiResult> {
    const psi = await this.getPsi();

    // Restore client from key
    const keyBytes = base64ToUint8Array(clientKey);
    const client = psi.client.createFromKey(keyBytes, true);

    // We need to recreate the request to compute intersection
    // (PSI.js requires the original inputs)
    client.createRequest(inputs);

    // Deserialize setup and response
    const setupBytes = base64ToUint8Array(psiSetupBase64);
    const responseBytes = base64ToUint8Array(psiResponseBase64);

    const setup = psi.serverSetup.deserializeBinary(setupBytes);
    const response = psi.response.deserializeBinary(responseBytes);

    // Compute intersection - only client learns this!
    const intersection = client.getIntersection(setup, response);

    return {
      intersection,
      cardinality: intersection.length,
    };
  }

  /**
   * Compute only cardinality (client side)
   *
   * More private than revealing intersection - only reveals count.
   */
  async computeCardinality(
    clientKey: string,
    inputs: string[],
    psiSetupBase64: string,
    psiResponseBase64: string
  ): Promise<number> {
    const psi = await this.getPsi();

    const keyBytes = base64ToUint8Array(clientKey);
    const client = psi.client.createFromKey(keyBytes, false); // false = cardinality only

    client.createRequest(inputs);

    const setupBytes = base64ToUint8Array(psiSetupBase64);
    const responseBytes = base64ToUint8Array(psiResponseBase64);

    const setup = psi.serverSetup.deserializeBinary(setupBytes);
    const response = psi.response.deserializeBinary(responseBytes);

    return client.getIntersectionSize(setup, response);
  }

  // ==========================================================================
  // Owner-Held Key Methods (Option B - Pool Owner Holds Key)
  // ==========================================================================

  /**
   * Create PSI setup with server key encrypted to owner's public key.
   *
   * This is called by the pool owner (client-side or via API).
   * The server key is encrypted using ECIES so only the pool owner
   * can decrypt it. The server stores the encrypted blob but cannot
   * access the plaintext key.
   *
   * @param request - Setup request with match tokens
   * @param ownerPublicKey - Pool owner's X25519 public key (hex)
   * @returns Setup with encrypted server key
   */
  async createOwnerEncryptedSetup(
    request: CreatePsiSetupRequest,
    ownerPublicKey: string
  ): Promise<OwnerHeldPsiSetup> {
    const psi = await this.getPsi();
    const fpr = request.fpr ?? 0.001;
    const maxClientElements = request.maxClientElements ?? 10000;

    // Create server with new key
    const server = psi.server.createWithNewKey(true);

    // Create setup message from tokens
    const setup = server.createSetupMessage(
      fpr,
      maxClientElements,
      request.matchTokens,
      psi.dataStructure.GCS
    );

    // Get private key and encrypt it to owner's public key
    const privateKey = server.getPrivateKeyBytes();
    const privateKeyBase64 = uint8ArrayToBase64(privateKey);
    const encryptedBox = encryptForPublicKey(privateKeyBase64, ownerPublicKey);

    return {
      poolId: request.poolId,
      setupMessage: uint8ArrayToBase64(setup.serializeBinary()),
      encryptedServerKey: serializeEncryptedBox(encryptedBox),
      ownerPublicKey,
      fpr,
      maxClientElements,
      dataStructure: 'GCS',
      createdAt: Date.now(),
    };
  }

  /**
   * Process a PSI request using a decrypted server key.
   *
   * This is called by the pool owner after they decrypt the server key.
   * The owner decrypts the key locally, then uses this method to process
   * the PSI request and generate the response.
   *
   * @param serverKeyBase64 - Decrypted PSI server key (base64)
   * @param psiRequestBase64 - Client's PSI request (base64)
   * @returns PSI response (base64)
   */
  async processRequestWithDecryptedKey(
    serverKeyBase64: string,
    psiRequestBase64: string
  ): Promise<string> {
    const psi = await this.getPsi();

    // Restore server from decrypted key
    const serverKey = base64ToUint8Array(serverKeyBase64);
    const server = psi.server.createFromKey(serverKey, true);

    // Deserialize and process request
    const requestBytes = base64ToUint8Array(psiRequestBase64);
    const request = psi.request.deserializeBinary(requestBytes);
    const response = server.processRequest(request);

    return uint8ArrayToBase64(response.serializeBinary());
  }
}

// Utility functions for base64 encoding/decoding
function uint8ArrayToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function base64ToUint8Array(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

// Singleton instance
let psiService: PsiService | null = null;

/**
 * Get the PSI service singleton
 */
export function getPsiService(): PsiService {
  if (!psiService) {
    psiService = new PsiService();
  }
  return psiService;
}
