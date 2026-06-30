import type {
  CreatePsiSetupRequest,
  OwnerHeldPsiSetup,
  PsiResult,
  PsiClientSession,
} from './types.js';
import {
  encryptForPublicKey,
  serializeEncryptedBox,
} from '../dh/ecies.js';
import type { PublicKey } from '../types.js';

function bytesToBase64(bytes: Uint8Array): string {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str);
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// Hand-rolled mirror of @openmined/psi.js internals.
// The library does not export TypeScript types; if it did this block could be replaced
// with: import type { ... } from '@openmined/psi.js';
// See: https://github.com/OpenMined/PSI/issues (upstream tracking issue)
interface PsiLibrary {
  server?: {
    createWithNewKey(revealIntersection?: boolean): PsiServer;
    createFromKey(key: Uint8Array, revealIntersection?: boolean): PsiServer;
  };
  client?: {
    createWithNewKey(revealIntersection?: boolean): PsiClient;
    createFromKey(key: Uint8Array, revealIntersection?: boolean): PsiClient;
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
  createSetupMessage(fpr: number, numClientInputs: number, inputs: readonly string[], dataStructure?: number): PsiServerSetup;
  processRequest(request: PsiRequest): PsiResponse;
  getPrivateKeyBytes(): Uint8Array;
}

interface PsiClient {
  createRequest(inputs: readonly string[]): PsiRequest;
  getIntersection(setup: PsiServerSetup, response: PsiResponse): number[];
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

export class PsiService {
  private psi: PsiLibrary | null = null;
  private initPromise: Promise<void> | null = null;

  async init(): Promise<void> {
    if (this.psi) return;
    if (this.initPromise) return this.initPromise;
    this.initPromise = (async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const PSI = await import('@openmined/psi.js') as any;
      const loadPsi: () => Promise<PsiLibrary> = PSI.default ?? PSI;
      this.psi = await loadPsi();
    })();
    return this.initPromise;
  }

  private async getPsi(): Promise<PsiLibrary> {
    await this.init();
    if (!this.psi) throw new Error('PSI library not initialized');
    return this.psi;
  }

  /**
   * Create PSI setup with server key encrypted to owner's public key.
   * The server stores the encrypted blob but cannot access the plaintext key.
   */
  async createOwnerEncryptedSetup(
    request: CreatePsiSetupRequest,
    ownerPublicKey: string,
  ): Promise<OwnerHeldPsiSetup> {
    const psi = await this.getPsi();
    if (!psi.server) throw new Error('PSI server not available');

    const fpr = request.fpr ?? 0.001;
    const maxClientElements = request.maxClientElements ?? 10000;

    const server = psi.server.createWithNewKey(true);
    const setup = server.createSetupMessage(fpr, maxClientElements, request.matchTokens);
    const privateKey = server.getPrivateKeyBytes();
    const encryptedBox = encryptForPublicKey(bytesToBase64(privateKey), ownerPublicKey as PublicKey);

    return {
      poolId: request.poolId,
      setupMessage: bytesToBase64(setup.serializeBinary()),
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
   * Called by the pool owner after they decrypt the key locally.
   */
  async processRequestWithDecryptedKey(
    serverKeyBase64: string,
    psiRequestBase64: string,
  ): Promise<string> {
    const psi = await this.getPsi();
    if (!psi.server) throw new Error('PSI server not available');

    const server = psi.server.createFromKey(base64ToBytes(serverKeyBase64), true);
    const request = psi.request.deserializeBinary(base64ToBytes(psiRequestBase64));
    const response = server.processRequest(request);

    return bytesToBase64(response.serializeBinary());
  }

  /**
   * Create a PSI request (client side).
   * Returns the serialized request to send and an opaque session object.
   * Pass the session unchanged to computeIntersection / computeCardinality —
   * never separate clientKey from inputs.
   */
  async createRequest(inputs: string[]): Promise<{ request: string; session: PsiClientSession }> {
    const psi = await this.getPsi();
    if (!psi.client) throw new Error('PSI client not available');

    const client = psi.client.createWithNewKey(true);
    const request = client.createRequest(inputs);

    return {
      request: bytesToBase64(request.serializeBinary()),
      session: {
        clientKey: bytesToBase64(client.getPrivateKeyBytes()),
        inputs: Object.freeze([...inputs]),
      },
    };
  }

  /**
   * Compute intersection (client side).
   * Pass the session returned by createRequest unchanged.
   * Only the caller learns the result.
   */
  async computeIntersection(
    session: PsiClientSession,
    psiSetupBase64: string,
    psiResponseBase64: string,
  ): Promise<PsiResult> {
    const psi = await this.getPsi();
    if (!psi.client) throw new Error('PSI client not available');

    const client = psi.client.createFromKey(base64ToBytes(session.clientKey), true);

    // PSI library requires replaying createRequest to restore OPRF state
    client.createRequest(session.inputs);

    const setup = psi.serverSetup.deserializeBinary(base64ToBytes(psiSetupBase64));
    const response = psi.response.deserializeBinary(base64ToBytes(psiResponseBase64));

    const indices = client.getIntersection(setup, response);
    const intersection = indices.map(i => session.inputs[i]);

    return { intersection, cardinality: intersection.length };
  }

  /**
   * Compute only cardinality (client side).
   * Pass the session returned by createRequest unchanged.
   */
  async computeCardinality(
    session: PsiClientSession,
    psiSetupBase64: string,
    psiResponseBase64: string,
  ): Promise<number> {
    const psi = await this.getPsi();
    if (!psi.client) throw new Error('PSI client not available');

    const client = psi.client.createFromKey(base64ToBytes(session.clientKey), false);

    // PSI library requires replaying createRequest to restore OPRF state
    client.createRequest(session.inputs);

    const setup = psi.serverSetup.deserializeBinary(base64ToBytes(psiSetupBase64));
    const response = psi.response.deserializeBinary(base64ToBytes(psiResponseBase64));

    return client.getIntersectionSize(setup, response);
  }
}
