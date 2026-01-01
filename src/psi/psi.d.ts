/**
 * Type declarations for @openmined/psi.js
 *
 * This module provides Private Set Intersection using WebAssembly.
 * Install with: npm install @openmined/psi.js
 */

declare module '@openmined/psi.js' {
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

  function PSI(): Promise<PsiLibrary>;
  export default PSI;
}
