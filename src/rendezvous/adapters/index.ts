/**
 * Rendezvous Adapters
 *
 * HTTP-based adapters for external services:
 * - Freebird: Unlinkable eligibility proofs (verifier at port 8082)
 * - Witness: Timestamp attestation (gateway at port 8080)
 */

export { HttpFreebirdAdapter, type FreebirdConfig } from './freebird.js';
export { HttpWitnessAdapter, type WitnessConfig } from './witness.js';
