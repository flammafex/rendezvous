/**
 * PSI application types.
 *
 * Matchlock exposes the reusable PSI primitives. Rendezvous only adds the
 * authenticated join request envelope used by its HTTP API.
 */

export type {
  PsiClientRequest,
  PsiJoinResponse,
  PsiResult,
  OwnerHeldPsiSetup,
  PendingPsiRequest,
  PsiResponseRecord,
  OwnerPsiProcessingResult,
  CreatePsiSetupRequest,
  PsiClientSession,
} from '../matchlock/index.js';

/** PSI join request from a client */
export interface PsiJoinRequest {
  /** Pool to compute intersection with */
  poolId: string;
  /** Freebird anonymous auth token */
  authToken: string;
  /** Serialized PSI client request (base64) */
  psiRequest: string;
}
