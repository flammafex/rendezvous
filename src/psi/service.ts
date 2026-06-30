/**
 * Rendezvous PSI compatibility facade.
 *
 * Matchlock now owns the extracted PSI implementation. Rendezvous keeps this
 * service wrapper so existing imports continue to work.
 */

import { PsiService as MatchlockPsiService } from 'matchlock';

export class PsiService extends MatchlockPsiService {}

let psiService: PsiService | null = null;

export function getPsiService(): PsiService {
  if (!psiService) {
    psiService = new PsiService();
  }
  return psiService;
}
