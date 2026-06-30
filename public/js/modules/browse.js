/**
 * Browse module for Rendezvous
 *
 * After the H3 consolidation, the Browse tab is a thin launcher: it shows a
 * pool selector and a "Browse & Select" button that opens the Join modal
 * (the canonical guided flow). The inline 4-step flow has been retired.
 *
 * The Join modal (join-flow.js) owns registration, browsing, and submission.
 */

import { fetchPool } from './api.js';
import { showToast } from './ui.js';
import { openJoinModal } from './join-flow.js';
import { startQRScanner } from './qr.js';
import { getParticipatedPools } from './state.js';

/**
 * Open the Join modal for the pool selected in the Browse tab.
 *
 * Reads the pool ID from the dropdown or direct-input field, fetches the
 * pool name (if needed), and launches the Join modal.
 */
export async function startBrowse() {
  const poolId = document.getElementById('browsePoolId').value.trim() ||
    document.getElementById('browsePoolSelect').value;

  if (!poolId) {
    showToast('Select a pool first', 'info');
    return;
  }

  try {
    const pool = await fetchPool(poolId);
    openJoinModal(poolId, pool.name);
  } catch (e) {
    showToast(e.message, 'error');
  }
}

/**
 * Show or hide the "already participated" hint based on whether the user
 * has submitted to any pool. Called on tab switch and after participation.
 */
export function updateParticipatedHint() {
  const hint = document.getElementById('browseParticipatedHint');
  if (!hint) return;
  const participated = getParticipatedPools();
  const hasParticipated = Object.keys(participated).length > 0;
  hint.classList.toggle('hidden', !hasParticipated);
}

/**
 * Initialize browse-related event listeners.
 */
export function initBrowseListeners() {
  const startBtn = document.getElementById('browseStartBtn');
  if (startBtn) {
    startBtn.addEventListener('click', startBrowse);
  }

  const scanBtn = document.getElementById('browseScanBtn');
  if (scanBtn) {
    scanBtn.addEventListener('click', () => startQRScanner());
  }

  // "Discover Matches" link in the participated hint
  const discoverLink = document.getElementById('browseGotoDiscover');
  if (discoverLink) {
    discoverLink.addEventListener('click', (e) => {
      e.preventDefault();
      const tab = document.getElementById('tab-discover');
      if (tab) tab.click();
    });
  }

  // Refresh the hint when the Browse tab is shown or participation unlocks
  const browseTab = document.getElementById('tab-browse');
  if (browseTab) {
    browseTab.addEventListener('click', updateParticipatedHint);
  }

  window.addEventListener('participationUnlocked', updateParticipatedHint);
}
