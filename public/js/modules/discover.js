/**
 * Discover module for Rendezvous
 * Handles match discovery and display
 */

import { fetchMatches, fetchRevealData } from './api.js';
import { deriveMatchToken, decryptRevealData } from './crypto.js';
import { escapeHtml } from './ui.js';
import { getDiscoveries } from './state.js';

/**
 * Handle discover form submission
 * @param {Event} e - Form submit event
 */
export async function handleDiscover(e) {
  e.preventDefault();

  const el = document.getElementById('matchResults');
  const poolId = document.getElementById('discoverPoolId').value.trim();
  const privateKey = document.getElementById('discoverPrivateKey').value.trim();

  await discoverMatches(poolId, privateKey, el);
}

/**
 * Discover matches for a pool
 * @param {string} poolId - Pool identifier
 * @param {string} privateKey - User's private key
 * @param {HTMLElement} resultElement - Element to display results
 * @param {number} retryCount - Current retry count
 */
async function discoverMatches(poolId, privateKey, resultElement, retryCount = 0) {
  try {
    const result = await fetchMatches(poolId);
    const tokenSet = new Set(result.matchedTokens);

    const stored = getDiscoveries()[poolId];
    if (!stored) {
      resultElement.innerHTML = '<p class="text-error">No saved selections for this pool</p>';
      return;
    }

    // Find which of our selections resulted in mutual matches
    const matchedSelections = [];
    for (const s of stored.selections) {
      const token = deriveMatchToken(privateKey, s.publicKey, poolId);
      if (tokenSet.has(token)) {
        matchedSelections.push({ ...s, matchToken: token });
      }
    }

    // Fetch reveal data and decrypt for each match
    const revealDataMap = {};
    if (matchedSelections.length > 0) {
      try {
        const revealResult = await fetchRevealData(poolId);
        for (const match of matchedSelections) {
          const encryptedData = revealResult.revealData[match.matchToken];
          if (encryptedData) {
            const decrypted = await decryptRevealData(encryptedData, match.matchToken);
            if (decrypted) {
              revealDataMap[match.publicKey] = decrypted;
            }
          }
        }
      } catch (revealErr) {
        console.log('No reveal data available:', revealErr.message);
      }
    }

    // Render matches with contact info
    const matchesHtml = matchedSelections.map(m => {
      const reveal = revealDataMap[m.publicKey];
      let contactHtml = '';
      if (reveal && (reveal.contact || reveal.message)) {
        contactHtml = '<div class="match-contact" style="margin-top:0.5rem;padding:0.5rem;background:rgba(99,102,241,0.1);border-radius:0.25rem;">';
        if (reveal.contact) {
          contactHtml += '<div style="color:var(--accent);font-weight:500;">' + escapeHtml(reveal.contact) + '</div>';
        }
        if (reveal.message) {
          contactHtml += '<div class="text-sm text-muted">' + escapeHtml(reveal.message) + '</div>';
        }
        contactHtml += '</div>';
      }
      return '<div class="match-item">' +
        '<div class="match-item-name">' + escapeHtml(m.displayName) + '</div>' +
        contactHtml +
        '<div class="match-item-key">' + m.publicKey + '</div></div>';
    }).join('');

    resultElement.innerHTML = '<div class="match-result">' +
      '<div class="match-count">' + matchedSelections.length + '</div>' +
      '<div class="match-label">Match' + (matchedSelections.length !== 1 ? 'es' : '') + '</div>' +
      (matchedSelections.length
        ? '<div class="match-list">' + matchesHtml + '</div>'
        : '<p class="text-muted mt-2">No mutual matches</p>') +
      '</div>';
  } catch (e) {
    // Check if this is a "still computing" error
    if (e.message.includes('not be closed') && retryCount < 12) {
      // Show countdown and auto-retry
      let countdown = 10;
      resultElement.innerHTML = '<div class="text-center">' +
        '<div class="empty-state-icon" style="font-size:2rem;">⏳</div>' +
        '<p>Matches are being computed...</p>' +
        '<p class="text-muted text-sm">Privacy delay in progress. Retrying in <span id="retryCountdown">' +
        countdown + '</span>s</p>' +
        '<button class="btn-secondary btn-sm mt-2" id="retryNowBtn">Retry Now</button></div>';

      // Add retry button handler
      const retryBtn = document.getElementById('retryNowBtn');
      if (retryBtn) {
        retryBtn.addEventListener('click', () => {
          clearInterval(countdownInterval);
          discoverMatches(poolId, privateKey, resultElement, retryCount + 1);
        });
      }

      const countdownInterval = setInterval(() => {
        countdown--;
        const countdownEl = document.getElementById('retryCountdown');
        if (countdownEl) countdownEl.textContent = countdown;
        if (countdown <= 0) {
          clearInterval(countdownInterval);
          discoverMatches(poolId, privateKey, resultElement, retryCount + 1);
        }
      }, 1000);
    } else {
      resultElement.innerHTML = '<p class="text-error">' + e.message + '</p>';
    }
  }
}

/**
 * Initialize discover-related event listeners
 */
export function initDiscoverListeners() {
  const discoverForm = document.getElementById('discoverForm');
  if (discoverForm) {
    discoverForm.addEventListener('submit', handleDiscover);
  }
}
