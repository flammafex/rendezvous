/**
 * Discover module for Rendezvous
 * Handles match discovery and display
 */

import { fetchMatches, fetchRevealData } from './api.js';
import { deriveMatchToken, decryptRevealData } from './crypto.js';
import { escapeHtml } from './ui.js';
import { getDiscoveries, getSavedKeys, getParticipatedPools } from './state.js';

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
    const ownRevealDataByToken = stored.ownRevealDataByToken || {};

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
          const revealEntries = revealResult?.revealData?.[match.matchToken];
          const encryptedEntries = Array.isArray(revealEntries)
            ? revealEntries
            : (typeof revealEntries === 'string' ? [revealEntries] : []);

          if (encryptedEntries.length > 0) {
            const ownEncrypted = ownRevealDataByToken[match.matchToken];
            for (const encryptedData of encryptedEntries) {
              // Exclude our own ciphertext so we only display counterpart contact data.
              if (ownEncrypted && encryptedData === ownEncrypted) {
                continue;
              }

              const decrypted = await decryptRevealData(encryptedData, match.matchToken);
              if (decrypted) {
                revealDataMap[match.publicKey] = decrypted;
                break;
              }
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
    const computingError = /not be closed|must be closed|being computed|not closed/i.test(e.message);
    if (computingError && retryCount < 12) {
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
 * Find a saved keypair for a given pool ID.
 *
 * Preference order:
 *  1. Participation record (stores the publicKey used for this pool) matched
 *     against a saved key with the same publicKey.
 *  2. A saved key whose poolLabel matches the pool ID (join-flow labels keys
 *     with the pool name, so this is a weaker signal and not used here).
 *
 * @param {string} poolId - Pool ID
 * @returns {object|null} Saved key object (with privateKey) or null
 */
function findSavedKeyForPool(poolId) {
  if (!poolId) return null;
  const savedKeys = getSavedKeys();
  if (savedKeys.length === 0) return null;

  // Preferred path: participation record stores the publicKey used for this pool
  const participated = getParticipatedPools();
  const participation = participated[poolId];
  if (participation && participation.publicKey) {
    const match = savedKeys.find(k => k.publicKey === participation.publicKey);
    if (match) return match;
  }

  return null;
}

/**
 * Render the list of pools the user has submitted preferences to, as clickable
 * chips above the discover form. Clicking a chip fills the pool ID field and
 * refreshes the saved-key hint.
 *
 * If the user has no saved submissions, shows a helpful empty state pointing
 * them to join a pool first.
 */
function renderParticipatedPools() {
  const form = document.getElementById('discoverForm');
  if (!form) return;

  // Ensure the container exists, inserted just above the form
  let container = document.getElementById('discoverPoolsList');
  if (!container) {
    container = document.createElement('div');
    container.id = 'discoverPoolsList';
    form.parentNode.insertBefore(container, form);
  }

  const discoveries = getDiscoveries();
  const poolIds = Object.keys(discoveries);

  if (poolIds.length === 0) {
    container.innerHTML =
      '<p class="text-sm text-muted">You haven\'t submitted preferences to any pool yet. ' +
      'Join a pool first.</p>';
    return;
  }

  // Build chips. Prefer a human-readable label from the saved key's poolLabel;
  // fall back to the raw pool ID.
  const chips = poolIds.map(id => {
    const savedKey = findSavedKeyForPool(id);
    const label = savedKey && savedKey.poolLabel
      ? escapeHtml(savedKey.poolLabel)
      : escapeHtml(id);
    return '<button type="button" class="selection-chip" data-discover-pool="' +
      escapeHtml(id) + '" title="' + escapeHtml(id) + '">' +
      '<span>' + label + '</span></button>';
  }).join('');

  container.innerHTML =
    '<div class="text-sm text-muted mb-1">Pools you\'ve participated in:</div>' +
    '<div class="selections-list" style="margin-top:0;">' + chips + '</div>';

  // Attach click handlers — fill the pool ID field and refresh the key hint
  container.querySelectorAll('[data-discover-pool]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.discoverPool;
      const poolInput = document.getElementById('discoverPoolId');
      if (poolInput) {
        poolInput.value = id;
        updateSavedKeyHint(id);
      }
    });
  });
}

/**
 * Show or refresh the "use saved private key" hint for the given pool ID.
 *
 * The hint is appended inside the private key's form-group so it sits visually
 * with the field it relates to. Only shown when a saved key exists for the
 * pool. The user must explicitly click the link to populate the field — we
 * never auto-fill the private key.
 *
 * @param {string} poolId - Pool ID (empty string removes the hint)
 */
function updateSavedKeyHint(poolId) {
  const keyInput = document.getElementById('discoverPrivateKey');
  if (!keyInput) return;
  const keyGroup = keyInput.closest('.form-group');

  let hint = document.getElementById('discoverKeyHint');

  if (!poolId) {
    if (hint) hint.remove();
    return;
  }

  const savedKey = findSavedKeyForPool(poolId);
  if (!savedKey || !savedKey.privateKey) {
    if (hint) hint.remove();
    return;
  }

  if (!hint) {
    hint = document.createElement('p');
    hint.id = 'discoverKeyHint';
    hint.className = 'text-sm text-muted';
    if (keyGroup) keyGroup.appendChild(hint);
  }

  hint.innerHTML = 'A saved key was found for this pool. ' +
    '<a href="#" id="discoverUseSavedKey">Use saved private key</a>';

  const link = document.getElementById('discoverUseSavedKey');
  if (link) {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      keyInput.value = savedKey.privateKey;
      // Focus the discover button so the user can submit immediately
      const submitBtn = document.querySelector('#discoverForm button[type="submit"]');
      if (submitBtn) submitBtn.focus();
    });
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

  // Render the participated-pools list (chips above the form)
  renderParticipatedPools();

  // Update the saved-key hint as the user types or pastes a pool ID
  const poolInput = document.getElementById('discoverPoolId');
  if (poolInput) {
    poolInput.addEventListener('input', () => updateSavedKeyHint(poolInput.value.trim()));
    poolInput.addEventListener('change', () => updateSavedKeyHint(poolInput.value.trim()));
  }

  // Re-render the chips when the user switches to the Discover tab, in case
  // they submitted to a new pool since the last render. (main.js owns the
  // tab-switching logic, so we attach our own listener here.)
  const discoverTab = document.querySelector('[data-tab="discover"]');
  if (discoverTab) {
    discoverTab.addEventListener('click', renderParticipatedPools);
  }

  // Also re-render when participation is unlocked (first submission in the
  // join modal), so the chips appear without requiring a tab switch.
  window.addEventListener('participationUnlocked', renderParticipatedPools);
}
