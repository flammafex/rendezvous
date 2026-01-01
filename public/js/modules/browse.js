/**
 * Browse module for Rendezvous
 * Handles pool browsing, participant registration, and preference submission
 */

import { fetchPool, fetchParticipants, registerParticipant, getParticipantByKey, submitPreferences } from './api.js';
import { getPublicKey, deriveMatchToken, deriveNullifier, encryptRevealData, generateDecoyTokens, shuffleArray } from './crypto.js';
import { escapeHtml, goToBrowseStep } from './ui.js';
import { browseState, getSavedKeys, getDiscoveries, saveDiscoveries } from './state.js';

/**
 * Fill registration form from saved key
 */
export function fillFromSavedKey() {
  const savedKeys = getSavedKeys();
  if (savedKeys.length > 0) {
    const lastKey = savedKeys[savedKeys.length - 1];
    document.getElementById('registerPublicKeyInput').value = lastKey.publicKey;
    document.getElementById('registerPrivateKeyInput').value = lastKey.privateKey;
  } else {
    alert('No saved keys! Generate one in the Keys tab first.');
  }
}

/**
 * Select a pool for browsing
 */
export async function selectPoolForBrowse() {
  const poolId = document.getElementById('browsePoolId').value.trim() ||
    document.getElementById('browsePoolSelect').value;

  if (!poolId) {
    alert('Select a pool');
    return;
  }

  try {
    const pool = await fetchPool(poolId);
    browseState.poolId = poolId;
    browseState.poolName = pool.name;
    // Clear any previous key inputs
    document.getElementById('registerPublicKeyInput').value = '';
    document.getElementById('registerPrivateKeyInput').value = '';
    goToBrowseStep(2);
  } catch (e) {
    alert(e.message);
  }
}

/**
 * Handle registration form submission
 * @param {Event} e - Form submit event
 */
export async function handleRegister(e) {
  e.preventDefault();

  const publicKey = document.getElementById('registerPublicKeyInput').value.trim();
  const privateKey = document.getElementById('registerPrivateKeyInput').value.trim();

  if (publicKey.length !== 64 || privateKey.length !== 64) {
    alert('Keys must be 64 hex characters');
    return;
  }

  // Validate that the keypair matches
  try {
    const derivedPubKey = getPublicKey(privateKey);
    if (derivedPubKey !== publicKey) {
      alert('Public key does not match private key!');
      return;
    }
  } catch (err) {
    alert('Invalid private key');
    return;
  }

  browseState.myPublicKey = publicKey;
  browseState.myPrivateKey = privateKey;

  try {
    // Check if already registered
    try {
      await getParticipantByKey(browseState.poolId, publicKey);
    } catch (notFound) {
      // Not registered yet, register now
      await registerParticipant(browseState.poolId, {
        publicKey,
        displayName: document.getElementById('registerDisplayName').value,
        bio: document.getElementById('registerBio').value
      });
    }

    await loadParticipantsForBrowse();
    goToBrowseStep(3);
  } catch (e) {
    alert(e.message);
  }
}

/**
 * Load participants for browsing
 */
export async function loadParticipantsForBrowse() {
  const data = await fetchParticipants(browseState.poolId);
  browseState.participants = data.participants.filter(p => p.publicKey !== browseState.myPublicKey);
  browseState.currentIndex = 0;
  browseState.selections = [];
  document.getElementById('browsePoolName').textContent = browseState.poolName;
  updateBrowseUI();
}

/**
 * Update browse UI state
 */
export function updateBrowseUI() {
  // Progress indicator
  document.getElementById('browseProgress').textContent =
    browseState.currentIndex + ' / ' + browseState.participants.length + ' reviewed';

  // Profile card
  const card = document.getElementById('currentProfileCard');
  if (browseState.currentIndex >= browseState.participants.length) {
    card.innerHTML = '<div class="empty-state"><div class="empty-state-icon">✓</div><p>Done! Submit when ready.</p></div>';
  } else {
    const p = browseState.participants[browseState.currentIndex];
    card.innerHTML =
      '<div class="profile-avatar">' + (p.displayName || '?')[0].toUpperCase() + '</div>' +
      '<div class="profile-name">' + escapeHtml(p.displayName) + '</div>' +
      '<div class="profile-bio">' + escapeHtml(p.bio || '') + '</div>' +
      '<div class="profile-key">' + p.publicKey + '</div>';
  }

  // Selections count
  document.getElementById('selectionsCount').textContent = browseState.selections.length;
  document.getElementById('submitSelectionsBtn').disabled = !browseState.selections.length;

  // Selections list
  const selectionsList = document.getElementById('selectionsList');
  if (browseState.selections.length) {
    selectionsList.innerHTML = browseState.selections.map(s =>
      '<div class="selection-chip">' +
      '<span>' + escapeHtml(s.displayName) + '</span>' +
      '<button data-remove-key="' + s.publicKey + '">&times;</button>' +
      '</div>'
    ).join('');

    // Add remove handlers
    selectionsList.querySelectorAll('[data-remove-key]').forEach(btn => {
      btn.addEventListener('click', () => {
        removeSelectionByKey(btn.dataset.removeKey);
      });
    });
  } else {
    selectionsList.innerHTML = '<span class="text-muted">None yet</span>';
  }

  // Final selections (step 4)
  document.getElementById('finalSelectionsCount').textContent = browseState.selections.length;
  document.getElementById('finalSelectionsList').innerHTML = browseState.selections.map(s =>
    '<div class="selection-chip">' + escapeHtml(s.displayName) + '</div>'
  ).join('');

  // Browse button states
  document.getElementById('browsePrevBtn').disabled = browseState.currentIndex <= 0;
  document.getElementById('browseNextBtn').disabled = browseState.currentIndex >= browseState.participants.length;
}

/**
 * Handle swipe action (like/pass)
 * @param {string} action - 'like' or 'pass'
 */
export function handleSwipe(action) {
  if (browseState.currentIndex >= browseState.participants.length) return;

  if (action === 'like') {
    const participant = browseState.participants[browseState.currentIndex];
    browseState.selections.push({
      publicKey: participant.publicKey,
      displayName: participant.displayName
    });
  }

  browseState.currentIndex++;
  updateBrowseUI();
}

/**
 * Handle browse navigation (without selection)
 * @param {string} direction - 'prev' or 'next'
 */
export function handleBrowse(direction) {
  if (direction === 'prev' && browseState.currentIndex > 0) {
    browseState.currentIndex--;
  } else if (direction === 'next' && browseState.currentIndex < browseState.participants.length) {
    browseState.currentIndex++;
  }
  updateBrowseUI();
}

/**
 * Remove a selection by public key
 * @param {string} publicKey - Public key to remove
 */
export function removeSelectionByKey(publicKey) {
  browseState.selections = browseState.selections.filter(s => s.publicKey !== publicKey);
  updateBrowseUI();
}

/**
 * Submit selections
 */
export async function submitSelections() {
  const el = document.getElementById('submitResult');
  const submitBtn = document.getElementById('submitPrefsBtn');
  const backBtn = document.getElementById('submitBackBtn');

  const privateKey = document.getElementById('submitPrivateKey').value.trim();
  if (privateKey.length !== 64) {
    el.innerHTML = '<div class="result-box error">Invalid key</div>';
    el.classList.remove('hidden');
    return;
  }

  // Disable button immediately to prevent double-click
  submitBtn.disabled = true;
  submitBtn.textContent = 'Submitting...';

  try {
    if (getPublicKey(privateKey) !== browseState.myPublicKey) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Submit Encrypted Preferences';
      el.innerHTML = '<div class="result-box error">Key mismatch</div>';
      el.classList.remove('hidden');
      return;
    }

    // Get contact info for reveal on match
    const contactInfo = document.getElementById('revealContactInfo').value.trim();
    const revealMessage = document.getElementById('revealMessage').value.trim();
    const revealContent = { contact: contactInfo, message: revealMessage };

    // Generate real match tokens and encrypt reveal data for each
    const realTokens = [];
    const revealData = [];
    for (const selection of browseState.selections) {
      const token = deriveMatchToken(privateKey, selection.publicKey, browseState.poolId);
      realTokens.push(token);
      // Encrypt contact info with match token (only mutual match can decrypt)
      if (contactInfo || revealMessage) {
        const encrypted = await encryptRevealData(revealContent, token);
        revealData.push({ matchToken: token, encryptedReveal: encrypted });
      }
    }

    // Privacy enhancement: Add decoy tokens to hide true selection count
    const decoyCount = 3 + Math.floor(Math.random() * 6);
    const decoyTokens = generateDecoyTokens(decoyCount);

    // Shuffle real and decoy tokens together
    const allTokens = shuffleArray([...realTokens, ...decoyTokens]);

    await submitPreferences(browseState.poolId, {
      matchTokens: allTokens,
      nullifier: deriveNullifier(privateKey, browseState.poolId),
      revealData: revealData.length ? revealData : undefined
    });

    el.innerHTML = '<div class="result-box success">' +
      '<strong>Submitted!</strong> Check Discover tab after pool closes.<br>' +
      '<span class="text-sm text-muted">' + decoyCount + ' decoy tokens added for privacy.' +
      (contactInfo ? ' Contact info encrypted for matches.' : '') + '</span></div>';
    el.classList.remove('hidden');

    // Save discoveries for later
    const discoveries = getDiscoveries();
    discoveries[browseState.poolId] = { selections: browseState.selections };
    saveDiscoveries(discoveries);

    // Success - keep button disabled and hide back button to prevent resubmission
    submitBtn.textContent = 'Submitted ✓';
    backBtn.style.display = 'none';
  } catch (e) {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Submit Encrypted Preferences';
    el.innerHTML = '<div class="result-box error">' + e.message + '</div>';
    el.classList.remove('hidden');
  }
}

/**
 * Initialize browse-related event listeners
 */
export function initBrowseListeners() {
  // Registration form
  const registerForm = document.getElementById('registerForm');
  if (registerForm) {
    registerForm.addEventListener('submit', handleRegister);
  }

  // Listen for pool selection event
  window.addEventListener('selectPoolForBrowse', selectPoolForBrowse);
}
