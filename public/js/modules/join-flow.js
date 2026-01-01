/**
 * Join Flow Module for Rendezvous
 * Handles the guided join modal for visitors
 */

import { fetchPool, fetchParticipants, registerParticipant, getParticipantByKey, submitPreferences } from './api.js';
import { generateKeypair, getPublicKey, deriveMatchToken, deriveNullifier, encryptRevealData, generateDecoyTokens, shuffleArray } from './crypto.js';
import { escapeHtml } from './ui.js';
import { getSavedKeys, saveKeys, markParticipation, hasParticipated, getDiscoveries, saveDiscoveries } from './state.js';

// Join flow state
const joinState = {
  poolId: null,
  poolName: null,
  publicKey: null,
  privateKey: null,
  displayName: null,
  bio: null,
  participants: [],
  currentIndex: 0,
  selections: [],
  currentStep: 1,
  requiresInviteToJoin: false,
  inviteCode: null
};

/**
 * Reset join flow state
 */
function resetJoinState() {
  joinState.poolId = null;
  joinState.poolName = null;
  joinState.publicKey = null;
  joinState.privateKey = null;
  joinState.displayName = null;
  joinState.bio = null;
  joinState.participants = [];
  joinState.currentIndex = 0;
  joinState.selections = [];
  joinState.currentStep = 1;
  joinState.requiresInviteToJoin = false;
  joinState.inviteCode = null;
}

/**
 * Create the join modal DOM structure
 */
function createJoinModal() {
  if (document.getElementById('joinModal')) return;

  const modal = document.createElement('div');
  modal.id = 'joinModal';
  modal.className = 'join-modal';
  modal.innerHTML = `
    <div class="join-modal-content">
      <div class="join-modal-header">
        <h2><span id="joinPoolName">Join Pool</span></h2>
        <button class="join-modal-close" id="joinModalClose">&times;</button>
      </div>

      <div class="join-progress">
        <div class="join-progress-step active" data-step="1">
          <span class="join-progress-number">1</span>
          <span>Identity</span>
        </div>
        <div class="join-progress-step" data-step="2">
          <span class="join-progress-number">2</span>
          <span>Browse</span>
        </div>
        <div class="join-progress-step" data-step="3">
          <span class="join-progress-number">3</span>
          <span>Submit</span>
        </div>
      </div>

      <!-- Step 1: Create Identity -->
      <div class="join-step active" data-step="1">
        <div class="identity-preview">
          <div class="identity-avatar" id="joinIdentityAvatar">?</div>
          <div class="identity-id-label">Your ID</div>
          <div class="identity-id" id="joinIdentityId">Generating...</div>
        </div>

        <div id="joinExistingKeysSection" class="existing-keys-section hidden">
          <div class="existing-keys-toggle" id="joinExistingKeysToggle">
            <span>Use existing identity</span>
            <span id="joinExistingKeysArrow">&#9662;</span>
          </div>
          <div class="existing-keys-list" id="joinExistingKeysList"></div>
        </div>

        <form id="joinIdentityForm">
          <div class="form-group">
            <label for="joinDisplayName">Display Name *</label>
            <input type="text" id="joinDisplayName" placeholder="Your name" required>
          </div>
          <div class="form-group">
            <label for="joinBio">Bio (optional)</label>
            <textarea id="joinBio" placeholder="Tell people about yourself..." rows="2"></textarea>
          </div>
          <div id="joinInviteCodeSection" class="form-group hidden">
            <label for="joinInviteCode">Invite Code *</label>
            <input type="text" id="joinInviteCode" class="input-mono" placeholder="Enter your invite code">
            <p class="text-sm text-muted">This pool requires an invite code to join.</p>
          </div>
        </form>

        <div class="join-modal-footer">
          <button class="btn-secondary" id="joinCancelBtn">Cancel</button>
          <button class="btn-primary" id="joinContinueStep1">Continue</button>
        </div>
      </div>

      <!-- Step 2: Browse Participants -->
      <div class="join-step" data-step="2">
        <div class="join-browse-container">
          <div class="join-browse-progress" id="joinBrowseProgress">0 / 0 reviewed</div>

          <div id="joinProfileCard" class="join-profile-card">
            <div class="join-loading">
              <div class="join-loading-spinner"></div>
              <span>Loading participants...</span>
            </div>
          </div>

          <div class="join-swipe-buttons">
            <button class="join-swipe-btn nav" id="joinPrevBtn" disabled>&#8592;</button>
            <button class="join-swipe-btn pass" id="joinPassBtn">&#10005;</button>
            <button class="join-swipe-btn like" id="joinLikeBtn">&#10003;</button>
            <button class="join-swipe-btn nav" id="joinNextBtn">&#8594;</button>
          </div>

          <div class="join-selections" id="joinSelections">
            <div class="join-selections-header">
              <span><span class="join-selections-count" id="joinSelectionsCount">0</span> selected</span>
            </div>
            <div class="join-selections-list" id="joinSelectionsList">
              <span class="text-muted">None yet</span>
            </div>
          </div>
        </div>

        <div class="join-modal-footer">
          <button class="btn-secondary" id="joinBackStep2">Back</button>
          <button class="btn-primary" id="joinContinueStep2" disabled>Continue to Submit</button>
        </div>
      </div>

      <!-- Step 3: Confirm & Submit -->
      <div class="join-step" data-step="3">
        <div class="privacy-note">
          <strong>Privacy Guarantee:</strong> Your selections are encrypted.
          Only mutual matches will be revealed.
        </div>

        <div class="join-confirm-selections">
          <h4>You selected <strong id="joinFinalCount">0</strong> people:</h4>
          <div class="join-confirm-list" id="joinFinalList"></div>
        </div>

        <div class="form-group" style="background:var(--bg-input);padding:1rem;border-radius:0.5rem;border:1px solid var(--border);">
          <label style="color:var(--accent);font-weight:500;">Contact Info (revealed only to mutual matches)</label>
          <input type="text" id="joinContactInfo" placeholder="e.g., email@example.com or @twitter_handle" style="margin-bottom:0.5rem;">
          <textarea id="joinMessage" rows="2" placeholder="Optional message to your matches..." style="margin-bottom:0;"></textarea>
          <p class="text-sm text-muted mt-1">This will be encrypted and only visible to people who also selected you.</p>
        </div>

        <div id="joinSubmitResult" class="hidden"></div>

        <div class="join-modal-footer">
          <button class="btn-secondary" id="joinBackStep3">Back</button>
          <button class="btn-success" id="joinSubmitBtn" style="flex:1;">Submit Encrypted Preferences</button>
        </div>
      </div>

      <!-- Success State -->
      <div class="join-step" data-step="success">
        <div class="join-success">
          <div class="join-success-icon">&#10003;</div>
          <h3>Submitted Successfully!</h3>
          <p class="text-muted">Check the Discover tab after the pool closes to see your matches.</p>
        </div>
        <div class="join-modal-footer">
          <button class="btn-primary" id="joinDoneBtn" style="flex:1;">Done</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  attachJoinModalListeners();
}

/**
 * Attach event listeners to join modal
 */
function attachJoinModalListeners() {
  // Close button
  document.getElementById('joinModalClose').addEventListener('click', () => {
    if (joinState.currentStep === 1 || confirm('Are you sure? Your progress will be lost.')) {
      closeJoinModal();
    }
  });

  // Cancel button (step 1)
  document.getElementById('joinCancelBtn').addEventListener('click', closeJoinModal);

  // Existing keys toggle
  document.getElementById('joinExistingKeysToggle').addEventListener('click', toggleExistingKeys);

  // Step 1 continue
  document.getElementById('joinContinueStep1').addEventListener('click', handleStep1Continue);

  // Step 2 navigation
  document.getElementById('joinBackStep2').addEventListener('click', () => goToJoinStep(1));
  document.getElementById('joinPrevBtn').addEventListener('click', () => handleJoinBrowse('prev'));
  document.getElementById('joinNextBtn').addEventListener('click', () => handleJoinBrowse('next'));
  document.getElementById('joinPassBtn').addEventListener('click', () => handleJoinSwipe('pass'));
  document.getElementById('joinLikeBtn').addEventListener('click', () => handleJoinSwipe('like'));
  document.getElementById('joinContinueStep2').addEventListener('click', () => goToJoinStep(3));

  // Step 3 navigation
  document.getElementById('joinBackStep3').addEventListener('click', () => goToJoinStep(2));
  document.getElementById('joinSubmitBtn').addEventListener('click', handleJoinSubmit);

  // Done button
  document.getElementById('joinDoneBtn').addEventListener('click', () => {
    closeJoinModal();
    unlockAllTabs();
  });

  // Close on overlay click
  document.getElementById('joinModal').addEventListener('click', (e) => {
    if (e.target.id === 'joinModal') {
      if (joinState.currentStep === 1 || confirm('Are you sure? Your progress will be lost.')) {
        closeJoinModal();
      }
    }
  });
}

/**
 * Open the join modal for a pool
 * @param {string} poolId - Pool ID
 * @param {string} poolName - Pool name
 */
export async function openJoinModal(poolId, poolName) {
  createJoinModal();
  resetJoinState();

  joinState.poolId = poolId;
  joinState.poolName = poolName;

  document.getElementById('joinPoolName').textContent = poolName || 'Join Pool';

  // Fetch pool to check if invite is required
  try {
    const pool = await fetchPool(poolId);
    joinState.requiresInviteToJoin = pool.requiresInviteToJoin === true;
  } catch (e) {
    console.error('Failed to fetch pool:', e);
    joinState.requiresInviteToJoin = false;
  }

  // Show/hide invite code field
  const inviteSection = document.getElementById('joinInviteCodeSection');
  if (joinState.requiresInviteToJoin) {
    inviteSection.classList.remove('hidden');
  } else {
    inviteSection.classList.add('hidden');
  }

  // Generate fresh keypair
  const keypair = generateKeypair();
  joinState.publicKey = keypair.publicKey;
  joinState.privateKey = keypair.privateKey;

  // Update identity preview
  updateIdentityPreview();

  // Show existing keys if any
  const savedKeys = getSavedKeys();
  const existingSection = document.getElementById('joinExistingKeysSection');
  if (savedKeys.length > 0) {
    existingSection.classList.remove('hidden');
    renderExistingKeys(savedKeys);
  } else {
    existingSection.classList.add('hidden');
  }

  // Reset form
  document.getElementById('joinDisplayName').value = '';
  document.getElementById('joinBio').value = '';
  document.getElementById('joinInviteCode').value = '';

  // Show modal
  goToJoinStep(1);
  document.getElementById('joinModal').classList.add('active');
  document.getElementById('joinDisplayName').focus();
}

/**
 * Close the join modal
 */
export function closeJoinModal() {
  const modal = document.getElementById('joinModal');
  if (modal) {
    modal.classList.remove('active');
  }
  resetJoinState();
}

/**
 * Update identity preview avatar and ID
 */
function updateIdentityPreview() {
  const displayName = document.getElementById('joinDisplayName')?.value || '?';
  document.getElementById('joinIdentityAvatar').textContent = displayName[0]?.toUpperCase() || '?';
  document.getElementById('joinIdentityId').textContent =
    joinState.publicKey ? joinState.publicKey.substring(0, 16) + '...' : 'Generating...';
}

/**
 * Toggle existing keys dropdown
 */
function toggleExistingKeys() {
  const list = document.getElementById('joinExistingKeysList');
  const arrow = document.getElementById('joinExistingKeysArrow');
  list.classList.toggle('expanded');
  arrow.textContent = list.classList.contains('expanded') ? '\u25B4' : '\u25BE';
}

/**
 * Render existing keys list
 */
function renderExistingKeys(keys) {
  const list = document.getElementById('joinExistingKeysList');
  list.innerHTML = keys.map((key, index) =>
    '<div class="existing-key-option" data-index="' + index + '">' +
    '<div class="existing-key-label">' + escapeHtml(key.label || 'Key ' + (index + 1)) + '</div>' +
    '<div class="existing-key-id">' + key.publicKey.substring(0, 12) + '...</div>' +
    '</div>'
  ).join('');

  // Add click handlers
  list.querySelectorAll('.existing-key-option').forEach(option => {
    option.addEventListener('click', () => {
      const index = parseInt(option.dataset.index);
      selectExistingKey(index);
    });
  });
}

/**
 * Select an existing key
 */
function selectExistingKey(index) {
  const savedKeys = getSavedKeys();
  const key = savedKeys[index];
  if (!key) return;

  joinState.publicKey = key.publicKey;
  joinState.privateKey = key.privateKey;

  // Update UI
  updateIdentityPreview();

  // Mark as selected
  document.querySelectorAll('.existing-key-option').forEach((el, i) => {
    el.classList.toggle('selected', i === index);
  });
}

/**
 * Go to a specific step in the join flow
 */
function goToJoinStep(step) {
  joinState.currentStep = step;

  // Update progress indicators
  document.querySelectorAll('.join-progress-step').forEach(el => {
    const stepNum = parseInt(el.dataset.step);
    el.classList.remove('active', 'completed');
    if (stepNum < step) el.classList.add('completed');
    if (stepNum === step) el.classList.add('active');
  });

  // Show/hide steps
  document.querySelectorAll('.join-step').forEach(el => {
    el.classList.remove('active');
    if (el.dataset.step === String(step) || el.dataset.step === step) {
      el.classList.add('active');
    }
  });
}

/**
 * Handle step 1 continue (identity creation)
 */
async function handleStep1Continue() {
  const displayName = document.getElementById('joinDisplayName').value.trim();
  if (!displayName) {
    alert('Please enter a display name');
    return;
  }

  // Validate invite code if required
  if (joinState.requiresInviteToJoin) {
    const inviteCode = document.getElementById('joinInviteCode').value.trim();
    if (!inviteCode) {
      alert('An invite code is required to join this pool');
      return;
    }
    joinState.inviteCode = inviteCode;
  }

  joinState.displayName = displayName;
  joinState.bio = document.getElementById('joinBio').value.trim();

  // Save keypair for this pool
  const savedKeys = getSavedKeys();
  const existingIndex = savedKeys.findIndex(k => k.publicKey === joinState.publicKey);
  if (existingIndex === -1) {
    savedKeys.push({
      publicKey: joinState.publicKey,
      privateKey: joinState.privateKey,
      label: joinState.poolName || 'Pool Key',
      savedAt: Date.now()
    });
    saveKeys(savedKeys);
  }

  // Register with pool
  try {
    document.getElementById('joinContinueStep1').disabled = true;
    document.getElementById('joinContinueStep1').textContent = 'Registering...';

    // Check if already registered
    try {
      await getParticipantByKey(joinState.poolId, joinState.publicKey);
    } catch (notFound) {
      // Not registered yet, register now
      await registerParticipant(joinState.poolId, {
        publicKey: joinState.publicKey,
        displayName: joinState.displayName,
        bio: joinState.bio
      });
    }

    // Load participants
    await loadJoinParticipants();

    document.getElementById('joinContinueStep1').disabled = false;
    document.getElementById('joinContinueStep1').textContent = 'Continue';

    goToJoinStep(2);
  } catch (e) {
    document.getElementById('joinContinueStep1').disabled = false;
    document.getElementById('joinContinueStep1').textContent = 'Continue';
    alert(e.message);
  }
}

/**
 * Load participants for browsing in join modal
 */
async function loadJoinParticipants() {
  const data = await fetchParticipants(joinState.poolId);
  joinState.participants = data.participants.filter(p => p.publicKey !== joinState.publicKey);
  joinState.currentIndex = 0;
  joinState.selections = [];
  updateJoinBrowseUI();
}

/**
 * Update browse UI in join modal
 */
function updateJoinBrowseUI() {
  // Progress
  document.getElementById('joinBrowseProgress').textContent =
    joinState.currentIndex + ' / ' + joinState.participants.length + ' reviewed';

  // Profile card
  const card = document.getElementById('joinProfileCard');
  if (joinState.participants.length === 0) {
    card.innerHTML = '<div class="join-browse-empty">' +
      '<div class="join-browse-empty-icon">&#128101;</div>' +
      '<p>No other participants yet.<br>Come back later or submit without selections.</p></div>';
  } else if (joinState.currentIndex >= joinState.participants.length) {
    card.innerHTML = '<div class="join-browse-empty">' +
      '<div class="join-browse-empty-icon">&#10003;</div>' +
      '<p>All reviewed!<br>Continue to submit your selections.</p></div>';
  } else {
    const p = joinState.participants[joinState.currentIndex];
    card.innerHTML =
      '<div class="join-profile-avatar">' + (p.displayName || '?')[0].toUpperCase() + '</div>' +
      '<div class="join-profile-name">' + escapeHtml(p.displayName) + '</div>' +
      '<div class="join-profile-bio">' + escapeHtml(p.bio || '') + '</div>' +
      '<div class="join-profile-key">' + p.publicKey + '</div>';
  }

  // Selections count
  document.getElementById('joinSelectionsCount').textContent = joinState.selections.length;
  document.getElementById('joinContinueStep2').disabled = false; // Can always continue, even with 0 selections

  // Selections list
  const selectionsList = document.getElementById('joinSelectionsList');
  if (joinState.selections.length) {
    selectionsList.innerHTML = joinState.selections.map(s =>
      '<div class="selection-chip">' +
      '<span>' + escapeHtml(s.displayName) + '</span>' +
      '<button data-remove-key="' + s.publicKey + '">&times;</button>' +
      '</div>'
    ).join('');

    selectionsList.querySelectorAll('[data-remove-key]').forEach(btn => {
      btn.addEventListener('click', () => {
        joinState.selections = joinState.selections.filter(s => s.publicKey !== btn.dataset.removeKey);
        updateJoinBrowseUI();
      });
    });
  } else {
    selectionsList.innerHTML = '<span class="text-muted">None yet</span>';
  }

  // Update step 3 preview
  document.getElementById('joinFinalCount').textContent = joinState.selections.length;
  document.getElementById('joinFinalList').innerHTML = joinState.selections.map(s =>
    '<div class="selection-chip">' + escapeHtml(s.displayName) + '</div>'
  ).join('') || '<span class="text-muted">No selections</span>';

  // Navigation buttons
  document.getElementById('joinPrevBtn').disabled = joinState.currentIndex <= 0;
  document.getElementById('joinNextBtn').disabled = joinState.currentIndex >= joinState.participants.length;
}

/**
 * Handle swipe action in join modal
 */
function handleJoinSwipe(action) {
  if (joinState.currentIndex >= joinState.participants.length) return;

  if (action === 'like') {
    const participant = joinState.participants[joinState.currentIndex];
    // Prevent duplicates
    if (!joinState.selections.find(s => s.publicKey === participant.publicKey)) {
      joinState.selections.push({
        publicKey: participant.publicKey,
        displayName: participant.displayName
      });
    }
  }

  joinState.currentIndex++;
  updateJoinBrowseUI();
}

/**
 * Handle browse navigation in join modal
 */
function handleJoinBrowse(direction) {
  if (direction === 'prev' && joinState.currentIndex > 0) {
    joinState.currentIndex--;
  } else if (direction === 'next' && joinState.currentIndex < joinState.participants.length) {
    joinState.currentIndex++;
  }
  updateJoinBrowseUI();
}

/**
 * Handle join submission
 */
async function handleJoinSubmit() {
  const submitBtn = document.getElementById('joinSubmitBtn');
  const resultEl = document.getElementById('joinSubmitResult');

  submitBtn.disabled = true;
  submitBtn.textContent = 'Submitting...';

  try {
    const contactInfo = document.getElementById('joinContactInfo').value.trim();
    const revealMessage = document.getElementById('joinMessage').value.trim();
    const revealContent = { contact: contactInfo, message: revealMessage };

    // Generate real match tokens and encrypt reveal data
    const realTokens = [];
    const revealData = [];
    for (const selection of joinState.selections) {
      const token = deriveMatchToken(joinState.privateKey, selection.publicKey, joinState.poolId);
      realTokens.push(token);
      if (contactInfo || revealMessage) {
        const encrypted = await encryptRevealData(revealContent, token);
        revealData.push({ matchToken: token, encryptedReveal: encrypted });
      }
    }

    // Add decoy tokens for privacy
    const decoyCount = 3 + Math.floor(Math.random() * 6);
    const decoyTokens = generateDecoyTokens(decoyCount);
    const allTokens = shuffleArray([...realTokens, ...decoyTokens]);

    const submissionData = {
      matchTokens: allTokens,
      nullifier: deriveNullifier(joinState.privateKey, joinState.poolId),
      revealData: revealData.length ? revealData : undefined
    };

    // Include invite code if required
    if (joinState.inviteCode) {
      submissionData.inviteCode = joinState.inviteCode;
    }

    await submitPreferences(joinState.poolId, submissionData);

    // Mark participation
    markParticipation(joinState.poolId, joinState.publicKey);

    // Save discoveries for later
    const discoveries = getDiscoveries();
    discoveries[joinState.poolId] = { selections: joinState.selections };
    saveDiscoveries(discoveries);

    // Show success
    goToJoinStep('success');

  } catch (e) {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Submit Encrypted Preferences';
    resultEl.innerHTML = '<div class="result-box error">' + escapeHtml(e.message) + '</div>';
    resultEl.classList.remove('hidden');
  }
}

/**
 * Unlock all tabs after first participation
 */
export function unlockAllTabs() {
  document.querySelectorAll('.tab.visitor-hidden').forEach(tab => {
    tab.classList.add('unlocked');
  });
  // Dispatch event for main.js to update Create Pool visibility
  window.dispatchEvent(new CustomEvent('participationUnlocked'));
}

/**
 * Check and update tab visibility based on participation
 */
export function updateTabVisibility() {
  const shouldUnlock = hasParticipated();
  document.querySelectorAll('.tab.visitor-hidden').forEach(tab => {
    if (shouldUnlock) {
      tab.classList.add('unlocked');
    } else {
      tab.classList.remove('unlocked');
    }
  });
}

/**
 * Initialize join flow (call on app start)
 */
export function initJoinFlow() {
  // Update tab visibility based on participation
  updateTabVisibility();

  // Update identity preview on name input
  const displayNameInput = document.getElementById('joinDisplayName');
  if (displayNameInput) {
    displayNameInput.addEventListener('input', updateIdentityPreview);
  }
}
