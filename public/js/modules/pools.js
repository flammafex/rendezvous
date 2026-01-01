/**
 * Pool management module for Rendezvous
 */

import { fetchPools, fetchPool, fetchParticipants, createPool, closePool as apiClosePool } from './api.js';
import { generateKeypair, generateSigningKeypair, createSignedRequest } from './crypto.js';
import { escapeHtml, formatTime, copyText } from './ui.js';
import { getOwnedPool, saveOwnedPool, isPoolOwner, getFreebirdStatus, requiresInviteCode } from './state.js';
import { generatePoolQR } from './qr.js';
import { openJoinModal } from './join-flow.js';

/**
 * Update visibility of Create Pool reveal link based on Freebird status
 *
 * Visibility rules:
 * - Freebird unconfigured: Show reveal link (open/dev mode)
 * - Freebird connected: Show reveal link (requires invite code)
 * - Freebird disconnected: Hide reveal link (fail closed)
 */
export function updateCreatePoolVisibility() {
  const revealSection = document.getElementById('createPoolReveal');
  const createPoolCard = document.getElementById('createPoolCard');
  if (!revealSection) return;

  const freebirdStatus = getFreebirdStatus();

  if (freebirdStatus === 'disconnected' || freebirdStatus.startsWith('error')) {
    // Freebird configured but unavailable - hide the reveal link
    revealSection.classList.add('hidden');
    if (createPoolCard) createPoolCard.classList.add('hidden');
  } else {
    // Freebird connected or unconfigured - show reveal link
    revealSection.classList.remove('hidden');
  }
}

/**
 * Show the create pool form
 */
export function showCreatePoolForm() {
  const revealSection = document.getElementById('createPoolReveal');
  const createPoolCard = document.getElementById('createPoolCard');
  if (revealSection) revealSection.classList.add('hidden');
  if (createPoolCard) {
    createPoolCard.classList.remove('hidden');
    // Focus the pool name input
    const nameInput = document.getElementById('poolName');
    if (nameInput) nameInput.focus();
  }
}

/**
 * Hide the create pool form
 */
export function hideCreatePoolForm() {
  const revealSection = document.getElementById('createPoolReveal');
  const createPoolCard = document.getElementById('createPoolCard');
  if (createPoolCard) createPoolCard.classList.add('hidden');
  if (revealSection) revealSection.classList.remove('hidden');
}

/**
 * Load and display all pools
 */
export async function loadPools() {
  const el = document.getElementById('poolList');
  try {
    const pools = await fetchPools();
    if (pools.length) {
      el.innerHTML = pools.map(p =>
        '<div class="pool-item" data-pool-id="' + p.id + '">' +
        '<h3>' + escapeHtml(p.name) + '</h3>' +
        '<div class="pool-meta">' +
        '<span class="status status-' + p.phase.currentPhase + '">' + p.phase.currentPhase + '</span>' +
        '<span>' + formatTime(p.phase.remainingMs) + '</span>' +
        '</div></div>'
      ).join('');

      // Add click handlers
      el.querySelectorAll('.pool-item').forEach(item => {
        item.addEventListener('click', () => showPoolDetails(item.dataset.poolId));
      });
    } else {
      el.innerHTML = '<p class="text-muted">No pools yet</p>';
    }
  } catch (e) {
    el.innerHTML = '<p class="text-error">' + e.message + '</p>';
  }
}

/**
 * Load pools for browse dropdown
 */
export async function loadPoolsForBrowse() {
  try {
    const pools = await fetchPools();
    const select = document.getElementById('browsePoolSelect');
    select.innerHTML = '<option value="">-- Select --</option>' +
      pools
        .filter(p => p.phase.currentPhase !== 'closed')
        .map(p => '<option value="' + p.id + '">' + escapeHtml(p.name) + '</option>')
        .join('');
  } catch (e) {
    console.error('Failed to load pools for browse:', e);
  }
}

/**
 * Show pool details
 * @param {string} id - Pool ID
 */
export async function showPoolDetails(id) {
  const detailsContainer = document.getElementById('poolDetails');
  const contentContainer = document.getElementById('poolDetailsContent');

  detailsContainer.classList.remove('hidden');

  try {
    const pool = await fetchPool(id);
    const parts = await fetchParticipants(id);
    const poolName = pool.name;
    const isOwner = isPoolOwner(id);

    contentContainer.innerHTML =
      '<p><strong>ID:</strong> <code>' + id + '</code> ' +
      '<button class="btn-secondary btn-sm" data-copy="' + id + '">Copy</button></p>' +
      '<p><strong>Status:</strong> <span class="status status-' + pool.phase.currentPhase + '">' +
      pool.phase.currentPhase + '</span>' +
      (isOwner ? ' <span class="status" style="background:var(--accent);font-size:0.65rem;">OWNER</span>' : '') +
      (pool.ephemeral ? ' <span class="status" style="background:var(--warning);color:black;font-size:0.65rem;">EPHEMERAL</span>' : '') +
      '</p>' +
      '<p><strong>Participants:</strong> ' + parts.total + '</p>' +
      '<p><strong>Deadline:</strong> ' + new Date(pool.revealDeadline).toLocaleString() + '</p>' +
      (pool.ephemeral && pool.phase.currentPhase === 'closed'
        ? '<p class="text-sm text-muted">Profiles have been deleted (ephemeral mode)</p>'
        : '') +
      (pool.matchResult
        ? '<div class="match-result"><div class="match-count">' +
          pool.matchResult.matchedTokens.length + '</div><div class="match-label">Matches</div></div>'
        : '') +
      '<div class="mt-2">' +
      (pool.phase.currentPhase !== 'closed'
        ? '<button class="btn-primary" data-action="join" data-pool-id="' + id + '" data-pool-name="' + escapeHtml(poolName) + '">Join</button> '
        : '') +
      '<button class="btn-secondary" data-action="share" data-pool-id="' + id + '" data-pool-name="' +
      escapeHtml(poolName) + '">Share QR</button> ' +
      (pool.phase.currentPhase !== 'closed' && isOwner
        ? '<button class="btn-warning" data-action="close" data-pool-id="' + id + '">Close</button>'
        : '') +
      '</div>';

    // Add event handlers
    contentContainer.querySelectorAll('[data-copy]').forEach(btn => {
      btn.addEventListener('click', () => copyText(btn.dataset.copy));
    });

    contentContainer.querySelectorAll('[data-action="join"]').forEach(btn => {
      btn.addEventListener('click', () => joinPool(btn.dataset.poolId, btn.dataset.poolName));
    });

    contentContainer.querySelectorAll('[data-action="share"]').forEach(btn => {
      btn.addEventListener('click', () => generatePoolQR(btn.dataset.poolId, btn.dataset.poolName));
    });

    contentContainer.querySelectorAll('[data-action="close"]').forEach(btn => {
      btn.addEventListener('click', () => closePool(btn.dataset.poolId));
    });
  } catch (e) {
    contentContainer.innerHTML = '<p class="text-error">' + e.message + '</p>';
  }
}

/**
 * Join a pool (open join modal)
 * @param {string} id - Pool ID
 * @param {string} [name] - Pool name (optional)
 */
export async function joinPool(id, name) {
  // If name not provided, fetch pool details
  let poolName = name;
  if (!poolName) {
    try {
      const pool = await fetchPool(id);
      poolName = pool.name;
    } catch (e) {
      poolName = 'Pool';
    }
  }
  openJoinModal(id, poolName);
}

/**
 * Close a pool (owner-only)
 * @param {string} id - Pool ID
 */
export async function closePool(id) {
  // Check if user owns this pool
  const ownership = getOwnedPool(id);
  if (!ownership) {
    alert('You do not have permission to close this pool. Only the pool owner can close it.');
    return;
  }

  if (!confirm('Close this pool? Match computation will begin with a random privacy delay.')) {
    return;
  }

  try {
    // Create signed request for authentication
    const { signature, timestamp } = createSignedRequest('pool-close', id, ownership.signingPrivateKey);

    const result = await apiClosePool(id, {
      ownerPublicKey: ownership.creatorPublicKey,
      signature,
      timestamp
    });

    if (result.status === 'computing') {
      alert(result.message + '\n\nRefresh the pool in a few minutes to see results.');
    } else if (result.matchResult) {
      alert('Found ' + result.matchResult.matchedTokens.length + ' matches!');
    }
    showPoolDetails(id);
    loadPools();
  } catch (e) {
    alert(e.message);
  }
}

/**
 * Handle pool creation form submission
 * @param {Event} e - Form submit event
 */
export async function handleCreatePool(e) {
  e.preventDefault();

  const el = document.getElementById('createPoolResult');

  // Check invite code if required (when Freebird is configured)
  let inviteCode = null;
  if (requiresInviteCode()) {
    inviteCode = document.getElementById('inviteCode').value.trim();
    if (!inviteCode) {
      el.innerHTML = '<div class="result-box error">An invite code is required to create pools.</div>';
      el.classList.remove('hidden');
      return;
    }
  }

  try {
    // Generate both X25519 (for matching) and Ed25519 (for signing) keypairs
    const creator = generateKeypair();
    const signing = generateSigningKeypair();
    const ephemeral = document.getElementById('poolEphemeral').checked;
    const requiresInviteToJoin = document.getElementById('poolRequiresInvite').checked;
    const poolName = document.getElementById('poolName').value;

    const requestBody = {
      name: poolName,
      description: document.getElementById('poolDescription').value,
      creatorPublicKey: creator.publicKey,
      creatorSigningKey: signing.signingPublicKey,
      revealDeadline: new Date(
        Date.now() + parseInt(document.getElementById('revealDeadline').value) * 3600000
      ).toISOString(),
      maxPreferencesPerParticipant: document.getElementById('maxPreferences').value
        ? parseInt(document.getElementById('maxPreferences').value)
        : undefined,
      ephemeral: ephemeral,
      requiresInviteToJoin: requiresInviteToJoin
    };

    if (inviteCode) {
      requestBody.inviteCode = inviteCode;
    }

    const pool = await createPool(requestBody);

    // Save ownership data for this pool
    saveOwnedPool(pool.id, {
      creatorPublicKey: creator.publicKey,
      signingPublicKey: signing.signingPublicKey,
      signingPrivateKey: signing.signingPrivateKey,
      poolName: pool.name
    });

    // Reset form and hide it
    e.target.reset();
    document.getElementById('revealDeadline').value = '24';
    document.getElementById('inviteCode').value = '';
    el.classList.add('hidden');
    hideCreatePoolForm();

    // Reload pools to show the new one
    await loadPools();

    // Show the new pool's details
    showPoolDetails(pool.id);
  } catch (err) {
    el.innerHTML = '<div class="result-box error">' + err.message + '</div>';
    el.classList.remove('hidden');
  }
}

/**
 * Initialize pool-related event listeners
 */
export function initPoolListeners() {
  const createForm = document.getElementById('createPoolForm');
  if (createForm) {
    createForm.addEventListener('submit', handleCreatePool);
  }

  // Refresh button
  const refreshBtn = document.querySelector('[data-action="refresh-pools"]');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadPools);
  }

  // Create pool reveal button
  const revealBtn = document.getElementById('createPoolRevealBtn');
  if (revealBtn) {
    revealBtn.addEventListener('click', showCreatePoolForm);
  }

  // Create pool close button
  const closeBtn = document.getElementById('createPoolCloseBtn');
  if (closeBtn) {
    closeBtn.addEventListener('click', hideCreatePoolForm);
  }
}
