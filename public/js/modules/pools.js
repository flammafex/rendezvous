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
 * Render the onboarding / empty-state experience shown when no pools exist.
 *
 * Explains what Rendezvous does, how the Diffie-Hellman match-token insight
 * works, what to do next, and the privacy guarantees the protocol enforces.
 * Returns an HTML string; the caller injects it into #poolList.
 */
function renderOnboarding() {
  return `
<div class="onboarding" aria-labelledby="onboarding-title">

  <section class="onboarding-hero">
    <div class="onboarding-eyebrow">Rendezvous</div>
    <h1 id="onboarding-title" class="onboarding-title">
      Find mutual interest without revealing who selected whom.
    </h1>
    <p class="onboarding-lede">
      Two parties can discover they mutually selected each other through a shared
      match token &mdash; derived independently from each person's private key and
      the other's public key. If only one selects, nothing is revealed.
    </p>
    <ul class="onboarding-usecases">
      <li>Dating</li>
      <li>Co-founder matching</li>
      <li>Hackathon teams</li>
      <li>Roommates</li>
      <li>Mentor pairing</li>
    </ul>
  </section>

  <section class="onboarding-section">
    <h2 class="onboarding-section-title">How it works</h2>
    <p class="onboarding-section-lede">
      Each person derives the same token from their private key and the other's
      public key (Diffie-Hellman). If both submit, the token appears twice
      &mdash; that's a match.
    </p>

    <div class="dh-diagram" role="img" aria-label="Alice and Bob each derive the same match token from their own private key and the other's public key.">
      <div class="dh-parties">
        <div class="dh-party">
          <div class="dh-party-name">Alice</div>
          <div class="dh-derivation">
            <code>priv<sub>A</sub></code>
            <span class="dh-op">+</span>
            <code>pub<sub>B</sub></code>
          </div>
          <div class="dh-arrow" aria-hidden="true"></div>
        </div>
        <div class="dh-party">
          <div class="dh-party-name">Bob</div>
          <div class="dh-derivation">
            <code>priv<sub>B</sub></code>
            <span class="dh-op">+</span>
            <code>pub<sub>A</sub></code>
          </div>
          <div class="dh-arrow" aria-hidden="true"></div>
        </div>
      </div>
      <div class="dh-shared">
        <code class="dh-shared-token">match_token</code>
        <div class="dh-shared-note">same value, derived independently</div>
      </div>
    </div>

    <ul class="dh-outcomes">
      <li class="dh-outcome dh-outcome-match">
        <span class="dh-outcome-marker" aria-hidden="true"></span>
        <span>Both submit &rarr; token appears <strong>twice</strong> &rarr; match revealed</span>
      </li>
      <li class="dh-outcome dh-outcome-silent">
        <span class="dh-outcome-marker" aria-hidden="true"></span>
        <span>One submits &rarr; token appears <strong>once</strong> &rarr; nothing revealed</span>
      </li>
    </ul>
  </section>

  <section class="onboarding-section">
    <h2 class="onboarding-section-title">Getting started</h2>
    <ol class="onboarding-steps">
      <li>
        <div class="step-marker">1</div>
        <div class="step-body">
          <strong>Create a pool</strong>
          <p>If you have an invite code (or this instance is open), create a pool for your group below.</p>
        </div>
      </li>
      <li>
        <div class="step-marker">2</div>
        <div class="step-body">
          <strong>Share it</strong>
          <p>Send the pool link or QR code to the people you want to match among.</p>
        </div>
      </li>
      <li>
        <div class="step-marker">3</div>
        <div class="step-body">
          <strong>Generate a fresh keypair</strong>
          <p>Each participant generates a new keypair per pool for pseudonymity. It lives on your device only.</p>
        </div>
      </li>
      <li>
        <div class="step-marker">4</div>
        <div class="step-body">
          <strong>Browse and select</strong>
          <p>Register a profile, browse the others, and select whoever you're interested in.</p>
        </div>
      </li>
      <li>
        <div class="step-marker">5</div>
        <div class="step-body">
          <strong>Close the pool</strong>
          <p>When the pool closes, only mutual matches are revealed to each other. Unilateral selections stay private.</p>
        </div>
      </li>
    </ol>
  </section>

  <section class="onboarding-section">
    <h2 class="onboarding-section-title">Privacy guarantees</h2>
    <div class="privacy-grid">
      <div class="privacy-item">
        <div class="privacy-item-title">Decoy tokens</div>
        <p>Each submission is padded with 3&ndash;8 random tokens, so the server can't tell how many people you actually selected.</p>
      </div>
      <div class="privacy-item">
        <div class="privacy-item-title">Padded responses</div>
        <p>All API responses are padded to a fixed 8KB size, hiding participant and match counts.</p>
      </div>
      <div class="privacy-item">
        <div class="privacy-item-title">Random delay</div>
        <p>A 30s&ndash;3min random delay before match computation makes timing correlation with submissions impractical.</p>
      </div>
      <div class="privacy-item">
        <div class="privacy-item-title">Ephemeral pools</div>
        <p>Pools marked ephemeral delete all participant profiles after match computation completes.</p>
      </div>
    </div>
  </section>

</div>
`;
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
      el.innerHTML = renderOnboarding();
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
      '<p><strong>ID:</strong> <code>' + escapeHtml(id) + '</code> <span id="poolIdCopyAction"></span></p>' +
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
      '<div id="poolDetailsActions" class="mt-2"></div>';

    // Add event handlers
    const copyAction = contentContainer.querySelector('#poolIdCopyAction');
    if (copyAction) {
      const copyBtn = document.createElement('button');
      copyBtn.className = 'btn-secondary btn-sm';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => copyText(id));
      copyAction.appendChild(copyBtn);
    }

    const actions = contentContainer.querySelector('#poolDetailsActions');
    if (actions) {
      if (pool.phase.currentPhase !== 'closed') {
        const joinBtn = document.createElement('button');
        joinBtn.className = 'btn-primary';
        joinBtn.textContent = 'Join';
        joinBtn.dataset.poolId = id;
        joinBtn.addEventListener('click', () => joinPool(id, poolName));
        actions.appendChild(joinBtn);
      }

      const shareBtn = document.createElement('button');
      shareBtn.className = 'btn-secondary';
      shareBtn.textContent = 'Share QR';
      shareBtn.style.marginLeft = '0.5rem';
      shareBtn.dataset.poolId = id;
      shareBtn.addEventListener('click', () => generatePoolQR(id, poolName));
      actions.appendChild(shareBtn);

      if (pool.phase.currentPhase !== 'closed' && isOwner) {
        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn-warning';
        closeBtn.textContent = 'Close';
        closeBtn.style.marginLeft = '0.5rem';
        closeBtn.dataset.poolId = id;
        closeBtn.addEventListener('click', () => closePool(id));
        actions.appendChild(closeBtn);
      }
    }
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
