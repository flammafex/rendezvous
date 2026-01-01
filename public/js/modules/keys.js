/**
 * Keys management module for Rendezvous
 */

import { generateKeypair } from './crypto.js';
import { escapeHtml, copyText } from './ui.js';
import { getCurrentKeypair, setCurrentKeypair, getSavedKeys, saveKeys } from './state.js';

/**
 * Generate a new keypair
 */
export function handleGenerateKeypair() {
  const keypair = generateKeypair();
  setCurrentKeypair(keypair);

  document.getElementById('generatedPublicKey').textContent = keypair.publicKey;
  document.getElementById('generatedPrivateKey').textContent = keypair.privateKey;
  document.getElementById('generatedKeys').classList.remove('hidden');
}

/**
 * Save current keypair to localStorage
 */
export function saveCurrentKey() {
  const keypair = getCurrentKeypair();
  if (!keypair) {
    alert('Generate first!');
    return;
  }

  const keys = getSavedKeys();
  keys.push({
    ...keypair,
    createdAt: new Date().toISOString()
  });
  saveKeys(keys);
  loadSavedKeys();
  alert('Saved!');
}

/**
 * Delete a saved key by index
 * @param {number} index - Key index
 */
export function deleteKey(index) {
  if (!confirm('Delete?')) return;

  const keys = getSavedKeys();
  keys.splice(index, 1);
  saveKeys(keys);
  loadSavedKeys();
}

/**
 * Generate a pseudonym (fresh identity for a specific pool)
 */
export function generatePseudonym() {
  const poolLabel = document.getElementById('pseudonymPoolName').value.trim() || 'Unnamed Pool';
  const keypair = generateKeypair();

  // Auto-save with pool label
  const keys = getSavedKeys();
  keys.push({
    ...keypair,
    createdAt: new Date().toISOString(),
    poolLabel: poolLabel
  });
  saveKeys(keys);

  // Show result
  document.getElementById('pseudonymPublicKey').textContent = keypair.publicKey;
  document.getElementById('pseudonymPrivateKey').textContent = keypair.privateKey;
  document.getElementById('pseudonymResult').classList.remove('hidden');

  // Update saved keys display
  loadSavedKeys();

  // Clear input for next use
  document.getElementById('pseudonymPoolName').value = '';
}

/**
 * Load and display saved keys
 */
export function loadSavedKeys() {
  const keys = getSavedKeys();
  const container = document.getElementById('savedKeys');

  if (keys.length) {
    container.innerHTML = keys.map((k, i) => {
      const label = k.poolLabel ? escapeHtml(k.poolLabel) : 'Key ' + (i + 1);
      return '<div class="card" style="padding:0.75rem;margin-bottom:0.5rem;">' +
        '<div class="text-sm" style="color:var(--accent);font-weight:500;">' + label + '</div>' +
        (k.poolLabel ? '<div class="text-sm text-muted">Created: ' + new Date(k.createdAt).toLocaleDateString() + '</div>' : '') +
        '<div class="key-display" style="font-size:0.7rem;margin:0.5rem 0;">' + k.publicKey + '</div>' +
        '<button class="btn-secondary btn-sm" data-copy-public="' + k.publicKey + '">Public</button> ' +
        '<button class="btn-secondary btn-sm" data-copy-private="' + k.privateKey + '">Private</button> ' +
        '<button class="btn-danger btn-sm" data-delete-key="' + i + '">Del</button></div>';
    }).join('');

    // Add event handlers
    container.querySelectorAll('[data-copy-public]').forEach(btn => {
      btn.addEventListener('click', () => copyText(btn.dataset.copyPublic));
    });

    container.querySelectorAll('[data-copy-private]').forEach(btn => {
      btn.addEventListener('click', () => copyText(btn.dataset.copyPrivate));
    });

    container.querySelectorAll('[data-delete-key]').forEach(btn => {
      btn.addEventListener('click', () => deleteKey(parseInt(btn.dataset.deleteKey)));
    });
  } else {
    container.innerHTML = '<p class="text-muted">No saved keys</p>';
  }
}

/**
 * Copy a key by element ID
 * @param {string} elementId - Element ID
 */
export function copyKey(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    copyText(element.textContent);
  }
}

/**
 * Initialize keys-related event listeners
 */
export function initKeysListeners() {
  // Generate keypair button
  const generateBtn = document.querySelector('[data-action="generate-keypair"]');
  if (generateBtn) {
    generateBtn.addEventListener('click', handleGenerateKeypair);
  }

  // Save current key button
  const saveBtn = document.querySelector('[data-action="save-current-key"]');
  if (saveBtn) {
    saveBtn.addEventListener('click', saveCurrentKey);
  }

  // Generate pseudonym button
  const pseudonymBtn = document.querySelector('[data-action="generate-pseudonym"]');
  if (pseudonymBtn) {
    pseudonymBtn.addEventListener('click', generatePseudonym);
  }

  // Copy key buttons
  document.querySelectorAll('[data-copy-key]').forEach(btn => {
    btn.addEventListener('click', () => copyKey(btn.dataset.copyKey));
  });
}
