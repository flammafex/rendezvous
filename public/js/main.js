/**
 * Main entry point for Rendezvous
 * Initializes all modules and sets up the application
 */

// Import modules
import './modules/theme.js'; // Auto-initializes on import
import { fetchStatus } from './modules/api.js';
import { setFreebirdStatus } from './modules/state.js';
import { copyText } from './modules/ui.js';
import { loadPools, loadPoolsForBrowse, initPoolListeners, updateCreatePoolVisibility, joinPool } from './modules/pools.js';
import { initBrowseListeners, updateParticipatedHint } from './modules/browse.js';
import { initDiscoverListeners } from './modules/discover.js';
import {
  handleGenerateKeypair,
  saveCurrentKey,
  generatePseudonym,
  loadSavedKeys,
  copyKey,
  deleteKey,
  initKeysListeners
} from './modules/keys.js';
import { startQRScanner, initQRListeners } from './modules/qr.js';
import { showExportKeysModal, showImportKeysModal, initSyncListeners } from './modules/sync.js';
import { initJoinFlow, updateTabVisibility } from './modules/join-flow.js';

/**
 * Initialize tab navigation with ARIA tablist semantics.
 *
 * Implements roving tabindex: only the active tab has tabindex="0", others
 * have tabindex="-1". Arrow Left/Right moves focus between visible tabs.
 * aria-selected and aria-hidden are kept in sync on every switch.
 */
function initTabs() {
  const tablist = document.querySelector('[role="tablist"]');
  if (!tablist) return;

  const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));

  function activateTab(tab) {
    // Update tab states
    tabs.forEach(t => {
      const isActive = t === tab;
      t.classList.toggle('active', isActive);
      t.setAttribute('aria-selected', isActive ? 'true' : 'false');
      t.setAttribute('tabindex', isActive ? '0' : '-1');
    });

    // Update panel states
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById(tab.dataset.tab);
    if (panel) panel.classList.add('active');

    // Load pools for browse when switching to browse tab
    if (tab.dataset.tab === 'browse') {
      loadPoolsForBrowse();
      updateParticipatedHint();
    }

    // Move focus to the activated tab (for click + arrow navigation)
    tab.focus();
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => activateTab(tab));
  });

  // Arrow-key navigation between tabs (roving tabindex pattern)
  tablist.addEventListener('keydown', (e) => {
    const visibleTabs = tabs.filter(t => !t.classList.contains('visitor-hidden') || t.classList.contains('unlocked'));
    const currentIndex = visibleTabs.indexOf(document.activeElement);
    if (currentIndex === -1) return;

    let targetIndex = -1;
    if (e.key === 'ArrowRight') {
      targetIndex = (currentIndex + 1) % visibleTabs.length;
    } else if (e.key === 'ArrowLeft') {
      targetIndex = (currentIndex - 1 + visibleTabs.length) % visibleTabs.length;
    } else if (e.key === 'Home') {
      targetIndex = 0;
    } else if (e.key === 'End') {
      targetIndex = visibleTabs.length - 1;
    }

    if (targetIndex >= 0 && visibleTabs[targetIndex]) {
      e.preventDefault();
      activateTab(visibleTabs[targetIndex]);
    }
  });
}

/**
 * Load and display service status
 */
async function loadServiceStatus() {
  try {
    const status = await fetchStatus();

    // Freebird status
    const freebirdDot = document.getElementById('freebird-status-dot');
    const freebirdText = document.getElementById('freebird-status-text');
    if (status.freebird === 'connected') {
      freebirdDot.className = 'status-dot connected';
      freebirdText.textContent = 'Freebird: Connected';
    } else if (status.freebird === 'unconfigured') {
      freebirdDot.className = 'status-dot unconfigured';
      freebirdText.textContent = 'Freebird: Not configured';
    } else {
      freebirdDot.className = 'status-dot disconnected';
      freebirdText.textContent = 'Freebird: ' + (status.freebird === 'disconnected' ? 'Disconnected' : status.freebird);
    }

    // Store Freebird status for pool creation authorization
    setFreebirdStatus(status.freebird, status.requiresInvite === true);
    updateTabVisibility();
    updateCreatePoolVisibility();

    // Show/hide invite code input based on Freebird configuration
    const inviteSection = document.getElementById('inviteCodeSection');
    if (status.requiresInvite) {
      inviteSection.classList.remove('hidden');
    } else {
      inviteSection.classList.add('hidden');
    }

    // Witness status
    const witnessDot = document.getElementById('witness-status-dot');
    const witnessText = document.getElementById('witness-status-text');
    if (status.witness === 'connected') {
      witnessDot.className = 'status-dot connected';
      witnessText.textContent = 'Witness: Connected';
    } else if (status.witness === 'unconfigured') {
      witnessDot.className = 'status-dot unconfigured';
      witnessText.textContent = 'Witness: Not configured';
    } else {
      witnessDot.className = 'status-dot disconnected';
      witnessText.textContent = 'Witness: ' + (status.witness === 'disconnected' ? 'Disconnected' : status.witness);
    }

    // Federation status
    const federationDot = document.getElementById('federation-status-dot');
    const federationText = document.getElementById('federation-status-text');
    if (status.federation === 'connected') {
      federationDot.className = 'status-dot connected';
      federationText.textContent = 'Federation: ' + status.federationPeers + ' peers';
    } else if (status.federation === 'enabled') {
      federationDot.className = 'status-dot unconfigured';
      federationText.textContent = 'Federation: No peers';
    } else {
      federationDot.className = 'status-dot unconfigured';
      federationText.textContent = 'Federation: Disabled';
    }
  } catch (e) {
    document.getElementById('freebird-status-dot').className = 'status-dot disconnected';
    document.getElementById('freebird-status-text').textContent = 'Freebird: Error';
    document.getElementById('witness-status-dot').className = 'status-dot disconnected';
    document.getElementById('witness-status-text').textContent = 'Witness: Error';
    document.getElementById('federation-status-dot').className = 'status-dot disconnected';
    document.getElementById('federation-status-text').textContent = 'Federation: Error';
  }
}

/**
 * Initialize service worker for PWA
 */
function initServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
      .then((reg) => console.log('Service worker registered:', reg.scope))
      .catch((err) => console.error('Service worker registration failed:', err));
  }
}

/**
 * Initialize offline detection
 */
function initOfflineDetection() {
  window.addEventListener('online', () => {
    document.body.classList.remove('offline');
    loadServiceStatus();
    loadPools();
  });

  window.addEventListener('offline', () => {
    document.body.classList.add('offline');
  });
}

/**
 * Initialize participation unlock listener
 */
function initParticipationListener() {
  window.addEventListener('participationUnlocked', () => {
    updateCreatePoolVisibility();
  });
}

/**
 * Handle URL parameters for deep links
 */
function handleUrlParams() {
  const urlParams = new URLSearchParams(window.location.search);
  const poolParam = urlParams.get('pool');
  const tabParam = urlParams.get('tab');

  if (poolParam) {
    // Open join modal for the pool
    joinPool(poolParam);
  } else if (tabParam) {
    const tabBtn = document.querySelector('[data-tab="' + tabParam + '"]');
    // Allow clicking if tab is not hidden OR if it's unlocked
    if (tabBtn && (!tabBtn.classList.contains('visitor-hidden') || tabBtn.classList.contains('unlocked'))) {
      tabBtn.click();
    }
  }
}

/**
 * Initialize inline onclick handlers that need global scope
 * These are used in HTML onclick attributes
 */
function initGlobalHandlers() {
  // QR actions
  window.startQRScanner = startQRScanner;

  // Key actions
  window.generateKeypair = handleGenerateKeypair;
  window.saveCurrentKey = saveCurrentKey;
  window.generatePseudonym = generatePseudonym;
  window.copyKey = copyKey;
  window.copyText = copyText;

  // Sync actions
  window.showExportKeysModal = showExportKeysModal;
  window.showImportKeysModal = showImportKeysModal;

  // Pool actions
  window.loadPools = loadPools;

  // Delete key (used in dynamic HTML)
  window.deleteKey = deleteKey;
}

/**
 * Initialize the application
 */
function init() {
  // Initialize tab navigation
  initTabs();

  // Initialize all module listeners
  initPoolListeners();
  initBrowseListeners();
  initDiscoverListeners();
  initKeysListeners();
  initQRListeners();
  initSyncListeners();
  initJoinFlow();

  // Initialize global handlers for onclick attributes
  initGlobalHandlers();

  // Initialize PWA features
  initServiceWorker();
  initOfflineDetection();
  initParticipationListener();

  // Load initial data
  loadPools();
  loadSavedKeys();
  loadServiceStatus();

  // Handle URL deep links
  handleUrlParams();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
