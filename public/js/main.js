/**
 * Main entry point for Rendezvous
 * Initializes all modules and sets up the application
 */

// Import modules
import './modules/theme.js'; // Auto-initializes on import
import { fetchStatus } from './modules/api.js';
import { setFreebirdStatus, browseState } from './modules/state.js';
import { goToBrowseStep, copyText } from './modules/ui.js';
import { loadPools, loadPoolsForBrowse, initPoolListeners, updateCreatePoolVisibility, joinPool } from './modules/pools.js';
import {
  fillFromSavedKey,
  selectPoolForBrowse,
  handleSwipe,
  handleBrowse,
  submitSelections,
  initBrowseListeners
} from './modules/browse.js';
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
 * Initialize tab navigation
 */
function initTabs() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(tab.dataset.tab).classList.add('active');

      // Load pools for browse when switching to browse tab
      if (tab.dataset.tab === 'browse') {
        loadPoolsForBrowse();
      }
    });
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
  // Pool refresh button
  const refreshBtn = document.querySelector('[onclick="loadPools()"]');
  if (refreshBtn) {
    refreshBtn.removeAttribute('onclick');
    refreshBtn.addEventListener('click', loadPools);
  }

  // Browse step navigation
  window.goToBrowseStep = goToBrowseStep;

  // Browse actions
  window.selectPoolForBrowse = selectPoolForBrowse;
  window.fillFromSavedKey = fillFromSavedKey;
  window.handleSwipe = handleSwipe;
  window.handleBrowse = handleBrowse;
  window.submitSelections = submitSelections;

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

  // Auto-fill private key on step 4
  const originalGoToBrowseStep = goToBrowseStep;
  window.goToBrowseStep = function(step) {
    originalGoToBrowseStep(step);
    if (step === 4 && browseState.myPrivateKey) {
      document.getElementById('submitPrivateKey').value = browseState.myPrivateKey;
    }
  };
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
  goToBrowseStep(1);

  // Handle URL deep links
  handleUrlParams();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
