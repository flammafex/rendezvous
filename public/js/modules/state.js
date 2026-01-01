/**
 * State management for Rendezvous
 */

// Browse state
export const browseState = {
  poolId: null,
  poolName: null,
  participants: [],
  currentIndex: 0,
  selections: [],
  myPublicKey: null,
  myPrivateKey: null
};

// Current keypair (temporary, not yet saved)
let _currentKeypair = null;

// Whether invite code is required for pool creation
let _inviteRequired = false;

/**
 * Get current keypair
 * @returns {object|null} Current keypair or null
 */
export function getCurrentKeypair() {
  return _currentKeypair;
}

/**
 * Get invite required flag
 * @returns {boolean} Whether invite is required
 */
export function getInviteRequired() {
  return _inviteRequired;
}

/**
 * Set current keypair
 * @param {object|null} keypair - Keypair object or null
 */
export function setCurrentKeypair(keypair) {
  _currentKeypair = keypair;
}

/**
 * Set invite required flag
 * @param {boolean} required - Whether invite is required
 */
export function setInviteRequired(required) {
  _inviteRequired = required;
}

/**
 * Reset browse state
 */
export function resetBrowseState() {
  browseState.poolId = null;
  browseState.poolName = null;
  browseState.participants = [];
  browseState.currentIndex = 0;
  browseState.selections = [];
  browseState.myPublicKey = null;
  browseState.myPrivateKey = null;
}

/**
 * Add a selection
 * @param {object} selection - Selection object with publicKey and displayName
 */
export function addSelection(selection) {
  browseState.selections.push(selection);
}

/**
 * Remove a selection by public key
 * @param {string} publicKey - Public key to remove
 */
export function removeSelection(publicKey) {
  browseState.selections = browseState.selections.filter(s => s.publicKey !== publicKey);
}

/**
 * Storage keys
 */
export const STORAGE_KEYS = {
  KEYS: 'rendezvous_keys',
  DISCOVERIES: 'rendezvous_discoveries',
  OWNED_POOLS: 'rendezvous_owned_pools',
  PARTICIPATED_POOLS: 'rendezvous_participated_pools'
};

// ============================================================================
// Freebird Status State
// ============================================================================

// Freebird status: 'unconfigured' | 'connected' | 'disconnected' | 'error:...'
let _freebirdStatus = 'unconfigured';
let _requiresInvite = false;

/**
 * Set Freebird status from server
 * @param {string} status - Freebird status
 * @param {boolean} requiresInvite - Whether invite code is required
 */
export function setFreebirdStatus(status, requiresInvite) {
  _freebirdStatus = status;
  _requiresInvite = requiresInvite;
}

/**
 * Get Freebird status
 * @returns {string} 'unconfigured' | 'connected' | 'disconnected' | 'error:...'
 */
export function getFreebirdStatus() {
  return _freebirdStatus;
}

/**
 * Check if Freebird is configured
 * @returns {boolean}
 */
export function isFreebirdConfigured() {
  return _freebirdStatus !== 'unconfigured';
}

/**
 * Check if Freebird is connected
 * @returns {boolean}
 */
export function isFreebirdConnected() {
  return _freebirdStatus === 'connected';
}

/**
 * Check if pool creation is allowed
 * - Unconfigured: allowed (open mode)
 * - Connected: allowed (with invite code)
 * - Disconnected: blocked (fail closed)
 * @returns {boolean}
 */
export function canCreatePools() {
  return _freebirdStatus === 'unconfigured' || _freebirdStatus === 'connected';
}

/**
 * Check if invite code is required for pool creation
 * @returns {boolean}
 */
export function requiresInviteCode() {
  return _requiresInvite;
}

/**
 * Get saved keys from localStorage
 * @returns {Array} Array of saved keys
 */
export function getSavedKeys() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.KEYS) || '[]');
  } catch {
    return [];
  }
}

/**
 * Save keys to localStorage
 * @param {Array} keys - Array of keys to save
 */
export function saveKeys(keys) {
  localStorage.setItem(STORAGE_KEYS.KEYS, JSON.stringify(keys));
}

/**
 * Get discoveries from localStorage
 * @returns {object} Discoveries object
 */
export function getDiscoveries() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.DISCOVERIES) || '{}');
  } catch {
    return {};
  }
}

/**
 * Save discoveries to localStorage
 * @param {object} discoveries - Discoveries object
 */
export function saveDiscoveries(discoveries) {
  localStorage.setItem(STORAGE_KEYS.DISCOVERIES, JSON.stringify(discoveries));
}

// ============================================================================
// Owned Pools Management (for pool owner authentication)
// ============================================================================

/**
 * Get all owned pools from localStorage
 * @returns {object} Object mapping poolId to ownership data
 */
export function getOwnedPools() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.OWNED_POOLS) || '{}');
  } catch {
    return {};
  }
}

/**
 * Get ownership data for a specific pool
 * @param {string} poolId - Pool ID
 * @returns {object|null} Ownership data or null if not owned
 */
export function getOwnedPool(poolId) {
  const pools = getOwnedPools();
  return pools[poolId] || null;
}

/**
 * Save ownership data for a pool
 * @param {string} poolId - Pool ID
 * @param {object} ownershipData - Object with creatorPublicKey, signingPublicKey, signingPrivateKey
 */
export function saveOwnedPool(poolId, ownershipData) {
  const pools = getOwnedPools();
  pools[poolId] = {
    ...ownershipData,
    savedAt: Date.now()
  };
  localStorage.setItem(STORAGE_KEYS.OWNED_POOLS, JSON.stringify(pools));
}

/**
 * Delete ownership data for a pool
 * @param {string} poolId - Pool ID
 */
export function deleteOwnedPool(poolId) {
  const pools = getOwnedPools();
  delete pools[poolId];
  localStorage.setItem(STORAGE_KEYS.OWNED_POOLS, JSON.stringify(pools));
}

/**
 * Check if user owns a specific pool
 * @param {string} poolId - Pool ID
 * @returns {boolean} True if user owns the pool
 */
export function isPoolOwner(poolId) {
  return getOwnedPool(poolId) !== null;
}

// ============================================================================
// Participation Tracking (for tab visibility)
// ============================================================================

/**
 * Get participated pools from localStorage
 * @returns {object} Object mapping poolId to participation data
 */
export function getParticipatedPools() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.PARTICIPATED_POOLS) || '{}');
  } catch {
    return {};
  }
}

/**
 * Mark participation in a pool
 * @param {string} poolId - Pool ID
 * @param {string} publicKey - User's public key used for this pool
 */
export function markParticipation(poolId, publicKey) {
  const pools = getParticipatedPools();
  pools[poolId] = {
    publicKey,
    participatedAt: Date.now()
  };
  localStorage.setItem(STORAGE_KEYS.PARTICIPATED_POOLS, JSON.stringify(pools));
}

/**
 * Check if user has participated in any pool
 * @returns {boolean} True if user has participated in at least one pool
 */
export function hasParticipated() {
  const pools = getParticipatedPools();
  return Object.keys(pools).length > 0;
}
