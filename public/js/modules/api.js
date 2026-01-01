/**
 * API module for Rendezvous
 * Handles all communication with the backend server
 */

/**
 * Make an API request
 * @param {string} endpoint - API endpoint (without /api prefix)
 * @param {object} options - Fetch options
 * @returns {Promise<any>} Response data
 * @throws {Error} If request fails
 */
export async function api(endpoint, options = {}) {
  const res = await fetch('/api' + endpoint, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  let data = await res.json();

  // Unwrap padded array responses (server wraps arrays in {data: [...], _p: "..."})
  if (data && Array.isArray(data.data) && data._p !== undefined) {
    data = data.data;
  }

  if (!res.ok) {
    throw new Error(data.error || 'API error');
  }

  return data;
}

/**
 * Fetch all pools
 * @returns {Promise<Array>} Array of pool objects
 */
export async function fetchPools() {
  return api('/pools');
}

/**
 * Fetch a single pool by ID
 * @param {string} poolId - Pool identifier
 * @returns {Promise<object>} Pool object
 */
export async function fetchPool(poolId) {
  return api('/pools/' + poolId);
}

/**
 * Create a new pool
 * @param {object} poolData - Pool configuration
 * @returns {Promise<object>} Created pool object
 */
export async function createPool(poolData) {
  return api('/pools', { method: 'POST', body: poolData });
}

/**
 * Close a pool and trigger match computation (owner-only)
 * @param {string} poolId - Pool identifier
 * @param {object} authData - Authentication data with ownerPublicKey, signature, timestamp
 * @returns {Promise<object>} Close result
 */
export async function closePool(poolId, authData) {
  return api('/pools/' + poolId + '/close', { method: 'POST', body: authData });
}

/**
 * Fetch pool participants
 * @param {string} poolId - Pool identifier
 * @returns {Promise<object>} Participants data
 */
export async function fetchParticipants(poolId) {
  return api('/pools/' + poolId + '/participants');
}

/**
 * Register as a participant in a pool
 * @param {string} poolId - Pool identifier
 * @param {object} participantData - Participant profile data
 * @returns {Promise<object>} Registration result
 */
export async function registerParticipant(poolId, participantData) {
  return api('/pools/' + poolId + '/participants', {
    method: 'POST',
    body: participantData
  });
}

/**
 * Get participant by public key
 * @param {string} poolId - Pool identifier
 * @param {string} publicKey - Participant's public key
 * @returns {Promise<object>} Participant data
 */
export async function getParticipantByKey(poolId, publicKey) {
  return api('/pools/' + poolId + '/participants/by-key/' + publicKey);
}

/**
 * Submit preferences (match tokens) to a pool
 * @param {string} poolId - Pool identifier
 * @param {object} submissionData - Submission data including match tokens
 * @returns {Promise<object>} Submission result
 */
export async function submitPreferences(poolId, submissionData) {
  return api('/pools/' + poolId + '/submit', {
    method: 'POST',
    body: submissionData
  });
}

/**
 * Fetch match results for a pool
 * @param {string} poolId - Pool identifier
 * @returns {Promise<object>} Match results
 */
export async function fetchMatches(poolId) {
  return api('/pools/' + poolId + '/matches');
}

/**
 * Fetch reveal data for matches
 * @param {string} poolId - Pool identifier
 * @returns {Promise<object>} Reveal data
 */
export async function fetchRevealData(poolId) {
  return api('/pools/' + poolId + '/matches/reveal-data');
}

/**
 * Fetch service status
 * @returns {Promise<object>} Status information
 */
export async function fetchStatus() {
  return api('/status');
}
