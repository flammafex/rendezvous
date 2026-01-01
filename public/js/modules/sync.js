/**
 * Device sync module for Rendezvous
 * Handles encrypted key transfer via QR codes
 */

import { createModal, escapeHtml } from './ui.js';
import { getSavedKeys, saveKeys } from './state.js';
import { loadSavedKeys } from './keys.js';

// Store for pending import data and scan stream
let pendingImportData = null;
let keyScanStream = null;

/**
 * Derive encryption key from passphrase using PBKDF2
 * @param {string} passphrase - User passphrase
 * @param {Uint8Array} salt - Salt for key derivation
 * @returns {Promise<CryptoKey>} Derived key
 */
async function deriveKeyFromPassphrase(passphrase, salt) {
  const encoder = new TextEncoder();
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    passphraseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data with passphrase
 * @param {object} data - Data to encrypt
 * @param {string} passphrase - Encryption passphrase
 * @returns {Promise<string>} Base64-encoded encrypted data
 */
async function encryptWithPassphrase(data, passphrase) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await deriveKeyFromPassphrase(passphrase, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(JSON.stringify(data))
  );

  // Combine salt + iv + encrypted data
  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(encrypted), salt.length + iv.length);

  return btoa(String.fromCharCode(...result));
}

/**
 * Decrypt data with passphrase
 * @param {string} encryptedBase64 - Base64-encoded encrypted data
 * @param {string} passphrase - Decryption passphrase
 * @returns {Promise<object>} Decrypted data
 */
async function decryptWithPassphrase(encryptedBase64, passphrase) {
  const decoder = new TextDecoder();
  const data = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const encrypted = data.slice(28);

  const key = await deriveKeyFromPassphrase(passphrase, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encrypted
  );

  return JSON.parse(decoder.decode(decrypted));
}

/**
 * Show export keys modal
 */
export function showExportKeysModal() {
  const keys = getSavedKeys();
  if (keys.length === 0) {
    alert('No saved keys to export. Generate and save a key first.');
    return;
  }

  const modal = createModal(
    '<h3>Export Keys to New Device</h3>' +
    '<p class="text-muted text-sm mb-2">Create an encrypted QR code containing your ' + keys.length + ' saved key(s).</p>' +
    '<div class="form-group">' +
    '<label>Encryption Passphrase</label>' +
    '<input type="password" id="export-passphrase" placeholder="Enter a strong passphrase" autocomplete="new-password">' +
    '<p class="text-sm text-muted">You\'ll need this passphrase to import on the other device.</p>' +
    '</div>' +
    '<div class="form-group">' +
    '<label>Confirm Passphrase</label>' +
    '<input type="password" id="export-passphrase-confirm" placeholder="Confirm passphrase" autocomplete="new-password">' +
    '</div>' +
    '<div id="export-qr-container" class="hidden">' +
    '<div class="qr-code" id="export-qr-code"></div>' +
    '<p class="text-sm text-success">Scan this QR code on your other device</p>' +
    '</div>' +
    '<div id="export-error" class="text-error text-sm hidden"></div>' +
    '<div class="qr-actions">' +
    '<button class="btn-primary" id="export-generate-btn">Generate QR Code</button>' +
    '<button class="btn-secondary" data-action="close">Close</button>' +
    '</div>'
  );

  // Widen modal for this use case
  modal.querySelector('.qr-modal-content').style.maxWidth = '400px';

  document.body.appendChild(modal);

  modal.querySelector('[data-action="close"]').addEventListener('click', () => modal.remove());
  modal.querySelector('#export-generate-btn').addEventListener('click', generateExportQR);
  document.getElementById('export-passphrase').focus();
}

/**
 * Generate encrypted QR for export
 */
async function generateExportQR() {
  const passphrase = document.getElementById('export-passphrase').value;
  const confirm = document.getElementById('export-passphrase-confirm').value;
  const errorEl = document.getElementById('export-error');
  const qrContainer = document.getElementById('export-qr-container');
  const generateBtn = document.getElementById('export-generate-btn');

  errorEl.classList.add('hidden');

  if (passphrase.length < 8) {
    errorEl.textContent = 'Passphrase must be at least 8 characters';
    errorEl.classList.remove('hidden');
    return;
  }

  if (passphrase !== confirm) {
    errorEl.textContent = 'Passphrases do not match';
    errorEl.classList.remove('hidden');
    return;
  }

  generateBtn.disabled = true;
  generateBtn.textContent = 'Encrypting...';

  try {
    const keys = getSavedKeys();
    const exportData = {
      version: 1,
      type: 'rendezvous-keys',
      keys: keys,
      exportedAt: new Date().toISOString()
    };

    const encrypted = await encryptWithPassphrase(exportData, passphrase);

    // Generate QR code
    const qr = window.qrcode(0, 'L');
    qr.addData('RV1:' + encrypted);
    qr.make();

    document.getElementById('export-qr-code').innerHTML = qr.createImgTag(4, 8);
    qrContainer.classList.remove('hidden');
    generateBtn.textContent = 'QR Generated!';
  } catch (err) {
    console.error('Export error:', err);
    errorEl.textContent = 'Failed to generate QR: ' + err.message;
    errorEl.classList.remove('hidden');
    generateBtn.disabled = false;
    generateBtn.textContent = 'Generate QR Code';
  }
}

/**
 * Show import keys modal
 */
export function showImportKeysModal() {
  const modal = createModal(
    '<h3>Import Keys from Another Device</h3>' +
    '<p class="text-muted text-sm mb-2">Scan the QR code from your other device, then enter the passphrase.</p>' +
    '<div id="import-scan-section">' +
    '<button class="btn-primary" style="width:100%;" id="start-key-scan-btn">Scan QR Code</button>' +
    '<p class="text-center text-muted mt-2">- or paste encrypted data -</p>' +
    '<textarea id="import-data" placeholder="Paste RV1:... data here" rows="3" style="font-size:0.75rem;"></textarea>' +
    '</div>' +
    '<div id="import-decrypt-section" class="hidden">' +
    '<p class="text-success text-sm mb-2">QR code scanned! Enter passphrase to decrypt.</p>' +
    '<div class="form-group">' +
    '<label>Decryption Passphrase</label>' +
    '<input type="password" id="import-passphrase" placeholder="Enter the passphrase used during export">' +
    '</div>' +
    '<button class="btn-primary" style="width:100%;" id="decrypt-import-btn">Decrypt & Import</button>' +
    '</div>' +
    '<div id="import-result" class="hidden mt-2"></div>' +
    '<div class="qr-actions mt-2">' +
    '<button class="btn-secondary" data-action="close">Close</button>' +
    '</div>'
  );

  modal.querySelector('.qr-modal-content').style.maxWidth = '400px';

  document.body.appendChild(modal);

  modal.querySelector('[data-action="close"]').addEventListener('click', () => modal.remove());
  modal.querySelector('#start-key-scan-btn').addEventListener('click', startKeyScanQR);
  modal.querySelector('#decrypt-import-btn').addEventListener('click', decryptImportedKeys);

  // Watch for pasted data
  document.getElementById('import-data').addEventListener('input', function() {
    const data = this.value.trim();
    if (data.startsWith('RV1:')) {
      pendingImportData = data.substring(4);
      document.getElementById('import-scan-section').classList.add('hidden');
      document.getElementById('import-decrypt-section').classList.remove('hidden');
      document.getElementById('import-passphrase').focus();
    }
  });
}

/**
 * Start QR scanner for key import
 */
function startKeyScanQR() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert('Camera not supported. Please paste the data manually.');
    return;
  }

  const scanSection = document.getElementById('import-scan-section');
  scanSection.innerHTML =
    '<video id="key-qr-video" autoplay playsinline style="width:100%;max-width:280px;border-radius:0.5rem;margin:0 auto;display:block;"></video>' +
    '<canvas id="key-qr-canvas" style="display:none;"></canvas>' +
    '<p class="text-sm text-muted text-center mt-2" id="key-qr-status">Point camera at QR code</p>' +
    '<button class="btn-secondary btn-sm mt-2" style="width:100%;" id="stop-key-scan-btn">Cancel Scan</button>';

  document.getElementById('stop-key-scan-btn').addEventListener('click', stopKeyScanQR);

  const video = document.getElementById('key-qr-video');
  const canvas = document.getElementById('key-qr-canvas');
  const ctx = canvas.getContext('2d');

  navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
    .then((stream) => {
      keyScanStream = stream;
      video.srcObject = stream;
      video.play();
      requestAnimationFrame(() => scanKeyQRFrame(video, canvas, ctx));
    })
    .catch((err) => {
      document.getElementById('key-qr-status').textContent = 'Camera access denied';
      console.error('Camera error:', err);
    });
}

/**
 * Scan key QR frame
 */
function scanKeyQRFrame(video, canvas, ctx) {
  if (!keyScanStream) return;

  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0);

    if (window.jsQR) {
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(imageData.data, imageData.width, imageData.height);
      if (code && code.data.startsWith('RV1:')) {
        stopKeyScanQR();
        pendingImportData = code.data.substring(4);
        document.getElementById('import-scan-section').classList.add('hidden');
        document.getElementById('import-decrypt-section').classList.remove('hidden');
        document.getElementById('import-passphrase').focus();
        return;
      }
    }
  }
  requestAnimationFrame(() => scanKeyQRFrame(video, canvas, ctx));
}

/**
 * Stop key scan QR
 */
function stopKeyScanQR() {
  if (keyScanStream) {
    keyScanStream.getTracks().forEach(track => track.stop());
    keyScanStream = null;
  }
}

/**
 * Decrypt and import keys
 */
async function decryptImportedKeys() {
  const passphrase = document.getElementById('import-passphrase').value;
  const resultEl = document.getElementById('import-result');

  if (!pendingImportData) {
    resultEl.innerHTML = '<p class="text-error">No data to decrypt</p>';
    resultEl.classList.remove('hidden');
    return;
  }

  if (!passphrase) {
    resultEl.innerHTML = '<p class="text-error">Please enter the passphrase</p>';
    resultEl.classList.remove('hidden');
    return;
  }

  try {
    const decrypted = await decryptWithPassphrase(pendingImportData, passphrase);

    if (decrypted.type !== 'rendezvous-keys' || !Array.isArray(decrypted.keys)) {
      throw new Error('Invalid key data format');
    }

    // Merge with existing keys (avoid duplicates by public key)
    const existingKeys = getSavedKeys();
    const existingPubKeys = new Set(existingKeys.map(k => k.publicKey));

    let imported = 0;
    let skipped = 0;
    for (const key of decrypted.keys) {
      if (existingPubKeys.has(key.publicKey)) {
        skipped++;
      } else {
        existingKeys.push(key);
        imported++;
      }
    }

    saveKeys(existingKeys);
    loadSavedKeys();

    resultEl.innerHTML = '<div class="result-box success">' +
      '<strong>Import successful!</strong><br>' +
      imported + ' key(s) imported' +
      (skipped > 0 ? ', ' + skipped + ' skipped (already exist)' : '') +
      '</div>';
    resultEl.classList.remove('hidden');

    // Clear pending data
    pendingImportData = null;

    // Hide decrypt section
    document.getElementById('import-decrypt-section').classList.add('hidden');
  } catch (err) {
    console.error('Decrypt error:', err);
    resultEl.innerHTML = '<p class="text-error">Failed to decrypt: Wrong passphrase or corrupted data</p>';
    resultEl.classList.remove('hidden');
  }
}

/**
 * Initialize sync-related event listeners
 */
export function initSyncListeners() {
  document.querySelectorAll('[data-action="export-keys"]').forEach(btn => {
    btn.addEventListener('click', showExportKeysModal);
  });

  document.querySelectorAll('[data-action="import-keys"]').forEach(btn => {
    btn.addEventListener('click', showImportKeysModal);
  });
}
