/**
 * QR code module for Rendezvous
 * Handles QR code generation and scanning
 */

import { escapeHtml, copyText, createModal } from './ui.js';
import { selectPoolForBrowse } from './browse.js';

// Store for active QR stream
let qrStream = null;

/**
 * Generate QR code for pool sharing
 * @param {string} poolId - Pool identifier
 * @param {string} poolName - Pool name
 */
export function generatePoolQR(poolId, poolName) {
  const url = window.location.origin + '?pool=' + encodeURIComponent(poolId);

  // Use qrcode-generator library (loaded from CDN)
  const qr = window.qrcode(0, 'M');
  qr.addData(url);
  qr.make();

  const modal = createModal(
    '<h3>Share Pool: ' + escapeHtml(poolName || 'Pool') + '</h3>' +
    '<div class="qr-code">' + qr.createImgTag(6, 8) + '</div>' +
    '<p class="text-sm text-muted">Scan to join this pool</p>' +
    '<div class="qr-url"><input type="text" value="' + url + '" readonly></div>' +
    '<div class="qr-actions">' +
    '<button class="btn-secondary" data-action="copy-link">Copy Link</button>' +
    '<button class="btn-secondary" data-action="share">Share</button>' +
    '<button class="btn-primary" data-action="close">Close</button>' +
    '</div>'
  );

  document.body.appendChild(modal);

  // Click handlers
  modal.querySelector('[data-action="copy-link"]').addEventListener('click', () => copyText(url));
  modal.querySelector('[data-action="share"]').addEventListener('click', () => sharePool(url, poolName));
  modal.querySelector('[data-action="close"]').addEventListener('click', () => modal.remove());

  // Select input on click
  modal.querySelector('.qr-url input').addEventListener('click', function() {
    this.select();
  });
}

/**
 * Share pool using Web Share API
 * @param {string} url - Pool URL
 * @param {string} name - Pool name
 */
async function sharePool(url, name) {
  if (navigator.share) {
    try {
      await navigator.share({
        title: 'Join ' + name + ' on Rendezvous',
        text: 'Join this private matching pool',
        url: url
      });
    } catch (err) {
      if (err.name !== 'AbortError') {
        copyText(url);
      }
    }
  } else {
    copyText(url);
  }
}

/**
 * Start QR scanner for pool joining
 */
export function startQRScanner() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert('Camera not supported on this device');
    return;
  }

  const modal = createModal(
    '<h3>Scan QR Code</h3>' +
    '<video id="qr-video" autoplay playsinline style="width:100%;max-width:300px;border-radius:0.5rem;"></video>' +
    '<canvas id="qr-canvas" style="display:none;"></canvas>' +
    '<p class="text-sm text-muted" id="qr-status">Point camera at QR code</p>' +
    '<button class="btn-secondary mt-2" data-action="cancel">Cancel</button>'
  );

  document.body.appendChild(modal);
  modal.querySelector('[data-action="cancel"]').addEventListener('click', () => stopQRScanner());

  const video = document.getElementById('qr-video');
  const canvas = document.getElementById('qr-canvas');
  const ctx = canvas.getContext('2d');

  navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
    .then((stream) => {
      qrStream = stream;
      video.srcObject = stream;
      video.play();
      requestAnimationFrame(() => scanQRFrame(video, canvas, ctx));
    })
    .catch((err) => {
      document.getElementById('qr-status').textContent = 'Camera access denied';
      console.error('Camera error:', err);
    });
}

/**
 * Scan QR frame
 * @param {HTMLVideoElement} video - Video element
 * @param {HTMLCanvasElement} canvas - Canvas element
 * @param {CanvasRenderingContext2D} ctx - Canvas context
 */
function scanQRFrame(video, canvas, ctx) {
  if (!qrStream) return;

  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0);

    // Try to decode QR code (using jsQR if loaded)
    if (window.jsQR) {
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(imageData.data, imageData.width, imageData.height);
      if (code) {
        handleQRResult(code.data);
        return;
      }
    }
  }
  requestAnimationFrame(() => scanQRFrame(video, canvas, ctx));
}

/**
 * Stop QR scanner
 */
export function stopQRScanner() {
  if (qrStream) {
    qrStream.getTracks().forEach(track => track.stop());
    qrStream = null;
  }
  const modal = document.querySelector('.qr-modal');
  if (modal) modal.remove();
}

/**
 * Handle QR scan result
 * @param {string} data - Scanned data
 */
function handleQRResult(data) {
  stopQRScanner();

  try {
    const url = new URL(data);
    const poolId = url.searchParams.get('pool');
    if (poolId) {
      document.getElementById('browsePoolId').value = poolId;
      document.querySelector('[data-tab="browse"]').click();
      selectPoolForBrowse();
    } else {
      alert('Invalid QR code - no pool ID found');
    }
  } catch (e) {
    // Maybe it's just a pool ID directly
    if (data.match(/^[0-9a-f-]{36}$/i)) {
      document.getElementById('browsePoolId').value = data;
      document.querySelector('[data-tab="browse"]').click();
      selectPoolForBrowse();
    } else {
      alert('Invalid QR code format');
    }
  }
}

/**
 * Initialize QR-related event listeners
 */
export function initQRListeners() {
  // Scan QR button
  document.querySelectorAll('[data-action="scan-qr"]').forEach(btn => {
    btn.addEventListener('click', startQRScanner);
  });
}
