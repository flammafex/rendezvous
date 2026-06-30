/**
 * UI utility functions for Rendezvous
 */

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML string
 */
export function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Format milliseconds to human-readable time
 * @param {number} ms - Milliseconds
 * @returns {string} Formatted time string
 */
export function formatTime(ms) {
  if (ms <= 0) return 'expired';
  const hours = Math.floor(ms / 3600000);
  return hours > 24 ? Math.floor(hours / 24) + 'd' : hours + 'h';
}

// === Toasts ===

const TOAST_DURATION = 2500;
const TOAST_FADE = 300;

/**
 * Lazily create the fixed toast container if it doesn't exist yet.
 * @returns {HTMLElement}
 */
function ensureToastContainer() {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    container.setAttribute('role', 'status');
    container.setAttribute('aria-live', 'polite');
    document.body.appendChild(container);
  }
  return container;
}

/**
 * Show a transient toast notification.
 * @param {string} message - Message text (plain text, not HTML)
 * @param {'success'|'error'|'info'} [type='info'] - Toast style variant
 */
export function showToast(message, type = 'info') {
  const container = ensureToastContainer();
  const toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.textContent = message;
  container.appendChild(toast);

  // Trigger entrance animation on next frame
  requestAnimationFrame(() => toast.classList.add('toast-visible'));

  // Auto-dismiss
  const dismiss = () => {
    toast.classList.remove('toast-visible');
    toast.classList.add('toast-leaving');
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, TOAST_FADE);
  };

  const timer = setTimeout(dismiss, TOAST_DURATION);

  // Allow click-to-dismiss (cancels the auto-dismiss)
  toast.addEventListener('click', () => {
    clearTimeout(timer);
    dismiss();
  });
}

// === Confirmation modal ===

let confirmEscapeListener = null;

/**
 * Show an in-app confirmation modal.
 *
 * @param {string} title - Modal title
 * @param {string} message - Body message (may contain inline HTML)
 * @param {string} confirmLabel - Label for the confirm button
 * @param {() => void} onConfirm - Called if the user confirms
 * @param {Object} [opts]
 * @param {boolean} [opts.danger=false] - Style the confirm button as destructive (red)
 */
export function showConfirm(title, message, confirmLabel, onConfirm, opts = {}) {
  const danger = opts.danger === true;

  const overlay = document.createElement('div');
  overlay.className = 'confirm-modal';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-labelledby', 'confirm-title');

  const card = document.createElement('div');
  card.className = 'confirm-modal-card';

  const titleEl = document.createElement('div');
  titleEl.id = 'confirm-title';
  titleEl.className = 'confirm-modal-title';
  titleEl.textContent = title;

  const body = document.createElement('div');
  body.className = 'confirm-modal-body';
  body.innerHTML = message;

  const actions = document.createElement('div');
  actions.className = 'confirm-modal-actions';

  const cancelBtn = document.createElement('button');
  cancelBtn.type = 'button';
  cancelBtn.className = 'btn-secondary';
  cancelBtn.textContent = 'Cancel';

  const confirmBtn = document.createElement('button');
  confirmBtn.type = 'button';
  confirmBtn.className = danger ? 'btn-danger' : 'btn-primary';
  confirmBtn.textContent = confirmLabel;

  actions.appendChild(cancelBtn);
  actions.appendChild(confirmBtn);

  card.appendChild(titleEl);
  card.appendChild(body);
  card.appendChild(actions);
  overlay.appendChild(card);
  document.body.appendChild(overlay);

  // Trigger entrance animation
  requestAnimationFrame(() => overlay.classList.add('confirm-modal-visible'));

  let closed = false;

  const close = () => {
    if (closed) return;
    closed = true;
    overlay.classList.remove('confirm-modal-visible');
    overlay.classList.add('confirm-modal-leaving');
    if (confirmEscapeListener) {
      document.removeEventListener('keydown', confirmEscapeListener);
      confirmEscapeListener = null;
    }
    setTimeout(() => {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }, 200);
  };

  const handleConfirm = () => {
    close();
    try {
      onConfirm();
    } catch (err) {
      console.error('confirm handler threw:', err);
    }
  };

  cancelBtn.addEventListener('click', close);
  confirmBtn.addEventListener('click', handleConfirm);

  // Click on overlay (outside the card) cancels
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) close();
  });

  // Escape cancels
  confirmEscapeListener = (e) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    }
  };
  document.addEventListener('keydown', confirmEscapeListener);

  // Focus the confirm button so Enter works immediately
  confirmBtn.focus();
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied!', 'success');
  } catch (err) {
    console.error('Failed to copy:', err);
    showToast('Copy failed', 'error');
  }
}

/**
 * Copy content of an element by ID
 * @param {string} elementId - Element ID
 */
export function copyKey(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    copyText(element.textContent);
  }
}

/**
 * Show/hide an element
 * @param {string|HTMLElement} element - Element or element ID
 * @param {boolean} show - Whether to show or hide
 */
export function toggleVisibility(element, show) {
  const el = typeof element === 'string' ? document.getElementById(element) : element;
  if (el) {
    el.classList.toggle('hidden', !show);
  }
}

/**
 * Create a QR modal element
 * @param {string} content - Modal content HTML
 * @returns {HTMLElement} Modal element
 */
export function createModal(content) {
  const modal = document.createElement('div');
  modal.className = 'qr-modal';
  modal.innerHTML = '<div class="qr-modal-content">' + content + '</div>';

  // Close on background click
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });

  return modal;
}

/**
 * Close all open modals
 */
export function closeModals() {
  document.querySelectorAll('.qr-modal').forEach(modal => modal.remove());
}

/**
 * Update step indicator
 * @param {number} currentStep - Current step number (1-based)
 * @param {number} totalSteps - Total number of steps
 */
export function updateStepIndicator(currentStep, totalSteps = 4) {
  for (let i = 1; i <= totalSteps; i++) {
    const step = document.getElementById('step' + i);
    if (step) {
      step.classList.remove('active', 'completed');
      if (i < currentStep) step.classList.add('completed');
      if (i === currentStep) step.classList.add('active');
    }
  }
}

/**
 * Navigate to a browse step
 * @param {number} step - Step number
 */
export function goToBrowseStep(step) {
  document.querySelectorAll('[id^="browseStep"]').forEach(el => el.classList.add('hidden'));
  const targetStep = document.getElementById('browseStep' + step);
  if (targetStep) {
    targetStep.classList.remove('hidden');
  }
  updateStepIndicator(step);
}
