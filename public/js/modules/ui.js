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

// === Modal infrastructure: focus trap + global Escape ===

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), ' +
  'textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Collect focusable elements inside a container, in DOM order.
 * @param {HTMLElement} container
 * @returns {HTMLElement[]}
 */
function getFocusable(container) {
  return Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR));
}

/**
 * Activate a focus trap on a modal element. Tab cycles within the modal;
 * Shift+Tab on the first element wraps to the last, Tab on the last wraps
 * to the first. The handler is stored on the element for later removal.
 *
 * @param {HTMLElement} modal - The modal element to trap focus within
 */
export function activateFocusTrap(modal) {
  if (!modal) return;

  const handler = (e) => {
    if (e.key !== 'Tab') return;
    const focusable = getFocusable(modal);
    if (focusable.length === 0) return;

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.shiftKey) {
      if (document.activeElement === first || !modal.contains(document.activeElement)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (document.activeElement === last || !modal.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  modal.addEventListener('keydown', handler);
  modal._focusTrapHandler = handler;
}

/**
 * Deactivate a previously-activated focus trap.
 * @param {HTMLElement} modal
 */
export function deactivateFocusTrap(modal) {
  if (!modal) return;
  if (modal._focusTrapHandler) {
    modal.removeEventListener('keydown', modal._focusTrapHandler);
    delete modal._focusTrapHandler;
  }
}

/**
 * Global Escape handler — closes the topmost open modal.
 *
 * Priority order (only the first match is acted on):
 *   1. .confirm-modal  → calls its stored _dismiss()
 *   2. .join-modal.active → clicks the close button (which may show a confirm)
 *   3. .qr-modal → clicks cancel button if present, otherwise removes the modal
 *
 * This handler is registered once at module load. showConfirm no longer
 * registers its own listener; instead it stores _dismiss on the overlay so
 * this handler can invoke it.
 */
function handleModalEscape(e) {
  if (e.key !== 'Escape') return;

  // Priority 1: confirmation modal (topmost)
  const confirmModal = document.querySelector('.confirm-modal');
  if (confirmModal) {
    e.preventDefault();
    if (typeof confirmModal._dismiss === 'function') {
      confirmModal._dismiss();
    }
    return;
  }

  // Priority 2: join modal
  const joinModal = document.querySelector('.join-modal.active');
  if (joinModal) {
    e.preventDefault();
    const closeBtn = document.getElementById('joinModalClose');
    if (closeBtn) closeBtn.click();
    return;
  }

  // Priority 3: qr-modal (created by createModal)
  const qrModal = document.querySelector('.qr-modal');
  if (qrModal) {
    e.preventDefault();
    const cancelBtn = qrModal.querySelector('[data-action="cancel"]');
    if (cancelBtn) {
      cancelBtn.click();
    } else {
      qrModal.remove();
    }
    return;
  }
}

document.addEventListener('keydown', handleModalEscape);

// === Confirmation modal ===

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

  const card = document.createElement('div');
  card.className = 'confirm-modal-card';
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-modal', 'true');
  card.setAttribute('aria-labelledby', 'confirm-title');

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

  // Activate focus trap on the card
  activateFocusTrap(card);

  let closed = false;

  const close = () => {
    if (closed) return;
    closed = true;
    overlay.classList.remove('confirm-modal-visible');
    overlay.classList.add('confirm-modal-leaving');
    deactivateFocusTrap(card);
    setTimeout(() => {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }, 200);
  };

  // Store dismiss on the overlay so the global Escape handler can call it
  overlay._dismiss = close;

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
  modal.innerHTML = '<div class="qr-modal-content" role="dialog" aria-modal="true">' + content + '</div>';

  const contentEl = modal.querySelector('.qr-modal-content');

  // Close on background click
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });

  // Activate focus trap (auto-cleaned when the element is removed from DOM)
  activateFocusTrap(contentEl);

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
