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

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    alert('Copied!');
  } catch (err) {
    console.error('Failed to copy:', err);
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
