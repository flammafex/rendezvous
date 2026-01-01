/**
 * Theme module for Rendezvous
 * Handles light/dark mode toggle with system preference detection
 */

const STORAGE_KEY = 'rendezvous-theme';

/**
 * Get the user's preferred theme
 * Priority: localStorage > system preference > dark (default)
 * @returns {'light' | 'dark'}
 */
function getPreferredTheme() {
  // Check localStorage first
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === 'light' || stored === 'dark') {
    return stored;
  }

  // Check system preference
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    return 'light';
  }

  // Default to dark
  return 'dark';
}

/**
 * Apply theme to document
 * @param {'light' | 'dark'} theme
 */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);

  // Update meta theme-color for mobile browsers
  const metaThemeColor = document.querySelector('meta[name="theme-color"]');
  if (metaThemeColor) {
    metaThemeColor.setAttribute('content', theme === 'light' ? '#f8f7f4' : '#0a0a0b');
  }
}

/**
 * Toggle between light and dark themes
 * @returns {'light' | 'dark'} The new theme
 */
export function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const newTheme = current === 'dark' ? 'light' : 'dark';

  applyTheme(newTheme);
  localStorage.setItem(STORAGE_KEY, newTheme);

  return newTheme;
}

/**
 * Get current theme
 * @returns {'light' | 'dark'}
 */
export function getCurrentTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark';
}

/**
 * Create and inject the theme toggle button into the header
 */
function createToggleButton() {
  // Create header actions container if it doesn't exist
  let headerActions = document.querySelector('.header-actions');
  if (!headerActions) {
    headerActions = document.createElement('div');
    headerActions.className = 'header-actions';
    document.querySelector('header').appendChild(headerActions);
  }

  // Create the toggle
  const toggle = document.createElement('div');
  toggle.className = 'theme-toggle';
  toggle.innerHTML = `
    <button
      class="theme-toggle-track"
      role="switch"
      aria-checked="${getCurrentTheme() === 'light'}"
      aria-label="Toggle light/dark theme"
    >
      <span class="theme-toggle-orb"></span>
      <span class="theme-toggle-sr">Toggle theme</span>
    </button>
    <span class="theme-toggle-label">${getCurrentTheme()}</span>
  `;

  headerActions.appendChild(toggle);

  // Add click handler
  const trackButton = toggle.querySelector('.theme-toggle-track');
  const label = toggle.querySelector('.theme-toggle-label');

  trackButton.addEventListener('click', () => {
    const newTheme = toggleTheme();
    trackButton.setAttribute('aria-checked', newTheme === 'light');
    label.textContent = newTheme;
  });
}

/**
 * Initialize theme system
 * - Apply saved/system preference
 * - Create toggle button
 * - Listen for system preference changes
 */
export function initTheme() {
  // Apply initial theme immediately (before DOM is fully loaded to prevent flash)
  const initialTheme = getPreferredTheme();
  applyTheme(initialTheme);

  // Create toggle button once DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', createToggleButton);
  } else {
    createToggleButton();
  }

  // Listen for system preference changes
  if (window.matchMedia) {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: light)');
    mediaQuery.addEventListener('change', (e) => {
      // Only auto-switch if user hasn't manually set a preference
      if (!localStorage.getItem(STORAGE_KEY)) {
        applyTheme(e.matches ? 'light' : 'dark');

        // Update toggle state if it exists
        const trackButton = document.querySelector('.theme-toggle-track');
        const label = document.querySelector('.theme-toggle-label');
        if (trackButton && label) {
          const newTheme = e.matches ? 'light' : 'dark';
          trackButton.setAttribute('aria-checked', e.matches);
          label.textContent = newTheme;
        }
      }
    });
  }
}

// Auto-initialize when this module is imported
initTheme();
