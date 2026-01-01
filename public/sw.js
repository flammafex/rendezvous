/**
 * Rendezvous Service Worker
 * Provides offline-first caching for the PWA
 */

const CACHE_NAME = 'rendezvous-v4';
const STATIC_CACHE = 'rendezvous-static-v3';
const API_CACHE = 'rendezvous-api-v1';

// Static assets to cache immediately
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  // External dependencies (cached on first use)
];

// API routes to cache with network-first strategy
const CACHEABLE_API_ROUTES = [
  '/api/pools',
  '/api/status',
  '/api/federation',
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('[SW] Installing service worker');
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('[SW] Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating service worker');
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== STATIC_CACHE && name !== API_CACHE)
            .map((name) => {
              console.log('[SW] Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => self.clients.claim())
  );
});

// Fetch event - implement caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip chrome-extension and other non-http requests
  if (!url.protocol.startsWith('http')) {
    return;
  }

  // API requests - network first, fall back to cache
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirstStrategy(request));
    return;
  }

  // External resources (CDN) - cache first
  if (url.origin !== location.origin) {
    event.respondWith(cacheFirstStrategy(request));
    return;
  }

  // Static assets - cache first, fall back to network
  event.respondWith(cacheFirstStrategy(request));
});

/**
 * Network-first strategy
 * Try network, fall back to cache, update cache on success
 */
async function networkFirstStrategy(request) {
  const cache = await caches.open(API_CACHE);

  try {
    const response = await fetch(request);

    // Cache successful GET responses
    if (response.ok) {
      cache.put(request, response.clone());
    }

    return response;
  } catch (error) {
    console.log('[SW] Network failed, trying cache:', request.url);
    const cached = await cache.match(request);

    if (cached) {
      return cached;
    }

    // Return offline response for API requests
    return new Response(
      JSON.stringify({ error: 'Offline', offline: true }),
      {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }
}

/**
 * Cache-first strategy
 * Try cache first, fall back to network, update cache
 */
async function cacheFirstStrategy(request) {
  const cache = await caches.open(STATIC_CACHE);
  const cached = await cache.match(request);

  if (cached) {
    // Return cached response immediately
    // Optionally update cache in background
    fetchAndCache(request, cache);
    return cached;
  }

  // Not in cache, fetch from network
  try {
    const response = await fetch(request);

    if (response.ok) {
      cache.put(request, response.clone());
    }

    return response;
  } catch (error) {
    console.log('[SW] Fetch failed:', request.url);

    // Return offline page for navigation requests
    if (request.mode === 'navigate') {
      const offlinePage = await cache.match('/');
      if (offlinePage) {
        return offlinePage;
      }
    }

    return new Response('Offline', { status: 503 });
  }
}

/**
 * Background fetch and cache update
 */
async function fetchAndCache(request, cache) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      cache.put(request, response);
    }
  } catch (error) {
    // Ignore background fetch errors
  }
}

// Handle background sync for offline submissions
self.addEventListener('sync', (event) => {
  console.log('[SW] Background sync:', event.tag);

  if (event.tag === 'submit-preferences') {
    event.waitUntil(syncPendingSubmissions());
  }
});

/**
 * Sync pending preference submissions
 */
async function syncPendingSubmissions() {
  // Get pending submissions from IndexedDB
  // This would be implemented with actual IndexedDB storage
  console.log('[SW] Syncing pending submissions');
}

// Handle push notifications (future feature)
self.addEventListener('push', (event) => {
  if (!event.data) return;

  const data = event.data.json();
  console.log('[SW] Push received:', data);

  event.waitUntil(
    self.registration.showNotification(data.title || 'Rendezvous', {
      body: data.body || 'You have a new notification',
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-72.png',
      data: data.data,
    })
  );
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const data = event.notification.data || {};

  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((clientList) => {
      // Focus existing window or open new one
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }

      if (clients.openWindow) {
        const url = data.url || '/';
        return clients.openWindow(url);
      }
    })
  );
});

console.log('[SW] Service worker loaded');
